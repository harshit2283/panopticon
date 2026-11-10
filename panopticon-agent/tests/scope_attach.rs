//! Lab test for the cgroup_skb backend: every program in the eBPF object
//! passes the verifier, every scope program attaches, and the kernel scope
//! rules hold on loopback traffic. Needs root on a Linux lab kernel:
//!
//!   cargo test --release -p panopticon-agent --test scope_attach --no-run
//!   sudo <binary> --ignored --nocapture --test-threads=1
//!
//! Prints one `MATRIX <program> load=.. attach=..` line per program.
#![cfg(target_os = "linux")]

#[path = "../src/scope_loader.rs"]
#[allow(dead_code)]
mod scope_loader;

use std::fs::File;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

use aya::maps::{Array, HashMap, MapData, PerCpuArray, RingBuf, SkStorage};
use aya::programs::Program;
use aya::{Ebpf, EbpfLoader};
use panopticon_common::scope::*;
use panopticon_common::*;
use scope_loader::*;

/// Fentry/fexit attach targets of the programs in the object.
const TARGETS: [(&str, &str); 13] = [
    (ACCEPT4, "inet_csk_accept"),
    (ACCEPT2, "inet_csk_accept"),
    ("scope_sol_tls", "sock_common_setsockopt"),
    ("scope_sol_tls_wq", "sock_common_setsockopt"),
    ("scope_sol_tls_compat", "compat_sock_common_setsockopt"),
    ("scope_sol_tls_compat_wq", "compat_sock_common_setsockopt"),
    ("scope_sol_tls_lsm", "security_socket_setsockopt"),
    ("scope_sol_tls_cgroup", "__cgroup_bpf_run_filter_setsockopt"),
    ("scope_set_ulp", "tcp_set_ulp"),
    ("tls_tcp_sendmsg_fentry", "tcp_sendmsg"),
    ("tls_tcp_recvmsg_fentry", "tcp_recvmsg"),
    ("tls_tcp_sendmsg_scoped", "tcp_sendmsg"),
    ("tls_tcp_recvmsg_scoped", "tcp_recvmsg"),
];

fn state(ebpf: &Ebpf, fd: &impl AsRawFd) -> Option<SockState> {
    let map: SkStorage<&MapData, SockState> =
        SkStorage::try_from(ebpf.map("SOCK_STATE").unwrap()).unwrap();
    map.get(&fd.as_raw_fd(), 0).ok()
}

/// pidfd_getfd exists (5.6+): ENOSYS is the only error with an fd of -1.
fn pidfd_getfd_exists() -> bool {
    // SAFETY: plain syscall on invalid fds.
    unsafe { libc::syscall(438, -1, -1, 0u32) };
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOSYS)
}

/// A dup of `fd` in process `pid` (pidfd_open + pidfd_getfd).
fn fd_of(pid: u32, fd: i32) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;
    // SAFETY: plain syscalls; non-negative results are fds we own.
    unsafe {
        let pidfd = libc::syscall(434, pid as libc::pid_t, 0u32);
        assert!(pidfd >= 0, "pidfd_open {pid}");
        let got = libc::syscall(438, pidfd as i32, fd, 0u32);
        libc::close(pidfd as i32);
        assert!(got >= 0, "pidfd_getfd {pid} {fd}");
        std::os::fd::OwnedFd::from_raw_fd(got as i32)
    }
}

fn cookie(fd: &impl AsRawFd) -> u64 {
    let mut c = 0u64;
    let mut len = 8u32;
    // SAFETY: valid fd and out-pointers; SO_COOKIE = 57.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            57,
            (&raw mut c).cast(),
            (&raw mut len).cast(),
        )
    };
    assert_eq!(rc, 0, "SO_COOKIE");
    c
}

fn set(ebpf: &mut Ebpf, index: u32, v: u64) {
    let mut cfg: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").unwrap()).unwrap();
    cfg.set(index, v, 0).unwrap();
}

fn drops(ebpf: &Ebpf, reason: u32) -> u64 {
    let m: PerCpuArray<&MapData, u64> =
        PerCpuArray::try_from(ebpf.map("SCOPE_DROPS").unwrap()).unwrap();
    m.get(&reason, 0).map_or(0, |v| v.iter().sum())
}

/// The fd the stand-in SSL_write below writes to.
static TEST_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

/// Stand-in for OpenSSL's `SSL_write(ssl, buf, num)`: the TLS write probes
/// attach to it by symbol. Writes the plaintext to `TEST_FD` (no TLS).
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn panop_test_ssl_write(_ssl: u64, buf: *const u8, num: i32) -> i32 {
    let fd = TEST_FD.load(std::sync::atomic::Ordering::SeqCst);
    run_hook(&PRE_HOOK);
    // SAFETY: buf holds num bytes (the callers in the test).
    let n = unsafe { libc::write(fd, buf.cast(), num as usize) as i32 };
    run_hook(&TEST_HOOK);
    n
}

/// Stand-in for OpenSSL's `SSL_read(ssl, buf, num)`: reads from `TEST_FD`.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn panop_test_ssl_read(_ssl: u64, buf: *mut u8, num: i32) -> i32 {
    let fd = TEST_FD.load(std::sync::atomic::Ordering::SeqCst);
    run_hook(&PRE_HOOK);
    // SAFETY: buf holds num bytes (the callers in the test).
    let n = unsafe { libc::read(fd, buf.cast(), num as usize) as i32 };
    run_hook(&TEST_HOOK);
    n
}

/// Run inside the stand-ins: PRE_HOOK before their socket I/O, TEST_HOOK
/// after it.
type Hook = Box<dyn FnMut() + Send>;
static TEST_HOOK: std::sync::Mutex<Option<Hook>> = std::sync::Mutex::new(None);
static PRE_HOOK: std::sync::Mutex<Option<Hook>> = std::sync::Mutex::new(None);

fn run_hook(h: &std::sync::Mutex<Option<Hook>>) {
    if let Some(hook) = h.lock().unwrap().as_mut() {
        hook();
    }
}

/// This thread's TLS_CALL slot as the post-I/O hook saw it: 0 absent,
/// else state + 1.
static SLOT_STATE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A second stand-in with only the write entry probe attached: an inner
/// call whose return probe never runs.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn panop_test_ssl_write_entry_only(_ssl: u64, _buf: *const u8, num: i32) -> i32 {
    std::hint::black_box(num)
}

/// Set by the hook when this thread's TLS_CALL slot exists mid-call.
static SLOT_SEEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The kernel id of a map, to open a second handle to it.
fn map_id(ebpf: &Ebpf, name: &str) -> u32 {
    use aya::maps::Map;
    match ebpf.map(name).unwrap() {
        Map::Array(d) | Map::HashMap(d) | Map::LruHashMap(d) => d.info().unwrap().id(),
        _ => unreachable!("{name}"),
    }
}

/// TLS_ACTIVE on every CPU: [pid_tgid, conn].
fn set_active(ebpf: &mut Ebpf, v: [u64; 2]) {
    let mut active: PerCpuArray<_, [u64; 2]> =
        PerCpuArray::try_from(ebpf.map_mut("TLS_ACTIVE").unwrap()).unwrap();
    let n = aya::util::nr_cpus().unwrap();
    let values = aya::maps::PerCpuValues::try_from(vec![v; n]).unwrap();
    active.set(0, values, 0).unwrap();
}

/// Drain ring 0: every TlsData event.
fn drain_tls(ring: &mut RingBuf<MapData>) -> Vec<DataEvent> {
    let mut out = Vec::new();
    while let Some(item) = ring.next() {
        // SAFETY: all-zero is a valid DataEvent.
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        if read_data_event_into(&item, &mut e) && e.event_type == EventType::TlsData {
            out.push(e);
        }
    }
    out
}

/// Drain ring 0: (cookie, direction, stream_off, payload) of every event.
fn drain(ring: &mut RingBuf<MapData>) -> Vec<(u64, Direction, u64, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some(item) = ring.next() {
        // SAFETY: all-zero is a valid DataEvent.
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        if read_data_event_into(&item, &mut e) {
            out.push((
                e.socket_cookie,
                e.direction,
                e.stream_off,
                e.payload_bytes().to_vec(),
            ));
        }
    }
    out
}

fn load_any(ebpf: &mut Ebpf, name: &str) -> Result<(), String> {
    let target = TARGETS.iter().find(|(p, _)| *p == name).map(|(_, f)| *f);
    let is_scope_kind = matches!(
        ebpf.program(name),
        Some(
            Program::CgroupSkb(_)
                | Program::CgroupSock(_)
                | Program::SockOps(_)
                | Program::TracePoint(_)
                | Program::UProbe(_)
                | Program::FEntry(_)
                | Program::FExit(_)
        )
    );
    if is_scope_kind {
        return load_program(ebpf, name, target).map_err(|e| format!("{e:#}"));
    }
    match ebpf.program_mut(name).unwrap() {
        Program::KProbe(p) => p.load().map_err(|e| e.to_string()),
        Program::SchedClassifier(p) => p.load().map_err(|e| e.to_string()),
        _ => Err("unhandled type".into()),
    }
}

fn in_map(ebpf: &Ebpf, map: &str, pid: u32) -> bool {
    let m: HashMap<&MapData, u32, u8> = HashMap::try_from(ebpf.map(map).unwrap()).unwrap();
    m.get(&pid, 0).is_ok()
}

fn pid_listed(ebpf: &Ebpf, pid: u32) -> bool {
    in_map(ebpf, "PID_FILTER", pid)
}

/// A process held inside do_exit: `cat` traced with PTRACE_O_TRACEEXIT, its
/// stdin closed so it exits on its own (no fatal signal, which could skip
/// the stop). It is stopped at PTRACE_EVENT_EXIT, which do_exit reaches
/// before setting PF_EXITING and before sched_process_exit fires.
fn hold_in_exit() -> std::process::Child {
    let mut child = std::process::Command::new("cat")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    // SAFETY: ptrace/waitpid on our own child.
    unsafe {
        let opts = libc::PTRACE_O_TRACEEXIT as usize;
        assert_eq!(
            libc::ptrace(libc::PTRACE_SEIZE, pid, 0usize, opts),
            0,
            "PTRACE_SEIZE"
        );
        drop(child.stdin.take());
        let mut st = 0;
        assert_eq!(libc::waitpid(pid, &mut st, libc::__WALL), pid);
        assert_eq!(
            st >> 8,
            libc::SIGTRAP | (libc::PTRACE_EVENT_EXIT << 8),
            "held at PTRACE_EVENT_EXIT (status {st:#x})"
        );
    }
    child
}

/// `sleep 30` running as `pid` (through ns_last_pid), if it can be placed.
fn spawn_sleep_at(pid: u32) -> Option<std::process::Child> {
    for _ in 0..50 {
        std::fs::write("/proc/sys/kernel/ns_last_pid", format!("{}", pid - 1)).unwrap();
        let mut c = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        if c.id() == pid {
            return Some(c);
        }
        c.kill().unwrap();
        c.wait().unwrap();
    }
    None
}

/// Let a held process finish exiting, and reap it.
fn release(mut child: std::process::Child) {
    // SAFETY: our tracee, stopped at PTRACE_EVENT_EXIT.
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, child.id() as libc::pid_t, 0usize, 0usize);
    }
    child.wait().unwrap();
}

/// `setsockopt(TCP_ULP, "tls")`; false if the kernel has no tls ULP.
fn set_tls_ulp(fd: &impl AsRawFd) -> bool {
    // SAFETY: valid fd and buffer; SOL_TCP = 6, TCP_ULP = 31.
    unsafe { libc::setsockopt(fd.as_raw_fd(), 6, 31, b"tls".as_ptr().cast(), 3) == 0 }
}

/// `setsockopt(SOL_TLS, TLS_RX)` with an AES-GCM-128 key: the socket's
/// receive side becomes kTLS, its sends stay as written.
fn set_tls_rx_key(fd: &impl AsRawFd) -> bool {
    set_key(fd, 282, 2) // SOL_TLS, TLS_RX
}

/// `setsockopt(level, optname)` with a struct tls12_crypto_info_aes_gcm_128
/// (version, cipher, iv[8], key[16], salt[4], rec_seq[8]).
fn set_key(fd: &impl AsRawFd, level: i32, optname: i32) -> bool {
    let mut k = [0u8; 40];
    k[..2].copy_from_slice(&0x0303u16.to_ne_bytes());
    k[2..4].copy_from_slice(&51u16.to_ne_bytes());
    // SAFETY: valid fd and buffer.
    unsafe { libc::setsockopt(fd.as_raw_fd(), level, optname, k.as_ptr().cast(), 40) == 0 }
}

/// Spawn a process that sends `payload` to `port`, trying to make it reuse
/// `pid` (through ns_last_pid). Returns whether the pid was reused.
fn spawn_with_pid(pid: u32, port: u16, payload: &str) -> bool {
    for _ in 0..50 {
        std::fs::write("/proc/sys/kernel/ns_last_pid", format!("{}", pid - 1)).unwrap();
        let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}; printf {payload} >&3; sleep 0.3");
        let mut child = std::process::Command::new("bash")
            .args(["-c", &script])
            .spawn()
            .unwrap();
        if child.id() == pid {
            child.wait().unwrap();
            return true;
        }
        child.wait().unwrap();
    }
    false
}

#[test]
#[ignore = "needs root on a Linux lab kernel"]
fn scope_programs_load_attach_and_hold() {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panopticon-ebpf"));
    let mut ebpf = EbpfLoader::new().load(bytes).expect("object and maps load");

    // ── the production load-check for a restricted config with TLS: every
    // program it needs (capture, writers, exit tracepoint, TLS uprobes)
    let setup = ScopeSetup {
        mode: SCOPE_SEL_PID | SCOPE_HEAD,
        tls: true,
        cgroup2_path: std::env::var("PANOPTICON_CGROUP2").unwrap_or_else(|_| "auto".into()),
    };
    let report = load_check(&mut ebpf, &setup).expect("production load_check");
    assert!(report.writers && report.exit_tp, "{report:?}");
    assert!(!report.markers.is_empty(), "{report:?}");
    println!("MARKERS {:?}", report.markers);
    let accept = report.accept.expect("one inet_csk_accept variant loads");
    let other_accept = if accept == ACCEPT4 { ACCEPT2 } else { ACCEPT4 };
    // Allowed load failures: the other accept arity, and kTLS marker
    // variants the load-check did not pick (other layout, absent function).
    let allowed: Vec<String> = SOL_TLS_MARKERS
        .iter()
        .flat_map(|(_, v)| v.iter())
        .filter(|p| !report.markers.contains(p))
        .map(|p| p.to_string())
        .chain([other_accept.to_string()])
        .collect();

    // ── every other program in the object through the verifier
    let names: Vec<String> = ebpf.programs().map(|(n, _)| n.to_string()).collect();
    let mut failed = Vec::new();
    for name in &names {
        match load_any(&mut ebpf, name) {
            Ok(()) => {
                // The verifier's processed-instruction count, where the
                // kernel reports it (bpf_prog_info.verified_insns, 5.16+).
                let insns = ebpf
                    .program(name)
                    .and_then(|p| p.info().ok())
                    .and_then(|i| i.verified_instruction_count());
                match insns {
                    Some(n) => println!("MATRIX {name} load=OK verified_insns={n}"),
                    None => println!("MATRIX {name} load=OK"),
                }
            }
            Err(e) => {
                println!("MATRIX {name} load=FAIL ({e})");
                failed.push(name.clone());
            }
        }
    }
    assert!(
        failed.contains(&other_accept.to_string()) && failed.iter().all(|f| allowed.contains(f)),
        "load failures {failed:?}, allowed {allowed:?}"
    );

    // Pre-agent listeners for arm-time owner initialisation (§3.1), made
    // before any other process is spawned: `holder` (listed) holds LA alone
    // and LB together with this process (unlisted at arm).
    let la = TcpListener::bind("127.0.0.1:0").unwrap();
    let lb = TcpListener::bind("127.0.0.1:0").unwrap();
    let la_port = la.local_addr().unwrap().port();
    let (la_raw, lb_raw) = (la.as_raw_fd(), lb.as_raw_fd());
    let mut holder = {
        use std::os::unix::process::CommandExt;
        let mut c = std::process::Command::new("sleep");
        c.arg("60");
        // SAFETY: dup2 only, between fork and exec; dup2 clears CLOEXEC.
        unsafe {
            c.pre_exec(move || {
                if libc::dup2(la_raw, 100) < 0 || libc::dup2(lb_raw, 101) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        c.spawn().unwrap()
    };
    drop(la);
    let holder_pid = holder.id();

    // Sockets that predate the attach: a listener and a connected client.
    let pre_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut pre_client = TcpStream::connect(pre_listener.local_addr().unwrap()).unwrap();
    let (_pre_server, _) = pre_listener.accept().unwrap();

    // Config as sync_config_to_ebpf writes it: restricted, disarmed.
    let me = std::process::id();
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    set(&mut ebpf, CONFIG_USE_RINGBUF, 1);
    set(&mut ebpf, CONFIG_RING_SHARD_MASK, 0);
    set(&mut ebpf, CONFIG_SCOPE_GEN, 1);
    set(&mut ebpf, CONFIG_PID_EPOCH, 77);
    set(&mut ebpf, CONFIG_HEAD_BYTES, 1 << 20);
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_HEAD);
    set(&mut ebpf, CONFIG_SCOPE_ARMED, 0);
    let mut ring = RingBuf::try_from(ebpf.take_map("DATA_EVENTS_0").unwrap()).unwrap();

    // ── legacy attach path (RHEL 8): an earlier agent's attachments, left
    // behind as after a SIGKILL, are found and removed before attaching
    let root = discover_cgroup_root(&setup.cgroup2_path).expect("cgroup2 root");
    println!("ROOT {root:?}");
    let cgroup = File::open(root.path()).unwrap();
    if !uses_links() {
        let mut stale = EbpfLoader::new().load(bytes).unwrap();
        let mut stale_links = Vec::new();
        for (p, _) in CGROUP_PROGRAMS {
            load_program(&mut stale, p, None).unwrap();
            attach_program(&mut stale, p, &cgroup, &mut stale_links).unwrap();
        }
        std::mem::forget(stale_links);
        std::mem::forget(stale); // attached, and never detached by us
        for (_, t) in CGROUP_PROGRAMS {
            assert_eq!(attached_ids(&cgroup, t).unwrap().len(), 1);
        }
    }

    // ── pid_filter candidates, chosen before the attach (as configured):
    // a live process; one gone before the exit tracepoint is attached; two
    // held inside do_exit (PTRACE_EVENT_EXIT), short of the tracepoint
    let mut sel = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let mut gone = std::process::Command::new("true").spawn().unwrap();
    gone.wait().unwrap();
    let held_early = hold_in_exit(); // finishes exiting between attach and arm
    let held_late = hold_in_exit(); // finishes exiting after arm
    // P: running when the config is read, then exits and is reaped before
    // the attach, and Q takes its PID
    let mut p = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let (sel_pid, gone_pid, p_pid) = (sel.id(), gone.id(), p.id());
    let (early_pid, late_pid) = (held_early.id(), held_late.id());
    let pids = [sel_pid, gone_pid, early_pid, late_pid, p_pid, holder_pid];
    let candidates = snapshot_candidates(&pids);
    let pidfd = candidates[0].pidfd.is_some();
    let candidates_pidfd = pidfd && pidfd_getfd_exists();
    println!("METHOD {}", if pidfd { "pidfd" } else { "start_time" });
    assert!(
        candidates[1].pidfd.is_none() && candidates[1].start.is_none(),
        "not running at read"
    );
    p.kill().unwrap();
    p.wait().unwrap();
    if !pidfd {
        // Start times are in clock ticks: let one pass so Q's differs. With
        // a pidfd, Q follows P at once.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut q = spawn_sleep_at(p_pid).expect("Q reuses P's pid");

    // ── production attach, disarmed
    let mut links = Vec::new();
    let (_, exit_attached) = attach_disarmed(
        &mut ebpf,
        &setup,
        Some(&candidates),
        |_, _| Ok(()),
        &mut links,
    )
    .expect("attach");
    assert!(exit_attached);
    for p in pids {
        assert!(in_map(&ebpf, "PID_CANDIDATES", p), "candidate {p} written");
        assert!(!pid_listed(&ebpf, p), "nothing published before arm");
    }
    if !uses_links() {
        // The instance lock is held: another open file description cannot
        // take it.
        let f = File::open(INSTANCE_LOCK).unwrap();
        // SAFETY: flock on an fd we own.
        let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_ne!(rc, 0, "instance lock held");
        use std::os::unix::fs::PermissionsExt;
        let mode = f.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "lock file mode");
        println!("LOCK held mode={mode:o}");
    }
    for (p, t) in CGROUP_PROGRAMS {
        let ours = ebpf.program(p).unwrap().info().unwrap().id();
        let ids = attached_ids(&cgroup, t).unwrap();
        assert!(ids.contains(&ours), "{p} attached");
        if !uses_links() {
            assert_eq!(ids, vec![ours], "{p}: the stale copy was removed");
        }
        println!("MATRIX {p} attach=OK");
    }
    for p in [EXIT_TP, accept]
        .into_iter()
        .chain(report.markers.iter().copied())
    {
        println!("MATRIX {p} attach=OK"); // required by attach_disarmed here
    }

    // ── forced exit interleaving, first order: the exit tracepoint runs
    // after the attach and before arm's insert. The kernel records it.
    release(held_early);
    let mut recorded = false;
    for _ in 0..200 {
        recorded = in_map(&ebpf, "PID_EXITED", early_pid);
        if recorded {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        recorded,
        "disarmed exit of a candidate recorded in PID_EXITED"
    );
    assert!(!in_map(&ebpf, "PID_EXITED", late_pid), "still held");

    // ── the startup window: sockets created (and established) before
    // arming stay uninitialised for life
    let lw = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut tw = TcpStream::connect(lw.local_addr().unwrap()).unwrap();
    let (mut tw_srv, _) = lw.accept().unwrap();
    let ulp = set_tls_ulp(&tw);
    println!("WINDOW tls_ulp={ulp}");
    let ru_w = UdpSocket::bind("127.0.0.1:0").unwrap();
    let su_w = UdpSocket::bind("127.0.0.1:0").unwrap();
    su_w.connect(ru_w.local_addr().unwrap()).unwrap();

    // ── arm
    let excluded = arm(&mut ebpf, Some(candidates)).unwrap();
    println!("ARM excluded={excluded:?}");
    assert!(pid_listed(&ebpf, sel_pid));
    assert!(
        pid_listed(&ebpf, late_pid),
        "held short of the tracepoint: selected"
    );
    assert!(!pid_listed(&ebpf, gone_pid), "a dead pid is not published");
    assert!(
        !pid_listed(&ebpf, early_pid),
        "a recorded exit is not published"
    );
    assert!(
        excluded.contains(&(early_pid, EXITED_RECORDED)),
        "{excluded:?}"
    );
    assert!(excluded.contains(&(gone_pid, NOT_RUNNING)), "{excluded:?}");
    assert!(
        excluded.contains(&(p_pid, IDENTITY_CHANGED)),
        "{excluded:?}"
    );
    assert_eq!(excluded.len(), 3, "{excluded:?}");
    assert!(
        !pid_listed(&ebpf, p_pid),
        "Q, reusing P's pid, is not selected"
    );
    assert!(q.try_wait().unwrap().is_none(), "Q still running");
    q.kill().unwrap();
    q.wait().unwrap();
    println!("IDENTITY reused_before_attach=OK");
    for p in pids {
        assert!(!in_map(&ebpf, "PID_CANDIDATES", p), "candidates cleared");
    }

    // ── second order: the tracepoint runs after arm's insert (armed now):
    // the entry is removed and nothing more is recorded
    release(held_late);
    assert!(
        !pid_listed(&ebpf, late_pid),
        "exit after arm removed the pid"
    );
    assert!(!in_map(&ebpf, "PID_EXITED", late_pid), "armed: no record");
    println!("EXIT_RACE OK");

    // A reused pid of the process that exited during startup is not
    // selected.
    let mut reuse_ok = false;
    for _ in 0..50 {
        std::fs::write("/proc/sys/kernel/ns_last_pid", format!("{}", early_pid - 1)).unwrap();
        let mut c = std::process::Command::new("sleep")
            .arg("1")
            .spawn()
            .unwrap();
        let hit = c.id() == early_pid;
        if hit {
            assert!(!pid_listed(&ebpf, early_pid), "reused pid not selected");
            reuse_ok = true;
        }
        c.kill().unwrap();
        c.wait().unwrap();
        if hit {
            break;
        }
    }
    println!("EXIT_RACE reuse={reuse_ok}");
    assert!(reuse_ok, "could not reuse pid {early_pid}");

    let uninit0 = drops(&ebpf, DROP_UNINIT);
    let mut buf = [0u8; 64];
    tw.write_all(b"window").unwrap();
    let _ = tw_srv.read(&mut buf).unwrap();
    su_w.send(b"window").unwrap();
    let _ = ru_w.recv(&mut buf).unwrap();
    let ev = drain(&mut ring);
    for c in [cookie(&tw), cookie(&tw_srv), cookie(&su_w), cookie(&ru_w)] {
        assert!(
            !ev.iter().any(|e| e.0 == c),
            "window socket exported: {ev:?}"
        );
    }
    assert!(state(&ebpf, &tw).is_none() && state(&ebpf, &su_w).is_none());
    assert!(
        drops(&ebpf, DROP_UNINIT) >= uninit0 + 4,
        "window sockets counted uninit"
    );

    // After arming: the tls ULP alone (no keys) does not mark a socket, and
    // its payload is captured as any other socket's. Installing a key marks
    // it (§3.5): its payload is dropped outside unscoped full, after its
    // verdict is cached, so its TLS calls can still get its address.
    if ulp {
        let mut tk = TcpStream::connect(lw.local_addr().unwrap()).unwrap();
        let (mut tk_srv, _) = lw.accept().unwrap();
        assert!(set_tls_ulp(&tk));
        assert_eq!(
            state(&ebpf, &tk).unwrap().flags & FLAG_KTLS,
            0,
            "ULP without keys: not marked"
        );
        tk.write_all(b"ulp-only").unwrap();
        let _ = tk_srv.read(&mut buf).unwrap();
        assert!(
            drain(&mut ring)
                .iter()
                .any(|e| e.0 == cookie(&tk) && e.3 == b"ulp-only"),
            "ULP without keys: captured"
        );
        assert!(set_tls_rx_key(&tk), "TLS_RX key installs");
        assert_ne!(
            state(&ebpf, &tk).unwrap().flags & FLAG_KTLS,
            0,
            "KTLS marked at key install"
        );
        let k0 = drops(&ebpf, DROP_KTLS_PAYLOAD);
        // TX has no key: these bytes are on the wire as written.
        tk.write_all(b"ktls").unwrap();
        let _ = tk_srv.read(&mut buf).unwrap();
        assert!(!drain(&mut ring).iter().any(|e| e.0 == cookie(&tk)));
        assert!(drops(&ebpf, DROP_KTLS_PAYLOAD) > k0);
        assert_eq!(
            cached_verdict(state(&ebpf, &tk).unwrap().verdict_word, 1),
            Some(VERDICT_IN),
            "verdict cached before the kTLS drop"
        );
        // A SOL_TLS setsockopt on a socket without the ULP fails, and still
        // marks (on entry, whatever the result).
        let tn = TcpStream::connect(lw.local_addr().unwrap()).unwrap();
        let (_tn_srv, _) = lw.accept().unwrap();
        assert!(!set_tls_rx_key(&tn));
        assert_ne!(state(&ebpf, &tn).unwrap().flags & FLAG_KTLS, 0);
        println!("KTLS key-install marking OK");

        // A foreign cgroup/setsockopt program that rewrites (SOL_TCP, 1000)
        // into (SOL_TLS, TLS_RX) (tests/oracle/sockopt_rewrite.bpf.c): the
        // marker sees the level the kernel goes on with.
        match std::env::var("SOCKOPT_REWRITE_OBJ") {
            Ok(obj) => {
                let mut foreign = Ebpf::load_file(&obj).expect("foreign object loads");
                let p: &mut aya::programs::CgroupSockopt = foreign
                    .program_mut("sockopt_rewrite")
                    .unwrap()
                    .try_into()
                    .unwrap();
                let mode = if uses_links() {
                    aya::programs::CgroupAttachMode::Single
                } else {
                    aya::programs::CgroupAttachMode::AllowMultiple
                };
                match p.load().and_then(|()| p.attach(&cgroup, mode)) {
                    Ok(_) => {
                        let tr = TcpStream::connect(lw.local_addr().unwrap()).unwrap();
                        let (_tr_srv, _) = lw.accept().unwrap();
                        assert!(set_tls_ulp(&tr));
                        assert!(set_key(&tr, 6, 1000), "rewritten to TLS_RX, key installed");
                        assert_ne!(
                            state(&ebpf, &tr).unwrap().flags & FLAG_KTLS,
                            0,
                            "rewritten key install marked"
                        );
                        println!("KTLS rewrite marking OK");
                    }
                    Err(e) => {
                        println!("KTLS rewrite: cgroup/setsockopt unavailable ({e}), skipped")
                    }
                }
            }
            Err(_) => println!("KTLS rewrite: SOCKOPT_REWRITE_OBJ not set, skipped"),
        }
    }

    // ── runtime: unscoped full
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    client.write_all(b"hello").unwrap();
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello");

    let ls = state(&ebpf, &listener).expect("listener has state (sock_create)");
    assert_eq!(ls.init_cookie, 0, "a listener is never initialised");
    assert_eq!(ls.owner_tgid, me);
    let cs = state(&ebpf, &client).expect("client state");
    assert_eq!(cs.init_cookie, cookie(&client), "client initialised");
    assert_eq!(cs.owner_tgid, me);
    assert_eq!(cs.syn_adj, 1);
    assert_eq!(
        cs.flags & (FLAG_BASELINE | FLAG_ROLE_CLIENT),
        FLAG_BASELINE | FLAG_ROLE_CLIENT
    );
    let ss = state(&ebpf, &server).expect("child state (BPF_F_CLONE)");
    assert_eq!(
        ss.init_cookie,
        cookie(&server),
        "child initialised with its own cookie"
    );
    assert_ne!(ss.init_cookie, cookie(&listener));
    assert_eq!(ss.owner_tgid, me, "owner inherited from the listener");
    assert_eq!(ss.acceptor_tgid, me, "acceptor recorded on the child");
    assert_eq!(ss.flags & FLAG_ROLE_SERVER, FLAG_ROLE_SERVER);
    assert_eq!(ss.pid_epoch, 77);

    let ev = drain(&mut ring);
    assert!(
        ev.iter().any(|e| e.0 == cookie(&client)
            && e.1 == Direction::Egress
            && e.2 == 0
            && e.3 == b"hello"),
        "client egress at offset 0: {ev:?}"
    );
    assert!(
        ev.iter().any(|e| e.0 == cookie(&server)
            && e.1 == Direction::Ingress
            && e.2 == 0
            && e.3 == b"hello"),
        "server ingress at offset 0: {ev:?}"
    );

    // Pre-agent sockets: no state, ever. A new child of a pre-agent
    // listener is initialised; its owner is unknown, its acceptor recorded.
    pre_client.write_all(b"old").unwrap();
    assert!(
        state(&ebpf, &pre_client).is_none(),
        "pre-agent socket has no state"
    );
    assert!(state(&ebpf, &pre_listener).is_none());
    let late = TcpStream::connect(pre_listener.local_addr().unwrap()).unwrap();
    let (late_child, _) = pre_listener.accept().unwrap();
    let lc = state(&ebpf, &late_child).expect("child of a pre-agent listener");
    assert_eq!(lc.init_cookie, cookie(&late_child));
    assert_eq!((lc.owner_tgid, lc.acceptor_tgid, lc.pid_epoch), (0, me, 77));
    drop(late);

    // connect(AF_UNSPEC): revoked for good (REUSED).
    let unspec = libc::sockaddr {
        sa_family: libc::AF_UNSPEC as u16,
        sa_data: [0; 14],
    };
    // SAFETY: valid fd and sockaddr.
    let rc = unsafe {
        libc::connect(
            client.as_raw_fd(),
            &unspec,
            std::mem::size_of::<libc::sockaddr>() as u32,
        )
    };
    assert_eq!(rc, 0, "connect(AF_UNSPEC)");
    let cs = state(&ebpf, &client).unwrap();
    assert_eq!(cs.init_cookie, 0, "STATE_CB revoked at TCP_CLOSE");
    assert_ne!(cs.flags & FLAG_REUSED, 0);
    let ev = drain(&mut ring);
    let _ = ev; // the SockClose record has no payload; drained only

    // ── head_only, N = 3
    set(&mut ebpf, CONFIG_HEAD_BYTES, 3);
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_HEAD);
    let mut c2 = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut s2, _) = listener.accept().unwrap();
    let cut0 = drops(&ebpf, DROP_HEAD_CUT);
    c2.write_all(b"hello").unwrap();
    let _ = s2.read(&mut buf).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    c2.write_all(b"more").unwrap();
    let _ = s2.read(&mut buf).unwrap();
    let ev = drain(&mut ring);
    let mine: Vec<_> = ev.iter().filter(|e| e.0 == cookie(&c2)).collect();
    assert_eq!(mine.len(), 1, "one head event, the rest cut: {ev:?}");
    assert_eq!((mine[0].2, mine[0].3.as_slice()), (0, &b"hel"[..]));
    assert!(drops(&ebpf, DROP_HEAD_CUT) >= cut0 + 2, "cut counted");

    // UDP: the budget is reserved per socket and direction (fetch-add).
    let ru = UdpSocket::bind("127.0.0.1:0").unwrap();
    let su = UdpSocket::bind("127.0.0.1:0").unwrap();
    su.connect(ru.local_addr().unwrap()).unwrap();
    for d in [&b"ab"[..], b"cd", b"ef"] {
        su.send(d).unwrap();
        let _ = ru.recv(&mut buf).unwrap();
    }
    let us = state(&ebpf, &su).expect("udp state");
    assert_eq!(
        us.init_cookie,
        cookie(&su),
        "UDP initialised at sock_create"
    );
    assert_eq!(us.udp_sent, 4, "the counter stops once it holds N");
    let ev = drain(&mut ring);
    let sent: Vec<_> = ev
        .iter()
        .filter(|e| e.0 == cookie(&su))
        .map(|e| (e.2, e.3.clone()))
        .collect();
    assert_eq!(
        sent,
        vec![(0, b"ab".to_vec()), (2, b"c".to_vec())],
        "{ev:?}"
    );

    // ── pid_filter: this process unlisted, then listed (new sockets)
    set(&mut ebpf, CONFIG_HEAD_BYTES, 0);
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_SEL_PID);
    let oos0 = drops(&ebpf, DROP_OUT_OF_SCOPE);
    let mut c3 = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut s3, _) = listener.accept().unwrap();
    c3.write_all(b"x").unwrap();
    let _ = s3.read(&mut buf).unwrap();
    assert!(
        drops(&ebpf, DROP_OUT_OF_SCOPE) >= oos0 + 2,
        "unlisted: out_of_scope"
    );

    // ── pre-agent listeners (§3.1): initialised at arm with their owner
    // iff every holder is listed; a child of one is in scope from its first
    // byte, before any accept()
    let getfd = candidates_pidfd;
    if getfd {
        let la_fd = fd_of(holder_pid, 100);
        let ls = state(&ebpf, &la_fd).expect("LA initialised at arm");
        assert_eq!(
            (ls.owner_tgid, ls.pid_bits, ls.pid_epoch, ls.init_cookie),
            (holder_pid, OWNER_LISTED, 77, 0),
            "LA owner: its only holder"
        );
        let lb_fd = fd_of(holder_pid, 101);
        assert!(
            state(&ebpf, &lb_fd).is_none(),
            "LB, also held by an unlisted process: not initialised"
        );
    }
    let no0 = drops(&ebpf, DROP_NO_OWNER);
    let mut ca = TcpStream::connect(("127.0.0.1", la_port)).unwrap();
    let mut cb = TcpStream::connect(lb.local_addr().unwrap()).unwrap();
    ca.write_all(b"preLA").unwrap();
    cb.write_all(b"preLB").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let ev = drain(&mut ring);
    let la_in = ev
        .iter()
        .any(|e| e.1 == Direction::Ingress && e.3 == b"preLA");
    println!("LISTENER_INIT pidfd_getfd={getfd} la_captured={la_in}");
    assert_eq!(la_in, getfd, "LA's child in scope before accept: {ev:?}");
    assert!(
        !ev.iter().any(|e| e.3 == b"preLB"),
        "LB's child not in scope before accept: {ev:?}"
    );
    assert!(drops(&ebpf, DROP_NO_OWNER) > no0, "LB's child: no_owner");
    drop((ca, cb));
    holder.kill().unwrap();
    holder.wait().unwrap();
    {
        let mut pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("PID_FILTER").unwrap()).unwrap();
        pids.insert(me, 1, 0).unwrap();
    }
    let mut c4 = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut s4, _) = listener.accept().unwrap();
    c4.write_all(b"listed").unwrap();
    let _ = s4.read(&mut buf).unwrap();
    let ev = drain(&mut ring);
    assert!(
        ev.iter()
            .any(|e| e.0 == cookie(&c4) && e.2 == 0 && e.3 == b"listed"),
        "listed creator: captured, with its offset outside head_only: {ev:?}"
    );
    assert!(
        !ev.iter().any(|e| e.0 == cookie(&c3)),
        "old verdict stays OUT"
    );

    // ── accept() before PASSIVE_ESTABLISHED (§3.1): a child is queued for
    // accept before its ESTABLISHED callback runs, so a spinning accept can
    // return it first. Whatever the order, it keeps its listed acceptor.
    // `listener`: owner unlisted (state cloned); `pre_listener`: no state.
    for (name, l) in [("cloned", &listener), ("no_state", &pre_listener)] {
        let addr = l.local_addr().unwrap();
        l.set_nonblocking(true).unwrap();
        let (mut first, mut lost, mut total) = (0, 0, 0);
        for _ in 0..8 {
            let n = 250;
            let dial = std::thread::spawn(move || {
                (0..n)
                    .map(|_| TcpStream::connect(addr).unwrap())
                    .collect::<Vec<_>>()
            });
            let mut kids = Vec::new();
            while kids.len() < n {
                match l.accept() {
                    Ok((k, _)) => {
                        if state(&ebpf, &k).is_none_or(|s| s.init_cookie != cookie(&k)) {
                            first += 1;
                        }
                        kids.push(k);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::hint::spin_loop(),
                    Err(e) => panic!("accept: {e}"),
                }
            }
            let clients = dial.join().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            for k in &kids {
                let ok = state(&ebpf, k).is_some_and(|s| {
                    s.init_cookie == cookie(k)
                        && s.acceptor_tgid == me
                        && s.accept_cookie == cookie(k)
                        && s.pid_bits & ACCEPTOR_LISTED != 0
                });
                lost += !ok as u32;
            }
            total += n;
            drop((kids, clients));
        }
        l.set_nonblocking(false).unwrap();
        println!("ACCEPT_RACE {name} accept_first={first} of {total} lost={lost}");
        assert_eq!(lost, 0, "{name}: children that lost their acceptor");
    }
    let _ = drain(&mut ring);

    // A listener that carries another socket's acceptor (an accepted socket
    // that reached TCP_CLOSE without REUSED, then listen()): its children
    // are never initialised.
    {
        let l0 = TcpListener::bind("127.0.0.1:0").unwrap();
        let _c0 = TcpStream::connect(l0.local_addr().unwrap()).unwrap();
        let (s0, _) = l0.accept().unwrap();
        drop(l0);
        let unspec = libc::sockaddr {
            sa_family: libc::AF_UNSPEC as u16,
            sa_data: [0; 14],
        };
        // SAFETY: valid fd and sockaddr.
        let rc = unsafe {
            libc::connect(
                s0.as_raw_fd(),
                &unspec,
                std::mem::size_of::<libc::sockaddr>() as u32,
            )
        };
        assert_eq!(rc, 0, "connect(AF_UNSPEC)");
        let mut st = state(&ebpf, &s0).unwrap();
        assert_eq!((st.acceptor_tgid, st.accept_cookie), (me, cookie(&s0)));
        st.flags &= !FLAG_REUSED; // as if STATE_CB had never been set
        {
            let mut map: SkStorage<&mut MapData, SockState> =
                SkStorage::try_from(ebpf.map_mut("SOCK_STATE").unwrap()).unwrap();
            map.insert(&s0, st, 0).unwrap();
        }
        // SAFETY: valid fd.
        if unsafe { libc::listen(s0.as_raw_fd(), 8) } != 0 {
            println!("RELISTEN skipped ({})", std::io::Error::last_os_error());
        } else {
            // SAFETY: valid fd and out-pointers.
            let port = unsafe {
                let mut a: libc::sockaddr_in = std::mem::zeroed();
                let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
                libc::getsockname(s0.as_raw_fd(), (&raw mut a).cast(), &mut len);
                u16::from_be(a.sin_port)
            };
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.write_all(b"relisten").unwrap();
            // SAFETY: valid listening fd; the result is a new fd we own.
            let k = unsafe {
                use std::os::fd::FromRawFd;
                let fd = libc::accept(s0.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut());
                assert!(fd >= 0, "accept on the re-listened socket");
                std::os::fd::OwnedFd::from_raw_fd(fd)
            };
            let ks = state(&ebpf, &k).expect("clone");
            assert_ne!(
                ks.init_cookie,
                cookie(&k),
                "foreign acceptor: never initialised"
            );
            assert!(
                !drain(&mut ring).iter().any(|e| e.0 == cookie(&k)),
                "nothing captured on it"
            );
            println!("RELISTEN OK");
        }
    }

    // ── TLS addresses (restricted): an address belongs to one OpenSSL call
    // and only to an in-scope socket of that call (tls_probes.rs TLS_CALL)
    // SAFETY: gettid has no preconditions.
    let pid_tgid = ((me as u64) << 32) | unsafe { libc::gettid() } as u64;
    let fentry_link = {
        let p: &mut aya::programs::FEntry = ebpf
            .program_mut("tls_tcp_sendmsg_scoped")
            .unwrap()
            .try_into()
            .unwrap();
        p.attach().expect("tls_tcp_sendmsg_scoped attaches")
    };
    // A call slot as an entry probe opens it, socket I/O inside the call,
    // then the slot as the return probe would consume it.
    let call = |ebpf: &mut Ebpf, conn: u64, socks: &mut [&mut TcpStream]| -> [u64; 9] {
        set_active(ebpf, [pid_tgid, conn]);
        let mut slots: HashMap<_, u64, [u64; 9]> =
            HashMap::try_from(ebpf.map_mut("TLS_CALL").unwrap()).unwrap();
        slots
            .insert(pid_tgid, [conn, 0, 0, 0, 0, 0, 0, 0, 0], 0)
            .unwrap();
        for s in socks.iter_mut() {
            s.write_all(b"t").unwrap();
        }
        let got = slots.get(&pid_tgid, 0).unwrap();
        slots.remove(&pid_tgid).unwrap();
        got
    };
    // TlsCall: conn, buf, len, aux, cookie, entry_sp, tuple (12 bytes),
    // state, scope_gen
    let state = |c: &[u64; 9]| c[7] >> 32;
    let c4_port = c4.local_addr().unwrap().port() as u64;
    let c = call(&mut ebpf, 0x7001, &mut [&mut c4]);
    assert_eq!(
        (state(&c), c[4], c[7] & 0xffff, c[8] as u32),
        (1, cookie(&c4), c4_port, 1)
    );
    let c = call(&mut ebpf, 0x7001, &mut [&mut c3]);
    assert_eq!(state(&c), 2, "same SSL*, next call on an OUT socket: none");
    let c = call(&mut ebpf, 0x7002, &mut [&mut c4, &mut c3]);
    assert_eq!(state(&c), 2, "a second socket in one call poisons it");
    let c = call(&mut ebpf, 0x7003, &mut [&mut pre_client]);
    assert_eq!(state(&c), 2, "socket without state");
    set(&mut ebpf, CONFIG_SCOPE_GEN, 2);
    let c = call(&mut ebpf, 0x7004, &mut [&mut c4]);
    assert_eq!(state(&c), 2, "verdict cached under an older generation");
    let c = call(&mut ebpf, 0x7005, &mut [&mut c4]); // its packet recomputed it
    assert_eq!((state(&c), c[7] & 0xffff, c[8] as u32), (1, c4_port, 2));

    // End to end through the real write probes, on a stand-in SSL_write in
    // this binary: emitted at return, with only that call's address.
    let mut uprobe_links = Vec::new();
    for prog in ["ssl_write_ret", "ssl_write_entry"] {
        let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
        let link = p
            .attach("panop_test_ssl_write", "/proc/self/exe", Some(me))
            .unwrap_or_else(|e| panic!("{prog} attaches: {e}"));
        uprobe_links.push((prog, link));
    }
    {
        let p: &mut aya::programs::UProbe = ebpf
            .program_mut("ssl_write_entry")
            .unwrap()
            .try_into()
            .unwrap();
        let link = p
            .attach(
                "panop_test_ssl_write_entry_only",
                "/proc/self/exe",
                Some(me),
            )
            .unwrap();
        uprobe_links.push(("ssl_write_entry", link));
    }
    let _ = drain(&mut ring);
    let write =
        std::hint::black_box(panop_test_ssl_write as extern "C" fn(u64, *const u8, i32) -> i32);
    let ssl = 0x5000u64;
    TEST_FD.store(c4.as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    assert_eq!(write(ssl, b"tls-in".as_ptr(), 6), 6);
    TEST_FD.store(c3.as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    assert_eq!(write(ssl, b"tls-out".as_ptr(), 7), 7);
    let tls = drain_tls(&mut ring);
    let find = |p: &[u8]| {
        *tls.iter()
            .find(|e| e.payload_bytes() == p)
            .unwrap_or_else(|| panic!("TLS event {p:?} emitted"))
    };
    let e = find(b"tls-in");
    assert_eq!(e.socket_cookie, ssl);
    assert_eq!(
        (e.src_addr, e.src_port as u64, e.dst_port),
        (0x7f00_0001, c4_port, listener.local_addr().unwrap().port()),
        "the call's own in-scope socket"
    );
    let e = find(b"tls-out");
    assert_eq!(
        (e.src_addr, e.dst_addr, e.src_port, e.dst_port, e.ip_proto),
        (0, 0, 0, 0, 0),
        "same SSL*, OUT socket: no address, none carried over"
    );

    // A narrowing between the socket check and the emission: the call is
    // still in scope (pid_filter), under the new generation, so the tuple
    // checked under the old one is not emitted.
    let config_id = match ebpf.map("CONFIG").unwrap() {
        aya::maps::Map::Array(d) => d.info().unwrap().id(),
        _ => unreachable!(),
    };
    let mut cfg2: Array<MapData, u64> =
        Array::try_from(aya::maps::Map::Array(MapData::from_id(config_id).unwrap())).unwrap();
    *TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
        let g = cfg2.get(&CONFIG_SCOPE_GEN, 0).unwrap();
        cfg2.set(CONFIG_SCOPE_GEN, g + 1, 0).unwrap();
    }));
    TEST_FD.store(c4.as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    assert_eq!(write(ssl, b"tls-narrowed".as_ptr(), 12), 12);
    // An inner call whose return probe never runs replaces the slot: the
    // outer return finds another frame's slot and emits nothing from it.
    *TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
        let inner = std::hint::black_box(
            panop_test_ssl_write_entry_only as extern "C" fn(u64, *const u8, i32) -> i32,
        );
        inner(ssl, b"inner!".as_ptr(), 6);
    }));
    assert_eq!(write(ssl, b"tls-outer".as_ptr(), 9), 9);
    *TEST_HOOK.lock().unwrap() = None;
    // And the next ordinary call is whole again.
    assert_eq!(write(ssl, b"tls-again".as_ptr(), 9), 9);
    let tls = drain_tls(&mut ring);
    let find = |p: &[u8]| tls.iter().find(|e| e.payload_bytes() == p).copied();
    let e = find(b"tls-narrowed").expect("narrowed call still emitted");
    assert_eq!(
        (e.src_addr, e.src_port, e.scope_gen),
        (0, 0, 3),
        "checked under 2, emitted under 3: no address"
    );
    assert!(
        find(b"tls-outer").is_none(),
        "mismatched frame: nothing emitted"
    );
    assert!(
        find(b"inner!").is_none(),
        "the inner slot's buffer is not emitted"
    );
    let e = find(b"tls-again").expect("next call emitted");
    assert_eq!(e.src_port as u64, c4_port, "next call has its own address");

    // ── capture off (the user switch, the fatal stop) or not armed: the TLS
    // probes collect nothing. No call slot during the call, no address, no
    // event; the first call of each pair is the control that would see one.
    let slots_id = map_id(&ebpf, "TLS_CALL");
    *TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
        let slots: HashMap<MapData, u64, [u64; 9]> =
            HashMap::try_from(aya::maps::Map::HashMap(MapData::from_id(slots_id).unwrap()))
                .unwrap();
        if slots.get(&pid_tgid, 0).is_ok() {
            SLOT_SEEN.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }));
    let seen = || SLOT_SEEN.swap(false, std::sync::atomic::Ordering::SeqCst);
    let slot_left = |ebpf: &Ebpf| {
        let m: HashMap<_, u64, [u64; 9]> =
            HashMap::try_from(ebpf.map("TLS_CALL").unwrap()).unwrap();
        m.get(&pid_tgid, 0).is_ok()
    };
    let conn_addr = |ebpf: &Ebpf| {
        let m: HashMap<_, [u64; 2], [u32; 3]> =
            HashMap::try_from(ebpf.map("TLS_CONN_ADDR").unwrap()).unwrap();
        m.get(&[ssl, me as u64], 0).is_ok()
    };
    let emitted = |ring: &mut RingBuf<MapData>, p: &[u8]| {
        drain_tls(ring).iter().any(|e| e.payload_bytes() == p)
    };
    let _ = drain(&mut ring);
    seen();
    assert_eq!(write(ssl, b"tls-on".as_ptr(), 6), 6);
    assert!(
        seen() && emitted(&mut ring, b"tls-on"),
        "control: slot, event"
    );
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 0);
    assert_eq!(write(ssl, b"tls-off".as_ptr(), 7), 7);
    assert!(!seen(), "capture off: no call slot");
    assert!(
        !slot_left(&ebpf) && !emitted(&mut ring, b"tls-off"),
        "capture off"
    );
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    set(&mut ebpf, CONFIG_SCOPE_ARMED, 0);
    assert_eq!(write(ssl, b"tls-unarmed".as_ptr(), 11), 11);
    assert!(!seen(), "restricted, not armed: no call slot");
    assert!(
        !slot_left(&ebpf) && !emitted(&mut ring, b"tls-unarmed"),
        "restricted, not armed"
    );
    set(&mut ebpf, CONFIG_SCOPE_ARMED, 1);
    // Unscoped full (as on TC): the address cache path, and arming does not
    // apply there.
    let full_link = {
        let p: &mut aya::programs::FEntry = ebpf
            .program_mut("tls_tcp_sendmsg_fentry")
            .unwrap()
            .try_into()
            .unwrap();
        p.attach().expect("tls_tcp_sendmsg_fentry attaches")
    };
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 0);
    assert_eq!(write(ssl, b"tls-full-off".as_ptr(), 12), 12);
    assert!(!conn_addr(&ebpf), "capture off: no TLS_CONN_ADDR entry");
    assert!(
        !emitted(&mut ring, b"tls-full-off"),
        "capture off: no event"
    );
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    set(&mut ebpf, CONFIG_SCOPE_ARMED, 0);
    assert_eq!(write(ssl, b"tls-full-on".as_ptr(), 11), 11);
    assert!(
        emitted(&mut ring, b"tls-full-on"),
        "unscoped: not gated by arming"
    );
    assert!(conn_addr(&ebpf), "control: unscoped address recorded");
    set(&mut ebpf, CONFIG_SCOPE_ARMED, 1);
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_SEL_PID);
    let p: &mut aya::programs::FEntry = ebpf
        .program_mut("tls_tcp_sendmsg_fentry")
        .unwrap()
        .try_into()
        .unwrap();
    p.detach(full_link).unwrap();
    println!("TLS_DISARM OK");

    // ── in flight: a call opened while capture is on, then capture off (or
    // the scope disarmed) before its socket I/O and return. No address is
    // filled, no event is emitted, and the call's saved state is removed.
    use std::sync::atomic::Ordering::SeqCst;
    let cfg_id = map_id(&ebpf, "CONFIG");
    let pre = |set_to: Option<(u32, u64)>| {
        *PRE_HOOK.lock().unwrap() = set_to.map(|(index, v)| -> Hook {
            Box::new(move || {
                let mut c: Array<MapData, u64> =
                    Array::try_from(aya::maps::Map::Array(MapData::from_id(cfg_id).unwrap()))
                        .unwrap();
                c.set(index, v, 0).unwrap();
            })
        });
    };
    *TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
        let slots: HashMap<MapData, u64, [u64; 9]> =
            HashMap::try_from(aya::maps::Map::HashMap(MapData::from_id(slots_id).unwrap()))
                .unwrap();
        let st = slots.get(&pid_tgid, 0).map_or(0, |c| (c[7] >> 32) + 1);
        SLOT_STATE.store(st, SeqCst);
    }));
    let scratch_left = |ebpf: &Ebpf| {
        let m: HashMap<_, u64, [u64; 4]> =
            HashMap::try_from(ebpf.map("TLS_SCRATCH").unwrap()).unwrap();
        m.get(&pid_tgid, 0).is_ok()
    };
    let stops = [
        (CONFIG_CAPTURE_ENABLED, "capture off"),
        (CONFIG_SCOPE_ARMED, "disarmed"),
    ];
    TEST_FD.store(c4.as_raw_fd(), SeqCst);
    // writes (restricted): control fills, in-flight stops do not
    assert_eq!(write(ssl, b"w-on".as_ptr(), 4), 4);
    assert_eq!(SLOT_STATE.swap(0, SeqCst), 2, "control: slot filled");
    assert!(emitted(&mut ring, b"w-on"), "control: write emitted");
    for (index, what) in stops {
        pre(Some((index, 0)));
        assert_eq!(write(ssl, b"w-stop".as_ptr(), 6), 6);
        pre(None);
        set(&mut ebpf, index, 1);
        assert_eq!(
            SLOT_STATE.swap(0, SeqCst),
            1,
            "{what}: slot opened, never filled"
        );
        assert!(!slot_left(&ebpf), "{what}: slot removed at return");
        assert!(!emitted(&mut ring, b"w-stop"), "{what}: no write event");
    }
    // reads: stand-in SSL_read with the read probes and the scoped
    // receive fentry
    let mut read_links = Vec::new();
    for prog in ["ssl_read_ret", "ssl_read_entry"] {
        let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
        let link = p
            .attach("panop_test_ssl_read", "/proc/self/exe", Some(me))
            .unwrap_or_else(|e| panic!("{prog} attaches: {e}"));
        read_links.push((prog, link));
    }
    let recv_link = {
        let p: &mut aya::programs::FEntry = ebpf
            .program_mut("tls_tcp_recvmsg_scoped")
            .unwrap()
            .try_into()
            .unwrap();
        p.attach().expect("tls_tcp_recvmsg_scoped attaches")
    };
    let read = std::hint::black_box(panop_test_ssl_read as extern "C" fn(u64, *mut u8, i32) -> i32);
    let mut rbuf = [0u8; 64];
    let mut read_once = |s4: &mut TcpStream, payload: &[u8]| {
        s4.write_all(payload).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(read(ssl, rbuf.as_mut_ptr(), 64), payload.len() as i32);
    };
    let _ = drain(&mut ring);
    read_once(&mut s4, b"r-on");
    assert_eq!(SLOT_STATE.swap(0, SeqCst), 2, "control: read slot filled");
    let tls = drain_tls(&mut ring);
    let e = tls
        .iter()
        .find(|e| e.payload_bytes() == b"r-on")
        .expect("control: read emitted");
    assert_eq!(
        (e.direction, e.dst_port as u64),
        (Direction::Ingress, c4_port),
        "control: read carries its own address"
    );
    for (index, what) in stops {
        pre(Some((index, 0)));
        read_once(&mut s4, b"r-stop");
        pre(None);
        set(&mut ebpf, index, 1);
        assert_eq!(
            SLOT_STATE.swap(0, SeqCst),
            1,
            "{what}: read slot never filled"
        );
        assert!(!slot_left(&ebpf), "{what}: read slot removed at return");
        assert!(!emitted(&mut ring, b"r-stop"), "{what}: no read event");
    }
    // unscoped reads keep their arguments in TLS_SCRATCH
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);
    read_once(&mut s4, b"r-full");
    assert!(
        emitted(&mut ring, b"r-full"),
        "control: unscoped read emitted"
    );
    assert!(!scratch_left(&ebpf), "control: scratch removed at return");
    pre(Some((CONFIG_CAPTURE_ENABLED, 0)));
    read_once(&mut s4, b"r-full-stop");
    pre(None);
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    assert!(
        !emitted(&mut ring, b"r-full-stop"),
        "capture off: no unscoped read event"
    );
    assert!(
        !scratch_left(&ebpf),
        "capture off: scratch removed at return"
    );
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_SEL_PID);
    // address probes with an independently seeded marker
    let full_link = {
        let p: &mut aya::programs::FEntry = ebpf
            .program_mut("tls_tcp_sendmsg_fentry")
            .unwrap()
            .try_into()
            .unwrap();
        p.attach().expect("tls_tcp_sendmsg_fentry attaches")
    };
    let conn_addr_of = |ebpf: &Ebpf, conn: u64| {
        let m: HashMap<_, [u64; 2], [u32; 3]> =
            HashMap::try_from(ebpf.map("TLS_CONN_ADDR").unwrap()).unwrap();
        m.get(&[conn, me as u64], 0).is_ok()
    };
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 0);
    set_active(&mut ebpf, [pid_tgid, 0x6001]);
    c4.write_all(b"m").unwrap();
    assert!(
        !conn_addr_of(&ebpf, 0x6001),
        "capture off: unscoped probe records nothing"
    );
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    set_active(&mut ebpf, [pid_tgid, 0x6002]);
    c4.write_all(b"m").unwrap();
    assert!(
        conn_addr_of(&ebpf, 0x6002),
        "control: unscoped probe records"
    );
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_SEL_PID);
    let p: &mut aya::programs::FEntry = ebpf
        .program_mut("tls_tcp_sendmsg_fentry")
        .unwrap()
        .try_into()
        .unwrap();
    p.detach(full_link).unwrap();
    for (index, what) in stops {
        set(&mut ebpf, index, 0);
        let c = call(&mut ebpf, 0x6003, &mut [&mut c4]);
        set(&mut ebpf, index, 1);
        assert_eq!(state(&c), 0, "{what}: scoped probe fills nothing");
    }
    let c = call(&mut ebpf, 0x6004, &mut [&mut c4]);
    assert_eq!(state(&c), 1, "control: scoped probe fills");
    for (prog, link) in read_links {
        let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
        p.detach(link).unwrap();
    }
    let p: &mut aya::programs::FEntry = ebpf
        .program_mut("tls_tcp_recvmsg_scoped")
        .unwrap()
        .try_into()
        .unwrap();
    p.detach(recv_link).unwrap();
    println!("TLS_INFLIGHT OK");
    *TEST_HOOK.lock().unwrap() = None;
    for (prog, link) in uprobe_links {
        let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
        p.detach(link).unwrap();
    }
    let p: &mut aya::programs::FEntry = ebpf
        .program_mut("tls_tcp_sendmsg_scoped")
        .unwrap()
        .try_into()
        .unwrap();
    p.detach(fentry_link).unwrap();
    set_active(&mut ebpf, [0, 0]);
    let _ = drain(&mut ring);
    println!("TLS_ADDR scoped=OK");

    // ── a selected process exits; its pid is reused by another process
    sel.kill().unwrap();
    sel.wait().unwrap();
    assert!(!pid_listed(&ebpf, sel_pid), "exit removed the pid");
    {
        // Unlist this process, so the server side below is out of scope too.
        let mut pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("PID_FILTER").unwrap()).unwrap();
        pids.remove(&me).unwrap();
    }
    let rl = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = rl.local_addr().unwrap().port();
    rl.set_nonblocking(true).unwrap();
    let reused = spawn_with_pid(sel_pid, port, "reuse");
    println!("PID_REUSE reused={reused}");
    assert!(reused, "could not reuse pid {sel_pid}");
    let mut got = Vec::new();
    while let Ok((mut c, _)) = rl.accept() {
        c.set_nonblocking(false).unwrap();
        let mut b = Vec::new();
        let _ = c.read_to_end(&mut b);
        got.extend(b);
    }
    assert!(
        got.ends_with(b"reuse"),
        "the reusing process connected: {got:?}"
    );
    let ev = drain(&mut ring);
    assert!(
        !ev.iter().any(|e| e.3.as_slice() == b"reuse"),
        "a reused pid is not selected: {ev:?}"
    );

    for r in 0..SCOPE_DROP_REASONS {
        println!("DROPS {} {}", SCOPE_DROP_NAMES[r as usize], drops(&ebpf, r));
    }
    drop(links);
    println!("RUNTIME OK");
}
