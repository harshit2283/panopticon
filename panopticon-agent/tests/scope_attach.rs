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

#[path = "../src/platform/go_read.rs"]
#[allow(dead_code)]
mod go_read;

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

/// One lab test at a time: each attaches node-wide programs.
static LAB: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

/// Stand-in for OpenSSL's `SSL_new(ctx)`: returns the object address,
/// after writing on it first when `io` is set (a creation callback).
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn panop_test_ssl_new(obj: u64, io: u64) -> u64 {
    if std::hint::black_box(io) != 0 {
        panop_test_ssl_write(obj, b"in-new".as_ptr(), 6);
    }
    std::hint::black_box(obj)
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

/// Drain ring 0: every event with its record's length in the ring.
fn drain_records(ring: &mut RingBuf<MapData>) -> Vec<(DataEvent, usize)> {
    let mut out = Vec::new();
    while let Some(item) = ring.next() {
        // SAFETY: all-zero is a valid DataEvent.
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        if read_data_event_into(&item, &mut e) {
            out.push((e, item.len()));
        }
    }
    out
}

/// Drain ring 0: every record's raw bytes, as published.
fn drain_raw(ring: &mut RingBuf<MapData>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(item) = ring.next() {
        out.push(item.to_vec());
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

fn ip_cmd(args: &str) -> bool {
    std::process::Command::new("ip")
        .args(args.split(' '))
        .status()
        .is_ok_and(|s| s.success())
}

fn ifindex_of(dev: &str) -> u32 {
    let n = std::ffi::CString::new(dev).unwrap();
    // SAFETY: a valid C string.
    let i = unsafe { libc::if_nametoindex(n.as_ptr()) };
    assert_ne!(i, 0, "{dev} has an ifindex");
    i
}

/// The devices and namespaces this test creates. Removed at start (a run
/// that panicked may have left them) and by [`LabGuard`] at the end, panic
/// included.
const LAB_LINKS: [&str; 5] = ["pvd0", "pvrf", "pnlo0", "pvfull", "pmc0"];
const LAB_NETNS: [&str; 4] = ["pnlo", "pnvrf", "pntask", "pnprobe"];

fn lab_cleanup() {
    for l in LAB_LINKS {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", l])
            .stderr(std::process::Stdio::null())
            .status();
    }
    for n in LAB_NETNS {
        let _ = std::process::Command::new("ip")
            .args(["netns", "del", n])
            .stderr(std::process::Stdio::null())
            .status();
    }
}

const L3MDEV_ACCEPT: &str = "/proc/sys/net/ipv4/udp_l3mdev_accept";

/// Cleans up on drop, panic included, and restores `udp_l3mdev_accept`.
struct LabGuard(Option<String>);

impl LabGuard {
    fn new() -> Self {
        lab_cleanup();
        Self(std::fs::read_to_string(L3MDEV_ACCEPT).ok())
    }
}

impl Drop for LabGuard {
    fn drop(&mut self) {
        lab_cleanup();
        if let Some(v) = &self.0 {
            let _ = std::fs::write(L3MDEV_ACCEPT, v.trim());
        }
    }
}

/// An IPv4 socket of `ty`, bound to `dev` if given.
fn bound(ty: i32, dev: Option<&str>) -> socket2::Socket {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::from(ty), None).unwrap();
    s.bind_device(dev.map(str::as_bytes)).unwrap();
    s
}

/// One datagram from `tx` (unbound) to `to`, routed in the VRF whose
/// master is `ifindex` (IP_PKTINFO `ipi_ifindex`).
fn send_pktinfo(tx: &UdpSocket, to: std::net::SocketAddr, ifindex: u32, msg: &[u8]) {
    let std::net::SocketAddr::V4(to) = to else {
        unreachable!()
    };
    let mut dst = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: to.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(*to.ip()).to_be(),
        },
        sin_zero: [0; 8],
    };
    let info = libc::in_pktinfo {
        ipi_ifindex: ifindex as i32,
        ipi_spec_dst: libc::in_addr { s_addr: 0 },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    // SAFETY: CMSG_SPACE of a plain struct size.
    let space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    let mut iov = libc::iovec {
        iov_base: msg.as_ptr() as *mut _,
        iov_len: msg.len(),
    };
    // SAFETY: all-zero msghdr is valid; fields set below.
    let mut mh: libc::msghdr = unsafe { std::mem::zeroed() };
    mh.msg_name = (&mut dst as *mut libc::sockaddr_in).cast();
    mh.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
    mh.msg_iov = &mut iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cbuf.as_mut_ptr().cast();
    mh.msg_controllen = space as _;
    // SAFETY: the control buffer holds one cmsg of in_pktinfo.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&mh);
        (*c).cmsg_level = libc::IPPROTO_IP;
        (*c).cmsg_type = libc::IP_PKTINFO;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast(), info);
        assert_eq!(
            libc::sendmsg(tx.as_raw_fd(), &mh, 0),
            msg.len() as isize,
            "sendmsg IP_PKTINFO"
        );
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
    let _lab = LAB.lock().unwrap_or_else(|e| e.into_inner());
    let _links = LabGuard::new();
    // A VRF that exists before the programs load: classification is per
    // packet, from the device it is on, so when the VRF was created does
    // not matter (§3.7). A kernel without the vrf module (Ubuntu cloud
    // kernels without modules-extra) skips the VRF cases, saying so.
    let vrf_ok = ip_cmd("link add pvrf type vrf table 211");
    if vrf_ok {
        assert!(
            ip_cmd("link set pvrf up")
                && ip_cmd("link add pvd0 type dummy")
                && ip_cmd("link set pvd0 master pvrf")
                && ip_cmd("addr add 10.212.0.1/24 dev pvd0")
                && ip_cmd("link set pvd0 up"),
            "VRF pvrf with pvd0"
        );
    }
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
    // The checks below run on loopback: capture it (capture_loopback =
    // true) until the loopback section turns it off. The listener rule
    // stays the default (acceptor) until its own section.
    set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 1);
    set(&mut ebpf, CONFIG_PID_CREATOR_RULE, 0);
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
    let pids = [sel_pid, gone_pid, early_pid, late_pid, p_pid];
    let candidates = snapshot_candidates(&pids);
    let pidfd = candidates[0].pidfd.is_some();
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
    let _ = drain(&mut ring);
    // A socket that never had a packet record emitted sends no close.
    let late_cookie = cookie(&late);
    assert_eq!(state(&ebpf, &late).map(|s| s.emitted), Some(0));
    drop(late);
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(
        !drain_records(&mut ring)
            .iter()
            .any(|(e, _)| e.socket_cookie == late_cookie),
        "no record for a socket that carried no data"
    );

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
    // The client carried data: its close is sent, as the header only.
    assert_eq!(cs.emitted, 1);
    let closes: Vec<_> = drain_records(&mut ring)
        .into_iter()
        .filter(|(e, _)| e.event_type == EventType::SockClose)
        .collect();
    assert!(
        closes
            .iter()
            .any(|(e, n)| e.socket_cookie == cookie(&client) && *n == DATA_EVENT_HEADER_LEN),
        "header-only close record for the client: {:?}",
        closes
            .iter()
            .map(|(e, n)| (e.socket_cookie, *n))
            .collect::<Vec<_>>()
    );

    // Packet records are reserved at the smallest payload size class that
    // holds the captured bytes: 100 bytes go in a 128-byte class.
    let mut c3 = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut s3, _) = listener.accept().unwrap();
    c3.write_all(&[7u8; 100]).unwrap();
    let _ = s3.read(&mut buf).unwrap();
    let recs = drain_records(&mut ring);
    assert!(
        recs.iter().any(|(e, n)| e.socket_cookie == cookie(&c3)
            && e.payload_bytes() == [7u8; 100]
            && *n == DATA_EVENT_HEADER_LEN + 128),
        "100-byte packet in a 128-byte class: {:?}",
        recs.iter()
            .map(|(e, n)| (e.socket_cookie, e.payload_len, *n))
            .collect::<Vec<_>>()
    );
    drop((c3, s3));

    // Capture stopped (the fatal disarm clears CAPTURE_ENABLED and leaves
    // the generation and cached verdicts as they were): a socket that
    // carried data sends no close record.
    let mut c5 = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut s5, _) = listener.accept().unwrap();
    c5.write_all(b"before-stop").unwrap();
    let _ = s5.read(&mut buf).unwrap();
    assert_eq!(state(&ebpf, &c5).map(|s| s.emitted), Some(1));
    let c5_cookie = cookie(&c5);
    let _ = drain_records(&mut ring);
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 0);
    drop((c5, s5));
    std::thread::sleep(std::time::Duration::from_millis(20));
    let after_stop = drain_records(&mut ring);
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    assert!(
        !after_stop.iter().any(|(e, _)| e.socket_cookie == c5_cookie),
        "no close record once capture is stopped"
    );
    println!("CLOSE_AFTER_STOP OK");

    // Every published byte of a record is written: once the ring has wrapped
    // over records full of 0xAB, small records (a 64-byte class with 5
    // bytes, a 128-byte class with 100) carry zeros past their payload, as
    // do close records and every other record seen.
    let mut c4 = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut s4, _) = listener.accept().unwrap();
    c4.set_nodelay(true).unwrap();
    let mut sink = vec![0u8; 1 << 16];
    let mut checked = 0usize;
    let mut check = |raw: Vec<Vec<u8>>| {
        for r in raw {
            let n = data_event_record_len(&r).expect("valid record");
            assert!(
                r[n..].iter().all(|&b| b == 0),
                "record of {} bytes has nonzero bytes past its payload ({n})",
                r.len()
            );
            checked += 1;
        }
    };
    for round in 0..3 {
        // ~3 MiB of 0xAB records: the 1 MiB shard wraps at least twice.
        for _ in 0..800 {
            c4.write_all(&[0xABu8; 4000]).unwrap();
            let mut got = 0;
            while got < 4000 {
                got += s4.read(&mut sink).unwrap();
            }
            check(drain_raw(&mut ring));
        }
        for len in [5usize, 100] {
            for _ in 0..50 {
                c4.write_all(&vec![round as u8 + 1; len]).unwrap();
                let mut got = 0;
                while got < len {
                    got += s4.read(&mut sink).unwrap();
                }
            }
            check(drain_raw(&mut ring));
        }
    }
    drop((c4, s4));
    std::thread::sleep(std::time::Duration::from_millis(20));
    check(drain_raw(&mut ring));
    assert!(checked > 2400, "records checked: {checked}");

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
    // that reached TCP_CLOSE without REUSED, then listen()): a listed
    // acceptor, no listed owner. Its children, accepted by an unlisted
    // process, are never initialised, and the accept hook leaves the cloned
    // acceptor untouched (rewriting `accept_cookie` first would let a
    // concurrent passive ESTABLISHED adopt the cloned ACCEPTOR_LISTED).
    // Accepts spin so some race their child's ESTABLISHED.
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
        st.pid_bits = ACCEPTOR_LISTED; // no listed owner
        let foreign = st.accept_cookie;
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
            {
                let mut pids: HashMap<_, u32, u8> =
                    HashMap::try_from(ebpf.map_mut("PID_FILTER").unwrap()).unwrap();
                pids.remove(&me).unwrap(); // the acceptor is unlisted
            }
            let dial = std::thread::spawn(move || {
                (0..64)
                    .map(|_| {
                        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
                        c.write_all(b"relisten").unwrap();
                        c
                    })
                    .collect::<Vec<_>>()
            });
            // SAFETY: valid fd.
            unsafe { libc::fcntl(s0.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
            let mut kids = Vec::new();
            while kids.len() < 64 {
                // SAFETY: valid listening fd; a non-negative result is a new fd we own.
                let fd = unsafe {
                    libc::accept(s0.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut())
                };
                if fd >= 0 {
                    // SAFETY: fd is ours.
                    kids.push(unsafe {
                        <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd)
                    });
                } else {
                    let e = std::io::Error::last_os_error();
                    assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock, "accept: {e}");
                    std::hint::spin_loop();
                }
            }
            let clients = dial.join().unwrap();
            for mut c in &clients {
                c.write_all(b"after").unwrap();
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
            let ev = drain(&mut ring);
            for k in &kids {
                let ks = state(&ebpf, k).expect("clone");
                assert_ne!(
                    ks.init_cookie,
                    cookie(k),
                    "foreign acceptor: never initialised"
                );
                assert_eq!(
                    (ks.accept_cookie, ks.acceptor_tgid, ks.pid_bits),
                    (foreign, me, ACCEPTOR_LISTED),
                    "the accept hook left the cloned acceptor untouched"
                );
                assert!(
                    !ev.iter().any(|e| e.0 == cookie(k)),
                    "nothing captured on it"
                );
            }
            {
                let mut pids: HashMap<_, u32, u8> =
                    HashMap::try_from(ebpf.map_mut("PID_FILTER").unwrap()).unwrap();
                pids.insert(me, 1, 0).unwrap();
            }
            drop((kids, clients));
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

    // ── capture_loopback (DESIGN §3.7). Off: a data packet on the loopback
    // device (127/8, the host's own address) is dropped before its verdict,
    // so none is cached. Packets only: TLS plaintext stays scoped by process
    // (a loopback socket's calls are emitted, without an address in
    // restricted modes, since no IN verdict is cached). Non-loopback traffic
    // over a veth pair into another netns (same-node pod-to-pod) is
    // captured. On (a widening): loopback captured again.
    let bump = |ebpf: &mut Ebpf| {
        let mut cfg: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").unwrap()).unwrap();
        let g = cfg.get(&CONFIG_SCOPE_GEN, 0).unwrap();
        cfg.set(CONFIG_SCOPE_GEN, g + 1, 0).unwrap();
    };
    let ip = |args: &str| {
        std::process::Command::new("ip")
            .args(args.split(' '))
            .status()
            .is_ok_and(|s| s.success())
    };
    let _ = ip("netns del pnlo");
    let _ = ip("link del pnlo0"); // left by an aborted run
    assert!(
        ip("netns add pnlo")
            && ip("link add pnlo0 type veth peer name pnlo1")
            && ip("link set pnlo1 netns pnlo")
            && ip("addr add 10.211.0.1/30 dev pnlo0")
            && ip("link set pnlo0 up")
            && ip("-n pnlo addr add 10.211.0.2/30 dev pnlo1")
            && ip("-n pnlo link set pnlo1 up"),
        "veth pair into netns pnlo"
    );
    let vl = {
        let ns = File::open("/run/netns/pnlo").unwrap();
        std::thread::spawn(move || {
            // SAFETY: setns of this thread only, to a netns fd we hold.
            assert_eq!(
                unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) },
                0
            );
            TcpListener::bind("10.211.0.2:0").unwrap()
        })
        .join()
        .unwrap()
    };
    // The host's own non-loopback address (the source toward a TEST-NET
    // address; nothing is sent).
    let own = UdpSocket::bind("0.0.0.0:0")
        .and_then(|u| {
            u.connect("192.0.2.1:9")?;
            u.local_addr()
        })
        .map(|a| a.ip())
        .ok()
        .filter(|a| !a.is_loopback() && !a.is_unspecified());
    let own_l = own.map(|a| TcpListener::bind((a, 0)).unwrap());
    println!("LOOPBACK own_address={own:?}");
    let exchange = |l: &TcpListener, msg: &[u8]| -> (TcpStream, TcpStream) {
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut s, _) = l.accept().unwrap();
        c.write_all(msg).unwrap();
        let mut b = vec![0u8; msg.len()];
        s.read_exact(&mut b).unwrap();
        (c, s)
    };
    let has = |ev: &[(u64, Direction, u64, Vec<u8>)], c: u64, m: &[u8]| {
        ev.iter().any(|e| e.0 == c && e.3 == m)
    };
    let mut pipe = [0i32; 2];
    // SAFETY: valid out-array.
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let _ = drain(&mut ring);

    set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 0);
    bump(&mut ebpf);
    let lo0 = drops(&ebpf, DROP_LOOPBACK);
    let (c5, s5) = exchange(&listener, b"lo-off");
    let own_pair = own_l.as_ref().map(|l| exchange(l, b"own-off"));
    let (cv, sv) = exchange(&vl, b"veth-off");
    let ev = drain(&mut ring);
    for c in [cookie(&c5), cookie(&s5)] {
        assert!(!ev.iter().any(|e| e.0 == c), "127/8 exported: {ev:?}");
    }
    if let Some((oc, os)) = &own_pair {
        for c in [cookie(oc), cookie(os)] {
            assert!(!ev.iter().any(|e| e.0 == c), "own address exported: {ev:?}");
        }
    }
    let lo_pkts = drops(&ebpf, DROP_LOOPBACK) - lo0;
    for f in [&c5, &s5] {
        assert_eq!(crate::state(&ebpf, f).unwrap().local, 1, "marked local");
    }
    assert_eq!(
        crate::state(&ebpf, &cv).unwrap().local,
        0,
        "veth: not local"
    );
    assert!(
        lo_pkts >= if own_pair.is_some() { 4 } else { 2 },
        "loopback data packets counted: {lo_pkts}"
    );
    assert_eq!(
        crate::state(&ebpf, &c5).unwrap().verdict_word,
        0,
        "dropped before the verdict: none cached"
    );
    assert!(
        has(&ev, cookie(&cv), b"veth-off") && has(&ev, cookie(&sv), b"veth-off"),
        "veth to another netns: both ends captured: {ev:?}"
    );
    // TLS, scoped by process only: c4 is loopback (no verdict under this
    // generation, so emitted without an address); cv is not (its packet
    // above cached IN: with its address); the pipe has no socket at all.
    let lo1 = drops(&ebpf, DROP_LOOPBACK);
    for (fd, m) in [
        (c4.as_raw_fd(), &b"tls-lo-off"[..]),
        (cv.as_raw_fd(), b"tls-veth-off"),
        (pipe[1], b"tls-pipe-off"),
    ] {
        TEST_FD.store(fd, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(write(ssl, m.as_ptr(), m.len() as i32), m.len() as i32);
    }
    let tls = drain_tls(&mut ring);
    let find = |p: &[u8]| tls.iter().find(|e| e.payload_bytes() == p).copied();
    let e = find(b"tls-lo-off").expect("TLS on a loopback socket emitted");
    assert_eq!(
        (e.src_addr, e.dst_addr, e.src_port, e.ip_proto),
        (0, 0, 0, 0),
        "no IN verdict while loopback packets are dropped: no address"
    );
    assert!(
        find(b"tls-pipe-off").is_some(),
        "TLS without an address emitted"
    );
    let e = find(b"tls-veth-off").expect("TLS on a veth socket emitted");
    assert_eq!(
        (e.src_addr, e.dst_addr, e.src_port),
        (0x0ad3_0001, 0x0ad3_0002, cv.local_addr().unwrap().port()),
        "with its own address"
    );
    assert_eq!(
        drops(&ebpf, DROP_LOOPBACK),
        lo1 + 2,
        "only c4's two data packets; no TLS event counted loopback"
    );

    // Unscoped full: the same packet rule.
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);
    let (cf, sf) = exchange(&listener, b"lo-full-off");
    let (cvf, svf) = exchange(&vl, b"veth-full-off");
    let ev = drain(&mut ring);
    assert!(
        !ev.iter().any(|e| e.0 == cookie(&cf) || e.0 == cookie(&sf)),
        "unscoped: 127/8 exported: {ev:?}"
    );
    assert!(
        has(&ev, cookie(&cvf), b"veth-full-off") && has(&ev, cookie(&svf), b"veth-full-off"),
        "unscoped: veth captured: {ev:?}"
    );
    // TLS in unscoped full: the address recorded for the connection is a
    // label only; a loopback one is emitted.
    let ssl_u = 0x5100u64;
    let key = [ssl_u as u32, (ssl_u >> 32) as u32, me, 0];
    let lo_t = [0x7f00_0001u32, 0x7f00_0001, 1 | 2 << 16];
    {
        let mut addrs: HashMap<_, [u32; 4], [u32; 3]> =
            HashMap::try_from(ebpf.map_mut("TLS_CONN_ADDR").unwrap()).unwrap();
        addrs.insert(key, lo_t, 0).unwrap();
    }
    TEST_FD.store(pipe[1], std::sync::atomic::Ordering::SeqCst);
    assert_eq!(write(ssl_u, b"tls-full-lo".as_ptr(), 11), 11);
    let tls = drain_tls(&mut ring);
    let e = tls
        .iter()
        .find(|e| e.payload_bytes() == b"tls-full-lo")
        .expect("unscoped TLS with a loopback address emitted");
    assert_eq!((e.src_addr, e.dst_addr), (0x7f00_0001, 0x7f00_0001));
    {
        let mut addrs: HashMap<_, [u32; 4], [u32; 3]> =
            HashMap::try_from(ebpf.map_mut("TLS_CONN_ADDR").unwrap()).unwrap();
        let _ = addrs.remove(&key);
    }
    // A loopback socket that emitted while loopback was captured sends no
    // close record (it carries the tuple) once loopback is off.
    set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 1);
    let (ca, sa) = exchange(&listener, b"lo-close-on");
    let control = [cookie(&ca), cookie(&sa)];
    drop((ca, sa));
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert!(
        drain_records(&mut ring).iter().any(
            |(e, _)| e.event_type == EventType::SockClose && control.contains(&e.socket_cookie)
        ),
        "control: a close record while loopback is captured"
    );
    let (cc, sc) = exchange(&listener, b"lo-close");
    let closed = [cookie(&cc), cookie(&sc)];
    set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 0);
    bump(&mut ebpf);
    drop((cc, sc));
    std::thread::sleep(std::time::Duration::from_millis(50));
    let recs = drain_records(&mut ring);
    assert!(
        recs.iter()
            .any(|(e, _)| e.event_type == EventType::TcPacket && closed.contains(&e.socket_cookie)),
        "emitted while captured"
    );
    assert!(
        !recs.iter().any(|(e, _)| e.event_type == EventType::SockClose
            && closed.contains(&e.socket_cookie)),
        "no close record once loopback is off"
    );
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_SEL_PID);

    // VRF (§3.7): every packet on a VRF master's device (`IFF_L3MDEV_MASTER`,
    // read from the packet's own `skb->dev`) is local: local delivery leaves
    // and arrives on the master whether the socket is bound to the master, to a
    // slave, or not at all. pvrf was created before the programs loaded.
    // Cases: TCP both ends bound to the master; TCP with the client bound to
    // the slave; UDP from an unbound sender that picks the VRF per datagram
    // (IP_PKTINFO), first datagram; UDP to an unbound receiver
    // (udp_l3mdev_accept = 1). Off: none exported, counted, every socket
    // marked. On: captured. TCP: no close record once off (UDP has none).
    if !vrf_ok {
        println!("LOOPBACK VRF SKIP (no vrf device type)");
    } else {
        let vrf_ifx = ifindex_of("pvrf");
        let vaddr = |port: u16| std::net::SocketAddr::from(([10, 212, 0, 1], port));
        let vrf_l = {
            let s = bound(libc::SOCK_STREAM, Some("pvrf"));
            s.bind(&vaddr(0).into()).unwrap();
            s.listen(8).unwrap();
            TcpListener::from(s)
        };
        let tcp = |dev: &str, msg: &[u8]| -> (TcpStream, TcpStream) {
            let s = bound(libc::SOCK_STREAM, Some(dev));
            s.connect(&vrf_l.local_addr().unwrap().into()).unwrap();
            let mut c = TcpStream::from(s);
            let (mut s, _) = vrf_l.accept().unwrap();
            c.write_all(msg).unwrap();
            let mut b = vec![0u8; msg.len()];
            s.read_exact(&mut b).unwrap();
            (c, s)
        };
        // UDP: a receiver bound to the master, and an unbound sender that
        // names the VRF on the datagram (IP_PKTINFO ipi_ifindex).
        let vrf_u = {
            let s = bound(libc::SOCK_DGRAM, Some("pvrf"));
            s.bind(&vaddr(0).into()).unwrap();
            UdpSocket::from(s)
        };
        let pktinfo = |msg: &[u8]| -> UdpSocket {
            let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
            send_pktinfo(&tx, vrf_u.local_addr().unwrap(), vrf_ifx, msg);
            let mut b = [0u8; 64];
            let (n, _) = vrf_u.recv_from(&mut b).unwrap();
            assert_eq!(&b[..n], msg);
            tx
        };
        // An unbound receiver: reachable from inside the VRF only with
        // udp_l3mdev_accept = 1 (restored below).
        let l3_accept = std::fs::read_to_string("/proc/sys/net/ipv4/udp_l3mdev_accept").unwrap();
        std::fs::write("/proc/sys/net/ipv4/udp_l3mdev_accept", "1").unwrap();
        let rx = UdpSocket::bind("0.0.0.0:0").unwrap();
        let rx_port = rx.local_addr().unwrap().port();
        let unbound_rx = |msg: &[u8]| -> UdpSocket {
            let tx = UdpSocket::from(bound(libc::SOCK_DGRAM, Some("pvrf")));
            tx.send_to(msg, vaddr(rx_port)).unwrap();
            let mut b = [0u8; 64];
            let n = rx.recv(&mut b).unwrap();
            assert_eq!(&b[..n], msg);
            tx
        };

        set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 0);
        bump(&mut ebpf);
        let lo_v = drops(&ebpf, DROP_LOOPBACK);
        let _ = drain(&mut ring);
        let (cm, sm) = tcp("pvrf", b"vrf-master-off");
        let (cs, ss) = tcp("pvd0", b"vrf-slave-off");
        let tp = pktinfo(b"vrf-pktinfo-off");
        let tr = unbound_rx(b"vrf-l3acc-off");
        let ev = drain(&mut ring);
        let off_cookies = [
            cookie(&cm),
            cookie(&sm),
            cookie(&cs),
            cookie(&ss),
            cookie(&tp),
            cookie(&vrf_u),
            cookie(&tr),
            cookie(&rx),
        ];
        assert!(
            !ev.iter().any(|e| off_cookies.contains(&e.0)),
            "VRF exported with loopback off: {ev:?}"
        );
        assert!(
            drops(&ebpf, DROP_LOOPBACK) >= lo_v + 6,
            "VRF packets counted: {}",
            drops(&ebpf, DROP_LOOPBACK) - lo_v
        );
        for (f, what) in [
            (
                crate::state(&ebpf, &cm).map(|s| s.local),
                "TCP master-bound client",
            ),
            (
                crate::state(&ebpf, &sm).map(|s| s.local),
                "TCP master-bound server",
            ),
            (
                crate::state(&ebpf, &cs).map(|s| s.local),
                "TCP slave-bound client",
            ),
            (
                crate::state(&ebpf, &ss).map(|s| s.local),
                "TCP server of the slave-bound client",
            ),
            (
                crate::state(&ebpf, &tp).map(|s| s.local),
                "UDP IP_PKTINFO sender, first datagram",
            ),
            (
                crate::state(&ebpf, &rx).map(|s| s.local),
                "UDP unbound receiver",
            ),
        ] {
            assert_eq!(f, Some(1), "{what} marked local");
        }

        // On (a widening): every case captured; TCP pairs for the close
        // check emit here, then close once loopback is off.
        set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 1);
        bump(&mut ebpf);
        let (cm2, sm2) = tcp("pvrf", b"vrf-master-on");
        let (cs2, ss2) = tcp("pvd0", b"vrf-slave-on");
        let tp2 = pktinfo(b"vrf-pktinfo-on");
        let tr2 = unbound_rx(b"vrf-l3acc-on");
        let ev = drain(&mut ring);
        for (c, m, what) in [
            (cookie(&cm2), &b"vrf-master-on"[..], "TCP master-bound"),
            (cookie(&sm2), b"vrf-master-on", "TCP master-bound server"),
            (cookie(&cs2), b"vrf-slave-on", "TCP slave-bound"),
            (cookie(&ss2), b"vrf-slave-on", "TCP slave-bound server"),
            (cookie(&tp2), b"vrf-pktinfo-on", "UDP IP_PKTINFO sender"),
            (cookie(&rx), b"vrf-l3acc-on", "UDP unbound receiver"),
        ] {
            assert!(has(&ev, c, m), "{what} captured with loopback on: {ev:?}");
        }
        let closing = [cookie(&cm2), cookie(&sm2), cookie(&cs2), cookie(&ss2)];
        set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 0);
        bump(&mut ebpf);
        drop((cm2, sm2, cs2, ss2));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(
            !drain_records(&mut ring)
                .iter()
                .any(|(e, _)| e.event_type == EventType::SockClose
                    && closing.contains(&e.socket_cookie)),
            "no VRF close record once loopback is off"
        );

        // Looped multicast and broadcast (§3.7, Codex VRF R3 finding 1): a
        // sender on the slave (pvd0) with multicast loop on. ip_mc_output
        // clones the packet for local delivery, but the clone has no socket
        // (skb_clone), so the egress runner does not run the program for it
        // (BPF_CGROUP_RUN_PROG_INET_EGRESS requires the skb's socket): the
        // sender has only the copy that leaves (multicast TTL > 0, or
        // broadcast), loopback on or off, and is not marked local; nothing
        // is dropped as loopback with it on. The receiver (bound to the
        // master; delivery on the master) is dropped while off, captured
        // while on. TTL 0 multicast has no leaving copy; broadcast is always
        // looped and has no TTL-0 rule.
        assert!(ip_cmd("link set pvd0 multicast on"));
        let group = std::net::Ipv4Addr::new(224, 0, 0, 123);
        let local = std::net::Ipv4Addr::new(10, 212, 0, 1);
        let mrx = {
            let s = bound(libc::SOCK_DGRAM, Some("pvrf"));
            s.bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into())
                .unwrap();
            s.join_multicast_v4(&group, &local).unwrap();
            s.set_broadcast(true).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            UdpSocket::from(s)
        };
        let mport = mrx.local_addr().unwrap().port();
        let mc_send = |to: std::net::Ipv4Addr, ttl: u32, msg: &[u8]| -> UdpSocket {
            let s = bound(libc::SOCK_DGRAM, Some("pvd0"));
            s.set_multicast_if_v4(&local).unwrap();
            s.set_multicast_loop_v4(true).unwrap();
            s.set_multicast_ttl_v4(ttl).unwrap();
            s.set_broadcast(true).unwrap();
            s.send_to(msg, &std::net::SocketAddr::from((to, mport)).into())
                .unwrap();
            let mut b = [0u8; 64];
            let n = mrx.recv(&mut b).expect("the looped copy is delivered");
            assert_eq!(&b[..n], msg);
            UdpSocket::from(s)
        };
        let bcast = std::net::Ipv4Addr::new(10, 212, 0, 255);
        let count = |ev: &[(u64, Direction, u64, Vec<u8>)], c: u64, m: &[u8]| {
            ev.iter().filter(|e| e.0 == c && e.3 == m).count()
        };
        let cases: [(std::net::Ipv4Addr, u32, &[u8], usize); 3] = [
            (group, 0, b"mc-ttl0", 0),
            (group, 1, b"mc-ttl1", 1),
            (bcast, 1, b"bcast", 1),
        ];
        for on in [false, true] {
            set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, u64::from(on));
            bump(&mut ebpf);
            let _ = drain(&mut ring);
            for (to, ttl, m, remote) in cases {
                let msg = [m, if on { &b"-on"[..] } else { b"-off" }].concat();
                let all_drops = |e: &Ebpf| {
                    (0..SCOPE_DROP_REASONS)
                        .map(|r| drops(e, r))
                        .collect::<Vec<u64>>()
                };
                let d0 = all_drops(&ebpf);
                let tx = mc_send(to, ttl, &msg);
                let ev = drain(&mut ring);
                // Per reason (other traffic on the host can add drops).
                let dropped: Vec<(&str, u64)> = all_drops(&ebpf)
                    .iter()
                    .zip(&d0)
                    .enumerate()
                    .filter(|(_, (a, b))| a != b)
                    .map(|(r, (a, b))| (SCOPE_DROP_NAMES[r], a - b))
                    .collect();
                let sent = count(&ev, cookie(&tx), &msg);
                let rcvd = count(&ev, cookie(&mrx), &msg);
                println!(
                    "MCLOOP {to} ttl={ttl} loopback={on}: sender {sent} receiver {rcvd} \
                     scope_drops {dropped:?}"
                );
                if on {
                    // Measured: the looped clone never reaches the program
                    // (skb_clone leaves skb->sk NULL; the egress runner
                    // requires the skb's socket), so only the original.
                    assert_eq!(sent, remote, "{to} ttl {ttl}: the original only: {ev:?}");
                    assert!(
                        !dropped.iter().any(|(r, _)| *r == "loopback"),
                        "{to} ttl {ttl}: nothing dropped as loopback with it on: {dropped:?}"
                    );
                    assert_eq!(rcvd, 1, "{to} ttl {ttl}: receiver captured");
                } else {
                    assert_eq!(sent, remote, "{to} ttl {ttl}: only the remote copy: {ev:?}");
                    assert_eq!(rcvd, 0, "{to} ttl {ttl}: receiver not captured");
                    assert_eq!(
                        crate::state(&ebpf, &tx).map(|s| s.local),
                        Some(0),
                        "{to} ttl {ttl}: sender not marked local"
                    );
                }
            }
        }
        set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 0);
        bump(&mut ebpf);
        drop(mrx);
        println!("LOOPBACK VRF MCLOOP OK");
        set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 1);
        bump(&mut ebpf);
        std::fs::write("/proc/sys/net/ipv4/udp_l3mdev_accept", l3_accept.trim()).unwrap();
        drop((cm, sm, cs, ss, tp, tr, tp2, tr2, rx, vrf_u, vrf_l));
        let _ = ip("link del pvd0");
        assert!(ip("link del pvrf"));
        println!("LOOPBACK VRF OK");
    }

    // Looped multicast without a VRF (all five kernels): the same clone,
    // on a plain dummy device. The sender has only the copy that leaves,
    // loopback on or off (the clone never reaches the program); the looped
    // copy's receive is on pmc0, not node-local, so it is captured.
    {
        assert!(
            ip_cmd("link add pmc0 type dummy")
                && ip_cmd("link set pmc0 multicast on")
                && ip_cmd("addr add 10.213.0.1/24 dev pmc0")
                && ip_cmd("link set pmc0 up"),
            "dummy pmc0"
        );
        let group = std::net::Ipv4Addr::new(224, 0, 0, 124);
        let local = std::net::Ipv4Addr::new(10, 213, 0, 1);
        let prx = {
            let s = bound(libc::SOCK_DGRAM, None);
            s.bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into())
                .unwrap();
            s.join_multicast_v4(&group, &local).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            UdpSocket::from(s)
        };
        let pport = prx.local_addr().unwrap().port();
        for on in [false, true] {
            set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, u64::from(on));
            bump(&mut ebpf);
            let _ = drain(&mut ring);
            for (ttl, remote) in [(0u32, 0usize), (1, 1)] {
                let msg = format!("plain-mc-ttl{ttl}-{on}").into_bytes();
                let s = bound(libc::SOCK_DGRAM, Some("pmc0"));
                s.set_multicast_if_v4(&local).unwrap();
                s.set_multicast_loop_v4(true).unwrap();
                s.set_multicast_ttl_v4(ttl).unwrap();
                s.send_to(&msg, &std::net::SocketAddr::from((group, pport)).into())
                    .unwrap();
                let mut b = [0u8; 64];
                let n = prx.recv(&mut b).expect("the looped copy is delivered");
                assert_eq!(&b[..n], &msg[..]);
                let tx = UdpSocket::from(s);
                let ev = drain(&mut ring);
                let sent = ev
                    .iter()
                    .filter(|e| e.0 == cookie(&tx) && e.3 == msg)
                    .count();
                let rcvd = ev
                    .iter()
                    .filter(|e| e.0 == cookie(&prx) && e.3 == msg)
                    .count();
                println!("MCPLAIN ttl={ttl} loopback={on}: sender {sent} receiver {rcvd}");
                assert_eq!(
                    sent, remote,
                    "plain ttl {ttl}: the leaving copy only: {ev:?}"
                );
                assert_eq!(rcvd, 1, "plain ttl {ttl}: the receive on pmc0 captured");
            }
        }
        drop(prx);
        assert!(ip_cmd("link del pmc0"));
        println!("LOOPBACK MCPLAIN OK");
    }

    // On again (a widening): loopback captured, TLS on it too.
    set(&mut ebpf, CONFIG_CAPTURE_LOOPBACK, 1);
    bump(&mut ebpf);
    let (c6, s6) = exchange(&listener, b"lo-on");
    let own_on = own_l.as_ref().map(|l| exchange(l, b"own-on"));
    let ev = drain(&mut ring);
    assert!(
        has(&ev, cookie(&c6), b"lo-on") && has(&ev, cookie(&s6), b"lo-on"),
        "loopback captured: {ev:?}"
    );
    if let Some((oc, _)) = &own_on {
        assert!(
            has(&ev, cookie(oc), b"own-on"),
            "own address captured: {ev:?}"
        );
    }
    c4.write_all(b"p").unwrap(); // recomputes c4's verdict (IN)
    for (fd, m) in [
        (c4.as_raw_fd(), &b"tls-lo-on"[..]),
        (pipe[1], b"tls-pipe-on"),
    ] {
        TEST_FD.store(fd, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(write(ssl, m.as_ptr(), m.len() as i32), m.len() as i32);
    }
    let tls = drain_tls(&mut ring);
    let find = |p: &[u8]| tls.iter().find(|e| e.payload_bytes() == p).copied();
    let e = find(b"tls-lo-on").expect("TLS on loopback emitted");
    assert_eq!(
        (e.src_addr, e.src_port as u64),
        (0x7f00_0001, c4_port),
        "with its address"
    );
    assert!(
        find(b"tls-pipe-on").is_some(),
        "TLS without an address emitted"
    );
    // The sections below write through c4, as before this one.
    TEST_FD.store(c4.as_raw_fd(), std::sync::atomic::Ordering::SeqCst);
    // SAFETY: our pipe fds.
    unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
    }
    drop((
        c5, s5, own_pair, cv, sv, cf, sf, cvf, svf, c6, s6, own_on, vl, own_l,
    ));
    let _ = ip("netns del pnlo");
    let _ = ip("link del pnlo0");
    println!("LOOPBACK OK lo_packets={lo_pkts}");

    // ── pid_filter_listener (§3.1): a listener created by this (listed)
    // process, its connection accepted by an unlisted one (a forked
    // child). Creator rule: the accepted socket's bytes are captured.
    // Switching to the acceptor rule (a narrowing, with its generation
    // bump) stops them on the live connection; the client end, created by
    // this process, stays captured under both rules.
    set(&mut ebpf, CONFIG_PID_CREATOR_RULE, 1);
    bump(&mut ebpf);
    let rl = TcpListener::bind("127.0.0.1:0").unwrap();
    let raddr = rl.local_addr().unwrap();
    // SAFETY: the child makes only async-signal-safe calls, then _exits.
    let kid = unsafe { libc::fork() };
    if kid == 0 {
        // SAFETY: plain syscalls on fds the child owns.
        unsafe {
            let fd = libc::accept(rl.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut());
            let mut b = [0u8; 64];
            loop {
                let n = libc::read(fd, b.as_mut_ptr().cast(), b.len());
                if n <= 0 {
                    break;
                }
                libc::write(fd, b.as_ptr().cast(), n as usize);
            }
            libc::_exit(0);
        }
    }
    assert!(kid > 0, "fork");
    drop(rl); // only the child accepts
    let mut rc = TcpStream::connect(raddr).unwrap();
    let rcc = cookie(&rc);
    let mut echo = |m: &[u8]| {
        rc.write_all(m).unwrap();
        let mut b = vec![0u8; m.len()];
        rc.read_exact(&mut b).unwrap();
    };
    let sides = |ev: &[(u64, Direction, u64, Vec<u8>)], m: &[u8]| {
        (
            ev.iter().filter(|e| e.0 == rcc && e.3 == m).count(),
            ev.iter().filter(|e| e.0 != rcc && e.3 == m).count(),
        )
    };
    echo(b"rule-creator");
    let ev = drain(&mut ring);
    assert_eq!(
        sides(&ev, b"rule-creator"),
        (2, 2),
        "creator rule: client and accepted ends: {ev:?}"
    );
    set(&mut ebpf, CONFIG_PID_CREATOR_RULE, 0);
    bump(&mut ebpf);
    let oos1 = drops(&ebpf, DROP_OUT_OF_SCOPE);
    echo(b"rule-acceptor");
    let ev = drain(&mut ring);
    assert_eq!(
        sides(&ev, b"rule-acceptor"),
        (2, 0),
        "acceptor rule: the unlisted acceptor's end is not captured: {ev:?}"
    );
    assert!(drops(&ebpf, DROP_OUT_OF_SCOPE) >= oos1 + 2);
    drop(rc);
    let mut st = 0;
    // SAFETY: our child.
    assert_eq!(unsafe { libc::waitpid(kid, &mut st, 0) }, kid);
    println!("LISTENER_RULE OK");

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
    // SSL_new's return sends a header-only TlsNew keyed like the returned
    // object's data; a NULL return sends nothing, nor does a call in which
    // a TLS write ran (a creation callback), nor one whose entry was not
    // seen.
    {
        let new = std::hint::black_box(panop_test_ssl_new as extern "C" fn(u64, u64) -> u64);
        let records = |ring: &mut RingBuf<MapData>| {
            let mut seen = Vec::new();
            while let Some(item) = ring.next() {
                // SAFETY: all-zero is a valid DataEvent.
                let mut r: DataEvent = unsafe { std::mem::zeroed() };
                if read_data_event_into(&item, &mut r) {
                    seen.push((r.event_type, r.socket_cookie, r.payload_len, item.len()));
                }
            }
            seen
        };
        let mut links = Vec::new();
        for prog in ["ssl_new_ret", "ssl_new_entry"] {
            let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
            let link = p
                .attach("panop_test_ssl_new", "/proc/self/exe", Some(me))
                .unwrap_or_else(|e| panic!("{prog} attaches: {e}"));
            links.push((prog, link));
            if prog == "ssl_new_ret" {
                // Return probe only: the entry was not seen.
                assert_eq!(new(ssl, 0), ssl);
                assert_eq!(records(&mut ring), vec![], "unseen entry: no TlsNew");
            }
        }
        let header = panopticon_common::DATA_EVENT_HEADER_LEN;
        assert_eq!(new(0, 0), 0);
        assert_eq!(new(ssl, 0), ssl);
        assert_eq!(
            records(&mut ring),
            vec![(EventType::TlsNew, ssl, 0, header)],
            "SSL_new: one header-only TlsNew for the returned object"
        );
        assert_eq!(new(ssl, 1), ssl);
        let seen = records(&mut ring);
        assert!(
            seen.iter()
                .any(|r| (r.0, r.1, r.2) == (EventType::TlsData, ssl, 6)),
            "the write inside SSL_new is captured: {seen:?}"
        );
        assert!(
            !seen.iter().any(|r| r.0 == EventType::TlsNew),
            "I/O inside SSL_new: no TlsNew: {seen:?}"
        );
        assert_eq!(new(ssl, 0), ssl);
        assert_eq!(
            records(&mut ring),
            vec![(EventType::TlsNew, ssl, 0, header)],
            "the mark is cleared at the return"
        );
        SLOT_STATE.store(0, SeqCst);
        for (prog, link) in links {
            let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
            p.detach(link).unwrap();
        }
    }
    println!("TLS_BORN OK");
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

/// Go `crypto/tls` reads (DESIGN §3.5 "Go TLS reads") through the real
/// probes on a real Go binary, `tests/oracle/scope_go_tls.go` built with
/// `CGO_ENABLED=0` at `PANOPTICON_GO_TLS` (default
/// /home/ubuntu/b2/fix/scope_go_tls): every record captured whole over TLS
/// 1.3 and TLS 1.2 (AEAD and CBC), also when the reader's stack moved
/// mid-read; no slots left after goroutine churn; slots of a process killed
/// mid-read removed by the sweep; scoped in, scoped out, narrowed mid-read,
/// capture switched off mid-read.
#[test]
#[ignore = "needs root on a Linux lab kernel and a built Go fixture"]
fn go_tls_reads() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    let _lab = LAB.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = std::env::var("PANOPTICON_GO_TLS")
        .unwrap_or_else(|_| "/home/ubuntu/b2/fix/scope_go_tls".into());
    // A private copy: uprobes are per file, so other users of the fixture
    // never reach this test's probes.
    let bin = std::env::temp_dir().join(format!("goreads-{}", std::process::id()));
    std::fs::copy(&fixture, &bin).unwrap_or_else(|e| {
        panic!("Go fixture {fixture}: {e} (CGO_ENABLED=0 go build tests/oracle/scope_go_tls.go)")
    });
    let elf = std::fs::read(&bin).unwrap();
    let probes = go_read::go_read_probes_from(&elf[..])
        .expect("discovery finds readRecordOrCCS and decrypt, and their RETs");
    println!(
        "GOREAD probes readRecordOrCCS entry={:#x} rets={} decrypt rets={}",
        probes.read_record_entry,
        probes.read_record_rets.len(),
        probes.decrypt_rets.len()
    );

    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panopticon-ebpf"));
    let mut ebpf = EbpfLoader::new().load(bytes).expect("object and maps load");
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    set(&mut ebpf, CONFIG_USE_RINGBUF, 1);
    set(&mut ebpf, CONFIG_RING_SHARD_MASK, 0);
    set(&mut ebpf, CONFIG_SCOPE_GEN, 1);
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0); // unscoped full
    let mut ring = RingBuf::try_from(ebpf.take_map("DATA_EVENTS_0").unwrap()).unwrap();
    let mut links: Vec<Box<dyn std::any::Any>> = Vec::new();
    for tp in ["sched_process_exec", "sched_process_exit"] {
        let p: &mut aya::programs::TracePoint = ebpf.program_mut(tp).unwrap().try_into().unwrap();
        p.load().unwrap();
        links.push(Box::new(p.attach("sched", tp).unwrap()));
    }
    // As the loader does: every RET probe, then the readRecordOrCCS entry.
    let path = bin.to_str().unwrap().to_string();
    for (prog, offsets) in [
        ("go_tls_rrc_ret", probes.read_record_rets.clone()),
        ("go_tls_decrypt_ret", probes.decrypt_rets.clone()),
        ("go_tls_rrc_entry", vec![probes.read_record_entry]),
    ] {
        let p: &mut aya::programs::UProbe = ebpf.program_mut(prog).unwrap().try_into().unwrap();
        p.load().unwrap_or_else(|e| panic!("{prog} loads: {e:#}"));
        for off in offsets {
            links.push(Box::new(p.attach(off, path.as_str(), None).unwrap()));
        }
    }

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    let run_env = |args: &[&str], tls12: &str| -> Child {
        Command::new(&bin)
            .args(args)
            .env("TLS12", tls12)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let run = |args: &[&str]| run_env(args, "");
    // Fixture processes still running if an assertion fails.
    struct Reap(Vec<u32>);
    impl Drop for Reap {
        fn drop(&mut self) {
            for &pid in &self.0 {
                // SAFETY: kill(2) on a pid; a gone process only fails it.
                unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            }
        }
    }
    let mut reap = Reap(Vec::new());
    let wait_ok = |mut c: Child, what: &str| {
        assert!(c.wait().unwrap().success(), "{what} failed");
    };
    let mut server = run(&["rserver", &addr]);
    let t0 = Instant::now();
    while TcpStream::connect(&addr).is_err() {
        assert!(t0.elapsed() < Duration::from_secs(10), "rserver listens");
        std::thread::sleep(Duration::from_millis(20));
    }
    let spid = server.id();
    reap.0.push(spid);
    // Go reads in the ring: (pid, payload).
    let reads = |ring: &mut RingBuf<MapData>| -> Vec<(u32, Vec<u8>)> {
        std::thread::sleep(Duration::from_millis(300));
        drain_tls(ring)
            .iter()
            .filter(|e| e.direction == Direction::Ingress && e.tls_library == TlsLibrary::GoTls)
            .map(|e| (e.pid, e.payload_bytes().to_vec()))
            .collect()
    };
    let keys = |ebpf: &Ebpf, tgid: Option<u32>| -> usize {
        let m: HashMap<&MapData, GoReadKey, GoReadCall> =
            HashMap::try_from(ebpf.map("GO_READ_CALLS").unwrap()).unwrap();
        m.keys()
            .filter_map(Result::ok)
            .filter(|k| tgid.is_none_or(|t| k.tgid == t))
            .count()
    };
    let has_epoch = |ebpf: &Ebpf, tgid: u32| {
        let m: HashMap<&MapData, u32, u64> =
            HashMap::try_from(ebpf.map("PROC_EPOCH").unwrap()).unwrap();
        m.get(&tgid, 0).is_ok()
    };
    let settle = |ebpf: &Ebpf, tgid: Option<u32>, want: usize, what: &str| {
        let t0 = Instant::now();
        while keys(ebpf, tgid) != want && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(keys(ebpf, tgid), want, "GO_READ_CALLS slots: {what}");
    };
    let sweep = |ebpf: &Ebpf| {
        let mut s = go_read::Sweep::open(ebpf).unwrap();
        let r = s.run().unwrap();
        println!("GOREAD sweep batched={}", s.batched);
        r
    };

    // ── unscoped full: every record whole, from both processes; the server
    // reads from a goroutine whose stack moves mid-read
    let _ = drain(&mut ring);
    let client = run(&["rclient", &addr, "A", "80"]);
    let cpid = client.id();
    wait_ok(client, "rclient A");
    let got = reads(&mut ring);
    let mut moved = 0;
    for i in 0..80 {
        let m = format!("B2R-A-{i}");
        assert!(
            got.iter().any(|(p, b)| *p == spid && b == m.as_bytes()),
            "server read {m} captured whole"
        );
        let reply = got
            .iter()
            .find(|(p, b)| *p == cpid && b.starts_with(format!("ECHO {m} m=").as_bytes()))
            .unwrap_or_else(|| panic!("client read of the reply to {m} captured"));
        assert_eq!(reply.1.len(), format!("ECHO {m} m=0").len(), "whole reply");
        moved += usize::from(reply.1.ends_with(b"m=1"));
    }
    println!("GOREAD full: 160 records whole; server stack moved mid-read in {moved}/80");
    assert!(
        moved > 0,
        "no read saw its stack move: frame depths across a move were not exercised"
    );
    settle(
        &ebpf,
        None,
        0,
        "after 80 connections' goroutines came and went",
    );
    assert!(
        !has_epoch(&ebpf, cpid),
        "the client's exit ended its instance"
    );
    assert!(has_epoch(&ebpf, spid));
    println!("GOREAD churn: 0 slots after 80 connection goroutines");

    // ── TLS 1.2: AEAD records and CBC records (MAC and padding stripped in
    // place) are decrypted differently; both whole
    for tls12 in ["aead", "cbc"] {
        let tag = format!("T12{tls12}");
        let client = run_env(&["rclient", &addr, &tag, "20"], tls12);
        let cpid = client.id();
        wait_ok(client, &tag);
        let got = reads(&mut ring);
        for i in 0..20 {
            let m = format!("B2R-{tag}-{i}");
            assert!(
                got.iter().any(|(p, b)| *p == spid && b == m.as_bytes()),
                "TLS 1.2 {tls12}: server read {m} captured whole"
            );
            assert!(
                got.iter().any(|(p, b)| *p == cpid
                    && b.starts_with(format!("ECHO {m} m=").as_bytes())
                    && b.len() == format!("ECHO {m} m=0").len()),
                "TLS 1.2 {tls12}: client read of the reply to {m} captured whole"
            );
        }
        settle(&ebpf, None, 0, "TLS 1.2");
    }
    println!("GOREAD tls12: AEAD and CBC records whole");

    // ── a process killed with reads in flight: its slots outlive it until
    // the sweep, which removes exactly those
    let mut hold = run(&["rhold", &addr, "20"]);
    let hpid = hold.id();
    reap.0.push(hpid);
    settle(&ebpf, Some(hpid), 20, "rhold blocked in 20 reads");
    hold.kill().unwrap();
    hold.wait().unwrap();
    settle(&ebpf, Some(spid), 0, "server reads ended by EOF");
    assert!(!has_epoch(&ebpf, hpid), "exit removed the epoch");
    assert_eq!(
        keys(&ebpf, Some(hpid)),
        20,
        "slots of the killed process remain"
    );
    assert_eq!(sweep(&ebpf), (20, 0));
    assert_eq!(keys(&ebpf, None), 0, "after the sweep");
    println!("GOREAD exit: 20 slots left by a killed process, swept to 0");

    // ── pid_filter: the server in scope, the client not
    set(&mut ebpf, CONFIG_SCOPE_MODE, SCOPE_SEL_PID);
    set(&mut ebpf, CONFIG_SCOPE_ARMED, 1);
    {
        let mut pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("PID_FILTER").unwrap()).unwrap();
        pids.insert(spid, 1, 0).unwrap();
    }
    let out0 = drops(&ebpf, DROP_TLS_OUT_OF_SCOPE);
    let client = run(&["rclient", &addr, "C", "20"]);
    let cpid = client.id();
    wait_ok(client, "rclient C");
    let got = reads(&mut ring);
    for i in 0..20 {
        let m = format!("B2R-C-{i}");
        assert!(
            got.iter().any(|(p, b)| *p == spid && b == m.as_bytes()),
            "scoped in: {m}"
        );
    }
    assert!(
        !got.iter().any(|(p, _)| *p == cpid),
        "scoped out: nothing from the client"
    );
    assert!(
        drops(&ebpf, DROP_TLS_OUT_OF_SCOPE) >= out0 + 20,
        "client reads counted"
    );
    settle(&ebpf, None, 0, "scoped");
    println!("GOREAD scoped: in-scope reads captured, out-of-scope none");

    // ── narrowed while a read is parked: what it returns after is dropped
    let go = std::env::temp_dir().join(format!("goreads-go-{}", std::process::id()));
    let _ = std::fs::remove_file(&go);
    let slow = run(&["rslow", &addr, "D", go.to_str().unwrap()]);
    reap.0.push(slow.id());
    let t0 = Instant::now();
    let mut pre = false;
    while !pre && t0.elapsed() < Duration::from_secs(10) {
        pre = reads(&mut ring)
            .iter()
            .any(|(p, b)| *p == spid && b == b"B2R-D-PRE");
    }
    assert!(pre, "control: in scope before the narrowing");
    settle(&ebpf, Some(spid), 1, "the server parked in its next read");
    {
        let mut pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("PID_FILTER").unwrap()).unwrap();
        pids.remove(&spid).unwrap();
    }
    set(&mut ebpf, CONFIG_SCOPE_GEN, 2);
    std::fs::write(&go, b"").unwrap();
    wait_ok(slow, "rslow D");
    let got = reads(&mut ring);
    assert!(
        !got.iter()
            .any(|(_, b)| b.windows(10).any(|w| w == b"B2R-D-POST")),
        "no read data after the narrowing"
    );
    std::fs::remove_file(&go).unwrap();
    settle(&ebpf, None, 0, "narrowed");
    println!("GOREAD narrowed: a read parked across the narrowing emits nothing");

    // ── capture switched off while reads are parked with saved slots: what
    // they return after is not emitted, and their slots still go
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);
    let _ = std::fs::remove_file(&go);
    let slow = run(&["rslow", &addr, "E", go.to_str().unwrap()]);
    let slow_pid = slow.id();
    reap.0.push(slow_pid);
    let t0 = Instant::now();
    let mut pre = false;
    while !pre && t0.elapsed() < Duration::from_secs(10) {
        pre = reads(&mut ring)
            .iter()
            .any(|(p, b)| *p == spid && b == b"B2R-E-PRE");
    }
    assert!(pre, "control: captured before capture is switched off");
    settle(&ebpf, Some(spid), 1, "the server parked in its next read");
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 0);
    std::fs::write(&go, b"").unwrap();
    wait_ok(slow, "rslow E");
    let got = reads(&mut ring);
    assert!(
        !got.iter()
            .any(|(_, b)| b.windows(10).any(|w| w == b"B2R-E-POST")),
        "no read data after capture is switched off"
    );
    std::fs::remove_file(&go).unwrap();
    settle(&ebpf, None, 0, "slots saved before capture went off");
    println!("GOREAD capture off: reads parked across the switch emit nothing");

    // ── capture off: nothing emitted, nothing kept
    wait_ok(run(&["rclient", &addr, "F", "10"]), "rclient F");
    assert!(reads(&mut ring).is_empty(), "capture off");
    let mut hold = run(&["rhold", &addr, "5"]);
    reap.0.push(hold.id());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(keys(&ebpf, None), 0, "no slot is made while capture is off");
    hold.kill().unwrap();
    hold.wait().unwrap();

    server.kill().unwrap();
    server.wait().unwrap();
    assert!(!has_epoch(&ebpf, spid));
    assert_eq!(sweep(&ebpf).0, 0);
    assert_eq!(keys(&ebpf, None), 0);
    drop(links);
    std::fs::remove_file(&bin).unwrap();
    println!("GOREAD OK");
}
