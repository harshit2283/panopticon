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
use aya::{Ebpf, EbpfLoader, Pod};
use panopticon_common::scope::*;
use panopticon_common::*;
use scope_loader::*;

/// Fentry/fexit attach targets of the programs in the object.
const TARGETS: [(&str, &str); 5] = [
    (ACCEPT4, "inet_csk_accept"),
    (ACCEPT2, "inet_csk_accept"),
    (SET_ULP, "tcp_set_ulp"),
    ("tls_tcp_sendmsg_fentry", "tcp_sendmsg"),
    ("tls_tcp_recvmsg_fentry", "tcp_recvmsg"),
];

#[derive(Clone, Copy)]
#[repr(C)]
struct RawState([u64; 8]);
// SAFETY: plain integers.
unsafe impl Pod for RawState {}

fn state(ebpf: &Ebpf, fd: &impl AsRawFd) -> Option<SockState> {
    let map: SkStorage<&MapData, RawState> =
        SkStorage::try_from(ebpf.map("SOCK_STATE").unwrap()).unwrap();
    let raw = map.get(&fd.as_raw_fd(), 0).ok()?;
    // SAFETY: SockState is repr(C), 64 bytes of integers.
    Some(unsafe { std::mem::transmute::<RawState, SockState>(raw) })
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
    let accept = report.accept.expect("one inet_csk_accept variant loads");
    let other_accept = if accept == ACCEPT4 { ACCEPT2 } else { ACCEPT4 };

    // ── every other program in the object through the verifier; the only
    // allowed failure is the other accept arity
    let names: Vec<String> = ebpf.programs().map(|(n, _)| n.to_string()).collect();
    let mut failed = Vec::new();
    for name in &names {
        match load_any(&mut ebpf, name) {
            Ok(()) => println!("MATRIX {name} load=OK"),
            Err(e) => {
                println!("MATRIX {name} load=FAIL ({e})");
                failed.push(name.clone());
            }
        }
    }
    assert_eq!(failed, vec![other_accept.to_string()], "load failures");

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
    for p in [EXIT_TP, SET_ULP, accept] {
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

    // After arming: a socket that attaches the tls ULP is marked, and its
    // payload dropped outside unscoped full.
    if ulp {
        let mut tk = TcpStream::connect(lw.local_addr().unwrap()).unwrap();
        let (mut tk_srv, _) = lw.accept().unwrap();
        assert!(set_tls_ulp(&tk));
        assert_ne!(
            state(&ebpf, &tk).unwrap().flags & FLAG_KTLS,
            0,
            "KTLS marked"
        );
        let k0 = drops(&ebpf, DROP_KTLS_PAYLOAD);
        tk.write_all(b"ktls").unwrap();
        let _ = tk_srv.read(&mut buf).unwrap();
        assert!(!drain(&mut ring).iter().any(|e| e.0 == cookie(&tk)));
        assert!(drops(&ebpf, DROP_KTLS_PAYLOAD) > k0);
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
