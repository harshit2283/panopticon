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

#[test]
#[ignore = "needs root on a Linux lab kernel"]
fn scope_programs_load_attach_and_hold() {
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panopticon-ebpf"));
    let mut ebpf = EbpfLoader::new().load(bytes).expect("object and maps load");

    // ── every program through the verifier
    let names: Vec<String> = ebpf.programs().map(|(n, _)| n.to_string()).collect();
    let mut loaded = Vec::new();
    for name in &names {
        match load_any(&mut ebpf, name) {
            Ok(()) => loaded.push(name.clone()),
            Err(e) => println!("MATRIX {name} load=FAIL ({e})"),
        }
    }

    // ── scope programs onto the cgroup2 root (writers first)
    let root = discover_cgroup_root(
        &std::env::var("PANOPTICON_CGROUP2").unwrap_or_else(|_| "auto".into()),
    )
    .expect("cgroup2 root");
    println!("ROOT {root:?}");
    let cgroup = File::open(root.path()).unwrap();
    let mut links = Vec::new();
    let order = [
        SOCK_CREATE,
        SOCKOPS,
        ACCEPT4,
        ACCEPT2,
        SET_ULP,
        EXIT_TP,
        SKB_INGRESS,
        SKB_EGRESS,
    ];
    let mut attached = Vec::new();
    for p in order {
        if !loaded.iter().any(|n| n == p) {
            continue;
        }
        match attach_program(&mut ebpf, p, &cgroup, &mut links) {
            Ok(()) => {
                attached.push(p);
                println!("MATRIX {p} load=OK attach=OK");
            }
            Err(e) => println!("MATRIX {p} load=OK attach=FAIL ({e:#})"),
        }
    }
    for n in &loaded {
        if !order.contains(&n.as_str()) {
            println!("MATRIX {n} load=OK attach=n/a");
        }
    }
    for p in [SOCK_CREATE, SOCKOPS, SET_ULP, SKB_INGRESS, SKB_EGRESS] {
        assert!(attached.contains(&p), "{p} must load and attach");
    }
    let accept = attached.iter().any(|p| *p == ACCEPT4 || *p == ACCEPT2);
    assert!(accept, "one inet_csk_accept variant must attach");
    assert!(
        !(attached.contains(&ACCEPT4) && attached.contains(&ACCEPT2)),
        "exactly one accept variant loads"
    );

    // ── runtime: unscoped full
    let me = std::process::id();
    set(&mut ebpf, CONFIG_CAPTURE_ENABLED, 1);
    set(&mut ebpf, CONFIG_USE_RINGBUF, 1);
    set(&mut ebpf, CONFIG_RING_SHARD_MASK, 0);
    set(&mut ebpf, CONFIG_SCOPE_GEN, 1);
    set(&mut ebpf, CONFIG_PID_EPOCH, 77);
    set(&mut ebpf, CONFIG_SCOPE_MODE, 0);
    let mut ring = RingBuf::try_from(ebpf.take_map("DATA_EVENTS_0").unwrap()).unwrap();

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
        ev.iter().any(|e| e.0 == cookie(&c4) && e.3 == b"listed"),
        "listed creator: captured {ev:?}"
    );
    assert!(
        !ev.iter().any(|e| e.0 == cookie(&c3)),
        "old verdict stays OUT"
    );

    for r in 0..SCOPE_DROP_REASONS {
        println!("DROPS {} {}", SCOPE_DROP_NAMES[r as usize], drops(&ebpf, r));
    }
    drop(links);
    println!("RUNTIME OK");
}
