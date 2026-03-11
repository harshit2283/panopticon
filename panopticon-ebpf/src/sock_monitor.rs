//! Socket event monitoring via kprobes.
//!
//! Tracks TCP connection lifecycle (connect, accept, close) and UDP
//! send/receive. Maintains `CONN_MAP` for active connection tracking
//! and emits socket events to `DATA_EVENTS` RingBuf.
//!
//! All kprobes extract the 5-tuple (src_addr, dst_addr, src_port,
//! dst_port, protocol) from `struct sock` for connection correlation.

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use panopticon_common::{ConnInfo, DataEvent, EventType, TlsLibrary};

use crate::maps::{CONFIG, CONN_MAP, DATA_EVENTS, DATA_EVENTS_PERF, PERF_SCRATCH};

// ── TCP Connect ────────────────────────────────────────────────────────────

/// Fires on `tcp_connect(struct sock *sk)` — outgoing TCP connection initiated.
///
/// Extracts the 5-tuple from the sock struct, stores in CONN_MAP,
/// and emits a SockConnect event.
#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) {
    let _ = try_tcp_connect(&ctx);
}

#[inline(always)]
fn try_tcp_connect(ctx: &ProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    // arg0: struct sock *sk
    let sk: *const u8 = ctx.arg(0).ok_or(())?;

    let (src_addr, dst_addr, src_port, dst_port) = read_sock_tuple(sk)?;
    let cookie = gen_connection_key(pid_tgid, src_addr, dst_addr, src_port, dst_port);
    let now = unsafe { bpf_ktime_get_ns() };

    // Store connection info in CONN_MAP
    let conn = ConnInfo {
        socket_cookie: cookie,
        connect_ts: now,
        src_addr,
        dst_addr,
        pid,
        tgid,
        src_port,
        dst_port,
        _pad: [0; 4],
    };
    let _ = CONN_MAP.insert(cookie, conn, 0);

    // Emit SockConnect event
    emit_sock_event(
        ctx,
        EventType::SockConnect,
        pid,
        tgid,
        cookie,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        6, // TCP
    )
}

// ── TCP Accept (return probe) ──────────────────────────────────────────────

/// Fires on return from `inet_csk_accept()` — incoming TCP connection accepted.
///
/// The return value is the newly created `struct sock *` for the accepted
/// connection. We extract the 5-tuple and emit a SockAccept event.
#[kretprobe]
pub fn inet_csk_accept_ret(ctx: RetProbeContext) {
    let _ = try_inet_csk_accept_ret(&ctx);
}

#[inline(always)]
fn try_inet_csk_accept_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    // Return value: struct sock *sk (the accepted socket)
    let sk = ctx.ret::<*const u8>();
    if sk.is_null() {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let (src_addr, dst_addr, src_port, dst_port) = read_sock_tuple(sk)?;
    let cookie = gen_connection_key(pid_tgid, src_addr, dst_addr, src_port, dst_port);
    let now = unsafe { bpf_ktime_get_ns() };

    let conn = ConnInfo {
        socket_cookie: cookie,
        connect_ts: now,
        src_addr,
        dst_addr,
        pid,
        tgid,
        src_port,
        dst_port,
        _pad: [0; 4],
    };
    let _ = CONN_MAP.insert(cookie, conn, 0);

    emit_sock_event(
        ctx,
        EventType::SockAccept,
        pid,
        tgid,
        cookie,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        6, // TCP
    )
}

// ── TCP Close ──────────────────────────────────────────────────────────────

/// Fires on `tcp_close(struct sock *sk)` — TCP connection being torn down.
///
/// Removes the connection from CONN_MAP and emits a SockClose event.
#[kprobe]
pub fn tcp_close(ctx: ProbeContext) {
    let _ = try_tcp_close(&ctx);
}

#[inline(always)]
fn try_tcp_close(ctx: &ProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let sk: *const u8 = ctx.arg(0).ok_or(())?;
    let (src_addr, dst_addr, src_port, dst_port) = read_sock_tuple(sk)?;
    let cookie = gen_connection_key(pid_tgid, src_addr, dst_addr, src_port, dst_port);

    // Remove from connection tracking
    let _ = CONN_MAP.remove(cookie);

    emit_sock_event(
        ctx,
        EventType::SockClose,
        pid,
        tgid,
        cookie,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        6, // TCP
    )
}

// ── UDP Send ───────────────────────────────────────────────────────────────

/// Fires on `udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)`.
///
/// Tracks outgoing UDP datagrams for connection correlation.
#[kprobe]
pub fn udp_sendmsg(ctx: ProbeContext) {
    let _ = try_udp_sendmsg(&ctx);
}

#[inline(always)]
fn try_udp_sendmsg(ctx: &ProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let sk: *const u8 = ctx.arg(0).ok_or(())?;
    let (src_addr, dst_addr, src_port, dst_port) = read_sock_tuple(sk)?;
    let cookie = gen_connection_key(pid_tgid, src_addr, dst_addr, src_port, dst_port);

    emit_sock_event(
        ctx,
        EventType::SockConnect, // Reuse SockConnect for UDP send tracking
        pid,
        tgid,
        cookie,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        17, // UDP
    )
}

// ── UDP Receive ────────────────────────────────────────────────────────────

/// Fires on `udp_recvmsg(struct sock *sk, struct msghdr *msg, ...)`.
///
/// Tracks incoming UDP datagrams for connection correlation.
#[kprobe]
pub fn udp_recvmsg(ctx: ProbeContext) {
    let _ = try_udp_recvmsg(&ctx);
}

#[inline(always)]
fn try_udp_recvmsg(ctx: &ProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let sk: *const u8 = ctx.arg(0).ok_or(())?;
    let (src_addr, dst_addr, src_port, dst_port) = read_sock_tuple(sk)?;
    let cookie = gen_connection_key(pid_tgid, src_addr, dst_addr, src_port, dst_port);

    emit_sock_event(
        ctx,
        EventType::SockAccept, // Reuse SockAccept for UDP recv tracking
        pid,
        tgid,
        cookie,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        17, // UDP
    )
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Reads the IPv4 5-tuple from `struct sock`.
///
/// Linux `struct sock` (via `struct sock_common`) field offsets (x86_64):
/// - `__sk_common.skc_daddr`   (dst IPv4): offset 0   (u32)
/// - `__sk_common.skc_rcv_saddr` (src IPv4): offset 4 (u32)
/// - `__sk_common.skc_dport`  (dst port, network byte order): offset 12 (u16)
/// - `__sk_common.skc_num`    (src port, host byte order): offset 14 (u16)
///
/// Note: These offsets are for modern kernels (4.x+). If supporting older
/// kernels, use CO-RE (Compile Once Run Everywhere) via BTF in Phase 2.
#[inline(always)]
fn read_sock_tuple(sk: *const u8) -> Result<(u32, u32, u16, u16), ()> {
    // SAFETY: reading from struct sock fields at known offsets.
    // The sock pointer is provided by the kernel and is valid during kprobe execution.
    unsafe {
        let dst_addr: u32 = bpf_probe_read_kernel(sk.add(0) as *const u32).map_err(|_| ())?;
        let src_addr: u32 = bpf_probe_read_kernel(sk.add(4) as *const u32).map_err(|_| ())?;
        let dst_port_be: u16 = bpf_probe_read_kernel(sk.add(12) as *const u16).map_err(|_| ())?;
        let src_port: u16 = bpf_probe_read_kernel(sk.add(14) as *const u16).map_err(|_| ())?;

        let dst_port = u16::from_be(dst_port_be);

        Ok((
            u32::from_be(src_addr),
            u32::from_be(dst_addr),
            src_port,
            dst_port,
        ))
    }
}

/// Generate a connection key from pid_tgid, addresses, and ports.
/// Includes src/dst addresses to avoid collisions between connections
/// from the same PID to different hosts on the same port.
#[inline(always)]
fn gen_connection_key(
    pid_tgid: u64,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
) -> u64 {
    // FNV-1a-style hash combining all fields for uniqueness
    let mut hash = pid_tgid;
    hash ^= src_addr as u64;
    hash = hash.wrapping_mul(0x00000100000001B3);
    hash ^= dst_addr as u64;
    hash = hash.wrapping_mul(0x00000100000001B3);
    hash ^= (src_port as u64) << 16 | dst_port as u64;
    hash
}

/// Emits a socket lifecycle event to the DATA_EVENTS RingBuf.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn emit_sock_event<C: EbpfContext>(
    ctx: &C,
    event_type: EventType,
    pid: u32,
    tgid: u32,
    cookie: u64,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
) -> Result<(), ()> {
    let use_ringbuf = match CONFIG.get(panopticon_common::CONFIG_USE_RINGBUF) {
        Some(&v) => v != 0,
        None => true,
    };

    if use_ringbuf {
        let Some(mut entry) = DATA_EVENTS.reserve::<DataEvent>(0) else {
            return Ok(()); // RingBuf full — drop
        };

        let event = entry.as_mut_ptr();
        // SAFETY: writing to reserved RingBuf memory. Zero entire event first
        // to prevent kernel memory leakage through the 4KB payload field.
        unsafe {
            core::ptr::write_bytes(event as *mut u8, 0, core::mem::size_of::<DataEvent>());
            populate_sock_event(
                event, event_type, pid, tgid, cookie, src_addr, dst_addr, src_port, dst_port,
                ip_proto,
            );
        }

        entry.submit(0);
    } else {
        // PerfEventArray path for kernels < 5.8
        // Use per-CPU scratch map (DataEvent is ~4.2KB, exceeds 512-byte BPF stack limit).
        let Some(event) = PERF_SCRATCH.get_ptr_mut(0) else {
            return Ok(());
        };

        unsafe {
            core::ptr::write_bytes(event as *mut u8, 0, core::mem::size_of::<DataEvent>());
            populate_sock_event(
                event, event_type, pid, tgid, cookie, src_addr, dst_addr, src_port, dst_port,
                ip_proto,
            );
        }

        DATA_EVENTS_PERF.output(ctx, unsafe { &*event }, 0);
    }

    Ok(())
}

/// Populate a socket lifecycle DataEvent. Shared between RingBuf and PerfEventArray paths.
#[inline(always)]
unsafe fn populate_sock_event(
    event: *mut DataEvent,
    event_type: EventType,
    pid: u32,
    tgid: u32,
    cookie: u64,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
) {
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).socket_cookie = cookie;
        (*event).event_type = event_type;
        (*event).direction = panopticon_common::Direction::Ingress; // N/A for sock events
        (*event).pid = pid;
        (*event).tgid = tgid;
        (*event).src_addr = src_addr;
        (*event).dst_addr = dst_addr;
        (*event).src_port = src_port;
        (*event).dst_port = dst_port;
        (*event).ip_proto = ip_proto;
        (*event).tls_library = TlsLibrary::None;
        (*event).payload_len = 0;
    }
}
