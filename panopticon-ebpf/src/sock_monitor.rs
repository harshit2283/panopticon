//! TCP connection lifecycle → process attribution.
//!
//! TC sees packets but not which process owns a connection. These hooks
//! report who opened (connect) or accepted (accept) each TCP connection,
//! tagged with the same 5-tuple flow cookie the TC classifier uses, so user
//! space can attach client/server PIDs to the exchanges it parses.
//!
//! - `tcp_connect` kprobe and `inet_csk_accept` kretprobe run in the calling
//!   process, so both PIDs are known.
//! - Without kprobes (kernels built without CONFIG_KPROBES), the
//!   `sock:inet_sock_set_state` tracepoint is the fallback: its
//!   CLOSE → SYN_SENT transition runs in the connecting process; the
//!   accepting side completes in softirq, so only client PIDs are known.
//!
//! Connection close is not hooked: user space drops a connection's state on
//! the FIN/RST packets TC delivers in order with the data. Per-datagram UDP
//! hooks were removed: they emitted a 4KB event per UDP send/receive on the
//! node that nothing consumed.

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe, tracepoint},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use panopticon_common::{DataEvent, EventType, TlsLibrary};

use crate::maps::{
    CONFIG, CONNECTING, DATA_EVENTS, DATA_EVENTS_PERF, PERF_SCRATCH, data_events_submit_flags,
};
use crate::tc_capture::tc_connection_cookie;

const IP_PROTO_TCP: u8 = 6;

/// `tcp_connect(struct sock *sk)`: outgoing connection, local port bound.
#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) {
    let _ = try_sock_owner(&ctx, ctx.arg(0), EventType::SockConnect);
}

/// Return of `inet_csk_accept()`: the accepted `struct sock *`, in the
/// accepting process.
#[kretprobe]
pub fn inet_csk_accept_ret(ctx: RetProbeContext) {
    let sk = ctx.ret::<*const u8>();
    if !sk.is_null() {
        let _ = try_sock_owner(&ctx, Some(sk), EventType::SockAccept);
    }
}

#[inline(always)]
fn try_sock_owner<C: EbpfContext>(
    ctx: &C,
    sk: Option<*const u8>,
    event_type: EventType,
) -> Result<(), ()> {
    let (src_addr, dst_addr, src_port, dst_port) = read_sock_tuple(sk.ok_or(())?)?;
    emit_owner(
        ctx,
        bpf_get_current_pid_tgid(),
        event_type,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    )
}

/// Fallback for kernels without kprobes. Field offsets from
/// /sys/kernel/tracing/events/sock/inet_sock_set_state/format (stable since
/// 4.16): skaddr@8 oldstate@16 newstate@20 sport@24 dport@26 family@28
/// protocol@30 saddr@32 daddr@36; ports in host order, addresses in network
/// order.
///
/// Two steps, because tcp_v4_connect enters SYN_SENT before it picks the
/// source port: CLOSE → SYN_SENT (in the connecting process) remembers the
/// socket's owner; SYN_SENT → ESTABLISHED (in softirq, full tuple known)
/// emits it.
#[tracepoint]
pub fn sock_state_connect(ctx: TracePointContext) {
    let _ = try_sock_state_connect(&ctx);
}

#[inline(always)]
fn try_sock_state_connect(ctx: &TracePointContext) -> Result<(), ()> {
    const TCP_ESTABLISHED: i32 = 1;
    const TCP_SYN_SENT: i32 = 2;
    const TCP_CLOSE: i32 = 7;
    const AF_INET: u16 = 2;
    let newstate: i32 = unsafe { ctx.read_at(20) }.map_err(|_| ())?;
    let oldstate: i32 = unsafe { ctx.read_at(16) }.map_err(|_| ())?;
    let opening = oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT;
    let established = oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED;
    if !opening && !established {
        return Ok(());
    }
    let family: u16 = unsafe { ctx.read_at(28) }.map_err(|_| ())?;
    let protocol: u16 = unsafe { ctx.read_at(30) }.map_err(|_| ())?;
    if family != AF_INET || protocol != IP_PROTO_TCP as u16 {
        return Ok(());
    }
    let skaddr: u64 = unsafe { ctx.read_at(8) }.map_err(|_| ())?;
    if opening {
        return CONNECTING
            .insert(skaddr, bpf_get_current_pid_tgid(), 0)
            .map_err(|_| ());
    }
    let pid_tgid = match unsafe { CONNECTING.get(skaddr) } {
        Some(p) => *p,
        None => return Ok(()),
    };
    let _ = CONNECTING.remove(skaddr);
    let src_port: u16 = unsafe { ctx.read_at(24) }.map_err(|_| ())?;
    let dst_port: u16 = unsafe { ctx.read_at(26) }.map_err(|_| ())?;
    let src_addr = u32::from_be(unsafe { ctx.read_at::<u32>(32) }.map_err(|_| ())?);
    let dst_addr = u32::from_be(unsafe { ctx.read_at::<u32>(36) }.map_err(|_| ())?);
    emit_owner(
        ctx,
        pid_tgid,
        EventType::SockConnect,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
    )
}

#[inline(always)]
fn emit_owner<C: EbpfContext>(
    ctx: &C,
    pid_tgid: u64,
    event_type: EventType,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
) -> Result<(), ()> {
    let cookie = tc_connection_cookie(src_addr, dst_addr, src_port, dst_port, IP_PROTO_TCP);
    emit_sock_event(
        ctx,
        event_type,
        (pid_tgid >> 32) as u32,
        pid_tgid as u32,
        cookie,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        IP_PROTO_TCP,
    )
}

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
pub(crate) fn read_sock_tuple(sk: *const u8) -> Result<(u32, u32, u16, u16), ()> {
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
            crate::maps::count_kernel_drop();
            return Ok(()); // RingBuf full — drop
        };

        let event = entry.as_mut_ptr();
        // SAFETY: writing to reserved RingBuf memory. The payload is not
        // zeroed: payload_len is 0, and the ring's memory only ever holds
        // other events that user space can already read.
        unsafe {
            populate_sock_event(
                event, event_type, pid, tgid, cookie, src_addr, dst_addr, src_port, dst_port,
                ip_proto,
            );
        }

        entry.submit(data_events_submit_flags());
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
        (*event).orig_len = 0;
        (*event).tcp_flags = 0;
        (*event)._pad = [0; 6];
    }
}
