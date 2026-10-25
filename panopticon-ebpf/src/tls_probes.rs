//! TLS interception uprobes for capturing plaintext before/after encryption.
//!
//! Attaches to OpenSSL's `SSL_write`/`SSL_read`, their `_ex` variants (what
//! OpenSSL 1.1.1+ applications such as CPython, curl and nginx call), and Go's
//! TLS write function. Captures the plaintext buffer contents and emits
//! TlsData events tagged with the connection object pointer (`SSL*`,
//! `*tls.Conn`) so user space can tell connections apart.
//!
//! Note: Go TLS Read is NOT intercepted in Phase 1. Go's goroutine stack
//! relocation can crash uretprobes, so we only intercept Go TLS writes.

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_buf,
    },
    macros::{fentry, kprobe, tracepoint, uprobe, uretprobe},
    programs::{FEntryContext, ProbeContext, RetProbeContext, TracePointContext},
};
use panopticon_common::{DataEvent, Direction, EventType, MAX_PAYLOAD_SIZE, TlsLibrary};

use crate::maps::{
    CONFIG, DATA_EVENTS, DATA_EVENTS_PERF, GO_READ_ARGS, GoReadKey, PERF_SCRATCH, SockTuple,
    TLS_ACTIVE, TLS_CONN_ADDR, TLS_SCRATCH, TlsConnKey, TlsReadArgs, data_events_submit_flags,
};
use crate::sock_monitor::read_sock_tuple;

/// Mark `conn` as the TLS connection this thread is doing I/O for, so the
/// socket hooks below can attach its addresses.
#[inline(always)]
fn mark_active(conn: u64) {
    if conn == 0 {
        return;
    }
    if let Some(slot) = TLS_ACTIVE.get_ptr_mut(0) {
        unsafe {
            (*slot).pid_tgid = bpf_get_current_pid_tgid();
            (*slot).conn = conn;
        }
    }
}

// ── Socket kprobes: TLS connection → addresses ─────────────────────────────

/// `tcp_sendmsg(sk, msg, size)` / `tcp_recvmsg(sk, ...)`: when called from
/// inside a hooked TLS call, record that connection's socket tuple. The
/// marker is consumed so later plain-TCP I/O on the same thread is not
/// attributed to it. Overwrites, so a connection object reused for a new
/// connection (same `SSL*` after free/alloc) gets the new addresses.
///
/// Hooked through the `sock:sock_send_length` / `sock:sock_recv_length`
/// tracepoints where available (stable ABI, kernel 6.3+), else fentry (BTF
/// trampolines), else kprobes.
#[tracepoint]
pub fn tls_sock_send_length(ctx: TracePointContext) {
    let _ = try_tls_sock_length(&ctx);
}

#[tracepoint]
pub fn tls_sock_recv_length(ctx: TracePointContext) {
    let _ = try_tls_sock_length(&ctx);
}

/// Both tracepoints share one layout (see
/// /sys/kernel/tracing/events/sock/sock_send_length/format):
/// `void *sk` at 8, `u16 family` at 16, `u16 protocol` at 18.
///
/// These fire for every socket send/receive on the node, so the cheap
/// "is this thread inside a TLS call" lookup comes before any field read.
#[inline(always)]
fn try_tls_sock_length(ctx: &TracePointContext) -> Result<(), ()> {
    const AF_INET: u16 = 2;
    const IPPROTO_TCP: u16 = 6;
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(conn) = take_active(pid_tgid) else {
        return Ok(());
    };
    let family: u16 = unsafe { ctx.read_at(16) }.map_err(|_| ())?;
    let protocol: u16 = unsafe { ctx.read_at(18) }.map_err(|_| ())?;
    if family != AF_INET || protocol != IPPROTO_TCP {
        return Ok(());
    }
    let sk: u64 = unsafe { ctx.read_at(8) }.map_err(|_| ())?;
    record_conn_addr(pid_tgid, conn, sk as *const u8)
}

#[fentry(function = "tcp_sendmsg")]
pub fn tls_tcp_sendmsg_fentry(ctx: FEntryContext) -> u32 {
    let _ = try_tls_tcp_io(ctx.arg(0));
    0
}

#[fentry(function = "tcp_recvmsg")]
pub fn tls_tcp_recvmsg_fentry(ctx: FEntryContext) -> u32 {
    let _ = try_tls_tcp_io(ctx.arg(0));
    0
}

#[kprobe]
pub fn tls_tcp_sendmsg(ctx: ProbeContext) {
    if let Some(sk) = ctx.arg(0) {
        let _ = try_tls_tcp_io(sk);
    }
}

#[kprobe]
pub fn tls_tcp_recvmsg(ctx: ProbeContext) {
    if let Some(sk) = ctx.arg(0) {
        let _ = try_tls_tcp_io(sk);
    }
}

#[inline(always)]
fn try_tls_tcp_io(sk: *const u8) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    match take_active(pid_tgid) {
        Some(conn) => record_conn_addr(pid_tgid, conn, sk),
        None => Ok(()),
    }
}

/// The TLS connection this thread is inside a call for, if any; consumed.
#[inline(always)]
fn take_active(pid_tgid: u64) -> Option<u64> {
    let slot = TLS_ACTIVE.get_ptr_mut(0)?;
    unsafe {
        if (*slot).conn == 0 || (*slot).pid_tgid != pid_tgid {
            return None;
        }
        let conn = (*slot).conn;
        (*slot).conn = 0;
        Some(conn)
    }
}

#[inline(always)]
fn record_conn_addr(pid_tgid: u64, conn: u64, sk: *const u8) -> Result<(), ()> {
    let (local_addr, remote_addr, local_port, remote_port) = read_sock_tuple(sk)?;
    let key = TlsConnKey {
        conn,
        pid: (pid_tgid >> 32) as u32,
        _pad: 0,
    };
    let tuple = SockTuple {
        local_addr,
        remote_addr,
        local_port,
        remote_port,
    };
    TLS_CONN_ADDR.insert(&key, &tuple, 0).map_err(|_| ())
}

// ── OpenSSL: SSL_write ─────────────────────────────────────────────────────

/// Intercepts `SSL_write(ssl, buf, num)` — captures plaintext being written.
/// Args: ssl (arg0), buf (arg1), num (arg2).
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) {
    let _ = try_ssl_write_entry(&ctx);
}

#[inline(always)]
fn try_ssl_write_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let ssl: u64 = ctx.arg(0).ok_or(())?;
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;
    if num <= 0 {
        return Ok(());
    }
    mark_active(ssl);

    emit_tls_event(
        ctx,
        ssl,
        buf,
        num as usize,
        Direction::Egress,
        TlsLibrary::OpenSsl,
    )
}

/// Intercepts `SSL_write_ex(ssl, buf, num, *written)`. `num` is a `size_t`;
/// without partial-write mode OpenSSL writes all of it or fails, so the
/// requested length is what goes on the wire.
#[uprobe]
pub fn ssl_write_ex_entry(ctx: ProbeContext) {
    let _ = try_ssl_write_ex_entry(&ctx);
}

#[inline(always)]
fn try_ssl_write_ex_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let ssl: u64 = ctx.arg(0).ok_or(())?;
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: u64 = ctx.arg(2).ok_or(())?;
    if num == 0 || num > u32::MAX as u64 {
        return Ok(());
    }
    mark_active(ssl);

    emit_tls_event(
        ctx,
        ssl,
        buf,
        num as usize,
        Direction::Egress,
        TlsLibrary::OpenSsl,
    )
}

// ── OpenSSL: SSL_read ──────────────────────────────────────────────────────

/// Intercepts `SSL_read(ssl, buf, num)` entry — stashes the arguments.
/// The actual data isn't available until the function returns with the
/// number of bytes read, so we save them in TLS_SCRATCH.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) {
    let _ = try_ssl_read_entry(&ctx);
}

#[inline(always)]
fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let args = TlsReadArgs {
        ssl: ctx.arg(0).ok_or(())?,
        buf: ctx.arg(1).ok_or(())?,
        readbytes: 0,
    };
    mark_active(args.ssl);
    TLS_SCRATCH
        .insert(bpf_get_current_pid_tgid(), args, 0)
        .map_err(|_| ())
}

/// Intercepts `SSL_read_ex(ssl, buf, num, *readbytes)` entry. Shares the
/// return probe with `SSL_read`; a non-zero `readbytes` pointer tells it
/// which return convention applies.
#[uprobe]
pub fn ssl_read_ex_entry(ctx: ProbeContext) {
    let _ = try_ssl_read_ex_entry(&ctx);
}

#[inline(always)]
fn try_ssl_read_ex_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let args = TlsReadArgs {
        ssl: ctx.arg(0).ok_or(())?,
        buf: ctx.arg(1).ok_or(())?,
        readbytes: ctx.arg(3).ok_or(())?,
    };
    if args.readbytes == 0 {
        return Ok(());
    }
    mark_active(args.ssl);
    TLS_SCRATCH
        .insert(bpf_get_current_pid_tgid(), args, 0)
        .map_err(|_| ())
}

/// Return probe for `SSL_read` and `SSL_read_ex` — reads the decrypted data
/// from the stashed buffer. `SSL_read` returns the byte count; `SSL_read_ex`
/// returns 1 on success and stores the count through `readbytes`.
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) {
    let _ = try_ssl_read_ret(&ctx);
}

#[inline(always)]
fn try_ssl_read_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Look up the arguments saved by the entry probe
    let args = unsafe {
        match TLS_SCRATCH.get(pid_tgid) {
            Some(args) => *args,
            None => return Ok(()), // Missed the entry probe
        }
    };

    // Clean up scratch space (and the marker, if the read was served from
    // already-buffered TLS records without touching the socket)
    let _ = TLS_SCRATCH.remove(pid_tgid);
    let _ = take_active(pid_tgid);

    let ret = ctx.ret::<i32>();
    if ret <= 0 {
        return Ok(()); // error / would-block / closed
    }
    let len = if args.readbytes == 0 {
        ret as u64
    } else {
        unsafe { bpf_probe_read_user(args.readbytes as *const u64) }.map_err(|_| ())?
    };
    if len == 0 || len > u32::MAX as u64 {
        return Ok(());
    }

    emit_tls_event(
        ctx,
        args.ssl,
        args.buf as *const u8,
        len as usize,
        Direction::Ingress,
        TlsLibrary::OpenSsl,
    )
}

// ── Go TLS: crypto/tls.(*Conn).Write ──────────────────────────────────────

/// Intercepts Go TLS writes. Go 1.17+ uses register-based ABI:
/// - RAX: receiver (`*tls.Conn`)
/// - RBX: pointer to byte slice data
/// - RCX: length of byte slice
/// - RDI: capacity of byte slice
///
/// Note: Go TLS Read is intentionally NOT intercepted — uretprobes crash
/// Go programs due to goroutine stack relocation.
#[uprobe]
pub fn go_tls_write_entry(ctx: ProbeContext) {
    let _ = try_go_tls_write(&ctx);
}

#[inline(always)]
fn try_go_tls_write(ctx: &ProbeContext) -> Result<(), ()> {
    let (conn, buf, len) = read_go_write_args(ctx)?;
    if len == 0 {
        return Ok(());
    }
    mark_active(conn);

    emit_tls_event(ctx, conn, buf, len, Direction::Egress, TlsLibrary::GoTls)
}

// ── Go TLS: crypto/tls.(*Conn).Read ───────────────────────────────────────

/// Entry of `(*Conn).Read(b []byte) (int, error)`: remember the buffer and
/// connection for this goroutine.
#[uprobe]
pub fn go_tls_read_entry(ctx: ProbeContext) {
    let _ = try_go_tls_read_entry(&ctx);
}

#[inline(always)]
fn try_go_tls_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let (conn, buf, _len) = read_go_write_args(ctx)?; // same argument layout
    let key = go_read_key(ctx)?;
    mark_active(conn);
    let args = TlsReadArgs {
        buf: buf as u64,
        ssl: conn,
        readbytes: 0,
    };
    GO_READ_ARGS.insert(&key, &args, 0).map_err(|_| ())
}

/// A RET instruction of `(*Conn).Read` (attached at every one): the byte
/// count is the first result register.
#[uprobe]
pub fn go_tls_read_ret(ctx: ProbeContext) {
    let _ = try_go_tls_read_ret(&ctx);
}

#[inline(always)]
fn try_go_tls_read_ret(ctx: &ProbeContext) -> Result<(), ()> {
    let key = go_read_key(ctx)?;
    let args = match unsafe { GO_READ_ARGS.get(&key) } {
        Some(a) => *a,
        None => return Ok(()), // missed the entry
    };
    let _ = GO_READ_ARGS.remove(&key);
    let n = go_first_result(ctx) as i64;
    if n <= 0 || n > u32::MAX as i64 {
        return Ok(());
    }
    emit_tls_event(
        ctx,
        args.ssl,
        args.buf as *const u8,
        n as usize,
        Direction::Ingress,
        TlsLibrary::GoTls,
    )
}

#[inline(always)]
fn go_read_key(ctx: &ProbeContext) -> Result<GoReadKey, ()> {
    let goroutine = go_g_register(ctx);
    if goroutine == 0 {
        return Err(());
    }
    Ok(GoReadKey {
        tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
        _pad: 0,
        goroutine,
    })
}

/// The current goroutine (`g`), pinned to a register in Go's ABIInternal:
/// R14 on x86_64, X28 on arm64.
#[inline(always)]
#[cfg(bpf_target_arch = "x86_64")]
fn go_g_register(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).r14 }
}

#[inline(always)]
#[cfg(not(bpf_target_arch = "x86_64"))]
fn go_g_register(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).regs[28] }
}

/// First integer result at a RET: RAX on x86_64, X0 on arm64.
#[inline(always)]
#[cfg(bpf_target_arch = "x86_64")]
fn go_first_result(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).rax }
}

#[inline(always)]
#[cfg(not(bpf_target_arch = "x86_64"))]
fn go_first_result(ctx: &ProbeContext) -> u64 {
    unsafe { (*ctx.regs).regs[0] }
}

#[inline(always)]
#[cfg(bpf_target_arch = "x86_64")]
fn read_go_write_args(ctx: &ProbeContext) -> Result<(u64, *const u8, usize), ()> {
    // Aya's ProbeContext::arg() follows the SysV ABI (rdi, rsi, rdx, ...).
    // Go methods on x86_64 use the internal ABI instead, with the receiver in
    // rax and the []byte fields in rbx/rcx/rdi.
    let regs = unsafe { &*ctx.regs };
    Ok((regs.rax, regs.rbx as *const u8, regs.rcx as usize))
}

#[inline(always)]
#[cfg(not(bpf_target_arch = "x86_64"))]
fn read_go_write_args(ctx: &ProbeContext) -> Result<(u64, *const u8, usize), ()> {
    // arm64 Go ABI: receiver and []byte fields in R0..R3, which is also
    // what arg(0..) reads.
    let conn: u64 = ctx.arg(0).ok_or(())?;
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let len: usize = ctx.arg(2).ok_or(())?;
    Ok((conn, buf, len))
}

// ── Shared helper ──────────────────────────────────────────────────────────

/// Fields shared by every event of one TLS read/write, computed once.
#[derive(Clone, Copy)]
struct TlsHeader {
    conn: u64,
    pid: u32,
    tgid: u32,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
    direction: Direction,
    tls_lib: TlsLibrary,
}

#[inline(always)]
fn tls_header(conn: u64, direction: Direction, tls_lib: TlsLibrary) -> TlsHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let mut h = TlsHeader {
        conn,
        pid,
        tgid: pid_tgid as u32,
        src_addr: 0,
        dst_addr: 0,
        src_port: 0,
        dst_port: 0,
        ip_proto: 0,
        direction,
        tls_lib,
    };
    // Addresses are known once this connection has done socket I/O inside a
    // hooked call (see try_tls_tcp_io); zero until then.
    let key = TlsConnKey { conn, pid, _pad: 0 };
    if let Some(t) = unsafe { TLS_CONN_ADDR.get(&key) } {
        let (src, dst) = match direction {
            Direction::Egress => ((t.local_addr, t.local_port), (t.remote_addr, t.remote_port)),
            _ => ((t.remote_addr, t.remote_port), (t.local_addr, t.local_port)),
        };
        h.src_addr = src.0;
        h.src_port = src.1;
        h.dst_addr = dst.0;
        h.dst_port = dst.1;
        h.ip_proto = 6;
    }
    h
}

#[inline(always)]
fn emit_tls_event<C: EbpfContext>(
    ctx: &C,
    conn: u64,
    buf: *const u8,
    len: usize,
    direction: Direction,
    tls_lib: TlsLibrary,
) -> Result<(), ()> {
    let h = tls_header(conn, direction, tls_lib);
    let use_ringbuf = match CONFIG.get(panopticon_common::CONFIG_USE_RINGBUF) {
        Some(&v) => v != 0,
        None => true,
    };
    if !use_ringbuf {
        // PerfEventArray path (kernels < 5.8): one event per call, on the
        // per-CPU scratch map (DataEvent far exceeds the BPF stack).
        let Some(event) = PERF_SCRATCH.get_ptr_mut(0) else {
            return Ok(());
        };
        unsafe {
            core::ptr::write_bytes(event as *mut u8, 0, core::mem::size_of::<DataEvent>());
        }
        populate_tls_event(event, &h, buf, len);
        DATA_EVENTS_PERF.output(ctx, unsafe { &*event }, 0);
        return Ok(());
    }
    // One TLS read/write routinely carries a full 16KB record or more, i.e.
    // several protocol frames. Emit it as consecutive MAX_PAYLOAD_SIZE
    // events (up to MAX_TLS_CHUNKS) so parsers see the stream contiguously;
    // a single truncated event left a gap across frame boundaries, which
    // e.g. HTTP/2 can only recover from by resetting (losing HPACK state).
    // The last chunk's orig_len carries whatever is left uncaptured. The
    // loop body is kept branch-light: the verifier walks every iteration.
    let mut off = 0usize;
    for i in 0..MAX_TLS_CHUNKS {
        if off >= len {
            break;
        }
        let remaining = len - off;
        let chunk = if i == MAX_TLS_CHUNKS - 1 || remaining <= MAX_PAYLOAD_SIZE {
            remaining
        } else {
            MAX_PAYLOAD_SIZE
        };
        let Some(mut entry) = DATA_EVENTS.reserve::<DataEvent>(0) else {
            crate::maps::count_kernel_drop();
            return Ok(()); // RingBuf full — drop
        };
        populate_tls_event(entry.as_mut_ptr(), &h, unsafe { buf.add(off) }, chunk);
        entry.submit(data_events_submit_flags());
        off += MAX_PAYLOAD_SIZE;
    }
    Ok(())
}

/// Chunks emitted per TLS read/write (MAX_PAYLOAD_SIZE each): 16KB, one
/// full TLS record. The verifier walks every chunk separately; 16 chunks
/// made the TLS programs too complex to load.
const MAX_TLS_CHUNKS: usize = 4;

/// Populate a TLS DataEvent. Shared between RingBuf and PerfEventArray paths.
#[inline(always)]
fn populate_tls_event(event: *mut DataEvent, h: &TlsHeader, buf: *const u8, len: usize) {
    // SAFETY: writing to reserved RingBuf memory or the per-CPU scratch event.
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        // No socket in uprobe context: the connection object stands in for it.
        (*event).socket_cookie = h.conn;
        (*event).event_type = EventType::TlsData;
        (*event).direction = h.direction;
        (*event).pid = h.pid;
        (*event).tgid = h.tgid;
        (*event).src_addr = h.src_addr;
        (*event).dst_addr = h.dst_addr;
        (*event).src_port = h.src_port;
        (*event).dst_port = h.dst_port;
        (*event).ip_proto = h.ip_proto;
        (*event).tls_library = h.tls_lib;
        (*event).tcp_flags = 0;
        (*event)._pad = [0; 6];
        (*event).orig_len = len as u32;

        // Copy plaintext from user space, clamped to MAX_PAYLOAD_SIZE
        let copy_len = if len > MAX_PAYLOAD_SIZE {
            MAX_PAYLOAD_SIZE
        } else {
            len
        };
        (*event).payload_len = copy_len as u32;

        if copy_len > 0 && copy_len <= MAX_PAYLOAD_SIZE {
            let dst = core::slice::from_raw_parts_mut((*event).payload.as_mut_ptr(), copy_len);
            if bpf_probe_read_user_buf(buf, dst).is_err() {
                (*event).payload_len = 0;
            }
        }
    }
}
