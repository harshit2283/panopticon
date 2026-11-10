//! TLS interception uprobes for capturing plaintext before/after encryption.
//!
//! Attaches to OpenSSL's `SSL_write`/`SSL_read`, their `_ex` variants (what
//! OpenSSL 1.1.1+ applications such as CPython, curl and nginx call), and Go's
//! TLS write function. Captures the plaintext buffer contents and emits
//! TlsData events tagged with the connection object pointer (`SSL*`,
//! `*tls.Conn`) so user space can tell connections apart.
//!
//! Go TLS reads are not captured. A read's buffer is only filled when the
//! call returns, and nothing saved at entry can be proven to still belong
//! to that call at its return: a stack-backed buffer moves when the
//! goroutine's stack grows, a Read that unwinds (recovered panic, Goexit)
//! leaves its arguments behind for a later call on a recycled goroutine,
//! and the entries of abandoned calls are never reclaimed without a sweep
//! the supported kernels lack. Go writes copy the caller's buffer at entry
//! and have none of these problems.

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
    CONFIG, DATA_EVENTS_PERF, EVENT_SCRATCH, SockTuple, TLS_ACTIVE, TLS_CALL, TLS_CALL_EMPTY,
    TLS_CALL_FILLED, TLS_CALL_POISONED, TLS_CONN_ADDR, TLS_SCRATCH, TlsCall, TlsConnKey,
    TlsReadArgs, pid_allowed, shard_for, shard_reserve, shard_submit_flags,
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
/// trampolines), else kprobes. These record only in unscoped `full`.
///
/// Restricted modes (cgroup_skb, DESIGN §3.5) keep no cross-call address
/// cache and use the `*_scoped` fentry programs only. An address belongs to
/// exactly one OpenSSL call: its entry probe opens the thread's `TLS_CALL`
/// slot, the scoped fentry fills it from the call's socket I/O, and the
/// call's return probe consumes it (`SSL_write*` is emitted at return in
/// these modes for that reason), only if the slot is this frame's
/// (`end_call`) and its socket was checked under the generation the
/// emitting call is in scope under (`tls_header`). A thread inside a TLS call can still do
/// I/O on a socket that is out of scope (a memory BIO, a socket received
/// from another process), so the socket itself must be in scope under the
/// current generation (`sock_capture::sock_addr_checked`). That check needs
/// the socket's `SOCK_STATE`, and `bpf_sk_storage_get` is offered to
/// tracing (fentry) programs only, not to tracepoint or kprobe programs.
/// Go TLS writes are addressless in these modes: they have no return
/// probe.
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
    let Some(conn) = take_active_if_on(pid_tgid) else {
        return Ok(());
    };
    let family: u16 = unsafe { ctx.read_at(16) }.map_err(|_| ())?;
    let protocol: u16 = unsafe { ctx.read_at(18) }.map_err(|_| ())?;
    if family != AF_INET || protocol != IPPROTO_TCP {
        return Ok(());
    }
    let sk: u64 = unsafe { ctx.read_at(8) }.map_err(|_| ())?;
    record_unscoped(pid_tgid, conn, sk as *const u8)
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

/// Restricted modes: fill this thread's call slot (see above).
#[fentry(function = "tcp_sendmsg")]
pub fn tls_tcp_sendmsg_scoped(ctx: FEntryContext) -> u32 {
    let _ = try_tls_tcp_io_scoped(ctx.arg(0));
    0
}

#[fentry(function = "tcp_recvmsg")]
pub fn tls_tcp_recvmsg_scoped(ctx: FEntryContext) -> u32 {
    let _ = try_tls_tcp_io_scoped(ctx.arg(0));
    0
}

/// The first in-scope socket seen in the call gives it its address; a
/// second socket seen, or any seen socket that fails the check, poisons the
/// slot so the call carries no address. "Seen" is I/O by this thread on the
/// CPU holding its TLS_ACTIVE marker: after a CPU migration, I/O neither
/// fills nor poisons. Any I/O of the thread in the call's interval counts
/// (a signal handler, a BIO callback), so the label can be another in-scope
/// socket of the same process under the same generation (a known label
/// limitation, not a scope leak).
#[inline(always)]
fn try_tls_tcp_io_scoped(sk: *mut core::ffi::c_void) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    // Cheap per-CPU prefilter (not consumed: the call may do more I/O),
    // before a hash lookup on every TCP send/receive on the node.
    if !peek_active(pid_tgid) || !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let Some(call) = TLS_CALL.get_ptr_mut(&pid_tgid) else {
        return Ok(());
    };
    // Only this thread reads or writes its slot (maps.rs TLS_CALL).
    let state = unsafe { (*call).state };
    if state == TLS_CALL_POISONED {
        return Ok(());
    }
    match crate::sock_capture::sock_addr_checked(sk) {
        Some((cookie, g, (local_addr, remote_addr, local_port, remote_port)))
            if state == TLS_CALL_EMPTY =>
        unsafe {
            (*call).cookie = cookie;
            (*call).scope_gen = g;
            (*call).tuple = SockTuple {
                local_addr,
                remote_addr,
                local_port,
                remote_port,
            };
            (*call).state = TLS_CALL_FILLED;
        },
        // The same socket again, checked afresh: under this generation now.
        Some((cookie, g, _)) if cookie == unsafe { (*call).cookie } => unsafe {
            (*call).scope_gen = g;
        },
        _ => unsafe { (*call).state = TLS_CALL_POISONED },
    }
    Ok(())
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
    match take_active_if_on(pid_tgid) {
        Some(conn) => record_unscoped(pid_tgid, conn, sk),
        None => Ok(()),
    }
}

/// The unscoped programs (tracepoint, fentry, kprobe) record nothing in a
/// restricted mode, whatever attached them.
#[inline(always)]
fn record_unscoped(pid_tgid: u64, conn: u64, sk: *const u8) -> Result<(), ()> {
    if !panopticon_common::scope::is_unscoped_full(crate::sock_capture::scope_mode()) {
        return Ok(());
    }
    record_conn_addr(pid_tgid, conn, sk)
}

/// The marker (`take_active`), only while TLS capture is on: the cheap
/// per-CPU check first, then the capture flags, before the marker is
/// consumed or any socket field read.
#[inline(always)]
fn take_active_if_on(pid_tgid: u64) -> Option<u64> {
    if !peek_active(pid_tgid) || !crate::sock_capture::tls_capture_on() {
        return None;
    }
    take_active(pid_tgid)
}

/// TLS capture off: a return probe only clears what this thread's entry
/// probe left, and collects nothing.
#[inline(always)]
fn forget_call(pid_tgid: u64) {
    let _ = TLS_SCRATCH.remove(&pid_tgid);
    let _ = TLS_CALL.remove(&pid_tgid);
    let _ = take_active(pid_tgid);
}

/// Whether this CPU's marker says this thread is inside a TLS call.
#[inline(always)]
fn peek_active(pid_tgid: u64) -> bool {
    match TLS_ACTIVE.get(0) {
        Some(a) => a.conn != 0 && a.pid_tgid == pid_tgid,
        None => false,
    }
}

/// Restricted modes: whether TLS addresses come from per-call slots.
#[inline(always)]
fn restricted() -> bool {
    !panopticon_common::scope::is_unscoped_full(crate::sock_capture::scope_mode())
}

/// User stack pointer of a probe's registers.
#[inline(always)]
#[cfg(bpf_target_arch = "x86_64")]
fn user_sp(regs: *const aya_ebpf::bindings::pt_regs) -> u64 {
    unsafe { (*regs).rsp }
}

#[inline(always)]
#[cfg(not(bpf_target_arch = "x86_64"))]
fn user_sp(regs: *const aya_ebpf::bindings::pt_regs) -> u64 {
    unsafe { (*regs).sp }
}

/// What a return pops off the stack: the return address on x86_64 (pushed
/// by `call`; the uretprobe sees the stack pointer after `ret`), nothing on
/// arm64 (`bl` keeps it in the link register).
#[cfg(bpf_target_arch = "x86_64")]
const RET_SP_ADJ: u64 = 8;
#[cfg(not(bpf_target_arch = "x86_64"))]
const RET_SP_ADJ: u64 = 0;

/// Whether a slot was opened by the entry of the call returning now.
#[inline(always)]
fn same_frame(entry_sp: u64, ret_sp: u64) -> bool {
    entry_sp != 0 && entry_sp.wrapping_add(RET_SP_ADJ) == ret_sp
}

/// The address a consumed call carries (`ok` != 0), with the generation its
/// socket was checked in scope under. Plain integers with no padding and
/// always fully written: the RHEL 8 verifier rejects reading stack bytes
/// that one path left unwritten (an `Option` of a struct does that).
#[derive(Clone, Copy)]
struct CallAddr {
    ok: u32,
    scope_gen: u32,
    local_addr: u32,
    remote_addr: u32,
    local_port: u16,
    remote_port: u16,
}

const NO_ADDR: CallAddr = CallAddr {
    ok: 0,
    scope_gen: 0,
    local_addr: 0,
    remote_addr: 0,
    local_port: 0,
    remote_port: 0,
};

/// What a return probe takes from its call slot (`found` != 0 only for a
/// slot opened by this frame's entry). Same layout rules as `CallAddr`.
#[derive(Clone, Copy)]
struct Ended {
    conn: u64,
    buf: u64,
    len: u64,
    aux: u64,
    found: u32,
    addr: CallAddr,
}

/// Restricted modes: open this thread's call slot, replacing whatever a
/// call whose return probe never ran left behind.
#[inline(always)]
fn begin_call(ctx: &ProbeContext, conn: u64, buf: u64, len: u64, aux: u64) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let call = TlsCall {
        conn,
        buf,
        len,
        aux,
        cookie: 0,
        entry_sp: user_sp(ctx.regs),
        tuple: SockTuple {
            local_addr: 0,
            remote_addr: 0,
            local_port: 0,
            remote_port: 0,
        },
        state: TLS_CALL_EMPTY,
        scope_gen: 0,
        _pad: 0,
    };
    if TLS_CALL.insert(&pid_tgid, &call, 0).is_err() {
        let _ = TLS_CALL.remove(&pid_tgid);
    }
}

/// Restricted modes, an entry probe that opens no call: drop any slot left
/// behind, so this call's return probe cannot consume it.
#[inline(always)]
fn drop_call() {
    let _ = TLS_CALL.remove(&bpf_get_current_pid_tgid());
}

/// The call slot of this thread, consumed whatever it holds (nothing
/// survives the call), and returned only if it belongs to the frame
/// returning now. A slot from another frame (a nested call, or an inner
/// call whose return probe never ran) carries another call's buffer and
/// address: nothing is emitted from it.
/// Fields are read one by one before the delete (no copy of the whole
/// value: a large struct copy costs the verifier a byte loop).
#[inline(always)]
fn end_call(ctx: &RetProbeContext, pid_tgid: u64) -> Ended {
    let mut e = Ended {
        conn: 0,
        buf: 0,
        len: 0,
        aux: 0,
        found: 0,
        addr: NO_ADDR,
    };
    let Some(call) = TLS_CALL.get_ptr(&pid_tgid) else {
        return e;
    };
    // SAFETY: this thread's own slot (maps.rs TLS_CALL), read before delete.
    unsafe {
        if same_frame((*call).entry_sp, user_sp(ctx.regs)) {
            e.found = 1;
            e.conn = (*call).conn;
            e.buf = (*call).buf;
            e.len = (*call).len;
            e.aux = (*call).aux;
            if (*call).state == TLS_CALL_FILLED {
                e.addr = CallAddr {
                    ok: 1,
                    scope_gen: (*call).scope_gen,
                    local_addr: (*call).tuple.local_addr,
                    remote_addr: (*call).tuple.remote_addr,
                    local_port: (*call).tuple.local_port,
                    remote_port: (*call).tuple.remote_port,
                };
            }
        }
    }
    let _ = TLS_CALL.remove(&pid_tgid);
    e
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
    if !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(())?;
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;
    let restricted = restricted();
    if num <= 0 {
        if restricted {
            drop_call();
        }
        return Ok(());
    }
    mark_active(ssl);
    if restricted {
        // Emitted by ssl_write_ret, with this call's own address.
        begin_call(ctx, ssl, buf as u64, num as u64, 0);
        return Ok(());
    }

    emit_tls_event(
        ctx,
        ssl,
        buf,
        num as usize,
        Direction::Egress,
        TlsLibrary::OpenSsl,
        NO_ADDR,
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
    if !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(())?;
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: u64 = ctx.arg(2).ok_or(())?;
    let restricted = restricted();
    if num == 0 || num > u32::MAX as u64 {
        if restricted {
            drop_call();
        }
        return Ok(());
    }
    mark_active(ssl);
    if restricted {
        let written: u64 = ctx.arg(3).ok_or(())?;
        begin_call(ctx, ssl, buf as u64, num, written);
        return Ok(());
    }

    emit_tls_event(
        ctx,
        ssl,
        buf,
        num as usize,
        Direction::Egress,
        TlsLibrary::OpenSsl,
        NO_ADDR,
    )
}

/// Return probe for `SSL_write` and `SSL_write_ex`, restricted modes only
/// (attached only there): emits the plaintext the entry saved, which the
/// caller's buffer still holds, with the address this call's own socket
/// I/O gave it. The scope check runs here, in the probe that copies.
/// `SSL_write` returns the byte count; `SSL_write_ex` returns 1 and stores
/// the count through `written`.
#[uretprobe]
pub fn ssl_write_ret(ctx: RetProbeContext) {
    let _ = try_ssl_write_ret(&ctx);
}

#[inline(always)]
fn try_ssl_write_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    if !crate::sock_capture::tls_capture_on() {
        forget_call(pid_tgid);
        return Ok(());
    }
    let call = end_call(ctx, pid_tgid);
    if call.found == 0 {
        return Ok(()); // no call opened by this frame's entry probe
    }
    let _ = take_active(pid_tgid);
    let ret = ctx.ret::<i32>();
    if ret <= 0 {
        return Ok(());
    }
    let len = if call.aux == 0 {
        ret as u64
    } else {
        unsafe { bpf_probe_read_user(call.aux as *const u64) }.map_err(|_| ())?
    };
    if len == 0 || len > call.len {
        return Ok(());
    }
    emit_tls_event(
        ctx,
        call.conn,
        call.buf as *const u8,
        len as usize,
        Direction::Egress,
        TlsLibrary::OpenSsl,
        call.addr,
    )
}

// ── OpenSSL: SSL_read ──────────────────────────────────────────────────────

/// Intercepts `SSL_read(ssl, buf, num)` entry — stashes the arguments.
/// The actual data isn't available until the function returns with the
/// number of bytes read, so `begin_read` saves them for the return probe.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) {
    let _ = try_ssl_read_entry(&ctx);
}

#[inline(always)]
fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    if !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(())?;
    let buf: u64 = ctx.arg(1).ok_or(())?;
    begin_read(ctx, ssl, buf, 0);
    Ok(())
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
    if !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let ssl: u64 = ctx.arg(0).ok_or(())?;
    let buf: u64 = ctx.arg(1).ok_or(())?;
    let readbytes: u64 = ctx.arg(3).ok_or(())?;
    if readbytes == 0 {
        // Opens no call: drop whatever an earlier call left, so this
        // call's return probe cannot consume it.
        let pid_tgid = bpf_get_current_pid_tgid();
        let _ = TLS_SCRATCH.remove(&pid_tgid);
        let _ = TLS_CALL.remove(&pid_tgid);
        return Ok(());
    }
    begin_read(ctx, ssl, buf, readbytes);
    Ok(())
}

/// Open an OpenSSL read: restricted modes keep the arguments in the call
/// slot (`begin_call`), unscoped modes in TLS_SCRATCH, each stamped with
/// the entry's stack pointer. Owner-only, and a failed insert leaves no
/// entry at all (fails closed: the return probe emits nothing).
#[inline(always)]
fn begin_read(ctx: &ProbeContext, ssl: u64, buf: u64, readbytes: u64) {
    mark_active(ssl);
    if restricted() {
        begin_call(ctx, ssl, buf, 0, readbytes);
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let args = TlsReadArgs {
        buf,
        ssl,
        readbytes,
        ident: user_sp(ctx.regs),
    };
    if TLS_SCRATCH.insert(&pid_tgid, &args, 0).is_err() {
        let _ = TLS_SCRATCH.remove(&pid_tgid);
    }
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
    if !crate::sock_capture::tls_capture_on() {
        forget_call(pid_tgid);
        return Ok(());
    }

    // The marker too, if the read was served from already-buffered TLS
    // records without touching the socket.
    let _ = take_active(pid_tgid);
    // This frame's own saved arguments, consumed whatever the result: the
    // call slot in restricted modes, TLS_SCRATCH otherwise. Anything not
    // opened by this frame's entry (a nested call, a missed return) is
    // dropped and nothing is emitted from it.
    let (ssl, buf, readbytes, addr) = if restricted() {
        let call = end_call(ctx, pid_tgid);
        if call.found == 0 {
            return Ok(());
        }
        (call.conn, call.buf, call.aux, call.addr)
    } else {
        let Some(a) = TLS_SCRATCH.get_ptr(&pid_tgid) else {
            return Ok(()); // missed the entry probe
        };
        // SAFETY: this thread's own entry (maps.rs TLS_SCRATCH), read field
        // by field before the delete.
        let (ssl, buf, readbytes, ident) =
            unsafe { ((*a).ssl, (*a).buf, (*a).readbytes, (*a).ident) };
        let _ = TLS_SCRATCH.remove(&pid_tgid);
        if !same_frame(ident, user_sp(ctx.regs)) {
            return Ok(());
        }
        (ssl, buf, readbytes, NO_ADDR)
    };

    let ret = ctx.ret::<i32>();
    if ret <= 0 {
        return Ok(()); // error / would-block / closed
    }
    let len = if readbytes == 0 {
        ret as u64
    } else {
        unsafe { bpf_probe_read_user(readbytes as *const u64) }.map_err(|_| ())?
    };
    if len == 0 || len > u32::MAX as u64 {
        return Ok(());
    }

    emit_tls_event(
        ctx,
        ssl,
        buf as *const u8,
        len as usize,
        Direction::Ingress,
        TlsLibrary::OpenSsl,
        addr,
    )
}

// ── Go TLS: crypto/tls.(*Conn).Write ──────────────────────────────────────

/// Intercepts Go TLS writes. Go 1.17+ uses register-based ABI:
/// - RAX: receiver (`*tls.Conn`)
/// - RBX: pointer to byte slice data
/// - RCX: length of byte slice
/// - RDI: capacity of byte slice
///
/// Go TLS reads are not captured (see the module comment).
#[uprobe]
pub fn go_tls_write_entry(ctx: ProbeContext) {
    let _ = try_go_tls_write(&ctx);
}

#[inline(always)]
fn try_go_tls_write(ctx: &ProbeContext) -> Result<(), ()> {
    if !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let (conn, buf, len) = read_go_write_args(ctx)?;
    if len == 0 {
        return Ok(());
    }
    mark_active(conn);

    emit_tls_event(
        ctx,
        conn,
        buf,
        len,
        Direction::Egress,
        TlsLibrary::GoTls,
        NO_ADDR,
    )
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

/// An event's addresses: `ports` is src | dst << 16. No padding.
#[derive(Clone, Copy)]
#[repr(C)]
struct HdrAddr {
    src_addr: u32,
    dst_addr: u32,
    ports: u32,
    ip_proto: u32,
}

/// Fields shared by every event of one TLS read/write, computed once.
#[derive(Clone, Copy)]
struct TlsHeader {
    conn: u64,
    pid: u32,
    tgid: u32,
    addr: HdrAddr,
    direction: Direction,
    tls_lib: TlsLibrary,
    scope_gen: u32,
}

#[inline(always)]
fn tls_header(
    conn: u64,
    direction: Direction,
    tls_lib: TlsLibrary,
    restricted: bool,
    scope_gen: u32,
    call_addr: CallAddr,
) -> TlsHeader {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let mut h = TlsHeader {
        conn,
        pid,
        tgid: pid_tgid as u32,
        addr: HdrAddr {
            src_addr: 0,
            dst_addr: 0,
            ports: 0,
            ip_proto: 0,
        },
        direction,
        tls_lib,
        scope_gen,
    };
    // Unscoped: addresses are known once this connection has done socket
    // I/O inside a hooked call (see try_tls_tcp_io); zero until then.
    // Restricted: only the address of this call's own in-scope socket
    // (try_tls_tcp_io_scoped), never one cached from another call, and only
    // if the socket was checked under the generation this call is in scope
    // under now: after a narrowing it is not trusted.
    let mut t = (0u32, 0u32, 0u16, 0u16, false);
    if restricted {
        if call_addr.ok != 0 && call_addr.scope_gen == scope_gen {
            t = (
                call_addr.local_addr,
                call_addr.remote_addr,
                call_addr.local_port,
                call_addr.remote_port,
                true,
            );
        }
    } else {
        let key = TlsConnKey { conn, pid, _pad: 0 };
        if let Some(c) = unsafe { TLS_CONN_ADDR.get(&key) } {
            t = (
                c.local_addr,
                c.remote_addr,
                c.local_port,
                c.remote_port,
                true,
            );
        }
    }
    let (local_addr, remote_addr, local_port, remote_port, known) = t;
    let a = if !known {
        HdrAddr {
            src_addr: 0,
            dst_addr: 0,
            ports: 0,
            ip_proto: 0,
        }
    } else if direction == Direction::Egress {
        HdrAddr {
            src_addr: local_addr,
            dst_addr: remote_addr,
            ports: local_port as u32 | (remote_port as u32) << 16,
            ip_proto: 6,
        }
    } else {
        HdrAddr {
            src_addr: remote_addr,
            dst_addr: local_addr,
            ports: remote_port as u32 | (local_port as u32) << 16,
            ip_proto: 6,
        }
    };
    // Launder through a helper copy: the verifier sees helper-written bytes
    // as unknown on every path, so "no address" (constants) and an address
    // (map values) reach the chunk loop as one state, not several (each
    // walks the whole loop; ssl_read_ret ran out of budget on 5.15 and
    // RHEL 8). The copy is from this program's own stack and cannot fault;
    // its result is not checked, so no branch is added.
    // SAFETY: both pointers are to HdrAddr-sized stack objects.
    unsafe {
        aya_ebpf::helpers::generated::bpf_probe_read_kernel(
            &raw mut h.addr as *mut core::ffi::c_void,
            core::mem::size_of::<HdrAddr>() as u32,
            &raw const a as *const core::ffi::c_void,
        );
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
    call_addr: CallAddr,
) -> Result<(), ()> {
    // Decided here, before any reserve or copy, for every TLS writer.
    if !crate::sock_capture::tls_capture_on() {
        return Ok(());
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let mode = crate::sock_capture::scope_mode();
    // Stamped from the map in both branches: a constant 0 on one path and a
    // map value on the other doubles the states the verifier walks through
    // the chunk loop below (ssl_read_ret hit the 1M limit on RHEL 8).
    let mut scope_gen = crate::sock_capture::scope_gen();
    let restricted = !panopticon_common::scope::is_unscoped_full(mode);
    if !restricted {
        // TC backend (and unscoped full): pid_filter as before, other
        // processes' plaintext never leaves the kernel.
        if !pid_allowed(tgid) {
            return Ok(());
        }
    } else {
        // cgroup_skb backend, restricted (DESIGN §3.5, §3.6): the selector
        // union and the mode alone decide, and every drop is counted.
        match crate::sock_capture::tls_call_scope(mode, tgid) {
            Ok(g) => scope_gen = g,
            Err(reason) => {
                crate::maps::count_scope_drop(reason);
                return Ok(());
            }
        }
    }
    let h = tls_header(conn, direction, tls_lib, restricted, scope_gen, call_addr);
    let use_ringbuf = match CONFIG.get(panopticon_common::CONFIG_USE_RINGBUF) {
        Some(&v) => v != 0,
        None => true,
    };
    if !use_ringbuf {
        // PerfEventArray path (kernels < 5.8): one event per call, on the
        // per-CPU scratch map (DataEvent far exceeds the BPF stack).
        let Some(event) = EVENT_SCRATCH.get_ptr_mut(0) else {
            return Ok(());
        };
        unsafe {
            // Typed, so the zeroing is 8-byte stores, not a byte loop the
            // verifier walks 4 KiB times.
            core::ptr::write_bytes(event, 0, 1);
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
    // Every chunk of one connection object goes to the same shard, in order.
    let shard = shard_for(conn);
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
        let Some(mut entry) = shard_reserve(shard) else {
            crate::maps::count_kernel_drop();
            return Ok(()); // RingBuf full — drop
        };
        let event = entry.as_mut_ptr();
        // Every published byte is written: ring memory is not zeroed and
        // user space maps all of it, so the payload past the copied bytes
        // would show an earlier record. Zeroed whole (8-byte stores) before
        // the copy: the copy length is not a constant.
        unsafe {
            crate::maps::zero_u64s((*event).payload.as_mut_ptr(), MAX_PAYLOAD_SIZE);
        }
        populate_tls_event(event, &h, unsafe { buf.add(off) }, chunk);
        entry.submit(shard_submit_flags(shard));
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
        (*event).src_addr = h.addr.src_addr;
        (*event).dst_addr = h.addr.dst_addr;
        (*event).src_port = h.addr.ports as u16;
        (*event).dst_port = (h.addr.ports >> 16) as u16;
        (*event).ip_proto = h.addr.ip_proto as u8;
        (*event).tls_library = h.tls_lib;
        (*event).tcp_flags = 0;
        (*event).tcp_seq = 0;
        (*event).tcp_ack = 0;
        crate::maps::clear_scope_fields(event);
        (*event).scope_gen = h.scope_gen;
        (*event).orig_len = len as u32;

        // Copy plaintext from user space, clamped to MAX_PAYLOAD_SIZE. The u32
        // min (not an if/else) bounds both the signed and unsigned range, which
        // the 5.15 verifier needs on the dead chunk paths it still walks.
        let copy_len = (len as u32).min(MAX_PAYLOAD_SIZE as u32) as usize;
        (*event).payload_len = copy_len as u32;

        if copy_len > 0 {
            let dst = core::slice::from_raw_parts_mut((*event).payload.as_mut_ptr(), copy_len);
            if bpf_probe_read_user_buf(buf, dst).is_err() {
                (*event).payload_len = 0;
            }
        }
    }
}
