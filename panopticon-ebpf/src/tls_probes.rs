//! TLS interception uprobes for capturing plaintext before/after encryption.
//!
//! Attaches to OpenSSL's `SSL_write`/`SSL_read` and Go's TLS write functions.
//! Captures the plaintext buffer contents and emits TlsData events.
//!
//! Note: Go TLS Read is NOT intercepted in Phase 1. Go's goroutine stack
//! relocation can crash uretprobes, so we only intercept Go TLS writes.

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_buf},
    macros::{uprobe, uretprobe},
    programs::{ProbeContext, RetProbeContext},
};
use panopticon_common::{DataEvent, Direction, EventType, MAX_PAYLOAD_SIZE, TlsLibrary};

use crate::maps::{CONFIG, DATA_EVENTS, DATA_EVENTS_PERF, PERF_SCRATCH, TLS_SCRATCH};

// ── OpenSSL: SSL_write ─────────────────────────────────────────────────────

/// Intercepts `SSL_write(ssl, buf, num)` — captures plaintext being written.
/// Args: ssl (arg0), buf (arg1), num (arg2).
#[uprobe]
pub fn ssl_write_entry(ctx: ProbeContext) {
    let _ = try_ssl_write_entry(&ctx);
}

#[inline(always)]
fn try_ssl_write_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;
    if num <= 0 {
        return Ok(());
    }

    emit_tls_event(
        ctx,
        buf,
        num as usize,
        Direction::Egress,
        TlsLibrary::OpenSsl,
    )
}

// ── OpenSSL: SSL_read ──────────────────────────────────────────────────────

/// Intercepts `SSL_read(ssl, buf, num)` entry — stashes buf pointer.
/// The actual data isn't available until the function returns with the
/// number of bytes read, so we save the pointer in TLS_SCRATCH.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) {
    let _ = try_ssl_read_entry(&ctx);
}

#[inline(always)]
fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    let buf: u64 = ctx.arg(1).ok_or(())?;
    let pid_tgid = bpf_get_current_pid_tgid();
    TLS_SCRATCH.insert(pid_tgid, buf, 0).map_err(|_| ())?;
    Ok(())
}

/// Intercepts `SSL_read` return — reads the decrypted data from the
/// stashed buffer pointer, using the return value as the byte count.
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) {
    let _ = try_ssl_read_ret(&ctx);
}

#[inline(always)]
fn try_ssl_read_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Look up the buffer pointer saved during ssl_read_entry
    let buf_ptr = unsafe {
        match TLS_SCRATCH.get(pid_tgid) {
            Some(ptr) => *ptr,
            None => return Ok(()), // Missed the entry probe
        }
    };

    // Clean up scratch space
    let _ = TLS_SCRATCH.remove(pid_tgid);

    // Return value is number of bytes read (or error if negative)
    let ret = ctx.ret::<i32>();
    if ret <= 0 {
        return Ok(());
    }

    emit_tls_event(
        ctx,
        buf_ptr as *const u8,
        ret as usize,
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
    let (buf, len) = read_go_write_args(ctx)?;
    if len == 0 {
        return Ok(());
    }

    emit_tls_event(ctx, buf, len, Direction::Egress, TlsLibrary::GoTls)
}

#[inline(always)]
#[cfg(bpf_target_arch = "x86_64")]
fn read_go_write_args(ctx: &ProbeContext) -> Result<(*const u8, usize), ()> {
    // Aya's ProbeContext::arg() follows the SysV ABI (rdi, rsi, rdx, ...).
    // Go methods on x86_64 use the internal ABI instead, with the receiver in
    // rax and the []byte fields in rbx/rcx/rdi.
    let regs = unsafe { &*ctx.regs };
    Ok((regs.rbx as *const u8, regs.rcx as usize))
}

#[inline(always)]
#[cfg(not(bpf_target_arch = "x86_64"))]
fn read_go_write_args(ctx: &ProbeContext) -> Result<(*const u8, usize), ()> {
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let len: usize = ctx.arg(2).ok_or(())?;
    Ok((buf, len))
}

// ── Shared helper ──────────────────────────────────────────────────────────

#[inline(always)]
fn emit_tls_event<C: EbpfContext>(
    ctx: &C,
    buf: *const u8,
    len: usize,
    direction: Direction,
    tls_lib: TlsLibrary,
) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let use_ringbuf = match CONFIG.get(panopticon_common::CONFIG_USE_RINGBUF) {
        Some(&v) => v != 0,
        None => true,
    };

    if use_ringbuf {
        // Reserve in RingBuf (DataEvent is ~4KB, too large for BPF stack)
        let Some(mut entry) = DATA_EVENTS.reserve::<DataEvent>(0) else {
            return Ok(()); // RingBuf full — drop
        };

        let event = entry.as_mut_ptr();
        populate_tls_event(event, buf, len, direction, tls_lib, pid, tgid);
        entry.submit(0);
    } else {
        // PerfEventArray path: use per-CPU scratch map (DataEvent is ~4.2KB,
        // far exceeds the 512-byte BPF stack limit).
        let Some(event) = PERF_SCRATCH.get_ptr_mut(0) else {
            return Ok(());
        };

        unsafe {
            core::ptr::write_bytes(event as *mut u8, 0, core::mem::size_of::<DataEvent>());
        }
        populate_tls_event(event, buf, len, direction, tls_lib, pid, tgid);
        DATA_EVENTS_PERF.output(ctx, unsafe { &*event }, 0);
    }

    Ok(())
}

/// Populate a TLS DataEvent. Shared between RingBuf and PerfEventArray paths.
#[inline(always)]
fn populate_tls_event(
    event: *mut DataEvent,
    buf: *const u8,
    len: usize,
    direction: Direction,
    tls_lib: TlsLibrary,
    pid: u32,
    tgid: u32,
) {
    // SAFETY: writing to reserved RingBuf memory or stack-allocated event.
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).socket_cookie = 0; // Not available in uprobe context
        (*event).event_type = EventType::TlsData;
        (*event).direction = direction;
        (*event).pid = pid;
        (*event).tgid = tgid;
        (*event).src_addr = 0; // Not available in uprobe context
        (*event).dst_addr = 0;
        (*event).src_port = 0;
        (*event).dst_port = 0;
        (*event).ip_proto = 0;
        (*event).tls_library = tls_lib;
        (*event)._pad = [0; 3];

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
