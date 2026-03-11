//! Process lifecycle monitoring via tracepoints.
//!
//! Tracks process creation (`sched_process_exec`) and termination
//! (`sched_process_exit`). Emits `ProcessEvent` records to the
//! `PROCESS_EVENTS` RingBuf and maintains the `PID_CGROUP_MAP` for
//! container identity resolution.

use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes},
    macros::tracepoint,
    programs::TracePointContext,
};
use panopticon_common::{EventType, MAX_COMM_SIZE, ProcessEvent};

use crate::maps::{PID_CGROUP_MAP, PROCESS_EVENTS};

// ── Process Exec ───────────────────────────────────────────────────────────

/// Fires on `sched:sched_process_exec` — a new process image is loaded.
///
/// Reads the new comm (command name) and emits a `ProcessExec` event.
/// Also stores the PID → cgroup mapping for container correlation.
#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) {
    let _ = try_sched_process_exec(&ctx);
}

#[inline(always)]
fn try_sched_process_exec(ctx: &TracePointContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    // Read the comm field from the tracepoint context.
    // The sched_process_exec tracepoint format has:
    //   field:char comm[TASK_COMM_LEN] offset:8 size:16
    //   field:pid_t pid             offset:24 size:4
    //   field:pid_t old_pid         offset:28 size:4
    let comm = read_comm(ctx)?;

    // Read the old_pid (parent's view of pid) at offset 28 as ppid approximation.
    // For a more accurate ppid, we'd read from task_struct, but this suffices for Phase 1.
    let ppid = unsafe { ctx.read_at::<u32>(28).map_err(|_| ())? };

    // Reserve space in RingBuf for ProcessEvent
    let Some(mut entry) = PROCESS_EVENTS.reserve::<ProcessEvent>(0) else {
        return Ok(()); // RingBuf full — drop event
    };

    let event = entry.as_mut_ptr();
    // SAFETY: writing to reserved RingBuf memory.
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).event_type = EventType::ProcessExec;
        (*event).pid = pid;
        (*event).tgid = tgid;
        (*event).ppid = ppid;
        (*event).comm = comm;
    }

    entry.submit(0);

    // Store PID → cgroup mapping (cgroup ID = 0 placeholder for Phase 1;
    // bpf_get_current_cgroup_id() requires kernel 4.18+ and CONFIG_CGROUPS).
    let cgroup_id: u64 = 0;
    let _ = PID_CGROUP_MAP.insert(pid, cgroup_id, 0);

    Ok(())
}

// ── Process Exit ───────────────────────────────────────────────────────────

/// Fires on `sched:sched_process_exit` — process is terminating.
///
/// Emits a `ProcessExit` event and cleans up kernel-side maps.
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) {
    let _ = try_sched_process_exit(&ctx);
}

#[inline(always)]
fn try_sched_process_exit(ctx: &TracePointContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    let comm = read_comm(ctx)?;

    let Some(mut entry) = PROCESS_EVENTS.reserve::<ProcessEvent>(0) else {
        return Ok(());
    };

    let event = entry.as_mut_ptr();
    // SAFETY: writing to reserved RingBuf memory.
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        (*event).event_type = EventType::ProcessExit;
        (*event).pid = pid;
        (*event).tgid = tgid;
        (*event).ppid = 0; // Not easily available in exit tracepoint
        (*event).comm = comm;
    }

    entry.submit(0);

    // Cleanup: remove PID from tracking maps
    let _ = PID_CGROUP_MAP.remove(pid);

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Reads the comm field from a sched tracepoint context.
/// The comm sits at offset 8 in sched_process_exec/exit tracepoint format.
#[inline(always)]
fn read_comm(ctx: &TracePointContext) -> Result<[u8; MAX_COMM_SIZE], ()> {
    let mut comm = [0u8; MAX_COMM_SIZE];

    // SAFETY: reading from the tracepoint context at the documented offset.
    // The comm field is at offset 8 in sched_process_exec format, size 16.
    let comm_ptr: *const u8 = unsafe { (ctx.as_ptr() as *const u8).add(8) };

    // Read comm as a kernel string (null-terminated), clamp to MAX_COMM_SIZE.
    // SAFETY: comm_ptr points into the tracepoint context buffer which is
    // valid for the duration of the BPF program execution.
    unsafe {
        match bpf_probe_read_kernel_str_bytes(comm_ptr, &mut comm) {
            Ok(_) => {}
            Err(_) => {
                // Fallback: zero-filled comm (already initialized)
            }
        }
    }

    Ok(comm)
}
