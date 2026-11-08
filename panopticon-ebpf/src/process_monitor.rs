//! Process lifecycle monitoring via tracepoints.
//!
//! Tracks process creation (`sched_process_exec`) and termination
//! (`sched_process_exit`). Emits `ProcessEvent` records to the
//! `PROCESS_EVENTS` RingBuf and maintains the `PID_CGROUP_MAP` for
//! container identity resolution.

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::tracepoint,
    programs::TracePointContext,
};
use panopticon_common::{EventType, MAX_COMM_SIZE, ProcessEvent};

use crate::maps::{
    PID_CANDIDATES, PID_CGROUP_MAP, PID_EXITED, PID_EXITED_LOST, PID_FILTER, PROC_EPOCH,
    PROCESS_EVENTS, TLS_CALL, TLS_SCRATCH,
};

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
fn try_sched_process_exec(_ctx: &TracePointContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tgid = pid_tgid as u32;

    // The sched_process_exec tracepoint has NO comm field:
    //   field:__data_loc char[] filename  offset:8  size:4
    //   field:pid_t pid                   offset:12 size:4
    //   field:pid_t old_pid               offset:16 size:4
    // By the time it fires the task's comm has already been updated to the
    // new image, so read it from the current task instead.
    let comm = bpf_get_current_comm().unwrap_or([0u8; MAX_COMM_SIZE]);

    // The real parent is only reachable via task_struct->real_parent, which
    // needs CO-RE relocations; report 0 (unknown) rather than a garbage value.
    let ppid: u32 = 0;

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

    // Store PID → cgroup mapping for container identity (kernel 4.18+; the
    // agent's floor is 5.8).
    // SAFETY: helper takes no arguments and only reads the current task.
    let cgroup_id: u64 = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    let _ = PID_CGROUP_MAP.insert(pid, cgroup_id, 0);
    // A new image is a new process instance (maps.rs PROC_EPOCH).
    let _ = PROC_EPOCH.insert(&pid, &unsafe { bpf_ktime_get_ns() }, 0);

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
    // A thread that exits inside a TLS call never reaches its return probe.
    let _ = TLS_CALL.remove(&pid_tgid);
    let _ = TLS_SCRATCH.remove(&pid_tgid);

    // sched_process_exit fires for every exiting *thread*. Only the thread
    // group leader exiting means the process is gone; otherwise a worker
    // thread exit would tear down state for a still-running process.
    if pid != tgid {
        return Ok(());
    }

    // pid_filter: forget the process before anything that can fail (comm
    // read, ring reserve), so a reused PID never inherits its selection
    // (DESIGN §3.1). `pid` here is the tgid (high half of pid_tgid), the
    // PID_FILTER key.
    //
    // During startup a candidate's exit is recorded in PID_EXITED first and
    // only then removed from PID_FILTER. `arm` does the mirror image: insert
    // into PID_FILTER, then look in PID_EXITED. If our record lands before
    // arm's lookup, arm sees it and removes the entry; if it lands after,
    // arm's insert also came before our remove below. Either way the entry
    // ends up absent. Removing first and recording second would let arm
    // insert between the two and miss the record.
    if !crate::sock_capture::armed() && unsafe { PID_CANDIDATES.get(&pid) }.is_some() {
        if PID_EXITED.insert(&pid, &1, 0).is_err() {
            if let Some(n) = PID_EXITED_LOST.get_ptr_mut(0) {
                unsafe { *n += 1 };
            }
        }
    }
    let _ = PID_FILTER.remove(&pid);
    // The process instance ends: Go read entries it left can never match a
    // later process that reuses the tgid (maps.rs GO_READ_ARGS).
    let _ = PROC_EPOCH.remove(&pid);

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

/// Reads the comm field from the sched_process_exit tracepoint context
/// (`char comm[16]` at offset 8). Not valid for sched_process_exec.
#[inline(always)]
fn read_comm(ctx: &TracePointContext) -> Result<[u8; MAX_COMM_SIZE], ()> {
    let mut comm = [0u8; MAX_COMM_SIZE];

    // SAFETY: reading from the tracepoint context at the documented offset.
    // The comm field is at offset 8 in sched_process_exit format, size 16.
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
