//! BPF map definitions shared across all eBPF programs.
//!
//! Maps are the primary communication mechanism between eBPF programs and
//! user-space. RingBuf maps provide zero-copy, ordered event delivery to the
//! agent. HashMaps track per-connection and per-process state in the kernel.

use aya_ebpf::bindings::{BPF_RB_AVAIL_DATA, BPF_RB_FORCE_WAKEUP, BPF_RB_NO_WAKEUP};
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray, PerfEventArray, RingBuf};
use panopticon_common::{
    CONFIG_ENTRIES, ConnInfo, DataEvent, MAX_CONNECTIONS, MAX_PID_FILTER, TLS_SCRATCH_SIZE,
};

/// Primary event channel for network data (TC captures + TLS intercepts).
/// 16MB ring buffer — ~4000 fixed-size DataEvents (~4.2KB each) in flight, so
/// a short user-space stall or traffic burst does not immediately drop events.
#[map]
pub static DATA_EVENTS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

/// Pending bytes in DATA_EVENTS at which a producer wakes the consumer.
/// ~60 events: large enough to batch, small vs. the 16MB ring.
const WAKEUP_THRESHOLD_BYTES: u64 = 256 * 1024;

/// Submit flags for DATA_EVENTS records.
///
/// A wakeup per record (flags = 0) raises an irq_work self-interrupt on every
/// event; measured on a VM it was ~90% of the TC program's per-packet cost
/// (~10.4µs vs ~1.0µs without). Wake the consumer only once a batch is
/// pending; user space also drains on a short timer, bounding latency when
/// traffic stays below the threshold.
#[inline(always)]
pub fn data_events_submit_flags() -> u64 {
    if DATA_EVENTS.query(BPF_RB_AVAIL_DATA as u64) >= WAKEUP_THRESHOLD_BYTES {
        BPF_RB_FORCE_WAKEUP as u64
    } else {
        BPF_RB_NO_WAKEUP as u64
    }
}

/// Fallback event channel for kernels < 5.8 that lack RingBuf support.
#[map]
pub static DATA_EVENTS_PERF: PerfEventArray<DataEvent> = PerfEventArray::new(0);

/// Event channel for process lifecycle events (exec/exit).
/// 64KB — process events are small (~40 bytes) and less frequent.
#[map]
pub static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Active connection tracking. Key: socket_cookie (u64).
/// LRU so that closes we never observe (missed kprobes, close on another
/// thread) age out instead of permanently filling the map.
#[map]
pub static CONN_MAP: LruHashMap<u64, ConnInfo> = LruHashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// PID → cgroup_id mapping for container identity resolution.
/// LRU for the same reason as CONN_MAP (missed exit events).
#[map]
pub static PID_CGROUP_MAP: LruHashMap<u32, u64> = LruHashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// Runtime configuration array. Indices defined by CONFIG_* constants.
#[map]
pub static CONFIG: Array<u64> = Array::with_max_entries(CONFIG_ENTRIES, 0);

/// Optional PID filter — when enabled, only capture traffic from listed PIDs.
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_FILTER, 0);

/// TLS probe state (stores buf pointers between SSL_read entry and return
/// probes). Key: pid_tgid.
///
/// Must NOT be per-CPU: SSL_read blocks, and the thread is frequently
/// rescheduled onto another CPU before the uretprobe fires, which made the
/// lookup miss and silently dropped inbound TLS plaintext. LRU so entries
/// whose return probe never fires (thread killed mid-read) are reclaimed.
#[map]
pub static TLS_SCRATCH: LruHashMap<u64, u64> = LruHashMap::with_max_entries(TLS_SCRATCH_SIZE, 0);

/// Go ABI metadata — maps PID to detected Go ABI version for register-based
/// argument extraction. Key: pid, Value: ABI version flags.
#[map]
pub static GO_ABI_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// PID to connection info mapping. Populated during connect/accept kprobes,
/// looked up in TLS uprobes to fill src/dst address info.
#[map]
pub static PID_TO_CONN: HashMap<u64, ConnInfo> = HashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// IPv6 packet drop counter. Single-element array used as atomic counter.
/// Index 0: total IPv6 packets dropped (not yet supported).
#[map]
pub static IPV6_DROPS: Array<u64> = Array::with_max_entries(1, 0);

/// Per-CPU scratch space for PerfEventArray output path.
/// DataEvent is ~4.2KB — too large for the 512-byte BPF stack.
/// The PerfEventArray path writes to this scratch map instead of the stack,
/// then passes the pointer to `bpf_perf_event_output`.
#[map]
pub static PERF_SCRATCH: PerCpuArray<DataEvent> = PerCpuArray::with_max_entries(1, 0);
