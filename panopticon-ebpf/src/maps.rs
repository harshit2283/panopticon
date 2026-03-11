//! BPF map definitions shared across all eBPF programs.
//!
//! Maps are the primary communication mechanism between eBPF programs and
//! user-space. RingBuf maps provide zero-copy, ordered event delivery to the
//! agent. HashMaps track per-connection and per-process state in the kernel.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, PerfEventArray, RingBuf};
use panopticon_common::{
    CONFIG_ENTRIES, ConnInfo, DataEvent, MAX_CONNECTIONS, MAX_PID_FILTER, TLS_SCRATCH_SIZE,
};

/// Primary event channel for network data (TC captures + TLS intercepts).
/// 256KB ring buffer — sized for ~60 DataEvents in flight.
#[map]
pub static DATA_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Fallback event channel for kernels < 5.8 that lack RingBuf support.
#[map]
pub static DATA_EVENTS_PERF: PerfEventArray<DataEvent> = PerfEventArray::new(0);

/// Event channel for process lifecycle events (exec/exit).
/// 64KB — process events are small (~40 bytes) and less frequent.
#[map]
pub static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Active connection tracking. Key: socket_cookie (u64).
#[map]
pub static CONN_MAP: HashMap<u64, ConnInfo> = HashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// PID → cgroup_id mapping for container identity resolution.
#[map]
pub static PID_CGROUP_MAP: HashMap<u32, u64> = HashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// Runtime configuration array. Indices defined by CONFIG_* constants.
#[map]
pub static CONFIG: Array<u64> = Array::with_max_entries(CONFIG_ENTRIES, 0);

/// Optional PID filter — when enabled, only capture traffic from listed PIDs.
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_FILTER, 0);

/// Per-CPU scratch space for TLS probe state (stores buf pointers between
/// SSL_read entry and return probes). Key: pid_tgid.
#[map]
pub static TLS_SCRATCH: PerCpuHashMap<u64, u64> =
    PerCpuHashMap::with_max_entries(TLS_SCRATCH_SIZE, 0);

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
