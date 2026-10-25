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

/// Events lost because DATA_EVENTS was full (user space not keeping up).
/// Per-CPU so the drop path needs no atomics; user space sums the CPUs.
#[map]
pub static KERNEL_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Count one event lost to a full ring buffer.
#[inline(always)]
pub fn count_kernel_drop() {
    if let Some(n) = KERNEL_DROPS.get_ptr_mut(0) {
        unsafe { *n += 1 };
    }
}

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
/// (~10.4µs vs ~1.0µs without). Wake the consumer once per
/// WAKEUP_THRESHOLD_BYTES of new data: when this record makes the pending
/// bytes cross a multiple of the threshold. Waking on every record while
/// pending was above the threshold (the earlier rule) did exactly the wrong
/// thing under load: a lagging consumer made every packet pay for a wakeup,
/// which left even less CPU to catch up (6.6µs/packet at ~40K packets/s).
/// User space also drains on a short timer, so a missed crossing (racing
/// producers) only delays delivery by one tick.
#[inline(always)]
pub fn data_events_submit_flags() -> u64 {
    // Ring buffer record = 8-byte header + DataEvent, rounded up to 8.
    const RECORD: u64 = ((core::mem::size_of::<DataEvent>() as u64 + 8) + 7) & !7;
    let pending = DATA_EVENTS.query(BPF_RB_AVAIL_DATA as u64);
    if pending / WAKEUP_THRESHOLD_BYTES != pending.saturating_sub(RECORD) / WAKEUP_THRESHOLD_BYTES {
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

/// Arguments of an in-flight `SSL_read` / `SSL_read_ex`, saved by the entry
/// probe for the return probe.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsReadArgs {
    pub buf: u64,
    pub ssl: u64,
    /// `SSL_read_ex`'s `size_t *readbytes`; 0 for `SSL_read`, whose return
    /// value is the byte count.
    pub readbytes: u64,
}

/// TLS probe state (read arguments between SSL_read entry and return
/// probes). Key: pid_tgid.
///
/// Must NOT be per-CPU: SSL_read blocks, and the thread is frequently
/// rescheduled onto another CPU before the uretprobe fires, which made the
/// lookup miss and silently dropped inbound TLS plaintext. LRU so entries
/// whose return probe never fires (thread killed mid-read) are reclaimed.
#[map]
pub static TLS_SCRATCH: LruHashMap<u64, TlsReadArgs> =
    LruHashMap::with_max_entries(TLS_SCRATCH_SIZE, 0);

/// The TLS call in progress on this CPU: which thread, and its connection
/// object (`SSL*`, `*tls.Conn`). Set by the TLS entry probes and consumed by
/// the socket send/receive hooks inside that call, which is how a TLS
/// connection learns its socket's addresses.
///
/// Per-CPU rather than a hash keyed by thread: the socket hooks run on every
/// TCP send/receive on the node, and a hash miss cost ~250ns each there. A
/// thread migrating mid-call only means that call learns nothing; the
/// connection's addresses are picked up on a later call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsActive {
    pub pid_tgid: u64,
    pub conn: u64,
}

#[map]
pub static TLS_ACTIVE: PerCpuArray<TlsActive> = PerCpuArray::with_max_entries(1, 0);

/// A TLS connection object, scoped to its process.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TlsConnKey {
    pub conn: u64,
    pub pid: u32,
    pub _pad: u32,
}

/// Socket 4-tuple (host byte order) as seen from the observed process.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockTuple {
    pub local_addr: u32,
    pub remote_addr: u32,
    pub local_port: u16,
    pub remote_port: u16,
}

/// Addresses of each TLS connection, learned on its first socket I/O.
#[map]
pub static TLS_CONN_ADDR: LruHashMap<TlsConnKey, SockTuple> =
    LruHashMap::with_max_entries(TLS_SCRATCH_SIZE * 2, 0);

/// Sockets between connect() and ESTABLISHED → owning pid_tgid, for the
/// tracepoint fallback in sock_monitor.rs. LRU: connections that never
/// complete are reclaimed.
#[map]
pub static CONNECTING: LruHashMap<u64, u64> = LruHashMap::with_max_entries(TLS_SCRATCH_SIZE, 0);

/// A Go `crypto/tls.(*Conn).Read` call in flight: process + goroutine.
/// Keyed by goroutine (the g register), not thread: a blocked Read parks
/// the goroutine, which may resume on another OS thread before returning.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GoReadKey {
    pub tgid: u32,
    pub _pad: u32,
    pub goroutine: u64,
}

/// Arguments of in-flight Go TLS reads (buf, conn), for the RET probes.
#[map]
pub static GO_READ_ARGS: LruHashMap<GoReadKey, TlsReadArgs> =
    LruHashMap::with_max_entries(TLS_SCRATCH_SIZE, 0);

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
