//! BPF map definitions shared across all eBPF programs.
//!
//! Maps are the primary communication mechanism between eBPF programs and
//! user-space. RingBuf maps provide ordered event delivery to the agent. HashMaps track per-connection and per-process state in the kernel.

use aya_ebpf::bindings::{BPF_RB_AVAIL_DATA, BPF_RB_FORCE_WAKEUP, BPF_RB_NO_WAKEUP};
use aya_ebpf::macros::map;
use aya_ebpf::maps::ring_buf::RingBufEntry;
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray, PerfEventArray, RingBuf};
use panopticon_common::{
    CONFIG_ENTRIES, CONFIG_PID_FILTER_ON, CONFIG_RING_SHARD_MASK, ConnInfo, DATA_EVENT_HEADER_LEN,
    DATA_RING_SHARDS, DataEvent, MAX_CGROUP_ALLOW, MAX_CONNECTIONS, MAX_PAYLOAD_SIZE,
    MAX_PID_FILTER, TLS_SCRATCH_SIZE, ring_shard,
    scope::{SCOPE_DROP_REASONS, STREAM_OFF_UNKNOWN},
};

/// Events lost because a DATA_EVENTS shard was full (user space not keeping
/// up). Per-CPU so the drop path needs no atomics; user space sums the CPUs.
#[map]
pub static KERNEL_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Count one event lost to a full ring buffer.
#[inline(always)]
pub fn count_kernel_drop() {
    if let Some(n) = KERNEL_DROPS.get_ptr_mut(0) {
        unsafe { *n += 1 };
    }
}

// ── Capture scope (sock_capture.rs) ────────────────────────────────────────
// Never pinned (DESIGN §2.1): each agent start begins with empty state.

/// Events the scope rules dropped, per `scope::DROP_*` reason, per CPU.
#[map]
pub static SCOPE_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(SCOPE_DROP_REASONS, 0);

/// Count one event dropped for `reason` (`scope::DROP_*`).
#[inline(always)]
pub fn count_scope_drop(reason: u32) {
    if let Some(n) = SCOPE_DROPS.get_ptr_mut(reason) {
        unsafe { *n += 1 };
    }
}

/// `cgroup_filter` / `pod_filter`: selected cgroup v2 ids. User space
/// updates it, then bumps CONFIG_SCOPE_GEN.
#[map]
pub static CGROUP_ALLOW: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CGROUP_ALLOW, 0);

/// Zero the DataEvent fields only the cgroup_skb backend fills, so other
/// producers never leak a previous event's values (ring memory and the
/// scratch map are not zeroed).
#[inline(always)]
pub fn clear_scope_fields(event: *mut DataEvent) {
    unsafe {
        (*event).cgroup_id = 0;
        (*event).stream_off = STREAM_OFF_UNKNOWN;
        (*event).owner_tgid = 0;
        (*event).acceptor_tgid = 0;
        (*event).scope_gen = 0;
        (*event).role = 0;
        (*event)._pad = [0; 1];
    }
}

// ── Network event ring buffers, sharded ────────────────────────────────────
//
// One ring shared by every CPU serialised all producers on the ring's
// reserve spinlock: at 4K connections on 64 vCPUs, bpf_ringbuf_reserve's
// lock slow path took 23% of all CPU. The events are spread over
// DATA_RING_SHARDS rings instead, chosen per connection (ring_shard: the
// per-connection order is preserved, see there), each drained by its own
// user-space thread. User space activates a power-of-two subset sized from
// the CPU count (CONFIG_RING_SHARD_MASK) and resizes every shard at load
// time so the active ones split a fixed total (loader DATA_RING_TOTAL_BYTES).
//
// TC packets are copied in at their captured size (emit_scratch_event), but
// TLS and socket events keep fixed 4,168-byte reserves (see EVENT_SCRATCH),
// so one connection's TLS burst has a single shard to fill: ~250 records at
// 1 MiB per shard on a 64-CPU node, where the single 16 MiB ring held ~3,900.

/// Size each shard is declared with; the loader overrides it.
const DATA_RING_DECLARED_BYTES: u32 = 1024 * 1024;

macro_rules! data_rings {
    ($($i:literal => $name:ident),* $(,)?) => {
        $(
            #[map]
            pub static $name: RingBuf = RingBuf::with_byte_size(DATA_RING_DECLARED_BYTES, 0);
        )*

        /// Copy `record` into shard `shard`. False if the ring is full.
        #[inline(always)]
        fn shard_output(shard: u32, record: &[u8]) -> bool {
            match shard {
                $($i => ring_output(&$name, record),)*
                _ => false,
            }
        }

        /// Reserve a fixed-size DataEvent in shard `shard`.
        #[inline(always)]
        pub fn shard_reserve(shard: u32) -> Option<RingBufEntry<DataEvent>> {
            match shard {
                $($i => $name.reserve::<DataEvent>(0),)*
                _ => None,
            }
        }

        /// Submit flags for a DataEvent just reserved in shard `shard`.
        #[inline(always)]
        pub fn shard_submit_flags(shard: u32) -> u64 {
            const RECORD: u64 = ring_record_bytes(core::mem::size_of::<DataEvent>() as u64);
            let pending = match shard {
                $($i => $name.query(BPF_RB_AVAIL_DATA as u64),)*
                _ => 0,
            };
            wakeup_flags(pending.saturating_sub(RECORD), RECORD)
        }
    };
}

data_rings!(
    0 => DATA_EVENTS_0, 1 => DATA_EVENTS_1, 2 => DATA_EVENTS_2, 3 => DATA_EVENTS_3,
    4 => DATA_EVENTS_4, 5 => DATA_EVENTS_5, 6 => DATA_EVENTS_6, 7 => DATA_EVENTS_7,
    8 => DATA_EVENTS_8, 9 => DATA_EVENTS_9, 10 => DATA_EVENTS_10, 11 => DATA_EVENTS_11,
    12 => DATA_EVENTS_12, 13 => DATA_EVENTS_13, 14 => DATA_EVENTS_14, 15 => DATA_EVENTS_15,
);
const _: () = assert!(DATA_RING_SHARDS == 16, "data_rings! declares 16 shards");

/// The shard for a connection's events.
#[inline(always)]
pub fn shard_for(socket_cookie: u64) -> u32 {
    let mask = CONFIG.get(CONFIG_RING_SHARD_MASK).map_or(0, |&m| m as u32);
    ring_shard(socket_cookie, mask & (DATA_RING_SHARDS as u32 - 1))
}

/// Send the event built in a scratch DataEvent to its connection's shard,
/// copying only the header and `payload_len` payload bytes: a typical
/// packet record is a few hundred bytes instead of 4,168, so a ring holds
/// many times more of them. Counts a kernel drop if the shard is full.
#[inline(always)]
pub fn emit_scratch_event(event: *const DataEvent) {
    // SAFETY: `event` is the per-CPU scratch map value, valid for a DataEvent.
    let (cookie, len) = unsafe {
        (
            (*event).socket_cookie,
            core::ptr::read_volatile(&(*event).payload_len),
        )
    };
    // The verifier needs the copy length provably within the map value; the
    // volatile read keeps LLVM from dropping this check as redundant.
    let len = if len > MAX_PAYLOAD_SIZE as u32 {
        MAX_PAYLOAD_SIZE
    } else {
        len as usize
    };
    let record =
        unsafe { core::slice::from_raw_parts(event as *const u8, DATA_EVENT_HEADER_LEN + len) };
    if !shard_output(shard_for(cookie), record) {
        count_kernel_drop();
    }
}

#[inline(always)]
fn ring_output(ring: &RingBuf, record: &[u8]) -> bool {
    let len = ring_record_bytes(record.len() as u64);
    let pending = ring.query(BPF_RB_AVAIL_DATA as u64);
    ring.output::<[u8]>(record, wakeup_flags(pending, len))
        .is_ok()
}

/// Bytes a record takes in a ring: 8-byte header + data, rounded up to 8.
#[inline(always)]
const fn ring_record_bytes(data_len: u64) -> u64 {
    (data_len + 8 + 7) & !7
}

/// Pending bytes in a shard at which a producer wakes its consumer: large
/// enough to batch, a quarter of the smallest shard the loader creates.
const WAKEUP_THRESHOLD_BYTES: u64 = 256 * 1024;

/// Submit flags for a record of `record` bytes added to a ring that held
/// `pending_before` unconsumed bytes.
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
fn wakeup_flags(pending_before: u64, record: u64) -> u64 {
    if (pending_before + record) / WAKEUP_THRESHOLD_BYTES != pending_before / WAKEUP_THRESHOLD_BYTES
    {
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

/// `pid_filter`: the processes (tgids) whose TLS and socket events are
/// emitted while CONFIG_PID_FILTER_ON is set. Filled by the loader.
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_FILTER, 0);

/// `pid_filter` startup record (cgroup_skb backend). The loader writes the
/// configured tgids here before sched_process_exit is attached; until the
/// scope is armed, the exit tracepoint records each candidate's exit in
/// PID_EXITED, which `arm` consults after publishing PID_FILTER. Neither map
/// is read once armed.
#[map]
pub static PID_CANDIDATES: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_FILTER, 0);

#[map]
pub static PID_EXITED: HashMap<u32, u8> = HashMap::with_max_entries(MAX_PID_FILTER, 0);

/// Failed PID_EXITED inserts; nonzero makes `arm` refuse pid_filter.
#[map]
pub static PID_EXITED_LOST: Array<u64> = Array::with_max_entries(1, 0);

/// Whether events of process `tgid` may be emitted. TC packets have no
/// process; user space filters them by their connection's owner.
#[inline(always)]
pub fn pid_allowed(tgid: u32) -> bool {
    match CONFIG.get(CONFIG_PID_FILTER_ON) {
        Some(&on) if on != 0 => unsafe { PID_FILTER.get(&tgid) }.is_some(),
        _ => true,
    }
}

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
    /// `CONFIG_SCOPE_GEN` the socket was verified in scope under
    /// (tls_probes.rs `record_conn_addr`); restricted modes serve the tuple
    /// only to a TLS call in scope under the same generation.
    pub scope_gen: u32,
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

/// Per-CPU scratch DataEvent (~4.2KB, far over the 512-byte BPF stack).
///
/// TC builds every event here, then emit_scratch_event copies its header and
/// payload to a ring shard; the PerfEventArray fallback sends it whole. Only
/// TC uses it on the ring path: TC runs with bottom halves disabled, so
/// nothing else on the CPU can touch the slot mid-event. The uprobes and
/// kprobes reserve their events in the ring instead, because a uprobe
/// program can be preempted (or interrupted by TC) on a preemptible kernel
/// and another program would then overwrite a shared slot.
#[map]
pub static EVENT_SCRATCH: PerCpuArray<DataEvent> = PerCpuArray::with_max_entries(1, 0);
