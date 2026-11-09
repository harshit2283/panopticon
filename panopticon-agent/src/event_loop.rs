// The ring readers (EventLoop, consume_*) are Linux-only; the workers and
// everything after the ring read run on every platform (tests drive them).
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, bail};
#[cfg(target_os = "linux")]
use arc_swap::ArcSwap;
#[cfg(target_os = "linux")]
use aya::maps::perf::PerfEventArrayBuffer;
#[cfg(target_os = "linux")]
use aya::maps::{PerfEventArray, RingBuf};
#[cfg(target_os = "linux")]
use bytes::BytesMut;
#[cfg(target_os = "linux")]
use panopticon_common::parse_data_event_bytes;
use panopticon_common::{
    DATA_EVENT_HEADER_LEN, DataEvent, Direction, EventType, MAX_PAYLOAD_SIZE, TCP_FLAG_FIN,
    TCP_FLAG_RST, TLS_KEY_BIT, data_event_record_len, read_data_event_into,
};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tracing::warn;
use tracing::{debug, info};

use crate::graph::{ConnectionTuple, GraphBuilder};
use crate::io_gate::IoGate;
use crate::pipeline::PipelineHandle;
use crate::protocol::detect::detect_protocol;
use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};
use crate::util::format_ipv4;
#[cfg(target_os = "linux")]
use crate::{config::AgentConfig, loader::EventSource};
use crate::{
    config::{PrivacyGate, PrivacyMode},
    export::audit::PiiAuditLog,
    export::json::JsonExportHandle,
    export::otlp::OtlpExportHandle,
    pii::PiiEngine,
};

/// What a worker holds of its pipeline. Everything here belongs to one
/// capture pipeline, except the aggregate `stats` and the `privacy` mode.
pub(crate) struct WorkerTaskContext {
    pub stats: Arc<EventStats>,
    pub idle_timeout: Duration,
    pub log_events: bool,
    pub max_connections_tracked: usize,
    pub pii_engine: Option<PiiEngine>,
    pub json_export: Option<JsonExportHandle>,
    pub otlp_export: Option<OtlpExportHandle>,
    pub audit_log: Option<PiiAuditLog>,
    pub graph_builder: Option<Arc<GraphBuilder>>,
    pub raw_capture: Option<crate::export::raw_capture::RawCaptureHandle>,
    pub max_body_bytes: usize,
    pub privacy: Arc<PrivacyGate>,
    /// pid_filter / sampling settings for the worker's capture gate.
    pub capture_gate: crate::capture_gate::GateConfig,
    /// Live cgroup_skb capture: the kernel made every scope decision, and
    /// its close records only free state.
    pub kernel_scope: bool,
    /// The pipeline's I/O gate (test pause points key on it).
    pub io_gate: Arc<IoGate>,
    /// The pipeline's Kafka topic ID map.
    pub kafka_topics: crate::protocol::kafka::KafkaTopics,
}

struct MessageContext<'a> {
    privacy: PrivacyMode,
    worker_id: usize,
    log_events: bool,
    stats: &'a EventStats,
    pii_engine: &'a Option<PiiEngine>,
    json_export: &'a Option<JsonExportHandle>,
    otlp_export: &'a Option<OtlpExportHandle>,
    audit_log: &'a Option<PiiAuditLog>,
    graph_builder: &'a Option<Arc<GraphBuilder>>,
    io_gate: &'a IoGate,
    event: &'a DataEvent,
    /// Whether this event's sender is the connection's server, when known.
    sender_is_server: Option<bool>,
    max_body_bytes: usize,
    /// Local processes that opened / accepted the connection, if seen.
    owners: Option<ConnOwners>,
}

/// PIDs of the local processes on either end of a TCP connection, from the
/// connect / accept hooks (sock_monitor.rs).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ConnOwners {
    client: Option<u32>,
    server: Option<u32>,
}

/// Per-worker connection → owners map. Bounded: owners arrive for every TCP
/// connection on the node, not only captured ones, so the map is cleared
/// when it reaches its cap rather than growing without limit.
#[derive(Default)]
struct OwnerTable {
    owners: fxhash::FxHashMap<u64, ConnOwners>,
    cap: usize,
}

impl OwnerTable {
    fn new(cap: usize) -> Self {
        Self {
            owners: Default::default(),
            cap: cap.max(1),
        }
    }

    /// Record a SockConnect / SockAccept event; ignores other events.
    fn observe(&mut self, event: &DataEvent) {
        let is_client = match event.event_type {
            EventType::SockConnect => true,
            EventType::SockAccept => false,
            _ => return,
        };
        if event.pid == 0 {
            return;
        }
        if self.owners.len() >= self.cap && !self.owners.contains_key(&event.socket_cookie) {
            self.owners.clear();
        }
        let entry = self.owners.entry(event.socket_cookie).or_default();
        if is_client {
            entry.client = Some(event.pid);
        } else {
            entry.server = Some(event.pid);
        }
    }

    fn get(&self, cookie: u64) -> Option<ConnOwners> {
        self.owners.get(&cookie).copied()
    }

    fn remove(&mut self, cookie: u64) {
        self.owners.remove(&cookie);
    }
}

// ── Event Statistics ──────────────────────────────────────────────────────

/// Atomic counters for monitoring event processing health.
/// Exported via tracing and (later) Prometheus.
pub struct EventStats {
    pub events_received: AtomicU64,
    pub events_dropped: AtomicU64,
    pub events_processed: AtomicU64,
    pub active_connections: AtomicU64,
    // Per-reason drop counters (6.9)
    pub drops_rate_limit: AtomicU64,
    pub drops_channel_full: AtomicU64,
    pub drops_parser_error: AtomicU64,
    // Backpressure detection (7.3)
    pub backpressure_events: AtomicU64,
    // Eviction counters (7.4)
    pub evictions_capacity: AtomicU64,
    pub evictions_idle: AtomicU64,
    /// Total PII entities detected across all fields of all messages.
    pub pii_detections: AtomicU64,
    /// Events whose payload was cut at the capture cap (orig_len > payload_len).
    pub truncated_events: AtomicU64,
    /// Events the kernel could not queue because the ring buffer was full
    /// (summed from the eBPF KERNEL_DROPS map; never reach `events_received`).
    pub kernel_drops: AtomicU64,
    /// Parsed exchanges not exported because the JSON writer was behind.
    pub drops_export_full: AtomicU64,
    /// Parser / PII steps that panicked and were skipped (worker kept running).
    pub worker_panics: AtomicU64,
    /// TCP segments ignored whole: retransmissions of bytes already parsed,
    /// or outside the connection's window (forged, or a stale RST / FIN).
    pub tcp_segments_ignored: AtomicU64,
    /// `pid_filter`: events dropped in user space (not counted: TLS and
    /// socket events of other processes, which the kernel drops).
    pub pid_filter_dropped_events: AtomicU64,
    /// `pid_filter`: TC connections dropped because no listed process was
    /// seen to own them (other processes' connections, connections opened
    /// before the agent started).
    pub pid_filter_unknown_owner_connections: AtomicU64,
    /// `connection_sample`: connections and events sampled out.
    pub sampled_out_connections: AtomicU64,
    pub sampled_out_events: AtomicU64,
    /// `head_only`: events cut or dropped past the per-direction limit.
    pub head_only_cut_events: AtomicU64,
    /// cgroup_skb: events dropped at the ring read because their scope
    /// generation is below the admission floor (a narrowing came after it).
    pub drops_stale_scope_gen: AtomicU64,
    /// Events dropped at the ring read because no capture pipeline is
    /// installed (a pipeline build failed after a narrowing, or capture
    /// stopped).
    pub drops_no_pipeline: AtomicU64,
    /// Capture was stopped for good (a fatal scope publication failure):
    /// the agent stays up, disarmed, and reports not ready.
    pub capture_stopped: AtomicBool,
    /// cgroup_skb: the kernel's `SCOPE_DROPS` per reason, summed over CPUs
    /// (refreshed from the map; indexed by `scope::DROP_*`).
    pub scope_drops: [AtomicU64; panopticon_common::scope::SCOPE_DROP_REASONS as usize],
}

impl EventStats {
    pub fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            events_processed: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            drops_rate_limit: AtomicU64::new(0),
            drops_channel_full: AtomicU64::new(0),
            drops_parser_error: AtomicU64::new(0),
            backpressure_events: AtomicU64::new(0),
            evictions_capacity: AtomicU64::new(0),
            evictions_idle: AtomicU64::new(0),
            pii_detections: AtomicU64::new(0),
            truncated_events: AtomicU64::new(0),
            kernel_drops: AtomicU64::new(0),
            drops_export_full: AtomicU64::new(0),
            worker_panics: AtomicU64::new(0),
            tcp_segments_ignored: AtomicU64::new(0),
            pid_filter_dropped_events: AtomicU64::new(0),
            pid_filter_unknown_owner_connections: AtomicU64::new(0),
            sampled_out_connections: AtomicU64::new(0),
            sampled_out_events: AtomicU64::new(0),
            head_only_cut_events: AtomicU64::new(0),
            drops_stale_scope_gen: AtomicU64::new(0),
            drops_no_pipeline: AtomicU64::new(0),
            capture_stopped: AtomicBool::new(false),
            scope_drops: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

// ── Admission floor (cgroup_skb, DESIGN §3 narrowing) ─────────────────────

/// The lowest scope generation the ring readers admit, shared by all of
/// them. Only ever raised. Stays 0 on TC, whose events carry generation 0.
#[derive(Clone, Default)]
pub struct AdmissionFloor(Arc<AtomicU32>);

impl AdmissionFloor {
    /// Admit nothing computed under a generation below `generation` from
    /// now on.
    pub fn raise(&self, generation: u32) {
        self.0.fetch_max(generation, Ordering::SeqCst);
    }

    /// Loaded once per drained batch, after the pipeline handle.
    pub(crate) fn get(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Whether `event` is dropped at the ring read under admission `floor`. A
/// close record carries no generation and reaches no sink (it only frees
/// state), so it is never stale.
fn below_floor(event: &DataEvent, floor: u32) -> bool {
    event.event_type != EventType::SockClose && event.scope_gen < floor
}

// ── Rate Limiter (global token bucket) ───────────────────────────────────

/// Global token-bucket rate limiter.
///
/// Refilled by the reader task at a fixed interval. A single AtomicU64
/// is sufficient — at 500K events/sec the ~10ns CAS per event is negligible
/// compared to the ~2µs per-event processing budget.
pub struct RateLimiter {
    tokens: AtomicU64,
    max_tokens: u64,
}

impl RateLimiter {
    /// Create a rate limiter with the given max events/sec.
    /// If `max_events_per_sec` is 0, the limiter is unlimited.
    pub fn new(max_events_per_sec: u64) -> Self {
        Self {
            tokens: AtomicU64::new(max_events_per_sec),
            max_tokens: max_events_per_sec,
        }
    }

    /// Try to consume one token. Returns true if allowed.
    pub fn try_acquire(&self) -> bool {
        if self.max_tokens == 0 {
            return true; // Unlimited
        }
        // Optimistic check to avoid CAS when already at zero
        if self.tokens.load(Ordering::Relaxed) == 0 {
            return false;
        }
        // CAS loop to decrement
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Refill tokens by a fraction of max. Called every 100ms (10x/sec)
    /// for smoother rate limiting instead of bursty once-per-second refill.
    pub fn refill(&self) {
        if self.max_tokens > 0 {
            let refill_amount = self.max_tokens / 10; // 10 ticks per second
            loop {
                let current = self.tokens.load(Ordering::Relaxed);
                let new_val = current.saturating_add(refill_amount).min(self.max_tokens);
                if self
                    .tokens
                    .compare_exchange_weak(current, new_val, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            }
        }
    }
}

// ── Event Loop ───────────────────────────────────────────────────────────

/// The ring readers. Everything after the ring read is the current capture
/// pipeline (`pipeline.rs`), whose handle the readers load from `slot`.
#[cfg(target_os = "linux")]
pub struct EventLoop {
    config: AgentConfig,
    stats: Arc<EventStats>,
    slot: Arc<ArcSwap<PipelineHandle>>,
    admission_floor: AdmissionFloor,
}

/// What every ring reader shares.
#[cfg(target_os = "linux")]
struct ReaderCtx {
    slot: Arc<ArcSwap<PipelineHandle>>,
    rate_limiter: Arc<RateLimiter>,
    stats: Arc<EventStats>,
    floor: AdmissionFloor,
}

#[cfg(target_os = "linux")]
impl EventLoop {
    pub fn new(
        config: AgentConfig,
        stats: Arc<EventStats>,
        slot: Arc<ArcSwap<PipelineHandle>>,
        admission_floor: AdmissionFloor,
    ) -> Self {
        Self {
            config,
            stats,
            slot,
            admission_floor,
        }
    }

    pub fn stats(&self) -> &Arc<EventStats> {
        &self.stats
    }

    /// Main entry point: consume the kernel's events and route them to the
    /// current pipeline's workers.
    pub async fn run(self, event_source: EventSource) -> Result<()> {
        if self.config.max_worker_count == 0 {
            bail!("max_worker_count must be >= 1");
        }
        if self.config.worker_channel_capacity == 0 {
            bail!("worker_channel_capacity must be >= 1");
        }

        // Rate limiter (aggregate: counts, not captured data)
        let rate_limiter = Arc::new(RateLimiter::new(self.config.max_events_per_sec));

        // Rate limiter refill task (every 100ms for smooth rate limiting)
        let rl = Arc::clone(&rate_limiter);
        let refill_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            loop {
                interval.tick().await;
                rl.refill();
            }
        });

        // Stats reporting task (every 10 seconds): aggregate counters only
        // (DESIGN §3, exempt), so it logs outside every pipeline.
        let stats_ref = Arc::clone(&self.stats);
        let stats_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let received = stats_ref.events_received.load(Ordering::Relaxed);
                let dropped = stats_ref.events_dropped.load(Ordering::Relaxed);
                let processed = stats_ref.events_processed.load(Ordering::Relaxed);
                let active = stats_ref.active_connections.load(Ordering::Relaxed);
                let drops_rate = stats_ref.drops_rate_limit.load(Ordering::Relaxed);
                let drops_channel = stats_ref.drops_channel_full.load(Ordering::Relaxed);
                let drops_parser = stats_ref.drops_parser_error.load(Ordering::Relaxed);
                let evictions_cap = stats_ref.evictions_capacity.load(Ordering::Relaxed);
                let evictions_idle = stats_ref.evictions_idle.load(Ordering::Relaxed);
                let backpressure = stats_ref.backpressure_events.load(Ordering::Relaxed);

                // Backpressure detection (7.3): warn if drop rate exceeds 5%
                if received > 0 {
                    let drop_rate = dropped as f64 / received as f64;
                    if drop_rate > 0.05 {
                        warn!(
                            drop_rate = format!("{:.2}%", drop_rate * 100.0),
                            received,
                            dropped,
                            "High drop rate detected — backpressure threshold exceeded"
                        );
                        stats_ref
                            .backpressure_events
                            .fetch_add(1, Ordering::Relaxed);
                        // TODO: set CONFIG_CAPTURE_ENABLED = 0 in eBPF CONFIG map when backpressure is high
                    }
                }
                info!(
                    received,
                    dropped,
                    processed,
                    active_connections = active,
                    drops_rate_limit = drops_rate,
                    drops_channel_full = drops_channel,
                    drops_parser_error = drops_parser,
                    evictions_capacity = evictions_cap,
                    evictions_idle = evictions_idle,
                    backpressure_events = backpressure,
                    "Event stats"
                );
            }
        });

        let reader = Arc::new(ReaderCtx {
            slot: Arc::clone(&self.slot),
            rate_limiter,
            stats: Arc::clone(&self.stats),
            floor: self.admission_floor.clone(),
        });
        // Consume kernel events inline — this is the main blocking call.
        let data_result = consume_data_events(event_source, reader).await;

        refill_handle.abort();
        stats_handle.abort();
        data_result
    }
}

/// Consume events from the kernel and route to workers.
/// Branches based on the EventSource (RingBuf for >= 5.8, PerfEventArray for older).
#[cfg(target_os = "linux")]
async fn consume_data_events(event_source: EventSource, reader: Arc<ReaderCtx>) -> Result<()> {
    match event_source {
        EventSource::RingBuf(rings) => consume_ringbufs(rings, reader).await,
        EventSource::PerfEventArray(perf_array) => consume_perf_array(perf_array, &reader).await,
    }
}

/// Consume the ring buffer shards (kernel >= 5.8), each on its own OS
/// thread. Draining used to run inside the tokio main loop, where one thread
/// copying every event capped throughput (98% of a core at 200 KB bodies ×
/// 1K connections, and every millisecond it lagged became kernel drops).
/// Each connection's events are in one shard, drained by one thread into
/// FIFO worker channels, so per-connection order is kept.
///
/// The drain threads are long-lived and outside every pipeline: they log
/// nothing derived from captured data, and hold a pipeline handle only for
/// the length of one drained batch.
#[cfg(target_os = "linux")]
async fn consume_ringbufs(
    rings: Vec<RingBuf<aya::maps::MapData>>,
    reader: Arc<ReaderCtx>,
) -> Result<()> {
    /// Stops the drain threads when this future ends or is dropped (shutdown
    /// drops it): they exit within one poll timeout, releasing their
    /// pipeline handles so the workers can drain and finish.
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let stop = StopOnDrop(Arc::new(AtomicBool::new(false)));
    let (exit_tx, mut exit_rx) = mpsc::unbounded_channel::<Result<()>>();

    info!(
        shards = rings.len(),
        "DATA_EVENTS RingBuf consumer started (Kernel >= 5.8)"
    );
    let shards = rings.len();
    for (shard, ring) in rings.into_iter().enumerate() {
        let reader = Arc::clone(&reader);
        let stop = Arc::clone(&stop.0);
        let exit_tx = exit_tx.clone();
        std::thread::Builder::new()
            .name(format!("ring-drain-{shard}"))
            .spawn(move || {
                let result = drain_thread(ring, (shard, shards), &reader, &stop);
                let _ = exit_tx.send(result);
            })
            .context("Failed to spawn a ring buffer drain thread")?;
    }
    drop(exit_tx);
    match exit_rx.recv().await {
        Some(Err(e)) => Err(e),
        _ => Err(anyhow::anyhow!("RingBuf drain thread exited")),
    }
}

/// One shard's drain loop: sleep until the kernel's wakeup or the drain
/// tick, then drain everything pending.
///
/// The kernel only wakes us once a batch is pending (see wakeup_flags in
/// the eBPF crate): a wakeup per event cost ~90% of per-packet kernel time.
/// Edge-triggered epoll returns on those wakeups only, not whenever a byte
/// is pending, so a busy ring is drained in batches rather than spun on.
/// The tick bounds delivery latency when traffic is too light to reach the
/// wakeup threshold; it backs off while the ring stays empty so an idle
/// agent isn't woken 500 times a second.
#[cfg(target_os = "linux")]
fn drain_thread(
    mut ring: RingBuf<aya::maps::MapData>,
    (shard, shards): (usize, usize),
    reader: &ReaderCtx,
    stop: &AtomicBool,
) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // SAFETY: plain syscalls; the epoll fd is owned (closed on return) and
    // the ring fd outlives it.
    let epoll = unsafe {
        let fd = libc::epoll_create1(libc::EPOLL_CLOEXEC);
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("epoll_create1");
        }
        let epoll = OwnedFd::from_raw_fd(fd);
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLET) as u32,
            u64: 0,
        };
        if libc::epoll_ctl(fd, libc::EPOLL_CTL_ADD, ring.as_raw_fd(), &mut ev) < 0 {
            return Err(std::io::Error::last_os_error()).context("epoll_ctl on ring buffer");
        }
        epoll
    };
    // Header and payload of the event being routed; reused for every event.
    // SAFETY: all-zero is a valid DataEvent (every enum has a 0 variant).
    let mut scratch: Box<DataEvent> = Box::new(unsafe { std::mem::zeroed() });
    let mut interval = RINGBUF_DRAIN_INTERVAL;
    while !stop.load(Ordering::Relaxed) {
        let mut ev = libc::epoll_event { events: 0, u64: 0 };
        // SAFETY: one valid epoll_event to fill.
        let woken =
            unsafe { libc::epoll_wait(epoll.as_raw_fd(), &mut ev, 1, interval.as_millis() as i32) };
        if woken < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err).context("epoll_wait on ring buffer");
        }
        let drained = drain_ringbuf(&mut ring, &mut scratch, reader, shard, shards);
        // Woken by the kernel: traffic is flowing, keep the tight bound.
        interval = if woken > 0 {
            RINGBUF_DRAIN_INTERVAL
        } else {
            next_drain_interval(interval, drained)
        };
    }
    Ok(())
}

/// Max delay before buffered ring-buffer events are drained without a kernel
/// wakeup (kernel → user-space latency bound under light traffic).
#[cfg(target_os = "linux")]
const RINGBUF_DRAIN_INTERVAL: Duration = Duration::from_millis(2);

/// Upper bound for the drain tick while the ring buffer stays empty: the
/// first event after an idle period is delivered within this delay.
#[cfg(target_os = "linux")]
const RINGBUF_IDLE_DRAIN_INTERVAL: Duration = Duration::from_millis(16);

/// Next drain tick: back to the tight bound as soon as a drain finds events,
/// doubling (up to the idle bound) after each empty drain.
#[cfg(target_os = "linux")]
fn next_drain_interval(current: Duration, drained: usize) -> Duration {
    if drained > 0 {
        RINGBUF_DRAIN_INTERVAL
    } else {
        (current * 2).min(RINGBUF_IDLE_DRAIN_INTERVAL)
    }
}

/// Drain every pending event from the ring buffer and route it to workers.
/// Copies each event's header and payload bytes once into the routing
/// scratch, and from there into the worker's batch: never a whole 4KB
/// DataEvent. The whole batch is admitted against one snapshot
/// ([`Admission`]).
#[cfg(target_os = "linux")]
fn drain_ringbuf(
    ring: &mut RingBuf<aya::maps::MapData>,
    scratch: &mut DataEvent,
    reader: &ReaderCtx,
    shard: usize,
    shards: usize,
) -> usize {
    let mut admission = Admission::new(&reader.slot, &reader.floor, &reader.stats, shard, shards);
    let mut drained = 0;
    while let Some(item) = ring.next() {
        drained += 1;
        if !read_data_event_into(item.as_ref(), scratch) {
            continue; // Malformed event, skip
        }
        admission.offer(scratch, &reader.rate_limiter);
    }
    admission.finish();
    drained
}

/// One drained batch's admission (DESIGN §3, review 11 finding 2): the
/// pipeline handle is loaded once, *then* the admission floor, and the
/// floor check, the dispatch and the hand-off to workers all use that
/// snapshot. Batches pending in the [`WorkerBatcher`] keep their
/// destination: they are never moved to a newer pipeline, and die with
/// theirs if it is revoked.
///
/// The load order matters: the publisher raises the floor before it
/// installs a new pipeline, so a reader that sees the new pipeline also
/// sees the raised floor and cannot admit an old-generation event into it.
/// A reader still holding the old pipeline may admit one there; that
/// pipeline's gate is revoked before the change is reported applied.
pub(crate) struct Admission<'a> {
    batcher: WorkerBatcher,
    floor: u32,
    stats: &'a EventStats,
    received: u64,
    stale: u64,
}

impl<'a> Admission<'a> {
    pub(crate) fn new(
        slot: &arc_swap::ArcSwap<PipelineHandle>,
        floor: &AdmissionFloor,
        stats: &'a EventStats,
        shard: usize,
        shards: usize,
    ) -> Self {
        let handle = slot.load_full(); // first: see above
        let floor = floor.get(); // then the floor
        Self {
            batcher: WorkerBatcher::new(handle, shard, shards),
            floor,
            stats,
            received: 0,
            stale: 0,
        }
    }

    /// Admit or drop one event.
    pub(crate) fn offer(&mut self, event: &DataEvent, rate_limiter: &RateLimiter) {
        self.received += 1;
        // Before dispatch: computed under a scope a narrowing has revoked.
        if below_floor(event, self.floor) {
            self.stale += 1;
            return;
        }
        if !rate_limiter.try_acquire() {
            self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            self.stats.drops_rate_limit.fetch_add(1, Ordering::Relaxed);
            return;
        }
        crate::test_hooks::pause(
            crate::test_hooks::READER_AFTER_ADMISSION,
            &self.batcher.handle.gate,
        );
        // Route to worker by connection key (deterministic affinity).
        self.batcher.push(connection_key(event), event, self.stats);
    }

    /// Send what is pending and count the batch.
    pub(crate) fn finish(mut self) {
        self.batcher.flush(self.stats);
        // One shared-counter update per drain, not per event: every drain
        // thread bumps it.
        self.stats
            .events_received
            .fetch_add(self.received, Ordering::Relaxed);
        if self.stale > 0 {
            self.stats
                .events_dropped
                .fetch_add(self.stale, Ordering::Relaxed);
            self.stats
                .drops_stale_scope_gen
                .fetch_add(self.stale, Ordering::Relaxed);
        }
    }
}

/// Events handed to a worker in one channel message, packed back to back:
/// each a DataEvent header plus only its `payload_len` payload bytes. A Vec
/// of whole DataEvents copied 4,160 bytes per event however small the
/// packet (glibc memmove was 15-21% of agent CPU).
#[derive(Default)]
pub(crate) struct EventBatch {
    bytes: Vec<u8>,
    len: usize,
}

impl EventBatch {
    /// Append `event`'s header and its captured payload bytes.
    pub(crate) fn push(&mut self, event: &DataEvent) {
        if self.bytes.capacity() == 0 {
            // One fixed-size allocation per batch, never regrown: a batch
            // is sent once it reaches WORKER_BATCH_BYTES, so this always
            // fits. Regrowing (32 KB → 512 KB for 64 full-size events)
            // doubled the memory held by queued batches.
            self.bytes
                .reserve_exact(WORKER_BATCH_BYTES + std::mem::size_of::<DataEvent>());
        }
        let payload = event.payload_bytes();
        // SAFETY: DataEvent is repr(C) plain data with no implicit padding;
        // the header is the first DATA_EVENT_HEADER_LEN bytes.
        let header = unsafe {
            std::slice::from_raw_parts(
                (event as *const DataEvent).cast::<u8>(),
                DATA_EVENT_HEADER_LEN,
            )
        };
        let start = self.bytes.len();
        self.bytes.extend_from_slice(header);
        if event.payload_len as usize > MAX_PAYLOAD_SIZE {
            // payload_bytes() clamped it; the record must say so too.
            let at = start + std::mem::offset_of!(DataEvent, payload_len);
            self.bytes[at..at + 4].copy_from_slice(&(payload.len() as u32).to_ne_bytes());
        }
        self.bytes.extend_from_slice(payload);
        self.len += 1;
    }

    fn len(&self) -> usize {
        self.len
    }

    /// Ready to send: WORKER_BATCH events or WORKER_BATCH_BYTES bytes.
    pub(crate) fn is_full(&self) -> bool {
        self.len >= WORKER_BATCH || self.bytes.len() >= WORKER_BATCH_BYTES
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The packed records, in push order. Load one with
    /// `read_data_event_into`.
    fn records(&self) -> impl Iterator<Item = &[u8]> {
        let mut rest = self.bytes.as_slice();
        std::iter::from_fn(move || {
            let (record, tail) = rest.split_at(data_event_record_len(rest)?);
            rest = tail;
            Some(record)
        })
    }
}

/// Most events per batch. One send (and at most one worker wakeup) per
/// batch instead of per event: per-event sends woke a parked worker thread
/// for almost every packet at moderate rates, which cost more CPU than
/// parsing the packet.
pub(crate) const WORKER_BATCH: usize = 64;

/// Most bytes per batch (plus the event that crosses it). Bounds the memory
/// a worker's queued batches hold to about channel slots × 68 KB, whatever
/// the payload size.
const WORKER_BATCH_BYTES: usize = 64 * 1024;

/// The worker for an event drained from ring shard `shard` of `shards`.
///
/// Each drain thread feeds its own subset of the workers (shard,
/// shard + shards, shard + 2 * shards, ...). Routing every shard to every
/// worker made each drain thread send a partial batch to nearly every worker
/// on every drain, so the workers' channel slots filled with small batches:
/// at 1K-4K connections that dropped 5-30% of events as channel-full while
/// the workers sat half idle. A connection's events are all in one shard, so
/// it still always reaches the same worker.
fn worker_index(routing_key: u64, shard: usize, shards: usize, workers: usize) -> usize {
    let per_shard = workers.div_ceil(shards.max(1));
    (shard + shards * (routing_key as usize % per_shard)) % workers
}

/// Groups events per worker during one ring buffer drain, for the workers
/// of one pipeline snapshot.
struct WorkerBatcher {
    handle: Arc<PipelineHandle>,
    pending: Vec<EventBatch>,
    shard: usize,
    shards: usize,
}

impl WorkerBatcher {
    fn new(handle: Arc<PipelineHandle>, shard: usize, shards: usize) -> Self {
        Self {
            pending: handle
                .senders
                .iter()
                .map(|_| EventBatch::default())
                .collect(),
            handle,
            shard,
            shards,
        }
    }

    fn push(&mut self, routing_key: u64, event: &DataEvent, stats: &EventStats) {
        let workers = self.handle.senders.len();
        if workers == 0 {
            // No pipeline installed: dropped, counted.
            stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            stats.drops_no_pipeline.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let idx = worker_index(routing_key, self.shard, self.shards, workers);
        self.pending[idx].push(event);
        if self.pending[idx].is_full() {
            self.send(idx, stats);
        }
    }

    fn flush(&mut self, stats: &EventStats) {
        for idx in 0..self.pending.len() {
            if !self.pending[idx].is_empty() {
                self.send(idx, stats);
            }
        }
    }

    /// try_send: never block the reader. Drop the batch if the worker is
    /// behind.
    fn send(&mut self, idx: usize, stats: &EventStats) {
        let batch = std::mem::take(&mut self.pending[idx]);
        let n = batch.len() as u64;
        if self.handle.senders[idx].try_send(batch).is_err() {
            stats.events_dropped.fetch_add(n, Ordering::Relaxed);
            stats.drops_channel_full.fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Consume events from a PerfEventArray (kernel < 5.8 fallback).
#[cfg(target_os = "linux")]
async fn consume_perf_array(
    mut perf_array: PerfEventArray<aya::maps::MapData>,
    reader: &ReaderCtx,
) -> Result<()> {
    let cpus = aya::util::online_cpus().map_err(|(path, error)| {
        anyhow::anyhow!("Failed to get online CPUs from {path}: {error}")
    })?;

    let (event_tx, mut event_rx) = mpsc::channel::<DataEvent>(4096);
    let mut reader_handles = Vec::new();
    for cpu in cpus {
        // Open a perf buffer for each CPU. 256 pages per CPU.
        let buf = perf_array
            .open(cpu, Some(256))
            .with_context(|| format!("Failed to open perf buffer for CPU {}", cpu))?;
        let tx = event_tx.clone();
        reader_handles.push(tokio::spawn(
            async move { perf_reader_task(cpu, buf, tx).await },
        ));
    }
    drop(event_tx);

    info!(
        cpus = reader_handles.len(),
        "DATA_EVENTS_PERF PerfEventArray consumer started (Kernel < 5.8 fallback)"
    );

    // Unlike RingBuf, PerfEventArray Events arrive per-CPU and may be globally out-of-order.
    // Flow parsing is per-connection so out-of-order across *different* connections is fine.
    while let Some(event) = event_rx.recv().await {
        // One event per receive: the snapshot (pipeline, then floor) is
        // taken for each.
        let mut admission = Admission::new(&reader.slot, &reader.floor, &reader.stats, 0, 1);
        admission.offer(&event, &reader.rate_limiter);
        admission.finish();
    }

    for handle in reader_handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!(error = %e, "PerfEventArray reader exited with error"),
            Err(e) => warn!(error = %e, "PerfEventArray reader task join error"),
        }
    }

    Err(anyhow::anyhow!("All PerfEventArray readers exited"))
}

#[cfg(target_os = "linux")]
async fn perf_reader_task(
    cpu: u32,
    buf: PerfEventArrayBuffer<aya::maps::MapData>,
    event_tx: mpsc::Sender<DataEvent>,
) -> Result<()> {
    let mut async_fd: AsyncFd<PerfEventArrayBuffer<aya::maps::MapData>> = AsyncFd::new(buf)?;
    let event_size = std::mem::size_of::<DataEvent>();
    let mut buffers = (0..10)
        .map(|_| BytesMut::with_capacity(event_size))
        .collect::<Vec<_>>();
    let mut dropped_on_backpressure = 0u64;

    loop {
        let mut guard = async_fd.readable_mut().await?;
        let perf = guard.get_inner_mut();
        let events = perf
            .read_events(&mut buffers)
            .with_context(|| format!("Failed to read perf events for CPU {}", cpu))?;

        if events.lost > 0 {
            warn!(cpu, lost = events.lost, "PerfEventArray lost events");
        }

        for data in buffers.iter().take(events.read) {
            let Some(event) = parse_data_event_bytes(data) else {
                continue;
            };
            if event_tx.try_send(event).is_err() {
                dropped_on_backpressure += 1;
                if dropped_on_backpressure.is_power_of_two() {
                    warn!(
                        cpu,
                        dropped_on_backpressure,
                        "PerfEventArray relay channel full, dropping events"
                    );
                }
            }
        }

        guard.clear_ready();
    }
}

/// Worker task: receives events from its channel, maintains per-connection
/// state. Runs under its pipeline's tracing `Dispatch`.
/// A worker's connection table. The connections it still holds leave the
/// shared `active_connections` gauge when it is dropped: when the worker
/// ends, and when a narrowing discards the worker's pipeline (its task is
/// aborted), so the gauge never keeps a discarded pipeline's connections.
struct TrackedConnections {
    manager: ConnectionFsmManager,
    stats: Arc<EventStats>,
}

impl std::ops::Deref for TrackedConnections {
    type Target = ConnectionFsmManager;
    fn deref(&self) -> &ConnectionFsmManager {
        &self.manager
    }
}

impl Drop for TrackedConnections {
    fn drop(&mut self) {
        let n = self.manager.len() as u64;
        let _ =
            self.stats
                .active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(n))
                });
    }
}

pub(crate) async fn worker_task(
    worker_id: usize,
    mut rx: mpsc::Receiver<EventBatch>,
    ctx: WorkerTaskContext,
) {
    use crate::capture_gate::{CaptureGate, Verdict};

    let manager = TrackedConnections {
        manager: ConnectionFsmManager::with_topics(
            ctx.max_connections_tracked,
            ctx.kafka_topics.clone(),
        ),
        stats: Arc::clone(&ctx.stats),
    };
    let mut owners = OwnerTable::new(ctx.max_connections_tracked);
    let mut gate = CaptureGate::new(ctx.capture_gate.clone(), ctx.max_connections_tracked);
    let mut last_sweep = Instant::now();
    let sweep_interval = Duration::from_secs(5);

    debug!(worker_id, "Worker started");

    // The event being processed: each record's header and payload bytes are
    // copied in; past payload_len it keeps earlier bytes, never read.
    // SAFETY: all-zero is a valid DataEvent (every enum has a 0 variant).
    let mut scratch: Box<DataEvent> = Box::new(unsafe { std::mem::zeroed() });
    while let Some(batch) = rx.recv().await {
        for record in batch.records() {
            if !read_data_event_into(record, &mut scratch) {
                continue;
            }
            let cookie = connection_key(&scratch);
            // Live cgroup_skb: a close record (sockops STATE_CB) is sent for
            // every socket the kernel tracks, in scope or not, with its
            // tuple and owner: it frees the connection's state and reaches
            // no sink. Counted processed (it is consumed here). On TC and in
            // replay a close takes the gated path below, as before.
            if ctx.kernel_scope && scratch.event_type == EventType::SockClose {
                ctx.stats.events_processed.fetch_add(1, Ordering::Relaxed);
                end_connection(&ctx, &manager, &mut owners, &mut gate, cookie);
                continue;
            }
            // Owners first: they decide whether the connection's TC packets
            // pass pid_filter. Only a listed process may name one.
            if gate.pid_allowed(scratch.pid) {
                owners.observe(&scratch);
            }
            let known = owners
                .get(cookie)
                .map_or([None; 2], |o| [o.client, o.server]);
            // The capture gate (pid_filter, sampling) comes before every
            // sink: nothing it drops is dumped, logged, parsed or exported.
            if gate.admit(&mut scratch, cookie, known, &ctx.stats) == Verdict::Process {
                process_event(
                    worker_id,
                    &ctx,
                    &manager,
                    &mut owners,
                    &mut gate,
                    &scratch,
                    cookie,
                );
            }
            // An accept / connect may name the owner of packets the gate
            // was holding: they follow, in order.
            if gate.has_held() {
                for mut held in gate.release(cookie, known) {
                    if gate.cut_head(&mut held, cookie, &ctx.stats) == Verdict::Process {
                        process_event(
                            worker_id,
                            &ctx,
                            &manager,
                            &mut owners,
                            &mut gate,
                            &held,
                            cookie,
                        );
                    }
                }
            }
        }
        if gate.has_held() {
            gate.expire_held(crate::util::monotonic_now_ns(), &ctx.stats);
        }

        // Periodic idle connection sweep
        if last_sweep.elapsed() >= sweep_interval {
            let evicted = manager.evict_idle(ctx.idle_timeout);
            if evicted > 0 {
                ctx.stats
                    .active_connections
                    .fetch_sub(evicted as u64, Ordering::Relaxed);
                ctx.stats
                    .evictions_idle
                    .fetch_add(evicted as u64, Ordering::Relaxed);
                debug!(worker_id, evicted, "Evicted idle connections");
            }
            gate.sweep(
                crate::util::monotonic_now_ns(),
                ctx.idle_timeout.as_nanos() as u64,
                &ctx.stats,
            );
            last_sweep = Instant::now();
        }
    }

    debug!(worker_id, "Worker shutting down");
}

/// Everything after the capture gate: raw dump, logging, parsing, PII,
/// graph and export of one admitted event.
fn process_event(
    worker_id: usize,
    ctx: &WorkerTaskContext,
    manager: &ConnectionFsmManager,
    owners: &mut OwnerTable,
    gate: &mut crate::capture_gate::CaptureGate,
    event: &DataEvent,
    cookie: u64,
) {
    crate::test_hooks::pause(crate::test_hooks::WORKER_BEFORE_SINK, &ctx.io_gate);
    // Read per event (an atomic load): a reload may have tightened it.
    let privacy = ctx.privacy.get();
    let log_events = ctx.log_events && privacy != PrivacyMode::MetricsOnly;
    if let Some(raw) = ctx.raw_capture.as_ref()
        && privacy == PrivacyMode::Full
    {
        raw.record(event);
    }

    ctx.stats.events_processed.fetch_add(1, Ordering::Relaxed);

    if log_events {
        let src = format_ipv4(event.src_addr);
        let dst = format_ipv4(event.dst_addr);
        info!(
            worker = worker_id,
            event_type = ?event.event_type,
            src = %format!("{}:{}", src, event.src_port),
            dst = %format!("{}:{}", dst, event.dst_port),
            payload_len = event.payload_len,
            pid = event.pid,
            tgid = event.tgid,
            tls_library = ?event.tls_library,
            cookie,
            "Event"
        );
    }

    // ── Protocol detection + parsing (Phase 3) ───────────────────
    let Some(results) = feed_event(manager, event, cookie, &ctx.stats, worker_id, log_events)
    else {
        // A retransmitted or out-of-window TCP segment: its bytes
        // and its FIN / RST are ignored.
        ctx.stats
            .tcp_segments_ignored
            .fetch_add(1, Ordering::Relaxed);
        return;
    };
    if !results.is_empty() {
        let src = sender_endpoint(event);
        let sender_is_server = manager.server_of(cookie).map(|s| s == src);
        for result in results {
            match result {
                FsmResult::Messages(msgs) => {
                    guarded_handle_messages(
                        msgs,
                        &MessageContext {
                            worker_id,
                            log_events,
                            stats: ctx.stats.as_ref(),
                            pii_engine: &ctx.pii_engine,
                            json_export: &ctx.json_export,
                            otlp_export: &ctx.otlp_export,
                            audit_log: &ctx.audit_log,
                            graph_builder: &ctx.graph_builder,
                            io_gate: &ctx.io_gate,
                            event,
                            sender_is_server,
                            max_body_bytes: ctx.max_body_bytes,
                            privacy,
                            owners: owners.get(cookie),
                        },
                    );
                }
                FsmResult::MessageComplete(msg) => {
                    guarded_handle_messages(
                        [msg],
                        &MessageContext {
                            worker_id,
                            log_events,
                            stats: ctx.stats.as_ref(),
                            pii_engine: &ctx.pii_engine,
                            json_export: &ctx.json_export,
                            otlp_export: &ctx.otlp_export,
                            audit_log: &ctx.audit_log,
                            graph_builder: &ctx.graph_builder,
                            io_gate: &ctx.io_gate,
                            event,
                            sender_is_server,
                            max_body_bytes: ctx.max_body_bytes,
                            privacy,
                            owners: owners.get(cookie),
                        },
                    );
                }
                FsmResult::Error(e) => {
                    debug!(worker = worker_id, cookie, error = %e, "Parser error, closing connection");
                    ctx.stats.drops_parser_error.fetch_add(1, Ordering::Relaxed);
                    if manager.close_connection(cookie) {
                        ctx.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                FsmResult::WaitingForMore => {}
                FsmResult::ConnectionClosed => {
                    if manager.close_connection(cookie) {
                        ctx.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    // Handle connection close: socket close (TC and replay), TCP RST, or
    // FIN from both sides (after this packet's payload was parsed).
    let closed = match event.event_type {
        EventType::SockClose => true,
        EventType::TcPacket if event.tcp_flags & TCP_FLAG_RST != 0 => true,
        EventType::TcPacket if event.tcp_flags & TCP_FLAG_FIN != 0 => {
            manager.note_fin(cookie, sender_endpoint(event), event.direction)
        }
        _ => false,
    };
    if closed {
        end_connection(ctx, manager, owners, gate, cookie);
    }
}

/// Free everything a worker holds for connection `cookie`.
fn end_connection(
    ctx: &WorkerTaskContext,
    manager: &ConnectionFsmManager,
    owners: &mut OwnerTable,
    gate: &mut crate::capture_gate::CaptureGate,
    cookie: u64,
) {
    owners.remove(cookie);
    gate.forget(cookie);
    if manager.close_connection(cookie) {
        ctx.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Run one parser / PII step so that a panic in it (a bug reachable from
/// captured bytes) costs that step, not the worker: an unwound tokio task
/// never restarts, and every event routed to it afterwards would be lost as
/// `drops_channel_full`. Counted in `worker_panics`; None when it panicked.
/// The release profile unwinds (no `panic = "abort"`), so this applies there.
fn guarded<T>(stats: &EventStats, worker_id: usize, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(_) => {
            stats.worker_panics.fetch_add(1, Ordering::Relaxed);
            // The panic hook already printed where; the payload may quote data.
            tracing::error!(worker = worker_id, "worker step panicked; event skipped");
            None
        }
    }
}

/// The sequence fields of a TC TCP packet; None for other events (UDP,
/// TLS plaintext, socket events), which have no sequence to check.
fn tcp_segment(event: &DataEvent) -> Option<crate::protocol::fsm::TcpSegment> {
    use panopticon_common::{TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN};
    const IP_PROTO_TCP: u8 = 6;
    (event.event_type == EventType::TcPacket && event.ip_proto == IP_PROTO_TCP).then(|| {
        crate::protocol::fsm::TcpSegment {
            seq: event.tcp_seq,
            ack: (event.tcp_flags & TCP_FLAG_ACK != 0).then_some(event.tcp_ack),
            len: event.orig_len,
            syn: event.tcp_flags & TCP_FLAG_SYN != 0,
            fin: event.tcp_flags & TCP_FLAG_FIN != 0,
            rst: event.tcp_flags & TCP_FLAG_RST != 0,
        }
    })
}

/// Run one event through its connection's parser: detect the protocol and
/// create the parser on the first payload, keep only the new, in-window
/// bytes of a TCP segment, and account for bytes that were never captured
/// (ring drops before it, the capture cap after it). Returns the parser
/// results in order, or None for a TCP segment that must be ignored whole
/// (a retransmission, or outside the window: its FIN / RST too).
fn feed_event(
    manager: &ConnectionFsmManager,
    event: &DataEvent,
    cookie: u64,
    stats: &EventStats,
    worker_id: usize,
    log_events: bool,
) -> Option<Vec<FsmResult>> {
    use crate::protocol::fsm::{CreateResult, SegmentVerdict};

    let payload = event.payload_bytes();
    if !payload.is_empty()
        && !manager.contains(cookie)
        && let Some(proto) = guarded(stats, worker_id, || {
            detect_protocol(payload, event.src_port, event.dst_port, event.direction)
        })
        .flatten()
    {
        let server = server_endpoint(event, proto, payload);
        match manager.get_or_create_with_server(cookie, proto, server) {
            CreateResult::Created => {
                stats.active_connections.fetch_add(1, Ordering::Relaxed);
            }
            CreateResult::CreatedWithEviction(evicted) => {
                // Created after evicting the oldest connections at capacity
                let evicted = evicted as u64;
                stats
                    .evictions_capacity
                    .fetch_add(evicted, Ordering::Relaxed);
                stats.active_connections.fetch_add(1, Ordering::Relaxed);
                stats
                    .active_connections
                    .fetch_sub(evicted, Ordering::Relaxed);
            }
            CreateResult::AlreadyExists => {}
        }
        if log_events {
            tracing::debug!(worker = worker_id, cookie, protocol = %proto, "Protocol detected");
        }
    }

    let src = sender_endpoint(event);
    let (gap, trim) = match tcp_segment(event)
        .and_then(|seg| manager.admit_segment(cookie, src, event.direction, seg))
    {
        Some(SegmentVerdict::Drop) => return None,
        Some(SegmentVerdict::Accept { gap, trim }) => (gap as usize, trim as usize),
        None => (0, 0),
    };
    // A parser panic closes the connection instead of the worker.
    let panicked = || Some(FsmResult::Error("parser panicked".into()));
    let skip = |n: usize| {
        guarded(stats, worker_id, || {
            manager.skip_from(cookie, src, event.direction, n, event.timestamp_ns)
        })
        .unwrap_or_else(panicked)
    };
    let mut results = Vec::new();
    // Bytes of this direction lost before this segment (ring drops).
    if gap > 0 {
        results.extend(skip(gap));
    }
    let data = &payload[trim.min(payload.len())..];
    if !data.is_empty() {
        results.extend(
            guarded(stats, worker_id, || {
                manager.process_packet_from(cookie, src, event.direction, data, event.timestamp_ns)
            })
            .unwrap_or_else(panicked),
        );
    }
    // Bytes beyond the capture cap (GSO/TSO super-packets, large TLS
    // writes) were never seen: let the parser count them instead of
    // desynchronising on the next message.
    let tail = (event.orig_len as usize).saturating_sub(trim.max(payload.len()));
    if tail > 0 {
        stats.truncated_events.fetch_add(1, Ordering::Relaxed);
        results.extend(skip(tail));
    }
    Some(results)
}

fn guarded_handle_messages(
    msgs: impl IntoIterator<Item = crate::protocol::L7Message>,
    ctx: &MessageContext<'_>,
) {
    guarded(ctx.stats, ctx.worker_id, || handle_messages(msgs, ctx));
}

fn handle_messages(
    msgs: impl IntoIterator<Item = crate::protocol::L7Message>,
    ctx: &MessageContext<'_>,
) {
    for mut msg in msgs {
        // PII scan + in-place redaction happens FIRST, so that logging, the
        // audit log, every exporter and the service graph only ever see the
        // sanitized message (path/query, headers and payload).
        let pii_report = scan_with_body_cap(&mut msg, ctx.max_body_bytes, |msg| {
            ctx.pii_engine
                .as_ref()
                // Redact unless the mode is full, and in full too if the config
                // asks for a redacted export ([pii] redact = true).
                .and_then(|e| {
                    let redact = ctx.privacy != PrivacyMode::Full || e.redacts();
                    e.scan_message_with(msg, redact)
                })
        });
        if let Some(report) = pii_report.as_ref() {
            ctx.stats
                .pii_detections
                .fetch_add(report.entities.len() as u64, Ordering::Relaxed);
        }
        let metrics_only = ctx.privacy == PrivacyMode::MetricsOnly;
        if metrics_only {
            strip_payload_strings(&mut msg);
        }

        if ctx.log_events {
            info!(
                worker = ctx.worker_id,
                protocol = %msg.protocol,
                method = ?msg.method,
                path = ?msg.path,
                status = ?msg.status,
                latency_ns = ?msg.latency_ns,
                pid = ctx.event.pid,
                tgid = ctx.event.tgid,
                tls_library = ?ctx.event.tls_library,
                "L7Message"
            );
        }

        // PII auditing
        if let Some(report) = pii_report.as_ref()
            && let Some(audit_arc) = ctx.audit_log.as_ref()
        {
            use crate::export::audit::{AuditAction, AuditEntry};
            let (service, service_addr) = audit_service(ctx, msg.protocol);
            let entries: Vec<AuditEntry> = report
                .entities
                .iter()
                .map(|e| AuditEntry {
                    timestamp_ns: msg.timestamp_ns,
                    category: e.category,
                    source: e.source,
                    confidence: e.confidence,
                    action: if report.redacted {
                        AuditAction::Redacted
                    } else {
                        AuditAction::Detected
                    },
                    service_identity: service.clone(),
                    service_addr: service_addr.clone(),
                })
                .collect();

            let _ = audit_arc.emit(&entries);
        }

        // OTLP export (channel-based — drop when full, never block workers)
        if let Some(handle) = ctx.otlp_export.as_ref().filter(|_| !metrics_only) {
            if !handle.try_send_span(msg.clone(), ctx.privacy) {
                debug!(
                    worker = ctx.worker_id,
                    "OTLP span dropped due to exporter backpressure"
                );
            }
            if let Some(report) = pii_report.as_ref() {
                for entity in &report.entities {
                    if !handle.try_send_pii_finding(
                        msg.timestamp_ns,
                        entity.category.to_string(),
                        entity.confidence,
                        ctx.privacy,
                    ) {
                        debug!(
                            worker = ctx.worker_id,
                            "OTLP PII finding dropped due to exporter backpressure"
                        );
                        break;
                    }
                }
            }
        }

        // Service graph: record observation. TLS uprobe events carry no
        // addresses yet; recording them would add a fake 0.0.0.0 node.
        let has_addresses = ctx.event.src_addr != 0 || ctx.event.dst_addr != 0;
        if let Some(gb) = ctx.graph_builder.as_ref().filter(|_| has_addresses) {
            let conn_tuple = ConnectionTuple {
                src_addr: ctx.event.src_addr,
                dst_addr: ctx.event.dst_addr,
                src_port: ctx.event.src_port,
                dst_port: ctx.event.dst_port,
                pid: ctx.event.pid,
            };
            gb.record_with_server(&conn_tuple, ctx.sender_is_server, &msg, pii_report.as_ref());
            if msg.protocol == crate::protocol::Protocol::Dns {
                crate::test_hooks::pause(crate::test_hooks::BEFORE_DNS_INSERT, ctx.io_gate);
            }
            gb.observe_dns(&msg);
            if msg.protocol == crate::protocol::Protocol::Dns {
                crate::test_hooks::pause(crate::test_hooks::AFTER_DNS_INSERT, ctx.io_gate);
            }
        }

        // JSON export (channel-based — no mutex, no per-event flush). Last, so
        // the message and report move into it instead of being cloned.
        if let Some(handle) = ctx.json_export.as_ref().filter(|_| !metrics_only)
            && !handle.try_send(
                msg,
                pii_report,
                crate::export::json::TransportContext {
                    client_pid: ctx.owners.and_then(|o| o.client),
                    server_pid: ctx.owners.and_then(|o| o.server),
                    ..crate::export::json::TransportContext::from_data_event(ctx.event)
                },
                ctx.privacy,
            )
        {
            ctx.stats.drops_export_full.fetch_add(1, Ordering::Relaxed);
            debug!(
                worker = ctx.worker_id,
                "JSON export event dropped due to exporter backpressure"
            );
        }
    }
}

/// The service the PII travelled to or from, for the audit log: the server
/// end's name, as the service graph names it, and its `ip:port`. In
/// `metrics_only` the name never comes from DNS answers (payload-derived):
/// a Kubernetes name or the address.
fn audit_service(
    ctx: &MessageContext<'_>,
    protocol: crate::protocol::Protocol,
) -> (String, String) {
    let e = ctx.event;
    if e.src_addr == 0 && e.dst_addr == 0 {
        return ("unknown".to_string(), "unknown".to_string());
    }
    let conn = ConnectionTuple {
        src_addr: e.src_addr,
        dst_addr: e.dst_addr,
        src_port: e.src_port,
        dst_port: e.dst_port,
        pid: e.pid,
    };
    let (_, (addr, port)) = crate::graph::orient(&conn, ctx.sender_is_server, protocol);
    let service_addr = format!("{}:{}", format_ipv4(addr), port);
    let dns = ctx.privacy != PrivacyMode::MetricsOnly;
    let name = match ctx.graph_builder.as_ref() {
        Some(gb) => {
            gb.server_identity(&conn, ctx.sender_is_server, protocol, dns)
                .name
        }
        None => service_addr.clone(),
    };
    (name, service_addr)
}

/// `metrics_only`: drop every string taken from the payload (path or query
/// template, method, headers, bodies) once PII has been counted, so the
/// graph, the audit log and logs cannot carry any of it. DNS answers stay:
/// they only feed the DNS cache that names services in the graph.
fn strip_payload_strings(msg: &mut crate::protocol::L7Message) {
    msg.method = None;
    msg.path = None;
    msg.content_type = None;
    msg.payload_text = None;
    msg.request_text = None;
    msg.headers.retain(|(k, _)| k == "dns_a_record");
}

/// Bytes past `max_body_bytes` that are still scanned, so a value straddling
/// the cut is detected whole and redacted before the cut drops its tail.
const SCAN_LOOKAHEAD: usize = 256;

/// Bound the bodies to `max` bytes around a PII scan: scan up to
/// `max + SCAN_LOOKAHEAD`, then cut to `max` and drop a token the cut split,
/// so no prefix of an undetected value (`123-45-6` of an SSN) is exported.
fn scan_with_body_cap(
    msg: &mut crate::protocol::L7Message,
    max: usize,
    scan: impl FnOnce(&mut crate::protocol::L7Message) -> Option<crate::pii::PiiReport>,
) -> Option<crate::pii::PiiReport> {
    cap_body_text(msg, max.saturating_add(SCAN_LOOKAHEAD));
    let mut report = scan(msg);
    let redacted = report.as_mut().and_then(|r| r.redacted_text.as_mut());
    for text in [
        msg.payload_text.as_mut(),
        msg.request_text.as_mut(),
        redacted,
    ]
    .into_iter()
    .flatten()
    {
        cut_partial_token(text, max);
    }
    report
}

/// Cut `text` to at most `max` bytes; when the cut falls inside a token
/// (letters, digits and `-._@+%`), drop that token's head too.
fn cut_partial_token(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let is_token = |c: char| c.is_alphanumeric() || "-._@+%".contains(c);
    let mut keep = crate::protocol::truncate_utf8(text, max).len();
    if text[keep..].chars().next().is_some_and(is_token) {
        keep = text[..keep]
            .char_indices()
            .rev()
            .find(|&(_, c)| !is_token(c))
            .map_or(0, |(i, c)| i + c.len_utf8());
    }
    text.truncate(keep);
}

/// Bound the body text a message carries before PII scanning and export.
fn cap_body_text(msg: &mut crate::protocol::L7Message, max: usize) {
    for text in [&mut msg.payload_text, &mut msg.request_text]
        .into_iter()
        .flatten()
    {
        if text.len() > max {
            let keep = crate::protocol::truncate_utf8(text, max).len();
            text.truncate(keep);
        }
    }
}

/// Stand-in endpoints for TLS uprobe events, which carry no addresses: the
/// observed process and whoever it is talking to.
const TLS_LOCAL: crate::protocol::fsm::Endpoint = (0, 1);
const TLS_PEER: crate::protocol::fsm::Endpoint = (0, 2);

/// Who sent this event's payload. For TLS events the direction is relative
/// to the observed process: it wrote (`Egress`) or read (`Ingress`).
pub(crate) fn sender_endpoint(event: &DataEvent) -> crate::protocol::fsm::Endpoint {
    match event.event_type {
        EventType::TlsData if event.direction == Direction::Egress => TLS_LOCAL,
        EventType::TlsData => TLS_PEER,
        _ => (event.src_addr, event.src_port),
    }
}

/// Which endpoint of a new connection is the server, so parsers always see
/// client→server as `Egress` whatever hook captured the bytes.
///
/// Decided from the detection payload's content where possible (an HTTP
/// request line came from the client, a MySQL greeting from the server...),
/// then from well-known service ports, then by assuming the lower port is the
/// server's. TLS events have no ports: if the content doesn't say, the
/// process-relative direction is kept (writes treated as requests), which is
/// right for clients.
fn server_endpoint(
    event: &DataEvent,
    proto: crate::protocol::Protocol,
    payload: &[u8],
) -> Option<crate::protocol::fsm::Endpoint> {
    use crate::protocol::detect::{is_service_port, sent_by_client};

    let src = sender_endpoint(event);
    match event.event_type {
        EventType::TcPacket => {}
        EventType::TlsData => {
            let other = if src == TLS_LOCAL {
                TLS_PEER
            } else {
                TLS_LOCAL
            };
            return match sent_by_client(proto, payload)? {
                true => Some(other),
                false => Some(src),
            };
        }
        _ => return None,
    }
    let dst = (event.dst_addr, event.dst_port);
    Some(match sent_by_client(proto, payload) {
        Some(true) => dst,
        Some(false) => src,
        None if is_service_port(event.dst_port) => dst,
        None if is_service_port(event.src_port) => src,
        None if event.dst_port <= event.src_port => dst,
        None => src,
    })
}

/// Key identifying the connection an event belongs to.
///
/// TC and socket events carry the flow cookie, which has bit 63 clear
/// (`panopticon_common::tc_flow_cookie`). TLS events carry the library's
/// connection object pointer (`SSL*`, `*tls.Conn`), chosen by the traced
/// process and unique only within it: it is hashed with the PID under a
/// per-process random key, so no process can pick a pointer that lands on
/// another connection's key (F18), and bit 63 is set so a TLS key never
/// equals a TC cookie. Events without one fall back to a per-thread key.
fn connection_key(event: &DataEvent) -> u64 {
    use std::hash::BuildHasher;
    static TLS_KEY: std::sync::OnceLock<std::hash::RandomState> = std::sync::OnceLock::new();
    if event.event_type != EventType::TlsData {
        return event.socket_cookie;
    }
    if event.socket_cookie == 0 {
        return tls_synthetic_cookie(event.pid, event.tgid);
    }
    TLS_KEY_BIT
        | TLS_KEY
            .get_or_init(std::hash::RandomState::new)
            .hash_one((event.pid, event.socket_cookie))
}

/// Synthetic per-thread key for TLS events without a connection pointer:
/// PID and TGID, in the TLS key space (bit 63 set, see [`connection_key`]).
fn tls_synthetic_cookie(pid: u32, tgid: u32) -> u64 {
    TLS_KEY_BIT | ((pid as u64) << 32) | (tgid as u64)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn drain_interval_backs_off_when_idle_and_resets_on_traffic() {
        let ms = Duration::from_millis;
        let mut d = RINGBUF_DRAIN_INTERVAL;
        let mut seen = vec![];
        for _ in 0..5 {
            d = next_drain_interval(d, 0);
            seen.push(d);
        }
        assert_eq!(seen, vec![ms(4), ms(8), ms(16), ms(16), ms(16)]);
        assert_eq!(next_drain_interval(d, 3), RINGBUF_DRAIN_INTERVAL);
    }

    use super::*;
    use crate::protocol::Protocol;
    use std::sync::atomic::Ordering;

    #[test]
    fn worker_index_gives_each_shard_its_own_workers_and_uses_them_all() {
        for (workers, shards) in [(64, 16), (20, 16), (12, 16), (16, 2), (1, 1), (7, 1)] {
            let mut used = vec![std::collections::BTreeSet::new(); workers];
            for shard in 0..shards {
                for key in 0..1000u64 {
                    let w = worker_index(key, shard, shards, workers);
                    assert!(w < workers);
                    assert_eq!(w, worker_index(key, shard, shards, workers));
                    used[w].insert(shard);
                }
            }
            assert!(
                used.iter().all(|s| !s.is_empty()),
                "{workers}/{shards}: idle worker"
            );
            if workers % shards == 0 {
                // Disjoint: every worker is fed by exactly one drain thread.
                assert!(used.iter().all(|s| s.len() == 1), "{workers}/{shards}");
            }
        }
    }

    #[test]
    fn event_batch_packs_header_and_payload_and_reads_back_in_order() {
        // SAFETY: all-zero is valid for DataEvent.
        let mut events: Vec<DataEvent> = (0..4).map(|_| unsafe { std::mem::zeroed() }).collect();
        for (i, (e, len)) in events.iter_mut().zip([0usize, 3, 4096, 9999]).enumerate() {
            e.socket_cookie = i as u64;
            e.event_type = EventType::TcPacket;
            e.direction = Direction::Egress;
            e.payload_len = len as u32;
            e.payload[..len.min(4096)].fill(b'a' + i as u8);
        }
        let mut batch = EventBatch::default();
        events.iter().for_each(|e| batch.push(e));
        assert_eq!(batch.len(), 4);
        // Header + payload only: 3 + 4096 + 4096 (clamped) payload bytes.
        assert_eq!(
            batch.bytes.len(),
            4 * DATA_EVENT_HEADER_LEN + 3 + 4096 + 4096
        );

        // SAFETY: as above.
        let mut scratch: DataEvent = unsafe { std::mem::zeroed() };
        let mut seen = 0;
        for (i, record) in batch.records().enumerate() {
            assert!(panopticon_common::read_data_event_into(
                record,
                &mut scratch
            ));
            let want = &events[i];
            assert_eq!(scratch.socket_cookie, want.socket_cookie);
            assert_eq!(scratch.direction, Direction::Egress);
            assert_eq!(scratch.payload_bytes(), want.payload_bytes());
            seen += 1;
        }
        assert_eq!(seen, 4);
        assert_eq!(
            scratch.payload_len, 4096,
            "oversized payload_len is clamped in the record"
        );
    }

    #[test]
    fn test_event_stats_atomic() {
        let stats = EventStats::new();
        assert_eq!(stats.events_received.load(Ordering::Relaxed), 0);

        // Simulate concurrent increments
        for _ in 0..1000 {
            stats.events_received.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(stats.events_received.load(Ordering::Relaxed), 1000);
    }

    #[test]
    fn test_drop_counters_initial_zero() {
        let stats = EventStats::new();
        assert_eq!(stats.drops_rate_limit.load(Ordering::Relaxed), 0);
        assert_eq!(stats.drops_channel_full.load(Ordering::Relaxed), 0);
        assert_eq!(stats.drops_parser_error.load(Ordering::Relaxed), 0);
        assert_eq!(stats.backpressure_events.load(Ordering::Relaxed), 0);
        assert_eq!(stats.evictions_capacity.load(Ordering::Relaxed), 0);
        assert_eq!(stats.evictions_idle.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_backpressure_counter() {
        let stats = EventStats::new();
        stats.backpressure_events.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.backpressure_events.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_eviction_counters() {
        let stats = EventStats::new();
        stats.evictions_capacity.fetch_add(3, Ordering::Relaxed);
        stats.evictions_idle.fetch_add(7, Ordering::Relaxed);
        assert_eq!(stats.evictions_capacity.load(Ordering::Relaxed), 3);
        assert_eq!(stats.evictions_idle.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn test_drop_counters_increment() {
        let stats = EventStats::new();
        stats.drops_rate_limit.fetch_add(5, Ordering::Relaxed);
        stats.drops_channel_full.fetch_add(3, Ordering::Relaxed);
        stats.drops_parser_error.fetch_add(1, Ordering::Relaxed);

        assert_eq!(stats.drops_rate_limit.load(Ordering::Relaxed), 5);
        assert_eq!(stats.drops_channel_full.load(Ordering::Relaxed), 3);
        assert_eq!(stats.drops_parser_error.load(Ordering::Relaxed), 1);

        // Total drops should be consistent
        stats.events_dropped.fetch_add(9, Ordering::Relaxed);
        let total = stats.events_dropped.load(Ordering::Relaxed);
        let sum = stats.drops_rate_limit.load(Ordering::Relaxed)
            + stats.drops_channel_full.load(Ordering::Relaxed)
            + stats.drops_parser_error.load(Ordering::Relaxed);
        assert_eq!(total, sum);
    }

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let rl = RateLimiter::new(100);
        for _ in 0..100 {
            assert!(rl.try_acquire(), "should allow events under limit");
        }
    }

    #[test]
    fn test_rate_limiter_drops_over_limit() {
        let rl = RateLimiter::new(10);
        for _ in 0..10 {
            assert!(rl.try_acquire());
        }
        // Now exhausted
        assert!(!rl.try_acquire(), "should deny events over limit");
        assert!(!rl.try_acquire(), "should continue denying");
    }

    #[test]
    fn test_rate_limiter_refill() {
        let rl = RateLimiter::new(100); // 100/10 = 10 tokens per refill
        // Drain all tokens
        for _ in 0..100 {
            assert!(rl.try_acquire());
        }
        assert!(!rl.try_acquire());

        // Refill adds max/10 tokens
        rl.refill();
        for _ in 0..10 {
            assert!(rl.try_acquire(), "should allow after refill");
        }
        assert!(!rl.try_acquire(), "should be empty again after 10 more");
    }

    #[test]
    fn test_rate_limiter_unlimited() {
        let rl = RateLimiter::new(0);
        for _ in 0..1_000_000 {
            assert!(rl.try_acquire(), "unlimited should always allow");
        }
    }

    #[test]
    fn test_worker_routing_deterministic() {
        let num_workers = 8;
        let cookie: u64 = 0xDEADBEEF_CAFEBABE;

        let idx1 = (cookie as usize) % num_workers;
        let idx2 = (cookie as usize) % num_workers;
        let idx3 = (cookie as usize) % num_workers;

        assert_eq!(idx1, idx2);
        assert_eq!(idx2, idx3);
    }

    #[test]
    fn test_worker_routing_distribution() {
        let num_workers = 4;
        let mut counts = [0u32; 4];
        // 100 different cookies should distribute across workers
        for cookie in 0u64..100 {
            let idx = (cookie as usize) % num_workers;
            counts[idx] += 1;
        }
        // Each worker should get at least some events
        for (i, &count) in counts.iter().enumerate() {
            assert!(count > 0, "worker {i} got no events");
        }
    }

    // ── TLS Synthetic Cookie Tests ─────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_synthetic_cookie_deterministic() {
        let c1 = tls_synthetic_cookie(1234, 1234);
        let c2 = tls_synthetic_cookie(1234, 1234);
        assert_eq!(c1, c2, "same PID should produce same cookie");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_synthetic_cookie_unique_per_pid() {
        let c1 = tls_synthetic_cookie(100, 100);
        let c2 = tls_synthetic_cookie(200, 200);
        let c3 = tls_synthetic_cookie(300, 300);
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
        assert_ne!(c1, c3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_synthetic_cookie_high_bit_set() {
        let cookie = tls_synthetic_cookie(1, 1);
        // Bit 63 set: outside the TC flow cookie space (bit 63 clear).
        assert!(cookie & TLS_KEY_BIT != 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_synthetic_cookie_no_collision_with_real() {
        // TC flow cookies have bit 63 clear, so small ones included
        for real_cookie in 1u64..10_000 {
            for pid in [1u32, 100, 1000, 65535] {
                assert_ne!(
                    tls_synthetic_cookie(pid, pid),
                    real_cookie,
                    "synthetic cookie for pid={pid} collided with real cookie={real_cookie}"
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_routing_different_pids_different_workers() {
        // TLS events with cookie=0 should be routed by PID, not all to worker 0
        let num_workers = 4;
        let mut worker_for_pid = std::collections::HashMap::new();

        for pid in 0u32..100 {
            let cookie = tls_synthetic_cookie(pid, pid);
            let idx = (cookie as usize) % num_workers;
            worker_for_pid.insert(pid, idx);
        }

        // Not all PIDs should map to the same worker
        let unique_workers: std::collections::HashSet<_> = worker_for_pid.values().collect();
        assert!(
            unique_workers.len() > 1,
            "all PIDs routed to same worker — broken distribution"
        );
    }

    #[test]
    fn tls_keys_are_keyed_and_disjoint_from_tc_cookies() {
        // SAFETY: all-zero is valid for DataEvent (all enums have a 0 variant)
        let mut tls: DataEvent = unsafe { std::mem::zeroed() };
        tls.event_type = EventType::TlsData;
        tls.pid = 4242;
        tls.socket_cookie = 0x5555_0000_1230; // the SSL* the process chose
        let key = connection_key(&tls);
        assert_eq!(key & TLS_KEY_BIT, TLS_KEY_BIT);
        // F18: the key is no longer the public, invertible fxhash, so a
        // process cannot solve for an SSL* that lands on a chosen key.
        assert_ne!(
            key,
            TLS_KEY_BIT | fxhash::hash64(&(tls.pid, tls.socket_cookie))
        );
        assert_eq!(key, connection_key(&tls), "stable within the process");
        // A TC flow cookie (bit 63 clear by construction) is used as is and
        // can never equal a TLS key.
        let mut tc = tls;
        tc.event_type = EventType::TcPacket;
        tc.socket_cookie =
            panopticon_common::tc_flow_cookie(9, 0x0A00_0001, 0x0A00_0002, 40000, 80, 6);
        assert_eq!(connection_key(&tc), tc.socket_cookie);
        assert_eq!(connection_key(&tc) & TLS_KEY_BIT, 0);
    }

    const CLI: (u32, u16) = (0x0A63_0002, 51000);
    const SRV: (u32, u16) = (0x0A63_0001, 18090);

    /// A TC TCP packet from `from` to the other end, as tc_capture.rs
    /// builds it.
    fn tcp_pkt(from: (u32, u16), seq: u32, ack: u32, flags: u8, payload: &[u8]) -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent (all enums have a 0 variant)
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        let to = if from == CLI { SRV } else { CLI };
        e.event_type = EventType::TcPacket;
        e.direction = if from == CLI {
            Direction::Ingress
        } else {
            Direction::Egress
        };
        (e.src_addr, e.src_port, e.dst_addr, e.dst_port) = (from.0, from.1, to.0, to.1);
        e.ip_proto = 6;
        e.socket_cookie = panopticon_common::tc_flow_cookie(0, from.0, to.0, from.1, to.1, 6);
        e.tcp_seq = seq;
        e.tcp_ack = ack;
        e.tcp_flags = flags | panopticon_common::TCP_FLAG_ACK;
        e.payload[..payload.len()].copy_from_slice(payload);
        (e.payload_len, e.orig_len) = (payload.len() as u32, payload.len() as u32);
        e
    }

    /// Feed events the way worker_task does; the paths of the messages
    /// they complete, or None for each event ignored whole.
    fn run_tcp(events: &[DataEvent]) -> (Vec<Option<String>>, Vec<bool>) {
        let (m, stats) = (ConnectionFsmManager::new(16), EventStats::new());
        let (mut paths, mut ignored) = (vec![], vec![]);
        for e in events {
            let fed = feed_event(&m, e, connection_key(e), &stats, 0, false);
            ignored.push(fed.is_none());
            for r in fed.into_iter().flatten() {
                match r {
                    FsmResult::Messages(ms) => paths.extend(ms.into_iter().map(|m| m.path)),
                    FsmResult::MessageComplete(m) => paths.push(m.path),
                    _ => {}
                }
            }
        }
        (paths, ignored)
    }

    #[test]
    fn retransmitted_segments_are_parsed_once() {
        let req = b"GET /orders/7 HTTP/1.1\r\nHost: shop\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (a, b) = req.split_at(20);
        let (paths, ignored) = run_tcp(&[
            tcp_pkt(CLI, 100, 900, 0, a),
            tcp_pkt(CLI, 100, 900, 0, a),          // retransmission
            tcp_pkt(CLI, 110, 900, 0, &req[10..]), // overlaps the first 10 bytes
            tcp_pkt(CLI, 100 + 20, 900, 0, b),     // and again, whole
            tcp_pkt(SRV, 900, 100 + req.len() as u32, 0, resp),
            tcp_pkt(SRV, 900, 100 + req.len() as u32, 0, resp), // duplicate
        ]);
        assert_eq!(paths, vec![Some("/orders/7".to_string())]);
        assert_eq!(ignored, vec![false, true, false, true, false, true]);
    }

    #[test]
    fn forged_out_of_window_request_and_rst_are_ignored() {
        let req = b"GET /real HTTP/1.1\r\nHost: shop\r\n\r\n";
        let fake = b"GET /forged HTTP/1.1\r\nHost: shop\r\n\r\n";
        let resp = b"HTTP/1.1 204 No Content\r\n\r\n";
        let next = 100 + req.len() as u32;
        let rst = panopticon_common::TCP_FLAG_RST;
        let (paths, ignored) = run_tcp(&[
            tcp_pkt(CLI, 100, 900, 0, req),
            tcp_pkt(CLI, next + 50_000_000, 900, 0, fake), // guessed sequence
            tcp_pkt(SRV, 77_777, next, rst, b""),          // spoofed RST
            tcp_pkt(SRV, 900, next, 0, resp),
        ]);
        assert_eq!(paths, vec![Some("/real".to_string())]);
        assert_eq!(ignored, vec![false, true, true, false]);
        // The real RST, at the server's next sequence number, counts.
        let (_, ignored) = run_tcp(&[
            tcp_pkt(CLI, 100, 900, 0, req),
            tcp_pkt(SRV, 900, next, rst, b""),
        ]);
        assert_eq!(ignored, vec![false, false]);
    }

    fn sock_event(kind: EventType, cookie: u64, pid: u32) -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent (all enums have a 0 variant)
        let mut event: DataEvent = unsafe { std::mem::zeroed() };
        event.event_type = kind;
        event.socket_cookie = cookie;
        event.pid = pid;
        event
    }

    #[test]
    fn owner_table_tracks_both_ends_and_stays_bounded() {
        let mut t = OwnerTable::new(2);
        t.observe(&sock_event(EventType::SockConnect, 1, 100));
        t.observe(&sock_event(EventType::SockAccept, 1, 200));
        t.observe(&sock_event(EventType::SockAccept, 2, 0)); // no pid: ignored
        t.observe(&sock_event(EventType::TcPacket, 2, 300)); // not an owner event
        assert_eq!(
            t.get(1),
            Some(ConnOwners {
                client: Some(100),
                server: Some(200)
            })
        );
        assert_eq!(t.get(2), None);
        t.observe(&sock_event(EventType::SockConnect, 2, 101));
        // Full: a third connection resets the table instead of growing it.
        t.observe(&sock_event(EventType::SockConnect, 3, 102));
        assert_eq!(t.owners.len(), 1);
        assert_eq!(t.get(3).and_then(|o| o.client), Some(102));
        t.remove(3);
        assert_eq!(t.get(3), None);
    }

    #[test]
    fn cap_body_text_bounds_both_bodies_on_char_boundaries() {
        let mut msg =
            crate::protocol::L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        msg.payload_text = Some("é".repeat(3000)); // 6000 bytes, 2-byte chars
        msg.request_text = Some("short".to_string());
        cap_body_text(&mut msg, 4095);
        assert_eq!(msg.payload_text.as_deref().map(str::len), Some(4094));
        assert_eq!(msg.request_text.as_deref(), Some("short"));
    }

    #[test]
    fn body_cap_never_exports_a_split_value() {
        let engine = crate::pii::PiiEngine::new(&crate::config::PiiConfig::default(), &[]);
        let mut msg =
            crate::protocol::L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        // The SSN straddles the 4096-byte cut.
        let head = "x ".repeat(2042); // 4084 bytes: the cut leaves "123-45-6"
        msg.payload_text = Some(format!("{head}ssn 123-45-6789 and more text"));
        let report = scan_with_body_cap(&mut msg, 4096, |m| engine.scan_message_with(m, true));
        let body = msg.payload_text.as_deref().unwrap();
        assert!(body.len() <= 4096);
        assert!(!body.contains("123-45"), "{}", &body[4080..]);
        assert!(report.unwrap().redacted_text.as_ref().unwrap().len() <= 4096);

        // Redaction off (full): still never ends in a split token.
        let mut msg =
            crate::protocol::L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        msg.payload_text = Some(format!("{head}ssn 123-45-6789"));
        scan_with_body_cap(&mut msg, 4096, |_| None);
        assert!(msg.payload_text.as_deref().unwrap().ends_with("ssn "));
    }

    #[test]
    fn guarded_step_survives_a_panic_and_counts_it() {
        let stats = EventStats::new();
        assert_eq!(guarded(&stats, 0, || 7), Some(7));
        let r = guarded(&stats, 0, || -> u8 {
            panic!("byte index 4 is not a char boundary")
        });
        assert_eq!(r, None);
        assert_eq!(stats.worker_panics.load(Ordering::Relaxed), 1);
        // Still usable afterwards.
        assert_eq!(guarded(&stats, 0, || 8), Some(8));
    }

    #[test]
    fn strip_payload_strings_keeps_only_dns_answers() {
        let mut msg =
            crate::protocol::L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        msg.method = Some("POST".into());
        msg.path = Some("/u?email=a@b.c".into());
        msg.content_type = Some("text/plain".into());
        msg.payload_text = Some("ssn 123-45-6789".into());
        msg.request_text = Some("body".into());
        msg.headers = vec![
            ("x-user".into(), "a@b.c".into()),
            ("dns_a_record".into(), "svc.local|167772161|30".into()),
        ];
        msg.status = Some(201);
        strip_payload_strings(&mut msg);
        assert!(msg.method.is_none() && msg.path.is_none() && msg.content_type.is_none());
        assert!(msg.payload_text.is_none() && msg.request_text.is_none());
        assert_eq!(msg.headers.len(), 1);
        assert_eq!(msg.headers[0].0, "dns_a_record");
        assert_eq!(msg.status, Some(201));
    }

    #[cfg(target_os = "linux")]
    fn tls_event(pid: u32, ssl: u64, direction: Direction, payload: &[u8]) -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent (all enums have a 0 variant)
        let mut event: DataEvent = unsafe { std::mem::zeroed() };
        event.event_type = EventType::TlsData;
        event.direction = direction;
        event.pid = pid;
        event.tgid = pid;
        event.socket_cookie = ssl;
        event.tls_library = panopticon_common::TlsLibrary::OpenSsl;
        event.payload[..payload.len()].copy_from_slice(payload);
        event.payload_len = payload.len() as u32;
        event.orig_len = payload.len() as u32;
        event
    }

    /// The worker's detect → create → parse steps for one event.
    #[cfg(target_os = "linux")]
    fn feed(manager: &ConnectionFsmManager, event: &DataEvent) -> Vec<crate::protocol::L7Message> {
        let key = connection_key(event);
        let payload = event.payload_bytes();
        if !manager.contains(key)
            && let Some(proto) = crate::protocol::detect::detect_protocol(
                payload,
                event.src_port,
                event.dst_port,
                event.direction,
            )
        {
            manager.get_or_create_with_server(key, proto, server_endpoint(event, proto, payload));
        }
        match manager.process_packet_from(
            key,
            sender_endpoint(event),
            event.direction,
            payload,
            event.timestamp_ns,
        ) {
            Some(FsmResult::Messages(m)) => m,
            Some(FsmResult::MessageComplete(m)) => vec![m],
            _ => vec![],
        }
    }

    const REQ: &[u8] = b"GET /orders/7 HTTP/1.1\r\nHost: shop\r\n\r\n";
    const RESP: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    #[cfg(target_os = "linux")]
    #[test]
    fn tls_exchange_parses_from_client_and_server_process() {
        // Client process: writes the request, reads the response.
        let m = ConnectionFsmManager::new(16);
        assert!(feed(&m, &tls_event(10, 0x5000, Direction::Egress, REQ)).is_empty());
        let msgs = feed(&m, &tls_event(10, 0x5000, Direction::Ingress, RESP));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].path.as_deref(), Some("/orders/7"));
        assert_eq!(msgs[0].status, Some(404));

        // Server process: reads the request, writes the response. Process-
        // relative directions are the opposite of the client's.
        let m = ConnectionFsmManager::new(16);
        assert!(feed(&m, &tls_event(20, 0x6000, Direction::Ingress, REQ)).is_empty());
        let msgs = feed(&m, &tls_event(20, 0x6000, Direction::Egress, RESP));
        assert_eq!(msgs.len(), 1, "server-side TLS exchange must parse");
        assert_eq!(msgs[0].path.as_deref(), Some("/orders/7"));
        assert_eq!(msgs[0].status, Some(404));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tls_server_process_direction_is_normalised() {
        // A Redis server over TLS reads the command (Ingress) and writes the
        // reply (Egress); the parser must still see a command and a reply.
        let m = ConnectionFsmManager::new(16);
        let cmd = b"*2\r\n$3\r\nGET\r\n$4\r\nuser\r\n";
        assert!(feed(&m, &tls_event(40, 0xC000, Direction::Ingress, cmd)).is_empty());
        let msgs = feed(
            &m,
            &tls_event(40, 0xC000, Direction::Egress, b"$3\r\nbob\r\n"),
        );
        assert_eq!(msgs.len(), 1, "server-side TLS Redis exchange must parse");
        assert_eq!(msgs[0].method.as_deref(), Some("GET"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tls_connections_on_one_thread_stay_separate() {
        // An event-loop server interleaves connections on one thread; each
        // SSL* must get its own parser.
        let m = ConnectionFsmManager::new(16);
        let req_b = b"GET /b HTTP/1.1\r\nHost: shop\r\n\r\n";
        assert!(feed(&m, &tls_event(30, 0xA000, Direction::Ingress, REQ)).is_empty());
        assert!(feed(&m, &tls_event(30, 0xB000, Direction::Ingress, req_b)).is_empty());
        let b = feed(&m, &tls_event(30, 0xB000, Direction::Egress, RESP));
        let a = feed(&m, &tls_event(30, 0xA000, Direction::Egress, RESP));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].path.as_deref(), Some("/b"));
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].path.as_deref(), Some("/orders/7"));
    }

    #[test]
    fn admission_floor_drops_stale_generations_only() {
        // SAFETY: all-zero is a valid DataEvent.
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        e.event_type = EventType::TcPacket;
        // TC: generation 0 under the floor that never moves off 0.
        let floor = AdmissionFloor::default();
        assert_eq!(floor.get(), 0);
        assert!(!below_floor(&e, floor.get()));

        // cgroup_skb starts at generation 1; a narrowing to 3 drops 1 and 2.
        floor.raise(3);
        floor.raise(2); // never lowered
        assert_eq!(floor.get(), 3);
        assert!(floor.clone().get() == 3, "one floor for every reader");
        for (kind, gen_, stale) in [
            (EventType::TcPacket, 1, true),
            (EventType::TcPacket, 2, true),
            (EventType::TcPacket, 3, false),
            (EventType::TcPacket, 4, false),
            (EventType::TlsData, 2, true),
            (EventType::TlsData, 3, false),
            // A close record (generation 0) only frees state: never stale.
            (EventType::SockClose, 0, false),
        ] {
            e.event_type = kind;
            e.scope_gen = gen_;
            assert_eq!(below_floor(&e, floor.get()), stale, "{kind:?} gen {gen_}");
        }
    }

    #[test]
    fn cgroup_skb_packets_and_close_records_key_by_socket_cookie() {
        // SAFETY: all-zero is a valid DataEvent.
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        e.socket_cookie = 0x1234_5678;
        e.pid = 7;
        for kind in [EventType::TcPacket, EventType::SockClose] {
            e.event_type = kind;
            assert_eq!(connection_key(&e), 0x1234_5678, "{kind:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn connection_key_scopes_tls_pointers_to_process() {
        let a = tls_event(1, 0x7f00_0000_1000, Direction::Egress, REQ);
        let same_conn = tls_event(1, 0x7f00_0000_1000, Direction::Ingress, RESP);
        let other_proc = tls_event(2, 0x7f00_0000_1000, Direction::Egress, REQ);
        assert_eq!(connection_key(&a), connection_key(&same_conn));
        assert_ne!(connection_key(&a), connection_key(&other_proc));
        assert!(connection_key(&a) & 0x8000_0000_0000_0000 != 0);

        let mut tc = a;
        tc.event_type = EventType::TcPacket;
        tc.socket_cookie = 42;
        assert_eq!(connection_key(&tc), 42);
    }

    // ── ConnectionFsmManager Integration Tests ──────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fsm_manager_protocol_detection_flow() {
        let manager = ConnectionFsmManager::new(1000);

        // Initially no connections
        assert!(!manager.contains(12345));

        // Simulate HTTP detection
        let http_request = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let proto = detect_protocol(
            http_request,
            54321,
            80,
            super::super::protocol::Direction::Egress,
        );
        assert!(proto.is_some());

        // Create FSM
        manager.get_or_create(12345, proto.unwrap());
        assert!(manager.contains(12345));

        // Process packet
        let result = manager.process_packet(
            12345,
            super::super::protocol::Direction::Egress,
            http_request,
            1000,
        );
        assert!(result.is_some());

        // Close connection
        manager.close_connection(12345);
        assert!(!manager.contains(12345));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fsm_manager_idle_eviction() {
        let manager = ConnectionFsmManager::new(1000);

        manager.get_or_create(1, Protocol::Http1);
        manager.get_or_create(2, Protocol::Redis);

        assert_eq!(manager.len(), 2);

        // Evict with very short timeout - should have no effect immediately
        manager.evict_idle(Duration::from_millis(1));

        // Give it time to be considered idle
        std::thread::sleep(Duration::from_millis(5));
        manager.evict_idle(Duration::from_millis(1));

        assert_eq!(manager.len(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_fsm_manager_process_nonexistent_connection() {
        let manager = ConnectionFsmManager::new(1000);

        // Processing a packet for a non-existent connection should return None
        let result = manager.process_packet(
            99999,
            super::super::protocol::Direction::Egress,
            b"data",
            1000,
        );
        assert!(result.is_none());
    }
}
