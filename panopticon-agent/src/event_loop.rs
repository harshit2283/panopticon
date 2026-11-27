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
use crate::protocol::detect::{detect_protocol, detect_tls_protocol};
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
    /// The pipeline's I/O gate (test pause points key on it).
    pub io_gate: Arc<IoGate>,
    /// The pipeline's Kafka topic ID map.
    pub kafka_topics: crate::protocol::kafka::KafkaTopics,
    /// The pipeline's raised packet caps (`raise_packet_cap`), if on.
    pub conn_cap: Option<Arc<crate::conn_cap::ConnCap>>,
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
    /// TCP records held in the reorder window (`reorder.rs`) because their
    /// bytes arrived ahead of the next expected one.
    pub tcp_reorder_held: AtomicU64,
    /// Held (or holdable) TCP records that went on with their hole still
    /// open: the window's time or space bound was reached, or the hole was
    /// wider than one packet. Each is a gap for the parser.
    pub tcp_reorder_gaps: AtomicU64,
    /// Events dropped at the ring read because their scope
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
    /// Connections whose packet cap was raised (`conn_cap.rs`).
    pub conn_cap_raised: AtomicU64,
    /// Raises not written: the kernel map refused the write, or the
    /// writer thread's queue was full.
    pub conn_cap_write_failed: AtomicU64,
    /// Raises refused because user space already keeps
    /// `conn_cap::CONN_CAP_LIVE_MAX` entries (the kernel's LRU would
    /// otherwise drop a live one to make room).
    pub conn_cap_refused: AtomicU64,
    /// Records of raised connections cut at `max_packet_bytes` because they
    /// were emitted before the raise was written (the race).
    pub conn_cap_truncated_before_raise: AtomicU64,
    /// Kernel `CONN_CAP_STATS`, summed over CPUs: packets captured past
    /// `max_packet_bytes` on raised connections, and those still cut at the
    /// raised cap.
    pub conn_cap_packets: AtomicU64,
    pub conn_cap_cut: AtomicU64,
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
            tcp_reorder_held: AtomicU64::new(0),
            tcp_reorder_gaps: AtomicU64::new(0),
            drops_stale_scope_gen: AtomicU64::new(0),
            drops_no_pipeline: AtomicU64::new(0),
            capture_stopped: AtomicBool::new(false),
            scope_drops: std::array::from_fn(|_| AtomicU64::new(0)),
            conn_cap_raised: AtomicU64::new(0),
            conn_cap_write_failed: AtomicU64::new(0),
            conn_cap_refused: AtomicU64::new(0),
            conn_cap_truncated_before_raise: AtomicU64::new(0),
            conn_cap_packets: AtomicU64::new(0),
            conn_cap_cut: AtomicU64::new(0),
        }
    }
}

// ── Admission floor (cgroup_skb, DESIGN §3 narrowing) ─────────────────────

/// The lowest scope generation the ring readers admit, shared by all of
/// them. Only ever raised. Capture starts at generation 1.
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

/// Whether `event` is dropped at the ring read under admission `floor`.
/// Close records too: the kernel stamps one with the generation its socket
/// was in scope under, and a stale one would carry a narrowed-out socket's
/// tuple across (its state went with the replaced pipeline anyway).
fn below_floor(event: &DataEvent, floor: u32) -> bool {
    event.scope_gen < floor
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
/// pipeline handle is loaded, *then* the admission floor, and the floor
/// check, the dispatch and the hand-off to workers use that snapshot.
/// Before each event the slot is checked again: once a new pipeline is
/// installed, the events drained after go to it (with the floor loaded
/// again), so a record emitted after the installation never reaches an
/// earlier pipeline. Batches pending in the
/// [`WorkerBatcher`] keep their destination: they are never moved to a
/// newer pipeline, and die with theirs if it is revoked.
///
/// The load order matters: the publisher raises the floor before it
/// installs a new pipeline, so a reader that sees the new pipeline also
/// sees the raised floor and cannot admit an old-generation event into it.
/// A reader still holding the old pipeline may admit one there; that
/// pipeline's gate is revoked before the change is reported applied.
pub(crate) struct Admission<'a> {
    batcher: WorkerBatcher,
    floor: u32,
    slot: &'a arc_swap::ArcSwap<PipelineHandle>,
    floor_src: &'a AdmissionFloor,
    stats: &'a EventStats,
    received: u64,
    stale: u64,
}

impl<'a> Admission<'a> {
    pub(crate) fn new(
        slot: &'a arc_swap::ArcSwap<PipelineHandle>,
        floor_src: &'a AdmissionFloor,
        stats: &'a EventStats,
        shard: usize,
        shards: usize,
    ) -> Self {
        let handle = slot.load_full(); // first: see above
        let floor = floor_src.get(); // then the floor
        Self {
            batcher: WorkerBatcher::new(handle, shard, shards),
            floor,
            slot,
            floor_src,
            stats,
            received: 0,
            stale: 0,
        }
    }

    /// Admit or drop one event.
    pub(crate) fn offer(&mut self, event: &DataEvent, rate_limiter: &RateLimiter) {
        self.received += 1;
        if !Arc::ptr_eq(&self.slot.load(), &self.batcher.handle) {
            // A new pipeline: what is pending keeps its destination.
            self.batcher.flush(self.stats);
            let handle = self.slot.load_full(); // first: see above
            self.floor = self.floor_src.get(); // then the floor
            self.batcher = WorkerBatcher::new(handle, self.batcher.shard, self.batcher.shards);
        }
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
    let manager = TrackedConnections {
        manager: ConnectionFsmManager::with_topics(
            ctx.max_connections_tracked,
            ctx.kafka_topics.clone(),
        ),
        stats: Arc::clone(&ctx.stats),
    };
    let mut last_sweep = Instant::now();
    // Never longer than the idle timeout itself (5 s at most), and on a
    // timer, not only when a batch arrives: a connection whose close never
    // came (lost in a full ring, raced by its first packet, or withheld
    // because the socket left scope) is freed on a quiet worker too.
    let sweep_interval = ctx
        .idle_timeout
        .min(Duration::from_secs(5))
        .max(Duration::from_millis(10));
    let mut sweep_timer = tokio::time::interval(sweep_interval);
    sweep_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    debug!(worker_id, "Worker started");

    // The event being processed: each record's header and payload bytes are
    // copied in; past payload_len it keeps earlier bytes, never read.
    // SAFETY: all-zero is a valid DataEvent (every enum has a 0 variant).
    let mut scratch: Box<DataEvent> = Box::new(unsafe { std::mem::zeroed() });
    let mut reorder = crate::reorder::ReorderWindow::default();
    loop {
        let deadline = reorder.deadline();
        let batch = tokio::select! {
            b = rx.recv() => match b {
                Some(b) => b,
                None => break,
            },
            // No traffic: run the timed work below with an empty batch.
            _ = sweep_timer.tick() => EventBatch::default(),
            // A reorder hole is due to be taken as a loss.
            _ = tokio::time::sleep_until(
                tokio::time::Instant::from_std(deadline.unwrap_or_else(Instant::now))
            ), if deadline.is_some() => EventBatch::default(),
        };
        for record in batch.records() {
            if !read_data_event_into(record, &mut scratch) {
                continue;
            }
            let cookie = connection_key(&scratch);
            // A close record (sockops STATE_CB, the header only) is sent for
            // a socket the kernel emitted a packet record for and that is in
            // scope when it closes, stamped with that generation (admitted
            // like any record): it frees the connection's state and reaches
            // no sink. Counted processed (it is consumed here).
            //
            // A TlsNew record (SSL_new returned the object, every mode):
            // any earlier object at that address was destroyed, so the key's
            // connection ends and the next one starts with no state. Kept in
            // the raw dump, so a replay ends the same connections.
            match scratch.event_type {
                EventType::SockClose => {}
                EventType::TlsNew => {
                    if let Some(raw) = ctx.raw_capture.as_ref()
                        && ctx.privacy.get() == PrivacyMode::Full
                    {
                        raw.record(&scratch);
                    }
                    ctx.stats.events_processed.fetch_add(1, Ordering::Relaxed);
                    end_connection(&ctx, &manager, cookie);
                    continue;
                }
                // The kernel made every scope decision (DESIGN §8): nothing
                // is filtered, held or cut here.
                _ => {
                    arrive_event(worker_id, &ctx, &scratch, cookie);
                    reorder.offer(
                        &manager,
                        cookie,
                        &scratch,
                        Instant::now(),
                        &ctx.stats,
                        &mut |e: &DataEvent| process_event(worker_id, &ctx, &manager, e, cookie),
                    );
                    continue;
                }
            }
            ctx.stats.events_processed.fetch_add(1, Ordering::Relaxed);
            // What the connection still holds goes first, holes and all.
            reorder.flush(&manager, cookie, &ctx.stats, &mut |e: &DataEvent| {
                process_event(worker_id, &ctx, &manager, e, cookie)
            });
            end_connection(&ctx, &manager, cookie);
        }
        if !reorder.is_empty() {
            reorder.expire(
                &manager,
                Instant::now(),
                &ctx.stats,
                &mut |c: u64, e: &DataEvent| process_event(worker_id, &ctx, &manager, e, c),
            );
        }

        // Periodic idle connection sweep
        if last_sweep.elapsed() >= sweep_interval {
            let evicted = manager.evict_idle(ctx.idle_timeout);
            // Raised connections this worker evicted (idle, or at capacity
            // since the last sweep) give their kernel entries back.
            if let Some(c) = &ctx.conn_cap {
                c.sweep(worker_id, |cookie| manager.contains(cookie));
            }
            if evicted > 0 {
                ctx.stats
                    .active_connections
                    .fetch_sub(evicted as u64, Ordering::Relaxed);
                ctx.stats
                    .evictions_idle
                    .fetch_add(evicted as u64, Ordering::Relaxed);
                debug!(worker_id, evicted, "Evicted idle connections");
            }
            last_sweep = Instant::now();
        }
    }

    reorder.flush_all(&manager, &ctx.stats, &mut |c: u64, e: &DataEvent| {
        process_event(worker_id, &ctx, &manager, e, c)
    });
    debug!(worker_id, "Worker shutting down");
}

/// Raw dump, count and log of one admitted event, as it arrives (before
/// the reorder window, `reorder.rs`).
fn arrive_event(worker_id: usize, ctx: &WorkerTaskContext, event: &DataEvent, cookie: u64) {
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
}

/// Parsing, PII, graph and export of one admitted event, in stream order
/// (after the reorder window).
fn process_event(
    worker_id: usize,
    ctx: &WorkerTaskContext,
    manager: &ConnectionFsmManager,
    event: &DataEvent,
    cookie: u64,
) {
    // Read when processed: a reload may have tightened it since arrival.
    let privacy = ctx.privacy.get();
    let log_events = ctx.log_events && privacy != PrivacyMode::MetricsOnly;

    // ── Protocol detection + parsing (Phase 3) ───────────────────
    let Some(results) = feed_event(
        manager,
        event,
        cookie,
        &ctx.stats,
        worker_id,
        log_events,
        ctx.conn_cap.as_deref(),
    ) else {
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

    // Handle connection close: TCP RST, or FIN from both sides (after this
    // packet's payload was parsed).
    let closed = match event.event_type {
        EventType::TcPacket if event.tcp_flags & TCP_FLAG_RST != 0 => true,
        EventType::TcPacket if event.tcp_flags & TCP_FLAG_FIN != 0 => {
            manager.note_fin(cookie, sender_endpoint(event), event.direction)
        }
        _ => false,
    };
    if closed {
        end_connection(ctx, manager, cookie);
    }
}

/// Free everything a worker holds for connection `cookie`.
fn end_connection(ctx: &WorkerTaskContext, manager: &ConnectionFsmManager, cookie: u64) {
    if manager.close_connection(cookie) {
        ctx.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
    if let Some(c) = &ctx.conn_cap {
        c.on_close(cookie);
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

/// The sequence fields of a TCP packet; None for other events (UDP,
/// TLS plaintext, socket events), which have no sequence to check.
pub(crate) fn tcp_segment(event: &DataEvent) -> Option<crate::protocol::fsm::TcpSegment> {
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

/// The protocol of a new key from its first payload. A TLS key is never
/// DNS (detect.rs `detect_tls_protocol`).
fn detect_event(event: &DataEvent, payload: &[u8]) -> Option<crate::protocol::Protocol> {
    use crate::protocol::Protocol;
    let detect = if event.event_type == EventType::TlsData {
        detect_tls_protocol
    } else {
        detect_protocol
    };
    let found = detect(payload, event.src_port, event.dst_port, event.direction);
    // An HTTP/2 server may write its SETTINGS before the client's preface
    // reaches the capture (RFC 9113 §3.4 allows either order). Read as
    // HTTP/2 only as the first byte of its stream (cgroup_skb's offset),
    // and before the port fallback; the parser still waits for the
    // client's preface before it reads any of it (http2.rs `feed`).
    if proven_stream_start(event) && crate::protocol::detect::is_http2_server_preface(payload) {
        return Some(if found == Some(Protocol::Grpc) {
            Protocol::Grpc
        } else {
            Protocol::Http2
        });
    }
    found
}

/// cgroup_skb located this record's first byte at its stream's start.
fn proven_stream_start(event: &DataEvent) -> bool {
    event.event_type == EventType::TcPacket
        && event.ip_proto == 6
        && event.cgroup_id != 0
        && event.stream_off == 0
}

/// Run one event through its connection's parser: detect the protocol and
/// create the parser on the first payload, keep only the new, in-window
/// bytes of a TCP segment, and account for bytes that were never captured
/// (ring drops before it, the capture cap after it). A TCP connection
/// detected as a protocol that loses frame sync on a cut packet has its
/// packet cap raised in the kernel (`conn_cap`). Returns the parser
/// results in order, or None for a TCP segment that must be ignored whole
/// (a retransmission, or outside the window: its FIN / RST too).
fn feed_event(
    manager: &ConnectionFsmManager,
    event: &DataEvent,
    cookie: u64,
    stats: &EventStats,
    worker_id: usize,
    log_events: bool,
    conn_cap: Option<&crate::conn_cap::ConnCap>,
) -> Option<Vec<FsmResult>> {
    use crate::protocol::fsm::{CreateResult, SegmentVerdict};

    let payload = event.payload_bytes();
    let src = sender_endpoint(event);
    let seg = tcp_segment(event);
    // A SYN (only in recordings made with the removed TC capture: cgroup_skb
    // sends `stream_off` instead) locates its side's first byte (before the
    // parser exists, which is created on the first payload); a bare SYN on a
    // tracked key is a new connection.
    if let Some(s) = seg.filter(|s| s.syn)
        && manager.note_syn(cookie, src, s.ack.is_some(), s.seq)
    {
        stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
    let mut created = false;
    if !payload.is_empty()
        && !manager.contains(cookie)
        && let Some(proto) = guarded(stats, worker_id, || detect_event(event, payload)).flatten()
    {
        let server = server_endpoint(event, proto, payload);
        match manager.get_or_create_with_server(cookie, proto, server) {
            CreateResult::Created => {
                created = true;
                stats.active_connections.fetch_add(1, Ordering::Relaxed);
            }
            CreateResult::CreatedWithEviction(evicted) => {
                created = true;
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
        // A record stamped with its socket's role: the endpoint above is
        // the kernel's (or content's that names a side), and its
        // directions are the socket's, not the process's as over TLS.
        if created
            && event.event_type == EventType::TcPacket
            && event.role != panopticon_common::scope::ROLE_UNKNOWN
        {
            manager.direction_from_role(cookie);
        }
        if log_events {
            tracing::debug!(worker = worker_id, cookie, protocol = %proto, "Protocol detected");
        }
        if created
            && seg.is_some()
            && let Some(c) = conn_cap
        {
            c.on_detect(cookie, proto, worker_id);
        }
    }

    match seg {
        // cgroup_skb: a first byte at stream offset 0 is the stream's start.
        // Any other offset is a late join (and seeding the tracker that far
        // back would put the segment outside its window).
        Some(s) if event.cgroup_id != 0 && event.stream_off == 0 => {
            manager.note_origin(cookie, src, event.direction, s.seq);
        }
        Some(_) => {}
        // TLS plaintext carries no stream position: every new TLS key
        // starts latched (fsm.rs `start_tls`). UDP has none either.
        None if created && event.event_type == EventType::TlsData => manager.start_tls(cookie),
        None if created => manager.mark_joined_late(cookie),
        None => {}
    }
    let (gap, trim) =
        match seg.and_then(|seg| manager.admit_segment(cookie, src, event.direction, seg)) {
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
    // Bytes beyond the capture cap (a packet past `max_packet_bytes`; a TLS
    // read or write past 4 records, 16 KiB; a head-only cut) were never seen: let
    // the parser count them instead of desynchronising on the next message.
    let tail = (event.orig_len as usize).saturating_sub(trim.max(payload.len()));
    if tail > 0 {
        stats.truncated_events.fetch_add(1, Ordering::Relaxed);
        if seg.is_some()
            && let Some(c) = conn_cap
        {
            c.on_truncated(cookie, event.timestamp_ns);
        }
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
            match ctx.pii_engine.as_ref() {
                // Redact unless the mode is full, and in full too if the config
                // asks for a redacted export ([pii] redact = true). The engine
                // protects known credential forms itself (best effort).
                Some(e) => {
                    let redact = ctx.privacy != PrivacyMode::Full || e.redacts();
                    e.scan_message_with(msg, redact)
                }
                // No engine ([pii] enabled = false, full mode): known
                // credential forms are still protected (best effort) unless
                // `mask_credentials = false`.
                None => {
                    if crate::protocol::mask_credentials_enabled() {
                        crate::pii::mask_credentials(msg);
                    }
                    None
                }
            }
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
            crate::test_hooks::pause(crate::test_hooks::WORKER_HOLDING_RESOLVED, ctx.io_gate);
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
                crate::export::json::TransportContext::from_data_event(ctx.event),
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
    msg.headers.clear();
}

/// Bytes past `max_body_bytes` that are still scanned, so a value straddling
/// the cut is detected whole and redacted before the cut drops its tail.
const SCAN_LOOKAHEAD: usize = 256;

/// Bound on every other string field (path, method, content type, header
/// names and values), applied as `max_body_bytes` is to bodies: 8 KiB, the
/// request-line and header-line limit of common HTTP servers.
const MAX_FIELD_BYTES: usize = 8 * 1024;

/// Bound the bodies to `max` bytes around a PII scan: scan up to
/// `max + SCAN_LOOKAHEAD`, then cut to `max` and drop a token the cut split,
/// so no prefix of an undetected value (`123-45-6` of an SSN) is exported.
/// The other string fields get the same treatment at [`MAX_FIELD_BYTES`].
fn scan_with_body_cap(
    msg: &mut crate::protocol::L7Message,
    max: usize,
    scan: impl FnOnce(&mut crate::protocol::L7Message) -> Option<crate::pii::PiiReport>,
) -> Option<crate::pii::PiiReport> {
    cap_body_text(msg, max.saturating_add(SCAN_LOOKAHEAD));
    // A header name is classified whole (credential header or not): one
    // that would be cut is withheld with its value instead.
    for (name, value) in msg.headers.iter_mut() {
        if name.len() > MAX_FIELD_BYTES {
            for f in [name, value] {
                zeroize::Zeroize::zeroize(f);
                f.push_str(crate::protocol::FIELD_WITHHELD);
            }
        }
    }
    let fields = |msg: &mut crate::protocol::L7Message, f: &mut dyn FnMut(&mut String)| {
        [&mut msg.method, &mut msg.path, &mut msg.content_type]
            .into_iter()
            .flatten()
            .for_each(&mut *f);
        msg.headers.iter_mut().for_each(|(name, value)| {
            f(name);
            f(value);
        });
    };
    fields(msg, &mut |text| {
        if text.len() > MAX_FIELD_BYTES + SCAN_LOOKAHEAD {
            text.truncate(
                crate::protocol::truncate_utf8(text, MAX_FIELD_BYTES + SCAN_LOOKAHEAD).len(),
            );
        }
    });
    let mut report = scan(msg);
    fields(msg, &mut |text| cut_partial_token(text, MAX_FIELD_BYTES));
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
/// Decided from the detection payload's content where it names a side (an
/// HTTP request line came from the client, a MySQL greeting from the
/// server...), then from the socket's role where the kernel stamped it
/// (established by `connect`: this socket is the client's; by `accept`:
/// the server's; a repaired socket counts as connected), then from an
/// HTTP/2 server preface at its stream's start (a SETTINGS shape a client
/// can send too, so below the role), then from well-known service ports,
/// then by assuming the lower port is the server's. TLS events have no ports: if the content
/// doesn't say, the process-relative direction is kept (writes treated as
/// requests), which is right for clients.
fn server_endpoint(
    event: &DataEvent,
    proto: crate::protocol::Protocol,
    payload: &[u8],
) -> Option<crate::protocol::fsm::Endpoint> {
    use crate::protocol::Protocol;
    use crate::protocol::detect::{is_service_port, sent_by_client};
    use panopticon_common::scope::{ROLE_CLIENT, ROLE_SERVER};

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
    // The socket's local end sent an egress record, its peer an ingress one.
    let local_sent = event.direction == Direction::Egress;
    let server_preface = proven_stream_start(event)
        && matches!(proto, Protocol::Http2 | Protocol::Grpc)
        && crate::protocol::detect::is_http2_server_preface(payload);
    Some(match sent_by_client(proto, payload) {
        Some(true) => dst,
        Some(false) => src,
        // The kernel's role is the socket's establishment side: a repaired
        // (restored) socket counts as connected, so content that names a
        // side goes first. A server-preface shape names none (a client can
        // open with the same nine bytes): the role outranks it.
        None if event.role == ROLE_CLIENT => {
            if local_sent {
                dst
            } else {
                src
            }
        }
        None if event.role == ROLE_SERVER => {
            if local_sent {
                src
            } else {
                dst
            }
        }
        // No role stamped: a SETTINGS frame at its stream's start is the
        // server's preface (a repaired socket has no stream offset).
        None if server_preface => src,
        None if is_service_port(event.dst_port) => dst,
        None if is_service_port(event.src_port) => src,
        None if event.dst_port <= event.src_port => dst,
        None => src,
    })
}

/// Key identifying the connection an event belongs to.
///
/// Packet and close records carry the kernel socket cookie, a counter with
/// bit 63 clear. TLS events carry the library's
/// connection object pointer (`SSL*`, `*tls.Conn`), chosen by the traced
/// process and unique only within it: it is hashed with the PID under a
/// per-process random key, so no process can pick a pointer that lands on
/// another connection's key (F18), and bit 63 is set so a TLS key never
/// equals a socket cookie. A `TlsNew` record is keyed like the data of the
/// object it starts. Events without one fall back to a per-thread key.
fn connection_key(event: &DataEvent) -> u64 {
    use std::hash::BuildHasher;
    static TLS_KEY: std::sync::OnceLock<std::hash::RandomState> = std::sync::OnceLock::new();
    if !matches!(event.event_type, EventType::TlsData | EventType::TlsNew) {
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
    use panopticon_common::scope::STREAM_OFF_UNKNOWN;
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
        // Bit 63 set: outside the socket cookie space (bit 63 clear).
        assert!(cookie & TLS_KEY_BIT != 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_synthetic_cookie_no_collision_with_real() {
        // Socket cookies have bit 63 clear, so small ones included
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
    fn tls_keys_are_keyed_and_disjoint_from_socket_cookies() {
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
        // A socket cookie (bit 63 clear) is used as is and can never equal
        // a TLS key.
        let mut tc = tls;
        tc.event_type = EventType::TcPacket;
        tc.socket_cookie = 0x0000_0000_0042_1234;
        assert_eq!(connection_key(&tc), tc.socket_cookie);
        assert_eq!(connection_key(&tc) & TLS_KEY_BIT, 0);
    }

    const CLI: (u32, u16) = (0x0A63_0002, 51000);
    const SRV: (u32, u16) = (0x0A63_0001, 18090);

    /// One key for both directions of a test connection (bit 63 clear).
    pub(crate) fn flow_cookie(a: (u32, u16), b: (u32, u16), proto: u8) -> u64 {
        fxhash::hash64(&(a.min(b), a.max(b), proto)) >> 1
    }

    /// A TCP packet from `from` to the other end (both directions keyed
    /// alike, as one connection).
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
        e.socket_cookie = flow_cookie(from, to, 6);
        e.tcp_seq = seq;
        e.tcp_ack = ack;
        e.tcp_flags = flags | panopticon_common::TCP_FLAG_ACK;
        e.stream_off = STREAM_OFF_UNKNOWN;
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
            let fed = feed_event(&m, e, connection_key(e), &stats, 0, false, None);
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

    /// The pre-accept hold (sock_capture.rs `hold_packet`, DESIGN §3.1): a
    /// server's first bytes, received before accept(), reach user space as
    /// the records released at accept(), from stream offset 0, then the live
    /// records follow. With more than two packets before accept() the third
    /// was dropped (`pending_overflow`), leaving a gap. The request line was
    /// seen from the stream's start (not joined late). A gap inside a
    /// Content-Length body is accounted and keeps the framing proven: both
    /// paths. A gap inside the headers leaves the framing unproven: no
    /// path from there (closed-set values only).
    #[test]
    fn released_hold_keeps_the_path_and_a_gap_is_skipped() {
        let head = b"POST /orders/new HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n";
        let h = head.len() as u32;
        let resp = b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n";
        let next = b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n";
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let (r, n) = (resp.len() as u32, next.len() as u32);
        let cli =
            |seq: u32, off: u32, p: &[u8]| at_off(tcp_pkt(CLI, 1000 + seq, 5000, 0, p), off as u64);
        let srv = |seq: u32, ack: u32, p: &[u8]| {
            at_off(tcp_pkt(SRV, 5000 + seq, 1000 + ack, 0, p), seq as u64)
        };
        // Released at accept(): slots 0 and 1. "efgh" (h+4..h+8) was the
        // third packet, dropped. Then live: "ijkl", the reply, the next
        // request and its reply.
        let evs = [
            cli(0, 0, head),
            cli(h, h, b"abcd"),
            cli(h + 8, h + 8, b"ijkl"),
            srv(0, h + 12, resp),
            cli(h + 12, h + 12, next),
            srv(r, h + 12 + n, ok),
        ];
        let (paths, _) = run_tcp(&evs);
        // The gap is inside a Content-Length body: its bytes are accounted
        // (skipped), the framing stays proven, and the next request's
        // boundary is known.
        assert_eq!(
            paths,
            vec![Some("/orders/new".to_string()), Some("/next".to_string())]
        );
        // A gap inside the headers instead (the third packet held the
        // Content-Length line): the framing is unproven from there.
        let h1 = b"POST /orders/new HTTP/1.1\r\n";
        let h2 = b"Host: a\r\n";
        let (l1, l2) = (h1.len() as u32, h2.len() as u32);
        let cl = b"Content-Length: 12\r\n\r\n";
        let rest = l1 + l2 + cl.len() as u32;
        let hevs = [
            cli(0, 0, h1),
            cli(l1, l1, h2),
            cli(rest, rest, b"abcdefghijkl"),
            srv(0, rest + 12, resp),
            cli(rest + 12, rest + 12, next),
            srv(r, rest + 12 + n, ok),
        ];
        let (paths, _) = run_tcp(&hevs);
        // Unproven framing (fsm.rs): nothing cut from the stream after it,
        // the request line before it included (its message never completed
        // with proven framing).
        assert_eq!(paths, vec![None, None], "header gap");
        // No gap: both paths.
        let whole = [
            cli(0, 0, head),
            cli(h, h, b"abcdefghijkl"),
            srv(0, h + 12, resp),
            cli(h + 12, h + 12, next),
            srv(r, h + 12 + n, ok),
        ];
        let (paths, _) = run_tcp(&whole);
        assert_eq!(
            paths,
            vec![Some("/orders/new".to_string()), Some("/next".to_string())]
        );
        // What the capture gave before the hold: the pre-accept packets
        // dropped, the first record past offset 0 (joined late): no path.
        let (paths, _) = run_tcp(&evs[2..]);
        assert!(paths.iter().all(|p| p.is_none()), "{paths:?}");
    }

    /// A Redis packet between CLI and SRV's address on port 6379, from the
    /// client or the server, `ack` set to the peer's next byte.
    fn redis_pkt(from_client: bool, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> DataEvent {
        let srv = (SRV.0, 6379);
        let mut e = tcp_pkt(CLI, seq, ack, flags, payload);
        let (from, to) = if from_client { (CLI, srv) } else { (srv, CLI) };
        (e.src_addr, e.src_port, e.dst_addr, e.dst_port) = (from.0, from.1, to.0, to.1);
        e.direction = if from_client {
            Direction::Ingress
        } else {
            Direction::Egress
        };
        e.socket_cookie = flow_cookie(from, to, 6);
        e
    }

    /// `raise_packet_cap`: a TCP connection detected as Redis has its cap
    /// raised at its first packet, one detected as HTTP/1.1 does not, and
    /// that first packet, cut at the cap and emitted (timestamp 0) before
    /// the raise, is counted as the race.
    #[test]
    fn detection_raises_the_packet_cap_of_framed_protocols() {
        use std::sync::atomic::Ordering::Relaxed;
        let (cap, fake, cstats) = crate::conn_cap::fake::conn_cap();
        let (m, stats) = (ConnectionFsmManager::new(16), EventStats::new());
        let mut first = redis_pkt(true, 1000, 5000, 0, b"*1\r\n$4\r\nPING\r\n");
        first.orig_len += 100;
        feed_event(
            &m,
            &first,
            connection_key(&first),
            &stats,
            0,
            false,
            Some(&cap),
        );
        let http = tcp_pkt(CLI, 1, 1, 0, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        feed_event(
            &m,
            &http,
            connection_key(&http),
            &stats,
            0,
            false,
            Some(&cap),
        );
        cap.flush(); // the writer thread has done the write
        let raised: Vec<u64> = fake.lock().unwrap().map.keys().copied().collect();
        assert_eq!(raised, vec![first.socket_cookie]);
        assert!(cap.is_raised(first.socket_cookie) && !cap.is_raised(http.socket_cookie));
        assert_eq!(cstats.conn_cap_raised.load(Relaxed), 1);
        assert_eq!(cstats.conn_cap_truncated_before_raise.load(Relaxed), 1);
        assert_eq!(stats.truncated_events.load(Relaxed), 1);
    }

    /// An HTTP/2 frame.
    fn h2_frame(t: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend([t, flags]);
        f.extend(stream.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Client preface and SETTINGS, then `rest`.
    fn h2_start(rest: &[u8]) -> Vec<u8> {
        let mut d = crate::protocol::detect::HTTP2_PREFACE.to_vec();
        d.extend(h2_frame(0x4, 0, 0, &[]));
        d.extend_from_slice(rest);
        d
    }

    /// A request on `stream`: static-table HEADERS (GET, /) and a DATA
    /// body, END_STREAM.
    fn h2_request(stream: u32, body: &[u8]) -> Vec<u8> {
        let mut d = h2_frame(0x1, 0x4, stream, &[0x82, 0x84]);
        d.extend(h2_frame(0x0, 0x1, stream, body));
        d
    }

    /// A `:status 200` reply ending `stream`.
    fn h2_reply(stream: u32) -> Vec<u8> {
        h2_frame(0x1, 0x4 | 0x1, stream, &[0x88])
    }

    /// An OpenSSL read or write on connection object 0x7000 of pid 50.
    fn ssl_event(dir: Direction, payload: &[u8]) -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent (all enums have a 0 variant)
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        e.event_type = EventType::TlsData;
        e.direction = dir;
        (e.pid, e.tgid) = (50, 50);
        e.socket_cookie = 0x7000;
        e.tls_library = panopticon_common::TlsLibrary::OpenSsl;
        e.payload[..payload.len()].copy_from_slice(payload);
        (e.payload_len, e.orig_len) = (payload.len() as u32, payload.len() as u32);
        e
    }

    /// `SSL_new` returning that object, on another thread of the process.
    #[test]
    fn tls_new_is_keyed_like_the_objects_data() {
        let mut born = ssl_event(Direction::Egress, b"");
        born.event_type = EventType::TlsNew;
        born.tgid = 51;
        let data = ssl_event(Direction::Ingress, b"x");
        assert_eq!(connection_key(&born), connection_key(&data));
    }

    /// Feed events through feed_event (the parsing step of worker_task;
    /// TlsNew records are the worker loop's, see narrowing_tests); every
    /// completed message.
    fn run_events(events: &[DataEvent]) -> Vec<crate::protocol::L7Message> {
        let (m, stats) = (ConnectionFsmManager::new(16), EventStats::new());
        let mut out = vec![];
        for e in events {
            for r in feed_event(&m, e, connection_key(e), &stats, 0, false, None)
                .into_iter()
                .flatten()
            {
                match r {
                    FsmResult::Messages(ms) => out.extend(ms),
                    FsmResult::MessageComplete(m) => out.push(m),
                    _ => {}
                }
            }
        }
        out
    }

    const CANARY: &[u8] = b"canary-s7Kf2v9LmQ8z";

    /// A length-prefixed DNS message (TCP framing) for `canary.example`,
    /// a query or its answer.
    fn dns_tcp_message(response: bool) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, if response { 0x81 } else { 0x01 }, 0x00];
        m.extend([0, 1, 0, response as u8, 0, 0, 0, 0]);
        m.extend(b"\x06canary\x07example\x00\x00\x01\x00\x01");
        if response {
            m.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 7]);
        }
        let mut out = (m.len() as u16).to_be_bytes().to_vec();
        out.extend(m);
        out
    }

    /// Codex R12 #1: a TLS key whose learned port is 53 is never parsed as
    /// DNS. The port-53 fallback would otherwise read a length-prefixed DNS
    /// message forged inside a TLS record (any client can write one) and
    /// export its question as the path (detect.rs `detect_tls_protocol`).
    #[test]
    fn tls_key_on_port_53_is_not_dns() {
        let (q, a) = (dns_tcp_message(false), dns_tcp_message(true));
        // The control: these bytes are DNS on port 53 to detection, and a
        // DNS parser exports the name.
        assert_eq!(
            detect_protocol(&q, 40000, 53, Direction::Egress),
            Some(crate::protocol::Protocol::Dns)
        );
        let mut dns = crate::protocol::dns::DnsParser::new();
        use crate::protocol::ProtocolParser;
        dns.feed(&q, Direction::Egress, 1);
        let crate::protocol::ParseResult::Messages(m) = dns.feed(&a, Direction::Ingress, 2) else {
            panic!("the control did not parse");
        };
        assert_eq!(m[0].path.as_deref(), Some("canary.example"));

        let rec = |dir, p: &[u8], lib| {
            let mut e = ssl_event(dir, p);
            (e.src_port, e.dst_port, e.tls_library) = match dir {
                Direction::Egress => (40000, 53, lib),
                Direction::Ingress => (53, 40000, lib),
            };
            e
        };
        for lib in [
            panopticon_common::TlsLibrary::OpenSsl,
            panopticon_common::TlsLibrary::GoTls,
        ] {
            let out = run_events(&[
                rec(Direction::Egress, &q, lib),
                rec(Direction::Ingress, &a, lib),
            ]);
            assert!(!format!("{out:?}").contains("canary"), "{lib:?}: {out:?}");
        }
    }

    /// Codex #5 through the worker's parsing step: a TLS key whose first
    /// record starts with a client preface (a Write that began inside a
    /// DATA payload of a connection the agent joined late) decodes nothing,
    /// OpenSSL or Go, whatever the record's stamp (fsm.rs `start_tls`).
    #[test]
    fn tls_key_first_seen_mid_connection_stays_latched() {
        for (lib, stamp) in [
            (panopticon_common::TlsLibrary::GoTls, 1_000),
            (panopticon_common::TlsLibrary::GoTls, STREAM_OFF_UNKNOWN),
            (panopticon_common::TlsLibrary::OpenSsl, 0),
        ] {
            let rec = |dir, p: &[u8]| {
                let mut e = ssl_event(dir, p);
                (e.tls_library, e.stream_off) = (lib, stamp);
                e
            };
            let out = run_events(&[
                rec(Direction::Egress, &h2_start(&h2_request(3, CANARY))),
                rec(Direction::Ingress, &h2_reply(3)),
            ]);
            assert!(!format!("{out:?}").contains("s7Kf"), "{lib:?} {stamp}");
        }
    }

    /// Codex R8 #1 / R9: TLS writes inside one DATA payload that start with
    /// the client preface (an upload of captured HTTP/2 bytes) must not
    /// restart the connection clean, nor does the second embedded preface.
    /// Only a TlsNew record (`SSL_new`) ends the key's connection (and the
    /// next starts latched, like every TLS key): not a socket seen during
    /// a call (R9), nor `SSL_free` (R10: it may drop one reference of
    /// several).
    #[test]
    fn embedded_prefaces_stay_withheld() {
        // A first write, then a DATA frame (stream 1) of 4096 bytes whose
        // payload the next writes carry.
        let mut open = h2_frame(0x1, 0x4, 1, &[0x83, 0x84]); // POST /
        open.extend(&h2_frame(0x0, 0, 1, &[0; 4096])[..9]);
        let mut forged = h2_start(&h2_request(3, CANARY));
        forged.extend(h2_frame(0x3, 0, 0, &[0; 4])); // RST_STREAM(0)
        let out = run_events(&[
            ssl_event(Direction::Egress, &h2_start(&open)),
            ssl_event(Direction::Egress, &h2_start(&[])),
            ssl_event(Direction::Egress, &forged),
            ssl_event(Direction::Ingress, &h2_reply(3)),
        ]);
        let dump = format!("{out:?}");
        assert!(!dump.contains("s7Kf"), "{dump}");
    }

    /// Codex R9's schedule: a read or write whose call did I/O on another
    /// socket (a BIO callback) carries an embedded preface, HEADERS and a
    /// body. Under R8 the socket change reset the key and this exported.
    #[test]
    fn embedded_preface_in_a_mislabelled_call_stays_withheld() {
        for dir in [Direction::Egress, Direction::Ingress] {
            let mut open = h2_frame(0x1, 0x4, 1, &[0x83, 0x84]);
            open.extend(&h2_frame(0x0, 0, 1, &[0; 4096])[..9]);
            let mut forged = h2_start(&h2_request(3, CANARY));
            forged.extend(h2_frame(0x3, 0, 0, &[0; 4])); // RST_STREAM(0)
            let back = match dir {
                Direction::Egress => Direction::Ingress,
                Direction::Ingress => Direction::Egress,
            };
            let out = run_events(&[
                ssl_event(dir, &h2_start(&open)),
                ssl_event(dir, &forged),
                ssl_event(back, &h2_reply(3)),
            ]);
            let dump = format!("{out:?}");
            assert!(!dump.contains("s7Kf"), "{dir:?}: {dump}");
        }
    }

    /// No TlsNew record: a preface on the SSL object is not a new
    /// connection, and does not clear a latch.
    #[test]
    fn preface_without_tls_new_stays_latched() {
        let cut = &h2_frame(0x0, 0, 1, &[0; 64])[..20];
        let mut first = h2_frame(0x1, 0x4, 1, &[0x83, 0x84]);
        first.extend_from_slice(cut);
        let out = run_events(&[
            ssl_event(Direction::Egress, &h2_start(&first)),
            ssl_event(Direction::Egress, &h2_start(&h2_request(3, CANARY))),
            ssl_event(Direction::Ingress, &h2_reply(3)),
        ]);
        let dump = format!("{out:?}");
        assert!(!dump.contains("s7Kf"), "{dump}");
        // Between frames, with nothing lost: still latched.
        let out = run_events(&[
            ssl_event(Direction::Egress, &h2_start(&h2_request(1, b"x"))),
            ssl_event(Direction::Ingress, &h2_reply(1)),
            ssl_event(Direction::Egress, &h2_start(&h2_request(1, CANARY))),
            ssl_event(Direction::Ingress, &h2_reply(1)),
        ]);
        let dump = format!("{out:?}");
        assert!(!dump.contains("s7Kf"), "{dump}");
    }

    /// An HPACK failure latches the connection: a later preface at a frame
    /// boundary does not clear it.
    #[test]
    fn hpack_failure_then_boundary_preface_stays_latched() {
        let bad = h2_frame(0x1, 0x4 | 0x1, 1, &[0x80]); // index 0: invalid
        let out = run_events(&[
            ssl_event(Direction::Egress, &h2_start(&bad)),
            ssl_event(Direction::Egress, &h2_start(&h2_request(3, CANARY))),
            ssl_event(Direction::Ingress, &h2_reply(3)),
        ]);
        let dump = format!("{out:?}");
        assert!(!dump.contains("s7Kf"), "{dump}");
    }

    // ── A server that speaks first (lab run_protocols, kernel 5.15) ──────

    /// The gRPC server's first write as captured on spike-jammy: SETTINGS
    /// (4 settings, among them grpc's 0xfe03) and a WINDOW_UPDATE.
    const GRPC_SERVER_PREFACE: &str = "000018040000000000000400400000000500400000000600004000\
        fe0300000001000004080000000000003f0001";
    /// The client's: the preface magic, SETTINGS (6) and a WINDOW_UPDATE.
    const GRPC_CLIENT_PREFACE: &str = "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a\
        00002404000000000000020000000000030000000000040040000000050040000000060000\
        4000fe0300000001000004080000000000003f0001";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// One unary call on stream 1, no PII: request HEADERS + DATA, reply
    /// HEADERS, DATA and trailers. (client bytes, server bytes)
    fn grpc_call() -> (Vec<u8>, Vec<u8>) {
        let mut enc = hpack::Encoder::new();
        let req = enc.encode(vec![
            (&b":method"[..], &b"POST"[..]),
            (b":scheme", b"http"),
            (b":path", b"/oracle.Svc/Echo"),
            (b":authority", b"10.99.0.1:9443"),
            (b"content-type", b"application/grpc"),
            (b"te", b"trailers"),
        ]);
        let mut c = h2_frame(0x1, 0x4, 1, &req);
        c.extend(h2_frame(0x0, 0x1, 1, b"\x00\x00\x00\x00\x05hello"));
        let mut enc = hpack::Encoder::new();
        let head = enc.encode(vec![
            (&b":status"[..], &b"200"[..]),
            (b"content-type", b"application/grpc"),
        ]);
        let trailers = enc.encode(vec![(&b"grpc-status"[..], &b"0"[..])]);
        let mut s = h2_frame(0x1, 0x4, 1, &head);
        s.extend(h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x02ok"));
        s.extend(h2_frame(0x1, 0x4 | 0x1, 1, &trailers));
        (c, s)
    }

    const GRPC_CLI: (u32, u16) = (0x0A63_0002, 55840);
    const GRPC_SRV: (u32, u16) = (0x0A63_0001, 9443);
    /// Socket cookies of the client's and the server's socket.
    const CLI_SOCK: u64 = 421241;
    const SRV_SOCK: u64 = 421242;

    /// A cgroup_skb record of `payload` at stream offset `off`, sent by the
    /// client or the server, seen on the client's socket or the server's
    /// (each with its kernel role and direction).
    fn grpc_rec(sock: u64, from_client: bool, off: u64, payload: &[u8]) -> DataEvent {
        use panopticon_common::scope::{ROLE_CLIENT, ROLE_SERVER};
        // Each side's first sequence number in the capture; acks lag by
        // the (few) bytes in flight, well inside the window.
        let (cli_isn, srv_isn) = (2_621_514_307u32, 2_138_406_149u32);
        let (from, isn, ack) = if from_client {
            (GRPC_CLI, cli_isn, srv_isn)
        } else {
            (GRPC_SRV, srv_isn, cli_isn)
        };
        let mut e = tcp_pkt(CLI, isn.wrapping_add(off as u32), ack, 0x08, payload);
        let to = if from_client { GRPC_SRV } else { GRPC_CLI };
        (e.src_addr, e.src_port, e.dst_addr, e.dst_port) = (from.0, from.1, to.0, to.1);
        e.socket_cookie = sock;
        e.role = if sock == CLI_SOCK {
            ROLE_CLIENT
        } else {
            ROLE_SERVER
        };
        e.direction = if (sock == CLI_SOCK) == from_client {
            Direction::Egress
        } else {
            Direction::Ingress
        };
        (e.cgroup_id, e.stream_off) = (23316, off);
        e
    }

    /// The connection on both sockets, in the order the jammy capture
    /// delivered it: the server's SETTINGS (offset 0, on both sockets)
    /// before the client's preface, then both SETTINGS ACKs and one call.
    fn server_first_connection() -> Vec<DataEvent> {
        let (sp, cp) = (unhex(GRPC_SERVER_PREFACE), unhex(GRPC_CLIENT_PREFACE));
        let ack = h2_frame(0x4, 0x1, 0, &[]);
        let (call, reply) = grpc_call();
        let (s1, c1) = (sp.len() as u64, cp.len() as u64);
        let (s2, c2) = (s1 + ack.len() as u64, c1 + ack.len() as u64);
        let mut evs = vec![];
        for sock in [SRV_SOCK, CLI_SOCK] {
            evs.push(grpc_rec(sock, false, 0, &sp));
        }
        for sock in [SRV_SOCK, CLI_SOCK] {
            evs.push(grpc_rec(sock, true, 0, &cp));
        }
        for sock in [CLI_SOCK, SRV_SOCK] {
            evs.push(grpc_rec(sock, false, s1, &ack));
            evs.push(grpc_rec(sock, true, c1, &ack));
            evs.push(grpc_rec(sock, true, c2, &call));
            evs.push(grpc_rec(sock, false, s2, &reply));
        }
        evs
    }

    /// (socket, protocol, path) of every message, feeding as worker_task.
    fn run_sockets(events: &[DataEvent]) -> Vec<(u64, Protocol, Option<String>)> {
        let (m, stats) = (ConnectionFsmManager::new(16), EventStats::new());
        let mut out = vec![];
        for e in events {
            for r in feed_event(&m, e, connection_key(e), &stats, 0, false, None)
                .into_iter()
                .flatten()
            {
                let ms = match r {
                    FsmResult::Messages(ms) => ms,
                    FsmResult::MessageComplete(m) => vec![m],
                    _ => vec![],
                };
                out.extend(
                    ms.into_iter()
                        .map(|m| (e.socket_cookie, m.protocol, m.path)),
                );
            }
        }
        out
    }

    /// grpc-go and grpc C-core servers write SETTINGS on accept, so the
    /// server's preface can reach the agent before the client's (RFC 9113
    /// §3.4 allows either order). Seen from both stream starts, both
    /// sockets' views are gRPC with the path. Before: the SETTINGS was not
    /// detected and was dropped, the client preface created the parser,
    /// the server side was then unplaced at offset 46 and the connection
    /// latched (all 1,000 records `http2`, no path, on 5.15).
    #[test]
    fn server_settings_before_client_preface_is_parsed_on_both_sockets() {
        let out = run_sockets(&server_first_connection());
        let path = Some("/oracle.Svc/Echo".to_string());
        for sock in [CLI_SOCK, SRV_SOCK] {
            assert_eq!(
                out.iter().filter(|(s, ..)| *s == sock).collect::<Vec<_>>(),
                vec![&(sock, Protocol::Grpc, path.clone())],
                "socket {sock}: {out:?}"
            );
        }
        // The client's preface first (the order on the other kernels).
        let mut evs = server_first_connection();
        evs.swap(0, 2);
        evs.swap(1, 3);
        let out = run_sockets(&evs);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(
            out.iter().all(|m| m.1 == Protocol::Grpc && m.2 == path),
            "{out:?}"
        );
    }

    /// What a server-first start does not prove: each case keeps the
    /// connection latched (no header decoded, so no path).
    #[test]
    fn server_first_start_still_latches_what_it_does_not_prove() {
        let unproven = |evs: &[DataEvent], case: &str| {
            let out = run_sockets(evs);
            assert!(out.iter().all(|m| m.2.is_none()), "{case}: {out:?}");
        };
        let full = server_first_connection();
        // The server's SETTINGS never captured: its side is first seen at
        // offset 46.
        let lost: Vec<_> = full.iter().skip(2).copied().collect();
        unproven(&lost, "server preface lost");
        // No stream offset on the SETTINGS record: not a proven start, so
        // it creates no parser, and the side is unplaced as before.
        let mut unknown = full.clone();
        for e in &mut unknown[..2] {
            e.stream_off = STREAM_OFF_UNKNOWN;
        }
        unproven(&unknown, "server preface without an offset");
        // The client's first bytes are not the preface (its preface lost):
        // the SETTINGS shape alone proves nothing about the client side.
        let no_preface: Vec<_> = full
            .iter()
            .enumerate()
            .filter(|(i, _)| ![2, 3].contains(i))
            .map(|(_, e)| *e)
            .collect();
        unproven(&no_preface, "client preface lost");
        // A second preface later in the client's stream (it may be the
        // inside of a DATA payload) after a server-first start does not
        // restart it clean: the call after it decodes no header.
        let mut again: Vec<_> = full
            .iter()
            .filter(|e| e.socket_cookie == SRV_SOCK)
            .copied()
            .collect();
        let next = |from_client: bool| {
            again
                .iter()
                .filter(|e| (e.src_port == GRPC_CLI.1) == from_client)
                .map(|e| e.stream_off + e.payload_len as u64)
                .max()
                .unwrap()
        };
        let (c, s) = (next(true), next(false));
        let cp = unhex(GRPC_CLIENT_PREFACE);
        let (call, reply) = grpc_call();
        again.push(grpc_rec(SRV_SOCK, true, c, &cp));
        again.push(grpc_rec(SRV_SOCK, true, c + cp.len() as u64, &call));
        again.push(grpc_rec(SRV_SOCK, false, s, &reply));
        let out = run_sockets(&again);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(out[0].2.is_some() && out[1].2.is_none(), "{out:?}");
    }

    /// Where content does not say, the kernel's socket role decides which
    /// end is the server before ports do: a server socket on the higher
    /// port.
    #[test]
    fn kernel_role_names_the_server_endpoint() {
        use panopticon_common::scope::{ROLE_CLIENT, ROLE_SERVER, ROLE_UNKNOWN};
        let mut e = tcp_pkt(SRV, 1, 0, 0, b"\x01\x02");
        (e.src_port, e.dst_port) = (50000, 40000);
        e.direction = Direction::Egress;
        let p = Protocol::Http2;
        e.role = ROLE_SERVER;
        assert_eq!(
            server_endpoint(&e, p, b"\x01\x02"),
            Some((e.src_addr, 50000))
        );
        e.role = ROLE_CLIENT;
        assert_eq!(
            server_endpoint(&e, p, b"\x01\x02"),
            Some((e.dst_addr, 40000))
        );
        e.direction = Direction::Ingress;
        assert_eq!(
            server_endpoint(&e, p, b"\x01\x02"),
            Some((e.src_addr, 50000))
        );
        // Unknown role: the lower port, as before.
        e.role = ROLE_UNKNOWN;
        assert_eq!(
            server_endpoint(&e, p, b"\x01\x02"),
            Some((e.dst_addr, 40000))
        );
    }

    /// A SETTINGS-shaped record at a stream's start does not outrank the
    /// kernel's socket role: a client that opens with one is still the
    /// client (review LOW-1). Before, the server-preface shape was tested
    /// first and pinned the client as the server.
    #[test]
    fn kernel_role_outranks_a_server_preface_shape() {
        let sp = unhex(GRPC_SERVER_PREFACE);
        // Seen on the server's socket (role server, ingress) and on the
        // client's (role client, egress): the server is GRPC_SRV either way.
        for sock in [SRV_SOCK, CLI_SOCK] {
            let e = grpc_rec(sock, true, 0, &sp);
            assert!(proven_stream_start(&e));
            assert_eq!(detect_event(&e, &sp), Some(Protocol::Http2));
            assert_eq!(
                server_endpoint(&e, Protocol::Http2, &sp),
                Some(GRPC_SRV),
                "socket {sock}"
            );
        }
        // A legitimate server's SETTINGS names it on both sockets, as before.
        for sock in [SRV_SOCK, CLI_SOCK] {
            let e = grpc_rec(sock, false, 0, &sp);
            assert_eq!(server_endpoint(&e, Protocol::Http2, &sp), Some(GRPC_SRV));
        }
        // No role stamped: the SETTINGS shape still decides.
        let mut e = grpc_rec(SRV_SOCK, true, 0, &sp);
        e.role = panopticon_common::scope::ROLE_UNKNOWN;
        assert_eq!(server_endpoint(&e, Protocol::Http2, &sp), Some(GRPC_CLI));
    }

    /// On a socket whose kernel role names the server, the peer's bytes
    /// do not re-decide it (review LOW-3): a server whose first bytes are
    /// a client preface is not taken for the client. Before, the parser
    /// swapped its sides, so the client's HEADERS were read as the
    /// server's and closed the stream at once (a message on the request).
    /// Now the preface stays the server's bytes (latched; read as frames
    /// it never completes one), and the client's request closes nothing.
    #[test]
    fn a_preface_from_the_server_does_not_swap_a_kernel_role() {
        let sp = unhex(GRPC_SERVER_PREFACE);
        let cp = unhex(GRPC_CLIENT_PREFACE);
        let static_req = h2_frame(0x1, 0x4 | 0x1, 1, &[0x83, 0x86, 0x84]);
        let static_resp = h2_frame(0x1, 0x4 | 0x1, 1, &[0x88]);
        for sock in [SRV_SOCK, CLI_SOCK] {
            let evs = [
                // The client opens with a SETTINGS shape (no preface).
                grpc_rec(sock, true, 0, &sp),
                // The server's first bytes are a client preface.
                grpc_rec(sock, false, 0, &cp),
                grpc_rec(sock, true, sp.len() as u64, &static_req),
                grpc_rec(sock, false, cp.len() as u64, &static_resp),
            ];
            let (m, stats) = (ConnectionFsmManager::new(16), EventStats::new());
            let mut done = vec![];
            for (i, e) in evs.iter().enumerate() {
                for r in feed_event(&m, e, connection_key(e), &stats, 0, false, None)
                    .into_iter()
                    .flatten()
                {
                    let n = match r {
                        FsmResult::Messages(ms) => ms.len(),
                        FsmResult::MessageComplete(_) => 1,
                        _ => 0,
                    };
                    done.extend(std::iter::repeat_n(i, n));
                }
            }
            assert!(done.is_empty(), "socket {sock}: completed at {done:?}");
            assert_eq!(
                m.connection_state(connection_key(&evs[0])),
                Some("streaming")
            );
        }
    }

    /// Feed events the way worker_task does; (method, reply text) of every
    /// message completed.
    fn run_redis(events: &[DataEvent]) -> Vec<(Option<String>, Option<String>)> {
        let (m, stats) = (ConnectionFsmManager::new(16), EventStats::new());
        let mut out = vec![];
        for e in events {
            for r in feed_event(&m, e, connection_key(e), &stats, 0, false, None)
                .into_iter()
                .flatten()
            {
                match r {
                    FsmResult::Messages(ms) => {
                        out.extend(ms.into_iter().map(|m| (m.method, m.payload_text)))
                    }
                    FsmResult::MessageComplete(m) => out.push((m.method, m.payload_text)),
                    _ => {}
                }
            }
        }
        out
    }

    /// Redis replies line up with commands only when the parser saw each
    /// direction from its first byte: proved by the SYN (TC recordings) or
    /// by the kernel's stream offset. A connection joined mid-pipeline,
    /// or with bytes lost later, exports no reply text: the reply to an
    /// `ACL GENPASS` sent before capture started is not exported under the
    /// first command captured.
    #[test]
    fn redis_replies_need_a_stream_seen_from_its_start() {
        use panopticon_common::TCP_FLAG_SYN;
        let get = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n";
        let glen = get.len() as u32;
        let genpass = b"$14\r\ncanary-genpass\r\n$1\r\nv\r\n";
        let leaked = |out: &[(Option<String>, Option<String>)]| {
            out.iter()
                .any(|(_, t)| t.as_deref().is_some_and(|t| t.contains("canary")))
        };
        let syn = |e: DataEvent| {
            let mut e = e;
            e.tcp_flags &= !panopticon_common::TCP_FLAG_ACK;
            e
        };

        // Joined mid-pipeline (no SYN): GENPASS's reply arrives first.
        let out = run_redis(&[
            redis_pkt(true, 1000, 5000, 0, get),
            redis_pkt(false, 5000, 1000 + glen, 0, genpass),
        ]);
        assert!(
            !out.is_empty(),
            "replies are still exported, as bare events"
        );
        assert!(!leaked(&out), "{out:?}");
        assert!(out.iter().all(|(_, t)| t.is_none()), "{out:?}");

        // Seen from the handshake: reply text is exported.
        let handshake = [
            syn(redis_pkt(true, 999, 0, TCP_FLAG_SYN, b"")),
            redis_pkt(false, 4999, 1000, TCP_FLAG_SYN, b""),
        ];
        let mut evs = handshake.to_vec();
        evs.push(redis_pkt(true, 1000, 5000, 0, get));
        evs.push(redis_pkt(false, 5000, 1000 + glen, 0, b"$1\r\nv\r\n"));
        let out = run_redis(&evs);
        assert_eq!(
            out,
            vec![(Some("GET".into()), Some("(bulk, 1 bytes)".into()))]
        );

        // Handshake seen, then client bytes lost (the GENPASS command).
        let mut evs = handshake.to_vec();
        evs.push(redis_pkt(true, 1000, 5000, 0, get));
        evs.push(redis_pkt(false, 5000, 1000 + glen, 0, b"$1\r\nv\r\n"));
        evs.push(redis_pkt(true, 1000 + glen + 40, 5007, 0, get));
        evs.push(redis_pkt(false, 5007, 1040 + 2 * glen, 0, genpass));
        let out = run_redis(&evs);
        assert!(!leaked(&out), "{out:?}");

        // Only the client's SYN seen: the server's stream start is unproven.
        let mut evs = vec![handshake[0]];
        evs.push(redis_pkt(true, 1000, 5000, 0, get));
        evs.push(redis_pkt(false, 5000, 1000 + glen, 0, genpass));
        assert!(!leaked(&run_redis(&evs)));

        // cgroup_skb: the kernel's stream offset proves each side's start.
        let with_off = |mut e: DataEvent, off: u64| {
            e.cgroup_id = 7;
            e.stream_off = off;
            e
        };
        let out = run_redis(&[
            with_off(redis_pkt(true, 1000, 5000, 0, get), 0),
            with_off(redis_pkt(false, 5000, 1000 + glen, 0, b"$1\r\nv\r\n"), 0),
        ]);
        assert_eq!(
            out,
            vec![(Some("GET".into()), Some("(bulk, 1 bytes)".into()))]
        );
        let out = run_redis(&[
            with_off(redis_pkt(true, 1040, 5000, 0, get), 40),
            with_off(redis_pkt(false, 5000, 1040 + glen, 0, genpass), 0),
        ]);
        assert!(!leaked(&out), "{out:?}");
        // Joined far into the stream (beyond the TCP window): still parsed,
        // replies exported without text or command.
        let out = run_redis(&[
            with_off(redis_pkt(true, 1000, 5000, 0, get), 9 << 20),
            with_off(redis_pkt(false, 5000, 1000 + glen, 0, genpass), 9 << 20),
        ]);
        assert_eq!(out.first(), Some(&(None, None)), "{out:?}");
        assert!(!leaked(&out), "{out:?}");
        let out = run_redis(&[
            with_off(redis_pkt(true, 1000, 5000, 0, get), STREAM_OFF_UNKNOWN),
            with_off(redis_pkt(false, 5000, 1000 + glen, 0, genpass), 0),
        ]);
        assert!(!leaked(&out), "{out:?}");
    }

    /// A large server write (a GSO super-packet, one skb) as cgroup_skb
    /// sends it (sock_capture.rs `emit`): consecutive MAX_PAYLOAD_SIZE
    /// chunk records with `tcp_seq` and `stream_off` advanced by each
    /// chunk's offset, `orig_len` the chunk's bytes, FIN on the last only.
    /// The parser sees the whole reply and the next one stays in sync. Cut
    /// to one 4 KiB record instead (before chunking), the tail was skipped
    /// mid-reply and the following reply lost its text.
    #[test]
    fn chunked_super_packet_keeps_the_stream_in_sync() {
        let get = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n";
        let glen = get.len() as u32;
        let mut big = format!("${}\r\n", 9000).into_bytes();
        big.extend(std::iter::repeat_n(b'x', 9000));
        big.extend(b"\r\n");
        let blen = big.len() as u32;
        let small = b"$1\r\nw\r\n";
        let at = |mut e: DataEvent, off: u64| {
            e.cgroup_id = 7;
            e.stream_off = off;
            e
        };
        // The kernel's chunking of `data` at stream offset `off`.
        let chunks = |seq: u32, ack: u32, off: u64, data: &[u8]| -> Vec<DataEvent> {
            data.chunks(MAX_PAYLOAD_SIZE)
                .enumerate()
                .map(|(i, c)| {
                    let o = (i * MAX_PAYLOAD_SIZE) as u32;
                    at(redis_pkt(false, seq + o, ack, 0, c), off + o as u64)
                })
                .collect()
        };
        let head = |reply: Vec<DataEvent>| {
            let mut evs = vec![at(redis_pkt(true, 1000, 5000, 0, get), 0)];
            evs.extend(reply);
            evs.push(at(
                redis_pkt(true, 1000 + glen, 5000 + blen, 0, get),
                glen as u64,
            ));
            evs.push(at(
                redis_pkt(false, 5000 + blen, 1000 + 2 * glen, 0, small),
                blen as u64,
            ));
            evs
        };

        let evs = head(chunks(5000, 1000 + glen, 0, &big));
        assert_eq!(evs.len(), 2 + 3 + 1, "9 KiB reply: three chunk records");
        let out = run_redis(&evs);
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[1], (Some("GET".into()), Some("(bulk, 1 bytes)".into())));

        // One record cut at the capture window: the next reply has no text.
        let mut cut = at(
            redis_pkt(false, 5000, 1000 + glen, 0, &big[..MAX_PAYLOAD_SIZE]),
            0,
        );
        cut.orig_len = blen;
        let out = run_redis(&head(vec![cut]));
        assert!(
            out.iter()
                .all(|(_, t)| t.as_deref() != Some("(bulk, 1 bytes)")),
            "{out:?}"
        );
    }

    type Exported = Vec<(Option<String>, Option<String>)>;

    fn collect(out: &mut Exported, results: Option<Vec<FsmResult>>) {
        for r in results.into_iter().flatten() {
            match r {
                FsmResult::Messages(ms) => {
                    out.extend(ms.into_iter().map(|m| (m.method, m.payload_text)))
                }
                FsmResult::MessageComplete(m) => out.push((m.method, m.payload_text)),
                _ => {}
            }
        }
    }

    /// `events` through the worker's reorder window (`reorder.rs`), all
    /// arriving at once; then every hole still open expires.
    fn run_reordered(events: &[DataEvent], stats: &EventStats) -> Exported {
        use crate::reorder::{HOLD_TIME, ReorderWindow};
        let m = ConnectionFsmManager::new(16);
        let mut w = ReorderWindow::default();
        let mut out = vec![];
        let t0 = Instant::now();
        let mut sink = |e: &DataEvent| {
            collect(
                &mut out,
                feed_event(&m, e, connection_key(e), stats, 0, false, None),
            )
        };
        for e in events {
            w.offer(&m, connection_key(e), e, t0, stats, &mut sink);
        }
        w.expire(&m, t0 + HOLD_TIME, stats, &mut |_, e: &DataEvent| sink(e));
        assert!(w.is_empty());
        out
    }

    fn at_off(mut e: DataEvent, off: u64) -> DataEvent {
        e.cgroup_id = 7;
        e.stream_off = off;
        e
    }

    /// The kernel's chunk records (sock_capture.rs `emit`) of one server
    /// packet carrying `data` at stream offset `off`.
    fn server_chunks(seq: u32, ack: u32, off: u64, data: &[u8]) -> Vec<DataEvent> {
        data.chunks(MAX_PAYLOAD_SIZE)
            .enumerate()
            .map(|(i, c)| {
                let o = (i * MAX_PAYLOAD_SIZE) as u32;
                at_off(redis_pkt(false, seq + o, ack, 0, c), off + o as u64)
            })
            .collect()
    }

    const GET: &[u8] = b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n";

    /// GET, a 20 KB reply sent as two 10 KB packets whose chunk records
    /// arrive in `order` (indices into A0 A1 A2 B0 B1 B2), GET, "w".
    fn two_packet_reply(order: &[usize]) -> Vec<DataEvent> {
        let glen = GET.len() as u32;
        let mut big = b"$20000\r\n".to_vec();
        big.extend(std::iter::repeat_n(b'x', 20000));
        big.extend(b"\r\n");
        let blen = big.len() as u32;
        let (a, b) = big.split_at(10_000);
        let mut chunks = server_chunks(5000, 1000 + glen, 0, a);
        chunks.extend(server_chunks(15_000, 1000 + glen, 10_000, b));
        let mut evs = vec![at_off(redis_pkt(true, 1000, 5000, 0, GET), 0)];
        evs.extend(order.iter().map(|&i| chunks[i]));
        evs.push(at_off(
            redis_pkt(true, 1000 + glen, 5000 + blen, 0, GET),
            glen as u64,
        ));
        evs.push(at_off(
            redis_pkt(false, 5000 + blen, 1000 + 2 * glen, 0, b"$1\r\nw\r\n"),
            blen as u64,
        ));
        evs
    }

    /// Two CPUs ran the capture of one socket at once (cgroup_skb ingress
    /// runs before the socket lock): the chunk records of two packets
    /// arrive interleaved. The reorder window puts them back in stream
    /// order; taken as they arrive, the second packet's first chunk opened
    /// a gap, the first packet's later chunks were dropped as behind, and
    /// the next reply lost its text.
    #[test]
    fn interleaved_chunks_of_two_packets_are_reordered() {
        let interleaved = two_packet_reply(&[0, 3, 1, 4, 2, 5]);
        let stats = EventStats::new();
        let out = run_reordered(&interleaved, &stats);
        assert_eq!(out.len(), 2, "{out:?}");
        assert_eq!(out[1], (Some("GET".into()), Some("(bulk, 1 bytes)".into())));
        assert!(stats.tcp_reorder_held.load(Ordering::Relaxed) > 0);
        assert_eq!(stats.tcp_reorder_gaps.load(Ordering::Relaxed), 0);
        // In order, the window holds nothing and the result is the same.
        let stats = EventStats::new();
        let in_order = run_reordered(&two_packet_reply(&[0, 1, 2, 3, 4, 5]), &stats);
        assert_eq!(in_order, out);
        assert_eq!(stats.tcp_reorder_held.load(Ordering::Relaxed), 0);
        // Without the window, the interleave cost the next reply's text.
        let raw = run_redis(&interleaved);
        assert!(
            raw.iter()
                .all(|(_, t)| t.as_deref() != Some("(bulk, 1 bytes)")),
            "{raw:?}"
        );
    }

    /// A real loss (a ring drop): the hole never fills. Held records,
    /// the other direction's included, go on in arrival order once it
    /// expires, the hole a gap: the parsers see what they saw before the
    /// window existed.
    #[test]
    fn reorder_hole_that_never_fills_expires_as_a_gap() {
        // B0 B1 B2 without A: the first 10 KB of the reply were lost.
        let lost = two_packet_reply(&[3, 4, 5]);
        let stats = EventStats::new();
        let out = run_reordered(&lost, &stats);
        assert_eq!(out, run_redis(&lost));
        assert!(
            out.iter()
                .all(|(_, t)| t.as_deref() != Some("(bulk, 1 bytes)")),
            "{out:?}"
        );
        assert_eq!(stats.tcp_reorder_gaps.load(Ordering::Relaxed), 1);
    }

    /// Past the per-connection byte bound, what is held goes on at once,
    /// in arrival order, its hole a gap.
    #[test]
    fn reorder_window_full_releases_with_a_gap() {
        use crate::reorder::{HOLD_BYTES_PER_CONN, ReorderWindow};
        let m = ConnectionFsmManager::new(16);
        let stats = EventStats::new();
        let mut w = ReorderWindow::default();
        let mut n = 0;
        let mut sink = |e: &DataEvent| {
            n += 1;
            feed_event(&m, e, connection_key(e), &stats, 0, false, None);
        };
        let t0 = Instant::now();
        let get = at_off(redis_pkt(true, 1000, 5000, 0, GET), 0);
        let glen = GET.len() as u32;
        w.offer(&m, connection_key(&get), &get, t0, &stats, &mut sink);
        let reply = at_off(redis_pkt(false, 5000, 1000 + glen, 0, b"$1\r\nv\r\n"), 0);
        w.offer(&m, connection_key(&reply), &reply, t0, &stats, &mut sink);
        // A packet 1 KB past the next byte, most of its bytes uncaptured.
        let mut ahead = at_off(redis_pkt(false, 5007 + 1024, 1000 + glen, 0, b"x"), 1031);
        ahead.orig_len = (HOLD_BYTES_PER_CONN - 100) as u32;
        w.offer(&m, connection_key(&ahead), &ahead, t0, &stats, &mut sink);
        assert!(!w.is_empty());
        let mut more = ahead;
        more.tcp_seq += ahead.orig_len;
        more.stream_off += ahead.orig_len as u64;
        more.orig_len = 200;
        w.offer(&m, connection_key(&more), &more, t0, &stats, &mut sink);
        assert!(w.is_empty());
        assert_eq!(n, 4);
        assert_eq!(stats.tcp_reorder_gaps.load(Ordering::Relaxed), 1);
    }

    /// TLS records carry no TCP sequence, so the window never holds one:
    /// each goes straight to its parser, even
    /// while a TCP hole is held, and none is ever dropped there.
    #[test]
    fn reorder_window_never_holds_a_tls_record() {
        use crate::reorder::ReorderWindow;
        let m = ConnectionFsmManager::new(16);
        let stats = EventStats::new();
        let mut w = ReorderWindow::default();
        let mut seen = vec![];
        let mut sink = |e: &DataEvent| {
            seen.push(e.event_type);
            feed_event(&m, e, connection_key(e), &stats, 0, false, None);
        };
        let t0 = Instant::now();
        let get = at_off(redis_pkt(true, 1000, 5000, 0, GET), 0);
        let glen = GET.len() as u32;
        w.offer(&m, connection_key(&get), &get, t0, &stats, &mut sink);
        let ahead = at_off(redis_pkt(false, 5000 + 1024, 1000 + glen, 0, b"x"), 1024);
        w.offer(&m, connection_key(&ahead), &ahead, t0, &stats, &mut sink);
        assert!(!w.is_empty(), "the TCP hole is held");
        for dir in [Direction::Egress, Direction::Ingress] {
            let tls = ssl_event(dir, b"x");
            w.offer(&m, connection_key(&tls), &tls, t0, &stats, &mut sink);
        }
        assert_eq!(
            seen,
            vec![EventType::TcPacket, EventType::TlsData, EventType::TlsData]
        );
    }

    /// A quiet connection: its hole expires on time, with no later record
    /// to trigger it.
    #[test]
    fn reorder_hole_expires_on_a_quiet_connection() {
        use crate::reorder::{HOLD_TIME, ReorderWindow};
        let m = ConnectionFsmManager::new(16);
        let stats = EventStats::new();
        let mut w = ReorderWindow::default();
        let mut n = 0;
        let mut sink = |e: &DataEvent| {
            n += 1;
            feed_event(&m, e, connection_key(e), &stats, 0, false, None);
        };
        let t0 = Instant::now();
        let get = at_off(redis_pkt(true, 1000, 5000, 0, GET), 0);
        w.offer(&m, connection_key(&get), &get, t0, &stats, &mut sink);
        let ahead = at_off(redis_pkt(true, 1000 + 500, 5000, 0, GET), 500);
        w.offer(&m, connection_key(&ahead), &ahead, t0, &stats, &mut sink);
        assert_eq!(w.deadline(), Some(t0 + HOLD_TIME));
        w.expire(&m, t0 + HOLD_TIME / 2, &stats, &mut |_, e: &DataEvent| {
            sink(e)
        });
        assert!(!w.is_empty());
        w.expire(&m, t0 + HOLD_TIME, &stats, &mut |_, e: &DataEvent| sink(e));
        assert!(w.is_empty());
        assert_eq!(n, 2);
        assert_eq!(stats.tcp_reorder_gaps.load(Ordering::Relaxed), 1);
    }

    /// A packet carrying RST is one record (sock_capture.rs `emit`), at the
    /// packet's own sequence number, however large. One at a wrong sequence
    /// number is ignored, payload and RST: the connection goes on. Split
    /// into chunks, its last chunk carried the RST at an advanced sequence
    /// number that passed the next-byte check.
    #[test]
    fn large_rst_at_a_wrong_sequence_number_is_ignored() {
        let glen = GET.len() as u32;
        let mut rst = at_off(
            redis_pkt(
                false,
                5000 + 4096,
                1000 + glen,
                TCP_FLAG_RST,
                &[b'x'; MAX_PAYLOAD_SIZE],
            ),
            4096,
        );
        rst.orig_len = 8192;
        let reply = at_off(redis_pkt(false, 5000, 1000 + glen, 0, b"$1\r\nv\r\n"), 0);
        let m = ConnectionFsmManager::new(16);
        let stats = EventStats::new();
        let get = at_off(redis_pkt(true, 1000, 5000, 0, GET), 0);
        let mut out = vec![];
        collect(
            &mut out,
            feed_event(&m, &get, connection_key(&get), &stats, 0, false, None),
        );
        assert!(feed_event(&m, &rst, connection_key(&rst), &stats, 0, false, None).is_none());
        collect(
            &mut out,
            feed_event(&m, &reply, connection_key(&reply), &stats, 0, false, None),
        );
        assert_eq!(
            out,
            vec![(Some("GET".into()), Some("(bulk, 1 bytes)".into()))]
        );
    }

    /// TLS plaintext carries no stream position: Redis replies over TLS
    /// are exported without text.
    #[test]
    fn redis_over_tls_exports_no_reply_text() {
        let m = ConnectionFsmManager::new(16);
        let stats = EventStats::new();
        let mut out = vec![];
        for (dir, data) in [
            (Direction::Egress, &b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n"[..]),
            (Direction::Ingress, b"$14\r\ncanary-genpass\r\n"),
        ] {
            let mut e: DataEvent = unsafe { std::mem::zeroed() };
            e.event_type = EventType::TlsData;
            e.direction = dir;
            e.socket_cookie = 0x7000;
            e.stream_off = STREAM_OFF_UNKNOWN;
            e.payload[..data.len()].copy_from_slice(data);
            (e.payload_len, e.orig_len) = (data.len() as u32, data.len() as u32);
            for r in feed_event(&m, &e, connection_key(&e), &stats, 0, false, None)
                .into_iter()
                .flatten()
            {
                match r {
                    FsmResult::Messages(ms) => out.extend(ms.into_iter().map(|m| m.payload_text)),
                    FsmResult::MessageComplete(m) => out.push(m.payload_text),
                    _ => {}
                }
            }
        }
        assert_eq!(out, vec![None]);
    }

    /// The client's SYN (seq 99) and the server's SYN+ACK (seq 899): they
    /// place each side's first byte, so the connection was seen from its
    /// start (without them every side is unplaced: a late join).
    fn handshake() -> [DataEvent; 2] {
        let mut syn = tcp_pkt(CLI, 99, 0, 0, b"");
        syn.tcp_flags = panopticon_common::TCP_FLAG_SYN;
        [
            syn,
            tcp_pkt(SRV, 899, 100, panopticon_common::TCP_FLAG_SYN, b""),
        ]
    }

    #[test]
    fn retransmitted_segments_are_parsed_once() {
        let req = b"GET /orders/7 HTTP/1.1\r\nHost: shop\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (a, b) = req.split_at(20);
        let [syn, syn_ack] = handshake();
        let (paths, ignored) = run_tcp(&[
            syn,
            syn_ack,
            tcp_pkt(CLI, 100, 900, 0, a),
            tcp_pkt(CLI, 100, 900, 0, a),          // retransmission
            tcp_pkt(CLI, 110, 900, 0, &req[10..]), // overlaps the first 10 bytes
            tcp_pkt(CLI, 100 + 20, 900, 0, b),     // and again, whole
            tcp_pkt(SRV, 900, 100 + req.len() as u32, 0, resp),
            tcp_pkt(SRV, 900, 100 + req.len() as u32, 0, resp), // duplicate
        ]);
        assert_eq!(paths, vec![Some("/orders/7".to_string())]);
        assert_eq!(
            ignored,
            vec![false, false, false, true, false, true, false, true]
        );
    }

    #[test]
    fn forged_out_of_window_request_and_rst_are_ignored() {
        let req = b"GET /real HTTP/1.1\r\nHost: shop\r\n\r\n";
        let fake = b"GET /forged HTTP/1.1\r\nHost: shop\r\n\r\n";
        let resp = b"HTTP/1.1 204 No Content\r\n\r\n";
        let next = 100 + req.len() as u32;
        let rst = panopticon_common::TCP_FLAG_RST;
        let [syn, syn_ack] = handshake();
        let (paths, ignored) = run_tcp(&[
            syn,
            syn_ack,
            tcp_pkt(CLI, 100, 900, 0, req),
            tcp_pkt(CLI, next + 50_000_000, 900, 0, fake), // guessed sequence
            tcp_pkt(SRV, 77_777, next, rst, b""),          // spoofed RST
            tcp_pkt(SRV, 900, next, 0, resp),
        ]);
        assert_eq!(paths, vec![Some("/real".to_string())]);
        assert_eq!(ignored, vec![false, false, false, true, true, false]);
        // The real RST, at the server's next sequence number, counts.
        let (_, ignored) = run_tcp(&[
            tcp_pkt(CLI, 100, 900, 0, req),
            tcp_pkt(SRV, 900, next, rst, b""),
        ]);
        assert_eq!(ignored, vec![false, false]);
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

    /// Codex: a header name past the field cap lost its `-token` suffix to
    /// the cut before the credential-header check saw it. Such a header is
    /// withheld whole.
    #[test]
    fn overlong_header_name_is_withheld_whole() {
        let name = format!("x-{}-token", "a".repeat(8500));
        let mut msg =
            crate::protocol::L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        msg.headers = vec![(name, "s7Kf2v9LmQ8z".into()), ("x-ok".into(), "v".into())];
        scan_with_body_cap(&mut msg, 4096, |m| {
            crate::pii::mask_credentials(m);
            None
        });
        assert!(
            msg.headers
                .iter()
                .all(|(n, v)| !v.contains("s7Kf") && n.len() < 100),
            "{:?}",
            msg.headers
                .iter()
                .map(|(n, v)| (n.len(), v))
                .collect::<Vec<_>>()
        );
        assert_eq!(msg.headers[1], ("x-ok".into(), "v".into()));
    }

    /// Path and header fields are bounded like bodies before the scan: a
    /// crafted 200 KiB header or path is neither scanned nor exported whole.
    #[test]
    fn field_cap_bounds_path_and_headers() {
        let engine = crate::pii::PiiEngine::new(&crate::config::PiiConfig::default(), &[]);
        let mut msg =
            crate::protocol::L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        let big = "1.1.1.1 ".repeat(200 * 1024 / 8);
        msg.path = Some(format!("/{big}"));
        msg.headers = vec![("x-pad".into(), big.clone()), (big.clone(), "v".into())];
        // Redaction off (full mode): the cap, not the redaction, bounds them.
        scan_with_body_cap(&mut msg, 4096, |m| engine.scan_message_with(m, false));
        // An overlong name is withheld whole with its value.
        assert_eq!(
            msg.headers[1],
            (
                crate::protocol::FIELD_WITHHELD.into(),
                crate::protocol::FIELD_WITHHELD.into()
            )
        );
        let fields = [msg.path.as_deref().unwrap(), &msg.headers[0].1];
        for f in fields {
            assert!(f.len() <= MAX_FIELD_BYTES, "{}", f.len());
            // Never cut inside a value.
            assert!(
                f.ends_with(' ') || f.ends_with("1.1.1.1"),
                "{}",
                &f[f.len() - 16..]
            );
        }
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
            // A wire header borrowing the old DNS-answer name gets no pass.
            ("dns_a_record".into(), "svc.local|167772161|30".into()),
        ];
        let answers = vec![crate::protocol::DnsAnswer {
            name: "svc.local".into(),
            ip: 167772161,
            ttl_secs: 30,
        }];
        msg.dns_answers = answers.clone();
        msg.status = Some(201);
        strip_payload_strings(&mut msg);
        assert!(msg.method.is_none() && msg.path.is_none() && msg.content_type.is_none());
        assert!(msg.payload_text.is_none() && msg.request_text.is_none());
        assert!(msg.headers.is_empty());
        assert_eq!(msg.dns_answers, answers);
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
            && let Some(proto) = detect_event(event, payload)
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
        // Generation 0 under the floor that never moves off 0.
        let floor = AdmissionFloor::default();
        assert_eq!(floor.get(), 0);
        assert!(!below_floor(&e, floor.get()));

        // Capture starts at generation 1; a narrowing to 3 drops 1 and 2.
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
            // Close records carry the generation they were authorised under.
            (EventType::SockClose, 2, true),
            (EventType::SockClose, 3, false),
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
