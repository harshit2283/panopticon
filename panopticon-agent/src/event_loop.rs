// EventStats and RateLimiter are cross-platform (used by metrics module on macOS),
// but their callers (EventLoop, consume_data_events, etc.) are Linux-only.
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use anyhow::{Context, Result, bail};
#[cfg(target_os = "linux")]
use aya::maps::perf::PerfEventArrayBuffer;
#[cfg(target_os = "linux")]
use aya::maps::{PerfEventArray, RingBuf};
#[cfg(target_os = "linux")]
use bytes::BytesMut;
#[cfg(target_os = "linux")]
use panopticon_common::{
    DataEvent, Direction, EventType, TCP_FLAG_FIN, TCP_FLAG_RST, parse_data_event_bytes,
};
#[cfg(target_os = "linux")]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
use crate::graph::{ConnectionTuple, GraphBuilder};
#[cfg(target_os = "linux")]
use crate::protocol::detect::detect_protocol;
#[cfg(target_os = "linux")]
use crate::protocol::fsm::{ConnectionFsmManager, FsmResult};
#[cfg(target_os = "linux")]
use crate::util::format_ipv4;
#[cfg(target_os = "linux")]
use crate::{
    config::AgentConfig, export::json::JsonExportHandle, export::otlp::OtlpExportHandle,
    loader::EventSource, pii::PiiEngine,
};

#[cfg(target_os = "linux")]
struct WorkerTaskContext {
    stats: Arc<EventStats>,
    idle_timeout: Duration,
    log_events: bool,
    max_connections_tracked: usize,
    pii_engine: Option<PiiEngine>,
    json_export: Option<JsonExportHandle>,
    otlp_export: Option<OtlpExportHandle>,
    audit_log: Option<Arc<std::sync::Mutex<crate::export::audit::PiiAuditLog>>>,
    graph_builder: Option<Arc<GraphBuilder>>,
    raw_capture: Option<crate::export::raw_capture::RawCaptureHandle>,
    max_body_bytes: usize,
}

#[cfg(target_os = "linux")]
struct MessageContext<'a> {
    worker_id: usize,
    log_events: bool,
    stats: &'a EventStats,
    pii_engine: &'a Option<PiiEngine>,
    json_export: &'a Option<JsonExportHandle>,
    otlp_export: &'a Option<OtlpExportHandle>,
    audit_log: &'a Option<Arc<std::sync::Mutex<crate::export::audit::PiiAuditLog>>>,
    graph_builder: &'a Option<Arc<GraphBuilder>>,
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
        }
    }
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

#[cfg(target_os = "linux")]
pub struct EventLoop {
    config: AgentConfig,
    stats: Arc<EventStats>,
    pii_engine: Option<PiiEngine>,
    json_export_handle: Option<JsonExportHandle>,
    otlp_export_handle: Option<OtlpExportHandle>,
    audit_log: Option<Arc<std::sync::Mutex<crate::export::audit::PiiAuditLog>>>,
    graph_builder: Option<Arc<GraphBuilder>>,
    raw_capture: Option<crate::export::raw_capture::RawCaptureHandle>,
}

#[cfg(target_os = "linux")]
impl EventLoop {
    pub fn new(
        config: AgentConfig,
        pii_engine: Option<PiiEngine>,
        json_export_handle: Option<JsonExportHandle>,
        otlp_export_handle: Option<OtlpExportHandle>,
        audit_log: Option<Arc<std::sync::Mutex<crate::export::audit::PiiAuditLog>>>,
        graph_builder: Option<GraphBuilder>,
    ) -> Self {
        Self {
            config,
            stats: Arc::new(EventStats::new()),
            pii_engine,
            json_export_handle,
            otlp_export_handle,
            audit_log,
            graph_builder: graph_builder.map(Arc::new),
            raw_capture: None,
        }
    }

    /// Record every processed event, unredacted, to a raw capture file.
    pub fn with_raw_capture(
        mut self,
        handle: crate::export::raw_capture::RawCaptureHandle,
    ) -> Self {
        self.raw_capture = Some(handle);
        self
    }

    /// Feed recorded events through one worker: exactly the path live events
    /// take after the ring buffer (parsing, PII, graph, export). For
    /// measuring user-space throughput without kernel or scheduling noise.
    pub async fn replay_through_worker(&self, events: Vec<DataEvent>) -> Result<()> {
        let (tx, rx) = mpsc::channel::<EventBatch>(4);
        let ctx = WorkerTaskContext {
            stats: Arc::clone(&self.stats),
            idle_timeout: self.config.idle_connection_timeout,
            log_events: self.config.log_events,
            max_connections_tracked: self.config.max_connections_tracked,
            pii_engine: self.pii_engine.clone(),
            json_export: self.json_export_handle.clone(),
            otlp_export: self.otlp_export_handle.clone(),
            audit_log: self.audit_log.clone(),
            graph_builder: self.graph_builder.clone(),
            raw_capture: None,
            max_body_bytes: self.config.max_body_bytes,
        };
        let worker = tokio::spawn(worker_task(0, rx, ctx));
        for chunk in events.chunks(WORKER_BATCH) {
            if tx.send(chunk.to_vec()).await.is_err() {
                break;
            }
        }
        drop(tx);
        worker.await?;
        Ok(())
    }

    pub fn stats(&self) -> &Arc<EventStats> {
        &self.stats
    }

    /// Main entry point: spawn workers, consume RingBufs, route events.
    ///
    /// `tls_rescan_tx` — if provided, ProcessExec events send the PID to this channel
    /// so the TLS scanner task can rescan the new process for TLS libraries.
    pub async fn run(
        self,
        event_source: EventSource,
        tls_rescan_tx: Option<mpsc::Sender<u32>>,
    ) -> Result<()> {
        let num_workers = self.config.max_worker_count;
        if num_workers == 0 {
            bail!("max_worker_count must be >= 1");
        }
        let channel_cap = self.config.worker_channel_capacity;
        if channel_cap == 0 {
            bail!("worker_channel_capacity must be >= 1");
        }
        let idle_timeout = self.config.idle_connection_timeout;
        let log_events = self.config.log_events;
        let max_connections_tracked = self.config.max_connections_tracked;

        // Create per-worker channels
        let mut senders = Vec::with_capacity(num_workers);
        let mut worker_handles = Vec::with_capacity(num_workers);

        // Capacity is configured in events; the channels carry batches.
        let batch_cap = channel_cap.div_ceil(WORKER_BATCH);
        for worker_id in 0..num_workers {
            let (tx, rx) = mpsc::channel::<EventBatch>(batch_cap);
            senders.push(tx);

            let stats = Arc::clone(&self.stats);
            let pii = self.pii_engine.clone();
            let exporter = self.json_export_handle.clone();
            let otlp_exporter = self.otlp_export_handle.clone();
            let audit_log = self.audit_log.clone();
            let graph = self.graph_builder.clone();
            let worker_ctx = WorkerTaskContext {
                stats,
                idle_timeout,
                log_events,
                max_connections_tracked,
                pii_engine: pii,
                json_export: exporter,
                otlp_export: otlp_exporter,
                audit_log,
                graph_builder: graph,
                raw_capture: self.raw_capture.clone(),
                max_body_bytes: self.config.max_body_bytes,
            };
            let handle = tokio::spawn(worker_task(worker_id, rx, worker_ctx));
            worker_handles.push(handle);
        }

        info!(
            workers = num_workers,
            channel_capacity = channel_cap,
            "Worker pool started"
        );

        // Rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(self.config.max_events_per_sec));

        // Rate limiter refill task (every 100ms for smooth rate limiting)
        let rl = Arc::clone(&rate_limiter);
        let pii_for_refill = self.pii_engine.clone();
        let refill_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            let mut tick_count = 0u64;
            loop {
                interval.tick().await;
                rl.refill();
                tick_count += 1;
                // PII sampler refill every 1 second (10 ticks)
                if tick_count.is_multiple_of(10)
                    && let Some(pii) = pii_for_refill.as_ref()
                {
                    pii.refill_sampler();
                }
            }
        });

        // Stats reporting task (every 10 seconds) — also flushes graph + prunes stale edges
        let stats_ref = Arc::clone(&self.stats);
        let graph_for_stats = self.graph_builder.clone();
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

                if let Some(gb) = graph_for_stats.as_ref() {
                    let flows = gb.flush();
                    // Edge timestamps come from bpf_ktime_get_ns (monotonic,
                    // since boot); wall-clock time here wiped the whole graph
                    // on every flush.
                    gb.prune(crate::util::monotonic_now_ns());
                    if let Ok(dag) = gb.dag().lock() {
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
                            graph_nodes = dag.node_count(),
                            graph_edges = dag.edge_count(),
                            flushed_flows = flows.len(),
                            "Event stats"
                        );
                    } else {
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
                } else {
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
            }
        });

        // Consume kernel events inline — this is the main blocking call.
        let data_result = consume_data_events(
            event_source,
            &senders,
            &rate_limiter,
            &self.stats,
            tls_rescan_tx,
        )
        .await;

        // Cleanup
        refill_handle.abort();
        stats_handle.abort();
        drop(senders); // Close channels → workers will drain and exit
        for handle in worker_handles {
            let _ = handle.await;
        }

        data_result
    }
}

/// Consume events from the kernel and route to workers.
/// Branches based on the EventSource (RingBuf for >= 5.8, PerfEventArray for older).
#[cfg(target_os = "linux")]
async fn consume_data_events(
    event_source: EventSource,
    senders: &[mpsc::Sender<EventBatch>],
    rate_limiter: &RateLimiter,
    stats: &EventStats,
    tls_rescan_tx: Option<mpsc::Sender<u32>>,
) -> Result<()> {
    match event_source {
        EventSource::RingBuf(ring_buf) => {
            consume_ringbuf(ring_buf, senders, rate_limiter, stats, tls_rescan_tx).await
        }
        EventSource::PerfEventArray(perf_array) => {
            consume_perf_array(perf_array, senders, rate_limiter, stats, tls_rescan_tx).await
        }
    }
}

/// Consume events from a RingBuf (kernel >= 5.8).
#[cfg(target_os = "linux")]
async fn consume_ringbuf(
    ring_buf: RingBuf<aya::maps::MapData>,
    senders: &[mpsc::Sender<EventBatch>],
    rate_limiter: &RateLimiter,
    stats: &EventStats,
    tls_rescan_tx: Option<mpsc::Sender<u32>>,
) -> Result<()> {
    // Wrap the ring buffer's fd in AsyncFd for epoll-based notification.
    // This avoids busy-polling: the task sleeps until the kernel signals data.
    let mut async_fd = AsyncFd::new(ring_buf)?;

    info!("DATA_EVENTS RingBuf consumer started (Kernel >= 5.8)");

    // Retry state for self-healing (7.5): track consecutive readable() failures
    let mut consecutive_errors: u32 = 0;
    const MAX_RETRIES: u32 = 3;

    // The kernel only wakes us once a batch is pending (see
    // data_events_submit_flags in the eBPF crate): a wakeup per event cost
    // ~90% of per-packet kernel time. The tick bounds delivery latency when
    // traffic is too light to reach the wakeup threshold; it backs off while
    // the ring stays empty so an idle agent isn't woken 500 times a second.
    let mut drain_interval = RINGBUF_DRAIN_INTERVAL;
    let drain_tick = tokio::time::sleep(drain_interval);
    tokio::pin!(drain_tick);

    loop {
        let woken = tokio::select! {
            ready = async_fd.readable_mut() => Some(ready),
            _ = &mut drain_tick => None,
        };
        match woken {
            None => {
                let drained = drain_ringbuf(
                    async_fd.get_mut(),
                    senders,
                    rate_limiter,
                    stats,
                    tls_rescan_tx.as_ref(),
                );
                drain_interval = next_drain_interval(drain_interval, drained);
                drain_tick
                    .as_mut()
                    .reset(tokio::time::Instant::now() + drain_interval);
            }
            Some(Ok(mut guard)) => {
                consecutive_errors = 0;
                drain_ringbuf(
                    guard.get_inner_mut(),
                    senders,
                    rate_limiter,
                    stats,
                    tls_rescan_tx.as_ref(),
                );
                // Clear readiness so we wait for the next epoll notification
                guard.clear_ready();
                // Traffic is flowing: tighten the latency bound again.
                drain_interval = RINGBUF_DRAIN_INTERVAL;
                drain_tick
                    .as_mut()
                    .reset(tokio::time::Instant::now() + drain_interval);
            }
            Some(Err(e)) => {
                consecutive_errors += 1;
                if consecutive_errors > MAX_RETRIES {
                    return Err(anyhow::anyhow!(
                        "RingBuf readable failed {} consecutive times, last error: {}",
                        consecutive_errors,
                        e
                    ));
                }
                let backoff_ms = 100 * 2u64.pow(consecutive_errors);
                warn!(
                    error = %e,
                    attempt = consecutive_errors,
                    backoff_ms,
                    "RingBuf readable_mut failed, retrying with backoff"
                );
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            }
        }
    }
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
#[cfg(target_os = "linux")]
fn drain_ringbuf(
    ring: &mut RingBuf<aya::maps::MapData>,
    senders: &[mpsc::Sender<EventBatch>],
    rate_limiter: &RateLimiter,
    stats: &EventStats,
    tls_rescan_tx: Option<&mpsc::Sender<u32>>,
) -> usize {
    let mut drained = 0;
    let mut batcher = WorkerBatcher::new(senders, stats);
    while let Some(item) = ring.next() {
        drained += 1;
        let data: &[u8] = item.as_ref();
        let Some(event) = parse_data_event_bytes(data) else {
            continue; // Malformed event, skip
        };

        stats.events_received.fetch_add(1, Ordering::Relaxed);

        // Handle ProcessEvent-typed events differently (they come through
        // PROCESS_EVENTS in the kernel, but we handle routing here)
        match event.event_type {
            EventType::ProcessExec => {
                debug!(
                    event_type = ?event.event_type,
                    pid = event.pid,
                    "Process exec event — triggering TLS rescan"
                );
                // 7.1: Send PID to TLS scanner for on-demand rescan
                if let Some(tx) = tls_rescan_tx.as_ref() {
                    let _ = tx.try_send(event.pid);
                }
                continue;
            }
            EventType::ProcessExit => {
                debug!(
                    event_type = ?event.event_type,
                    pid = event.pid,
                    "Process exit event"
                );
                // TODO: PID→connection cleanup requires PID tracking in ConnectionEntry.
                // Currently the FSM manager is keyed by socket_cookie, not PID.
                // A PID→cookie index in ConnectionFsmManager would enable cleanup here.
                continue;
            }
            _ => {}
        }

        // Rate limit check
        if !rate_limiter.try_acquire() {
            stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            stats.drops_rate_limit.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        // Route to worker by connection key (deterministic affinity).
        batcher.push(connection_key(&event), event);
    }
    batcher.flush();
    drained
}

/// Events handed to a worker in one channel message.
type EventBatch = Vec<DataEvent>;

/// Most events per batch. One send (and at most one worker wakeup) per
/// batch instead of per event: per-event sends woke a parked worker thread
/// for almost every packet at moderate rates, which cost more CPU than
/// parsing the packet.
const WORKER_BATCH: usize = 64;

/// Groups events per worker during one ring buffer drain.
#[cfg(target_os = "linux")]
struct WorkerBatcher<'a> {
    senders: &'a [mpsc::Sender<EventBatch>],
    pending: Vec<EventBatch>,
    stats: &'a EventStats,
}

#[cfg(target_os = "linux")]
impl<'a> WorkerBatcher<'a> {
    fn new(senders: &'a [mpsc::Sender<EventBatch>], stats: &'a EventStats) -> Self {
        Self {
            senders,
            pending: senders.iter().map(|_| Vec::new()).collect(),
            stats,
        }
    }

    fn push(&mut self, routing_key: u64, event: DataEvent) {
        if self.senders.is_empty() {
            return;
        }
        let idx = (routing_key as usize) % self.senders.len();
        self.pending[idx].push(event);
        if self.pending[idx].len() >= WORKER_BATCH {
            self.send(idx);
        }
    }

    fn flush(&mut self) {
        for idx in 0..self.pending.len() {
            if !self.pending[idx].is_empty() {
                self.send(idx);
            }
        }
    }

    /// try_send: never block the reader. Drop the batch if the worker is
    /// behind.
    fn send(&mut self, idx: usize) {
        let batch = std::mem::replace(&mut self.pending[idx], Vec::with_capacity(WORKER_BATCH));
        let n = batch.len() as u64;
        if self.senders[idx].try_send(batch).is_err() {
            self.stats.events_dropped.fetch_add(n, Ordering::Relaxed);
            self.stats
                .drops_channel_full
                .fetch_add(n, Ordering::Relaxed);
        }
    }
}

/// Consume events from a PerfEventArray (kernel < 5.8 fallback).
#[cfg(target_os = "linux")]
async fn consume_perf_array(
    mut perf_array: PerfEventArray<aya::maps::MapData>,
    senders: &[mpsc::Sender<EventBatch>],
    rate_limiter: &RateLimiter,
    stats: &EventStats,
    tls_rescan_tx: Option<mpsc::Sender<u32>>,
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
        stats.events_received.fetch_add(1, Ordering::Relaxed);

        // Same routing logic as RingBuf
        match event.event_type {
            EventType::ProcessExec => {
                if let Some(tx) = tls_rescan_tx.as_ref() {
                    let _ = tx.try_send(event.pid);
                }
                continue;
            }
            EventType::ProcessExit => continue,
            _ => {}
        }

        if !rate_limiter.try_acquire() {
            stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            stats.drops_rate_limit.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        let routing_cookie = connection_key(&event);

        let num_workers = senders.len();
        let worker_idx = if num_workers > 0 {
            (routing_cookie as usize) % num_workers
        } else {
            0
        };

        if senders[worker_idx].try_send(vec![event]).is_err() {
            stats.events_dropped.fetch_add(1, Ordering::Relaxed);
            stats.drops_channel_full.fetch_add(1, Ordering::Relaxed);
        }
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

/// Worker task: receives events from its channel, maintains per-connection state.
#[cfg(target_os = "linux")]
async fn worker_task(worker_id: usize, mut rx: mpsc::Receiver<EventBatch>, ctx: WorkerTaskContext) {
    let manager = ConnectionFsmManager::new(ctx.max_connections_tracked);
    let mut owners = OwnerTable::new(ctx.max_connections_tracked);
    let mut last_sweep = Instant::now();
    let sweep_interval = Duration::from_secs(5);

    debug!(worker_id, "Worker started");

    while let Some(batch) = rx.recv().await {
        // By reference: each DataEvent is ~4KB, so moving it out of the
        // batch would copy it again.
        for event in &batch {
            if let Some(raw) = ctx.raw_capture.as_ref() {
                raw.record(event);
            }

            let cookie = connection_key(event);
            if event.event_type != EventType::TcPacket && event.event_type != EventType::TlsData {
                owners.observe(event);
            }

            ctx.stats.events_processed.fetch_add(1, Ordering::Relaxed);

            if ctx.log_events {
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
            let payload = event.payload_bytes();
            if !payload.is_empty() {
                // Detect protocol and create FSM if not exists
                if !manager.contains(cookie)
                    && let Some(proto) =
                        detect_protocol(payload, event.src_port, event.dst_port, event.direction)
                {
                    use crate::protocol::fsm::CreateResult;
                    let server = server_endpoint(event, proto, payload);
                    let result = manager.get_or_create_with_server(cookie, proto, server);
                    match result {
                        CreateResult::Created => {
                            ctx.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                        }
                        CreateResult::CreatedWithEviction(evicted) => {
                            // Created after evicting the oldest connections at capacity
                            let evicted = evicted as u64;
                            ctx.stats
                                .evictions_capacity
                                .fetch_add(evicted, Ordering::Relaxed);
                            ctx.stats.active_connections.fetch_add(1, Ordering::Relaxed);
                            ctx.stats
                                .active_connections
                                .fetch_sub(evicted, Ordering::Relaxed);
                        }
                        CreateResult::AlreadyExists => {
                            // Race: another event created it between contains() and get_or_create()
                        }
                    }
                    if ctx.log_events {
                        debug!(worker = worker_id, cookie, protocol = %proto, "Protocol detected");
                    }
                }

                let src = sender_endpoint(event);
                let first = manager.process_packet_from(
                    cookie,
                    src,
                    event.direction,
                    payload,
                    event.timestamp_ns,
                );
                // Bytes beyond the capture cap (GSO/TSO super-packets, large TLS
                // writes) were never seen: let the parser count them instead of
                // desynchronising on the next message.
                let truncated = event.truncated_bytes() as usize;
                let after_gap = if truncated > 0 {
                    ctx.stats.truncated_events.fetch_add(1, Ordering::Relaxed);
                    manager.skip_from(cookie, src, event.direction, truncated, event.timestamp_ns)
                } else {
                    None
                };
                let sender_is_server = manager.server_of(cookie).map(|s| s == src);
                for result in [first, after_gap].into_iter().flatten() {
                    match result {
                        FsmResult::Messages(msgs) => {
                            handle_messages(
                                &msgs,
                                &MessageContext {
                                    worker_id,
                                    log_events: ctx.log_events,
                                    stats: ctx.stats.as_ref(),
                                    pii_engine: &ctx.pii_engine,
                                    json_export: &ctx.json_export,
                                    otlp_export: &ctx.otlp_export,
                                    audit_log: &ctx.audit_log,
                                    graph_builder: &ctx.graph_builder,
                                    event,
                                    sender_is_server,
                                    max_body_bytes: ctx.max_body_bytes,
                                    owners: owners.get(cookie),
                                },
                            );
                        }
                        FsmResult::MessageComplete(msg) => {
                            handle_messages(
                                &[msg],
                                &MessageContext {
                                    worker_id,
                                    log_events: ctx.log_events,
                                    stats: ctx.stats.as_ref(),
                                    pii_engine: &ctx.pii_engine,
                                    json_export: &ctx.json_export,
                                    otlp_export: &ctx.otlp_export,
                                    audit_log: &ctx.audit_log,
                                    graph_builder: &ctx.graph_builder,
                                    event,
                                    sender_is_server,
                                    max_body_bytes: ctx.max_body_bytes,
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

            // Handle connection close events: socket close, TCP RST, or FIN
            // from both sides (after this packet's payload was parsed).
            let closed = match event.event_type {
                EventType::SockClose => true,
                EventType::TcPacket if event.tcp_flags & TCP_FLAG_RST != 0 => true,
                EventType::TcPacket if event.tcp_flags & TCP_FLAG_FIN != 0 => {
                    manager.note_fin(cookie, sender_endpoint(event), event.direction)
                }
                _ => false,
            };
            if closed {
                owners.remove(cookie);
                if manager.close_connection(cookie) {
                    ctx.stats.active_connections.fetch_sub(1, Ordering::Relaxed);
                }
            }
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
            last_sweep = Instant::now();
        }
    }

    debug!(worker_id, "Worker shutting down");
}

#[cfg(target_os = "linux")]
fn handle_messages(msgs: &[crate::protocol::L7Message], ctx: &MessageContext<'_>) {
    for msg in msgs {
        // PII scan + in-place redaction happens FIRST, so that logging, the
        // audit log, every exporter and the service graph only ever see the
        // sanitized message (path/query, headers and payload).
        let mut msg = msg.clone();
        cap_body_text(&mut msg, ctx.max_body_bytes);
        let pii_report = ctx
            .pii_engine
            .as_ref()
            .and_then(|e| e.scan_message(&mut msg));
        if let Some(report) = pii_report.as_ref() {
            ctx.stats
                .pii_detections
                .fetch_add(report.entities.len() as u64, Ordering::Relaxed);
        }
        let msg = &msg;

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
                    service_identity: "unknown".to_string(),
                })
                .collect();

            if let Ok(mut log) = audit_arc.lock() {
                let _ = log.emit(&entries);
            }
        }

        // JSON export (channel-based — no mutex, no per-event flush)
        if let Some(handle) = ctx.json_export.as_ref()
            && !handle.try_send(
                msg.clone(),
                pii_report.clone(),
                crate::export::json::TransportContext {
                    client_pid: ctx.owners.and_then(|o| o.client),
                    server_pid: ctx.owners.and_then(|o| o.server),
                    ..crate::export::json::TransportContext::from_data_event(ctx.event)
                },
            )
        {
            ctx.stats.drops_export_full.fetch_add(1, Ordering::Relaxed);
            debug!(
                worker = ctx.worker_id,
                "JSON export event dropped due to exporter backpressure"
            );
        }

        // OTLP export (channel-based — drop when full, never block workers)
        if let Some(handle) = ctx.otlp_export.as_ref() {
            if !handle.try_send_span(msg.clone()) {
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
            gb.record_with_server(&conn_tuple, ctx.sender_is_server, msg, pii_report.as_ref());

            // DNS cache feeding (Option A): extract resolved A records from DNS messages
            if msg.protocol == crate::protocol::Protocol::Dns {
                for (key, value) in &msg.headers {
                    if key == "dns_a_record" {
                        // Format: "domain|ip_u32|ttl_secs"
                        let parts: Vec<&str> = value.splitn(3, '|').collect();
                        if parts.len() == 3
                            && let (Ok(ip), Ok(ttl)) =
                                (parts[1].parse::<u32>(), parts[2].parse::<u64>())
                        {
                            gb.dns_cache.insert_observed(
                                parts[0],
                                ip,
                                std::time::Duration::from_secs(ttl),
                            );
                        }
                    }
                }
            }
        }
    }
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
fn sender_endpoint(event: &DataEvent) -> crate::protocol::fsm::Endpoint {
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
/// TC and socket events carry the kernel socket cookie. TLS events carry the
/// library's connection object pointer (`SSL*`, `*tls.Conn`), unique only
/// within a process, so it is combined with the PID; the high bit keeps
/// these keys apart from kernel cookies. Events without one fall back to a
/// per-thread key.
#[cfg(target_os = "linux")]
fn connection_key(event: &DataEvent) -> u64 {
    if event.event_type != EventType::TlsData {
        return event.socket_cookie;
    }
    if event.socket_cookie == 0 {
        return tls_synthetic_cookie(event.pid, event.tgid);
    }
    0x8000_0000_0000_0000 | fxhash::hash64(&(event.pid, event.socket_cookie))
}

/// Generate a synthetic per-thread cookie for TLS events without a
/// connection pointer.
///
/// Uses PID + TGID to create a unique key that won't collide with real socket cookies.
/// Real socket cookies are kernel-assigned, typically < 2^32.
/// High bit set avoids collision with real cookies.
/// Includes both pid and tgid to handle forked processes correctly.
#[cfg(target_os = "linux")]
fn tls_synthetic_cookie(pid: u32, tgid: u32) -> u64 {
    0x8000_0000_0000_0000 | ((pid as u64) << 32) | (tgid as u64)
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
        // High bit must be set to avoid collision with real kernel cookies
        assert!(cookie & 0x8000_0000_0000_0000 != 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_tls_synthetic_cookie_no_collision_with_real() {
        // Real kernel cookies are typically small positive integers
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
