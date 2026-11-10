//! The disposable capture pipeline (DESIGN §3, narrowing; review 10).
//!
//! Everything downstream of the ring read is one [`Pipeline`]: the
//! workers and their channels, the connection FSM managers, the service
//! graph (aggregator, DAG, DNS cache, identity memo), the PII engine's
//! captured state (sampler, tokenizer, external client), the Kafka topic
//! map, the exporters' buffers and tasks, and the tracing `Dispatch` its
//! tasks log through. Each pipeline owns one [`IoGate`], and every write
//! that can carry captured data out of the process goes through it.
//!
//! [`Shared`] holds what is not derived from captured data and outlives
//! pipelines: the config, aggregate counters, the privacy mode, Kubernetes
//! metadata, the PII regexes and model, and the output files.
//!
//! [`Scope`] holds the current pipeline and the slot the ring readers load
//! it from. A narrowing replaces the pipeline and revokes the old gate
//! ([`Scope::narrow`]); the old pipeline is then dropped, never flushed.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::capture_gate::GateConfig;
use crate::config::{AgentConfig, CaptureBackend, PrivacyGate};
use crate::event_loop::{AdmissionFloor, EventBatch, EventStats, WorkerTaskContext};
use crate::export::audit::PiiAuditLog;
use crate::export::json::{JsonExportHandle, JsonExporter};
use crate::export::otlp::{OtlpExportHandle, OtlpWorker};
use crate::export::raw_capture::{self, RawCaptureHandle};
use crate::graph::GraphBuilder;
use crate::io_gate::{GatedLog, IoGate, LogSink, RecordFile, dispatched};
use crate::k8s::K8sMetadata;
use crate::pii::PiiEngine;

/// How long a graceful shutdown waits for each stage to drain.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// State shared by every pipeline: nothing derived from captured data.
pub struct Shared {
    pub config: AgentConfig,
    pub stats: Arc<EventStats>,
    pub privacy: Arc<PrivacyGate>,
    pub k8s: Option<Arc<K8sMetadata>>,
    /// The PII engine template: regexes and model, shared by every
    /// pipeline's copy.
    pub pii: Option<PiiEngine>,
    /// The workers' capture gate settings.
    pub capture_gate: GateConfig,
    /// Live cgroup_skb capture: the kernel decided every scope rule.
    pub kernel_scope: bool,
    pub json: Option<Arc<RecordFile>>,
    pub audit: Option<Arc<RecordFile>>,
    pub raw: Option<Arc<RecordFile>>,
    /// `EnvFilter` directives of the pipelines' log subscribers.
    pub log_filter: String,
    pub log_sink: LogSink,
    /// Tests: how many upcoming pipeline builds fail.
    #[cfg(test)]
    pub fail_builds: std::sync::atomic::AtomicU32,
}

impl Shared {
    /// Live capture: open every output file once.
    pub fn open(
        config: AgentConfig,
        privacy: Arc<PrivacyGate>,
        k8s: Option<Arc<K8sMetadata>>,
        log_filter: String,
    ) -> Result<Self> {
        let json = match &config.json_export_path {
            Some(path) => {
                tracing::info!(path = %path, "JSON export enabled");
                Some(JsonExporter::open(path)?)
            }
            None => None,
        };
        let audit =
            config
                .pii_audit_log_path
                .as_deref()
                .and_then(|path| match PiiAuditLog::open(path) {
                    Ok(f) => {
                        tracing::info!(path = %path, "PII audit log enabled");
                        Some(f)
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to create PII audit log");
                        None
                    }
                });
        let raw = match &config.capture_raw_path {
            Some(path) => {
                let f = raw_capture::open(
                    path,
                    config.capture_raw_max_bytes,
                    crate::util::monotonic_now_ns(),
                )?;
                tracing::warn!(
                    path = %path,
                    max_bytes = config.capture_raw_max_bytes,
                    "RAW CAPTURE ENABLED: every captured payload is written UNREDACTED \
                     (credentials, tokens, personal data). Protect and delete this file."
                );
                Some(f)
            }
            None => None,
        };
        let pii = config.pii.enabled.then(|| {
            let ml = matches!(config.pii.mode, crate::config::PiiMode::InAgent { .. });
            tracing::info!(
                regex = config.pii.regex_enabled,
                ml = ml,
                "PII detection enabled"
            );
            PiiEngine::new(&config.pii, &config.pii_external_url_allowlist)
        });
        Ok(Self {
            capture_gate: GateConfig::from_config(&config),
            kernel_scope: config.capture_backend == CaptureBackend::CgroupSkb,
            config,
            stats: Arc::new(EventStats::new()),
            privacy,
            k8s,
            pii,
            json,
            audit,
            raw,
            log_filter,
            log_sink: crate::io_gate::stdout_sink(),
            #[cfg(test)]
            fail_builds: Default::default(),
        })
    }

    /// Offline replay of a recording (`--replay-bench`, tests): one worker,
    /// the JSON export only, and the user-space scope rules always applied
    /// whatever the backend (no kernel decided anything for these events;
    /// the rules err toward drop).
    pub fn for_replay(mut config: AgentConfig, privacy: Arc<PrivacyGate>) -> Result<Self> {
        config.max_worker_count = 1;
        config.otlp.enabled = false;
        let json = config
            .json_export_path
            .as_deref()
            .map(JsonExporter::open)
            .transpose()?;
        Ok(Self {
            capture_gate: GateConfig::user_space(&config),
            kernel_scope: false,
            pii: config
                .pii
                .enabled
                .then(|| PiiEngine::new(&config.pii, &config.pii_external_url_allowlist)),
            config,
            stats: Arc::new(EventStats::new()),
            privacy,
            k8s: None,
            json,
            audit: None,
            raw: None,
            log_filter: "info".to_string(),
            log_sink: crate::io_gate::stdout_sink(),
            #[cfg(test)]
            fail_builds: Default::default(),
        })
    }
}

/// What the ring readers load, once per drained batch: the pipeline's
/// worker channels (and its gate, for the test pause points).
pub struct PipelineHandle {
    pub(crate) gate: Arc<IoGate>,
    pub(crate) senders: Vec<mpsc::Sender<EventBatch>>,
}

impl PipelineHandle {
    /// No pipeline: readers drop (and count) everything.
    pub fn closed() -> Arc<Self> {
        let gate = IoGate::new();
        gate.revoke();
        Arc::new(Self {
            gate,
            senders: Vec::new(),
        })
    }
}

/// One capture pipeline. See the module docs.
pub struct Pipeline {
    gate: Arc<IoGate>,
    handle: Arc<PipelineHandle>,
    workers: Vec<JoinHandle<()>>,
    housekeeping: JoinHandle<()>,
    json: Option<JoinHandle<()>>,
    otlp: Option<OtlpWorker>,
    raw: Option<(RawCaptureHandle, std::thread::JoinHandle<()>)>,
}

/// The pipeline's log subscriber: the agent's format and filter, written
/// through the pipeline's gate.
fn log_dispatch(shared: &Shared, gate: &Arc<IoGate>) -> tracing::Dispatch {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&shared.log_filter))
        .with_target(true)
        .with_writer(GatedLog::new(Arc::clone(gate), shared.log_sink.clone()))
        .finish();
    tracing::Dispatch::new(subscriber)
}

impl Pipeline {
    /// Build a pipeline and start its tasks. Must run inside the runtime.
    pub fn build(shared: &Shared) -> Result<Self> {
        #[cfg(test)]
        if shared
            .fail_builds
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| n.checked_sub(1),
            )
            .is_ok()
        {
            anyhow::bail!("test: pipeline build failure");
        }
        let cfg = &shared.config;
        let gate = IoGate::new();
        let dispatch = log_dispatch(shared, &gate);
        let pii = shared
            .pii
            .as_ref()
            .map(|e| e.for_pipeline(Arc::clone(&gate), dispatch.clone()))
            .transpose()
            .context("cannot set up PII detection for the pipeline")?;
        let otlp = if cfg.otlp.enabled {
            let (handle, worker) = OtlpExportHandle::spawn(
                &cfg.otlp,
                4096,
                Arc::clone(&shared.privacy),
                Arc::clone(&gate),
                dispatch.clone(),
            )
            .context("OTLP export")?;
            Some((handle, worker))
        } else {
            None
        };
        let raw = match &shared.raw {
            Some(f) => Some(raw_capture::spawn(
                Arc::clone(f),
                Arc::clone(&gate),
                16_384,
                Arc::clone(&shared.privacy),
                dispatch.clone(),
            )?),
            None => None,
        };
        let json = shared.json.as_ref().map(|f| {
            JsonExportHandle::spawn_on(
                Arc::clone(f),
                Arc::clone(&gate),
                4096,
                shared.k8s.clone(),
                Arc::clone(&shared.privacy),
                dispatch.clone(),
            )
        });
        let graph = cfg
            .graph
            .enabled
            .then(|| Arc::new(GraphBuilder::new(&cfg.graph).with_k8s(shared.k8s.clone())));
        let kafka_topics = crate::protocol::kafka::KafkaTopics::default();

        // Capacity is configured in events; the channels carry batches.
        let batch_cap = cfg
            .worker_channel_capacity
            .div_ceil(crate::event_loop::WORKER_BATCH)
            .max(1);
        let mut senders = Vec::with_capacity(cfg.max_worker_count);
        let mut workers = Vec::with_capacity(cfg.max_worker_count);
        for worker_id in 0..cfg.max_worker_count {
            let (tx, rx) = mpsc::channel::<EventBatch>(batch_cap);
            senders.push(tx);
            let ctx = WorkerTaskContext {
                stats: Arc::clone(&shared.stats),
                idle_timeout: cfg.idle_connection_timeout,
                log_events: cfg.log_events,
                max_connections_tracked: cfg.max_connections_tracked,
                pii_engine: pii.clone(),
                json_export: json.as_ref().map(|(h, _)| h.clone()),
                otlp_export: otlp.as_ref().map(|(h, _)| h.clone()),
                audit_log: shared
                    .audit
                    .as_ref()
                    .map(|f| PiiAuditLog::on(Arc::clone(f), Arc::clone(&gate))),
                graph_builder: graph.clone(),
                raw_capture: raw.as_ref().map(|(h, _)| h.clone()),
                max_body_bytes: cfg.max_body_bytes,
                privacy: Arc::clone(&shared.privacy),
                capture_gate: shared.capture_gate.clone(),
                kernel_scope: shared.kernel_scope,
                io_gate: Arc::clone(&gate),
                kafka_topics: kafka_topics.clone(),
            };
            workers.push(tokio::spawn(dispatched(
                crate::event_loop::worker_task(worker_id, rx, ctx),
                dispatch.clone(),
            )));
        }
        let housekeeping = tokio::spawn(dispatched(housekeeping(graph, pii), dispatch.clone()));
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(workers = workers.len(), "Capture pipeline started");
        });

        Ok(Self {
            handle: Arc::new(PipelineHandle {
                gate: Arc::clone(&gate),
                senders,
            }),
            gate,
            workers,
            housekeeping,
            json: json.map(|(_, w)| w),
            otlp: otlp.map(|(_, w)| w),
            raw,
        })
    }

    pub fn handle(&self) -> Arc<PipelineHandle> {
        Arc::clone(&self.handle)
    }

    /// Narrowing step 4: revoke the gate. Waits for every gated write in
    /// flight; nothing the pipeline holds can leave the process afterwards.
    pub async fn revoke(&self) {
        let gate = Arc::clone(&self.gate);
        // The write lock can wait on a blocked write: off the runtime. If
        // the blocking pool refuses (runtime shutting down), revoke here.
        if tokio::task::spawn_blocking(move || gate.revoke())
            .await
            .is_err()
        {
            self.gate.revoke();
        }
    }

    /// After [`revoke`](Self::revoke): stop everything and drop its state,
    /// never flushing. Writers still running find the gate revoked.
    pub fn discard(self) {
        debug_assert!(self.gate.is_revoked());
        for w in &self.workers {
            w.abort();
        }
        self.housekeeping.abort();
        // The JSON writer exits once the workers' senders are gone; its
        // buffered batch is refused by the gate.
        drop(self.json);
        if let Some(otlp) = self.otlp {
            otlp.discard();
        }
        if let Some((handle, _thread)) = self.raw {
            handle.shutdown();
        }
    }

    /// Agent shutdown (not revoked): the readers have let go of the handle;
    /// the workers drain their queues, then the writers flush.
    pub async fn shutdown(self) {
        drop(self.handle);
        for w in self.workers {
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, w).await;
        }
        self.housekeeping.abort();
        if let Some(json) = self.json {
            let _ = tokio::time::timeout(DRAIN_TIMEOUT, json).await;
        }
        if let Some(otlp) = self.otlp {
            otlp.finish(DRAIN_TIMEOUT).await;
        }
        if let Some((handle, thread)) = self.raw {
            // Drain the queue before the process exits.
            handle.shutdown();
            drop(handle);
            let _ = tokio::time::timeout(
                2 * DRAIN_TIMEOUT,
                tokio::task::spawn_blocking(move || thread.join()),
            )
            .await;
        }
    }

    /// Feed recorded events through worker 0, waiting for room: exactly the
    /// path live events take after the ring buffer, for measuring
    /// user-space throughput (`--replay-bench`).
    pub async fn replay(&self, events: &[panopticon_common::DataEvent]) {
        let Some(tx) = self.handle.senders.first() else {
            return;
        };
        let mut batch = EventBatch::default();
        for event in events {
            batch.push(event);
            if batch.is_full() && tx.send(std::mem::take(&mut batch)).await.is_err() {
                return;
            }
        }
        if !batch.is_empty() {
            let _ = tx.send(batch).await;
        }
    }
}

/// Per-pipeline upkeep: the PII sampler budget every second, the service
/// graph's flush and prune every 10 s.
async fn housekeeping(graph: Option<Arc<GraphBuilder>>, pii: Option<PiiEngine>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut n = 0u64;
    loop {
        tick.tick().await;
        n += 1;
        if let Some(pii) = &pii {
            pii.refill_sampler();
        }
        if let Some(gb) = graph.as_ref().filter(|_| n.is_multiple_of(10)) {
            let flows = gb.flush();
            // Edge timestamps come from bpf_ktime_get_ns (monotonic,
            // since boot); wall-clock time here wiped the whole graph on
            // every flush.
            gb.prune(crate::util::monotonic_now_ns());
            if let Ok(dag) = gb.dag().lock() {
                tracing::info!(
                    graph_nodes = dag.node_count(),
                    graph_edges = dag.edge_count(),
                    flushed_flows = flows.len(),
                    "Service graph"
                );
            }
        }
    }
}

// ── Scope ──────────────────────────────────────────────────────────────────

/// The current pipeline, and the slot the ring readers load it from.
pub struct Scope {
    shared: Arc<Shared>,
    slot: Arc<ArcSwap<PipelineHandle>>,
    floor: AdmissionFloor,
    current: tokio::sync::Mutex<Option<Pipeline>>,
}

impl Scope {
    /// Build the first pipeline. Failing here fails startup.
    pub fn start(shared: Arc<Shared>, floor: AdmissionFloor) -> Result<Arc<Self>> {
        let first = Pipeline::build(&shared)?;
        Ok(Arc::new(Self {
            slot: Arc::new(ArcSwap::new(first.handle())),
            shared,
            floor,
            current: tokio::sync::Mutex::new(Some(first)),
        }))
    }

    pub fn slot(&self) -> Arc<ArcSwap<PipelineHandle>> {
        Arc::clone(&self.slot)
    }

    /// Build a pipeline and install it; on failure install the closed
    /// handle. Returns the new pipeline, if any.
    fn install(&self) -> Option<Pipeline> {
        match Pipeline::build(&self.shared) {
            Ok(p) => {
                self.slot.store(p.handle());
                Some(p)
            }
            Err(e) => {
                tracing::error!(
                    error = %format!("{e:#}"),
                    "Capture pipeline build failed: nothing is captured until a later \
                     scope change builds one"
                );
                self.slot.store(PipelineHandle::closed());
                None
            }
        }
    }

    /// Narrowing steps 2 to 4 (DESIGN §3) for scope generation `generation`
    /// (step 1, the map update and bump, is the caller's): raise the
    /// admission floor, build a fresh pipeline and switch the readers to
    /// it, then revoke the old one's gate. The old pipeline is then shut
    /// down in the background, never flushed. A build failure keeps the
    /// floor raised and still revokes (Revision 1 item 7). Returns whether
    /// a pipeline is installed.
    pub async fn narrow(&self, generation: u32) -> bool {
        let mut current = self.current.lock().await;
        self.floor.raise(generation); // 2
        let new = self.install(); // 3
        let installed = new.is_some();
        if let Some(old) = std::mem::replace(&mut *current, new) {
            old.revoke().await; // 4
            old.discard();
        }
        installed
    }

    /// Build a pipeline if none is installed (after a failed build).
    pub async fn ensure_installed(&self) -> bool {
        let mut current = self.current.lock().await;
        if current.is_none() {
            *current = self.install();
        }
        current.is_some()
    }

    /// Fatal capture stop: install the closed handle and revoke the current
    /// pipeline, for good (no rebuild follows).
    pub async fn stop(&self) {
        self.shared
            .stats
            .capture_stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut current = self.current.lock().await;
        self.slot.store(PipelineHandle::closed());
        if let Some(old) = current.take() {
            old.revoke().await;
            old.discard();
        }
    }

    /// Agent shutdown: drain the current pipeline and flush its outputs.
    pub async fn shutdown(&self) {
        let mut current = self.current.lock().await;
        self.slot.store(PipelineHandle::closed());
        if let Some(p) = current.take() {
            p.shutdown().await;
        }
    }

    /// The installed pipeline's gate (tests).
    #[cfg(test)]
    pub async fn gate(&self) -> Option<Arc<IoGate>> {
        self.current
            .lock()
            .await
            .as_ref()
            .map(|p| Arc::clone(&p.gate))
    }
}
