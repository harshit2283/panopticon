use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "compression")]
mod compression;
mod config;
mod event_loop;
mod export;
mod graph;
mod k8s;
#[cfg(target_os = "linux")]
mod loader;
mod pii;

mod platform;
mod protocol;
pub mod replay;
mod util;

/// Panopticon Agent — eBPF-powered network observability
///
/// Attaches eBPF programs to capture network traffic, TLS plaintext,
/// process lifecycle events, and socket state changes. Streams events
/// to configured sinks for analysis.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interfaces to attach TC classifiers to (repeatable, e.g. -i eth0 -i wlan0).
    /// Default: the config file's `interfaces`, else the default-route interface(s).
    #[arg(short, long)]
    interface: Vec<String>,

    /// Enable verbose (debug-level) logging
    #[arg(short, long)]
    verbose: bool,

    /// Path to TOML config file
    #[arg(long, env = "PANOPTICON_CONFIG")]
    config: Option<String>,

    /// Print captured events to stdout (dev mode)
    #[arg(long)]
    log_events: bool,

    /// Write events as JSONL to this file path
    #[arg(long)]
    json_export: Option<String>,

    /// Write PII audit events as JSONL to this file path
    #[arg(long)]
    pii_audit_log: Option<String>,

    /// Bind address for HTTP server (health, metrics, debug)
    #[arg(long)]
    metrics_bind: Option<String>,

    /// Run smoke test: attach probes, verify events, then exit
    #[arg(long)]
    smoke_test: bool,

    /// Kubernetes identity (name endpoints namespace/workload): `auto` (when
    /// running in a pod), `true` or `false`. Overrides `[kubernetes] enabled`.
    #[arg(long, env = "PANOPTICON_KUBERNETES", value_name = "auto|true|false",
          value_parser = ["auto", "true", "false"])]
    kubernetes: Option<String>,

    /// Write every captured event, UNREDACTED, to this file (PNCAP format,
    /// owner-only permissions, truncated at start). Decode with --decode-capture.
    #[arg(long, value_name = "FILE")]
    capture_raw: Option<String>,

    /// Print a raw capture file as JSON lines (metadata + base64 payload), then exit.
    /// Needs no privileges.
    #[arg(long, value_name = "FILE")]
    decode_capture: Option<String>,

    /// Benchmark: run a raw capture file (from --capture-raw) through one
    /// worker's parse/PII/graph/export path as fast as possible, print the
    /// throughput, then exit. Uses the config file's settings; needs no
    /// privileges and loads no eBPF.
    #[arg(long, value_name = "FILE")]
    replay_bench: Option<String>,
}

/// mimalloc instead of glibc malloc: parser workers allocate messages that
/// the export thread frees, and glibc's arena locks serialized them (~20% of
/// busy samples in the replay benchmark).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(unix)]
    if let Some(ref path) = args.decode_capture {
        use anyhow::Context;
        let file =
            std::fs::File::open(path).with_context(|| format!("cannot open capture {path}"))?;
        let stdout = std::io::stdout().lock();
        export::raw_capture::decode_to_jsonl(
            std::io::BufReader::new(file),
            std::io::BufWriter::new(stdout),
        )?;
        return Ok(());
    }

    // Initialize tracing subscriber with env filter
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        interfaces = ?args.interface,
        "Panopticon Agent starting"
    );

    #[cfg(not(target_os = "linux"))]
    {
        tracing::error!("eBPF requires Linux. This binary is a stub on other platforms.");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        use std::collections::HashSet;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        use anyhow::Context;
        use arc_swap::ArcSwap;

        // Disable core dumps to prevent PII leakage
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
        info!("Core dumps disabled (PR_SET_DUMPABLE=0)");

        // Load config: file first (if provided), then CLI overrides
        let mut agent_config = match &args.config {
            Some(path) => {
                info!(path = %path, "Loading config from file");
                config::load_config(path)?
            }
            None => config::AgentConfig::default(),
        };
        if !args.interface.is_empty() {
            agent_config.interfaces = args.interface.clone();
        }
        if args.log_events {
            agent_config.log_events = true;
        }
        if let Some(ref path) = args.json_export {
            agent_config.json_export_path = Some(path.clone());
        }
        if let Some(ref path) = args.pii_audit_log {
            agent_config.pii_audit_log_path = Some(path.clone());
        }
        if let Some(ref bind) = args.metrics_bind {
            agent_config.metrics_bind = Some(bind.clone());
        }
        agent_config.smoke_test = args.smoke_test;
        if let Some(mode) = args.kubernetes.as_deref() {
            agent_config.kubernetes.mode = match mode {
                "true" => config::KubernetesMode::Enabled,
                "false" => config::KubernetesMode::Disabled,
                _ => config::KubernetesMode::Auto,
            };
        }
        if let Some(ref path) = args.capture_raw {
            agent_config.capture_raw_path = Some(path.clone());
        }
        if let Some(ref path) = args.replay_bench {
            return replay_bench(&agent_config, path).await;
        }
        if agent_config.interfaces.is_empty() {
            let route = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
            agent_config.interfaces = util::default_route_interfaces(&route);
            if agent_config.interfaces.is_empty() {
                anyhow::bail!(
                    "No --interface given and no IPv4 default route found in /proc/net/route; \
                     pass --interface or set `interfaces` in the config file"
                );
            }
            info!(interfaces = ?agent_config.interfaces, "Auto-detected default-route interface(s)");
        }

        let caps = loader::detect_kernel_caps()?;
        info!(
            kernel = %format!("{}.{}.{}", caps.version.0, caps.version.1, caps.version.2),
            ringbuf = caps.has_ringbuf,
            btf = caps.has_btf,
            tc_ebpf = caps.has_tc_ebpf,
            "Kernel capabilities detected"
        );

        // Advisory capability check — warn if missing caps, don't block startup
        let missing_caps = loader::check_required_capabilities(&caps);
        if !missing_caps.is_empty() {
            tracing::warn!(
                missing = ?missing_caps,
                "Missing Linux capabilities — eBPF attachment may fail. \
                 Kernel >= 5.8 needs CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN; \
                 older kernels need CAP_SYS_ADMIN."
            );
        }

        let mut programs = loader::load_and_attach(&agent_config.interfaces, &caps, &agent_config)?;

        // 1. Extract EventSource (RingBuf or PerfEventArray) BEFORE wrapping Ebpf in Arc<Mutex>.
        //    This breaks the borrow chain — event loop no longer needs &mut Ebpf.
        let event_source = loader::take_event_source(&mut programs.ebpf, &caps)
            .context("Failed to initialize event source from eBPF maps")?;
        let kernel_drops = loader::take_kernel_drops(&mut programs.ebpf);

        // 2. Initial TLS library scan (still has exclusive &mut access)
        let mut attached_libs = HashSet::new();
        if agent_config.tls_scan_enabled {
            let targets = platform::proc_scanner::scan_all_processes();
            let mut tls_probes = 0;
            for target in &targets {
                tls_probes +=
                    loader::attach_tls_uprobes(&mut programs.ebpf, target, &mut programs._links);
                // Track by inode to handle symlinks/mount namespaces
                if let Some(file_id) = platform::proc_scanner::get_file_id(&target.library_path) {
                    attached_libs.insert(file_id);
                }
            }
            info!(
                targets = targets.len(),
                probes = tls_probes,
                "Initial TLS scan complete"
            );
        }

        // 3. Wrap Ebpf + links in shared state for background scanner
        let shared_ebpf = Arc::new(Mutex::new(loader::EbpfState {
            ebpf: programs.ebpf,
            links: programs._links,
            attached_libs,
        }));

        // 4. Create TLS rescan channel and spawn background TLS scanner task
        //    ProcessExec events in the event loop send PIDs to tls_rescan_tx,
        //    which the scanner task receives for on-demand library scanning.
        let (tls_rescan_tx, tls_rescan_rx) = tokio::sync::mpsc::channel::<u32>(256);
        let scanner_handle = if agent_config.tls_scan_enabled {
            let ebpf_clone = Arc::clone(&shared_ebpf);
            let interval = agent_config.tls_scan_interval;
            Some(tokio::spawn(platform::proc_scanner::tls_scanner_task(
                ebpf_clone,
                interval,
                tls_rescan_rx,
            )))
        } else {
            None
        };
        let tls_rescan_tx = if agent_config.tls_scan_enabled {
            Some(tls_rescan_tx)
        } else {
            // Drop sender if scanner not enabled, so channel closes cleanly
            None
        };

        // 5. Construct PII engine + JSON exporter
        let pii_engine = if agent_config.pii.enabled {
            let ml = matches!(agent_config.pii.mode, config::PiiMode::InAgent { .. });
            info!(
                regex = agent_config.pii.regex_enabled,
                ml = ml,
                "PII detection enabled"
            );
            Some(pii::PiiEngine::new(
                &agent_config.pii,
                &agent_config.pii_external_url_allowlist,
            ))
        } else {
            None
        };

        // Kubernetes metadata (pod/service names for graph nodes and exports).
        // Starts a background sync and returns at once; never fails startup.
        let k8s_metadata = k8s::K8sMetadata::start(&agent_config.kubernetes);

        let (json_export_handle, json_writer_handle) = match &agent_config.json_export_path {
            Some(path) => {
                info!(path = %path, "JSON export enabled");
                let (handle, writer) = export::json::JsonExportHandle::spawn_with_k8s(
                    path,
                    4096,
                    k8s_metadata.clone(),
                )?;
                (Some(handle), Some(writer))
            }
            None => (None, None),
        };
        let (otlp_export_handle, otlp_writer_handle) = if agent_config.otlp.enabled {
            info!(
                endpoint = %agent_config.otlp.endpoint,
                service_name = %agent_config.otlp.service_name,
                "OTLP gRPC export enabled"
            );
            match export::otlp::OtlpExportHandle::spawn(&agent_config.otlp, 4096) {
                Ok((handle, worker)) => (Some(handle), Some(worker)),
                Err(e) => {
                    tracing::error!(error = %e, "Failed to initialize OTLP exporter");
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        let pii_audit_log = match &agent_config.pii_audit_log_path {
            Some(path) => {
                info!(path = %path, "PII audit log enabled");
                match export::audit::PiiAuditLog::new(path) {
                    Ok(log) => Some(Arc::new(Mutex::new(log))),
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to create PII audit log");
                        None
                    }
                }
            }
            None => None,
        };

        // 6. Construct graph builder
        let graph_builder = if agent_config.graph.enabled {
            info!("Service graph enabled");
            Some(graph::GraphBuilder::new(&agent_config.graph).with_k8s(k8s_metadata.clone()))
        } else {
            None
        };

        // 7. Construct event loop (needed before HTTP server for shared stats access)
        let event_loop = event_loop::EventLoop::new(
            agent_config.clone(),
            pii_engine,
            json_export_handle,
            otlp_export_handle,
            pii_audit_log,
            graph_builder,
        );

        // 7b. Raw capture (unredacted): opt-in only, loudly.
        let (event_loop, raw_capture) = match &agent_config.capture_raw_path {
            Some(path) => {
                let (handle, thread) = export::raw_capture::spawn(
                    path,
                    agent_config.capture_raw_max_bytes,
                    16_384,
                    util::monotonic_now_ns(),
                )?;
                tracing::warn!(
                    path = %path,
                    max_bytes = agent_config.capture_raw_max_bytes,
                    "RAW CAPTURE ENABLED: every captured payload is written UNREDACTED \
                     (credentials, tokens, personal data). Protect and delete this file."
                );
                (
                    event_loop.with_raw_capture(handle.clone()),
                    Some((handle, thread)),
                )
            }
            None => (event_loop, None),
        };

        // 8. HTTP server (health, metrics, debug endpoints).
        //    Probes are attached at this point, so the agent is ready; the flag
        //    is cleared again as soon as shutdown begins.
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let event_stats = event_loop.stats().clone();
        if let Some(map) = kernel_drops {
            let stats = event_stats.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    stats.kernel_drops.store(
                        loader::sum_per_cpu(&map),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            });
        }
        let http_handle = if let Some(ref bind) = agent_config.metrics_bind {
            let (metrics, registry) = export::metrics::AgentMetrics::new();
            let state = export::http_server::AppState {
                registry: Arc::new(registry),
                stats: event_loop.stats().clone(),
                metrics,
                worker_count: agent_config.max_worker_count,
                ready: Arc::clone(&ready),
                raw_capture: raw_capture.as_ref().map(|(h, _)| h.clone()),
            };
            let bind = bind.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = export::http_server::start_http_server(bind, state).await {
                    tracing::error!(error = %e, "HTTP server failed");
                }
            }))
        } else {
            None
        };

        let smoke_test = agent_config.smoke_test;

        // 9. SIGHUP config hot-reload
        let shared_config = Arc::new(ArcSwap::from_pointee(agent_config));
        let config_path_for_reload = args.config.clone();
        let config_swap = Arc::clone(&shared_config);
        let sighup_handle = tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("failed to register SIGHUP handler");
            loop {
                sig.recv().await;
                if let Some(ref path) = config_path_for_reload {
                    match config::load_config(path) {
                        Ok(new_config) => {
                            info!(path = %path, "Config reloaded via SIGHUP");
                            config_swap.store(Arc::new(new_config));
                            // TODO: sync runtime-tunable fields to eBPF CONFIG map
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Config reload failed, keeping current");
                        }
                    }
                } else {
                    info!("SIGHUP received but no config file specified, ignoring");
                }
            }
        });

        // Kubernetes stops pods with SIGTERM (SIGINT only for interactive use).
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("failed to register SIGTERM handler")?;

        // Consume events from the kernel and route to workers.
        // This is the main blocking task that drives the system.
        let mut exit_result: Result<()> = Ok(());
        tokio::select! {
            result = event_loop.run(event_source, tls_rescan_tx) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "Event loop exited with error");
                    exit_result = Err(e.context("event loop failed"));
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received, shutting down...");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, shutting down...");
            }
            outcome = smoke_test_wait(smoke_test, &event_stats) => {
                exit_result = outcome;
            }
        }
        ready.store(false, std::sync::atomic::Ordering::Relaxed);

        // 10. Cleanup — abort background tasks, wait for JSON writer drain
        sighup_handle.abort();
        if let Some(h) = http_handle {
            h.abort();
        }
        if let Some(h) = scanner_handle {
            h.abort();
        }
        if let Some(h) = json_writer_handle {
            // Give the writer 5s to flush remaining events
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
        if let Some(h) = otlp_writer_handle {
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
        if let Some((handle, thread)) = raw_capture {
            // Drain the queue and flush the file before the process exits.
            handle.shutdown();
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::task::spawn_blocking(move || thread.join()),
            )
            .await;
        }

        exit_result
    }
}

/// `--smoke-test`: succeed as soon as the attached programs deliver at least
/// one event, fail after a timeout. Never resolves when smoke testing is off.
#[cfg(target_os = "linux")]
async fn smoke_test_wait(enabled: bool, stats: &event_loop::EventStats) -> Result<()> {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);

    if !enabled {
        return std::future::pending().await;
    }
    info!(
        timeout_secs = SMOKE_TIMEOUT.as_secs(),
        "Smoke test: waiting for first event"
    );
    let deadline = tokio::time::Instant::now() + SMOKE_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        let received = stats.events_received.load(Ordering::Relaxed);
        if received > 0 {
            info!(received, "Smoke test passed: events are flowing");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!(
        "Smoke test failed: no events received within {}s",
        SMOKE_TIMEOUT.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Args;

    #[test]
    fn test_cli_default_args() {
        let args = Args::parse_from(["panopticon-agent"]);
        assert!(args.interface.is_empty());
        assert!(!args.verbose);
        assert!(!args.log_events);
        assert!(args.json_export.is_none());
        assert!(!args.smoke_test);
    }

    #[test]
    fn test_cli_custom_interface() {
        let args = Args::parse_from(["panopticon-agent", "--interface", "wlan0"]);
        assert_eq!(args.interface, vec!["wlan0"]);
    }

    #[test]
    fn test_cli_verbose_flag() {
        let args = Args::parse_from(["panopticon-agent", "--verbose"]);
        assert!(args.verbose);
    }

    #[test]
    fn test_cli_short_flags() {
        let args = Args::parse_from(["panopticon-agent", "-i", "lo", "-v"]);
        assert_eq!(args.interface, vec!["lo"]);
        assert!(args.verbose);
    }

    #[test]
    fn test_cli_multi_interface() {
        let args = Args::parse_from([
            "panopticon-agent",
            "-i",
            "eth0",
            "-i",
            "wlan0",
            "-i",
            "docker0",
        ]);
        assert_eq!(args.interface, vec!["eth0", "wlan0", "docker0"]);
    }

    #[test]
    fn test_cli_log_events() {
        let args = Args::parse_from(["panopticon-agent", "--log-events"]);
        assert!(args.log_events);
    }

    #[test]
    fn test_cli_json_export() {
        let args = Args::parse_from(["panopticon-agent", "--json-export", "/tmp/events.jsonl"]);
        assert_eq!(args.json_export.as_deref(), Some("/tmp/events.jsonl"));
    }

    #[test]
    fn test_cli_smoke_test() {
        let args = Args::parse_from(["panopticon-agent", "--smoke-test"]);
        assert!(args.smoke_test);
    }

    #[test]
    fn test_cli_config_arg() {
        let args = Args::parse_from(["panopticon-agent", "--config", "/etc/panopticon.toml"]);
        assert_eq!(args.config.as_deref(), Some("/etc/panopticon.toml"));
    }

    #[test]
    fn test_cli_metrics_bind() {
        let args = Args::parse_from(["panopticon-agent", "--metrics-bind", "0.0.0.0:9090"]);
        assert_eq!(args.metrics_bind.as_deref(), Some("0.0.0.0:9090"));
    }

    #[test]
    fn test_cli_kubernetes_mode() {
        let args = Args::parse_from(["panopticon-agent"]);
        assert!(args.kubernetes.is_none());
        let args = Args::parse_from(["panopticon-agent", "--kubernetes", "false"]);
        assert_eq!(args.kubernetes.as_deref(), Some("false"));
        assert!(Args::try_parse_from(["panopticon-agent", "--kubernetes", "maybe"]).is_err());
    }

    #[test]
    fn test_cli_default_no_config() {
        let args = Args::parse_from(["panopticon-agent"]);
        assert!(args.config.is_none());
        assert!(args.metrics_bind.is_none());
    }
}

/// `--replay-bench`: feed a capture through the production worker path.
#[cfg(target_os = "linux")]
async fn replay_bench(config: &config::AgentConfig, path: &str) -> Result<()> {
    use anyhow::Context;
    use std::sync::atomic::Ordering;

    let file = std::fs::File::open(path).with_context(|| format!("cannot open capture {path}"))?;
    let mut reader = replay::CaptureReader::new(std::io::BufReader::new(file))
        .context("not a Panopticon capture (PNCAP)")?;
    let mut events = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Some(event)) => events.push(event),
            Ok(None) => break,
            // The agent may have stopped mid-record.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("invalid capture record"),
        }
    }

    let pii = config
        .pii
        .enabled
        .then(|| pii::PiiEngine::new(&config.pii, &config.pii_external_url_allowlist));
    let (json, writer) = match &config.json_export_path {
        Some(p) => {
            let (h, w) = export::json::JsonExportHandle::spawn(p, 4096)?;
            (Some(h), Some(w))
        }
        None => (None, None),
    };
    let graph = config
        .graph
        .enabled
        .then(|| graph::GraphBuilder::new(&config.graph));
    let event_loop = event_loop::EventLoop::new(config.clone(), pii, json, None, None, graph);

    let n = events.len();
    let start = std::time::Instant::now();
    event_loop.replay_through_worker(events).await?;
    let elapsed = start.elapsed().as_secs_f64();
    let stats = event_loop.stats().clone();
    drop(event_loop);
    if let Some(w) = writer {
        w.await?;
    }
    println!(
        "events={n} elapsed={elapsed:.3}s rate={:.0}/s per_event={:.2}us pii_detections={} parser_errors={}",
        n as f64 / elapsed,
        elapsed * 1e6 / n.max(1) as f64,
        stats.pii_detections.load(Ordering::Relaxed),
        stats.drops_parser_error.load(Ordering::Relaxed),
    );
    Ok(())
}
