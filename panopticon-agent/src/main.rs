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
    /// Network interfaces to attach TC classifiers to (repeatable, e.g. -i eth0 -i wlan0)
    #[arg(short, long, default_value = "eth0")]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

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

        let (json_export_handle, json_writer_handle) = match &agent_config.json_export_path {
            Some(path) => {
                info!(path = %path, "JSON export enabled");
                let (handle, writer) = export::json::JsonExportHandle::spawn(path, 4096)?;
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
            Some(graph::GraphBuilder::new(&agent_config.graph))
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

        // 8. HTTP server (health, metrics, debug endpoints)
        let http_handle = if let Some(ref bind) = agent_config.metrics_bind {
            let (metrics, registry) = export::metrics::AgentMetrics::new();
            let state = export::http_server::AppState {
                registry: Arc::new(registry),
                stats: event_loop.stats().clone(),
                metrics,
                worker_count: agent_config.max_worker_count,
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

        // Consume events from the kernel and route to workers.
        // This is the main blocking task that drives the system.
        tokio::select! {
            result = event_loop.run(event_source, tls_rescan_tx) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "Event loop exited with error");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
            }
        }

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
    }

    #[cfg(target_os = "linux")]
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Args;

    #[test]
    fn test_cli_default_args() {
        let args = Args::parse_from(["panopticon-agent"]);
        assert_eq!(args.interface, vec!["eth0"]);
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
    fn test_cli_default_no_config() {
        let args = Args::parse_from(["panopticon-agent"]);
        assert!(args.config.is_none());
        assert!(args.metrics_bind.is_none());
    }
}
