use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod capture_gate;
#[cfg(feature = "compression")]
mod compression;
mod config;
mod event_loop;
mod export;
mod graph;
// Driven by the Linux capture path only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod io_gate;
mod k8s;
#[cfg(target_os = "linux")]
mod loader;
mod pii;
// Driven by the Linux capture path only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod pipeline;

#[cfg(test)]
mod narrowing_tests;
mod platform;
mod protocol;
pub mod replay;
#[cfg(target_os = "linux")]
mod scope_loader;
// Driven by the Linux capture path only.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod scope_publisher;
mod scope_select;
#[cfg(test)]
mod statics_check;
#[allow(dead_code)]
mod test_hooks;
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

    /// What captured data may leave the agent: `full` (unredacted export and
    /// raw dump allowed), `redacted` (PII masked; default) or `metrics_only`
    /// (metrics, service map and PII audit only). Overrides `[privacy] mode`.
    #[arg(long, env = "PANOPTICON_PRIVACY_MODE", value_name = "full|redacted|metrics_only",
          value_parser = config::PrivacyMode::NAMES)]
    privacy_mode: Option<String>,

    /// Write every captured event, UNREDACTED, including decrypted TLS, to
    /// this file (PNCAP format, owner-only permissions, truncated at start).
    /// Needs --privacy-mode full. Decode with --decode-capture.
    #[arg(long, value_name = "FILE")]
    capture_raw: Option<String>,

    /// Print a raw capture file as JSON lines (metadata + base64 payload), then exit.
    /// With --pcap, write a Wireshark-readable pcap file instead.
    /// Needs no privileges, but needs --privacy-mode full (the output is unredacted).
    #[arg(long, value_name = "FILE")]
    decode_capture: Option<String>,

    /// With --decode-capture: write the capture to this classic pcap file
    /// (raw IPv4, synthesized TCP/UDP headers) for Wireshark or tshark.
    #[arg(long, value_name = "OUT", requires = "decode_capture")]
    pcap: Option<String>,

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

const FULL_MODE_WARNING: &str = "PRIVACY MODE FULL: captured payloads, including DECRYPTED \
     TLS traffic, credentials and personal data, are written UNREDACTED to the configured \
     export and dump files. Restrict access to them and delete them when done.";

/// The privacy mode for the offline tools (`--decode-capture`, `--pcap`):
/// `--privacy-mode`, else the config file's `[privacy] mode`, else the default.
fn offline_privacy_mode(args: &Args) -> Result<config::PrivacyMode> {
    if let Some(mode) = args
        .privacy_mode
        .as_deref()
        .and_then(config::PrivacyMode::parse)
    {
        return Ok(mode);
    }
    Ok(match &args.config {
        Some(path) => config::load_config(path)?.privacy_mode,
        None => config::AgentConfig::default().privacy_mode,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(unix)]
    if args.decode_capture.is_some() {
        // The capture holds every payload unredacted, TLS decrypted: decoding
        // it is a full-mode operation like writing it.
        let mode = offline_privacy_mode(&args)?;
        if mode != config::PrivacyMode::Full {
            anyhow::bail!(
                "--decode-capture prints raw, unredacted payloads (decrypted TLS, \
                 credentials, personal data); it needs --privacy-mode full, but the \
                 mode is \"{mode}\""
            );
        }
        eprintln!("panopticon: WARNING: {FULL_MODE_WARNING}");
    }

    #[cfg(unix)]
    if let (Some(input), Some(out)) = (&args.decode_capture, &args.pcap) {
        let (records, skipped) = export::pcap::convert_file(input, out)?;
        eprintln!("wrote {records} packets to {out} ({skipped} events without payload skipped)");
        return Ok(());
    }

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

    // Initialize tracing subscriber with env filter. Each capture pipeline
    // gets its own subscriber with the same filter (pipeline.rs).
    let log_filter = log_directives(args.verbose, std::env::var("RUST_LOG").ok());
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&log_filter))
        .with_target(true)
        .init();
    install_panic_hook();

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

        // Disable core dumps to prevent PII leakage. Capture never starts
        // without it (DESIGN §3): a core dump would carry everything the
        // process holds, past any gate.
        disable_core_dumps()?;
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
        let cli_privacy = args
            .privacy_mode
            .as_deref()
            .and_then(config::PrivacyMode::parse);
        if let Some(mode) = cli_privacy {
            agent_config.privacy_mode = mode;
        }
        // After every override: nothing may contradict the privacy mode.
        config::apply_privacy(&mut agent_config)?;
        protocol::set_mask_credentials(agent_config.mask_credentials);
        protocol::set_credential_rules(config::credential_rules(&agent_config)?);
        info!(
            patterns = agent_config.credential_patterns.len(),
            builtin = ?agent_config.credential_builtin,
            "Credential rules"
        );
        if !agent_config.mask_credentials {
            eprintln!(
                "panopticon: WARNING: [privacy] mask_credentials = false: login secrets are exported unmasked"
            );
            tracing::warn!(
                "[privacy] mask_credentials = false: login secrets are exported unmasked"
            );
        }
        let privacy_mode = agent_config.privacy_mode;
        info!(mode = %privacy_mode, "Privacy mode");
        info!(
            pid_filter = ?agent_config.pid_filter,
            cgroup_filter = ?agent_config.cgroup_filter,
            pod_filter = ?agent_config.pod_filter,
            sampling_mode = ?agent_config.sampling_mode,
            sample_rate = agent_config.sample_rate,
            "Capture scope"
        );
        // pid_filter identities, read before anything is attached: arm leaves
        // out a PID whose process has changed since (scope_loader::arm).
        let pid_candidates = agent_config
            .pid_filter
            .as_deref()
            .map(scope_loader::snapshot_candidates);
        if privacy_mode == config::PrivacyMode::Full {
            // Also on stderr: RUST_LOG=error must not hide it.
            eprintln!("panopticon: WARNING: {FULL_MODE_WARNING}");
            tracing::warn!("{FULL_MODE_WARNING}");
        }
        if let Some(ref path) = args.replay_bench {
            return replay_bench(&agent_config, path).await;
        }
        if agent_config.interfaces.is_empty()
            && agent_config.capture_backend == config::CaptureBackend::Tc
        {
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
                 Kernels with CAP_BPF (5.8+, RHEL 8's 4.18) need CAP_BPF + \
                 CAP_PERFMON + CAP_NET_ADMIN; older kernels need CAP_SYS_ADMIN."
            );
        }

        // Kubernetes metadata (pod/service names for graph nodes and exports).
        // Starts a background sync and returns at once; never fails startup
        // unless pod_filter needs it.
        let k8s_metadata = k8s::K8sMetadata::start(&agent_config.kubernetes);
        // pod_filter: this node's matching pods, after the first sync
        // (bounded wait), resolved to cgroups before arming.
        let selected_pods = match (&agent_config.pod_filter, &k8s_metadata) {
            (None, _) => Vec::new(),
            (Some(filters), Some(meta)) => scope_select::startup_pods(meta, filters).await,
            (Some(_), None) => anyhow::bail!(
                "refusing pod_filter: Kubernetes metadata is not available (not in a pod, \
                 or the API client could not be set up)"
            ),
        };

        let mut programs = loader::load_and_attach(
            &agent_config.interfaces,
            &caps,
            &agent_config,
            pid_candidates,
            &selected_pods,
        )?;

        // 1. Extract EventSource (RingBuf or PerfEventArray) BEFORE wrapping Ebpf in Arc<Mutex>.
        //    This breaks the borrow chain — event loop no longer needs &mut Ebpf.
        let event_source = loader::take_event_source(&mut programs.ebpf, &caps)
            .context("Failed to initialize event source from eBPF maps")?;
        let kernel_drops = loader::take_per_cpu_counters(&mut programs.ebpf, "KERNEL_DROPS");
        let cgroup_backend = agent_config.capture_backend == config::CaptureBackend::CgroupSkb;
        let (scope_drops, vrf_events) = if cgroup_backend {
            (
                loader::take_per_cpu_counters(&mut programs.ebpf, "SCOPE_DROPS"),
                loader::take_per_cpu_counters(&mut programs.ebpf, "VRF_EVENTS"),
            )
        } else {
            (None, None)
        };

        // 2. Initial TLS library scan (still has exclusive &mut access)
        let mut attached_libs = HashSet::new();
        if agent_config.tls_scan_enabled {
            let targets = platform::proc_scanner::scan_all_processes();
            let mut tls_probes = 0;
            for target in &targets {
                tls_probes += loader::attach_tls_uprobes(
                    &mut programs.ebpf,
                    target,
                    &mut programs._links,
                    programs.go_reads,
                );
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
        let programs_cgroup_root = programs.cgroup_root.take();
        let shared_ebpf = Arc::new(Mutex::new(loader::EbpfState {
            ebpf: programs.ebpf,
            links: programs._links,
            attached_libs,
            go_reads: programs.go_reads,
        }));
        let cgroup_root = programs_cgroup_root;

        // 4. Background TLS scanner (periodic; it takes no input from the
        //    capture path).
        let scanner_handle = agent_config.tls_scan_enabled.then(|| {
            tokio::spawn(platform::proc_scanner::tls_scanner_task(
                Arc::clone(&shared_ebpf),
                agent_config.tls_scan_interval,
            ))
        });

        // 5. The privacy mode in effect, shared by the workers and every
        //    writer: a reload can only tighten it, and the writers check
        //    each record.
        let privacy = Arc::new(config::PrivacyGate::new(agent_config.privacy_mode));

        // 6. Outputs and everything else that outlives capture pipelines,
        //    then the first pipeline (DESIGN §3: everything after the ring
        //    read is one disposable pipeline).
        let shared = Arc::new(pipeline::Shared::open(
            agent_config.clone(),
            Arc::clone(&privacy),
            k8s_metadata.clone(),
            log_filter,
        )?);
        if agent_config.otlp.enabled {
            info!(
                endpoint = %agent_config.otlp.endpoint,
                service_name = %agent_config.otlp.service_name,
                "OTLP gRPC export enabled"
            );
        }
        if agent_config.graph.enabled {
            info!("Service graph enabled");
        }
        let admission_floor = event_loop::AdmissionFloor::default();
        let scope = pipeline::Scope::start(Arc::clone(&shared), admission_floor.clone())
            .context("cannot start the capture pipeline")?;

        // 7. The ring readers.
        let event_loop = event_loop::EventLoop::new(
            agent_config.clone(),
            Arc::clone(&shared.stats),
            scope.slot(),
            admission_floor,
        );

        // 7b. The scope publisher (cgroup_skb backend): reloads of the
        //     cgroup selectors and the scope options, Kubernetes pod changes
        //     and (cgroup selector only) the net_cls watch.
        let cgroup_selector =
            loader::scope_config(&agent_config).0 & panopticon_common::scope::SCOPE_SEL_CGROUP != 0;
        let (scope_tx, publisher_handle) = match &cgroup_root {
            Some(root) => {
                let mut publisher = scope_publisher::Publisher::new(
                    scope_publisher::AyaMaps(Arc::clone(&shared_ebpf)),
                    Arc::clone(&scope),
                    root.clone(),
                    k8s_metadata.clone(),
                    std::env::var("NODE_NAME").ok().filter(|n| !n.is_empty()),
                    agent_config.cgroup_filter.as_deref().unwrap_or_default(),
                    agent_config.pod_filter.as_deref().unwrap_or_default(),
                    config::ScopeOptions::of(&agent_config),
                )
                .context("cannot start the scope publisher")?;
                // The first reconciliation (pods may have changed since
                // startup selected them), before the readers start and
                // before the agent reports ready. Err: disarming failed.
                publisher
                    .pods_changed()
                    .await
                    .context("scope publisher: first reconciliation failed")?;
                let (tx, rx) = tokio::sync::mpsc::channel(16);
                // §3.2: the cgroup selector stops admitting if a v1
                // net_cls/net_prio hierarchy appears at runtime (refused at
                // startup already).
                if cgroup_selector {
                    scope_select::spawn_net_cls_watch(tx.clone());
                }
                (
                    Some(tx),
                    Some(tokio::spawn(scope_publisher::run(publisher, rx))),
                )
            }
            None => (None, None),
        };
        // 8. HTTP server (health, metrics, debug endpoints).
        //    Probes are attached at this point, so the agent is ready; the flag
        //    is cleared again as soon as shutdown begins.
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let event_stats = Arc::clone(&shared.stats);
        if kernel_drops.is_some() || scope_drops.is_some() {
            let stats = event_stats.clone();
            tokio::spawn(async move {
                use std::sync::atomic::Ordering::Relaxed;
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    if let Some(map) = &kernel_drops {
                        stats
                            .kernel_drops
                            .store(loader::sum_per_cpu(map, 0), Relaxed);
                    }
                    if let Some(map) = &scope_drops {
                        for (i, c) in stats.scope_drops.iter().enumerate() {
                            c.store(loader::sum_per_cpu(map, i as u32), Relaxed);
                        }
                    }
                    if let Some(map) = &vrf_events {
                        for (i, c) in stats.vrf_events.iter().enumerate() {
                            c.store(loader::sum_per_cpu(map, i as u32), Relaxed);
                        }
                    }
                }
            });
        }
        let http_handle = if let Some(ref bind) = agent_config.metrics_bind {
            let (mut metrics, mut registry) = export::metrics::AgentMetrics::new();
            if cgroup_backend {
                metrics.register_scope_drops(&mut registry);
            }
            let state = export::http_server::AppState {
                registry: Arc::new(registry),
                stats: Arc::clone(&shared.stats),
                metrics,
                worker_count: agent_config.max_worker_count,
                ready: Arc::clone(&ready),
                raw_capture: shared.raw.clone(),
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
        let running_can_redact = config::can_redact(&agent_config.pii);
        let shared_config = Arc::new(ArcSwap::from_pointee(agent_config));
        let config_path_for_reload = args.config.clone();
        let config_swap = Arc::clone(&shared_config);
        let reload_scope_tx = scope_tx.clone();
        let reload_k8s = k8s_metadata.is_some();
        let sighup_handle = tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("failed to register SIGHUP handler");
            loop {
                sig.recv().await;
                if let Some(ref path) = config_path_for_reload {
                    let reloaded = config::load_config(path).and_then(|mut c| {
                        // --privacy-mode keeps overriding the file.
                        if let Some(mode) = cli_privacy {
                            c.privacy_mode = mode;
                        }
                        config::apply_privacy(&mut c)?;
                        Ok(c)
                    });
                    match reloaded {
                        Ok(new_config) => {
                            // The privacy mode may only get stricter at
                            // runtime; widening it needs a restart.
                            let current = privacy.get();
                            let requested = new_config.privacy_mode;
                            let check = config::check_reload(
                                current,
                                requested,
                                running_can_redact,
                            )
                            .and_then(|()| {
                                if new_config.mask_credentials
                                    != protocol::mask_credentials_enabled()
                                {
                                    Err("changing [privacy] mask_credentials needs a restart"
                                        .into())
                                } else {
                                    Ok(())
                                }
                            })
                            .and_then(|()| {
                                config::check_restart_only(&config_swap.load(), &new_config)
                            })
                            .and_then(|()| {
                                if new_config.pod_filter.is_some() && !reload_k8s {
                                    Err("pod_filter needs Kubernetes metadata, which is not \
                                         available"
                                        .into())
                                } else {
                                    Ok(())
                                }
                            });
                            // cgroup_filter / pod_filter, capture_loopback,
                            // pid_filter_listener: the scope publisher
                            // applies the change (a narrowing revokes the
                            // capture pipeline) and replies once applied; it
                            // rejects selectors that do not resolve. The
                            // options can only differ on cgroup_skb (they
                            // are refused on tc), where it runs.
                            let running = config_swap.load_full();
                            let options = config::ScopeOptions::of(&new_config);
                            let rescope = running.cgroup_filter != new_config.cgroup_filter
                                || running.pod_filter != new_config.pod_filter
                                || config::ScopeOptions::of(&running) != options;
                            let check = match (check, rescope, &reload_scope_tx) {
                                (Ok(()), true, Some(tx)) => {
                                    let (reply, applied) = tokio::sync::oneshot::channel();
                                    let sent = tx
                                        .send(scope_publisher::ScopeMsg::Reload {
                                            cgroup_filter: new_config.cgroup_filter.clone(),
                                            pod_filter: new_config.pod_filter.clone(),
                                            options,
                                            reply,
                                        })
                                        .await;
                                    match (sent, applied.await) {
                                        (Ok(()), Ok(r)) => r,
                                        _ => Err("the scope publisher has stopped".into()),
                                    }
                                }
                                (check, _, _) => check,
                            };
                            if let Err(why) = check.and_then(|()| {
                                privacy
                                    .tighten(requested)
                                    .then_some(())
                                    .ok_or_else(|| "a wider privacy mode needs a restart".into())
                            }) {
                                tracing::error!(
                                    current = %current,
                                    requested = %requested,
                                    "Config reload rejected: {why}; keeping the current config"
                                );
                                continue;
                            }
                            if requested != current {
                                tracing::warn!(
                                    from = %current,
                                    to = %requested,
                                    "Privacy mode tightened at runtime"
                                );
                            }
                            // Validated at load; fields protected from here on
                            // use the new rules (a message already being
                            // scanned finishes with the old ones).
                            match config::credential_rules(&new_config) {
                                Ok(rules) => protocol::set_credential_rules(rules),
                                Err(e) => {
                                    tracing::error!(error = %e, "Credential rules not reloaded")
                                }
                            }
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
            result = event_loop.run(event_source) => {
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
            e = publisher_failed(publisher_handle, &shared_ebpf, &scope) => {
                exit_result = Err(e);
            }
        }
        ready.store(false, std::sync::atomic::Ordering::Relaxed);

        // 10. Cleanup — abort background tasks, then drain the current
        //     pipeline and flush its outputs (a revoked one never flushes).
        sighup_handle.abort();
        if let Some(h) = http_handle {
            h.abort();
        }
        if let Some(h) = scanner_handle {
            h.abort();
        }
        drop(scope_tx);
        scope.shutdown().await;

        exit_result
    }
}

/// A panic message can quote the data being processed (a string slice out
/// of a payload): print only where it happened, in every privacy mode
/// (DESIGN §3). stderr is outside every pipeline gate.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("{}", panic_line(info.location()));
    }));
}

fn panic_line(at: Option<&std::panic::Location<'_>>) -> String {
    let at = at.map_or_else(|| "unknown location".to_string(), |l| l.to_string());
    format!("thread panicked at {at} (message withheld: it may quote captured data)")
}

/// `prctl(PR_SET_DUMPABLE, 0)`, checked: the agent refuses to start capture
/// when it fails.
#[cfg(target_os = "linux")]
fn disable_core_dumps() -> Result<()> {
    // SAFETY: a plain syscall with integer arguments.
    check_prctl(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) })
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn check_prctl(ret: i32) -> Result<()> {
    if ret != 0 {
        anyhow::bail!(
            "refusing to start: prctl(PR_SET_DUMPABLE, 0) failed ({}); a core dump \
             could expose captured data",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// The publisher task ending, for any reason, is a fatal capture stop
/// (disarm, revoke, log): resolves with the error the agent exits with.
/// Never resolves without a publisher.
#[cfg(target_os = "linux")]
async fn publisher_failed(
    handle: Option<tokio::task::JoinHandle<Result<()>>>,
    ebpf: &std::sync::Arc<std::sync::Mutex<loader::EbpfState>>,
    scope: &pipeline::Scope,
) -> anyhow::Error {
    match handle {
        Some(h) => {
            scope_publisher::supervise(
                h,
                scope_publisher::AyaMaps(std::sync::Arc::clone(ebpf)),
                scope,
            )
            .await
        }
        None => std::future::pending().await,
    }
}

/// The log filter directives: `debug` with `--verbose`, else `RUST_LOG`
/// when it parses, else `info`.
fn log_directives(verbose: bool, rust_log: Option<String>) -> String {
    if verbose {
        return "debug".to_string();
    }
    rust_log
        .filter(|f| EnvFilter::try_new(f).is_ok())
        .unwrap_or_else(|| "info".to_string())
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

    use super::{Args, check_prctl, config, offline_privacy_mode, panic_line};

    #[test]
    fn log_directives_follow_verbose_then_rust_log() {
        use super::log_directives;
        assert_eq!(log_directives(true, Some("warn".into())), "debug");
        assert_eq!(log_directives(false, Some("warn".into())), "warn");
        assert_eq!(log_directives(false, Some("=[".into())), "info");
        assert_eq!(log_directives(false, None), "info");
    }

    #[test]
    fn prctl_failure_refuses_to_start() {
        assert!(check_prctl(0).is_ok());
        let err = check_prctl(-1).unwrap_err().to_string();
        assert!(err.contains("refusing to start"), "{err}");
    }

    #[test]
    fn panic_line_names_the_location_only() {
        let line = panic_line(Some(std::panic::Location::caller()));
        assert!(line.contains("main.rs"), "{line}");
        assert!(line.contains("withheld"), "{line}");
        assert!(panic_line(None).contains("unknown location"));
    }

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
    fn test_cli_privacy_mode() {
        let args = Args::parse_from(["panopticon-agent"]);
        assert!(args.privacy_mode.is_none());
        for mode in ["full", "redacted", "metrics_only"] {
            let args = Args::parse_from(["panopticon-agent", "--privacy-mode", mode]);
            assert_eq!(args.privacy_mode.as_deref(), Some(mode));
        }
        assert!(Args::try_parse_from(["panopticon-agent", "--privacy-mode", "all"]).is_err());
    }

    #[test]
    fn test_offline_decode_needs_full_mode() {
        let mode = |argv: &[&str]| offline_privacy_mode(&Args::try_parse_from(argv).unwrap());
        let base = ["panopticon-agent", "--decode-capture", "raw.pncap"];
        assert_eq!(mode(&base).unwrap(), config::PrivacyMode::Redacted);
        let with = |extra: &[&'static str]| [&base[..], extra].concat();
        assert_eq!(
            mode(&with(&["--pcap", "o.pcap", "--privacy-mode", "full"])).unwrap(),
            config::PrivacyMode::Full
        );
        assert_eq!(
            mode(&with(&["--privacy-mode", "metrics_only"])).unwrap(),
            config::PrivacyMode::MetricsOnly
        );
    }

    #[test]
    fn test_cli_pcap_requires_decode_capture() {
        assert!(Args::try_parse_from(["panopticon-agent", "--pcap", "out.pcap"]).is_err());
        let args = Args::parse_from([
            "panopticon-agent",
            "--decode-capture",
            "dump.pncap",
            "--pcap",
            "out.pcap",
        ]);
        assert_eq!(args.pcap.as_deref(), Some("out.pcap"));
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

    let privacy = std::sync::Arc::new(config::PrivacyGate::new(config.privacy_mode));
    let shared = pipeline::Shared::for_replay(config.clone(), privacy)?;
    let stats = std::sync::Arc::clone(&shared.stats);
    let pipeline = pipeline::Pipeline::build(&shared)?;

    let n = events.len();
    let start = std::time::Instant::now();
    pipeline.replay(&events).await;
    pipeline.shutdown().await;
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "events={n} elapsed={elapsed:.3}s rate={:.0}/s per_event={:.2}us pii_detections={} parser_errors={}",
        n as f64 / elapsed,
        elapsed * 1e6 / n.max(1) as f64,
        stats.pii_detections.load(Ordering::Relaxed),
        stats.drops_parser_error.load(Ordering::Relaxed),
    );
    Ok(())
}
