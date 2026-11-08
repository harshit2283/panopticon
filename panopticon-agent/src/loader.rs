use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::Array,
    programs::{KProbe, ProgramError, SchedClassifier, TracePoint, UProbe, tc::TcAttachType},
};
use tracing::{debug, info, warn};

use crate::config::{AgentConfig, CaptureBackend, SamplingMode};
use crate::platform::proc_scanner::{GoVersion, TlsTarget, TlsType};
use crate::scope_loader::{self, ScopeSetup};
use panopticon_common::{
    CONFIG_CAPTURE_ENABLED, CONFIG_COOKIE_KEY, CONFIG_HEAD_BYTES, CONFIG_MAX_PAYLOAD,
    CONFIG_PID_EPOCH, CONFIG_PID_FILTER_ON, CONFIG_RING_SHARD_MASK, CONFIG_SAMPLE_THRESHOLD,
    CONFIG_SCOPE_ARMED, CONFIG_SCOPE_GEN, CONFIG_SCOPE_MODE, CONFIG_TCP_SYN_EVENTS,
    CONFIG_USE_RINGBUF, DATA_RING_SHARDS, MAX_PAYLOAD_SIZE, scope,
};

/// The kernel scope settings of `config`: `(CONFIG_SCOPE_MODE,
/// CONFIG_SAMPLE_THRESHOLD, CONFIG_HEAD_BYTES)`. All zero on the TC backend,
/// where the kernel scope rules stay off and nothing changes.
pub fn scope_config(config: &AgentConfig) -> (u64, u64, u64) {
    if config.capture_backend != CaptureBackend::CgroupSkb {
        return (0, 0, 0);
    }
    let mut mode = 0;
    if config.pid_filter.is_some() {
        mode |= scope::SCOPE_SEL_PID;
    }
    if config.cgroup_filter.is_some() || config.pod_filter.is_some() {
        mode |= scope::SCOPE_SEL_CGROUP;
    }
    let mut threshold = 0;
    let mut head = 0;
    match config.sampling_mode {
        SamplingMode::Full => {}
        // Rate 1 is `full` (DESIGN §3.4), which keeps TLS plaintext.
        SamplingMode::ConnectionSample if config.sample_rate >= 1.0 => {}
        SamplingMode::ConnectionSample => {
            mode |= scope::SCOPE_SAMPLE;
            threshold = scope::sample_threshold(config.sample_rate);
        }
        SamplingMode::HeadOnly { max_bytes } => {
            mode |= scope::SCOPE_HEAD;
            head = max_bytes;
        }
    }
    (mode, threshold, head)
}

/// The DATA_EVENTS ring shards in the eBPF object (maps.rs `data_rings!`).
const DATA_RING_NAMES: [&str; DATA_RING_SHARDS] = [
    "DATA_EVENTS_0",
    "DATA_EVENTS_1",
    "DATA_EVENTS_2",
    "DATA_EVENTS_3",
    "DATA_EVENTS_4",
    "DATA_EVENTS_5",
    "DATA_EVENTS_6",
    "DATA_EVENTS_7",
    "DATA_EVENTS_8",
    "DATA_EVENTS_9",
    "DATA_EVENTS_10",
    "DATA_EVENTS_11",
    "DATA_EVENTS_12",
    "DATA_EVENTS_13",
    "DATA_EVENTS_14",
    "DATA_EVENTS_15",
];

/// Ring buffer memory split over the active shards. Records carry only the
/// captured payload, so this holds many more small packets than the same
/// bytes of fixed 4KB records did.
const DATA_RING_TOTAL_BYTES: u32 = 16 * 1024 * 1024;

/// Active DATA_EVENTS shards: one per 4 online CPUs, as a power of two in
/// 1..=16 (64 CPUs: 16, 8 CPUs: 2). Every CPU of the node produces into the
/// rings, so this counts the node's CPUs, not the agent's affinity mask.
pub fn ring_shard_count() -> usize {
    // SAFETY: sysconf has no preconditions.
    let cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as usize;
    (cpus / 4).clamp(1, DATA_RING_SHARDS).next_power_of_two()
}

fn pinned_map_names() -> impl Iterator<Item = &'static str> {
    PINNED_MAP_NAMES.into_iter().chain(DATA_RING_NAMES)
}

/// Never a capture-scope map (SOCK_STATE, CGROUP_ALLOW, SCOPE_DROPS and the
/// pid_filter maps): their contents are only valid for the run that wrote
/// them. CONFIG is pinned, so its scope words are rewritten at every start.
const PINNED_MAP_NAMES: [&str; 10] = [
    "DATA_EVENTS_PERF",
    "PROCESS_EVENTS",
    "CONN_MAP",
    "PID_CGROUP_MAP",
    "CONFIG",
    "TLS_SCRATCH",
    "GO_ABI_MAP",
    "PID_TO_CONN",
    "IPV6_DROPS",
    "EVENT_SCRATCH",
];

/// Detected kernel capabilities that determine which eBPF features are available.
#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub version: (u32, u32, u32),
    /// RingBuf support, probed by creating a ring buffer map (5.8+ upstream,
    /// backported to RHEL 8's 4.18).
    pub has_ringbuf: bool,
    /// BTF (BPF Type Format) available — /sys/kernel/btf/vmlinux exists.
    pub has_btf: bool,
    /// Cgroup ID helper available (kernel >= 4.18).
    pub has_cgroup_id: bool,
    /// TC eBPF hooks available (kernel >= 4.15).
    pub has_tc_ebpf: bool,
}

/// Holds loaded eBPF programs and their attachment links.
/// Links must be kept alive — dropping them detaches the probes.
pub struct LoadedPrograms {
    pub ebpf: Ebpf,
    /// Heterogeneous link types kept alive via type erasure.
    pub _links: Vec<Box<dyn std::any::Any + Send>>,
}

/// Shared eBPF state for concurrent access between event loop and scanner.
pub struct EbpfState {
    pub ebpf: Ebpf,
    pub links: Vec<Box<dyn std::any::Any + Send>>,
    /// `(device_id, inode)` pairs of already-attached libraries —
    /// handles symlinks and mount namespace ambiguity.
    pub attached_libs: HashSet<(u64, u64)>,
}

/// Detect kernel capabilities from /proc/version, sysfs and a BPF map probe.
pub fn detect_kernel_caps() -> Result<KernelCapabilities> {
    let version = read_kernel_version()?;
    let (major, minor, _patch) = version;

    // Probe instead of trusting the version: RHEL 8's 4.18 has the ring
    // buffer backported. Fall back to the version only if probing errors
    // (e.g. no privilege, or not Linux).
    let has_ringbuf =
        aya::sys::is_map_supported(aya::maps::MapType::RingBuf).unwrap_or((major, minor) >= (5, 8));

    Ok(KernelCapabilities {
        version,
        has_ringbuf,
        has_btf: Path::new("/sys/kernel/btf/vmlinux").exists(),
        has_cgroup_id: (major, minor) >= (4, 18),
        has_tc_ebpf: (major, minor) >= (4, 15),
    })
}

/// Load eBPF programs and attach to the specified interface and kernel hooks.
///
/// Each attachment is wrapped in a match — failure logs and continues.
/// Returns the loaded programs with links kept alive.
pub fn load_and_attach(
    interfaces: &[String],
    caps: &KernelCapabilities,
    config: &AgentConfig,
    pid_candidates: Option<Vec<scope_loader::Candidate>>,
    pods: &[crate::scope_select::SelectedPod],
) -> Result<LoadedPrograms> {
    if !caps.has_tc_ebpf {
        anyhow::bail!(
            "Kernel {}.{}.{} does not support TC eBPF (requires >= 4.15)",
            caps.version.0,
            caps.version.1,
            caps.version.2
        );
    }

    let mut ebpf = load_ebpf_bytes(config.map_pin_path.as_deref()).map_err(|e| {
        if caps.has_ringbuf {
            e
        } else {
            e.context(format!(
                "kernel {}.{}.{} has no BPF ring buffer: the agent needs it and the 5.5+ \
                 probe-read helpers (upstream 5.8+, or a distro kernel with them \
                 backported, such as RHEL 8's 4.18)",
                caps.version.0, caps.version.1, caps.version.2
            ))
        }
    })?;
    let mut links: Vec<Box<dyn std::any::Any + Send>> = Vec::new();

    // Write initial config to eBPF CONFIG map
    sync_config_to_ebpf(&mut ebpf, config, caps)?;

    // ── cgroup_skb backend: scope writers, then capture (DESIGN §7) ───
    let cgroup_backend = config.capture_backend == CaptureBackend::CgroupSkb;
    let mut exit_tp_attached = false;
    if cgroup_backend {
        let setup = ScopeSetup {
            mode: scope_config(config).0,
            tls: config.tls_scan_enabled,
            cgroup2_path: config.cgroup2_path.clone(),
        };
        let cgroup_sel = setup.mode & scope::SCOPE_SEL_CGROUP != 0;
        let paths = config.cgroup_filter.as_deref().unwrap_or_default();
        // CGROUP_ALLOW is published before anything is attached (and so
        // before arm); the selector's refusals come first.
        let select = |ebpf: &mut Ebpf, root: &scope_loader::CgroupRoot| {
            if cgroup_sel {
                crate::scope_select::startup_publish(ebpf, root.path(), paths, pods)
            } else {
                Ok(())
            }
        };
        let (_root, exit_tp) =
            scope_loader::load_and_attach(&mut ebpf, &setup, pid_candidates, select, &mut links)?;
        exit_tp_attached = exit_tp;
    }
    let interfaces: &[String] = if cgroup_backend { &[] } else { interfaces };

    // ── TC classifiers (ingress + egress) per interface ───────────────
    if !cgroup_backend {
        ensure_tc_program_loaded(&mut ebpf, "tc_ingress")?;
        ensure_tc_program_loaded(&mut ebpf, "tc_egress")?;
    }
    let mut tc_links_attached = 0usize;
    for iface in interfaces {
        if attach_tc_classifier(
            &mut ebpf,
            iface,
            "tc_ingress",
            TcAttachType::Ingress,
            &mut links,
        ) {
            tc_links_attached += 1;
        }
        if attach_tc_classifier(
            &mut ebpf,
            iface,
            "tc_egress",
            TcAttachType::Egress,
            &mut links,
        ) {
            tc_links_attached += 1;
        }
    }

    // ── Connection owners (client/server PIDs) ────────────────────────
    // kprobes where the kernel has them (both sides), else the
    // inet_sock_set_state tracepoint (connecting side only). Not on
    // cgroup_skb (DESIGN §8): they report the tuple and PID of every
    // connection on the node, outside any kernel scope decision; the
    // kernel stamps owner_tgid / acceptor_tgid into captured events instead.
    if !cgroup_backend {
        let connect_kprobe = attach_kprobe(&mut ebpf, "tcp_connect", "tcp_connect", &mut links);
        attach_kretprobe(
            &mut ebpf,
            "inet_csk_accept_ret",
            "inet_csk_accept",
            &mut links,
        );
        if !connect_kprobe {
            attach_tracepoint(
                &mut ebpf,
                "sock_state_connect",
                "sock",
                "inet_sock_set_state",
                &mut links,
            );
        }
    }
    let restricted_scope = !scope::is_unscoped_full(scope_config(config).0);
    if config.tls_scan_enabled && restricted_scope {
        // Restricted modes (cgroup_skb): a socket's tuple is recorded only
        // if that socket is itself in scope, which needs its SOCK_STATE.
        // Only fentry can read it; the tracepoint and kprobe variants are
        // never attached here (tls_probes.rs `tls_tcp_sendmsg_scoped`).
        for (prog, function) in [
            ("tls_tcp_sendmsg_scoped", "tcp_sendmsg"),
            ("tls_tcp_recvmsg_scoped", "tcp_recvmsg"),
        ] {
            if !attach_fentry(&mut ebpf, prog, function, &mut links) {
                warn!(
                    prog,
                    function,
                    "restricted capture scope needs fentry with sk_storage for TLS socket \
                     addresses; tracepoint and kprobe fallbacks refused, TLS events will \
                     carry no addresses"
                );
            }
        }
    } else if config.tls_scan_enabled {
        // Give TLS connections their socket addresses (see tls_probes.rs):
        // sock tracepoints (6.3+, RHEL 9) when their record layout matches,
        // else fentry where the kernel has BTF, else kprobes.
        for (tracepoint, fentry_prog, kprobe_prog, function) in [
            (
                "sock_send_length",
                "tls_tcp_sendmsg_fentry",
                "tls_tcp_sendmsg",
                "tcp_sendmsg",
            ),
            (
                "sock_recv_length",
                "tls_tcp_recvmsg_fentry",
                "tls_tcp_recvmsg",
                "tcp_recvmsg",
            ),
        ] {
            let tp_prog = format!("tls_{tracepoint}");
            match try_attach_tracepoint(&mut ebpf, &tp_prog, "sock", tracepoint) {
                Ok(link) => {
                    info!(prog = %tp_prog, "tracepoint attached");
                    links.push(Box::new(link));
                }
                Err(e) => {
                    debug!(prog = %tp_prog, error = %e, "tracepoint unavailable, falling back");
                    if !attach_fentry(&mut ebpf, fentry_prog, function, &mut links) {
                        attach_kprobe(&mut ebpf, kprobe_prog, function, &mut links);
                    }
                }
            }
        }
    }

    // ── Tracepoints for process monitoring ────────────────────────────
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exec",
        "sched",
        "sched_process_exec",
        &mut links,
    );
    if !exit_tp_attached {
        attach_tracepoint(
            &mut ebpf,
            "sched_process_exit",
            "sched",
            "sched_process_exit",
            &mut links,
        );
    }

    info!(
        probes_attached = links.len(),
        tc_links_attached,
        tc_links_expected = interfaces.len() * 2,
        has_cgroup_id = caps.has_cgroup_id,
        interfaces = ?interfaces,
        "eBPF programs loaded and attached"
    );
    if cgroup_backend {
        info!("cgroup_skb backend: TC classifiers not attached");
    } else if interfaces.is_empty() {
        info!("No TC interfaces requested; skipping TC degraded-state warnings");
    } else if tc_links_attached == 0 {
        warn!(
            interfaces = ?interfaces,
            "No TC classifiers attached; socket lifecycle events may still appear, but payload capture will be absent"
        );
    } else if tc_links_attached < interfaces.len() * 2 {
        warn!(
            interfaces = ?interfaces,
            tc_links_attached,
            tc_links_expected = interfaces.len() * 2,
            "Only a subset of requested TC classifiers attached"
        );
    }

    Ok(LoadedPrograms {
        ebpf,
        _links: links,
    })
}

fn ensure_tc_program_loaded(ebpf: &mut Ebpf, prog_name: &str) -> Result<()> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    match prog.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Write agent config values into the eBPF CONFIG array map.
pub fn sync_config_to_ebpf(
    ebpf: &mut Ebpf,
    config: &AgentConfig,
    caps: &KernelCapabilities,
) -> Result<()> {
    // pid_filter: the list first, then the switch. A failure stops the agent
    // rather than capturing every process. A pinned map may still hold an
    // earlier run's list, so it is emptied first.
    {
        let mut pids: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
            ebpf.map_mut("PID_FILTER")
                .context("PID_FILTER map not found")?,
        )?;
        let stale: Vec<u32> = pids.keys().collect::<Result<_, _>>()?;
        for pid in stale {
            pids.remove(&pid)?;
        }
        // The cgroup_skb backend publishes the list itself, only once the
        // exit tracepoint is attached (scope_loader::arm).
        let publish = config.capture_backend != CaptureBackend::CgroupSkb;
        for &pid in config.pid_filter.iter().flatten().filter(|_| publish) {
            pids.insert(pid, 1, 0)
                .with_context(|| format!("cannot add PID {pid} to the PID_FILTER map"))?;
        }
    }
    let mut cfg_map: Array<_, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map not found")?)?;

    cfg_map.set(CONFIG_CAPTURE_ENABLED, config.capture_enabled as u64, 0)?;
    cfg_map.set(CONFIG_MAX_PAYLOAD, MAX_PAYLOAD_SIZE as u64, 0)?;
    cfg_map.set(CONFIG_USE_RINGBUF, caps.has_ringbuf as u64, 0)?;
    cfg_map.set(CONFIG_PID_FILTER_ON, config.pid_filter.is_some() as u64, 0)?;
    let syn_events = crate::capture_gate::GateConfig::from_config(config).wants_syn();
    cfg_map.set(CONFIG_TCP_SYN_EVENTS, syn_events as u64, 0)?;
    cfg_map.set(CONFIG_RING_SHARD_MASK, ring_shard_count() as u64 - 1, 0)?;
    // A fresh random key per agent start: flow cookies are not computable
    // offline. Set before TC is attached (load path), so every cookie of a
    // run uses the same key.
    use std::hash::BuildHasher;
    let cookie_key = std::collections::hash_map::RandomState::new().hash_one(0u8);
    cfg_map.set(CONFIG_COOKIE_KEY, cookie_key, 0)?;

    // Capture scope (cgroup_skb backend; all zero on TC). Set before any
    // program is attached. The epoch is random per start so `pid_bits`
    // never outlive the pid_filter they were computed under (§3.1).
    let (mode, threshold, head) = scope_config(config);
    let epoch = (std::collections::hash_map::RandomState::new().hash_one(1u8) as u32).max(1);
    cfg_map.set(CONFIG_PID_EPOCH, epoch as u64, 0)?;
    cfg_map.set(CONFIG_SAMPLE_THRESHOLD, threshold, 0)?;
    cfg_map.set(CONFIG_HEAD_BYTES, head, 0)?;
    cfg_map.set(CONFIG_SCOPE_GEN, 1, 0)?;
    cfg_map.set(CONFIG_SCOPE_MODE, mode, 0)?;
    // Disarmed until scope_loader::arm, the last step of startup. Written
    // explicitly: a pinned CONFIG map keeps an earlier run's value. The mode
    // above is set now, not at arming: capture hooks running with mode 0
    // would capture unscoped during startup.
    cfg_map.set(CONFIG_SCOPE_ARMED, 0, 0)?;

    Ok(())
}

// ── TLS Uprobe Attachment ─────────────────────────────────────────────────

/// Attach TLS uprobes to a discovered target.
/// Returns the number of successfully attached probes.
///
/// The probes go into the file the offsets were read from, opened again
/// and checked against its examined identity, and attached through
/// `/proc/self/fd/<n>`: the kernel resolves that magic link to the open
/// inode, not the workload-controlled path (F14).
pub fn attach_tls_uprobes(
    ebpf: &mut Ebpf,
    target: &TlsTarget,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> usize {
    use std::os::fd::AsRawFd;
    let file = match crate::platform::proc_scanner::open_examined(target) {
        Ok(file) => file,
        Err(e) => {
            warn!(pid = target.pid, path = %target.library_path, error = %e, "Not attaching TLS uprobes");
            return 0;
        }
    };
    let pinned = TlsTarget {
        library_path: format!("/proc/self/fd/{}", file.as_raw_fd()),
        ..target.clone()
    };
    let attached = attach_tls_uprobes_to(ebpf, &pinned, links);
    drop(file); // the uprobes hold the inode now
    if attached > 0 {
        info!(
            pid = target.pid,
            path = %target.library_path,
            probes = attached,
            "TLS uprobes attached"
        );
    }
    attached
}

/// Whether the loaded object runs a restricted capture scope
/// (`CONFIG_SCOPE_MODE` != 0, cgroup_skb only). Unreadable counts as
/// restricted: the extra return probe is a no-op in unscoped modes.
fn restricted_kernel_scope(ebpf: &Ebpf) -> bool {
    let read = || -> Option<u64> {
        let cfg: Array<_, u64> = Array::try_from(ebpf.map("CONFIG")?).ok()?;
        cfg.get(&CONFIG_SCOPE_MODE, 0).ok()
    };
    read().is_none_or(|mode| !scope::is_unscoped_full(mode))
}

/// Attach the target's probes at `target.library_path` (an fd path).
fn attach_tls_uprobes_to(
    ebpf: &mut Ebpf,
    target: &TlsTarget,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> usize {
    let mut attached = 0;
    // Restricted modes emit SSL_write* at return, with that call's own
    // socket address (tls_probes.rs `ssl_write_ret`). The return probe goes
    // first: an entry without it would open calls nothing emits.
    let write_at_return = restricted_kernel_scope(ebpf);
    let write_ret =
        |ebpf: &mut Ebpf, offset: u64, links: &mut Vec<Box<dyn std::any::Any + Send>>| {
            !write_at_return
                || attach_uretprobe(
                    ebpf,
                    "ssl_write_ret",
                    &target.library_path,
                    offset,
                    None,
                    links,
                )
        };

    match &target.tls_type {
        TlsType::OpenSsl {
            ssl_write_offset,
            ssl_read_offset,
            ssl_write_ex_offset,
            ssl_read_ex_offset,
        } => {
            // SSL_write — uprobe (pid=None for system-wide shared lib coverage)
            if write_ret(ebpf, *ssl_write_offset, links)
                && attach_uprobe(
                    ebpf,
                    "ssl_write_entry",
                    &target.library_path,
                    *ssl_write_offset,
                    None,
                    links,
                )
            {
                attached += 1;
            }

            // SSL_read — uprobe (entry)
            if attach_uprobe(
                ebpf,
                "ssl_read_entry",
                &target.library_path,
                *ssl_read_offset,
                None,
                links,
            ) {
                attached += 1;
            }

            // SSL_read — uretprobe (return)
            if attach_uretprobe(
                ebpf,
                "ssl_read_ret",
                &target.library_path,
                *ssl_read_offset,
                None,
                links,
            ) {
                attached += 1;
            }

            // SSL_write_ex / SSL_read_ex. SSL_read_ex shares the return probe.
            if let Some(offset) = *ssl_write_ex_offset
                && write_ret(ebpf, offset, links)
                && attach_uprobe(
                    ebpf,
                    "ssl_write_ex_entry",
                    &target.library_path,
                    offset,
                    None,
                    links,
                )
            {
                attached += 1;
            }
            if let Some(offset) = *ssl_read_ex_offset {
                if attach_uprobe(
                    ebpf,
                    "ssl_read_ex_entry",
                    &target.library_path,
                    offset,
                    None,
                    links,
                ) {
                    attached += 1;
                }
                if attach_uretprobe(
                    ebpf,
                    "ssl_read_ret",
                    &target.library_path,
                    offset,
                    None,
                    links,
                ) {
                    attached += 1;
                }
            }
        }
        TlsType::GoTls {
            write_offset,
            read,
            go_version,
        } => {
            match go_version {
                GoVersion::RegisterAbi => {
                    // No PID filter: like libssl, the probes cover every
                    // process running this binary (every replica on the node).
                    let path = &target.library_path;
                    if attach_uprobe(ebpf, "go_tls_write_entry", path, *write_offset, None, links) {
                        attached += 1;
                    }
                    if let Some(read) = read
                        && attach_uprobe(
                            ebpf,
                            "go_tls_read_entry",
                            path,
                            read.entry_offset,
                            None,
                            links,
                        )
                    {
                        attached += 1;
                        for &ret in &read.ret_offsets {
                            if attach_uprobe(ebpf, "go_tls_read_ret", path, ret, None, links) {
                                attached += 1;
                            }
                        }
                    }
                }
                GoVersion::StackAbi => {
                    // Stack-based ABI not supported in v1 — needs different eBPF probe
                    warn!(
                        pid = target.pid,
                        path = %target.library_path,
                        "Skipping Go TLS (stack ABI, Go < 1.17)"
                    );
                }
            }
        }
    }

    attached
}

/// Attach TLS uprobes operating on shared `EbpfState` directly.
/// Caller is responsible for locking the mutex.
pub fn attach_tls_uprobes_on_state(state: &mut EbpfState, target: &TlsTarget) -> usize {
    attach_tls_uprobes(&mut state.ebpf, target, &mut state.links)
}

fn attach_uprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    target_path: &str,
    offset: u64,
    pid: Option<i32>,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> bool {
    match try_attach_uprobe(ebpf, prog_name, target_path, offset, pid) {
        Ok(link) => {
            info!(
                prog = prog_name,
                path = target_path,
                offset,
                pid = ?pid,
                "uprobe attached"
            );
            links.push(Box::new(link));
            true
        }
        Err(e) => {
            warn!(
                prog = prog_name,
                path = target_path,
                offset,
                pid = ?pid,
                error = %e,
                error_debug = ?e,
                "Failed to attach uprobe"
            );
            false
        }
    }
}

fn try_attach_uprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    target_path: &str,
    offset: u64,
    pid: Option<i32>,
) -> Result<aya::programs::uprobe::UProbeLinkId> {
    let prog: &mut UProbe = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    match prog.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(err) => return Err(err.into()),
    }
    let link_id = prog.attach(offset, target_path, pid.map(|p| p as u32))?;
    Ok(link_id)
}

fn attach_uretprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    target_path: &str,
    offset: u64,
    pid: Option<i32>,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> bool {
    match try_attach_uretprobe(ebpf, prog_name, target_path, offset, pid) {
        Ok(link) => {
            info!(
                prog = prog_name,
                path = target_path,
                offset,
                "uretprobe attached"
            );
            links.push(Box::new(link));
            true
        }
        Err(e) => {
            warn!(prog = prog_name, path = target_path, offset, error = %e, "Failed to attach uretprobe");
            false
        }
    }
}

fn try_attach_uretprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    target_path: &str,
    offset: u64,
    pid: Option<i32>,
) -> Result<aya::programs::uprobe::UProbeLinkId> {
    let prog: &mut UProbe = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    match prog.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(err) => return Err(err.into()),
    }
    let link_id = prog.attach(offset, target_path, pid.map(|p| p as u32))?;
    Ok(link_id)
}

// ── Event Source Abstraction ──────────────────────────────────────────────

/// Abstraction over the kernel-to-user event delivery mechanism.
/// Modern kernels use the active `RingBuf` shards, older kernels fall back
/// to `PerfEventArray`.
pub enum EventSource {
    RingBuf(Vec<aya::maps::RingBuf<aya::maps::MapData>>),
    PerfEventArray(aya::maps::PerfEventArray<aya::maps::MapData>),
}

/// Extract the appropriate event source map from the eBPF object based on capabilities.
pub fn take_event_source(ebpf: &mut Ebpf, caps: &KernelCapabilities) -> Result<EventSource> {
    if caps.has_ringbuf {
        let rings = DATA_RING_NAMES[..ring_shard_count()]
            .iter()
            .map(|name| {
                let map = ebpf
                    .take_map(name)
                    .with_context(|| format!("{name} map not found in eBPF object"))?;
                aya::maps::RingBuf::try_from(map)
                    .with_context(|| format!("Failed to cast {name} to RingBuf"))
            })
            .collect::<Result<_>>()?;
        Ok(EventSource::RingBuf(rings))
    } else {
        let map = ebpf
            .take_map("DATA_EVENTS_PERF")
            .context("DATA_EVENTS_PERF map not found in eBPF object")?;
        Ok(EventSource::PerfEventArray(
            aya::maps::PerfEventArray::try_from(map)
                .context("Failed to cast DATA_EVENTS_PERF to PerfEventArray")?,
        ))
    }
}

/// Take a per-CPU counter map: `KERNEL_DROPS` (events the kernel dropped
/// because the ring buffer was full) or `SCOPE_DROPS` (cgroup_skb scope
/// drops by reason). `None` on objects built without it.
pub fn take_per_cpu_counters(
    ebpf: &mut Ebpf,
    name: &str,
) -> Option<aya::maps::PerCpuArray<aya::maps::MapData, u64>> {
    let map = ebpf.take_map(name)?;
    aya::maps::PerCpuArray::try_from(map)
        .inspect_err(|e| warn!(map = name, error = %e, "map has an unexpected type"))
        .ok()
}

/// Sum entry `index` of a per-CPU counter across CPUs.
pub fn sum_per_cpu(map: &aya::maps::PerCpuArray<aya::maps::MapData, u64>, index: u32) -> u64 {
    map.get(&index, 0).map_or(0, |v| v.iter().sum())
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn load_ebpf_bytes(map_pin_path: Option<&str>) -> Result<Ebpf> {
    // aya-build writes the compiled eBPF ELF to OUT_DIR during cargo build.
    // include_bytes_aligned! embeds it into the agent binary.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panopticon-ebpf"));

    let mut loader = EbpfLoader::new();
    // Split the ring memory over the active shards; the inactive ones are
    // never written (CONFIG_RING_SHARD_MASK), so they get a single page.
    let shards = ring_shard_count();
    // SAFETY: sysconf has no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as u32;
    let shard_bytes = (DATA_RING_TOTAL_BYTES / shards as u32).max(page);
    for (i, name) in DATA_RING_NAMES.into_iter().enumerate() {
        loader.map_max_entries(name, if i < shards { shard_bytes } else { page });
    }

    let ebpf = match map_pin_path {
        Some(pin_path) => {
            // Verify bpffs is mounted before attempting to pin
            if !verify_bpffs_mounted(pin_path) {
                warn!(
                    path = pin_path,
                    "bpffs not detected at pin path — map pinning may fail. \
                     Ensure 'mount -t bpf bpf /sys/fs/bpf' is configured."
                );
            }

            // Ensure dedicated pin directory exists
            let pin_dir = normalize_pin_dir(pin_path);
            std::fs::create_dir_all(&pin_dir).with_context(|| {
                format!("Failed to create map pin directory: {}", pin_dir.display())
            })?;

            info!(
                path = %pin_dir.display(),
                "eBPF map pinning enabled — maps will persist across restarts"
            );

            for map_name in pinned_map_names() {
                loader.map_pin_path(map_name, pin_dir.as_path());
            }
            loader.load(bytes)?
        }
        None => loader.load(bytes)?,
    };

    Ok(ebpf)
}

/// Check if bpffs is mounted at or above the given path.
/// Parses /proc/mounts for a bpf filesystem mount.
fn verify_bpffs_mounted(path: &str) -> bool {
    parse_bpffs_mounted_from_content(path, "/proc/mounts")
}

/// Inner function: reads the mounts file and checks for bpf mount.
/// Extracted so tests can use fixture content via `parse_bpffs_from_mounts_content`.
fn parse_bpffs_mounted_from_content(path: &str, mounts_path: &str) -> bool {
    if let Ok(mounts) = std::fs::read_to_string(mounts_path) {
        return parse_bpffs_from_mounts_content(path, &mounts);
    }
    false
}

/// Parse /proc/mounts content to check if bpffs is mounted at or above `path`.
fn parse_bpffs_from_mounts_content(path: &str, mounts_content: &str) -> bool {
    for line in mounts_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "bpf" && path.starts_with(parts[1]) {
            return true;
        }
    }
    false
}

/// Remove all pinned maps from the bpffs directory.
/// Call on agent uninstall or when a clean restart is desired.
#[allow(dead_code)]
pub fn unpin_maps(pin_path: &str) -> Result<usize> {
    let pin_dir = normalize_pin_dir(pin_path);
    std::fs::read_dir(&pin_dir)
        .with_context(|| format!("Failed to read pin directory: {}", pin_dir.display()))?;

    let mut removed = 0;
    for map_name in pinned_map_names() {
        let path = pin_dir.join(map_name);
        if path.exists() && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }

    info!(
        path = %pin_dir.display(),
        maps_removed = removed,
        "Unpinned eBPF maps"
    );
    Ok(removed)
}

fn normalize_pin_dir(pin_path: &str) -> std::path::PathBuf {
    let base = std::path::Path::new(pin_path);
    if base
        .file_name()
        .is_some_and(|name| name == OsStr::new("panopticon"))
    {
        base.to_path_buf()
    } else {
        base.join("panopticon")
    }
}

fn attach_tc_classifier(
    ebpf: &mut Ebpf,
    iface: &str,
    prog_name: &str,
    direction: TcAttachType,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> bool {
    match try_attach_tc(ebpf, iface, prog_name, direction) {
        Ok(link) => {
            info!(prog = prog_name, iface, "TC classifier attached");
            links.push(Box::new(link));
            true
        }
        Err(e) => {
            warn!(prog = prog_name, iface, error = %e, "Failed to attach TC classifier");
            false
        }
    }
}

fn try_attach_tc(
    ebpf: &mut Ebpf,
    iface: &str,
    prog_name: &str,
    direction: TcAttachType,
) -> Result<aya::programs::tc::SchedClassifierLinkId> {
    let _ = aya::programs::tc::qdisc_add_clsact(iface);
    // On kernels < 6.6 aya attaches via netlink clsact filters, which outlive
    // the process. After a crash/SIGKILL the old classifier keeps running, and
    // a fresh attach would stack a second one (duplicating every packet).
    // Remove stale filters with our program name first; NotFound is the
    // normal case (clean start, or TCX links on 6.6+ which die with the fd).
    match aya::programs::tc::qdisc_detach_program(iface, direction, prog_name) {
        Ok(()) => warn!(
            prog = prog_name,
            iface, "Removed stale TC classifier left by a previous agent instance"
        ),
        Err(aya::programs::tc::TcError::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
        }
        Err(e) => warn!(prog = prog_name, iface, error = %e, "Stale TC classifier cleanup failed"),
    }
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    let link_id = prog.attach(iface, direction)?;
    Ok(link_id)
}

/// Attach an fentry program; `false` (logged at debug) if the kernel lacks
/// BTF or trampoline support, so the caller can fall back to a kprobe.
fn attach_fentry(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> bool {
    let result = (|| -> Result<_> {
        let btf = aya::Btf::from_sys_fs().context("kernel BTF not available")?;
        let prog: &mut aya::programs::FEntry = ebpf
            .program_mut(prog_name)
            .context(format!("program '{prog_name}' not found"))?
            .try_into()?;
        prog.load(fn_name, &btf)?;
        Ok(prog.attach()?)
    })();
    match result {
        Ok(link) => {
            info!(prog = prog_name, function = fn_name, "fentry attached");
            links.push(Box::new(link));
            true
        }
        Err(e) => {
            debug!(prog = prog_name, function = fn_name, error = %e, "fentry unavailable, falling back");
            false
        }
    }
}

fn attach_kprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> bool {
    match try_attach_kprobe(ebpf, prog_name, fn_name) {
        Ok(link) => {
            info!(prog = prog_name, function = fn_name, "kprobe attached");
            links.push(Box::new(link));
            true
        }
        Err(e) => {
            warn!(prog = prog_name, function = fn_name, error = %e, "Failed to attach kprobe");
            false
        }
    }
}

fn try_attach_kprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
) -> Result<aya::programs::kprobe::KProbeLinkId> {
    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    prog.load()?;
    let link_id = prog.attach(fn_name, 0)?;
    Ok(link_id)
}

fn attach_kretprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) {
    match try_attach_kretprobe(ebpf, prog_name, fn_name) {
        Ok(link) => {
            info!(prog = prog_name, function = fn_name, "kretprobe attached");
            links.push(Box::new(link));
        }
        Err(e) => {
            warn!(prog = prog_name, function = fn_name, error = %e, "Failed to attach kretprobe")
        }
    }
}

fn try_attach_kretprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
) -> Result<aya::programs::kprobe::KProbeLinkId> {
    let prog: &mut KProbe = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    prog.load()?;
    let link_id = prog.attach(fn_name, 0)?;
    Ok(link_id)
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) {
    match try_attach_tracepoint(ebpf, prog_name, category, name) {
        Ok(link) => {
            info!(prog = prog_name, category, name, "tracepoint attached");
            links.push(Box::new(link));
        }
        Err(e) => {
            warn!(prog = prog_name, category, name, error = %e, "Failed to attach tracepoint")
        }
    }
}

fn try_attach_tracepoint(
    ebpf: &mut Ebpf,
    prog_name: &str,
    category: &str,
    name: &str,
) -> Result<aya::programs::trace_point::TracePointLinkId> {
    check_tracepoint_layout(category, name)?;
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    prog.load()?;
    let link_id = prog.attach(category, name)?;
    Ok(link_id)
}

/// Field offsets the eBPF tracepoint programs read with `read_at`
/// (tls_probes.rs, sock_monitor.rs). Kernels can lay these records out
/// differently: RHEL 9 adds `common_preempt_lazy_count` to the common header,
/// moving every field by 8, and RHEL 8's 4.18 has a `u8` protocol in
/// `inet_sock_set_state`, moving `saddr`/`daddr` back by one.
const TRACEPOINT_LAYOUTS: &[(&str, &[(&str, usize)])] = &[
    (
        "sock_send_length",
        &[("sk", 8), ("family", 16), ("protocol", 18)],
    ),
    (
        "sock_recv_length",
        &[("sk", 8), ("family", 16), ("protocol", 18)],
    ),
    (
        "inet_sock_set_state",
        &[
            ("skaddr", 8),
            ("oldstate", 16),
            ("newstate", 20),
            ("sport", 24),
            ("dport", 26),
            ("family", 28),
            ("protocol", 30),
            ("saddr", 32),
            ("daddr", 36),
        ],
    ),
];

/// Refuse a tracepoint whose record layout (from its tracefs `format` file)
/// differs from the offsets the program reads, so the caller falls back to
/// fentry/kprobes instead of reading the wrong fields. Unreadable format
/// files pass: attaching then fails on its own.
fn check_tracepoint_layout(category: &str, name: &str) -> Result<()> {
    let Some((_, fields)) = TRACEPOINT_LAYOUTS.iter().find(|(n, _)| *n == name) else {
        return Ok(());
    };
    let Some(format) = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .find_map(|root| {
            std::fs::read_to_string(format!("{root}/events/{category}/{name}/format")).ok()
        })
    else {
        return Ok(());
    };
    tracepoint_layout_mismatch(&format, fields).map_or(Ok(()), |m| {
        anyhow::bail!("{category}/{name} record layout differs: {m}")
    })
}

/// The first expected field whose offset in `format` differs, described.
fn tracepoint_layout_mismatch(format: &str, fields: &[(&str, usize)]) -> Option<String> {
    let offset_of = |field: &str| {
        format.lines().find_map(|line| {
            let decl = line.trim().strip_prefix("field:")?.split(';').next()?;
            let ident = decl.rsplit([' ', '*']).next()?.split('[').next()?;
            if ident != field {
                return None;
            }
            line.split("offset:")
                .nth(1)?
                .split(';')
                .next()?
                .parse::<usize>()
                .ok()
        })
    };
    fields
        .iter()
        .find_map(|&(field, want)| match offset_of(field) {
            Some(got) if got == want => None,
            got => Some(format!("{field} at {got:?}, program reads {want}")),
        })
}

/// Parse kernel version from /proc/version_signature or /proc/version.
fn read_kernel_version() -> Result<(u32, u32, u32)> {
    let content =
        std::fs::read_to_string("/proc/version").context("Failed to read /proc/version")?;
    parse_kernel_version(&content).context("Failed to parse kernel version from /proc/version")
}

/// Extract (major, minor, patch) from a version string like "Linux version 5.15.0-91-generic ..."
fn parse_kernel_version(version_str: &str) -> Option<(u32, u32, u32)> {
    // Look for a pattern like "X.Y.Z" where X, Y, Z are digits
    for word in version_str.split_whitespace() {
        let parts: Vec<&str> = word.split('.').collect();
        if parts.len() >= 3
            && let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
        {
            // Patch may have trailing non-digit chars like "0-91-generic"
            let patch_str = parts[2]
                .split(|c: char| !c.is_ascii_digit())
                .next()
                .unwrap_or("0");
            let patch = patch_str.parse::<u32>().unwrap_or(0);
            return Some((major, minor, patch));
        }
    }
    None
}

// ── Kernel Capability Probing ─────────────────────────────────────────────

/// Linux capability bit positions.
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;

/// Check if the process has the required Linux capabilities for eBPF.
/// Returns a list of missing capability names (empty = all present).
///
/// Kernels that know CAP_BPF (upstream 5.8+, RHEL 8's 4.18) accept the
/// fine-grained CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN; older ones need
/// CAP_SYS_ADMIN. Read from /proc/sys/kernel/cap_last_cap, not the version.
pub fn check_required_capabilities(caps: &KernelCapabilities) -> Vec<&'static str> {
    let effective = read_effective_caps().unwrap_or(0);
    let fine_grained = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map_or((caps.version.0, caps.version.1) >= (5, 8), |last| {
            last >= CAP_BPF
        });
    check_capabilities_with_bitmask(fine_grained, effective)
}

/// Inner function testable with a specific bitmask (avoids reading /proc in tests).
fn check_capabilities_with_bitmask(fine_grained: bool, effective: u64) -> Vec<&'static str> {
    let mut missing = Vec::new();

    if fine_grained {
        // Modern kernel: fine-grained caps
        if effective & (1u64 << CAP_BPF) == 0 {
            missing.push("CAP_BPF");
        }
        if effective & (1u64 << CAP_PERFMON) == 0 {
            missing.push("CAP_PERFMON");
        }
        if effective & (1u64 << CAP_NET_ADMIN) == 0 {
            missing.push("CAP_NET_ADMIN");
        }
    } else {
        // Older kernel: requires CAP_SYS_ADMIN
        if effective & (1u64 << CAP_SYS_ADMIN) == 0 {
            missing.push("CAP_SYS_ADMIN");
        }
    }

    missing
}

/// Read the effective capability bitmask from /proc/self/status.
fn read_effective_caps() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_effective_caps(&status)
}

/// Parse CapEff from a /proc/self/status content string.
/// Extracted for testing with fixture strings.
fn parse_effective_caps(status_content: &str) -> Option<u64> {
    for line in status_content.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:\t") {
            return u64::from_str_radix(hex.trim(), 16).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Kernel version parsing ────────────────────────────────────────

    #[test]
    fn test_parse_kernel_version_standard() {
        let v = parse_kernel_version("Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045)");
        assert_eq!(v, Some((5, 15, 0)));
    }

    #[test]
    fn test_parse_kernel_version_simple() {
        let v = parse_kernel_version("Linux version 6.1.52");
        assert_eq!(v, Some((6, 1, 52)));
    }

    #[test]
    fn test_parse_kernel_version_with_extra() {
        let v = parse_kernel_version("Linux version 4.18.0-477.el8.x86_64 (mockbuild)");
        assert_eq!(v, Some((4, 18, 0)));
    }

    #[test]
    fn test_parse_kernel_version_garbage() {
        let v = parse_kernel_version("not a kernel version");
        assert_eq!(v, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_kernel_caps() {
        let caps = detect_kernel_caps().expect("should detect kernel caps");
        assert!(caps.version.0 >= 4, "kernel major version should be >= 4");
        assert!(caps.has_tc_ebpf, "modern kernels should have TC eBPF");
    }

    // ── Capability parsing ────────────────────────────────────────────

    #[test]
    fn test_parse_effective_caps_real_fixture() {
        let status = "\
Name:\tpanopticon-agent
Umask:\t0022
State:\tS (sleeping)
Tgid:\t12345
Pid:\t12345
CapInh:\t0000000000000000
CapPrm:\t000001ffffffffff
CapEff:\t000001ffffffffff
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000000000
";
        let result = parse_effective_caps(status);
        assert_eq!(result, Some(0x000001ffffffffff));
    }

    #[test]
    fn test_parse_effective_caps_missing_line() {
        let status = "\
Name:\tsome-process
Pid:\t1
CapPrm:\t00000000ffffffff
";
        let result = parse_effective_caps(status);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_effective_caps_zero() {
        let status = "CapEff:\t0000000000000000\n";
        let result = parse_effective_caps(status);
        assert_eq!(result, Some(0));
    }

    // ── Tracepoint record layout ──────────────────────────────────────

    #[test]
    fn test_tracepoint_layout_upstream_and_rhel9() {
        let fields = TRACEPOINT_LAYOUTS[0].1;
        let upstream = "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
            \tfield:void * sk;\toffset:8;\tsize:8;\tsigned:0;\n\
            \tfield:__u16 family;\toffset:16;\tsize:2;\tsigned:0;\n\
            \tfield:__u16 protocol;\toffset:18;\tsize:2;\tsigned:0;\n";
        assert_eq!(tracepoint_layout_mismatch(upstream, fields), None);
        // RHEL 9 (5.14): common_preempt_lazy_count shifts every field by 8.
        let rhel9 = "\tfield:unsigned char common_preempt_lazy_count;\toffset:8;\tsize:1;\tsigned:0;\n\n\
            \tfield:void * sk;\toffset:16;\tsize:8;\tsigned:0;\n\
            \tfield:__u16 family;\toffset:24;\tsize:2;\tsigned:0;\n\
            \tfield:__u16 protocol;\toffset:26;\tsize:2;\tsigned:0;\n";
        assert_eq!(
            tracepoint_layout_mismatch(rhel9, fields).as_deref(),
            Some("sk at Some(16), program reads 8")
        );
        // Array fields (`__u8 saddr[4]`) match by name.
        let saddr = [("saddr", 31)];
        let rhel8 = "\tfield:__u8 saddr[4];\toffset:31;\tsize:4;\tsigned:0;\n";
        assert_eq!(tracepoint_layout_mismatch(rhel8, &saddr), None);
    }

    // ── Capability requirement checks ─────────────────────────────────

    #[test]
    fn test_check_caps_modern_kernel_all_present() {
        // All three caps set: CAP_NET_ADMIN(12) + CAP_PERFMON(38) + CAP_BPF(39)
        let bitmask = (1u64 << 12) | (1u64 << 38) | (1u64 << 39);
        let missing = check_capabilities_with_bitmask(true, bitmask);
        assert!(missing.is_empty(), "all caps present, got: {:?}", missing);
    }

    #[test]
    fn test_check_caps_modern_kernel_missing_bpf() {
        // Only NET_ADMIN + PERFMON, missing BPF
        let bitmask = (1u64 << 12) | (1u64 << 38);
        let missing = check_capabilities_with_bitmask(true, bitmask);
        assert_eq!(missing, vec!["CAP_BPF"]);
    }

    #[test]
    fn test_check_caps_old_kernel_sys_admin_present() {
        let bitmask = 1u64 << CAP_SYS_ADMIN;
        let missing = check_capabilities_with_bitmask(false, bitmask);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_check_caps_old_kernel_sys_admin_missing() {
        let bitmask = 0u64; // no caps
        let missing = check_capabilities_with_bitmask(false, bitmask);
        assert_eq!(missing, vec!["CAP_SYS_ADMIN"]);
    }

    // ── Map pinning / bpffs tests ─────────────────────────────────────

    #[test]
    fn scope_maps_are_never_pinned() {
        for m in [
            "SOCK_STATE",
            "CGROUP_ALLOW",
            "SCOPE_DROPS",
            "PID_FILTER",
            "PID_CANDIDATES",
            "PID_EXITED",
            "PID_EXITED_LOST",
        ] {
            assert!(!pinned_map_names().any(|n| n == m), "{m} is pinned");
        }
    }

    #[test]
    fn test_bpffs_mounted_with_bpf_entry() {
        let mounts = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
bpf /sys/fs/bpf bpf rw,nosuid,nodev,noexec,relatime,mode=700 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1624628k,mode=755,inode64 0 0
";
        assert!(parse_bpffs_from_mounts_content(
            "/sys/fs/bpf/panopticon",
            mounts
        ));
    }

    #[test]
    fn test_bpffs_not_mounted() {
        let mounts = "\
sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev 0 0
";
        assert!(!parse_bpffs_from_mounts_content(
            "/sys/fs/bpf/panopticon",
            mounts
        ));
    }

    #[test]
    fn test_bpffs_wrong_mount_path() {
        let mounts = "bpf /other/bpf bpf rw 0 0\n";
        assert!(!parse_bpffs_from_mounts_content(
            "/sys/fs/bpf/panopticon",
            mounts
        ));
    }

    #[test]
    fn test_unpin_maps_on_temp_dir() {
        let root = std::env::temp_dir().join("panopticon_test_unpin");
        let dir = root.join("panopticon");
        let _ = std::fs::create_dir_all(&dir);

        // Create some test files
        std::fs::write(dir.join("DATA_EVENTS_0"), b"fake").unwrap();
        std::fs::write(dir.join("CONFIG"), b"fake").unwrap();
        std::fs::write(dir.join("CONN_MAP"), b"fake").unwrap();

        let removed = unpin_maps(root.to_str().unwrap()).unwrap();
        assert_eq!(removed, 3);

        // Pin directory should still exist but be empty.
        let count = std::fs::read_dir(&dir).unwrap().count();
        assert_eq!(count, 0);

        let _ = std::fs::remove_dir(&dir);
        let _ = std::fs::remove_dir(&root);
    }

    #[test]
    fn test_normalize_pin_dir_suffix_behavior() {
        let a = normalize_pin_dir("/sys/fs/bpf");
        let b = normalize_pin_dir("/sys/fs/bpf/panopticon");
        assert_eq!(a, std::path::Path::new("/sys/fs/bpf/panopticon"));
        assert_eq!(b, std::path::Path::new("/sys/fs/bpf/panopticon"));
    }
}
