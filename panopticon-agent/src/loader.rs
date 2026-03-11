use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    Ebpf, EbpfLoader,
    maps::Array,
    programs::{KProbe, ProgramError, SchedClassifier, TracePoint, UProbe, tc::TcAttachType},
};
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::platform::proc_scanner::{GoVersion, TlsTarget, TlsType};
use panopticon_common::{
    CONFIG_CAPTURE_ENABLED, CONFIG_MAX_PAYLOAD, CONFIG_PID_FILTER_ON, CONFIG_USE_RINGBUF,
    MAX_PAYLOAD_SIZE,
};

const PINNED_MAP_NAMES: [&str; 12] = [
    "DATA_EVENTS",
    "DATA_EVENTS_PERF",
    "PROCESS_EVENTS",
    "CONN_MAP",
    "PID_CGROUP_MAP",
    "CONFIG",
    "PID_FILTER",
    "TLS_SCRATCH",
    "GO_ABI_MAP",
    "PID_TO_CONN",
    "IPV6_DROPS",
    "PERF_SCRATCH",
];

/// Detected kernel capabilities that determine which eBPF features are available.
#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub version: (u32, u32, u32),
    /// RingBuf support (kernel >= 5.8).
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

/// Detect kernel capabilities by reading /proc/version and checking sysfs.
pub fn detect_kernel_caps() -> Result<KernelCapabilities> {
    let version = read_kernel_version()?;
    let (major, minor, _patch) = version;

    Ok(KernelCapabilities {
        version,
        has_ringbuf: (major, minor) >= (5, 8),
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
) -> Result<LoadedPrograms> {
    if !caps.has_tc_ebpf {
        anyhow::bail!(
            "Kernel {}.{}.{} does not support TC eBPF (requires >= 4.15)",
            caps.version.0,
            caps.version.1,
            caps.version.2
        );
    }

    let mut ebpf = load_ebpf_bytes(config.map_pin_path.as_deref())?;
    let mut links: Vec<Box<dyn std::any::Any + Send>> = Vec::new();

    // Write initial config to eBPF CONFIG map
    sync_config_to_ebpf(&mut ebpf, config, caps)?;

    // ── TC classifiers (ingress + egress) per interface ───────────────
    ensure_tc_program_loaded(&mut ebpf, "tc_ingress")?;
    ensure_tc_program_loaded(&mut ebpf, "tc_egress")?;
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

    // ── Kprobes for socket monitoring ─────────────────────────────────
    attach_kprobe(&mut ebpf, "tcp_connect", "tcp_connect", &mut links);
    attach_kretprobe(
        &mut ebpf,
        "inet_csk_accept_ret",
        "inet_csk_accept",
        &mut links,
    );
    attach_kprobe(&mut ebpf, "tcp_close", "tcp_close", &mut links);
    attach_kprobe(&mut ebpf, "udp_sendmsg", "udp_sendmsg", &mut links);
    attach_kprobe(&mut ebpf, "udp_recvmsg", "udp_recvmsg", &mut links);

    // ── Tracepoints for process monitoring ────────────────────────────
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exec",
        "sched",
        "sched_process_exec",
        &mut links,
    );
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
        &mut links,
    );

    info!(
        probes_attached = links.len(),
        tc_links_attached,
        tc_links_expected = interfaces.len() * 2,
        has_cgroup_id = caps.has_cgroup_id,
        interfaces = ?interfaces,
        "eBPF programs loaded and attached"
    );
    if interfaces.is_empty() {
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
    let mut cfg_map: Array<_, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map not found")?)?;

    cfg_map.set(CONFIG_CAPTURE_ENABLED, config.capture_enabled as u64, 0)?;
    cfg_map.set(CONFIG_MAX_PAYLOAD, MAX_PAYLOAD_SIZE as u64, 0)?;
    cfg_map.set(CONFIG_USE_RINGBUF, caps.has_ringbuf as u64, 0)?;
    cfg_map.set(CONFIG_PID_FILTER_ON, config.pid_filter.is_some() as u64, 0)?;

    Ok(())
}

// ── TLS Uprobe Attachment ─────────────────────────────────────────────────

/// Attach TLS uprobes to a discovered target.
/// Returns the number of successfully attached probes.
pub fn attach_tls_uprobes(
    ebpf: &mut Ebpf,
    target: &TlsTarget,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> usize {
    let mut attached = 0;

    match &target.tls_type {
        TlsType::OpenSsl {
            ssl_write_offset,
            ssl_read_offset,
        } => {
            // SSL_write — uprobe (pid=None for system-wide shared lib coverage)
            if attach_uprobe(
                ebpf,
                "ssl_write_entry",
                &target.library_path,
                *ssl_write_offset,
                None,
                links,
            ) {
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
        }
        TlsType::GoTls {
            write_offset,
            go_version,
        } => {
            match go_version {
                GoVersion::RegisterAbi => {
                    if attach_go_tls_uprobe(
                        ebpf,
                        "go_tls_write_entry",
                        &target.library_path,
                        *write_offset,
                        target.pid as i32,
                        links,
                    ) {
                        attached += 1;
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

/// Attach TLS uprobes operating on shared `EbpfState` directly.
/// Caller is responsible for locking the mutex.
pub fn attach_tls_uprobes_on_state(state: &mut EbpfState, target: &TlsTarget) -> usize {
    attach_tls_uprobes(&mut state.ebpf, target, &mut state.links)
}

fn attach_go_tls_uprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    target_path: &str,
    offset: u64,
    pid: i32,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) -> bool {
    match try_attach_uprobe(ebpf, prog_name, target_path, offset, Some(pid)) {
        Ok(link) => {
            info!(
                prog = prog_name,
                path = target_path,
                offset,
                pid,
                "uprobe attached"
            );
            links.push(Box::new(link));
            true
        }
        Err(err) => {
            warn!(
                prog = prog_name,
                path = target_path,
                offset,
                pid,
                error = %err,
                "Failed to attach pid-scoped Go TLS uprobe; retrying without pid filter"
            );

            match try_attach_uprobe(ebpf, prog_name, target_path, offset, None) {
                Ok(link) => {
                    info!(
                        prog = prog_name,
                        path = target_path,
                        offset,
                        pid,
                        "uprobe attached without pid filter"
                    );
                    links.push(Box::new(link));
                    true
                }
                Err(retry_err) => {
                    warn!(
                        prog = prog_name,
                        path = target_path,
                        offset,
                        pid,
                        error = %retry_err,
                        "Failed to attach Go TLS uprobe"
                    );
                    false
                }
            }
        }
    }
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
/// Modern kernels use `RingBuf`, older kernels fall back to `PerfEventArray`.
pub enum EventSource {
    RingBuf(aya::maps::RingBuf<aya::maps::MapData>),
    PerfEventArray(aya::maps::PerfEventArray<aya::maps::MapData>),
}

/// Extract the appropriate event source map from the eBPF object based on capabilities.
pub fn take_event_source(ebpf: &mut Ebpf, caps: &KernelCapabilities) -> Result<EventSource> {
    if caps.has_ringbuf {
        let map = ebpf
            .take_map("DATA_EVENTS")
            .context("DATA_EVENTS map not found in eBPF object")?;
        Ok(EventSource::RingBuf(
            aya::maps::RingBuf::try_from(map).context("Failed to cast DATA_EVENTS to RingBuf")?,
        ))
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

// ── Internal helpers ──────────────────────────────────────────────────────

fn load_ebpf_bytes(map_pin_path: Option<&str>) -> Result<Ebpf> {
    // aya-build writes the compiled eBPF ELF to OUT_DIR during cargo build.
    // include_bytes_aligned! embeds it into the agent binary.
    let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panopticon-ebpf"));

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

            let mut loader = EbpfLoader::new();
            for map_name in PINNED_MAP_NAMES {
                loader.map_pin_path(map_name, pin_dir.as_path());
            }
            loader.load(bytes)?
        }
        None => aya::Ebpf::load(bytes)?,
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
    for map_name in PINNED_MAP_NAMES {
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
    let prog: &mut SchedClassifier = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    let link_id = prog.attach(iface, direction)?;
    Ok(link_id)
}

fn attach_kprobe(
    ebpf: &mut Ebpf,
    prog_name: &str,
    fn_name: &str,
    links: &mut Vec<Box<dyn std::any::Any + Send>>,
) {
    match try_attach_kprobe(ebpf, prog_name, fn_name) {
        Ok(link) => {
            info!(prog = prog_name, function = fn_name, "kprobe attached");
            links.push(Box::new(link));
        }
        Err(e) => {
            warn!(prog = prog_name, function = fn_name, error = %e, "Failed to attach kprobe")
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
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .context(format!("program '{prog_name}' not found"))?
        .try_into()?;
    prog.load()?;
    let link_id = prog.attach(category, name)?;
    Ok(link_id)
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
/// Kernel >= 5.8 supports fine-grained capabilities (CAP_BPF + CAP_PERFMON + CAP_NET_ADMIN).
/// Older kernels require the coarse-grained CAP_SYS_ADMIN.
pub fn check_required_capabilities(caps: &KernelCapabilities) -> Vec<&'static str> {
    let effective = read_effective_caps().unwrap_or(0);
    check_capabilities_with_bitmask(caps, effective)
}

/// Inner function testable with a specific bitmask (avoids reading /proc in tests).
fn check_capabilities_with_bitmask(caps: &KernelCapabilities, effective: u64) -> Vec<&'static str> {
    let mut missing = Vec::new();

    if (caps.version.0, caps.version.1) >= (5, 8) {
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

    // ── Capability requirement checks ─────────────────────────────────

    #[test]
    fn test_check_caps_modern_kernel_all_present() {
        let caps = KernelCapabilities {
            version: (5, 15, 0),
            has_ringbuf: true,
            has_btf: true,
            has_cgroup_id: true,
            has_tc_ebpf: true,
        };
        // All three caps set: CAP_NET_ADMIN(12) + CAP_PERFMON(38) + CAP_BPF(39)
        let bitmask = (1u64 << 12) | (1u64 << 38) | (1u64 << 39);
        let missing = check_capabilities_with_bitmask(&caps, bitmask);
        assert!(missing.is_empty(), "all caps present, got: {:?}", missing);
    }

    #[test]
    fn test_check_caps_modern_kernel_missing_bpf() {
        let caps = KernelCapabilities {
            version: (5, 15, 0),
            has_ringbuf: true,
            has_btf: true,
            has_cgroup_id: true,
            has_tc_ebpf: true,
        };
        // Only NET_ADMIN + PERFMON, missing BPF
        let bitmask = (1u64 << 12) | (1u64 << 38);
        let missing = check_capabilities_with_bitmask(&caps, bitmask);
        assert_eq!(missing, vec!["CAP_BPF"]);
    }

    #[test]
    fn test_check_caps_old_kernel_sys_admin_present() {
        let caps = KernelCapabilities {
            version: (4, 18, 0),
            has_ringbuf: false,
            has_btf: false,
            has_cgroup_id: true,
            has_tc_ebpf: true,
        };
        let bitmask = 1u64 << CAP_SYS_ADMIN;
        let missing = check_capabilities_with_bitmask(&caps, bitmask);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_check_caps_old_kernel_sys_admin_missing() {
        let caps = KernelCapabilities {
            version: (4, 18, 0),
            has_ringbuf: false,
            has_btf: false,
            has_cgroup_id: true,
            has_tc_ebpf: true,
        };
        let bitmask = 0u64; // no caps
        let missing = check_capabilities_with_bitmask(&caps, bitmask);
        assert_eq!(missing, vec!["CAP_SYS_ADMIN"]);
    }

    // ── Map pinning / bpffs tests ─────────────────────────────────────

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
        std::fs::write(dir.join("DATA_EVENTS"), b"fake").unwrap();
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
