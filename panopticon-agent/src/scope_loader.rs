//! Loader for the cgroup_skb capture backend (DESIGN §7): load-check every
//! program a mode needs before anything is attached, find the cgroup v2
//! root, then attach the scope writers before the capture programs.
//!
//! Self-contained (aya, anyhow, tracing, libc, panopticon-common only) so
//! the lab attach test (`tests/scope_attach.rs`) runs this same code.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya::{
    Btf, Ebpf,
    programs::{CgroupAttachMode, CgroupSkbAttachType, ProgramError},
};
use panopticon_common::scope::{SCOPE_HEAD, SCOPE_SAMPLE, SCOPE_SEL_CGROUP, SCOPE_SEL_PID};
use tracing::{info, warn};

/// What the configured mode needs from the kernel.
#[derive(Debug, Clone)]
pub struct ScopeSetup {
    /// `CONFIG_SCOPE_MODE` (`scope::SCOPE_*` bits); 0 is unscoped `full`.
    pub mode: u64,
    /// TLS uprobes will be attached (`tls_scan_enabled`).
    pub tls: bool,
    /// `[capture] cgroup2_path`: `"auto"` or a cgroup v2 mount point.
    pub cgroup2_path: String,
}

pub const SKB_INGRESS: &str = "scope_skb_ingress";
pub const SKB_EGRESS: &str = "scope_skb_egress";
pub const SOCK_CREATE: &str = "scope_sock_create";
pub const SOCKOPS: &str = "scope_sockops";
pub const ACCEPT4: &str = "scope_accept4";
pub const ACCEPT2: &str = "scope_accept2";
pub const SET_ULP: &str = "scope_set_ulp";
pub const EXIT_TP: &str = "sched_process_exit";
/// TLS uprobe programs; the scope gate lives in their shared emit path.
pub const TLS_PROGRAMS: [&str; 8] = [
    "ssl_write_entry",
    "ssl_write_ex_entry",
    "ssl_read_entry",
    "ssl_read_ex_entry",
    "ssl_read_ret",
    "go_tls_write_entry",
    "go_tls_read_entry",
    "go_tls_read_ret",
];

/// The settings a restricted mode came from, for refusal messages.
pub fn mode_settings(mode: u64) -> String {
    let mut s = Vec::new();
    if mode & SCOPE_SEL_PID != 0 {
        s.push("pid_filter");
    }
    if mode & SCOPE_SEL_CGROUP != 0 {
        s.push("cgroup_filter/pod_filter");
    }
    if mode & SCOPE_SAMPLE != 0 {
        s.push("sampling_mode = \"connection_sample\"");
    }
    if mode & SCOPE_HEAD != 0 {
        s.push("sampling_mode = \"head_only\"");
    }
    s.join(", ")
}

/// Load one program by name (any type this backend uses). Fentry/fexit
/// programs attach to `target`.
pub fn load_program(ebpf: &mut Ebpf, name: &str, target: Option<&str>) -> Result<()> {
    let prog = ebpf
        .program_mut(name)
        .with_context(|| format!("program {name} is not in the eBPF object"))?;
    let r = match prog {
        aya::programs::Program::CgroupSkb(p) => p.load(),
        aya::programs::Program::CgroupSock(p) => p.load(),
        aya::programs::Program::SockOps(p) => p.load(),
        aya::programs::Program::TracePoint(p) => p.load(),
        aya::programs::Program::UProbe(p) => p.load(),
        aya::programs::Program::FExit(p) => p.load(target.unwrap_or_default(), &kernel_btf()?),
        aya::programs::Program::FEntry(p) => p.load(target.unwrap_or_default(), &kernel_btf()?),
        _ => bail!("program {name} has a type this loader does not handle"),
    };
    match r {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => Ok(()),
        Err(e) => Err(describe(e)).with_context(|| format!("{name} does not load")),
    }
}

fn kernel_btf() -> Result<Btf> {
    Btf::from_sys_fs().context("kernel BTF (/sys/kernel/btf/vmlinux) is not available")
}

/// A program error with the tail of the verifier log, if there is one.
fn describe(e: ProgramError) -> anyhow::Error {
    if let ProgramError::LoadError {
        io_error,
        verifier_log,
    } = &e
    {
        let log = verifier_log.to_string();
        let tail: Vec<&str> = log.lines().rev().take(6).collect();
        let tail: Vec<&str> = tail.into_iter().rev().collect();
        return anyhow::anyhow!("{io_error}; verifier: {}", tail.join(" | "));
    }
    anyhow::Error::new(e)
}

/// What the load-check found.
#[derive(Debug)]
pub struct LoadReport {
    /// The `inet_csk_accept` variant that loaded, if any.
    pub accept: Option<&'static str>,
    /// Whether the scope writers loaded (required in restricted modes).
    pub writers: bool,
}

/// Load every program `setup` needs, attaching nothing. Fails with the
/// refusal (§7) naming the program and the setting that needs it.
pub fn load_check(ebpf: &mut Ebpf, setup: &ScopeSetup) -> Result<LoadReport> {
    let restricted = setup.mode != 0;
    let settings = mode_settings(setup.mode);
    if restricted && !cfg!(target_arch = "x86_64") {
        // §2.2: publication order is validated on x86-64 (TSO) only.
        bail!(
            "refusing {settings}: scoped capture is only validated on x86-64 (DESIGN §2.2); \
             use unscoped full or capture.backend = \"tc\""
        );
    }
    for p in [SKB_INGRESS, SKB_EGRESS] {
        load_program(ebpf, p, None).with_context(|| {
            "refusing to start: capture.backend = \"cgroup_skb\" needs cgroup_skb with \
             sk_storage (BPF_F_CLONE), bpf_tcp_sock and BPF_ADD|BPF_FETCH"
        })?;
    }
    let mut writers = true;
    for (p, target) in [
        (SOCK_CREATE, None),
        (SOCKOPS, None),
        (SET_ULP, Some("tcp_set_ulp")),
    ] {
        if let Err(e) = load_program(ebpf, p, target) {
            if restricted {
                return Err(e.context(format!(
                    "refusing {settings}: every mode except unscoped full needs {p}"
                )));
            }
            warn!(prog = p, error = %format!("{e:#}"), "scope writer unavailable; unscoped full continues");
            writers = false;
        }
    }
    let accept = [ACCEPT4, ACCEPT2]
        .into_iter()
        .find(|p| load_program(ebpf, p, Some("inet_csk_accept")).is_ok());
    if accept.is_none() && setup.mode & SCOPE_SEL_PID != 0 {
        warn!(
            "fexit inet_csk_accept loads in neither variant: pid_filter uses socket creators only"
        );
    }
    if setup.mode & SCOPE_SEL_PID != 0 {
        load_program(ebpf, EXIT_TP, None).context(
            "refusing pid_filter: the sched_process_exit tracepoint is required (PID reuse)",
        )?;
    }
    if restricted && setup.tls {
        for p in TLS_PROGRAMS {
            load_program(ebpf, p, None).with_context(|| {
                format!(
                    "refusing TLS capture with {settings}: {p} does not load; set \
                     tls_scan_enabled = false or use unscoped full"
                )
            })?;
        }
    }
    Ok(LoadReport { accept, writers })
}

// ── cgroup v2 root ─────────────────────────────────────────────────────────

const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
/// Where the agent mounts its own cgroup2 when the host has none (RHEL 8).
pub const PRIVATE_CGROUP2: &str = "/run/panopticon/cgroup2";

/// The cgroup v2 root programs attach to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CgroupRoot {
    /// The host's unified hierarchy: cgroup ids are the workloads' cgroups.
    Host(PathBuf),
    /// A private cgroup2 mount on a v1 host: every socket is in its root, so
    /// the cgroup selector cannot work (§3.2); `pid_filter` does.
    Private(PathBuf),
}

impl CgroupRoot {
    pub fn path(&self) -> &Path {
        match self {
            Self::Host(p) | Self::Private(p) => p,
        }
    }
}

fn is_cgroup2(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: statfs writes into the zeroed struct; c is a valid C string.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    unsafe { libc::statfs(c.as_ptr(), &mut st) == 0 && st.f_type as i64 == CGROUP2_SUPER_MAGIC }
}

/// `/sys/fs/cgroup` if it is cgroup2; else the hybrid `/sys/fs/cgroup/unified`;
/// else a private cgroup2 mounted at [`PRIVATE_CGROUP2`]. An explicit path
/// must be a cgroup2 mount.
pub fn discover_cgroup_root(setting: &str) -> Result<CgroupRoot> {
    if setting != "auto" {
        let p = PathBuf::from(setting);
        if !is_cgroup2(&p) {
            bail!("[capture] cgroup2_path = \"{setting}\" is not a cgroup2 mount");
        }
        return Ok(CgroupRoot::Host(p));
    }
    for p in ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"] {
        if is_cgroup2(Path::new(p)) {
            return Ok(CgroupRoot::Host(p.into()));
        }
    }
    let p = PathBuf::from(PRIVATE_CGROUP2);
    if !is_cgroup2(&p) {
        std::fs::create_dir_all(&p).with_context(|| format!("cannot create {}", p.display()))?;
        let target = std::ffi::CString::new(PRIVATE_CGROUP2)?;
        // SAFETY: valid C strings; no data argument.
        let rc = unsafe {
            libc::mount(
                c"cgroup2".as_ptr(),
                target.as_ptr(),
                c"cgroup2".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("no cgroup2 hierarchy, and mounting one at {PRIVATE_CGROUP2} failed")
            });
        }
    }
    Ok(CgroupRoot::Private(p))
}

// ── Attach ─────────────────────────────────────────────────────────────────

type Links = Vec<Box<dyn std::any::Any + Send>>;

/// Attach one loaded program. Cgroup programs go on `cgroup` with
/// `BPF_F_ALLOW_MULTI` semantics, so other tools' programs on the root keep
/// running: from 5.7 aya attaches through a bpf_link, which the kernel
/// always attaches as multi and which rejects any attach flag (EINVAL);
/// before that (RHEL 8) through `BPF_PROG_ATTACH`, which needs the flag.
pub fn attach_program(ebpf: &mut Ebpf, name: &str, cgroup: &File, links: &mut Links) -> Result<()> {
    use aya::util::KernelVersion;
    // The same test aya makes when it picks the attach call.
    let link = KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(5, 7, 0));
    let mode = if link {
        CgroupAttachMode::Single
    } else {
        CgroupAttachMode::AllowMultiple
    };
    let prog = ebpf
        .program_mut(name)
        .with_context(|| format!("program {name} is not in the eBPF object"))?;
    let r: std::result::Result<Box<dyn std::any::Any + Send>, ProgramError> = match prog {
        aya::programs::Program::CgroupSkb(p) => {
            let at = if name == SKB_EGRESS {
                CgroupSkbAttachType::Egress
            } else {
                CgroupSkbAttachType::Ingress
            };
            p.attach(cgroup, at, mode).map(|l| Box::new(l) as _)
        }
        aya::programs::Program::CgroupSock(p) => p.attach(cgroup, mode).map(|l| Box::new(l) as _),
        aya::programs::Program::SockOps(p) => p.attach(cgroup, mode).map(|l| Box::new(l) as _),
        aya::programs::Program::FExit(p) => p.attach().map(|l| Box::new(l) as _),
        aya::programs::Program::FEntry(p) => p.attach().map(|l| Box::new(l) as _),
        aya::programs::Program::TracePoint(p) => p
            .attach("sched", "sched_process_exit")
            .map(|l| Box::new(l) as _),
        _ => bail!("program {name} has a type this loader does not attach"),
    };
    links.push(
        r.map_err(describe)
            .with_context(|| format!("{name} does not attach"))?,
    );
    Ok(())
}

/// Load-check, find the root, then attach: writers first, capture last, so
/// no packet is captured before the state it depends on is being written.
/// Returns the root and whether the exit tracepoint was attached here.
pub fn load_and_attach(
    ebpf: &mut Ebpf,
    setup: &ScopeSetup,
    links: &mut Links,
) -> Result<(CgroupRoot, bool)> {
    let report = load_check(ebpf, setup)?;
    let root = discover_cgroup_root(&setup.cgroup2_path)?;
    if setup.mode & SCOPE_SEL_CGROUP != 0 && matches!(root, CgroupRoot::Private(_)) {
        bail!(
            "refusing cgroup_filter/pod_filter: {} is a private cgroup2 on a cgroup v1 host, \
             where every socket is in its root (DESIGN §3.2); pid_filter works",
            root.path().display()
        );
    }
    let cgroup = File::open(root.path())
        .with_context(|| format!("cannot open cgroup root {}", root.path().display()))?;
    let restricted = setup.mode != 0;
    let mut writers: Vec<&str> = Vec::new();
    if report.writers {
        writers.extend([SOCK_CREATE, SOCKOPS, SET_ULP]);
    }
    writers.extend(report.accept);
    let exit_tp = setup.mode & SCOPE_SEL_PID != 0;
    if exit_tp {
        writers.push(EXIT_TP);
    }
    for p in writers {
        if let Err(e) = attach_program(ebpf, p, &cgroup, links) {
            let required = restricted && !matches!(p, ACCEPT4 | ACCEPT2);
            if required {
                return Err(e.context(format!("refusing {}", mode_settings(setup.mode))));
            }
            warn!(prog = p, error = %format!("{e:#}"), "scope writer did not attach");
        }
    }
    for p in [SKB_INGRESS, SKB_EGRESS] {
        attach_program(ebpf, p, &cgroup, links)?;
    }
    info!(
        root = %root.path().display(),
        private = matches!(root, CgroupRoot::Private(_)),
        accept = ?report.accept,
        mode = setup.mode,
        "cgroup_skb capture attached"
    );
    Ok((root, exit_tp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_name_the_settings() {
        assert_eq!(mode_settings(0), "");
        assert_eq!(
            mode_settings(SCOPE_SEL_PID | SCOPE_HEAD),
            "pid_filter, sampling_mode = \"head_only\""
        );
    }

    #[test]
    fn explicit_cgroup2_path_must_be_cgroup2() {
        let e = discover_cgroup_root("/").unwrap_err().to_string();
        assert!(e.contains("not a cgroup2 mount"), "{e}");
    }
}
