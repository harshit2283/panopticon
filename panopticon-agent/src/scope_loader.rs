//! Loader for the cgroup_skb capture backend (DESIGN §7): load-check every
//! program a mode needs before anything is attached, find the cgroup v2
//! root, attach everything while the scope writers are disarmed, publish
//! `PID_FILTER`, and arm (`CONFIG_SCOPE_ARMED`) last.
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
use panopticon_common::CONFIG_SCOPE_ARMED;
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
    /// Whether the sched_process_exit tracepoint loaded (required with
    /// pid_filter).
    pub exit_tp: bool,
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
    let exit_tp = match load_program(ebpf, EXIT_TP, None) {
        Ok(()) => true,
        Err(e) if setup.mode & SCOPE_SEL_PID != 0 => {
            return Err(e.context(
                "refusing pid_filter: the sched_process_exit tracepoint is required (PID reuse)",
            ));
        }
        Err(e) => {
            warn!(error = %format!("{e:#}"), "sched_process_exit unavailable");
            false
        }
    };
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
    Ok(LoadReport {
        accept,
        writers,
        exit_tp,
    })
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
    let mode = if uses_links() {
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

/// Attach everything `setup` needs, with the scope writers disarmed
/// (CONFIG_SCOPE_ARMED must be 0, as `sync_config_to_ebpf` leaves it), in
/// dependency order:
/// 1. load-check everything (nothing attached if any required program fails);
/// 2. sched_process_exit, so no listed process can exit unseen once
///    PID_FILTER is published;
/// 3. the tcp_set_ulp marker, so no socket attaches kTLS unmarked;
/// 4. both capture hooks and fexit accept;
/// 5. sock_create and sockops.
///
/// Nothing is initialised before [`arm`], so no socket gets state while a
/// dependency above is missing. Returns the root and whether the exit
/// tracepoint was attached.
pub fn attach_disarmed(
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
    if !uses_links() {
        remove_stale_legacy(ebpf, &cgroup)?;
    }
    let restricted = setup.mode != 0;
    let settings = mode_settings(setup.mode);
    // (program, required)
    let mut order: Vec<(&str, bool)> = Vec::new();
    if report.exit_tp {
        order.push((EXIT_TP, setup.mode & SCOPE_SEL_PID != 0));
    }
    if report.writers {
        order.push((SET_ULP, restricted));
    }
    order.extend([(SKB_INGRESS, true), (SKB_EGRESS, true)]);
    order.extend(report.accept.map(|p| (p, false)));
    if report.writers {
        order.extend([(SOCK_CREATE, restricted), (SOCKOPS, restricted)]);
    }
    let mut exit_attached = false;
    for (p, required) in order {
        match attach_program(ebpf, p, &cgroup, links) {
            Ok(()) => exit_attached |= p == EXIT_TP,
            Err(e) if required => return Err(e.context(format!("refusing {settings}"))),
            Err(e) => warn!(prog = p, error = %format!("{e:#}"), "did not attach"),
        }
    }
    info!(
        root = %root.path().display(),
        private = matches!(root, CgroupRoot::Private(_)),
        accept = ?report.accept,
        mode = setup.mode,
        "cgroup_skb capture attached (disarmed)"
    );
    Ok((root, exit_attached))
}

/// Publish `pid_filter`, drop every listed process that is not alive (it
/// may have exited before the exit tracepoint was attached, and its PID
/// could be reused), then arm: the last write of startup.
pub fn arm(ebpf: &mut Ebpf, pids: Option<&[u32]>) -> Result<()> {
    if let Some(pids) = pids {
        let mut map: aya::maps::HashMap<_, u32, u8> = aya::maps::HashMap::try_from(
            ebpf.map_mut("PID_FILTER")
                .context("PID_FILTER map not found")?,
        )?;
        for &pid in pids {
            map.insert(pid, 1, 0)
                .with_context(|| format!("cannot add PID {pid} to the PID_FILTER map"))?;
        }
        for &pid in pids {
            if !process_alive(pid) {
                warn!(pid, "pid_filter process is not running; not selected");
                match map.remove(&pid) {
                    Ok(()) | Err(aya::maps::MapError::KeyNotFound) => {}
                    Err(e) => return Err(e).context(format!("cannot remove PID {pid}")),
                }
            }
        }
    }
    let mut cfg: aya::maps::Array<_, u64> =
        aya::maps::Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map not found")?)?;
    cfg.set(CONFIG_SCOPE_ARMED, 1, 0)?;
    info!("capture scope armed");
    Ok(())
}

/// Live and not a zombie: a zombie has already passed sched_process_exit.
pub fn process_alive(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    // "pid (comm) S ...": the state follows the last ')'.
    match stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.trim_start().chars().next())
    {
        Some('Z' | 'X' | 'x') | None => false,
        Some(_) => true,
    }
}

/// Attach (disarmed), then arm. The production startup path.
pub fn load_and_attach(
    ebpf: &mut Ebpf,
    setup: &ScopeSetup,
    pids: Option<&[u32]>,
    links: &mut Links,
) -> Result<(CgroupRoot, bool)> {
    let r = attach_disarmed(ebpf, setup, links)?;
    arm(ebpf, pids)?;
    Ok(r)
}

// ── Stale legacy attachments (RHEL 8) ──────────────────────────────────────

/// Whether aya attaches cgroup programs through bpf_link (5.7+), whose
/// attachment dies with the agent. The same test aya makes.
pub fn uses_links() -> bool {
    use aya::util::KernelVersion;
    KernelVersion::current().is_ok_and(|v| v >= KernelVersion::new(5, 7, 0))
}

const BPF_PROG_DETACH: libc::c_long = 9;
const BPF_PROG_QUERY: libc::c_long = 16;

/// Our cgroup programs and their attach types (BPF_CGROUP_*).
pub const CGROUP_PROGRAMS: [(&str, u32); 4] = [
    (SKB_INGRESS, 0),
    (SKB_EGRESS, 1),
    (SOCK_CREATE, 2),
    (SOCKOPS, 3),
];

#[repr(C)]
#[derive(Default)]
struct QueryAttr {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Default)]
struct DetachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

fn bpf<T>(cmd: libc::c_long, attr: &mut T) -> std::io::Result<()> {
    // SAFETY: attr is a valid bpf_attr prefix of the given size.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            attr as *mut T,
            std::mem::size_of::<T>() as u32,
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Ids of the programs attached to `cgroup` for `attach_type`.
pub fn attached_ids(cgroup: &File, attach_type: u32) -> Result<Vec<u32>> {
    use std::os::fd::AsRawFd;
    let mut ids = vec![0u32; 64];
    let mut attr = QueryAttr {
        target_fd: cgroup.as_raw_fd() as u32,
        attach_type,
        prog_ids: ids.as_mut_ptr() as u64,
        prog_cnt: ids.len() as u32,
        ..Default::default()
    };
    bpf(BPF_PROG_QUERY, &mut attr).context("BPF_PROG_QUERY on the cgroup root")?;
    ids.truncate(attr.prog_cnt as usize);
    Ok(ids)
}

/// On the legacy attach path an attachment outlives the agent (SIGKILL,
/// crash). Before attaching, detach only programs that are provably ours:
/// the same name and the same instruction tag (the kernel's hash of the
/// program with map fds zeroed, so identical across loads of this object)
/// as the program this agent just loaded. A program with our name but
/// another tag (another build) is not ours to remove: refuse to start.
/// Other tools' programs are never touched.
pub fn remove_stale_legacy(ebpf: &Ebpf, cgroup: &File) -> Result<()> {
    use std::os::fd::{AsFd, AsRawFd};
    for (name, attach_type) in CGROUP_PROGRAMS {
        let Some(prog) = ebpf.program(name) else {
            continue;
        };
        let Ok(ours) = prog.info() else {
            continue; // not loaded: nothing of ours to compare against
        };
        let short = &name[..name.len().min(15)]; // BPF_OBJ_NAME_LEN - 1
        for id in attached_ids(cgroup, attach_type)? {
            if id == ours.id() {
                continue;
            }
            let Some(info) = aya::programs::loaded_programs()
                .filter_map(|p| p.ok())
                .find(|p| p.id() == id)
            else {
                continue; // gone meanwhile
            };
            if info.name_as_str() != Some(short) {
                continue; // another tool's program
            }
            if info.tag() != ours.tag() {
                bail!(
                    "refusing to start: program {name} (id {id}) from another panopticon build \
                     is attached to the cgroup root and cannot be identified as stale; \
                     detach it with `bpftool cgroup detach`"
                );
            }
            let fd = info.fd().map_err(describe)?;
            let mut attr = DetachAttr {
                target_fd: cgroup.as_raw_fd() as u32,
                attach_bpf_fd: fd.as_fd().as_raw_fd() as u32,
                attach_type,
                ..Default::default()
            };
            bpf(BPF_PROG_DETACH, &mut attr)
                .with_context(|| format!("cannot detach stale {name} (id {id})"))?;
            warn!(
                prog = name,
                id, "removed a stale attachment left by an earlier agent"
            );
        }
    }
    Ok(())
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
