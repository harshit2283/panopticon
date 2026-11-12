//! Loader for the cgroup_skb capture backend (DESIGN §7): load-check every
//! program a mode needs before anything is attached, find the cgroup v2
//! root, publish the cgroup selectors (`CGROUP_ALLOW`, through the caller's
//! `select` hook), attach everything while the scope writers are disarmed,
//! publish `PID_FILTER`, and arm (`CONFIG_SCOPE_ARMED`) last.
//!
//! Self-contained (aya, anyhow, tracing, libc, panopticon-common only) so
//! the lab attach test (`tests/scope_attach.rs`) runs this same code.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya::util::KernelVersion;
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
/// The kTLS key-install markers (DESIGN §3.5), `(function, variants)`:
/// `sock_common_setsockopt` (and `compat_sock_common_setsockopt` where the
/// kernel has it, before 5.9 with CONFIG_COMPAT), each with the one variant
/// whose `struct socket` layout loads; else (5.9 to 6.0, where the first
/// takes a struct argument trampolines do not support)
/// `security_socket_setsockopt` and `__cgroup_bpf_run_filter_setsockopt`
/// (where the kernel has it), and before 5.14 also `tcp_set_ulp` (SMC).
pub const SOL_TLS_MARKERS: [(&str, &[&str]); 5] = [
    (
        "sock_common_setsockopt",
        &["scope_sol_tls", "scope_sol_tls_wq"],
    ),
    (
        "compat_sock_common_setsockopt",
        &["scope_sol_tls_compat", "scope_sol_tls_compat_wq"],
    ),
    ("security_socket_setsockopt", &["scope_sol_tls_lsm"]),
    (
        "__cgroup_bpf_run_filter_setsockopt",
        &["scope_sol_tls_cgroup"],
    ),
    ("tcp_set_ulp", &["scope_set_ulp"]),
];
pub const EXIT_TP: &str = "sched_process_exit";
/// TLS uprobe programs; the scope gate lives in their shared emit path.
pub const TLS_PROGRAMS: &[&str] = &[
    "ssl_write_entry",
    "ssl_write_ex_entry",
    "ssl_write_ret",
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
    /// The kTLS key-install marker variant loaded for each function in
    /// [`SOL_TLS_MARKERS`] the kernel has.
    pub markers: Vec<&'static str>,
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
    load_vrf_hooks(ebpf)?;
    let mut writers = true;
    for (p, target) in [(SOCK_CREATE, None), (SOCKOPS, None)] {
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
    let markers = match load_markers(ebpf) {
        Ok(m) => m,
        Err(e) if restricted => {
            return Err(e.context(format!(
                "refusing {settings}: every mode except unscoped full needs the kTLS \
                 key-install marker"
            )));
        }
        Err(e) => {
            warn!(error = %format!("{e:#}"), "kTLS marker unavailable; unscoped full continues");
            writers = false;
            Vec::new()
        }
    };
    let accept = [ACCEPT4, ACCEPT2]
        .into_iter()
        .find(|p| load_program(ebpf, p, Some("inet_csk_accept")).is_ok());
    if accept.is_none() && setup.mode & SCOPE_SEL_PID != 0 {
        warn!(
            "fexit inet_csk_accept loads in neither variant: pid_filter uses socket creators \
             only, so it selects no accepted connection under pid_filter_listener = \
             \"acceptor\" (the default)"
        );
    }
    let exit_tp = match load_program(ebpf, EXIT_TP, None) {
        Ok(()) => true,
        Err(e) if setup.mode & SCOPE_SEL_PID != 0 => {
            return Err(e.context(
                "refusing pid_filter: the sched_process_exit tracepoint is required (PID reuse)",
            ));
        }
        Err(e) if restricted && setup.tls => {
            return Err(e.context(format!(
                "refusing TLS capture with {settings}: the sched_process_exit tracepoint is \
                 required (it removes TLS_CALL slots of threads that exit mid-call); set \
                 tls_scan_enabled = false or use unscoped full"
            )));
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
        markers,
        exit_tp,
    })
}

/// Load the kTLS key-install markers ([`SOL_TLS_MARKERS`]): the programs to
/// attach, or why the kernel cannot be marked.
fn load_markers(ebpf: &mut Ebpf) -> Result<Vec<&'static str>> {
    let mut errors = Vec::new();
    let mut load = |ebpf: &mut Ebpf, (func, variants): (&str, &[&'static str])| {
        variants
            .iter()
            .copied()
            .find(|p| match load_program(ebpf, p, Some(func)) {
                Ok(()) => true,
                Err(e) => {
                    errors.push(format!("{e:#}"));
                    false
                }
            })
    };
    let [common, compat, lsm, cgroup, ulp] = SOL_TLS_MARKERS;
    // The first hook, then its companion, required where the kernel has it.
    let (first, second) = match load(ebpf, common) {
        Some(p) => (Some(p), compat),
        None => (load(ebpf, lsm), cgroup),
    };
    let mut markers: Vec<&'static str> = first.into_iter().collect();
    match load(ebpf, second) {
        Some(q) => markers.push(q),
        None if !kernel_has_symbol(second.0) => {}
        None => markers.clear(),
    }
    if first.is_none() {
        markers.clear();
    }
    // Past the LSM hook, SMC calls its TCP socket's `ops->setsockopt`
    // directly, and before 5.14 it passes `TCP_ULP` through to that socket:
    // there a ULP attach marks too (the rule before key-install marking).
    if markers.first().is_some_and(|p| lsm.1.contains(p))
        && KernelVersion::current().map_or(true, |v| v < KernelVersion::new(5, 14, 0))
    {
        match load(ebpf, ulp) {
            Some(p) => markers.push(p),
            None => markers.clear(),
        }
    }
    if markers.is_empty() {
        bail!("no complete set loads: {}", errors.join("; "));
    }
    Ok(markers)
}

/// Whether `/proc/kallsyms` lists `name`. Only a complete, successful scan
/// can establish absence: an open or read error counts as present, so its
/// hook is required (errs toward refusing).
fn kernel_has_symbol(name: &str) -> bool {
    match File::open("/proc/kallsyms") {
        Ok(f) => lists_symbol(std::io::BufReader::new(f), name),
        Err(_) => true,
    }
}

fn lists_symbol(r: impl std::io::BufRead, name: &str) -> bool {
    for line in r.lines() {
        match line {
            Ok(l) if l.split_whitespace().nth(2) == Some(name) => return true,
            Ok(_) => {}
            Err(_) => return true,
        }
    }
    false
}

// ── VRF masters (DESIGN §3.7) ──────────────────────────────────────────────

/// fexit `register_netdevice`: records every VRF master created from now on.
pub const VRF_REGISTER: &str = "scope_vrf_register";
/// Load the VRF hook (required: without it a VRF created later is captured
/// as remote traffic while `capture_loopback = false`). A VRF device cannot
/// change namespace (`NETIF_F_NETNS_LOCAL`), so its ifindex is final at
/// registration.
fn load_vrf_hooks(ebpf: &mut Ebpf) -> Result<()> {
    load_program(ebpf, VRF_REGISTER, Some("register_netdevice")).with_context(|| {
        "refusing to start: capture.backend = \"cgroup_skb\" needs fexit on \
         register_netdevice to recognise VRF devices (DESIGN §3.7)"
    })
}

/// Write the hook's offsets, attach it, then record every VRF master that
/// already exists (the scan), all before the capture hooks attach: a VRF
/// created during the scan is recorded by the hook. Returns the masters
/// the scan found.
pub fn start_vrf_watch(ebpf: &mut Ebpf, links: &mut Links) -> Result<Vec<u32>> {
    let raw = std::fs::read("/sys/kernel/btf/vmlinux").context("kernel BTF")?;
    let offs = netdev_offsets(&raw).context("net_device offsets from kernel BTF")?;
    {
        let mut a: aya::maps::Array<_, u32> =
            aya::maps::Array::try_from(ebpf.map_mut("NETDEV_OFFS").context("NETDEV_OFFS map")?)?;
        for (i, o) in offs.into_iter().enumerate() {
            a.set(i as u32, o, 0)?;
        }
    }
    let prog = ebpf
        .program_mut(VRF_REGISTER)
        .context("scope_vrf_register is not in the eBPF object")?;
    let aya::programs::Program::FExit(prog) = prog else {
        bail!("scope_vrf_register is not fexit");
    };
    links.push(Box::new(
        prog.attach()
            .map_err(describe)
            .context("scope_vrf_register does not attach")?,
    ));
    let found = scan_vrf_masters();
    let mut m: aya::maps::HashMap<_, u32, u8> =
        aya::maps::HashMap::try_from(ebpf.map_mut("VRF_MASTERS").context("VRF_MASTERS map")?)?;
    for &i in &found {
        m.insert(i, 1, 0)
            .with_context(|| format!("cannot record VRF master ifindex {i}"))?;
    }
    info!(masters = ?found, "VRF masters recorded");
    Ok(found)
}

/// Every network namespace reachable at startup: bind mounts in
/// `/run/netns`, every task's namespace, and every open namespace fd. A
/// namespace held only by a socket or a kernel reference is not reachable
/// (DESIGN §3.7). Deduplicated by inode.
fn netns_paths() -> Vec<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut add = |p: PathBuf| {
        if let Ok(m) = std::fs::metadata(&p)
            && seen.insert((m.dev(), m.ino()))
        {
            out.push(p);
        }
    };
    let ls = |d: &Path| -> Vec<PathBuf> {
        std::fs::read_dir(d)
            .map(|r| r.flatten().map(|e| e.path()).collect())
            .unwrap_or_default()
    };
    for p in ls(Path::new("/run/netns")) {
        add(p);
    }
    for proc_dir in ls(Path::new("/proc")) {
        if !proc_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        for t in ls(&proc_dir.join("task")) {
            add(t.join("ns/net"));
        }
        for fd in ls(&proc_dir.join("fd")) {
            if std::fs::read_link(&fd).is_ok_and(|l| l.to_string_lossy().starts_with("net:[")) {
                add(fd);
            }
        }
    }
    out
}

/// VRF masters (ifindex) in every reachable namespace. A namespace that
/// cannot be entered or dumped is logged, not fatal (DESIGN §3.7 states
/// the gap).
fn scan_vrf_masters() -> Vec<u32> {
    let mut all = Vec::new();
    for p in netns_paths() {
        let r = File::open(&p).map_err(anyhow::Error::from).and_then(|f| {
            std::thread::spawn(move || vrf_masters_in(&f))
                .join()
                .map_err(|_| anyhow::anyhow!("scan thread panicked"))?
        });
        match r {
            Ok(v) => all.extend(v),
            Err(e) => {
                warn!(netns = %p.display(), error = %format!("{e:#}"), "VRF scan skipped a namespace")
            }
        }
    }
    all.sort_unstable();
    all.dedup();
    all
}

/// Enter `ns` (this thread only) and dump its links over rtnetlink.
fn vrf_masters_in(ns: &File) -> Result<Vec<u32>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: setns on this (scan) thread only, with a namespace fd we hold.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setns");
    }
    // SAFETY: a new socket; owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("netlink socket");
    }
    // SAFETY: fd is a socket we just opened.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // nlmsghdr (16) + ifinfomsg (16): RTM_GETLINK dump.
    let mut req = [0u8; 32];
    req[0..4].copy_from_slice(&32u32.to_ne_bytes());
    req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
    req[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    req[8..12].copy_from_slice(&1u32.to_ne_bytes());
    // SAFETY: valid buffer for the call.
    if unsafe { libc::send(sock.as_raw_fd(), req.as_ptr().cast(), req.len(), 0) } < 0 {
        return Err(std::io::Error::last_os_error()).context("RTM_GETLINK");
    }
    let mut found = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        // SAFETY: valid buffer for the call.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error()).context("rtnetlink recv");
        }
        match parse_links(&buf[..n as usize], &mut found)? {
            true => return Ok(found),
            false if n == 0 => bail!("rtnetlink closed mid-dump"),
            false => {}
        }
    }
}

/// Parse one rtnetlink datagram of an RTM_GETLINK dump, adding the ifindex
/// of every link whose `IFLA_INFO_KIND` is "vrf". True at `NLMSG_DONE`.
fn parse_links(mut b: &[u8], found: &mut Vec<u32>) -> Result<bool> {
    const IFLA_LINKINFO: u16 = 18;
    const IFLA_INFO_KIND: u16 = 1;
    let u16_at = |b: &[u8], i: usize| u16::from_ne_bytes([b[i], b[i + 1]]);
    let u32_at = |b: &[u8], i: usize| u32::from_ne_bytes(b[i..i + 4].try_into().unwrap());
    let align = |n: usize| (n + 3) & !3;
    while b.len() >= 16 {
        let len = u32_at(b, 0) as usize;
        if len < 16 || len > b.len() {
            bail!("malformed rtnetlink message");
        }
        let msg = &b[..len];
        b = &b[align(len).min(b.len())..];
        match u16_at(msg, 4) as i32 {
            libc::NLMSG_DONE => return Ok(true),
            libc::NLMSG_ERROR => bail!("rtnetlink error {}", u32_at(msg, 16) as i32),
            t if t == libc::RTM_NEWLINK as i32 && msg.len() >= 32 => {
                let ifindex = u32_at(msg, 20);
                let mut a = &msg[32..];
                while a.len() >= 4 {
                    let alen = u16_at(a, 0) as usize;
                    if alen < 4 || alen > a.len() {
                        break;
                    }
                    if u16_at(a, 2) & 0x3fff == IFLA_LINKINFO {
                        let mut n = &a[4..alen];
                        while n.len() >= 4 {
                            let nlen = u16_at(n, 0) as usize;
                            if nlen < 4 || nlen > n.len() {
                                break;
                            }
                            if u16_at(n, 2) & 0x3fff == IFLA_INFO_KIND && &n[4..nlen] == b"vrf\0" {
                                found.push(ifindex);
                            }
                            n = &n[align(nlen).min(n.len())..];
                        }
                    }
                    a = &a[align(alen).min(a.len())..];
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

/// Byte offsets of `net_device.ifindex`, `net_device.rtnl_link_ops` and
/// `rtnl_link_ops.kind` from raw kernel BTF (aya keeps its type accessors
/// private). Members of anonymous structs and unions are searched too.
fn netdev_offsets(raw: &[u8]) -> Result<[u32; 3]> {
    let btf = RawBtf::parse(raw)?;
    let nd = btf
        .struct_by_name("net_device")
        .context("struct net_device")?;
    let ops = btf
        .struct_by_name("rtnl_link_ops")
        .context("struct rtnl_link_ops")?;
    let get = |s, m| {
        btf.member_offset(s, m)
            .with_context(|| format!("member {m}"))
    };
    Ok([
        get(nd, "ifindex")?,
        get(nd, "rtnl_link_ops")?,
        get(ops, "kind")?,
    ])
}

/// One BTF type: (kind, name_off, kind_flag, members as (name_off, type,
/// offset field)).
type BtfEntry = (u32, u32, bool, Vec<(u32, u32, u32)>);

/// Just enough of the BTF format to find struct member offsets.
struct RawBtf<'a> {
    strs: &'a [u8],
    types: Vec<BtfEntry>,
}

impl<'a> RawBtf<'a> {
    fn parse(raw: &'a [u8]) -> Result<Self> {
        let u32_at = |i: usize| -> Result<u32> {
            Ok(u32::from_le_bytes(
                raw.get(i..i + 4).context("BTF truncated")?.try_into()?,
            ))
        };
        if raw.len() < 24 || u16::from_le_bytes([raw[0], raw[1]]) != 0xeb9f {
            bail!("not little-endian BTF");
        }
        let hdr = u32_at(4)? as usize;
        let (toff, tlen) = (hdr + u32_at(8)? as usize, u32_at(12)? as usize);
        let (soff, slen) = (hdr + u32_at(16)? as usize, u32_at(20)? as usize);
        let strs = raw.get(soff..soff + slen).context("BTF strings")?;
        let mut types = vec![(0, 0, false, Vec::new())]; // id 0 is void
        let mut i = toff;
        while i < toff + tlen {
            let (name, info) = (u32_at(i)?, u32_at(i + 4)?);
            let (kind, vlen, kflag) = (
                (info >> 24) & 0x1f,
                (info & 0xffff) as usize,
                info >> 31 == 1,
            );
            i += 12;
            let mut members = Vec::new();
            let extra = match kind {
                1 | 14 | 17 => 4, // INT, VAR, DECL_TAG
                3 => 12,          // ARRAY
                4 | 5 => {
                    for m in 0..vlen {
                        let j = i + m * 12;
                        members.push((u32_at(j)?, u32_at(j + 4)?, u32_at(j + 8)?));
                    }
                    vlen * 12
                }
                6 | 13 => vlen * 8,   // ENUM, FUNC_PROTO
                15 | 19 => vlen * 12, // DATASEC, ENUM64
                _ => 0,
            };
            i += extra;
            types.push((kind, name, kflag, members));
        }
        Ok(Self { strs, types })
    }

    fn name(&self, off: u32) -> &[u8] {
        let s = self.strs.get(off as usize..).unwrap_or_default();
        &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
    }

    fn struct_by_name(&self, n: &str) -> Option<u32> {
        self.types
            .iter()
            .position(|(k, name, _, m)| {
                *k == 4 && !m.is_empty() && self.name(*name) == n.as_bytes()
            })
            .map(|i| i as u32)
    }

    /// Byte offset of member `m` in struct/union `id`, through anonymous
    /// members.
    fn member_offset(&self, id: u32, m: &str) -> Option<u32> {
        let (_, _, kflag, members) = self.types.get(id as usize)?;
        for &(name, ty, off) in members {
            let bits = if *kflag { off & 0xff_ffff } else { off };
            if self.name(name) == m.as_bytes() {
                return Some(bits / 8);
            }
            // An anonymous member is a STRUCT or UNION directly.
            if name == 0
                && let Some(inner) = self.member_offset(ty, m)
            {
                return Some(bits / 8 + inner);
            }
        }
        None
    }
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

/// Attach everything `setup` needs, with the scope writers disarmed, in
/// dependency order:
/// 1. load-check everything (nothing attached if any required program fails);
/// 2. `select` (cgroup_filter/pod_filter: publish CGROUP_ALLOW) once the
///    root is known and the private-root refusal has passed;
/// 3. write the `pid_filter` candidates (PID_CANDIDATES), then attach
///    sched_process_exit, so every candidate exit from here on is recorded
///    in PID_EXITED for [`arm`];
/// 4. the kTLS key-install markers, so no socket installs kTLS keys unmarked;
/// 5. the VRF hooks and the scan of existing VRF masters, then both capture
///    hooks and fexit accept;
/// 6. sock_create and sockops.
///
/// Nothing is initialised before [`arm`], so no socket gets state while a
/// dependency above is missing. Returns the root and whether the exit
/// tracepoint was attached.
pub fn attach_disarmed(
    ebpf: &mut Ebpf,
    setup: &ScopeSetup,
    pids: Option<&[Candidate]>,
    select: impl FnOnce(&mut Ebpf, &CgroupRoot) -> Result<()>,
    links: &mut Links,
) -> Result<(CgroupRoot, bool)> {
    // Disarmed whatever CONFIG held before (a pinned CONFIG survives
    // restarts); sync_config_to_ebpf writes 0 too.
    config_array(ebpf)?.set(CONFIG_SCOPE_ARMED, 0, 0)?;
    let report = load_check(ebpf, setup)?;
    let root = discover_cgroup_root(&setup.cgroup2_path)?;
    if setup.mode & SCOPE_SEL_CGROUP != 0 && matches!(root, CgroupRoot::Private(_)) {
        bail!(
            "refusing cgroup_filter/pod_filter: {} is a private cgroup2 on a cgroup v1 host, \
             where every socket is in its root (DESIGN §3.2); pid_filter works",
            root.path().display()
        );
    }
    select(&mut *ebpf, &root)?;
    let cgroup = File::open(root.path())
        .with_context(|| format!("cannot open cgroup root {}", root.path().display()))?;
    if !uses_links() {
        take_instance_lock()?;
        remove_stale_legacy(ebpf, &cgroup)?;
    }
    if let Some(pids) = pids {
        let mut map = pid_map(ebpf, "PID_CANDIDATES")?;
        for &Candidate { pid, .. } in pids {
            map.insert(pid, 1, 0)
                .with_context(|| format!("cannot add PID {pid} to PID_CANDIDATES"))?;
        }
    }
    let restricted = setup.mode != 0;
    let settings = mode_settings(setup.mode);
    // (program, required)
    let mut order: Vec<(&str, bool)> = Vec::new();
    if report.exit_tp {
        // Required by pid_filter (PID reuse) and by restricted TLS (TLS_CALL
        // slots of threads that exit mid-call).
        order.push((
            EXIT_TP,
            setup.mode & SCOPE_SEL_PID != 0 || restricted && setup.tls,
        ));
    }
    if report.writers {
        order.extend(report.markers.iter().map(|&p| (p, restricted)));
    }
    order.extend([(SKB_INGRESS, true), (SKB_EGRESS, true)]);
    order.extend(report.accept.map(|p| (p, false)));
    if report.writers {
        order.extend([(SOCK_CREATE, restricted), (SOCKOPS, restricted)]);
    }
    // VRF masters are known before any capture hook runs (§3.7).
    start_vrf_watch(ebpf, links).context("refusing to start")?;
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

fn config_array(ebpf: &mut Ebpf) -> Result<aya::maps::Array<&mut aya::maps::MapData, u64>> {
    Ok(aya::maps::Array::try_from(
        ebpf.map_mut("CONFIG").context("CONFIG map not found")?,
    )?)
}

fn pid_map<'a>(
    ebpf: &'a mut Ebpf,
    name: &str,
) -> Result<aya::maps::HashMap<&'a mut aya::maps::MapData, u32, u8>> {
    Ok(aya::maps::HashMap::try_from(
        ebpf.map_mut(name)
            .with_context(|| format!("{name} map not found"))?,
    )?)
}

/// Why [`arm`] left a listed process out.
pub const NOT_RUNNING: &str = "not running when pid_filter was read";
pub const EXITED_RECORDED: &str = "exit recorded by sched_process_exit during startup";
pub const IDENTITY_CHANGED: &str = "gone, or its PID reused, since pid_filter was read";
pub const EXITED_BEFORE_ATTACH: &str = "exiting before sched_process_exit was attached";

/// A configured `pid_filter` process as the agent found it when it read the
/// config: a pidfd (the identity, where pidfd_open exists: 5.3+) and its
/// start time (clock ticks since boot, `/proc/<pid>/stat` field 22; the
/// identity without pidfd_open). Neither: not running then.
#[derive(Debug)]
pub struct Candidate {
    pub pid: u32,
    pub start: Option<u64>,
    pub pidfd: Option<std::os::fd::OwnedFd>,
}

impl Candidate {
    fn running(&self) -> bool {
        self.pidfd.is_some() || self.start.is_some()
    }
}

/// Fields of `/proc/<pid>/stat`, from field 3 (state) on: the ones after
/// the comm, split after the last ')' since comm may hold spaces and ')'.
fn stat_fields(pid: u32) -> Option<Vec<u64>> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_stat(stat: &str) -> Option<Vec<u64>> {
    let (_, rest) = stat.rsplit_once(')')?;
    // state (field 3) is a letter; keep its slot so indices stay aligned
    Some(
        rest.split_whitespace()
            .map(|f| f.parse().unwrap_or(u64::MAX))
            .collect(),
    )
}

/// Field `n` (1-based, as in proc(5)) of `/proc/<pid>/stat`, n >= 4.
fn stat_field(fields: &[u64], n: usize) -> Option<u64> {
    fields.get(n - 3).copied().filter(|&v| v != u64::MAX)
}

const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
const SYS_PIDFD_OPEN: libc::c_long = 434;

fn pidfd_open(pid: u32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain syscall; a non-negative result is a new fd we own.
    let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::pid_t, 0u32) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

/// The pidfd's process has not exited: signal 0 reaches it (ESRCH once it
/// is gone) and the pidfd is not readable (it becomes readable when the
/// process exits). Any error counts as exited.
fn pidfd_alive(fd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: valid pidfd; signal 0 with no siginfo only checks.
    let rc = unsafe {
        libc::syscall(
            SYS_PIDFD_SEND_SIGNAL,
            fd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if rc != 0 {
        return false;
    }
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd, no wait.
    unsafe { libc::poll(&mut p, 1, 0) == 0 }
}

/// Snapshot the configured PIDs' identities: a pidfd each, or their start
/// times where pidfd_open does not exist (ENOSYS). Call it when the agent
/// first reads `pid_filter`, before anything is attached, and hand the
/// result to [`arm`], which closes the pidfds. A PID already reused before
/// this read cannot be told from the operator's target: that is inherent to
/// a numeric pid_filter.
// ponytail: the start-time fallback has clock-tick (USER_HZ) resolution, so
// on kernels without pidfd_open an exit and reuse within one tick of the
// original start is missed.
pub fn snapshot_candidates(pids: &[u32]) -> Vec<Candidate> {
    let mut pidfd_supported = true;
    let out: Vec<Candidate> = pids
        .iter()
        .map(|&pid| {
            let start = stat_fields(pid).and_then(|f| stat_field(&f, 22));
            match pidfd_open(pid) {
                Ok(fd) => Candidate {
                    pid,
                    start,
                    pidfd: Some(fd),
                },
                Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                    pidfd_supported = false;
                    Candidate {
                        pid,
                        start,
                        pidfd: None,
                    }
                }
                // ESRCH (gone), EINVAL (not a process), ...: not selectable.
                Err(_) => Candidate {
                    pid,
                    start: None,
                    pidfd: None,
                },
            }
        })
        .collect();
    if !pids.is_empty() {
        let method = if pidfd_supported {
            "pidfd"
        } else {
            "start time (no pidfd_open)"
        };
        info!(method, "pid_filter process identity");
    }
    out
}

/// Publish `pid_filter` and arm: the last write of startup. Must follow
/// [`attach_disarmed`] with the same candidates; closes their pidfds.
/// Returns the listed processes that were left out, and why.
///
/// For each candidate: insert into PID_FILTER, THEN look in PID_EXITED and
/// remove the entry if the exit tracepoint recorded the process. The
/// tracepoint records before it removes (process_monitor.rs), so whichever
/// way the two race the entry ends up absent. A candidate not recorded is
/// still left out if it is no longer the process the config was read
/// against (it exited, unseen, before the tracepoint was attached, and the
/// PID may be reused) or if it was already exiting.
pub fn arm(ebpf: &mut Ebpf, pids: Option<Vec<Candidate>>) -> Result<Vec<(u32, &'static str)>> {
    const PF_EXITING: u64 = 0x4;
    let mut excluded = Vec::new();
    if let Some(pids) = &pids {
        let mut filter = pid_map(ebpf, "PID_FILTER")?;
        for c in pids {
            if !c.running() {
                excluded.push((c.pid, NOT_RUNNING));
                continue;
            }
            filter
                .insert(c.pid, 1, 0)
                .with_context(|| format!("cannot add PID {} to the PID_FILTER map", c.pid))?;
        }
        let exited = pid_map(ebpf, "PID_EXITED")?;
        for c in pids.iter().filter(|c| c.running()) {
            match exited.get(&c.pid, 0) {
                Ok(_) => excluded.push((c.pid, EXITED_RECORDED)),
                Err(aya::maps::MapError::KeyNotFound) => {
                    // The exit tracepoint is attached now, so the process,
                    // if still running and not yet exiting, will have its
                    // exit recorded. PF_EXITING is set before the tracepoint
                    // runs. The stat is read before the identity check: a
                    // pidfd still alive afterwards means it was this
                    // process's. Unreadable counts as gone.
                    let fields = stat_fields(c.pid).unwrap_or_default();
                    let same = match &c.pidfd {
                        Some(fd) => pidfd_alive(fd),
                        None => stat_field(&fields, 22) == c.start,
                    };
                    if !same {
                        excluded.push((c.pid, IDENTITY_CHANGED));
                    } else if stat_field(&fields, 9).is_none_or(|f| f & PF_EXITING != 0) {
                        excluded.push((c.pid, EXITED_BEFORE_ATTACH));
                    }
                }
                Err(e) => {
                    return Err(e).context(format!("cannot read PID_EXITED for {}", c.pid));
                }
            }
        }
        let lost: aya::maps::Array<_, u64> = aya::maps::Array::try_from(
            ebpf.map("PID_EXITED_LOST")
                .context("PID_EXITED_LOST map not found")?,
        )?;
        let lost = lost.get(&0, 0)?;
        if lost != 0 {
            bail!(
                "refusing pid_filter: {lost} exits of listed processes could not be recorded \
                 during startup (PID_EXITED full), so a reused PID could be selected"
            );
        }
        let mut filter = pid_map(ebpf, "PID_FILTER")?;
        for &(pid, why) in &excluded {
            warn!(pid, reason = why, "pid_filter process not selected");
            remove_pid(&mut filter, pid)?;
        }
    }
    config_array(ebpf)?.set(CONFIG_SCOPE_ARMED, 1, 0)?;
    info!("capture scope armed");
    if let Some(pids) = pids {
        // Armed: the exit tracepoint no longer reads the candidates.
        let mut candidates = pid_map(ebpf, "PID_CANDIDATES")?;
        for c in &pids {
            remove_pid(&mut candidates, c.pid)?;
        }
    } // the pidfds close here
    Ok(excluded)
}

/// Remove `pid`. Already absent is fine: never inserted (not running at
/// read), or removed meanwhile by the exit tracepoint.
fn remove_pid(
    map: &mut aya::maps::HashMap<&mut aya::maps::MapData, u32, u8>,
    pid: u32,
) -> Result<()> {
    match map.remove(&pid) {
        Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
        Err(aya::maps::MapError::SyscallError(e))
            if e.io_error.raw_os_error() == Some(libc::ENOENT) =>
        {
            Ok(())
        }
        Err(e) => Err(e).context(format!("cannot remove PID {pid}")),
    }
}

/// Attach (disarmed), then arm. The production startup path. `select`
/// publishes the cgroup selectors (see [`attach_disarmed`]).
pub fn load_and_attach(
    ebpf: &mut Ebpf,
    setup: &ScopeSetup,
    pids: Option<Vec<Candidate>>,
    select: impl FnOnce(&mut Ebpf, &CgroupRoot) -> Result<()>,
    links: &mut Links,
) -> Result<(CgroupRoot, bool)> {
    let r = attach_disarmed(ebpf, setup, pids.as_deref(), select, links)?;
    arm(ebpf, pids)?;
    Ok(r)
}

// ── Instance lock ──────────────────────────────────────────────────────────

/// Host path of the instance lock.
pub const INSTANCE_LOCK: &str = "/run/panopticon/scope.lock";

static LOCK: std::sync::OnceLock<File> = std::sync::OnceLock::new();

/// One agent instance owns the legacy (outliving) cgroup attachments: take
/// an exclusive lock, held for the life of the process, before removing
/// any. Held by another instance: refuse to start.
pub fn take_instance_lock() -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    if LOCK.get().is_some() {
        return Ok(());
    }
    let path = Path::new(INSTANCE_LOCK);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot open {INSTANCE_LOCK}"))?;
    // SAFETY: flock on an fd we own.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        bail!(
            "refusing to start: cannot lock {INSTANCE_LOCK} ({e}); another agent instance \
             owns the cgroup attachments"
        );
    }
    let _ = LOCK.set(f);
    Ok(())
}

// ── Stale legacy attachments (RHEL 8) ──────────────────────────────────────

/// Whether aya attaches cgroup programs through bpf_link (5.7+), whose
/// attachment dies with the agent. The same test aya makes.
pub fn uses_links() -> bool {
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

const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;

#[repr(C)]
#[derive(Default)]
struct GetFdByIdAttr {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

/// The prefix of `struct bpf_prog_info` up to `name` (4.15+).
#[repr(C)]
#[derive(Default)]
struct ProgInfo {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
}

impl ProgInfo {
    fn name(&self) -> &[u8] {
        let n = self.name.iter().position(|&b| b == 0).unwrap_or(16);
        &self.name[..n]
    }
}

fn prog_info(fd: std::os::fd::BorrowedFd<'_>) -> Result<ProgInfo> {
    use std::os::fd::AsRawFd;
    let mut info = ProgInfo::default();
    let mut attr = InfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: std::mem::size_of::<ProgInfo>() as u32,
        info: &mut info as *mut ProgInfo as u64,
    };
    bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr).context("BPF_OBJ_GET_INFO_BY_FD")?;
    Ok(info)
}

fn prog_fd_by_id(id: u32) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let mut attr = GetFdByIdAttr {
        id,
        ..Default::default()
    };
    // SAFETY: attr is a valid bpf_attr prefix of the given size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_GET_FD_BY_ID,
            &mut attr as *mut GetFdByIdAttr,
            std::mem::size_of::<GetFdByIdAttr>() as u32,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("BPF_PROG_GET_FD_BY_ID");
    }
    // SAFETY: the kernel returned a new fd that nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

/// On the legacy attach path an attachment outlives the agent (SIGKILL,
/// crash). Before attaching, and holding the instance lock, detach only
/// programs that are provably ours: the same name and the same instruction
/// tag (the kernel's hash of the program with map fds zeroed, so identical
/// across loads of this object) as the program this agent loaded. Every
/// failure to enumerate or identify refuses to start: a program with our
/// name and another tag (another build), one with our name that this agent
/// did not load and so cannot compare, and any query or lookup error.
/// Other tools' programs are never touched.
pub fn remove_stale_legacy(ebpf: &Ebpf, cgroup: &File) -> Result<()> {
    use std::os::fd::{AsFd, AsRawFd};
    for (name, attach_type) in CGROUP_PROGRAMS {
        let ours = match ebpf.program(name).map(|p| p.fd()) {
            Some(Ok(fd)) => {
                Some(prog_info(fd.as_fd()).with_context(|| format!("cannot identify our {name}"))?)
            }
            _ => None,
        };
        let short = &name.as_bytes()[..name.len().min(15)]; // BPF_OBJ_NAME_LEN - 1
        for id in attached_ids(cgroup, attach_type)? {
            let refuse = || {
                format!(
                    "refusing to start: cannot identify program id {id} attached to the \
                     cgroup root for {name}"
                )
            };
            let fd = prog_fd_by_id(id).with_context(refuse)?;
            let info = prog_info(fd.as_fd()).with_context(refuse)?;
            if info.name() != short {
                continue; // another tool's program
            }
            let Some(ours) = &ours else {
                bail!(
                    "refusing to start: program {name} (id {id}) is attached to the cgroup root \
                     but this agent did not load {name} to compare it against; detach it with \
                     `bpftool cgroup detach`"
                );
            };
            if info.id == ours.id {
                continue;
            }
            if info.tag != ours.tag {
                bail!(
                    "refusing to start: program {name} (id {id}) from another panopticon build \
                     is attached to the cgroup root and cannot be identified as stale; \
                     detach it with `bpftool cgroup detach`"
                );
            }
            let mut attr = DetachAttr {
                target_fd: cgroup.as_raw_fd() as u32,
                attach_bpf_fd: fd.as_raw_fd() as u32,
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
    fn rtnetlink_dump_finds_vrf_links() {
        // RTM_NEWLINK ifindex 7 with IFLA_LINKINFO { IFLA_INFO_KIND "vrf" },
        // ifindex 8 kind "veth", then NLMSG_DONE.
        let link = |ifindex: u32, kind: &[u8]| {
            let attr = |ty: u16, body: &[u8]| {
                let mut a = [
                    &((4 + body.len()) as u16).to_ne_bytes()[..],
                    &ty.to_ne_bytes(),
                    body,
                ]
                .concat();
                a.resize(a.len().div_ceil(4) * 4, 0);
                a
            };
            let mut ifi = vec![0u8; 16];
            ifi[4..8].copy_from_slice(&ifindex.to_ne_bytes());
            let body = [ifi, attr(18, &attr(1, kind))].concat();
            let mut h = vec![0u8; 16];
            h[0..4].copy_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
            h[4..6].copy_from_slice(&libc::RTM_NEWLINK.to_ne_bytes());
            [h, body].concat()
        };
        let mut done = vec![0u8; 20];
        done[0..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        let mut found = Vec::new();
        let first = [link(7, b"vrf\0"), link(8, b"veth\0")].concat();
        assert!(!parse_links(&first, &mut found).unwrap());
        assert!(parse_links(&done, &mut found).unwrap());
        assert_eq!(found, vec![7]);
        assert!(parse_links(&[0u8; 16], &mut found).is_err(), "zero length");
    }

    /// A reader that yields `head`, then fails.
    struct FailsAfter(std::io::Cursor<Vec<u8>>);
    impl std::io::Read for FailsAfter {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(b)? {
                0 => Err(std::io::Error::other("ENOMEM")),
                n => Ok(n),
            }
        }
    }

    #[test]
    fn only_a_complete_scan_establishes_absence() {
        let syms = "ffff t foo\nffff T bar\n";
        assert!(lists_symbol(syms.as_bytes(), "bar"));
        assert!(!lists_symbol(syms.as_bytes(), "baz"));
        let failing = std::io::BufReader::new(FailsAfter(std::io::Cursor::new(syms.into())));
        assert!(
            lists_symbol(failing, "baz"),
            "a read error must count as present"
        );
    }

    #[test]
    fn stat_fields_survive_a_hostile_comm() {
        // comm "a) 9 (b": fields must be counted after the last ')'.
        let stat = "42 (a) 9 (b) S 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 987654 0";
        let f = parse_stat(stat).unwrap();
        assert_eq!(stat_field(&f, 9), Some(4194560));
        assert_eq!(stat_field(&f, 22), Some(987654));
        assert_eq!(stat_field(&f, 3), None); // the state letter
        assert_eq!(stat_field(&f, 60), None);
    }

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
