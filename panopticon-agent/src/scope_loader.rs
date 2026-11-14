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

/// Write where the capture hooks read the packet device's
/// `IFF_L3MDEV_MASTER` bit (`NETDEV_OFFS`), from the kernel's BTF. Called
/// before the capture hooks attach; until then the mask is 0 and every
/// packet counts as on a VRF master (fails closed). Classification is per
/// packet, from the device the packet is on: there is no VRF inventory.
pub fn write_netdev_offsets(ebpf: &mut Ebpf) -> Result<[u32; 3]> {
    let raw = std::fs::read("/sys/kernel/btf/vmlinux").context("kernel BTF")?;
    let offs = netdev_offsets(&raw).context("IFF_L3MDEV_MASTER location from kernel BTF")?;
    let mut a: aya::maps::Array<_, u32> =
        aya::maps::Array::try_from(ebpf.map_mut("NETDEV_OFFS").context("NETDEV_OFFS map")?)?;
    for (i, o) in offs.into_iter().enumerate() {
        a.set(i as u32, o, 0)?;
    }
    info!(
        skb_dev = offs[0],
        flag_byte = offs[1],
        flag_mask = offs[2],
        "VRF master flag located"
    );
    Ok(offs)
}

/// `[sk_buff.dev byte offset, byte offset in net_device of the priv_flags
/// byte holding IFF_L3MDEV_MASTER, that bit's mask]` (`scope::NETDEV_*`)
/// from raw kernel BTF (aya keeps its type accessors private). Members of
/// anonymous structs and unions are searched (bounded depth); every member
/// used must lie inside its container and have the expected shape (`dev`: a
/// pointer to `struct net_device`, whose `priv_flags` is then searched in
/// that very type, not one found by name; `priv_flags`: an integer with no
/// encoding offset, or a bitfield, wide enough for the bit;
/// `IFF_L3MDEV_MASTER`: a single bit; the byte read inside `net_device`).
/// Anything else is refused, so a wrong offset is never used.
fn netdev_offsets(raw: &[u8]) -> Result<[u32; 3]> {
    let btf = RawBtf::parse(raw)?;
    let skb = btf.struct_by_name("sk_buff").context("struct sk_buff")?;
    let (dev_bits, dev_bf, dev_t) = btf.member(skb, "dev", 0).context("member sk_buff.dev")?;
    let nd = btf.pointee(dev_t).context("sk_buff.dev is not a pointer")?;
    let (nd_kind, nd_name, _, nd_size, nd_members) = &btf.types[nd as usize];
    if dev_bf != 0
        || dev_bits % 8 != 0
        || *nd_kind != BTF_STRUCT
        || nd_members.is_empty()
        || btf.name(*nd_name) != b"net_device"
    {
        bail!("sk_buff.dev is not a pointer to struct net_device");
    }
    let (pf_bits, pf_bf, pf_t) = btf
        .member(nd, "priv_flags", 0)
        .context("member net_device.priv_flags")?;
    let (int_size, int_off, int_bits) = btf
        .int_info(pf_t)
        .context("net_device.priv_flags is not an integer")?;
    if int_off != 0 || int_bits != int_size * 8 {
        bail!("net_device.priv_flags has an integer encoding offset or partial width");
    }
    let width = if pf_bf != 0 { pf_bf } else { int_bits };
    let val = btf
        .enumerator("IFF_L3MDEV_MASTER")
        .context("enumerator IFF_L3MDEV_MASTER")?;
    if !val.is_power_of_two() || val.trailing_zeros() >= width {
        bail!("IFF_L3MDEV_MASTER ({val:#x}) is not a single bit of priv_flags");
    }
    let bit = pf_bits + val.trailing_zeros();
    if bit / 8 >= *nd_size {
        bail!("IFF_L3MDEV_MASTER byte lies outside struct net_device");
    }
    let mask = 1u32 << (bit % 8);
    Ok([dev_bits / 8, bit / 8, mask])
}

const BTF_INT: u32 = 1;
const BTF_PTR: u32 = 2;
const BTF_STRUCT: u32 = 4;
const BTF_UNION: u32 = 5;
const BTF_ENUM: u32 = 6;
const BTF_ENUM64: u32 = 19;
/// Kinds that only qualify or name another type: typedef, volatile, const,
/// restrict, type tag.
const BTF_MODIFIERS: [u32; 5] = [8, 9, 10, 11, 18];
/// How deep anonymous members are searched.
const BTF_ANON_DEPTH: u32 = 8;

/// One BTF type: (kind, name_off, kind_flag, size_or_type, members as
/// (name_off, type, offset field); for an INT, one entry holding its
/// encoding word as (0, 0, encoding)).
type BtfEntry = (u32, u32, bool, u32, Vec<(u32, u32, u32)>);

/// Just enough of the BTF format to find struct members and enumerators,
/// strictly: a known version, every section and record within bounds, no
/// unknown kind.
struct RawBtf<'a> {
    strs: &'a [u8],
    types: Vec<BtfEntry>,
    /// Every enumerator: (name_off, value).
    enums: Vec<(u32, u64)>,
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
        if raw[2] != 1 {
            bail!("BTF version {} (expected 1)", raw[2]);
        }
        let hdr = u32_at(4)? as usize;
        if hdr < 24 {
            bail!("BTF header too short");
        }
        let section = |off: usize, len: usize| -> Result<std::ops::Range<usize>> {
            let start = hdr.checked_add(off).context("BTF section offset")?;
            let end = start.checked_add(len).context("BTF section length")?;
            if end > raw.len() {
                bail!("BTF section out of bounds");
            }
            Ok(start..end)
        };
        let types_r = section(u32_at(8)? as usize, u32_at(12)? as usize)?;
        let strs = &raw[section(u32_at(16)? as usize, u32_at(20)? as usize)?];
        let mut types = vec![(0, 0, false, 0, Vec::new())]; // id 0 is void
        let mut enums = Vec::new();
        let mut i = types_r.start;
        while i < types_r.end {
            if i + 12 > types_r.end {
                bail!("BTF type record crosses the type section");
            }
            let (name, info, size_or_type) = (u32_at(i)?, u32_at(i + 4)?, u32_at(i + 8)?);
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
                6 => {
                    for m in 0..vlen {
                        let j = i + m * 8;
                        enums.push((u32_at(j)?, u32_at(j + 4)? as u64));
                    }
                    vlen * 8
                }
                19 => {
                    for m in 0..vlen {
                        let j = i + m * 12;
                        let v = (u32_at(j + 8)? as u64) << 32 | u32_at(j + 4)? as u64;
                        enums.push((u32_at(j)?, v));
                    }
                    vlen * 12
                }
                13 => vlen * 8,            // FUNC_PROTO
                15 => vlen * 12,           // DATASEC
                2 | 7..=12 | 16 | 18 => 0, // PTR, FWD, modifiers, FUNC, FLOAT, TYPE_TAG
                k => bail!("unknown BTF kind {k}"),
            };
            if kind == BTF_INT {
                // The INT encoding's bit size must fit the declared size.
                let enc = u32_at(i)?;
                if (enc & 0xff) + ((enc >> 16) & 0xff) > size_or_type * 8 {
                    bail!("malformed BTF int");
                }
                members.push((0, 0, enc));
            }
            i += extra;
            if i > types_r.end {
                bail!("BTF type record crosses the type section");
            }
            types.push((kind, name, kflag, size_or_type, members));
        }
        Ok(Self { strs, types, enums })
    }

    fn name(&self, off: u32) -> &[u8] {
        let s = self.strs.get(off as usize..).unwrap_or_default();
        &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]
    }

    /// The one complete struct named `n`; refused if there are two.
    fn struct_by_name(&self, n: &str) -> Option<u32> {
        let mut found = self
            .types
            .iter()
            .enumerate()
            .filter(|(_, (k, name, _, _, m))| {
                *k == BTF_STRUCT && !m.is_empty() && self.name(*name) == n.as_bytes()
            });
        let (id, _) = found.next()?;
        found.next().is_none().then_some(id as u32)
    }

    /// The value of the enumerator `n`; refused if it is defined twice with
    /// different values.
    fn enumerator(&self, n: &str) -> Option<u64> {
        let mut found = None;
        for &(name, v) in &self.enums {
            if self.name(name) == n.as_bytes() {
                if found.is_some_and(|f| f != v) {
                    return None;
                }
                found = Some(v);
            }
        }
        found
    }

    /// `t` with typedefs and qualifiers stripped (bounded: BTF has no
    /// cycles through them, but a malformed one is refused).
    fn strip(&self, mut t: u32) -> Option<u32> {
        for _ in 0..32 {
            let (k, _, _, next, _) = self.types.get(t as usize)?;
            if !BTF_MODIFIERS.contains(k) {
                return Some(t);
            }
            t = *next;
        }
        None
    }

    /// (size in bytes, encoding bit offset, encoding bits) of `t` if it is
    /// (after modifiers) an INT.
    fn int_info(&self, t: u32) -> Option<(u32, u32, u32)> {
        let t = self.strip(t)?;
        let (k, _, _, size, enc) = self.types.get(t as usize)?;
        let enc = enc.first()?.2;
        (*k == BTF_INT).then_some((*size, (enc >> 16) & 0xff, enc & 0xff))
    }

    /// Size in bytes of `t` (after modifiers): integers, pointers,
    /// aggregates and enums only; anything else is unknown.
    fn size_of(&self, t: u32) -> Option<u32> {
        let t = self.strip(t)?;
        let (k, _, _, size, _) = self.types.get(t as usize)?;
        match *k {
            BTF_INT | BTF_STRUCT | BTF_UNION | BTF_ENUM | BTF_ENUM64 => Some(*size),
            BTF_PTR => Some(8),
            _ => None,
        }
    }

    /// The type `t` points to (modifiers stripped on both sides).
    fn pointee(&self, t: u32) -> Option<u32> {
        let t = self.strip(t)?;
        let (k, _, _, target, _) = self.types.get(t as usize)?;
        if *k != BTF_PTR {
            return None;
        }
        self.strip(*target)
    }

    /// (bit offset, bitfield size or 0, type) of member `m` of struct/union
    /// `id`, searching anonymous members up to [`BTF_ANON_DEPTH`] deep. The
    /// member found, and every anonymous member on the way, must lie inside
    /// its container; a bitfield must start on a byte boundary; a union
    /// member must start at 0 (the BTF is refused otherwise); an anonymous
    /// aggregate encoded as a bitfield is not searched.
    fn member(&self, id: u32, m: &str, depth: u32) -> Option<(u32, u32, u32)> {
        let (kind, _, kflag, size, members) = self.types.get(id as usize)?;
        let container_bits = size.checked_mul(8)?;
        for &(name, ty, off) in members {
            let (bits, bitfield) = if *kflag {
                (off & 0xff_ffff, off >> 24)
            } else {
                (off, 0)
            };
            if *kind == BTF_UNION && bits != 0 {
                return None; // malformed: a union member starts at 0
            }
            if bits % 8 != 0 {
                continue;
            }
            let extent = if bitfield != 0 {
                bitfield
            } else {
                self.size_of(ty).map_or(0, |s| s * 8)
            };
            if self.name(name) == m.as_bytes() {
                return (extent != 0 && bits.checked_add(extent)? <= container_bits)
                    .then_some((bits, bitfield, ty));
            }
            if name == 0 && bitfield == 0 && depth < BTF_ANON_DEPTH {
                let inner = self.strip(ty)?;
                if matches!(
                    self.types.get(inner as usize),
                    Some((BTF_STRUCT | BTF_UNION, ..))
                ) && extent != 0
                    && bits.checked_add(extent)? <= container_bits
                    && let Some((o, bf, t)) = self.member(inner, m, depth + 1)
                {
                    return Some((bits + o, bf, t));
                }
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
/// 5. the VRF master flag's location (`NETDEV_OFFS`), then both capture
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
    // The capture hooks classify VRF masters from the packet's device
    // (§3.7): its flag's location is written before they attach.
    write_netdev_offsets(ebpf).context("refusing to start")?;
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

    /// A BTF blob builder: types as (kind, name, kind_flag, size_or_type,
    /// extra words, vlen); names are interned into the string table.
    struct BtfBuilder {
        strs: Vec<u8>,
        types: Vec<u8>,
        n: u32,
    }

    impl BtfBuilder {
        fn new() -> Self {
            Self {
                strs: vec![0],
                types: Vec::new(),
                n: 0,
            }
        }

        fn s(&mut self, n: &str) -> u32 {
            if n.is_empty() {
                return 0;
            }
            let o = self.strs.len() as u32;
            self.strs.extend_from_slice(n.as_bytes());
            self.strs.push(0);
            o
        }

        fn ty(&mut self, kind: u32, name: &str, kflag: bool, size: u32, extra: &[u32], vlen: u32) {
            let n = self.s(name);
            let info = (u32::from(kflag) << 31) | (kind << 24) | vlen;
            self.n += 1;
            for w in [n, info, size].iter().chain(extra) {
                self.types.extend(w.to_le_bytes());
            }
        }

        /// Types added so far (the id of the last one).
        fn count(&self) -> u32 {
            self.n
        }

        fn build(&self, version: u8) -> Vec<u8> {
            let mut b = vec![0x9f, 0xeb, version, 0];
            let t = self.types.len() as u32;
            for w in [24u32, 0, t, t, self.strs.len() as u32] {
                b.extend(w.to_le_bytes());
            }
            b.extend(&self.types);
            b.extend(&self.strs);
            b
        }
    }

    /// sk_buff { union { net_device *dev } @16 }, net_device { int x @0;
    /// struct { u64 priv_flags:`bf` @0 } @8 }, enum { IFF_X = 1,
    /// IFF_L3MDEV_MASTER = `flag` }. `skb_size` lets the union fall outside.
    fn netdev_btf(bf: u32, flag: u32, skb_size: u32, dev_is_ptr: bool) -> RawBtfBlob {
        let mut b = BtfBuilder::new();
        let (dev, pf, x) = (b.s("dev"), b.s("priv_flags"), b.s("x"));
        let (ix, il3) = (b.s("IFF_X"), b.s("IFF_L3MDEV_MASTER"));
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(4, "net_device", false, 64, &[x, 1, 0, 0, 4, 64], 2); // 3
        b.ty(4, "", true, 8, &[pf, 2, bf << 24], 1); // 4 anon, bitfield
        b.ty(2, "", false, 3, &[], 0); // 5 *net_device
        let dev_t = if dev_is_ptr { 5 } else { 1 };
        b.ty(5, "", false, 16, &[dev, dev_t, 0], 1); // 6 anon union
        b.ty(4, "sk_buff", false, skb_size, &[0, 6, 128], 1); // 7
        b.ty(6, "netdev_priv_flags", false, 4, &[ix, 1, il3, flag], 2); // 8
        RawBtfBlob(b.build(1), b)
    }

    struct RawBtfBlob(Vec<u8>, BtfBuilder);

    #[test]
    fn btf_offsets_through_anonymous_members_and_a_bitfield() {
        // priv_flags at bit 64; bit 18 -> byte (64 + 18) / 8 = 10, mask 1 << 2.
        let good = netdev_btf(32, 1 << 18, 32, true).0;
        assert_eq!(netdev_offsets(&good).unwrap(), [16, 10, 4]);
    }

    #[test]
    fn btf_reader_refuses_what_it_cannot_prove() {
        let off = |blob: RawBtfBlob| netdev_offsets(&blob.0);
        assert!(
            off(netdev_btf(32, 1 << 18, 24, true)).is_err(),
            "union outside sk_buff"
        );
        assert!(
            off(netdev_btf(32, 3 << 18, 32, true)).is_err(),
            "not a single bit"
        );
        assert!(
            off(netdev_btf(8, 1 << 18, 32, true)).is_err(),
            "bit beyond the bitfield"
        );
        assert!(
            off(netdev_btf(32, 1 << 18, 32, false)).is_err(),
            "dev not a pointer"
        );
        let blob = netdev_btf(32, 1 << 18, 32, true);
        assert!(netdev_offsets(&blob.1.build(2)).is_err(), "version 2");
        assert!(
            netdev_offsets(&blob.0[..blob.0.len() - 30]).is_err(),
            "truncated"
        );
        let mut unknown = blob.0.clone();
        unknown[24 + 7] = 25; // the first record's kind byte
        assert!(netdev_offsets(&unknown).is_err(), "unknown kind");
    }

    /// sk_buff { *net_device dev @16 }, with `nd` the net_device types
    /// built by the caller after the common ones (int = 1, u64 = 2).
    fn skb_btf(b: &mut BtfBuilder, dev_target: u32, flag: u32) -> Vec<u8> {
        let (dev, ix, il3) = (b.s("dev"), b.s("IFF_X"), b.s("IFF_L3MDEV_MASTER"));
        b.ty(2, "", false, dev_target, &[], 0);
        let ptr_id = b.count();
        b.ty(4, "sk_buff", false, 32, &[dev, ptr_id, 128], 1);
        b.ty(6, "netdev_priv_flags", false, 4, &[ix, 1, il3, flag], 2);
        b.build(1)
    }

    #[test]
    fn btf_int_encoding_offset_is_refused() {
        // priv_flags: a 4-byte INT whose encoding has offset 8, 24 bits.
        let mut b = BtfBuilder::new();
        let pf = b.s("priv_flags");
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(1, "odd", false, 4, &[(8 << 16) | 24], 0); // 3
        b.ty(4, "net_device", false, 16, &[pf, 3, 64], 1); // 4
        let blob = skb_btf(&mut b, 4, 1 << 18);
        assert!(netdev_offsets(&blob).is_err());
    }

    #[test]
    fn btf_bitfield_anonymous_aggregate_is_not_searched() {
        // net_device (9 bytes) { int x @0; anon:1 @64 { u64 priv_flags:32 } }
        let mut b = BtfBuilder::new();
        let (pf, x) = (b.s("priv_flags"), b.s("x"));
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(4, "", true, 8, &[pf, 2, 32 << 24], 1); // 3
        b.ty(
            4,
            "net_device",
            true,
            9,
            &[x, 1, 0, 0, 3, 64 | (1 << 24)],
            2,
        ); // 4
        let blob = skb_btf(&mut b, 4, 1 << 18);
        assert!(netdev_offsets(&blob).is_err());
    }

    #[test]
    fn btf_net_device_is_the_dev_pointee() {
        // Two complete net_device types; sk_buff.dev points to the second,
        // whose priv_flags is at byte 24: bit 18 -> byte 26, mask 4.
        let mut b = BtfBuilder::new();
        let (pf, x) = (b.s("priv_flags"), b.s("x"));
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(4, "net_device", false, 16, &[x, 1, 0, pf, 1, 64], 2); // 3
        b.ty(4, "net_device", false, 32, &[x, 1, 0, pf, 1, 192], 2); // 4
        let blob = skb_btf(&mut b, 4, 1 << 18);
        assert_eq!(netdev_offsets(&blob).unwrap(), [16, 26, 4]);
        // and a flag byte outside the pointee is refused
        let mut b = BtfBuilder::new();
        let pf = b.s("priv_flags");
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(4, "net_device", false, 10, &[pf, 1, 64], 1); // 3: 4-byte int at 8 overflows
        let blob = skb_btf(&mut b, 3, 1 << 18);
        assert!(netdev_offsets(&blob).is_err());
    }

    #[test]
    fn btf_union_member_offset_is_refused() {
        // Codex VRF R4: net_device { anon union @8 { u32 priv_flags @bit 64 } }.
        let mut b = BtfBuilder::new();
        let pf = b.s("priv_flags");
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(5, "", false, 16, &[pf, 1, 64], 1); // 3: union, member at bit 64
        b.ty(4, "net_device", false, 64, &[0, 3, 64], 1); // 4
        let blob = skb_btf(&mut b, 4, 1 << 18);
        assert!(netdev_offsets(&blob).is_err());
        // the same union with the member at 0 is accepted: byte 8 + 2
        let mut b = BtfBuilder::new();
        let pf = b.s("priv_flags");
        b.ty(1, "int", false, 4, &[32], 0);
        b.ty(1, "u64", false, 8, &[64], 0);
        b.ty(5, "", false, 16, &[pf, 1, 0], 1);
        b.ty(4, "net_device", false, 64, &[0, 3, 64], 1);
        let blob = skb_btf(&mut b, 4, 1 << 18);
        assert_eq!(netdev_offsets(&blob).unwrap(), [16, 10, 4]);
    }

    #[test]
    fn btf_duplicate_sk_buff_is_refused() {
        let mut b = BtfBuilder::new();
        let pf = b.s("priv_flags");
        b.ty(1, "int", false, 4, &[32], 0); // 1
        b.ty(1, "u64", false, 8, &[64], 0); // 2
        b.ty(4, "net_device", false, 16, &[pf, 1, 64], 1); // 3
        let x = b.s("x");
        b.ty(4, "sk_buff", false, 8, &[x, 2, 0], 1); // 4: a second sk_buff
        let blob = skb_btf(&mut b, 3, 1 << 18);
        assert!(netdev_offsets(&blob).is_err());
    }

    #[test]
    fn btf_anonymous_search_is_bounded() {
        // sk_buff's only member is an anonymous sk_buff: without a depth
        // bound the search would never end.
        let mut b = BtfBuilder::new();
        b.ty(4, "sk_buff", false, 8, &[0, 1, 0], 1); // 1: anon member of type 1
        b.ty(4, "net_device", false, 8, &[0, 1, 0], 1);
        let blob = b.build(1);
        let btf = RawBtf::parse(&blob).unwrap();
        assert!(btf.member(1, "dev", 0).is_none());
        assert!(netdev_offsets(&blob).is_err());
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
