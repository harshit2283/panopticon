#![allow(dead_code)]

//! TLS library discovery via /proc scanning and ELF symbol resolution.
//!
//! **Cross-platform**: `resolve_elf_symbols`, `go_build_admitted`,
//! `go_read_probes` work on any OS (testable on macOS with ELF fixtures).
//!
//! **Linux-only**: `scan_all_processes`, `scan_pid`, `parse_proc_maps`
//! read `/proc/*/maps` to find loaded TLS libraries.

use std::cell::Cell;
use std::collections::HashMap;
use std::ops::Range;

use anyhow::{Context, Result};
use object::read::elf::{ElfFile, FileHeader};
use object::{Object, ObjectSection, ObjectSymbol, ReadCache, ReadRef};

pub use super::go_read::GoReadProbes;
use super::go_read::{go_read_probes_from, symbol_file_offset};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

// ── Types ────────────────────────────────────────────────────────────────

/// A discovered TLS library target ready for uprobe attachment.
#[derive(Debug, Clone)]
pub struct TlsTarget {
    pub pid: u32,
    pub library_path: String,
    pub tls_type: TlsType,
    /// Identity of the file the probe offsets were read from: the attach
    /// must hit that same file (see [`open_examined`]).
    pub file_key: Option<FileKey>,
}

/// Identity of a file's contents: device, inode, mtime (ns) and size, so a
/// file replaced or rewritten in place no longer matches.
pub type FileKey = (u64, u64, i64, u64);

/// The [`FileKey`] of an open file (fstat: the file itself, not a path).
#[cfg(unix)]
pub fn file_key(file: &std::fs::File) -> std::io::Result<FileKey> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    let mtime_ns = m.mtime().saturating_mul(1_000_000_000) + m.mtime_nsec();
    Ok((m.dev(), m.ino(), mtime_ns, m.size()))
}

/// Open the file a target's offsets were read from, for the uprobe attach
/// (F14). `library_path` lies under `/proc/<pid>/root`, which the workload
/// controls: between the scan and the attach it can swap the file, and the
/// agent would place probes at offsets examined in one file into another
/// (possibly one shared with other workloads). The file opened now must be
/// the one examined, or the attach is refused; the caller attaches through
/// `/proc/self/fd/<n>` of the returned file, so the kernel resolves exactly
/// this inode and not the path again.
#[cfg(unix)]
pub fn open_examined(target: &TlsTarget) -> std::io::Result<std::fs::File> {
    let file = open_workload_file(&target.library_path)?;
    if target.file_key.is_none() || target.file_key != Some(file_key(&file)?) {
        return Err(std::io::Error::other(
            "the file changed since it was examined",
        ));
    }
    Ok(file)
}

/// Open a file a workload controls (a mapped path under `/proc/<pid>/root`)
/// without letting it block or reach anything but a regular file. The
/// workload can replace the path at any moment: a FIFO with no writer would
/// block open(2) forever (hanging the startup scan, or the attach while it
/// holds the eBPF lock), a device open can have side effects. So: refused
/// unless the path is a regular file, opened non-blocking, and refused again
/// unless the opened descriptor is a regular file (a swap between the two
/// checks gets a non-blocking open of whatever was swapped in, then the
/// refusal).
#[cfg(unix)]
pub fn open_workload_file(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let regular = |m: std::fs::Metadata| {
        m.is_file()
            .then_some(())
            .ok_or_else(|| std::io::Error::other("not a regular file"))
    };
    regular(std::fs::metadata(path)?)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)?;
    regular(file.metadata()?)?;
    Ok(file)
}

/// The kind of TLS library discovered, with symbol offsets for uprobe attachment.
#[derive(Debug, Clone)]
pub enum TlsType {
    OpenSsl {
        ssl_write_offset: u64,
        ssl_read_offset: u64,
        /// `SSL_write_ex` / `SSL_read_ex` (OpenSSL 1.1.1+). Applications that
        /// use them never call `SSL_write` / `SSL_read`.
        ssl_write_ex_offset: Option<u64>,
        ssl_read_ex_offset: Option<u64>,
    },
    /// Only for a build [`go_build_admitted`] accepts.
    GoTls {
        write_offset: u64,
        /// Go TLS read probe offsets (go_read.rs), if found.
        read: Option<GoReadProbes>,
    },
}

// ── ELF Symbol Resolution (cross-platform) ──────────────────────────────

/// Resolve symbol offsets from an ELF binary's `.dynsym` or `.symtab`.
///
/// Returns a map of `symbol_name → file_offset` for each requested symbol
/// that was found. Missing symbols are silently omitted from the result.
///
/// Reads only the ELF ranges that are needed (headers, symbol and string
/// tables) instead of loading the whole file: every executable on the node is
/// probed as a potential Go binary, and reading each one fully made the
/// agent's peak RSS track the size of the largest binary on the host.
pub fn resolve_elf_symbols(path: &str, symbols: &[&str]) -> Result<HashMap<String, u64>> {
    with_untrusted_elf(path, |data| resolve_elf_symbols_from_bytes(data, symbols))
        .with_context(|| format!("failed to open ELF: {path}"))?
}

/// Largest file examined as a TLS target. Real libssl and Go binaries are far
/// smaller; anything bigger is skipped rather than parsed.
const MAX_ELF_FILE_BYTES: u64 = 1 << 30;

/// Byte budget for all reads from one workload-controlled ELF. `ReadCache`
/// allocates and zero-fills whatever size a section header declares (symtab,
/// dynsym, symtab_shndx, `.go.buildinfo`, ...), so without a cap a sparse
/// file with a huge `sh_size` OOM-kills the agent. Every read is charged
/// before it is allocated; once the budget is spent the parse fails.
const MAX_ELF_READ_BYTES: u64 = 128 << 20;

/// Charged per string lookup on top of the string itself: about what one
/// `ReadCache` string entry costs (hash slot, key, boxed bytes), so the
/// budget bounds the entries too, empty strings included. 128 MiB of budget
/// then bounds a parse to 1M lookups; a large Go binary has a few hundred
/// thousand symbols.
const MIN_STRING_CHARGE: u64 = 128;

/// Longest string `ReadCache` scans for (and keeps) in one lookup.
const MAX_STRING_SCAN: u64 = 4096;

/// `ReadRef` over a file cache that refuses reads past a cumulative budget.
#[derive(Clone, Copy)]
struct BudgetedRead<'a> {
    cache: &'a ReadCache<std::fs::File>,
    left: &'a Cell<u64>,
}

impl BudgetedRead<'_> {
    /// Spend `n` bytes of the budget. A refusal spends all of it, so every
    /// later read is refused too and a parse stops instead of carrying on
    /// with smaller reads.
    fn charge(self, n: u64) -> std::result::Result<(), ()> {
        match self.left.get().checked_sub(n) {
            Some(left) if self.left.get() > 0 => {
                self.left.set(left);
                Ok(())
            }
            _ => {
                self.left.set(0);
                Err(())
            }
        }
    }
}

impl<'a> ReadRef<'a> for BudgetedRead<'a> {
    fn len(self) -> std::result::Result<u64, ()> {
        self.cache.len()
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> std::result::Result<&'a [u8], ()> {
        self.charge(size)?; // before ReadCache allocates `size` bytes
        self.cache.read_bytes_at(offset, size)
    }

    fn read_bytes_at_until(
        self,
        range: Range<u64>,
        delimiter: u8,
    ) -> std::result::Result<&'a [u8], ()> {
        // ReadCache scans up to MAX_STRING_SCAN bytes and keeps one entry
        // per lookup, even of an empty string. Reserve the most it can keep
        // before it allocates; keep charged the string plus the entry
        // (security scan F8).
        self.charge(MAX_STRING_SCAN + MIN_STRING_CHARGE)?;
        let bytes = self.cache.read_bytes_at_until(range, delimiter)?;
        let unused = MAX_STRING_SCAN.saturating_sub(bytes.len() as u64);
        self.left.set(self.left.get() + unused);
        Ok(bytes)
    }
}

/// Open a workload-controlled ELF and run `f` over a budgeted reader. Every
/// parse of a file under `/proc/<pid>/root` must go through here.
fn with_untrusted_elf<T>(path: &str, f: impl FnOnce(BudgetedRead<'_>) -> T) -> Result<T> {
    let file = open_workload_file(path)?;
    let size = file.metadata()?.len();
    anyhow::ensure!(size <= MAX_ELF_FILE_BYTES, "ELF too large: {size} bytes");
    let cache = ReadCache::new(file);
    let left = Cell::new(MAX_ELF_READ_BYTES);
    Ok(f(BudgetedRead {
        cache: &cache,
        left: &left,
    }))
}

/// Inner implementation over any `ReadRef` (a byte slice in tests, a
/// range-reading file cache in production).
pub fn resolve_elf_symbols_from_bytes<'data, R: ReadRef<'data>>(
    data: R,
    symbols: &[&str],
) -> Result<HashMap<String, u64>> {
    let mut result = HashMap::new();

    // Try 64-bit ELF first, then 32-bit
    if let Ok(elf) = ElfFile::<object::elf::FileHeader64<object::Endianness>, R>::parse(data) {
        collect_symbols(&elf, symbols, &mut result);
    } else if let Ok(elf) = ElfFile::<object::elf::FileHeader32<object::Endianness>, R>::parse(data)
    {
        collect_symbols(&elf, symbols, &mut result);
    } else {
        anyhow::bail!("not a valid ELF file");
    }

    Ok(result)
}

/// Stops at the first name that cannot be read: a spent read budget fails
/// every later lookup, and scanning on would only repeat the failure.
fn collect_symbols<'data, Elf: FileHeader, R: ReadRef<'data>>(
    elf: &ElfFile<'data, Elf, R>,
    wanted: &[&str],
    result: &mut HashMap<String, u64>,
) {
    for sym in elf.symbols() {
        let Ok(name) = sym.name() else { return };
        if wanted.contains(&name) {
            // Use the symbol's address (virtual address / file offset).
            // For uprobes, aya expects the offset within the ELF file,
            // which for non-PIE executables equals the symbol address.
            // For shared libraries (PIE), we need address - base_vaddr.
            let offset = symbol_file_offset(elf, sym.address());
            result.insert(name.to_string(), offset);
        }
    }
    // Also check dynamic symbols
    for sym in elf.dynamic_symbols() {
        let Ok(name) = sym.name() else { return };
        if wanted.contains(&name) && !result.contains_key(name) {
            let offset = symbol_file_offset(elf, sym.address());
            result.insert(name.to_string(), offset);
        }
    }
}

/// The Go TLS read probe offsets in an ELF (go_read.rs).
pub fn go_read_probes(path: &str) -> Option<GoReadProbes> {
    with_untrusted_elf(path, |data| go_read_probes_from(data)).ok()?
}

/// Whether the Go probes can read a Go binary's functions: Ok(toolchain
/// version) only when its build is positively one whose internal calling
/// convention (ABIInternal, the register ABI) they decode, for this
/// agent's architecture; otherwise why not. Read from the build
/// information the Go toolchain records (`.go.buildinfo`), never guessed
/// from a version alone: a missing or unreadable field rejects the binary,
/// and with it every Go probe, writes included.
pub fn go_build_admitted(path: &str) -> std::result::Result<String, &'static str> {
    with_untrusted_elf(path, |data| {
        let elf = ElfFile::<object::elf::FileHeader64<object::Endianness>, _>::parse(data)
            .map_err(|_| "not a 64-bit ELF")?;
        let info = elf
            .section_by_name(".go.buildinfo")
            .ok_or("no Go build information")?
            .data()
            .map_err(|_| "unreadable Go build information")?;
        admit_go_build(info, elf.architecture(), HOST_ARCH)
    })
    .map_err(|_| "cannot open")?
}

#[cfg(target_arch = "x86_64")]
const HOST_ARCH: object::Architecture = object::Architecture::X86_64;
#[cfg(target_arch = "aarch64")]
const HOST_ARCH: object::Architecture = object::Architecture::Aarch64;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const HOST_ARCH: object::Architecture = object::Architecture::Unknown;

/// [`go_build_admitted`] over the contents of `.go.buildinfo`. Admitted:
/// the format Go 1.18+ writes (64-bit little-endian, strings inline), a
/// `go1.N` version with N >= 18, `-compiler=gc`, `GOARCH` amd64 or arm64
/// matching the ELF and the agent, and no `noregabi*` experiment, either in
/// the `GOEXPERIMENT` setting or baked into the toolchain (the version's
/// ` X:` suffix). Register ABI is the default on amd64 from Go 1.17 and on
/// arm64 from 1.18; an experiment is the only way to turn it off.
fn admit_go_build(
    info: &[u8],
    elf_arch: object::Architecture,
    host_arch: object::Architecture,
) -> std::result::Result<String, &'static str> {
    const MAGIC: &[u8] = b"\xff Go buildinf:";
    if info.len() < 32 || &info[..MAGIC.len()] != MAGIC {
        return Err("no Go build information header");
    }
    // Pointer size 8; flags: inline strings (Go 1.18+), little-endian.
    if info[14] != 8 || info[15] & 3 != 2 {
        return Err("Go build information not in the Go 1.18+ 64-bit format");
    }
    let mut rest = &info[32..];
    let version = take_go_string(&mut rest).ok_or("unreadable Go version")?;
    let mut modinfo = take_go_string(&mut rest).ok_or("unreadable Go build settings")?;
    // Framed by 16-byte sentinels, as runtime/debug strips them.
    if modinfo.len() >= 33 && modinfo[modinfo.len() - 17] == b'\n' {
        modinfo = &modinfo[16..modinfo.len() - 16];
    } else {
        return Err("no Go build settings");
    }
    let version = std::str::from_utf8(version).map_err(|_| "unreadable Go version")?;
    let modinfo = std::str::from_utf8(modinfo).map_err(|_| "unreadable Go build settings")?;
    let minor = version
        .strip_prefix("go1.")
        .and_then(|v| v.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|m| m.parse::<u32>().ok())
        .ok_or("unrecognised Go version")?;
    if minor < 18 {
        return Err("Go older than 1.18");
    }
    let setting = |key: &str| {
        modinfo.lines().find_map(|l| {
            l.strip_prefix("build\t")?
                .strip_prefix(key)?
                .strip_prefix('=')
        })
    };
    if setting("-compiler") != Some("gc") {
        return Err("not built by the gc compiler");
    }
    let arch = match setting("GOARCH") {
        Some("amd64") => object::Architecture::X86_64,
        Some("arm64") => object::Architecture::Aarch64,
        _ => return Err("GOARCH not amd64 or arm64"),
    };
    if arch != elf_arch || arch != host_arch {
        return Err("built for another architecture");
    }
    if version.contains("noregabi")
        || setting("GOEXPERIMENT").is_some_and(|e| e.contains("noregabi"))
    {
        return Err("register ABI turned off by a GOEXPERIMENT");
    }
    Ok(version.to_string())
}

/// A uvarint-length-prefixed string at the start of `data`, advancing it.
fn take_go_string<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (mut len, mut shift) = (0u64, 0);
    loop {
        let (&b, rest) = data.split_first()?;
        *data = rest;
        len |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 56 {
            return None;
        }
    }
    let len = usize::try_from(len).ok().filter(|&l| l <= data.len())?;
    let (s, rest) = data.split_at(len);
    *data = rest;
    Some(s)
}

// ── /proc Scanning (Linux-only) ─────────────────────────────────────────

/// Scan all processes for loaded TLS libraries.
///
/// Reads `/proc/*/maps`, identifies `libssl.so` and Go binaries.
#[cfg(target_os = "linux")]
pub fn scan_all_processes() -> Vec<TlsTarget> {
    let mut targets = Vec::new();

    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(e) => {
            warn!(error = %e, "Failed to read /proc");
            return targets;
        }
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            targets.extend(scan_pid(pid));
        }
    }

    dedup_targets(&mut targets, get_file_id);

    debug!(count = targets.len(), "TLS library scan complete");
    targets
}

/// Keep one target per library file. TLS uprobes are attached without a
/// PID filter, so they already cover every process mapping that file; each
/// PID reaches it through a different `/proc/<pid>/root/...` path, and
/// attaching once per path made every SSL call emit duplicate events.
fn dedup_targets(targets: &mut Vec<TlsTarget>, file_id: impl Fn(&str) -> Option<(u64, u64)>) {
    let mut seen = std::collections::HashSet::new();
    targets.retain(|t| {
        let file = file_id(&t.library_path).ok_or_else(|| t.library_path.clone());
        seen.insert(file)
    });
}

/// Scan a single PID's `/proc/<pid>/maps` for TLS libraries.
#[cfg(target_os = "linux")]
pub fn scan_pid(pid: u32) -> Vec<TlsTarget> {
    let mut targets = Vec::new();

    let libs = match parse_proc_maps(pid) {
        Ok(libs) => libs,
        Err(_) => return targets, // Process may have exited
    };

    for (path, _base_addr) in &libs {
        if !is_openssl_library(path) && !is_go_binary(path) {
            continue;
        }
        let namespace_path = namespace_resolved_path(pid, path);
        if let Some((tls_type, file_key)) = examine_cached(path, &namespace_path) {
            targets.push(TlsTarget {
                pid,
                library_path: namespace_path,
                tls_type,
                file_key: Some(file_key),
            });
        }
    }

    targets
}

/// Bound on cached verdicts; the cache is cleared when it is reached.
#[cfg(target_os = "linux")]
const MAX_CACHED_VERDICTS: usize = 8192;

/// TLS verdict for a mapped file, cached per file (its [`FileKey`]) so each
/// binary's ELF symbol tables are parsed once, not on every periodic rescan
/// of every process that maps it. Negative verdicts (not TLS) are cached
/// too: most files examined are executables without crypto/tls.
///
/// The file is opened once and parsed through `/proc/self/fd/<n>`, so every
/// read of the examination sees the same inode as the key it is cached and
/// attached under (F14), however the workload changes the path meanwhile.
#[cfg(target_os = "linux")]
fn examine_cached(path: &str, namespace_path: &str) -> Option<(TlsType, FileKey)> {
    use std::collections::HashMap;
    use std::os::fd::AsRawFd;
    use std::sync::{Mutex, OnceLock};

    static VERDICTS: OnceLock<Mutex<HashMap<FileKey, Option<TlsType>>>> = OnceLock::new();
    let file = open_workload_file(namespace_path).ok()?;
    let key = file_key(&file).ok()?;
    let cache = VERDICTS.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(verdict) = cache.lock().ok()?.get(&key) {
        return verdict.clone().map(|t| (t, key));
    }
    let verdict = examine_binary(path, &format!("/proc/self/fd/{}", file.as_raw_fd()));
    if let Ok(mut cache) = cache.lock() {
        if cache.len() >= MAX_CACHED_VERDICTS {
            cache.clear();
        }
        cache.insert(key, verdict.clone());
    }
    verdict.map(|t| (t, key))
}

/// Parse a mapped file's ELF to see whether it is a TLS library we hook.
#[cfg(target_os = "linux")]
fn examine_binary(path: &str, namespace_path: &str) -> Option<TlsType> {
    // Check for OpenSSL
    if is_openssl_library(path)
        && let Ok(syms) = resolve_elf_symbols(
            namespace_path,
            &["SSL_write", "SSL_read", "SSL_write_ex", "SSL_read_ex"],
        )
        && let (Some(&write_off), Some(&read_off)) = (syms.get("SSL_write"), syms.get("SSL_read"))
    {
        debug!(path, target = %namespace_path, "Found OpenSSL library");
        return Some(TlsType::OpenSsl {
            ssl_write_offset: write_off,
            ssl_read_offset: read_off,
            ssl_write_ex_offset: syms.get("SSL_write_ex").copied(),
            ssl_read_ex_offset: syms.get("SSL_read_ex").copied(),
        });
    }

    // Check for Go binaries
    if !is_go_binary(path) {
        return None;
    }
    let version = match go_build_admitted(namespace_path) {
        Ok(version) => version,
        Err(reason) => {
            if reason != "no Go build information" {
                debug!(path, target = %namespace_path, reason, "Go binary not probed");
            }
            return None;
        }
    };
    {
        if let Ok(syms) = resolve_elf_symbols(namespace_path, &["crypto/tls.(*Conn).Write"])
            && let Some(&write_off) = syms.get("crypto/tls.(*Conn).Write")
        {
            let read = go_read_probes(namespace_path);
            debug!(path, target = %namespace_path, %version, read = read.is_some(), "Found Go TLS binary");
            return Some(TlsType::GoTls {
                write_offset: write_off,
                read,
            });
        }
        debug!(
            path,
            target = %namespace_path,
            %version,
            "Go binary detected but crypto/tls.(*Conn).Write was not found"
        );
    }
    None
}

/// Parse `/proc/<pid>/maps` output, extract unique library paths.
///
/// Returns `Vec<(library_path, base_address)>` for mapped files with
/// execute permission (only executable mappings can contain TLS symbols).
#[cfg(target_os = "linux")]
fn parse_proc_maps(pid: u32) -> Result<Vec<(String, u64)>> {
    let maps_path = format!("/proc/{pid}/maps");
    let content = std::fs::read_to_string(&maps_path)
        .with_context(|| format!("failed to read {maps_path}"))?;

    let mut libs = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (path, base_addr) in content.lines().filter_map(maps_exec_file) {
        if seen.insert(path.clone()) {
            libs.push((path, base_addr));
        }
    }

    Ok(libs)
}

/// The file and start address of an executable file mapping in one
/// `/proc/<pid>/maps` line (`address perms offset dev inode pathname`), or
/// None. A pathname may contain spaces. A mapping whose file was deleted
/// (` (deleted)`) is skipped: its path now names another file, if any, which
/// the workload chose.
fn maps_exec_file(line: &str) -> Option<(String, u64)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 6 || !parts[1].contains('x') {
        return None;
    }
    let path = parts[5..].join(" ");
    if !path.starts_with('/') || path.ends_with(" (deleted)") {
        return None;
    }
    let base = parts[0].split('-').next()?;
    Some((path, u64::from_str_radix(base, 16).unwrap_or(0)))
}

/// Resolve a process-local mapped path through that process's mount namespace.
///
/// This allows the agent container to attach uprobes to binaries and shared
/// libraries that live in sibling containers with different root filesystems.
#[cfg(target_os = "linux")]
fn namespace_resolved_path(pid: u32, path: &str) -> String {
    let namespaced = format!("/proc/{pid}/root{path}");
    if std::fs::metadata(&namespaced).is_ok() {
        namespaced
    } else {
        path.to_string()
    }
}

/// Check if a path looks like an OpenSSL shared library.
#[cfg(target_os = "linux")]
fn is_openssl_library(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename.starts_with("libssl.so")
}

/// Check if a path might be a Go binary (has execute mapping, no .so extension).
/// We'll verify by looking for the `.go.buildinfo` section.
#[cfg(target_os = "linux")]
fn is_go_binary(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    // Go binaries are typically statically linked, no .so extension
    !filename.contains(".so") && !filename.starts_with("lib")
}

// ── Background TLS Scanner Task ─────────────────────────────────────────

/// Return `(device_id, inode)` for a file path, handling symlinks correctly.
#[cfg(target_os = "linux")]
pub fn get_file_id(path: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

/// Long-lived background task that periodically rescans `/proc` for new TLS
/// libraries and attaches uprobes to them.
///
/// It takes no input from the capture path: a long-lived task outside the
/// disposable pipeline must not hold captured values (DESIGN §3).
///
/// Key design choices following review feedback:
/// - **Inode-based dedup**: `(dev, ino)` instead of paths — handles symlinks/namespaces
/// - **IO outside lock**: scan + ELF parsing before acquiring the mutex
/// - **Batch logging**: one summary log per scan, not per-target
/// - **Jitter**: 0–10% of interval to prevent fleet-wide CPU spikes
#[cfg(target_os = "linux")]
pub async fn tls_scanner_task(
    shared_ebpf: std::sync::Arc<std::sync::Mutex<crate::loader::EbpfState>>,
    scan_interval: std::time::Duration,
) {
    let mut interval = tokio::time::interval(scan_interval);
    interval.tick().await; // skip immediate first tick — initial scan already done

    loop {
        interval.tick().await;
        // Jitter: sleep 0–10% of the interval to avoid thundering herd
        let jitter_max_ms = (scan_interval.as_millis() as u64 / 10).max(1);
        let jitter_ms = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            nanos % jitter_max_ms
        };
        tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;

        // ── IO + ELF parsing OUTSIDE the lock, and off the async
        //    runtime: a full scan blocks for long enough to stall the
        //    packet workers sharing the runtime threads.
        let Ok(targets) = tokio::task::spawn_blocking(scan_all_processes).await else {
            continue;
        };
        prune_attached_libs(&shared_ebpf, &targets);
        let newly_attached = attach_new_targets(&shared_ebpf, targets);
        let shared = shared_ebpf.clone();
        let _ = tokio::task::spawn_blocking(move || sweep_go_reads(&shared)).await;
        if newly_attached > 0 {
            info!(
                new_libraries = newly_attached,
                "Background TLS scan: attached uprobes to new libraries"
            );
        }
    }
}

/// Go TLS read slots of process instances that ended (go_read.rs `Sweep`).
/// The shared state is locked only to open the map handles: the walk runs
/// after the lock is released, so scope publication never waits on it, and
/// on a blocking thread (`tls_scanner_task`), not an async worker.
#[cfg(target_os = "linux")]
fn sweep_go_reads(shared_ebpf: &std::sync::Arc<std::sync::Mutex<crate::loader::EbpfState>>) {
    let opened = {
        let state = shared_ebpf.lock().unwrap_or_else(|e| e.into_inner());
        super::go_read::Sweep::open(&state.ebpf)
    };
    match opened.and_then(|mut sweep| sweep.run()) {
        Ok((0, 0)) => {}
        Ok((slots, epochs)) => debug!(
            slots,
            epochs, "Go TLS read slots of ended processes removed"
        ),
        Err(e) => warn!(error = %format!("{e:#}"), "Go TLS read sweep failed"),
    }
}

/// Prune `attached_libs` to libraries still visible in the latest full scan.
#[cfg(target_os = "linux")]
fn prune_attached_libs(
    shared_ebpf: &std::sync::Arc<std::sync::Mutex<crate::loader::EbpfState>>,
    targets: &[TlsTarget],
) {
    use std::collections::HashSet;

    let current_ids: HashSet<(u64, u64)> = targets
        .iter()
        .filter_map(|t| get_file_id(&t.library_path))
        .collect();

    let mut state = match shared_ebpf.lock() {
        Ok(state) => state,
        Err(e) => {
            warn!(error = %e, "TLS scanner lock poisoned during prune; continuing");
            e.into_inner()
        }
    };
    state.attached_libs.retain(|id| current_ids.contains(id));
}

/// Attach uprobes for any new TLS targets not already tracked.
/// Returns the number of newly attached libraries.
#[cfg(target_os = "linux")]
fn attach_new_targets(
    shared_ebpf: &std::sync::Arc<std::sync::Mutex<crate::loader::EbpfState>>,
    targets: Vec<TlsTarget>,
) -> usize {
    use std::collections::HashSet;

    // Snapshot the current set to filter without holding the lock
    let already_attached: HashSet<(u64, u64)> = match shared_ebpf.lock() {
        Ok(state) => state.attached_libs.clone(),
        Err(e) => {
            warn!(error = %e, "TLS scanner lock poisoned while reading attached set");
            e.into_inner().attached_libs.clone()
        }
    };

    // Pre-filter: resolve inodes and skip already-attached libraries
    let new_targets: Vec<_> = targets
        .into_iter()
        .filter(|t| {
            get_file_id(&t.library_path)
                .map(|id| !already_attached.contains(&id))
                .unwrap_or(false)
        })
        .collect();

    if new_targets.is_empty() {
        return 0;
    }

    // ── Brief lock: only uprobe attachment (~µs per target) ──────
    let mut state = match shared_ebpf.lock() {
        Ok(state) => state,
        Err(e) => {
            warn!(error = %e, "TLS scanner lock poisoned during attach; continuing");
            e.into_inner()
        }
    };
    let mut newly_attached = 0usize;
    for target in &new_targets {
        if let Some(file_id) = get_file_id(&target.library_path) {
            // Double-check under lock (another scan may have raced)
            if !state.attached_libs.contains(&file_id) {
                let count = crate::loader::attach_tls_uprobes_on_state(&mut state, target);
                if count > 0 {
                    state.attached_libs.insert(file_id);
                    newly_attached += 1;
                }
            }
        }
    }
    drop(state);

    newly_attached
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── admit_go_build ───────────────────────────────────────────────

    /// `.go.buildinfo` as the Go 1.18+ toolchain writes it.
    fn buildinfo(version: &str, settings: &[&str]) -> Vec<u8> {
        let mut b = b"\xff Go buildinf:\x08\x02".to_vec();
        b.resize(32, 0);
        let mut modinfo = vec![0xaau8; 16];
        modinfo.extend(b"path\tcommand-line-arguments\n");
        for s in settings {
            modinfo.extend(format!("build\t{s}\n").bytes());
        }
        modinfo.extend([0xbb; 16]);
        for s in [version.as_bytes(), &modinfo] {
            assert!(s.len() < 1 << 14);
            b.extend([(s.len() as u8 & 0x7f) | 0x80, (s.len() >> 7) as u8]); // uvarint
            b.extend(s);
        }
        b
    }

    const X86: object::Architecture = object::Architecture::X86_64;
    const ARM: object::Architecture = object::Architecture::Aarch64;

    #[test]
    fn test_admit_go_build_register_abi_builds() {
        let amd = [
            "-compiler=gc",
            "CGO_ENABLED=0",
            "GOARCH=amd64",
            "GOOS=linux",
            "GOAMD64=v1",
        ];
        let info = buildinfo("go1.21.5", &amd);
        assert_eq!(admit_go_build(&info, X86, X86), Ok("go1.21.5".into()));
        let arm = ["-compiler=gc", "GOARCH=arm64", "GOOS=linux"];
        assert!(admit_go_build(&buildinfo("go1.18", &arm), ARM, ARM).is_ok());
        let other_exp = ["-compiler=gc", "GOARCH=arm64", "GOEXPERIMENT=loopvar"];
        assert!(admit_go_build(&buildinfo("go1.22.0", &other_exp), ARM, ARM).is_ok());
    }

    /// Codex HIGH 2: a version alone does not establish the ABI.
    #[test]
    fn test_admit_go_build_rejects_unestablished_abi() {
        let arm = |exp: &str| buildinfo("go1.18", &["-compiler=gc", "GOARCH=arm64", exp]);
        // Go 1.18 arm64 built with the register ABI turned off.
        assert!(admit_go_build(&arm("GOEXPERIMENT=noregabiargs"), ARM, ARM).is_err());
        assert!(admit_go_build(&arm("GOEXPERIMENT=fieldtrack,noregabi"), ARM, ARM).is_err());
        // ... or a toolchain built with it off.
        let baked = buildinfo("go1.19 X:noregabiargs", &["-compiler=gc", "GOARCH=arm64"]);
        assert!(admit_go_build(&baked, ARM, ARM).is_err());
        // Settings missing: nothing is established.
        assert!(admit_go_build(&buildinfo("go1.21.5", &["GOARCH=amd64"]), X86, X86).is_err());
        assert!(admit_go_build(&buildinfo("go1.21.5", &["-compiler=gc"]), X86, X86).is_err());
        assert!(admit_go_build(&buildinfo("go1.21.5", &[]), X86, X86).is_err());
        let gccgo = buildinfo("go1.21.5", &["-compiler=gccgo", "GOARCH=amd64"]);
        assert!(admit_go_build(&gccgo, X86, X86).is_err());
        // Architecture: the build's, the ELF's and the agent's must agree.
        let amd = buildinfo("go1.21.5", &["-compiler=gc", "GOARCH=amd64"]);
        assert!(admit_go_build(&amd, ARM, ARM).is_err());
        assert!(admit_go_build(&amd, X86, ARM).is_err());
        let i386 = buildinfo("go1.21.5", &["-compiler=gc", "GOARCH=386"]);
        assert!(admit_go_build(&i386, X86, X86).is_err());
        // Versions: before 1.18, or not a release.
        let gc = ["-compiler=gc", "GOARCH=amd64"];
        assert!(admit_go_build(&buildinfo("go1.17.13", &gc), X86, X86).is_err());
        assert!(admit_go_build(&buildinfo("devel go1.23-abc", &gc), X86, X86).is_err());
        // Pre-1.18 format (pointer-referenced strings), 32-bit, truncated.
        let mut old = amd.clone();
        old[15] = 0;
        assert!(admit_go_build(&old, X86, X86).is_err());
        let mut p32 = amd.clone();
        p32[14] = 4;
        assert!(admit_go_build(&p32, X86, X86).is_err());
        for n in [0, 16, 31, 33, amd.len() - 1] {
            assert!(
                admit_go_build(&amd[..n], X86, X86).is_err(),
                "truncated at {n}"
            );
        }
    }

    /// F14: the attach opens the file the offsets were read from, or
    /// nothing: not a file swapped in at the same path, nor the same file
    /// rewritten in place.
    #[cfg(unix)]
    #[test]
    fn test_attach_refuses_a_file_swapped_after_examination() {
        let dir = std::env::temp_dir().join(format!("panopticon-f14-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = dir.join("libssl.so.3");
        std::fs::write(&lib, b"examined").unwrap();
        let examined = file_key(&std::fs::File::open(&lib).unwrap()).unwrap();
        let target = |key| TlsTarget {
            pid: 1,
            library_path: lib.to_string_lossy().into_owned(),
            tls_type: TlsType::GoTls {
                write_offset: 0x1000,
                read: None,
            },
            file_key: key,
        };
        assert!(open_examined(&target(Some(examined))).is_ok());
        assert!(open_examined(&target(None)).is_err(), "never examined");

        // Swapped: another file renamed over the path.
        let other = dir.join("other");
        std::fs::write(&other, b"examined").unwrap();
        std::fs::rename(&other, &lib).unwrap();
        assert!(open_examined(&target(Some(examined))).is_err());

        // Rewritten in place: same inode, other contents.
        let swapped = file_key(&std::fs::File::open(&lib).unwrap()).unwrap();
        std::fs::write(&lib, b"rewritten, longer").unwrap();
        assert!(open_examined(&target(Some(swapped))).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_dedup_targets_by_file_not_path() {
        let ssl = |pid: u32, path: &str| TlsTarget {
            pid,
            library_path: path.to_string(),
            tls_type: TlsType::OpenSsl {
                ssl_write_offset: 1,
                ssl_read_offset: 2,
                ssl_write_ex_offset: None,
                ssl_read_ex_offset: None,
            },
            file_key: None,
        };
        let go = |pid: u32, path: &str| TlsTarget {
            pid,
            library_path: path.to_string(),
            tls_type: TlsType::GoTls {
                write_offset: 3,
                read: None,
            },
            file_key: None,
        };
        let mut targets = vec![
            ssl(10, "/proc/10/root/usr/lib/libssl.so.3"),
            ssl(11, "/proc/11/root/usr/lib/libssl.so.3"), // same file
            ssl(12, "/proc/12/root/usr/lib/libssl.so.3"), // container's own copy
            go(20, "/proc/20/root/app"),
            go(21, "/proc/21/root/app"), // same binary, other process: covered
            go(21, "/proc/21/root/app"),
        ];
        let id = |path: &str| {
            Some(match path {
                p if p.starts_with("/proc/12/") => (1, 99),
                p if p.ends_with("libssl.so.3") => (1, 42),
                _ => (1, 7),
            })
        };
        dedup_targets(&mut targets, id);
        let kept: Vec<u32> = targets.iter().map(|t| t.pid).collect();
        assert_eq!(kept, vec![10, 12, 20]);
    }

    // ── resolve_elf_symbols_from_bytes ───────────────────────────────

    #[test]
    fn test_resolve_elf_symbols_invalid_data() {
        let data = b"not an elf file";
        let result = resolve_elf_symbols_from_bytes(&data[..], &["SSL_write"]);
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_resolve_elf_symbols_from_file_matches_in_memory_parse() {
        // The test binary itself is an ELF with a symbol table; the
        // range-reading file path must agree with parsing the whole file.
        let exe = std::env::current_exe().unwrap();
        let path = exe.to_str().unwrap();
        let wanted = ["main", "malloc", "rust_begin_unwind"];
        let from_file = resolve_elf_symbols(path, &wanted).unwrap();
        let bytes = std::fs::read(path).unwrap();
        let from_bytes = resolve_elf_symbols_from_bytes(&bytes[..], &wanted).unwrap();
        assert!(!from_file.is_empty());
        assert_eq!(from_file, from_bytes);
        assert!(go_build_admitted(path).is_err());
    }

    /// Write a sparse ELF64 whose SHT_SYMTAB declares `symtab_size` bytes at
    /// offset 4096. Only the headers occupy disk.
    fn write_sparse_elf(name: &str, symtab_size: u64) -> std::path::PathBuf {
        let mut elf = vec![0u8; 64 + 3 * 64 + 1]; // headers, then one NUL as strtab
        elf[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        elf[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        elf[60..62].copy_from_slice(&3u16.to_le_bytes()); // e_shnum
        elf[62..64].copy_from_slice(&2u16.to_le_bytes()); // e_shstrndx
        let mut sh = |i: usize, ty: u32, off: u64, size: u64, link: u32, ent: u64| {
            let b = 64 + i * 64;
            elf[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
            elf[b + 24..b + 32].copy_from_slice(&off.to_le_bytes());
            elf[b + 32..b + 40].copy_from_slice(&size.to_le_bytes());
            elf[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            elf[b + 56..b + 64].copy_from_slice(&ent.to_le_bytes());
        };
        sh(1, object::elf::SHT_SYMTAB, 4096, symtab_size, 2, 24);
        sh(2, object::elf::SHT_STRTAB, 256, 1, 0, 0);
        let path =
            std::env::temp_dir().join(format!("panopticon-f4-{name}-{}.elf", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        std::io::Write::write_all(&mut &file, &elf).unwrap();
        file.set_len(4096 + symtab_size).unwrap(); // sparse: no disk used
        path
    }

    /// F4: a symtab whose declared size is over the read budget must fail
    /// the parse before `ReadCache` allocates and zero-fills that size.
    #[test]
    fn test_huge_declared_symtab_rejected_without_allocating() {
        // Control: the same ELF with a small symtab parses.
        let small = write_sparse_elf("small", 24 * 4);
        let ok = resolve_elf_symbols(small.to_str().unwrap(), &["SSL_write"]);
        std::fs::remove_file(&small).unwrap();
        assert!(ok.is_ok(), "control ELF must parse: {ok:?}");

        let huge = write_sparse_elf("huge", 24 << 24); // 384 MiB of symbols
        let p = huge.to_str().unwrap();
        let symbols = resolve_elf_symbols(p, &["SSL_write"]);
        let go = go_build_admitted(p).ok();
        let probes = go_read_probes(p);
        std::fs::remove_file(&huge).unwrap();
        assert!(symbols.is_err(), "over-budget symtab must fail the parse");
        assert_eq!(go, None);
        assert_eq!(probes, None);
    }

    /// F8: every string lookup is charged at least MIN_STRING_CHARGE, also
    /// an empty one, so lookups (and ReadCache's entry per lookup) stop
    /// once the budget is spent.
    #[test]
    fn test_empty_string_lookups_charged() {
        let path = std::env::temp_dir().join(format!("panopticon-f8-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let (left, refused) = with_untrusted_elf(path.to_str().unwrap(), |r| {
            for off in 0..1000 {
                r.read_bytes_at_until(off..4096, 0).unwrap();
            }
            let left = r.left.get();
            r.left.set(MIN_STRING_CHARGE - 1);
            (left, r.read_bytes_at_until(2000..4096, 0).is_err())
        })
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(left, MAX_ELF_READ_BYTES - 1000 * MIN_STRING_CHARGE);
        assert!(refused, "an empty lookup past the budget is refused");
    }

    /// F8: a string lookup reserves the most ReadCache can keep for it
    /// before the cache is touched, and a refused read spends the budget:
    /// every later read is refused too.
    #[test]
    fn test_string_lookup_reserved_before_the_cache_and_latched() {
        let path = std::env::temp_dir().join(format!("panopticon-f8r-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let (lookup, after) = with_untrusted_elf(path.to_str().unwrap(), |r| {
            // Enough for what an empty string keeps, not for the reservation.
            r.left.set(MIN_STRING_CHARGE + 10);
            (
                r.read_bytes_at_until(0..4096, 0).is_ok(),
                r.read_bytes_at(0, 1).is_ok(),
            )
        })
        .unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(!lookup, "refused before the cache allocates");
        assert!(!after, "the refusal is latched");
    }

    /// F8: the symbol scan stops at the first name it cannot read, instead
    /// of looking up every remaining name.
    #[test]
    fn test_symbol_scan_stops_at_unreadable_name() {
        use super::super::go_read::tests::{NoStrings, elf_with_functions};
        let elf = elf_with_functions(&[("a", &[0xc3]), ("b", &[0xc3]), ("SSL_write", &[0xc3])]);
        let lookups = std::cell::Cell::new(0);
        let found = resolve_elf_symbols_from_bytes(NoStrings(&elf, &lookups), &["SSL_write"]);
        assert!(found.unwrap().is_empty());
        assert_eq!(lookups.get(), 1);
    }

    #[test]
    fn test_maps_exec_file() {
        let m = |l| maps_exec_file(l);
        assert_eq!(
            m("7f12-7f13 r-xp 00000000 08:01 12345    /usr/lib/libssl.so.3"),
            Some(("/usr/lib/libssl.so.3".into(), 0x7f12))
        );
        assert_eq!(
            m("1000-2000 r-xp 0 08:01 7 /opt/my app/bin"),
            Some(("/opt/my app/bin".into(), 0x1000))
        );
        assert_eq!(m("1000-2000 r-xp 0 08:01 7 /tmp/evil (deleted)"), None);
        assert_eq!(m("1000-2000 r--p 0 08:01 7 /usr/lib/libssl.so.3"), None);
        assert_eq!(m("1000-2000 r-xp 0 00:00 0 [vdso]"), None);
        assert_eq!(m("1000-2000 r-xp 0 00:00 0"), None);
    }

    /// Codex: a FIFO at a mapped path is refused at once, by every opener
    /// of workload files (examination and attach), instead of blocking
    /// open(2) forever for want of a writer.
    #[cfg(unix)]
    #[test]
    fn test_workload_fifo_refused_without_blocking() {
        let dir = std::env::temp_dir().join(format!("panopticon-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("evil");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let p = fifo.to_str().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let target = TlsTarget {
                pid: 1,
                library_path: p.clone(),
                tls_type: TlsType::GoTls {
                    write_offset: 0,
                    read: None,
                },
                file_key: Some((0, 0, 0, 0)),
            };
            let _ = tx.send((
                open_workload_file(&p).is_err(),
                open_examined(&target).is_err(),
                resolve_elf_symbols(&p, &["SSL_write"]).is_err(),
                go_build_admitted(&p).is_err(),
            ));
        });
        let got = rx.recv_timeout(std::time::Duration::from_secs(5));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(got, Ok((true, true, true, true)), "refused, not blocked");
        // A regular file still opens.
        let exe = std::env::current_exe().unwrap();
        assert!(open_workload_file(exe.to_str().unwrap()).is_ok());
    }

    #[test]
    fn test_resolve_elf_symbols_empty_request() {
        // Even with invalid data, requesting no symbols should still fail
        // because we validate ELF format first
        let data = b"not an elf file";
        let result = resolve_elf_symbols_from_bytes(&data[..], &[]);
        assert!(result.is_err());
    }

    // ── /proc scanning (Linux-only) ─────────────────────────────────

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn test_is_openssl_library() {
            assert!(is_openssl_library("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
            assert!(is_openssl_library("/lib/libssl.so.1.1"));
            assert!(!is_openssl_library("/usr/lib/libcrypto.so.3"));
            assert!(!is_openssl_library("/usr/bin/openssl"));
        }

        #[test]
        fn test_is_go_binary() {
            assert!(is_go_binary("/usr/local/bin/myserver"));
            assert!(!is_go_binary("/usr/lib/libssl.so.3"));
            assert!(!is_go_binary("/usr/lib/libc.so.6"));
        }

        #[test]
        fn test_scan_pid_self() {
            // Scanning our own PID should not panic (may find no TLS libs)
            let pid = std::process::id();
            let targets = scan_pid(pid);
            // We don't assert specific results because the test runner
            // may or may not link OpenSSL, but it should not crash.
            let _ = targets;
        }

        #[test]
        fn test_scan_pid_nonexistent() {
            // Scanning a nonexistent PID should return empty, not error
            let targets = scan_pid(999_999_999);
            assert!(targets.is_empty());
        }

        #[test]
        fn test_parse_proc_maps_self() {
            let pid = std::process::id();
            let libs = parse_proc_maps(pid).expect("should read own maps");
            // We should find at least some executable mappings
            assert!(
                !libs.is_empty(),
                "should have at least one executable mapping"
            );
        }
    }
}
