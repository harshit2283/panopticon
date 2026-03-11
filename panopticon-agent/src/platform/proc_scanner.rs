#![allow(dead_code)]

//! TLS library discovery via /proc scanning and ELF symbol resolution.
//!
//! **Cross-platform**: `resolve_elf_symbols`, `detect_go_version`, `parse_go_abi`
//! work on any OS (testable on macOS with ELF fixtures).
//!
//! **Linux-only**: `scan_all_processes`, `scan_pid`, `parse_proc_maps`
//! read `/proc/*/maps` to find loaded TLS libraries.

use std::collections::HashMap;

use anyhow::{Context, Result};
use object::read::elf::{ElfFile, FileHeader};
use object::{Object, ObjectSection, ObjectSymbol};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

// ── Types ────────────────────────────────────────────────────────────────

/// A discovered TLS library target ready for uprobe attachment.
#[derive(Debug, Clone)]
pub struct TlsTarget {
    pub pid: u32,
    pub library_path: String,
    pub tls_type: TlsType,
}

/// The kind of TLS library discovered, with symbol offsets for uprobe attachment.
#[derive(Debug, Clone)]
pub enum TlsType {
    OpenSsl {
        ssl_write_offset: u64,
        ssl_read_offset: u64,
    },
    GoTls {
        write_offset: u64,
        go_version: GoVersion,
    },
}

/// Go ABI version — determines how arguments are passed to functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoVersion {
    /// Go >= 1.17 — register-based ABI (what our eBPF probe expects).
    RegisterAbi,
    /// Go < 1.17 — stack-based ABI (skip attachment in v1).
    StackAbi,
}

// ── ELF Symbol Resolution (cross-platform) ──────────────────────────────

/// Resolve symbol offsets from an ELF binary's `.dynsym` or `.symtab`.
///
/// Returns a map of `symbol_name → file_offset` for each requested symbol
/// that was found. Missing symbols are silently omitted from the result.
pub fn resolve_elf_symbols(path: &str, symbols: &[&str]) -> Result<HashMap<String, u64>> {
    let data = std::fs::read(path).with_context(|| format!("failed to read ELF: {path}"))?;
    resolve_elf_symbols_from_bytes(&data, symbols)
}

/// Inner implementation operating on bytes — easier to test with fixtures.
pub fn resolve_elf_symbols_from_bytes(
    data: &[u8],
    symbols: &[&str],
) -> Result<HashMap<String, u64>> {
    let mut result = HashMap::new();

    // Try 64-bit ELF first, then 32-bit
    if let Ok(elf) = ElfFile::<object::elf::FileHeader64<object::Endianness>>::parse(data) {
        collect_symbols(&elf, symbols, &mut result);
    } else if let Ok(elf) = ElfFile::<object::elf::FileHeader32<object::Endianness>>::parse(data) {
        collect_symbols(&elf, symbols, &mut result);
    } else {
        anyhow::bail!("not a valid ELF file");
    }

    Ok(result)
}

fn collect_symbols<'data, Elf: FileHeader>(
    elf: &ElfFile<'data, Elf>,
    wanted: &[&str],
    result: &mut HashMap<String, u64>,
) {
    for sym in elf.symbols() {
        if let Ok(name) = sym.name()
            && wanted.contains(&name)
        {
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
        if let Ok(name) = sym.name()
            && wanted.contains(&name)
            && !result.contains_key(name)
        {
            let offset = symbol_file_offset(elf, sym.address());
            result.insert(name.to_string(), offset);
        }
    }
}

/// Convert a symbol's virtual address to a file offset suitable for uprobe attachment.
///
/// For shared libraries (.so), subtract the base virtual address of the first
/// LOAD segment to get the offset relative to the library's load address.
/// For executables, the address is typically usable directly.
fn symbol_file_offset<'data, Elf: FileHeader>(elf: &ElfFile<'data, Elf>, sym_addr: u64) -> u64 {
    // Find the minimum virtual address across all LOAD segments.
    // This is the base address from which offsets are calculated.
    use object::read::elf::ProgramHeader;

    let endian = elf.endian();
    if let Ok(segments) = elf.elf_header().program_headers(endian, elf.data()) {
        let base_vaddr = segments
            .iter()
            .filter(|seg| seg.p_type(endian) == object::elf::PT_LOAD)
            .map(|seg| seg.p_vaddr(endian).into())
            .min()
            .unwrap_or(0u64);

        if base_vaddr > 0 && sym_addr >= base_vaddr {
            return sym_addr - base_vaddr;
        }
    }

    sym_addr
}

/// Detect Go version from the `.go.buildinfo` ELF section.
///
/// Returns the Go version string (e.g., `"go1.21.5"`) or `None` if
/// not a Go binary or the version cannot be determined.
pub fn detect_go_version(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    detect_go_version_from_bytes(&data)
}

/// Inner implementation for testability.
pub fn detect_go_version_from_bytes(data: &[u8]) -> Option<String> {
    // Try 64-bit first, then 32-bit
    if let Ok(elf) = ElfFile::<object::elf::FileHeader64<object::Endianness>>::parse(data) {
        return extract_go_version(&elf);
    }
    if let Ok(elf) = ElfFile::<object::elf::FileHeader32<object::Endianness>>::parse(data) {
        return extract_go_version(&elf);
    }
    None
}

fn extract_go_version<'data, Elf: FileHeader>(elf: &ElfFile<'data, Elf>) -> Option<String> {
    // Look for .go.buildinfo section
    let section = elf.section_by_name(".go.buildinfo")?;
    let section_data = section.data().ok()?;

    // The .go.buildinfo section starts with a 16-byte header (Go 1.18+):
    //   bytes 0-3:  magic "\xff Go buildinf:"  (14 bytes actually)
    // For older Go versions, the version string is embedded differently.
    // We'll search for "go1." pattern in the section data.
    extract_go_version_string(section_data)
}

/// Extract Go version string from buildinfo section data.
/// Searches for "go1.X" pattern in the raw bytes.
fn extract_go_version_string(data: &[u8]) -> Option<String> {
    // Search for "go1." in the section data
    let needle = b"go1.";
    for i in 0..data.len().saturating_sub(needle.len()) {
        if &data[i..i + needle.len()] == needle {
            // Read until non-version character
            let start = i;
            let mut end = i + needle.len();
            while end < data.len() && (data[end].is_ascii_digit() || data[end] == b'.') {
                end += 1;
            }
            if end > start + needle.len()
                && let Ok(version) = std::str::from_utf8(&data[start..end])
            {
                return Some(version.to_string());
            }
        }
    }
    None
}

/// Parse a Go version string into a `GoVersion` enum.
///
/// Go >= 1.17 uses register-based ABI (what our eBPF probe expects).
/// Go < 1.17 uses stack-based ABI (unsupported in v1).
pub fn parse_go_abi(version_str: &str) -> GoVersion {
    // Expected format: "go1.XX" or "go1.XX.Y"
    let version = version_str.strip_prefix("go1.").unwrap_or("");
    let minor: u32 = version
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if minor >= 17 {
        GoVersion::RegisterAbi
    } else {
        GoVersion::StackAbi
    }
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

    // Deduplicate by library_path (multiple PIDs may load the same libssl.so)
    // For uprobes attached globally (pid=None), we only need one attachment per library.
    let mut seen_libs = std::collections::HashSet::new();
    targets.retain(|t| seen_libs.insert(t.library_path.clone()));

    debug!(count = targets.len(), "TLS library scan complete");
    targets
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
        let namespace_path = namespace_resolved_path(pid, path);

        // Check for OpenSSL
        if is_openssl_library(path)
            && let Ok(syms) = resolve_elf_symbols(&namespace_path, &["SSL_write", "SSL_read"])
            && let (Some(&write_off), Some(&read_off)) =
                (syms.get("SSL_write"), syms.get("SSL_read"))
        {
            targets.push(TlsTarget {
                pid,
                library_path: namespace_path.clone(),
                tls_type: TlsType::OpenSsl {
                    ssl_write_offset: write_off,
                    ssl_read_offset: read_off,
                },
            });
            debug!(pid, path, target = %namespace_path, "Found OpenSSL library");
        }

        // Check for Go binaries
        if is_go_binary(path)
            && let Some(version) = detect_go_version(&namespace_path)
        {
            let go_abi = parse_go_abi(&version);
            if let Ok(syms) = resolve_elf_symbols(&namespace_path, &["crypto/tls.(*Conn).Write"])
                && let Some(&write_off) = syms.get("crypto/tls.(*Conn).Write")
            {
                targets.push(TlsTarget {
                    pid,
                    library_path: namespace_path.clone(),
                    tls_type: TlsType::GoTls {
                        write_offset: write_off,
                        go_version: go_abi,
                    },
                });
                debug!(pid, path, target = %namespace_path, %version, "Found Go TLS binary");
            } else {
                debug!(
                    pid,
                    path,
                    target = %namespace_path,
                    %version,
                    "Go binary detected but crypto/tls.(*Conn).Write was not found"
                );
            }
        }
    }

    targets
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

    for line in content.lines() {
        // Format: address perms offset dev inode pathname
        // Example: 7f1234000000-7f1234100000 r-xp 00000000 08:01 12345 /usr/lib/libssl.so.3
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let perms = parts[1];
        let path = parts[5];

        // Only care about executable mappings with real file paths
        if !perms.contains('x') || !path.starts_with('/') {
            continue;
        }

        // Parse base address from the address range
        let base_addr = parts[0]
            .split('-')
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or(0);

        if seen.insert(path.to_string()) {
            libs.push((path.to_string(), base_addr));
        }
    }

    Ok(libs)
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
/// Also listens on `rescan_rx` for on-demand PID scans triggered by ProcessExec
/// events — when a new process starts, we immediately check it for TLS libraries
/// rather than waiting for the next periodic scan.
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
    mut rescan_rx: tokio::sync::mpsc::Receiver<u32>,
) {
    let mut interval = tokio::time::interval(scan_interval);
    interval.tick().await; // skip immediate first tick — initial scan already done

    loop {
        // Select between periodic full scan and on-demand PID scan
        enum ScanType {
            Full,
            Pid(u32),
        }

        let scan_type = tokio::select! {
            _ = interval.tick() => ScanType::Full,
            pid = rescan_rx.recv() => {
                match pid {
                    Some(pid) => ScanType::Pid(pid),
                    None => break, // Channel closed, shut down
                }
            }
        };

        match scan_type {
            ScanType::Full => {
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

                // ── IO + ELF parsing OUTSIDE the lock ────────────────
                let targets = scan_all_processes();
                prune_attached_libs(&shared_ebpf, &targets);
                let newly_attached = attach_new_targets(&shared_ebpf, targets);
                if newly_attached > 0 {
                    info!(
                        new_libraries = newly_attached,
                        "Background TLS scan: attached uprobes to new libraries"
                    );
                }
            }
            ScanType::Pid(pid) => {
                debug!(pid, "On-demand TLS rescan for new process");
                // Small delay to let the process finish loading its libraries
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let targets = scan_pid(pid);
                let newly_attached = attach_new_targets(&shared_ebpf, targets);
                if newly_attached > 0 {
                    info!(
                        pid,
                        new_libraries = newly_attached,
                        "On-demand TLS scan: attached uprobes for new process"
                    );
                }
            }
        }
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

    // ── parse_go_abi ─────────────────────────────────────────────────

    #[test]
    fn test_parse_go_abi_modern() {
        assert_eq!(parse_go_abi("go1.21.5"), GoVersion::RegisterAbi);
        assert_eq!(parse_go_abi("go1.17"), GoVersion::RegisterAbi);
        assert_eq!(parse_go_abi("go1.22.0"), GoVersion::RegisterAbi);
    }

    #[test]
    fn test_parse_go_abi_old() {
        assert_eq!(parse_go_abi("go1.16"), GoVersion::StackAbi);
        assert_eq!(parse_go_abi("go1.15.3"), GoVersion::StackAbi);
        assert_eq!(parse_go_abi("go1.10"), GoVersion::StackAbi);
    }

    #[test]
    fn test_parse_go_abi_boundary() {
        assert_eq!(parse_go_abi("go1.17"), GoVersion::RegisterAbi);
        assert_eq!(parse_go_abi("go1.16"), GoVersion::StackAbi);
    }

    #[test]
    fn test_parse_go_abi_invalid() {
        // Gracefully handle garbage — defaults to StackAbi (safe: won't attach)
        assert_eq!(parse_go_abi("garbage"), GoVersion::StackAbi);
        assert_eq!(parse_go_abi(""), GoVersion::StackAbi);
    }

    // ── extract_go_version_string ────────────────────────────────────

    #[test]
    fn test_extract_go_version_string_found() {
        let data = b"\x00\x00go1.21.5\x00some other data";
        assert_eq!(
            extract_go_version_string(data),
            Some("go1.21.5".to_string())
        );
    }

    #[test]
    fn test_extract_go_version_string_not_found() {
        let data = b"\x00\x00no version here\x00";
        assert_eq!(extract_go_version_string(data), None);
    }

    #[test]
    fn test_extract_go_version_string_multiple() {
        // Should find the first occurrence
        let data = b"go1.19.3\x00go1.21.0";
        assert_eq!(
            extract_go_version_string(data),
            Some("go1.19.3".to_string())
        );
    }

    // ── resolve_elf_symbols_from_bytes ───────────────────────────────

    #[test]
    fn test_resolve_elf_symbols_invalid_data() {
        let data = b"not an elf file";
        let result = resolve_elf_symbols_from_bytes(data, &["SSL_write"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_elf_symbols_empty_request() {
        // Even with invalid data, requesting no symbols should still fail
        // because we validate ELF format first
        let data = b"not an elf file";
        let result = resolve_elf_symbols_from_bytes(data, &[]);
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
