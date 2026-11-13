//! Go `crypto/tls` read capture, user-space side (DESIGN §3.5 "Go TLS
//! reads"): where to put the probes, and the sweep of slots left by process
//! instances that ended. Depends only on `object`, `iced-x86` and `aya`, so
//! the scope_attach lab test includes this file as it is.

use object::read::elf::{ElfFile, FileHeader};
use object::{Object, ObjectSection, ObjectSymbol, ReadRef};

/// Reads one record into the connection's input buffer and decrypts it
/// there: its entry names the connection a goroutine is reading for.
pub const READ_RECORD: &str = "crypto/tls.(*Conn).readRecordOrCCS";
/// Decrypts a record in place; at its return the plaintext is emitted.
pub const DECRYPT: &str = "crypto/tls.(*halfConn).decrypt";

/// Probe offsets for Go TLS reads: the entry and every return instruction
/// of `readRecordOrCCS`, and every return instruction of `decrypt`. Go
/// functions cannot use a uretprobe (the runtime moves goroutine stacks,
/// which corrupts the rewritten return address), so returns are probed at
/// their RET instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoReadProbes {
    pub read_record_entry: u64,
    pub read_record_rets: Vec<u64>,
    pub decrypt_rets: Vec<u64>,
}

/// Most return instructions accepted in one function (sanity bound).
const MAX_GO_RETURNS: usize = 64;

/// Largest function body examined. The real functions are a few KiB; a
/// workload's ELF can declare anything, and decoding is bounded by this,
/// not by the file's read budget (security scan F4).
const MAX_GO_FN_BYTES: u64 = 1 << 20;

/// The probe offsets in an ELF, or None when they cannot all be found: a
/// symbol name that cannot be read (the scan stops there: a spent read
/// budget fails every later read too), no sized symbol for either function,
/// code outside its section, an instruction that does not decode, or no (or
/// too many) returns.
pub fn go_read_probes_from<'data, R: ReadRef<'data>>(data: R) -> Option<GoReadProbes> {
    let elf = ElfFile::<object::elf::FileHeader64<object::Endianness>, R>::parse(data).ok()?;
    let (mut read_record, mut decrypt) = (None, None);
    for sym in elf.symbols() {
        let name = sym.name().ok()?;
        let slot = match name {
            READ_RECORD => &mut read_record,
            DECRYPT => &mut decrypt,
            _ => continue,
        };
        if sym.size() > 0 && slot.is_none() {
            *slot = Some((sym.address(), sym.size()));
        }
        if read_record.is_some() && decrypt.is_some() {
            break;
        }
    }
    let read_record = read_record?;
    let read_record_rets = function_returns(&elf, data, read_record)?;
    let decrypt_rets = function_returns(&elf, data, decrypt?)?;
    Some(GoReadProbes {
        read_record_entry: symbol_file_offset(&elf, read_record.0),
        read_record_rets,
        decrypt_rets,
    })
}

/// File offsets of the return instructions of the function at `addr`
/// (`size` bytes), or None (see [`go_read_probes_from`]).
fn function_returns<'data, R: ReadRef<'data>>(
    elf: &ElfFile<'data, object::elf::FileHeader64<object::Endianness>, R>,
    data: R,
    (addr, size): (u64, u64),
) -> Option<Vec<u64>> {
    if size > MAX_GO_FN_BYTES {
        return None;
    }
    // Read only the function's bytes, not the whole section.
    let section = elf.sections().find(|s| {
        s.address() <= addr
            && addr
                .checked_add(size)
                .is_some_and(|e| e <= s.address() + s.size())
    })?;
    let (sec_off, sec_len) = section.file_range()?;
    let rel = addr - section.address();
    if rel.checked_add(size)? > sec_len {
        return None;
    }
    let code = data.read_bytes_at(sec_off.checked_add(rel)?, size).ok()?;
    let rets = return_addresses(elf.architecture(), addr, code)?;
    if rets.is_empty() {
        return None;
    }
    Some(
        rets.into_iter()
            .map(|a| symbol_file_offset(elf, a))
            .collect(),
    )
}

/// Virtual addresses of the return instructions in `code` (loaded at
/// `addr`), or None past `MAX_GO_RETURNS` (refused as soon as one more is
/// found, so the list never outgrows the bound). Decodes instructions
/// rather than searching for the RET byte, which also occurs inside other
/// instructions.
fn return_addresses(arch: object::Architecture, addr: u64, code: &[u8]) -> Option<Vec<u64>> {
    let mut rets = Vec::new();
    let mut push = |ip: u64| {
        rets.push(ip);
        rets.len() <= MAX_GO_RETURNS
    };
    match arch {
        object::Architecture::X86_64 => {
            use iced_x86::{Decoder, DecoderOptions, Mnemonic};
            let mut decoder = Decoder::with_ip(64, code, addr, DecoderOptions::NONE);
            for insn in &mut decoder {
                if insn.is_invalid() {
                    return None; // not code we understand: don't guess
                }
                if insn.mnemonic() == Mnemonic::Ret && !push(insn.ip()) {
                    return None;
                }
            }
        }
        object::Architecture::Aarch64 => {
            const RET: u32 = 0xd65f_03c0; // ret (x30)
            for (i, w) in code.chunks_exact(4).enumerate() {
                if u32::from_le_bytes([w[0], w[1], w[2], w[3]]) == RET && !push(addr + 4 * i as u64)
                {
                    return None;
                }
            }
        }
        _ => return None,
    }
    Some(rets)
}

/// Convert a symbol's virtual address to a file offset suitable for uprobe attachment.
///
/// For shared libraries (.so), subtract the base virtual address of the first
/// LOAD segment to get the offset relative to the library's load address.
/// For executables, the address is typically usable directly.
pub fn symbol_file_offset<'data, Elf: FileHeader, R: ReadRef<'data>>(
    elf: &ElfFile<'data, Elf, R>,
    sym_addr: u64,
) -> u64 {
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

/// Own handles on the two maps the sweep walks, opened by map id so the
/// walk needs neither the `Ebpf` object nor the lock that guards it: open
/// them under the lock, release it, then [`Sweep::run`] (off the async
/// runtime: a pass is thousands of syscalls).
#[cfg(target_os = "linux")]
pub struct Sweep {
    epochs: aya::maps::Map,
    calls: aya::maps::Map,
    /// Whether the last pass walked with batched lookups ([`walk_map`]).
    pub batched: bool,
}

#[cfg(target_os = "linux")]
impl Sweep {
    pub fn open(ebpf: &aya::Ebpf) -> anyhow::Result<Self> {
        use aya::maps::{Map, MapData};
        let open = |name: &str| -> anyhow::Result<Map> {
            let id = match ebpf.map(name) {
                Some(Map::HashMap(d)) => d.info()?.id(),
                _ => anyhow::bail!("{name}: no such hash map"),
            };
            Ok(Map::HashMap(MapData::from_id(id)?))
        };
        Ok(Self {
            epochs: open("PROC_EPOCH")?,
            calls: open("GO_READ_CALLS")?,
            batched: false,
        })
    }

    /// Remove what ended process instances left: `PROC_EPOCH` entries of
    /// processes gone from `/proc` (an instance whose last threads
    /// re-created its epoch after its leader's exit removed it), then
    /// `GO_READ_CALLS` slots whose epoch is not their process's current one
    /// (record reads that never returned: the process exited or exec'd
    /// mid-read). Returns how many of each were removed.
    ///
    /// Each slot's epoch is compared with `PROC_EPOCH` as it is when that
    /// slot is examined. A slot exists only after its epoch did, and an
    /// epoch, once removed, never comes back (a new one is a later
    /// timestamp), so a slot whose epoch is absent or different then is dead
    /// for good: no probe can still accept it (maps.rs GO_READ_CALLS).
    /// Removing a live epoch (a PID reused between the `/proc` check and the
    /// removal) only makes that process's reads in flight emit nothing.
    ///
    /// The walks run while the kernel inserts and deletes ([`walk_map`]).
    pub fn run(&mut self) -> anyhow::Result<(usize, usize)> {
        use aya::maps::{HashMap, Map, MapData};
        use panopticon_common::{GO_READS_IN_FLIGHT, GoReadCall, GoReadKey, TLS_SCRATCH_SIZE};
        use std::os::fd::{AsFd, AsRawFd};
        let fd = |m: &Map| match m {
            Map::HashMap(d) => d.fd().as_fd().as_raw_fd() as u32,
            _ => unreachable!("opened as a hash map"),
        };
        let (epochs_fd, calls_fd) = (fd(&self.epochs), fd(&self.calls));
        let mut epochs: HashMap<&mut MapData, u32, u64> = HashMap::try_from(&mut self.epochs)?;
        let (gone, batched) =
            walk_map::<u32, u64>(epochs_fd, TLS_SCRATCH_SIZE, |k| epochs.get(k, 0).is_ok())?;
        self.batched = batched;
        let gone: Vec<u32> = gone
            .into_iter()
            .filter(|tgid| !std::path::Path::new(&format!("/proc/{tgid}")).exists())
            .collect();
        let gone = gone.iter().filter(|t| epochs.remove(t).is_ok()).count();
        let mut calls: HashMap<&mut MapData, GoReadKey, GoReadCall> =
            HashMap::try_from(&mut self.calls)?;
        let (keys, _) = walk_map::<GoReadKey, GoReadCall>(calls_fd, GO_READS_IN_FLIGHT, |k| {
            calls.get(k, 0).is_ok()
        })?;
        let dead = keys
            .iter()
            .filter(|k| epochs.get(&k.tgid, 0).ok() != Some(k.epoch) && calls.remove(k).is_ok())
            .count();
        Ok((dead, gone))
    }
}

/// The keys of a hash map whose value type is `V`, and whether they came
/// from a batched walk. Batched (`BPF_MAP_LOOKUP_BATCH`, Linux 5.6+) where
/// the kernel has it: its cursor is a bucket index, so deletions under the
/// walk never send it back, and every pass reaches every bucket. Otherwise
/// (kernels without batch operations; the five lab kernels, RHEL 8.10
/// included, all have them) [`walk_keys`] with BPF_MAP_GET_NEXT_KEY from any key (aya
/// only walks from the first).
#[cfg(target_os = "linux")]
fn walk_map<K: aya::Pod + Eq + std::hash::Hash, V: aya::Pod>(
    fd: u32,
    capacity: u32,
    exists: impl Fn(&K) -> bool,
) -> anyhow::Result<(Vec<K>, bool)> {
    if let Some(keys) = batch_keys::<K, V>(fd, capacity)? {
        return Ok((keys, true));
    }
    let mut err = None;
    let next = |key: Option<&K>| -> Option<K> {
        #[repr(C)]
        struct Attr {
            map_fd: u32,
            _pad: u32,
            key: u64,
            next_key: u64,
        }
        const BPF_MAP_GET_NEXT_KEY: libc::c_long = 4;
        let mut out = std::mem::MaybeUninit::<K>::zeroed();
        let attr = Attr {
            map_fd: fd,
            _pad: 0,
            key: key.map_or(0, |k| k as *const K as u64),
            next_key: out.as_mut_ptr() as u64,
        };
        // SAFETY: bpf(2) reads `attr` and writes one key of K's size to `out`.
        let r = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_GET_NEXT_KEY,
                &attr,
                size_of::<Attr>(),
            )
        };
        if r == 0 {
            // SAFETY: written by the kernel; any bytes are a valid Pod.
            return Some(unsafe { out.assume_init() });
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOENT) {
            err = Some(e);
        }
        None
    };
    let keys = walk_keys(next, exists, 4 * capacity as usize);
    match err {
        Some(e) => Err(e.into()),
        None => Ok((keys, false)),
    }
}

/// Every key by `BPF_MAP_LOOKUP_BATCH`, at most `capacity` of them, or None
/// when the kernel refuses the first batch (no batch operations).
#[cfg(target_os = "linux")]
fn batch_keys<K: aya::Pod, V: aya::Pod>(fd: u32, capacity: u32) -> std::io::Result<Option<Vec<K>>> {
    #[repr(C)]
    struct Attr {
        in_batch: u64,
        out_batch: u64,
        keys: u64,
        values: u64,
        count: u32,
        map_fd: u32,
        elem_flags: u64,
        flags: u64,
    }
    const BPF_MAP_LOOKUP_BATCH: libc::c_long = 24;
    let capacity = capacity as usize;
    let mut chunk = 256usize;
    let mut out: Vec<K> = Vec::new();
    let (mut token_in, mut token_out) = (0u32, 0u32);
    let mut first = true;
    // Each call moves past at least one bucket; buckets <= 2 x capacity.
    for _ in 0..=2 * capacity {
        let mut keys = vec![std::mem::MaybeUninit::<K>::zeroed(); chunk];
        let mut values = vec![std::mem::MaybeUninit::<V>::zeroed(); chunk];
        let mut attr = Attr {
            in_batch: if first {
                0
            } else {
                &token_in as *const u32 as u64
            },
            out_batch: &mut token_out as *mut u32 as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: chunk as u32,
            map_fd: fd,
            elem_flags: 0,
            flags: 0,
        };
        // SAFETY: bpf(2) writes at most `count` keys and values into buffers
        // of that many elements, `count` and the 4-byte bucket token.
        let r = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_MAP_LOOKUP_BATCH,
                &mut attr,
                size_of::<Attr>(),
            )
        };
        let e = (r != 0).then(std::io::Error::last_os_error);
        match e.as_ref().and_then(|e| e.raw_os_error()) {
            None | Some(libc::ENOENT) => {}
            Some(libc::ENOSPC) if chunk < capacity.max(256) => {
                chunk *= 2; // one bucket holds more than a chunk
                continue;
            }
            _ if first => return Ok(None),
            _ => return Err(e.unwrap()),
        }
        let n = (attr.count as usize).min(chunk);
        // SAFETY: the kernel wrote the first `n` keys; any bytes are a Pod.
        out.extend(keys[..n].iter().map(|k| unsafe { k.assume_init() }));
        if e.is_some() || out.len() >= capacity {
            out.truncate(capacity);
            return Ok(Some(out)); // ENOENT: past the last bucket
        }
        token_in = token_out;
        first = false;
    }
    Ok(Some(out))
}

/// The keys of a hash map being changed under the walk, in at most `budget`
/// steps (each get-next-key or existence check is one).
///
/// The kernel's get-next-key restarts at the first key when the key it is
/// given was deleted meanwhile, so a plain walk can be held at the head by
/// churn and never reach later keys. Here, after each step, the key the walk
/// stood on is checked: if it is gone (or the step returned a key already
/// visited), the step may have restarted, and the walk resumes from the
/// latest key it visited that still exists, instead of from the head. Dead
/// slots, the ones the sweep is for, are never deleted by the kernel, so
/// once visited they anchor the walk; to hold it back, churn would have to
/// delete each key the walk stands on within the microseconds between two
/// of its syscalls. Keys a pass does not reach (budget spent) wait for the
/// next pass.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn walk_keys<K: Copy + Eq + std::hash::Hash>(
    mut next: impl FnMut(Option<&K>) -> Option<K>,
    exists: impl Fn(&K) -> bool,
    budget: usize,
) -> Vec<K> {
    let mut seen = std::collections::HashSet::new();
    let mut order: Vec<K> = Vec::new();
    let mut cur: Option<K> = None;
    let mut steps = 0;
    let step = |steps: &mut usize| {
        *steps += 1;
        *steps <= budget
    };
    while step(&mut steps) {
        let Some(k) = next(cur.as_ref()) else { break };
        let stood = match cur {
            Some(c) => {
                if !step(&mut steps) {
                    break;
                }
                exists(&c)
            }
            None => true,
        };
        if stood && seen.insert(k) {
            order.push(k);
            cur = Some(k);
            continue;
        }
        if stood {
            // A visited key returned after a key that still exists: deleted
            // and re-inserted further on. Step over it.
            cur = Some(k);
            continue;
        }
        // The key stood on is gone: resume from the latest visited key that
        // still exists.
        cur = None;
        for v in order.iter().rev() {
            if !step(&mut steps) {
                return order;
            }
            if exists(v) {
                cur = Some(*v);
                break;
            }
        }
        if cur.is_none() {
            break; // every visited key is gone: nothing left to anchor on
        }
    }
    order
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn test_return_addresses_decodes_instructions_x86_64() {
        let code = [
            0x48, 0x89, 0xc3, // mov rbx, rax
            0xb8, 0xc3, 0x00, 0x00, 0x00, // mov eax, 0xc3 (0xc3 byte, not a ret)
            0xc3, // ret
            0x48, 0x31, 0xc0, // xor rax, rax
            0xc3, // ret
        ];
        let rets = return_addresses(object::Architecture::X86_64, 0x1000, &code).unwrap();
        assert_eq!(rets, vec![0x1008, 0x100c]);
    }

    #[test]
    fn test_return_addresses_aarch64() {
        let mut code = Vec::new();
        for w in [0xd503201fu32, 0xd65f03c0, 0xaa0003e1, 0xd65f03c0] {
            code.extend(w.to_le_bytes()); // nop, ret, mov x1, x0, ret
        }
        let rets = return_addresses(object::Architecture::Aarch64, 0x4000, &code).unwrap();
        assert_eq!(rets, vec![0x4004, 0x400c]);
    }

    /// F4: past MAX_GO_RETURNS the scan stops and refuses, on both
    /// architectures; at the bound it is accepted.
    #[test]
    fn test_return_addresses_refused_past_the_bound() {
        let x86 = |n: usize| vec![0xc3u8; n];
        let arm = |n: usize| 0xd65f_03c0u32.to_le_bytes().repeat(n);
        for arch in [object::Architecture::X86_64, object::Architecture::Aarch64] {
            let code = |n| {
                if arch == object::Architecture::X86_64 {
                    x86(n)
                } else {
                    arm(n)
                }
            };
            let ok = return_addresses(arch, 0, &code(MAX_GO_RETURNS)).unwrap();
            assert_eq!(ok.len(), MAX_GO_RETURNS, "{arch:?}");
            assert_eq!(return_addresses(arch, 0, &code(MAX_GO_RETURNS + 1)), None);
            assert_eq!(return_addresses(arch, 0, &code(1 << 20)), None);
        }
    }

    /// An x86_64 ELF with one function symbol per `(name, code)`, laid out
    /// one after another from 0x1000.
    pub(crate) fn elf_with_functions(funcs: &[(&str, &[u8])]) -> Vec<u8> {
        let text = 4096usize;
        let code: Vec<u8> = funcs.iter().flat_map(|(_, c)| c.iter().copied()).collect();
        let mut elf = vec![0u8; text + code.len()];
        elf[text..].copy_from_slice(&code);
        elf[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&4u16.to_le_bytes()); // null, symtab, strtab, text
        elf[62..64].copy_from_slice(&2u16.to_le_bytes());
        let (strtab, symtab) = (320, 1024);
        let mut names = vec![0u8];
        let mut addr = 0x1000u64;
        for (i, (name, code)) in funcs.iter().enumerate() {
            let sym = symtab + 24 * (i + 1); // entry 0 is the null symbol
            elf[sym..sym + 4].copy_from_slice(&(names.len() as u32).to_le_bytes());
            elf[sym + 4] = 0x12; // STB_GLOBAL, STT_FUNC
            elf[sym + 6..sym + 8].copy_from_slice(&3u16.to_le_bytes()); // .text
            elf[sym + 8..sym + 16].copy_from_slice(&addr.to_le_bytes());
            elf[sym + 16..sym + 24].copy_from_slice(&(code.len() as u64).to_le_bytes());
            names.extend(name.bytes().chain([0]));
            addr += code.len() as u64;
        }
        assert!(strtab + names.len() <= symtab && symtab + 24 * (funcs.len() + 1) <= text);
        elf[strtab..strtab + names.len()].copy_from_slice(&names);
        let mut sh =
            |i: usize, ty: u32, addr: u64, off: usize, size: usize, link: u32, ent: u64| {
                let b = 64 + i * 64;
                elf[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
                elf[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes());
                elf[b + 24..b + 32].copy_from_slice(&(off as u64).to_le_bytes());
                elf[b + 32..b + 40].copy_from_slice(&(size as u64).to_le_bytes());
                elf[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
                elf[b + 44..b + 48].copy_from_slice(&1u32.to_le_bytes()); // sh_info
                elf[b + 56..b + 64].copy_from_slice(&ent.to_le_bytes());
            };
        sh(
            1,
            object::elf::SHT_SYMTAB,
            0,
            symtab,
            24 * (funcs.len() + 1),
            2,
            24,
        );
        sh(2, object::elf::SHT_STRTAB, 0, strtab, names.len(), 0, 0);
        sh(3, object::elf::SHT_PROGBITS, 0x1000, text, code.len(), 0, 0);
        elf
    }

    /// Discovery end to end on an ELF; and F4: a function body over
    /// MAX_GO_FN_BYTES is refused before it is decoded.
    #[test]
    fn test_go_read_probes_from_elf_and_size_cap() {
        // push rbp; ret; xor eax, eax; ret  |  ret
        let rrc: &[u8] = &[0x55, 0xc3, 0x31, 0xc0, 0xc3];
        let elf = elf_with_functions(&[("other", &[0xc3]), (READ_RECORD, rrc), (DECRYPT, &[0xc3])]);
        assert_eq!(
            go_read_probes_from(&elf[..]),
            Some(GoReadProbes {
                read_record_entry: 0x1001,
                read_record_rets: vec![0x1002, 0x1005],
                decrypt_rets: vec![0x1006],
            })
        );
        // Both functions are needed.
        assert_eq!(
            go_read_probes_from(&elf_with_functions(&[(READ_RECORD, rrc)])[..]),
            None
        );
        assert_eq!(
            go_read_probes_from(&elf_with_functions(&[(DECRYPT, rrc)])[..]),
            None
        );
        let mut big = vec![0x90u8; MAX_GO_FN_BYTES as usize + 1]; // nops
        big[0] = 0xc3;
        let elf = |big: &[u8]| elf_with_functions(&[(READ_RECORD, rrc), (DECRYPT, big)]);
        assert_eq!(go_read_probes_from(&elf(&big)[..]), None);
        big.truncate(MAX_GO_FN_BYTES as usize);
        assert!(go_read_probes_from(&elf(&big)[..]).is_some());
    }

    /// A reader whose string lookups all fail, counting them.
    #[derive(Clone, Copy)]
    pub(crate) struct NoStrings<'a>(pub &'a [u8], pub &'a std::cell::Cell<usize>);

    impl<'a> ReadRef<'a> for NoStrings<'a> {
        fn len(self) -> Result<u64, ()> {
            Ok(self.0.len() as u64)
        }
        fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
            self.0.read_bytes_at(offset, size)
        }
        fn read_bytes_at_until(self, _: std::ops::Range<u64>, _: u8) -> Result<&'a [u8], ()> {
            self.1.set(self.1.get() + 1);
            Err(())
        }
    }

    /// F8: the symbol search stops at the first name it cannot read (a
    /// spent budget fails every later lookup), instead of scanning on.
    #[test]
    fn test_symbol_search_stops_at_unreadable_name() {
        let elf = elf_with_functions(&[("a", &[0xc3]), ("b", &[0xc3]), (DECRYPT, &[0xc3])]);
        let lookups = std::cell::Cell::new(0);
        assert_eq!(go_read_probes_from(NoStrings(&elf, &lookups)), None);
        assert_eq!(lookups.get(), 1);
    }

    /// A map in bucket order where deleting the key a walk stands on sends
    /// its next step back to the first key, as the kernel's does.
    struct Churned {
        keys: Vec<u32>,
    }

    impl Churned {
        fn next(&self, cur: Option<&u32>) -> Option<u32> {
            match cur {
                None => self.keys.first().copied(),
                Some(c) => match self.keys.iter().position(|k| k == c) {
                    Some(i) => self.keys.get(i + 1).copied(),
                    None => self.keys.first().copied(), // restart
                },
            }
        }
    }

    /// Codex MED: churn at the head must not keep a walk from later keys.
    /// Every live key (odd) is deleted as soon as the walk stands on it and
    /// put back at the head; the dead ones (even, never touched by the
    /// kernel) must all be reached within the budget.
    #[test]
    fn test_walk_keys_progresses_under_churn() {
        let m = std::cell::RefCell::new(Churned {
            keys: (0..2000).collect(),
        });
        let next = |cur: Option<&u32>| {
            let mut m = m.borrow_mut();
            let k = m.next(cur)?;
            if k % 2 == 1 {
                // the probe ends that read; the goroutine reads again
                m.keys.retain(|x| *x != k);
                m.keys.insert(0, k + 10_000);
            }
            Some(k)
        };
        let exists = |k: &u32| m.borrow().keys.contains(k);
        let got = walk_keys(next, exists, 4 * 2000);
        let dead: std::collections::HashSet<u32> = got
            .iter()
            .copied()
            .filter(|k| k % 2 == 0 && *k < 2000)
            .collect();
        assert_eq!(dead.len(), 1000, "every dead key reached");

        // A plain walk (restart from the head, no resume) never gets far.
        let m2 = std::cell::RefCell::new(Churned {
            keys: (0..2000).collect(),
        });
        let mut cur = None;
        let mut plain = std::collections::HashSet::new();
        for _ in 0..4 * 2000 {
            let mut mm = m2.borrow_mut();
            let Some(k) = mm.next(cur.as_ref()) else {
                break;
            };
            if k % 2 == 1 {
                mm.keys.retain(|x| *x != k);
                mm.keys.insert(0, k + 10_000);
            }
            plain.insert(k);
            cur = Some(k);
        }
        assert!(plain.iter().filter(|k| *k % 2 == 0 && **k < 2000).count() < 10);
    }

    /// The fallback's residual (Codex MED): a key deleted and re-inserted
    /// at the same place between the walk's get-next-key and its check of
    /// that key (A, restart, A again) can hold the walk at that key. The
    /// walk then stays within its budget and keeps what it reached; on
    /// kernels with batched lookups the sweep does not use this walk.
    #[test]
    fn test_walk_keys_same_key_churn_stays_bounded() {
        let keys: Vec<u32> = (0..100).collect();
        let next = |cur: Option<&u32>| match cur {
            None => Some(0),
            Some(5) => Some(0), // 5 deleted under the step: restart...
            Some(c) => keys.get(*c as usize + 1).copied(),
        };
        let exists = |_: &u32| true; // ...and back before the check
        let got = walk_keys(next, exists, 1000);
        assert_eq!(got, (0..=5).collect::<Vec<_>>(), "held at 5, bounded");
    }

    /// A walk over a quiet map visits every key once, within the budget.
    #[test]
    fn test_walk_keys_quiet_map() {
        let m = Churned {
            keys: (0..100).collect(),
        };
        let got = walk_keys(|c| m.next(c), |k| m.keys.contains(k), 400);
        assert_eq!(got, (0..100).collect::<Vec<_>>());
        // Two steps a key (get-next-key, then the check of the key stood on).
        assert_eq!(walk_keys(|c| m.next(c), |_| true, 10).len(), 5, "budget");
    }
}
