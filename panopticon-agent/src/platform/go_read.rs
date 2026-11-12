//! Go `crypto/tls.(*Conn).Read` capture, user-space side (DESIGN §3.5 "Go
//! TLS reads"): where to put the probes, and the sweep of entries left by
//! process instances that ended. Depends only on `object`, `iced-x86` and
//! `aya`, so the scope_attach lab test includes this file as it is.

use object::read::elf::{ElfFile, FileHeader};
use object::{Object, ObjectSection, ObjectSymbol, ReadRef};

/// Entry offset of a Go `(*Conn).Read` and the offset of every return
/// instruction in it. Go reads cannot use a uretprobe (the runtime moves
/// goroutine stacks, which corrupts the rewritten return address), so the
/// result is read by a uprobe on each RET instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoReadProbes {
    pub entry_offset: u64,
    pub ret_offsets: Vec<u64>,
}

/// Most return instructions accepted in one function (sanity bound).
const MAX_GO_RETURNS: usize = 64;

/// Largest function body examined. The real `(*Conn).Read` is a few KiB; a
/// workload's ELF can declare anything, and decoding is bounded by this,
/// not by the file's read budget (security scan F4).
const MAX_GO_FN_BYTES: u64 = 1 << 20;

/// The probe offsets of the function `name` in an ELF, or None when they
/// cannot all be found: no sized symbol, code outside its section, an
/// instruction that does not decode, or no (or too many) returns.
pub fn go_read_probes_from<'data, R: ReadRef<'data>>(data: R, name: &str) -> Option<GoReadProbes> {
    let elf = ElfFile::<object::elf::FileHeader64<object::Endianness>, R>::parse(data).ok()?;
    let sym = elf
        .symbols()
        .find(|s| s.name().ok() == Some(name) && s.size() > 0)?;
    let (addr, size) = (sym.address(), sym.size());
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
    Some(GoReadProbes {
        entry_offset: symbol_file_offset(&elf, addr),
        ret_offsets: rets
            .into_iter()
            .map(|a| symbol_file_offset(&elf, a))
            .collect(),
    })
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

/// Remove what ended process instances left: `PROC_EPOCH` entries of
/// processes gone from `/proc` (an instance whose last threads re-created
/// its epoch after its leader's exit removed it), then `GO_READ_ARGS`
/// entries whose epoch is not their process's current one (Reads that
/// never returned: the process exited or exec'd mid-Read). Returns how many
/// of each were removed.
///
/// Each entry's epoch is compared with `PROC_EPOCH` as it is when that entry
/// is examined. An entry exists only after its epoch did, and an epoch, once
/// removed, never comes back (a new one is a later timestamp), so an entry
/// whose epoch is absent or different then is dead for good: no RET probe
/// can still accept it (maps.rs GO_READ_ARGS). Removing a live epoch (a PID
/// reused between the `/proc` check and the removal) only makes that
/// process's Reads in flight emit nothing.
#[cfg(target_os = "linux")]
pub fn sweep(ebpf: &aya::Ebpf) -> anyhow::Result<(usize, usize)> {
    use aya::maps::{HashMap, Map, MapData};
    use panopticon_common::{GoReadArgs, GoReadKey};

    // Own handles (by map id), so both maps are open at once.
    let open = |name: &str| -> anyhow::Result<Map> {
        let id = match ebpf.map(name) {
            Some(Map::HashMap(d)) => d.info()?.id(),
            _ => anyhow::bail!("{name}: no such hash map"),
        };
        Ok(Map::HashMap(MapData::from_id(id)?))
    };
    let mut epochs: HashMap<MapData, u32, u64> = HashMap::try_from(open("PROC_EPOCH")?)?;
    let mut args: HashMap<MapData, GoReadKey, GoReadArgs> =
        HashMap::try_from(open("GO_READ_ARGS")?)?;

    let gone: Vec<u32> = epochs
        .keys()
        .filter_map(Result::ok)
        .filter(|tgid| !std::path::Path::new(&format!("/proc/{tgid}")).exists())
        .collect();
    for tgid in &gone {
        let _ = epochs.remove(tgid);
    }
    let keys: Vec<GoReadKey> = args.keys().filter_map(Result::ok).collect();
    let mut dead = 0;
    for k in &keys {
        if epochs.get(&k.tgid, 0).ok() != Some(k.epoch) && args.remove(k).is_ok() {
            dead += 1;
        }
    }
    Ok((dead, gone.len()))
}

#[cfg(test)]
mod tests {
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
            let code = |n| if arch == object::Architecture::X86_64 { x86(n) } else { arm(n) };
            let ok = return_addresses(arch, 0, &code(MAX_GO_RETURNS)).unwrap();
            assert_eq!(ok.len(), MAX_GO_RETURNS, "{arch:?}");
            assert_eq!(return_addresses(arch, 0, &code(MAX_GO_RETURNS + 1)), None);
            assert_eq!(return_addresses(arch, 0, &code(1 << 20)), None);
        }
    }

    /// An x86_64 ELF with one function symbol `name` of `code`, at 0x1000.
    fn elf_with_function(name: &str, code: &[u8]) -> Vec<u8> {
        let text = 4096usize;
        let mut elf = vec![0u8; text + code.len()];
        elf[text..].copy_from_slice(code);
        elf[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[40..48].copy_from_slice(&64u64.to_le_bytes()); // e_shoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&4u16.to_le_bytes()); // null, symtab, strtab, text
        elf[62..64].copy_from_slice(&2u16.to_le_bytes());
        let strtab = 320;
        let names = format!("\0{name}\0");
        elf[strtab..strtab + names.len()].copy_from_slice(names.as_bytes());
        let symtab = 512;
        let sym = symtab + 24; // entry 1 (0 is the null symbol)
        elf[sym..sym + 4].copy_from_slice(&1u32.to_le_bytes()); // st_name
        elf[sym + 4] = 0x12; // STB_GLOBAL, STT_FUNC
        elf[sym + 6..sym + 8].copy_from_slice(&3u16.to_le_bytes()); // .text
        elf[sym + 8..sym + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[sym + 16..sym + 24].copy_from_slice(&(code.len() as u64).to_le_bytes());
        let mut sh = |i: usize, ty: u32, addr: u64, off: usize, size: usize, link: u32, ent: u64| {
            let b = 64 + i * 64;
            elf[b + 4..b + 8].copy_from_slice(&ty.to_le_bytes());
            elf[b + 16..b + 24].copy_from_slice(&addr.to_le_bytes());
            elf[b + 24..b + 32].copy_from_slice(&(off as u64).to_le_bytes());
            elf[b + 32..b + 40].copy_from_slice(&(size as u64).to_le_bytes());
            elf[b + 40..b + 44].copy_from_slice(&link.to_le_bytes());
            elf[b + 44..b + 48].copy_from_slice(&1u32.to_le_bytes()); // sh_info
            elf[b + 56..b + 64].copy_from_slice(&ent.to_le_bytes());
        };
        sh(1, object::elf::SHT_SYMTAB, 0, symtab, 48, 2, 24);
        sh(2, object::elf::SHT_STRTAB, 0, strtab, names.len(), 0, 0);
        sh(3, object::elf::SHT_PROGBITS, 0x1000, text, code.len(), 0, 0);
        elf
    }

    /// Discovery end to end on an ELF, and F4: a function body over
    /// MAX_GO_FN_BYTES is refused before it is decoded.
    #[test]
    fn test_go_read_probes_from_elf_and_size_cap() {
        let name = "crypto/tls.(*Conn).Read";
        // push rbp; ret; xor eax, eax; ret
        let elf = elf_with_function(name, &[0x55, 0xc3, 0x31, 0xc0, 0xc3]);
        assert_eq!(
            go_read_probes_from(&elf[..], name),
            Some(GoReadProbes {
                entry_offset: 0x1000,
                ret_offsets: vec![0x1001, 0x1004],
            })
        );
        assert_eq!(go_read_probes_from(&elf[..], "other"), None);
        let mut big = vec![0x90u8; MAX_GO_FN_BYTES as usize + 1]; // nops
        big[0] = 0xc3;
        assert_eq!(go_read_probes_from(&elf_with_function(name, &big)[..], name), None);
        big.truncate(MAX_GO_FN_BYTES as usize);
        assert!(go_read_probes_from(&elf_with_function(name, &big)[..], name).is_some());
    }
}
