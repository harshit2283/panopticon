//! TC (Traffic Control) classifier programs for capturing network packets.
//!
//! Attached to both ingress and egress hooks on the target interface.
//! Parses Ethernet → IPv4 → TCP/UDP headers, copies payload into a
//! DataEvent via RingBuf reserve (never stack — DataEvent is ~4KB),
//! and always returns TC_ACT_OK (passive observer, never drops packets).

use aya_ebpf::{
    bindings::TC_ACT_OK, cty::c_long, helpers::bpf_ktime_get_ns, macros::classifier,
    programs::TcContext,
};
use panopticon_common::{
    CONFIG_CAPTURE_ENABLED, DataEvent, Direction, EventType, MAX_PAYLOAD_SIZE, TlsLibrary,
};

use crate::maps::{CONFIG, DATA_EVENTS, DATA_EVENTS_PERF, IPV6_DROPS, PERF_SCRATCH};

// ── FNV-1a hash for connection cookie ──────────────────────────────────────

/// Compute a deterministic connection cookie from the 5-tuple using FNV-1a.
/// Normalizes by ordering (addr, port) pairs so both directions get the same cookie.
#[inline(always)]
fn tc_connection_cookie(
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
) -> u64 {
    // Normalize: smaller (addr, port) pair first for bidirectional consistency
    let (a_addr, a_port, b_addr, b_port) = if (src_addr, src_port) <= (dst_addr, dst_port) {
        (src_addr, src_port, dst_addr, dst_port)
    } else {
        (dst_addr, dst_port, src_addr, src_port)
    };

    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET;
    // Hash each byte of the 5-tuple
    let bytes: [u8; 13] = [
        (a_addr >> 24) as u8,
        (a_addr >> 16) as u8,
        (a_addr >> 8) as u8,
        a_addr as u8,
        (a_port >> 8) as u8,
        a_port as u8,
        (b_addr >> 24) as u8,
        (b_addr >> 16) as u8,
        (b_addr >> 8) as u8,
        b_addr as u8,
        (b_port >> 8) as u8,
        b_port as u8,
        ip_proto,
    ];

    let mut i = 0;
    while i < 13 {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

// ── Ethernet / IP / TCP / UDP constants ────────────────────────────────────

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IPV4_HDR_MIN_LEN: usize = 20;
const TCP_HDR_MIN_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const TC_CAPTURE_COPY_MAX: u32 = 1024;

// ── TC entry points ────────────────────────────────────────────────────────

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_capture(&ctx, Direction::Ingress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_capture(&ctx, Direction::Egress) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

// ── Core capture logic ─────────────────────────────────────────────────────

#[inline(always)]
fn try_tc_capture(ctx: &TcContext, direction: Direction) -> Result<i32, c_long> {
    if !is_capture_enabled() {
        return Ok(TC_ACT_OK);
    }

    let use_ringbuf = match CONFIG.get(panopticon_common::CONFIG_USE_RINGBUF) {
        Some(&v) => v != 0,
        None => true, // default to ringbuf
    };

    let data_end = ctx.data_end();
    let data = ctx.data();

    if data + ETH_HDR_LEN > data_end {
        return Ok(TC_ACT_OK);
    }

    let eth_proto = u16::from_be(ctx.load(12)?);
    if eth_proto != ETH_P_IP {
        if eth_proto == ETH_P_IPV6 {
            // Count IPv6 drops — IPv6 support is planned but not yet implemented
            if let Some(counter) = IPV6_DROPS.get_ptr_mut(0) {
                unsafe {
                    *counter += 1;
                }
            }
        }
        return Ok(TC_ACT_OK);
    }

    let ip_offset = ETH_HDR_LEN;
    if data + ip_offset + IPV4_HDR_MIN_LEN > data_end {
        return Ok(TC_ACT_OK);
    }

    let version_ihl: u8 = ctx.load(ip_offset)?;
    let ihl = ((version_ihl & 0x0F) as usize) * 4;
    if ihl < IPV4_HDR_MIN_LEN {
        return Ok(TC_ACT_OK);
    }

    let ip_proto: u8 = ctx.load(ip_offset + 9)?;
    let total_len = u16::from_be(ctx.load::<u16>(ip_offset + 2)?) as usize;
    let src_addr = u32::from_be(ctx.load::<u32>(ip_offset + 12)?);
    let dst_addr = u32::from_be(ctx.load::<u32>(ip_offset + 16)?);

    let transport_offset = ip_offset + ihl;
    let (src_port, dst_port, payload_offset) = match ip_proto {
        IP_PROTO_TCP => {
            if data + transport_offset + TCP_HDR_MIN_LEN > data_end {
                return Ok(TC_ACT_OK);
            }
            let sport = u16::from_be(ctx.load::<u16>(transport_offset)?);
            let dport = u16::from_be(ctx.load::<u16>(transport_offset + 2)?);
            let data_off: u8 = ctx.load(transport_offset + 12)?;
            let tcp_hdr_len = ((data_off >> 4) as usize) * 4;
            (sport, dport, transport_offset + tcp_hdr_len)
        }
        IP_PROTO_UDP => {
            if data + transport_offset + UDP_HDR_LEN > data_end {
                return Ok(TC_ACT_OK);
            }
            let sport = u16::from_be(ctx.load::<u16>(transport_offset)?);
            let dport = u16::from_be(ctx.load::<u16>(transport_offset + 2)?);
            (sport, dport, transport_offset + UDP_HDR_LEN)
        }
        _ => return Ok(TC_ACT_OK),
    };

    let ip_payload_end = ip_offset + total_len;
    if payload_offset >= ip_payload_end {
        return Ok(TC_ACT_OK);
    }
    let payload_len = ip_payload_end - payload_offset;
    let capture_len = if payload_len > MAX_PAYLOAD_SIZE {
        MAX_PAYLOAD_SIZE as u32
    } else {
        payload_len as u32
    };

    if use_ringbuf {
        let Some(mut entry) = DATA_EVENTS.reserve::<DataEvent>(0) else {
            return Ok(TC_ACT_OK);
        };

        let event = entry.as_mut_ptr();
        populate_tc_event(
            event,
            ctx,
            direction,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            ip_proto,
            payload_offset,
            capture_len,
            true,
        );

        entry.submit(0);
    } else {
        // PerfEventArray path: use per-CPU scratch map (DataEvent is ~4.2KB,
        // far exceeds the 512-byte BPF stack limit).
        let Some(event) = PERF_SCRATCH.get_ptr_mut(0) else {
            return Ok(TC_ACT_OK);
        };

        unsafe {
            core::ptr::write_bytes(event as *mut u8, 0, core::mem::size_of::<DataEvent>());
        }

        populate_tc_event(
            event,
            ctx,
            direction,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            ip_proto,
            payload_offset,
            capture_len,
            false,
        );

        DATA_EVENTS_PERF.output(ctx, unsafe { &*event }, 0);
    }

    Ok(TC_ACT_OK)
}

#[inline(always)]
fn populate_tc_event(
    event: *mut DataEvent,
    ctx: &TcContext,
    direction: Direction,
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    ip_proto: u8,
    payload_offset: usize,
    load_len: u32,
    capture_payload: bool,
) {
    unsafe {
        (*event).timestamp_ns = bpf_ktime_get_ns();
        // Use a deterministic bidirectional flow cookie for TC events.
        // Socket cookie differs between client/server sockets and breaks
        // request/response correlation in stream parsers.
        (*event).socket_cookie =
            tc_connection_cookie(src_addr, dst_addr, src_port, dst_port, ip_proto);
        (*event).event_type = EventType::TcPacket;
        (*event).direction = direction;
        (*event).pid = 0;
        (*event).tgid = 0;
        (*event).src_addr = src_addr;
        (*event).dst_addr = dst_addr;
        (*event).src_port = src_port;
        (*event).dst_port = dst_port;
        (*event).ip_proto = ip_proto;
        (*event).tls_library = TlsLibrary::None;
        (*event)._pad = [0; 3];

        if !capture_payload {
            (*event).payload_len = 0;
            return;
        }

        if load_len == 0 {
            (*event).payload_len = 0;
            return;
        }

        let copy_len = if load_len > TC_CAPTURE_COPY_MAX {
            TC_CAPTURE_COPY_MAX
        } else {
            load_len
        };
        (*event).payload_len = copy_len;

        let mut i: u32 = 0;
        while i < TC_CAPTURE_COPY_MAX {
            if i >= copy_len {
                break;
            }

            match ctx.load::<u8>(payload_offset + i as usize) {
                Ok(byte) => {
                    (*event).payload[i as usize] = byte;
                }
                Err(_) => {
                    (*event).payload_len = i;
                    break;
                }
            }
            i += 1;
        }
    }
}

#[inline(always)]
fn is_capture_enabled() -> bool {
    match CONFIG.get(CONFIG_CAPTURE_ENABLED) {
        Some(val) => *val != 0,
        None => true,
    }
}
