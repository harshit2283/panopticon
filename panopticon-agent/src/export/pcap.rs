//! Convert a PNCAP raw capture (`--capture-raw`) into a classic pcap file
//! that Wireshark and tshark open directly
//! (`panopticon-agent --decode-capture dump.pncap --pcap dump.pcap`).
//!
//! Events carry L7 payload only, so every packet gets synthesized IPv4 and
//! TCP (or UDP) headers from the event's addresses, ports and direction
//! (LINKTYPE_RAW). TCP sequence numbers run per flow and direction, advanced
//! by each event's original length: "Follow TCP stream" shows the payload in
//! order and a truncated capture shows up as missing bytes, not garbage.
//!
//! TLS plaintext from the uprobes appears as cleartext streams:
//! - packets of a connection whose plaintext was captured are dropped (they
//!   are its ciphertext), and when both ends of one connection run on the
//!   node only the server's view (the lower port's) is kept: the other is
//!   the same bytes again;
//! - a TLS connection whose socket addresses were never seen gets stand-in
//!   endpoints `127.0.0.1:<port> -> 127.0.0.2:443`, the port derived from the
//!   process and connection.
//!
//! Timestamps are the kernel's monotonic clock (time since boot), so
//! Wireshark shows dates in January 1970.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};

use anyhow::{Context, Result};
use panopticon_common::{DataEvent, Direction, EventType};

use crate::replay::CaptureReader;

const LINKTYPE_RAW: u32 = 101;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

type Endpoint = (u32, u16);
type Flow = (Endpoint, Endpoint);

/// `convert_file` writes the pcap owner-only: it holds decrypted payloads.
pub fn convert_file(input: &str, output: &str) -> Result<(u64, u64)> {
    use std::os::unix::fs::OpenOptionsExt;
    let open = || {
        std::fs::File::open(input)
            .map(io::BufReader::new)
            .with_context(|| format!("cannot open capture {input}"))
    };
    let out = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(output)
        .with_context(|| format!("cannot create {output}"))?;
    convert(open()?, open()?, io::BufWriter::new(out))
}

/// Read the capture twice (`first` to learn TLS connections' addresses,
/// `second` to write) and write pcap to `out`. Returns (packets written,
/// events skipped).
pub fn convert<R: Read, W: Write>(first: R, second: R, out: W) -> Result<(u64, u64)> {
    let mut plan = Plan::default();
    for_each_event(first, |e| plan.observe(e))?;
    let mut pcap = PcapWriter::new(out)?;
    let mut skipped = 0;
    for_each_event(second, |e| match plan.endpoints(e) {
        Some((src, dst)) => pcap.packet(e, src, dst),
        None => {
            skipped += 1;
            Ok(())
        }
    })?;
    pcap.out.flush()?;
    Ok((pcap.records, skipped))
}

fn for_each_event<R: Read>(
    input: R,
    mut f: impl FnMut(&DataEvent) -> io::Result<()>,
) -> Result<()> {
    let mut reader = CaptureReader::new(input).context("not a Panopticon capture (PNCAP)")?;
    loop {
        match reader.read_event() {
            Ok(Some(event)) => f(&event)?,
            Ok(None) => return Ok(()),
            // The agent stopped mid-record.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e).context("invalid capture record"),
        }
    }
}

fn unordered(a: Endpoint, b: Endpoint) -> Flow {
    if a <= b { (a, b) } else { (b, a) }
}

/// (local, remote) of a TLS event that carries addresses.
fn tls_local_remote(e: &DataEvent) -> Option<Flow> {
    if e.src_addr == 0 && e.dst_addr == 0 {
        return None;
    }
    let (src, dst) = ((e.src_addr, e.src_port), (e.dst_addr, e.dst_port));
    Some(match e.direction {
        Direction::Egress => (src, dst),
        Direction::Ingress => (dst, src),
    })
}

/// Addresses of one library connection object over time: allocators reuse
/// `SSL*` pointers, so one key can stand for several connections in turn.
#[derive(Default)]
struct TlsConn {
    /// (local, remote) of each successive connection, in capture order.
    addrs: VecDeque<Flow>,
    /// The second pass is inside the front connection (saw its addresses).
    inside: bool,
}

/// What the first pass learns about TLS connections.
#[derive(Default)]
struct Plan {
    /// (pid, library connection) -> its connections' addresses.
    tls: HashMap<(u32, u64), TlsConn>,
    /// Address pair -> (pid, its local port): the process whose plaintext
    /// view is written.
    tls_owner: HashMap<Flow, (u32, u16)>,
}

impl Plan {
    fn observe(&mut self, e: &DataEvent) -> io::Result<()> {
        if e.event_type == EventType::TlsData
            && let Some(lr) = tls_local_remote(e)
        {
            let conn = self.tls.entry((e.pid, e.socket_cookie)).or_default();
            if conn.addrs.back() != Some(&lr) {
                conn.addrs.push_back(lr);
            }
            // With both ends on the node, keep the server's view (the end
            // with the lower port): a client's first write on a reused
            // connection object can carry the previous connection's
            // addresses, a server's reads and writes cannot.
            let owner = self
                .tls_owner
                .entry(unordered(lr.0, lr.1))
                .or_insert((e.pid, lr.0.1));
            if owner.0 != e.pid && lr.0.1 < owner.1 {
                *owner = (e.pid, lr.0.1);
            }
        }
        Ok(())
    }

    /// (local, remote) for a TLS event. Addresses are only missing before a
    /// connection's first socket I/O, so an event without them after one
    /// with them starts the key's next connection.
    fn tls_endpoints(&mut self, e: &DataEvent) -> Flow {
        let conn = self.tls.entry((e.pid, e.socket_cookie)).or_default();
        match tls_local_remote(e) {
            Some(lr) => {
                while conn.addrs.len() > 1 && conn.addrs.front() != Some(&lr) {
                    conn.addrs.pop_front();
                }
                conn.inside = true;
                lr
            }
            None => {
                if conn.inside && conn.addrs.len() > 1 {
                    conn.addrs.pop_front();
                }
                conn.inside = false;
                conn.addrs.front().copied().unwrap_or_else(|| {
                    let h = fxhash::hash64(&(e.pid, e.socket_cookie));
                    (
                        (0x7F00_0001, 1024 + (h % 60_000) as u16),
                        (0x7F00_0002, 443),
                    )
                })
            }
        }
    }

    /// (sender, receiver) of the event's payload, or None to skip it.
    fn endpoints(&mut self, e: &DataEvent) -> Option<Flow> {
        if e.payload_len == 0 {
            return None;
        }
        match e.event_type {
            EventType::TcPacket => {
                let (src, dst) = ((e.src_addr, e.src_port), (e.dst_addr, e.dst_port));
                (!self.tls_owner.contains_key(&unordered(src, dst))).then_some((src, dst))
            }
            EventType::TlsData => {
                let (local, remote) = self.tls_endpoints(e);
                if self
                    .tls_owner
                    .get(&unordered(local, remote))
                    .is_some_and(|&(owner, _)| owner != e.pid)
                {
                    return None;
                }
                Some(match e.direction {
                    Direction::Egress => (local, remote),
                    Direction::Ingress => (remote, local),
                })
            }
            _ => None,
        }
    }
}

struct PcapWriter<W: Write> {
    out: W,
    /// Next TCP sequence number per (sender, receiver).
    next_seq: HashMap<Flow, u32>,
    ip_id: u16,
    records: u64,
}

impl<W: Write> PcapWriter<W> {
    fn new(mut out: W) -> io::Result<Self> {
        out.write_all(&0xa1b2_c3d4u32.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?;
        out.write_all(&4u16.to_le_bytes())?;
        out.write_all(&0i32.to_le_bytes())?; // thiszone
        out.write_all(&0u32.to_le_bytes())?; // sigfigs
        out.write_all(&65_535u32.to_le_bytes())?; // snaplen
        out.write_all(&LINKTYPE_RAW.to_le_bytes())?;
        Ok(Self {
            out,
            next_seq: HashMap::new(),
            ip_id: 0,
            records: 0,
        })
    }

    fn packet(&mut self, e: &DataEvent, src: Endpoint, dst: Endpoint) -> io::Result<()> {
        let payload = e.payload_bytes();
        let orig_payload = (e.orig_len as usize).max(payload.len());
        let udp = e.event_type == EventType::TcPacket && e.ip_proto == IPPROTO_UDP;
        let l4_len = if udp { 8 } else { 20 };

        let mut pkt = Vec::with_capacity(20 + l4_len + payload.len());
        let total = (20 + l4_len + payload.len()) as u16;
        self.ip_id = self.ip_id.wrapping_add(1);
        pkt.extend_from_slice(&[0x45, 0]);
        pkt.extend_from_slice(&total.to_be_bytes());
        pkt.extend_from_slice(&self.ip_id.to_be_bytes());
        pkt.extend_from_slice(&[0x40, 0, 64, if udp { IPPROTO_UDP } else { IPPROTO_TCP }]);
        pkt.extend_from_slice(&[0, 0]); // header checksum, below
        pkt.extend_from_slice(&src.0.to_be_bytes());
        pkt.extend_from_slice(&dst.0.to_be_bytes());
        let ip_sum = checksum(&pkt[..20], 0);
        pkt[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        pkt.extend_from_slice(&src.1.to_be_bytes());
        pkt.extend_from_slice(&dst.1.to_be_bytes());
        if udp {
            pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            pkt.extend_from_slice(&[0, 0]); // optional for IPv4
            pkt.extend_from_slice(payload);
        } else {
            let seq = *self.next_seq.get(&(src, dst)).unwrap_or(&1);
            let ack = *self.next_seq.get(&(dst, src)).unwrap_or(&1);
            self.next_seq
                .insert((src, dst), seq.wrapping_add(orig_payload as u32));
            pkt.extend_from_slice(&seq.to_be_bytes());
            pkt.extend_from_slice(&ack.to_be_bytes());
            pkt.extend_from_slice(&[0x50, 0x18]); // 20-byte header; PSH|ACK
            pkt.extend_from_slice(&65_535u16.to_be_bytes()); // window
            pkt.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
            pkt.extend_from_slice(payload);
            // Pseudo-header: addresses, protocol, TCP length.
            let mut pseudo = [0u8; 12];
            pseudo[..4].copy_from_slice(&src.0.to_be_bytes());
            pseudo[4..8].copy_from_slice(&dst.0.to_be_bytes());
            pseudo[9] = IPPROTO_TCP;
            pseudo[10..].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
            let tcp_sum = checksum(&pkt[20..], sum16(&pseudo));
            pkt[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
        }

        let ts = e.timestamp_ns;
        self.out
            .write_all(&((ts / 1_000_000_000) as u32).to_le_bytes())?;
        self.out
            .write_all(&((ts % 1_000_000_000 / 1000) as u32).to_le_bytes())?;
        self.out.write_all(&(pkt.len() as u32).to_le_bytes())?;
        self.out
            .write_all(&((20 + l4_len + orig_payload) as u32).to_le_bytes())?;
        self.out.write_all(&pkt)?;
        self.records += 1;
        Ok(())
    }
}

/// One's-complement sum of big-endian 16-bit words (odd byte padded).
fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}

/// Internet checksum of `data`, starting from a partial sum.
fn checksum(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial + sum16(data);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replay::CaptureWriter;

    fn event(
        kind: EventType,
        dir: Direction,
        src: Endpoint,
        dst: Endpoint,
        data: &[u8],
    ) -> DataEvent {
        // SAFETY: all-zero is valid for DataEvent (every enum has a 0 variant).
        let mut e: DataEvent = unsafe { std::mem::zeroed() };
        e.event_type = kind;
        e.direction = dir;
        e.pid = 42;
        e.socket_cookie = 7;
        (e.src_addr, e.src_port, e.dst_addr, e.dst_port) = (src.0, src.1, dst.0, dst.1);
        e.ip_proto = IPPROTO_TCP;
        e.payload[..data.len()].copy_from_slice(data);
        e.payload_len = data.len() as u32;
        e.orig_len = data.len() as u32;
        e.timestamp_ns = 1_500_000_000;
        e
    }

    struct Record {
        orig_len: u32,
        pkt: Vec<u8>,
    }

    fn convert_events(events: &[DataEvent]) -> (Vec<u8>, Vec<Record>) {
        let mut w = CaptureWriter::new(Vec::new(), 0).unwrap();
        for e in events {
            w.write_event(e).unwrap();
        }
        let capture = w.into_bytes().unwrap();
        let mut out = Vec::new();
        convert(&capture[..], &capture[..], &mut out).unwrap();
        let (header, mut rest) = out.split_at(24);
        let mut records = Vec::new();
        while !rest.is_empty() {
            let u32_at = |i: usize| u32::from_le_bytes(rest[i..i + 4].try_into().unwrap());
            let (incl, orig) = (u32_at(8) as usize, u32_at(12));
            records.push(Record {
                orig_len: orig,
                pkt: rest[16..16 + incl].to_vec(),
            });
            rest = &rest[16 + incl..];
        }
        (header.to_vec(), records)
    }

    fn seq(pkt: &[u8]) -> u32 {
        u32::from_be_bytes(pkt[24..28].try_into().unwrap())
    }

    const CLIENT: Endpoint = (0x0A00_0002, 40_000);
    const SERVER: Endpoint = (0x0A00_0001, 80);

    #[test]
    fn writes_tcp_flows_with_running_sequence_numbers() {
        let req = b"GET /a HTTP/1.1\r\n\r\n";
        let resp = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
        let mut truncated = event(
            EventType::TcPacket,
            Direction::Egress,
            CLIENT,
            SERVER,
            b"POST",
        );
        truncated.orig_len = 100; // only 4 of 100 bytes captured
        let (header, recs) = convert_events(&[
            event(EventType::TcPacket, Direction::Ingress, CLIENT, SERVER, req),
            event(EventType::TcPacket, Direction::Egress, SERVER, CLIENT, resp),
            event(
                EventType::SockConnect,
                Direction::Egress,
                CLIENT,
                SERVER,
                b"",
            ),
            truncated,
            event(
                EventType::TcPacket,
                Direction::Ingress,
                CLIENT,
                SERVER,
                b"next",
            ),
        ]);
        assert_eq!(&header[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(
            u32::from_le_bytes(header[20..24].try_into().unwrap()),
            LINKTYPE_RAW
        );
        assert_eq!(recs.len(), 4, "the payload-less event is skipped");

        let first = &recs[0].pkt;
        assert_eq!(first[0], 0x45);
        assert_eq!(
            u16::from_be_bytes([first[2], first[3]]) as usize,
            first.len()
        );
        assert_eq!(first[9], IPPROTO_TCP);
        assert_eq!(&first[12..16], &[10, 0, 0, 2]);
        assert_eq!(&first[16..20], &[10, 0, 0, 1]);
        assert_eq!(u16::from_be_bytes([first[20], first[21]]), 40_000);
        assert_eq!(u16::from_be_bytes([first[22], first[23]]), 80);
        assert_eq!(&first[40..], req);
        assert_eq!(checksum(&first[..20], 0), 0, "valid IP header checksum");

        // Each direction counts its own bytes; ack is the other side's next.
        assert_eq!(seq(&recs[0].pkt), 1);
        assert_eq!(seq(&recs[1].pkt), 1);
        assert_eq!(
            u32::from_be_bytes(recs[1].pkt[28..32].try_into().unwrap()),
            1 + req.len() as u32
        );
        assert_eq!(seq(&recs[2].pkt), 1 + req.len() as u32);
        // The truncated segment advances by its original length.
        assert_eq!(recs[2].orig_len, 40 + 100);
        assert_eq!(seq(&recs[3].pkt), 1 + req.len() as u32 + 100);
    }

    #[test]
    fn reused_tls_connection_object_gets_each_connections_addresses() {
        let other_client: Endpoint = (0x0A00_0002, 40_001);
        let tls = |dir, src, dst, data: &[u8]| event(EventType::TlsData, dir, src, dst, data);
        let (_, recs) = convert_events(&[
            tls(Direction::Egress, (0, 0), (0, 0), b"one"),
            tls(Direction::Ingress, SERVER, CLIENT, b"r1"),
            // Same SSL* pointer, next connection: first write before socket I/O.
            tls(Direction::Egress, (0, 0), (0, 0), b"two"),
            tls(Direction::Ingress, SERVER, other_client, b"r2"),
        ]);
        let src_port = |r: &Record| u16::from_be_bytes([r.pkt[20], r.pkt[21]]);
        assert_eq!(src_port(&recs[0]), 40_000);
        assert_eq!(src_port(&recs[2]), 40_001);
        assert_eq!(
            seq(&recs[2].pkt),
            1,
            "a new connection starts its own sequence"
        );
    }

    #[test]
    fn tls_plaintext_replaces_ciphertext_and_keeps_one_view() {
        let mut udp = event(
            EventType::TcPacket,
            Direction::Egress,
            CLIENT,
            (0x0A00_0003, 53),
            b"dns",
        );
        udp.ip_proto = IPPROTO_UDP;
        let cipher = event(
            EventType::TcPacket,
            Direction::Ingress,
            CLIENT,
            SERVER,
            b"\x17\x03\x03",
        );
        let tls = |pid, conn, dir, src, dst, data: &[u8]| {
            let mut e = event(EventType::TlsData, dir, src, dst, data);
            (e.pid, e.socket_cookie) = (pid, conn);
            e
        };
        // Client process 10: wrote the request (addresses not yet known),
        // read the response.
        let first_write = tls(10, 1, Direction::Egress, (0, 0), (0, 0), b"GET /");
        let read = tls(10, 1, Direction::Ingress, SERVER, CLIENT, b"HTTP/1.1 200");
        // Server process 20: the same exchange from the other end.
        let server_read = tls(20, 2, Direction::Ingress, CLIENT, SERVER, b"GET /");
        let server_write = tls(20, 2, Direction::Egress, SERVER, CLIENT, b"HTTP/1.1 200");
        // A client-only connection (its server is elsewhere).
        let remote: Endpoint = (0x0A00_0009, 443);
        let lone_write = tls(10, 3, Direction::Egress, (0, 0), (0, 0), b"POST /x");
        let lone_read = tls(10, 3, Direction::Ingress, remote, CLIENT, b"HTTP/1.1 201");

        let (_, recs) = convert_events(&[
            udp,
            cipher,
            first_write,
            read,
            server_read,
            server_write,
            lone_write,
            lone_read,
        ]);
        assert_eq!(
            recs.len(),
            5,
            "ciphertext and the client's duplicate view dropped"
        );
        assert_eq!(recs[0].pkt[9], IPPROTO_UDP);
        assert_eq!(&recs[0].pkt[28..], b"dns");
        // The server's view, oriented client -> server for the request.
        assert_eq!(&recs[1].pkt[12..16], &[10, 0, 0, 2]);
        assert_eq!(&recs[1].pkt[40..], b"GET /");
        assert_eq!(&recs[2].pkt[12..16], &[10, 0, 0, 1]);
        assert_eq!(&recs[2].pkt[40..], b"HTTP/1.1 200");
        // The early write uses the addresses learned later: client -> remote.
        let w = &recs[3].pkt;
        assert_eq!(&w[12..16], &[10, 0, 0, 2]);
        assert_eq!(&w[16..20], &[10, 0, 0, 9]);
        assert_eq!(u16::from_be_bytes([w[22], w[23]]), 443);
        assert_eq!(&w[40..], b"POST /x");
    }
}
