#![allow(dead_code)]

//! FSM infrastructure for protocol parsers.
//!
//! Provides:
//! - `StreamBuffer` for per-direction reassembly
//! - `FsmResult` for FSM state transition results
//! - `ProtocolFsm` trait for FSM-based protocol parsing
//! - `ConnectionFsmManager` for concurrent FSM instance management

use std::time::Instant;

use bytes::BytesMut;
use dashmap::DashMap;

use super::{Direction, L7Message, ParseResult, Protocol, ProtocolParser, create_parser};

const DEFAULT_MAX_SIZE: usize = 256 * 1024;
const DEFAULT_MAX_CONNECTIONS: usize = 100_000;

/// Reassembly buffer backed by `BytesMut` for O(1) `consume()`.
/// `Vec<u8>::drain(..n)` is O(n) because it shifts remaining bytes.
/// `BytesMut::advance(n)` just moves an internal pointer.
pub struct StreamBuffer {
    buf: BytesMut,
    max_size: usize,
}

impl StreamBuffer {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max_size,
        }
    }

    pub fn extend(&mut self, data: &[u8]) -> Result<(), ()> {
        if self.buf.len() + data.len() > self.max_size {
            return Err(());
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    pub fn data(&self) -> &[u8] {
        &self.buf
    }

    pub fn consume(&mut self, n: usize) {
        assert!(
            n <= self.buf.len(),
            "consume({n}) exceeds buffer length {}",
            self.buf.len()
        );
        let _ = self.buf.split_to(n);
    }

    pub fn clear(&mut self) {
        self.buf.clear();
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Default for StreamBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Result from `ConnectionFsmManager::get_or_create()` indicating what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateResult {
    /// A new connection entry was created.
    Created,
    /// The connection already existed; its timestamp was refreshed.
    AlreadyExists,
    /// A new entry was created after evicting this many of the least
    /// recently seen connections to stay within capacity.
    CreatedWithEviction(usize),
}

/// Fraction of the table evicted at once when it is full (1/N).
const EVICTION_BATCH_DIVISOR: usize = 16;

#[derive(Debug)]
pub enum FsmResult {
    WaitingForMore,
    MessageComplete(L7Message),
    Messages(Vec<L7Message>),
    Error(String),
    ConnectionClosed,
}

pub trait ProtocolFsm: Send {
    fn process_packet(&mut self, direction: Direction, data: &[u8], timestamp_ns: u64)
    -> FsmResult;

    fn current_state(&self) -> &'static str;

    fn protocol(&self) -> Protocol;

    fn protocol_version(&self) -> Option<&str> {
        None
    }

    fn reset_for_next_transaction(&mut self);

    /// See [`ProtocolParser::skip`]. `None` = cannot resync.
    fn skip(&mut self, _direction: Direction, _n: usize, _timestamp_ns: u64) -> Option<FsmResult> {
        None
    }

    /// See [`ProtocolParser::joined_late`].
    fn joined_late(&mut self) {}

    /// See [`ProtocolParser::uncertain`].
    fn uncertain(&self) -> bool {
        false
    }
}

pub struct ProtocolFsmAdapter {
    parser: Box<dyn ProtocolParser>,
}

impl ProtocolFsmAdapter {
    pub fn new(protocol: Protocol, topics: &super::kafka::KafkaTopics) -> Self {
        Self {
            parser: create_parser(protocol, topics),
        }
    }
}

impl ProtocolFsm for ProtocolFsmAdapter {
    fn process_packet(
        &mut self,
        direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> FsmResult {
        match self.parser.feed(data, direction, timestamp_ns) {
            ParseResult::NeedMoreData => FsmResult::WaitingForMore,
            ParseResult::Messages(msgs) => {
                if msgs.len() == 1 {
                    FsmResult::MessageComplete(msgs.into_iter().next().unwrap())
                } else {
                    FsmResult::Messages(msgs)
                }
            }
            ParseResult::Error(e) => FsmResult::Error(e),
        }
    }

    fn current_state(&self) -> &'static str {
        self.parser.state_name()
    }

    fn protocol(&self) -> Protocol {
        self.parser.protocol()
    }

    fn protocol_version(&self) -> Option<&str> {
        self.parser.protocol_version()
    }

    fn reset_for_next_transaction(&mut self) {}

    fn skip(&mut self, direction: Direction, n: usize, timestamp_ns: u64) -> Option<FsmResult> {
        self.parser
            .skip(direction, n, timestamp_ns)
            .map(|r| match r {
                ParseResult::NeedMoreData => FsmResult::WaitingForMore,
                ParseResult::Messages(msgs) => FsmResult::Messages(msgs),
                ParseResult::Error(e) => FsmResult::Error(e),
            })
    }

    fn joined_late(&mut self) {
        self.parser.joined_late();
    }

    fn uncertain(&self) -> bool {
        self.parser.uncertain()
    }
}

/// An `(IPv4 address, port)` pair as carried in `DataEvent`.
pub type Endpoint = (u32, u16);

/// How far a TCP segment's sequence number may run ahead of the next
/// expected byte (bytes the agent missed: ring buffer drops) and its
/// acknowledgment number may differ from the other side's stream, and the
/// segment still be taken as genuine: about the largest receive window Linux
/// opens by default (`tcp_rmem`). A blind (off-path) forger has to land both
/// numbers in range, like RFC 5961 asks of a receiver: about 1 in 2^17 per
/// guess. A segment further ahead is still accepted once the receiver has
/// acknowledged up to it.
const TCP_WINDOW: u32 = 8 << 20;

/// The sequence-relevant fields of one captured TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub seq: u32,
    /// The acknowledgment number, if the ACK flag is set.
    pub ack: Option<u32>,
    /// Payload length on the wire (`orig_len`, not the captured bytes).
    pub len: u32,
    pub syn: bool,
    pub fin: bool,
    pub rst: bool,
}

/// What to do with a captured TCP segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentVerdict {
    /// Process it: first account for `gap` bytes that were never captured,
    /// then the payload from byte `trim` on (the bytes before `trim` were
    /// already processed). Its FIN / RST are genuine.
    Accept { gap: u32, trim: u32 },
    /// A retransmission of bytes already processed, or outside the window:
    /// ignore its payload and its flags.
    Drop,
}

/// Per-direction TCP sequence tracking for one connection. TC sees every
/// segment that matches the 5-tuple: retransmissions (parsed twice, they
/// corrupted the stream: AMQP recall fell to 88-97% on RHEL 8), and forged
/// segments or RSTs the receiver would reject. Only bytes at the next
/// expected sequence number reach the parser, once each; a FIN counts only
/// in window and an RST only at the next expected byte (RFC 5961).
#[derive(Debug, Default)]
struct TcpTracker {
    /// Next expected sequence number from the client (0) / server (1).
    next: [Option<u32>; 2],
    /// Highest acknowledgment the other side sent for each side's data:
    /// bytes it confirms exist, even if the agent never saw them.
    acked: [Option<u32>; 2],
}

/// `a - b` in sequence space (RFC 1982 serial arithmetic, so wraparound
/// at 2^32 is handled): positive when `a` is after `b`.
fn seq_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

impl TcpTracker {
    fn admit(&mut self, side: usize, seg: TcpSegment) -> SegmentVerdict {
        // SYN takes one sequence number before the data, FIN one after.
        let data_seq = seg.seq.wrapping_add(seg.syn as u32);
        let span = seg.len + seg.fin as u32;
        let end = data_seq.wrapping_add(span);
        // Before any byte of this side was seen, what the peer acknowledged
        // is where its data must start.
        let expected = self.next[side].or(self.acked[side]);
        // The acknowledgment must be about where the other side's stream
        // is: it may lag by data in flight, or lead by data the agent
        // missed. Further ahead only on a segment exactly at the next byte
        // (after a long loss), which a blind forger cannot hit.
        let ack_ok = match (seg.ack, self.next[1 - side]) {
            (Some(ack), Some(other)) => {
                let d = seq_diff(ack, other);
                d.unsigned_abs() < TCP_WINDOW || (d > 0 && expected == Some(data_seq))
            }
            _ => true,
        };
        let verdict = match expected {
            _ if !ack_ok => SegmentVerdict::Drop,
            None => SegmentVerdict::Accept { gap: 0, trim: 0 },
            Some(next) => {
                let off = seq_diff(data_seq, next);
                let acked_past = self.acked[side].is_some_and(|a| seq_diff(a, data_seq) >= 0);
                let ahead_ok = if seg.rst {
                    off == 0 || acked_past
                } else {
                    (off as u32) < TCP_WINDOW || acked_past
                };
                if off < 0 {
                    let behind = off.unsigned_abs();
                    if behind >= span {
                        SegmentVerdict::Drop // already seen
                    } else {
                        SegmentVerdict::Accept {
                            gap: 0,
                            trim: behind,
                        }
                    }
                } else if ahead_ok {
                    SegmentVerdict::Accept {
                        gap: off as u32,
                        trim: 0,
                    }
                } else {
                    SegmentVerdict::Drop // out of window: forged or stale
                }
            }
        };
        if verdict != SegmentVerdict::Drop {
            let next = self.next[side].unwrap_or(end);
            self.next[side] = Some(if seq_diff(end, next) > 0 { end } else { next });
            if let Some(ack) = seg.ack {
                let acked = &mut self.acked[1 - side];
                if acked.is_none_or(|a| seq_diff(ack, a) > 0) {
                    *acked = Some(ack);
                }
            }
        }
        verdict
    }
}

/// Where each side's stream starts (the sequence number of its first byte),
/// learnt from SYNs before the connection's parser exists.
#[derive(Debug, Clone, Copy)]
struct Origin {
    client: Option<(Endpoint, u32)>,
    server: Option<(Endpoint, u32)>,
    at: Instant,
}

/// Unified entry combining the FSM instance and last-seen timestamp.
struct ConnectionEntry {
    fsm: Box<dyn ProtocolFsm>,
    last_seen: Instant,
    /// The server side of the connection, when known. Used to turn capture
    /// direction (TC ingress/egress, which depends on which node the agent
    /// runs on) into the client→server / server→client direction parsers
    /// expect.
    server: Option<Endpoint>,
    /// FIN seen from the client / from the server.
    fin: [bool; 2],
    tcp: TcpTracker,
    /// Payload was fed to a parser of this entry.
    fed: bool,
    /// Bytes of the connection were lost, its start was proved missing (an
    /// unplaced TCP side, a gap the parser could not account for), or its
    /// parser latched (`ProtocolFsm::uncertain`: a preface that did not
    /// prove a connection start, an HPACK failure). Lives as long as the
    /// entry: a replacement parser is latched again (`joined_late`), and
    /// only a new entry starts without it.
    lost: bool,
    /// TLS: the cookie of the TCP socket under the connection object
    /// (`DataEvent::tls_sock_cookie`), once one was seen; 0 if unknown.
    sock: u64,
}

impl ConnectionEntry {
    /// Client→server is `Egress`, server→client is `Ingress`, regardless of
    /// which TC hook saw the packet (falls back to that when the server
    /// endpoint is unknown).
    fn direction_of(&self, src: Endpoint, capture_direction: Direction) -> Direction {
        match self.server {
            Some(server) if src == server => Direction::Ingress,
            Some(_) => Direction::Egress,
            None => capture_direction,
        }
    }
}

pub struct ConnectionFsmManager {
    connections: DashMap<u64, ConnectionEntry>,
    /// Stream origins of connections whose first payload has not arrived.
    origins: DashMap<u64, Origin>,
    max_connections: usize,
    /// The pipeline's Kafka topic ID map, given to every Kafka parser.
    topics: super::kafka::KafkaTopics,
}

impl ConnectionFsmManager {
    /// A manager with its own Kafka topic map (tests, standalone use).
    pub fn new(max_connections: usize) -> Self {
        Self::with_topics(max_connections, Default::default())
    }

    /// A manager whose Kafka parsers share `topics`, their pipeline's map.
    pub fn with_topics(max_connections: usize, topics: super::kafka::KafkaTopics) -> Self {
        Self {
            connections: DashMap::new(),
            origins: DashMap::new(),
            max_connections,
            topics,
        }
    }

    pub fn get_or_create(&self, conn_id: u64, protocol: Protocol) -> CreateResult {
        self.get_or_create_with_server(conn_id, protocol, None)
    }

    /// Like [`get_or_create`](Self::get_or_create), pinning the connection's
    /// server endpoint for [`process_packet_from`](Self::process_packet_from).
    pub fn get_or_create_with_server(
        &self,
        conn_id: u64,
        protocol: Protocol,
        server: Option<Endpoint>,
    ) -> CreateResult {
        if let Some(mut entry) = self.connections.get_mut(&conn_id) {
            entry.last_seen = Instant::now();
            return CreateResult::AlreadyExists;
        }

        let mut evicted = 0;

        // Log capacity warnings at threshold levels
        let current_len = self.connections.len();
        let threshold_80 = self.max_connections * 80 / 100;
        let threshold_95 = self.max_connections * 95 / 100;
        if current_len >= threshold_95 {
            tracing::warn!(
                current = current_len,
                max = self.max_connections,
                "Connection tracking at 95% capacity — evicting aggressively"
            );
        } else if current_len >= threshold_80 {
            tracing::warn!(
                current = current_len,
                max = self.max_connections,
                "Connection tracking at 80% capacity"
            );
        }

        if self.connections.len() >= self.max_connections {
            evicted = self.evict_oldest_batch();
        }

        let fsm: Box<dyn ProtocolFsm> = Box::new(ProtocolFsmAdapter::new(protocol, &self.topics));
        let mut entry = ConnectionEntry {
            fsm,
            last_seen: Instant::now(),
            server,
            fin: [false; 2],
            tcp: TcpTracker::default(),
            fed: false,
            lost: false,
            sock: 0,
        };
        if let Some((_, origin)) = self.origins.remove(&conn_id) {
            // The SYN+ACK's sender is the server, whatever the payload said.
            if let Some((ep, _)) = origin.server {
                entry.server = Some(ep);
            }
            if let Some(server) = entry.server {
                for (ep, seq) in [origin.client, origin.server].into_iter().flatten() {
                    entry.tcp.next[(ep == server) as usize] = Some(seq);
                }
            }
        }
        self.connections.insert(conn_id, entry);

        if evicted > 0 {
            CreateResult::CreatedWithEviction(evicted)
        } else {
            CreateResult::Created
        }
    }

    /// Evict the least recently seen 1/EVICTION_BATCH_DIVISOR of the table.
    ///
    /// Finding the oldest entry takes a scan of the whole table; doing that
    /// for every new connection once full cost ~2.5ms per connection at the
    /// default 65,536 entries (a table full of idle UDP flows, e.g. DNS,
    /// capped a worker at ~400 new connections/s). One scan per batch keeps
    /// the cost amortized O(EVICTION_BATCH_DIVISOR) per insert.
    fn evict_oldest_batch(&self) -> usize {
        let target = (self.max_connections / EVICTION_BATCH_DIVISOR).max(1);
        let mut ages: Vec<(Instant, u64)> = self
            .connections
            .iter()
            .map(|e| (e.value().last_seen, *e.key()))
            .collect();
        if ages.len() > target {
            ages.select_nth_unstable_by_key(target - 1, |a| a.0);
            ages.truncate(target);
        }
        ages.iter()
            .filter(|(_, id)| self.connections.remove(id).is_some())
            .count()
    }

    /// Feed a packet in `direction`, used as given.
    pub fn process_packet(
        &self,
        conn_id: u64,
        direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> Option<FsmResult> {
        let mut entry = self.connections.get_mut(&conn_id)?;
        Some(self.feed(&mut entry, direction, data, timestamp_ns))
    }

    /// Feed a packet sent by `src`. If the connection's server endpoint is
    /// known, direction is derived from it (from server ⇒ `Ingress`,
    /// otherwise `Egress`); else `capture_direction` is used as-is.
    pub fn process_packet_from(
        &self,
        conn_id: u64,
        src: Endpoint,
        capture_direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> Option<FsmResult> {
        let mut entry = self.connections.get_mut(&conn_id)?;
        let direction = entry.direction_of(src, capture_direction);
        Some(self.feed(&mut entry, direction, data, timestamp_ns))
    }

    fn feed(
        &self,
        entry: &mut ConnectionEntry,
        direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> FsmResult {
        entry.last_seen = Instant::now();
        // A client preface means a new HTTP/2 connection may have started;
        // its frames and HPACK state must not be read as a continuation of
        // the old one, so the parser is replaced. The replacement starts
        // clean only as the entry's first payload with no loss recorded:
        // anywhere else the preface bytes can be the inside of a DATA
        // payload, so it is latched. A new connection reusing a TLS key is
        // told apart by its socket (`note_socket`), never by its bytes.
        let h2 = matches!(entry.fsm.protocol(), Protocol::Http2 | Protocol::Grpc);
        let preface = h2 && data.starts_with(super::detect::HTTP2_PREFACE);
        let first = !entry.fed && !entry.lost;
        if preface && (first || direction == Direction::Egress) {
            let protocol = entry.fsm.protocol();
            entry.fsm = Box::new(ProtocolFsmAdapter::new(protocol, &self.topics));
            entry.fin = [false; 2];
            if !first {
                entry.fsm.joined_late();
            }
        }
        entry.fed = true;
        let result = entry.fsm.process_packet(direction, data, timestamp_ns);
        entry.lost |= entry.fsm.uncertain();
        result
    }

    /// TLS: the connection object under `conn_id` did I/O on the TCP socket
    /// with cookie `sock` (0: unknown). A known socket other than the one
    /// recorded is a new connection reusing the object's address: its
    /// entry is dropped (true), so the next payload creates a new one with
    /// no latches. 0 never drops an entry or replaces a recorded socket.
    pub fn note_socket(&self, conn_id: u64, sock: u64) -> bool {
        let Some(mut entry) = self.connections.get_mut(&conn_id) else {
            return false;
        };
        if sock == 0 || entry.sock == sock {
            return false;
        }
        if entry.sock == 0 {
            entry.sock = sock;
            return false;
        }
        drop(entry);
        self.close_connection(conn_id)
    }

    /// Check a TCP segment sent by `src` against the connection's sequence
    /// state (see [`TcpTracker`]). `None` if the connection is not tracked.
    pub fn admit_segment(
        &self,
        conn_id: u64,
        src: Endpoint,
        capture_direction: Direction,
        seg: TcpSegment,
    ) -> Option<SegmentVerdict> {
        let mut entry = self.connections.get_mut(&conn_id)?;
        let side = match entry.direction_of(src, capture_direction) {
            Direction::Egress => 0,
            Direction::Ingress => 1,
        };
        // No origin for this side: its first byte was never located, so
        // the parser starts somewhere inside the stream.
        let unplaced = entry.tcp.next[side].is_none();
        let verdict = entry.tcp.admit(side, seg);
        if unplaced && verdict != SegmentVerdict::Drop {
            entry.lost = true;
            entry.fsm.joined_late();
        }
        Some(verdict)
    }

    /// A SYN sent by `src` (`ack`: a SYN+ACK, from the server): that side's
    /// stream starts at `seq + 1`. A bare SYN for a tracked connection that
    /// sent a FIN starts a new connection on its key: the old one is closed
    /// (true). Without a FIN it is ignored: one forged SYN must not reset a
    /// live connection's state.
    pub fn note_syn(&self, conn_id: u64, src: Endpoint, ack: bool, seq: u32) -> bool {
        let reused = !ack
            && self
                .connections
                .get(&conn_id)
                .is_some_and(|e| e.fin[0] || e.fin[1]);
        let closed = reused && self.close_connection(conn_id);
        if self.connections.contains_key(&conn_id) {
            return closed; // a late SYN+ACK: the parser already started
        }
        let start = Some((src, seq.wrapping_add(1)));
        if let Some(mut o) = self.origins.get_mut(&conn_id) {
            if ack {
                o.server = start;
            } else {
                o.client = start;
            }
            o.at = Instant::now();
        } else if self.origins.len() < self.max_connections {
            // ponytail: a full table leaves later connections unproven (no
            // Redis reply text) until evict_idle; evict the oldest if it bites.
            let (client, server) = if ack { (None, start) } else { (start, None) };
            self.origins.insert(
                conn_id,
                Origin {
                    client,
                    server,
                    at: Instant::now(),
                },
            );
        }
        closed
    }

    /// `src`'s stream starts at sequence number `origin` (from the kernel's
    /// stream offset). Takes effect only before that side's first byte.
    pub fn note_origin(
        &self,
        conn_id: u64,
        src: Endpoint,
        capture_direction: Direction,
        origin: u32,
    ) {
        if let Some(mut entry) = self.connections.get_mut(&conn_id) {
            let side = match entry.direction_of(src, capture_direction) {
                Direction::Egress => 0,
                Direction::Ingress => 1,
            };
            if entry.tcp.next[side].is_none() {
                entry.tcp.next[side] = Some(origin);
            }
        }
    }

    /// The connection's parser did not see its stream from the start (see
    /// [`ProtocolFsm::joined_late`]).
    pub fn mark_joined_late(&self, conn_id: u64) {
        if let Some(mut entry) = self.connections.get_mut(&conn_id) {
            entry.fsm.joined_late();
        }
    }

    /// `n` bytes sent by `src` were not captured. Lets the parser account for
    /// them; if it cannot resync, the connection's parser is replaced with a
    /// fresh one so the gap costs one exchange instead of the whole
    /// connection. Returns any messages completed by the skip.
    pub fn skip_from(
        &self,
        conn_id: u64,
        src: Endpoint,
        capture_direction: Direction,
        n: usize,
        timestamp_ns: u64,
    ) -> Option<FsmResult> {
        let mut entry = self.connections.get_mut(&conn_id)?;
        let direction = entry.direction_of(src, capture_direction);
        let result = entry.fsm.skip(direction, n, timestamp_ns);
        if result.is_none() {
            let protocol = entry.fsm.protocol();
            entry.fsm = Box::new(ProtocolFsmAdapter::new(protocol, &self.topics));
        }
        // Bytes were lost: whatever the parser does next starts mid-stream.
        // The exception: an HTTP/2 parser that accounted for the gap inside
        // a DATA frame (its HPACK state and framing are intact).
        let h2 = matches!(entry.fsm.protocol(), Protocol::Http2 | Protocol::Grpc);
        if result.is_none() || !h2 {
            entry.lost = true;
            entry.fsm.joined_late();
        }
        entry.lost |= entry.fsm.uncertain();
        result
    }

    /// Record a FIN sent by `src`. Returns true once both sides have sent
    /// one, i.e. the connection is finished and can be closed.
    pub fn note_fin(&self, conn_id: u64, src: Endpoint, capture_direction: Direction) -> bool {
        let Some(mut entry) = self.connections.get_mut(&conn_id) else {
            // Closing before any payload: its origin is not needed.
            self.origins.remove(&conn_id);
            return false;
        };
        let side = match entry.direction_of(src, capture_direction) {
            Direction::Egress => 0,
            Direction::Ingress => 1,
        };
        entry.fin[side] = true;
        entry.fin == [true; 2]
    }

    /// The connection's server endpoint, if it was determined at creation.
    pub fn server_of(&self, conn_id: u64) -> Option<Endpoint> {
        self.connections.get(&conn_id)?.server
    }

    /// Close a connection and return whether it existed.
    pub fn close_connection(&self, conn_id: u64) -> bool {
        self.origins.remove(&conn_id);
        self.connections.remove(&conn_id).is_some()
    }

    pub fn connection_state(&self, conn_id: u64) -> Option<&'static str> {
        self.connections
            .get(&conn_id)
            .map(|entry| entry.fsm.current_state())
    }

    pub fn evict_idle(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let expired: Vec<u64> = self
            .connections
            .iter()
            .filter(|entry| now.duration_since(entry.value().last_seen) > ttl)
            .map(|entry| *entry.key())
            .collect();

        let count = expired.len();
        for conn_id in expired {
            self.connections.remove(&conn_id);
        }
        self.origins.retain(|_, o| now.duration_since(o.at) <= ttl);
        count
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    pub fn contains(&self, conn_id: u64) -> bool {
        self.connections.contains_key(&conn_id)
    }
}

impl Default for ConnectionFsmManager {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONNECTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reused_connection_key_restarts_http2_parsing() {
        fn frame(t: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
            let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
            f.push(t);
            f.push(flags);
            f.extend(stream.to_be_bytes());
            f.extend_from_slice(payload);
            f
        }
        let preface = |enc: &mut hpack::Encoder<'static>, path: &str| {
            let mut d = super::super::detect::HTTP2_PREFACE.to_vec();
            d.extend(frame(0x4, 0, 0, &[])); // SETTINGS
            let h = enc.encode(
                [(":method", "GET"), (":path", path), (":scheme", "https")]
                    .iter()
                    .map(|(k, v)| (k.as_bytes(), v.as_bytes())),
            );
            d.extend(frame(0x1, 0x4 | 0x1, 1, &h)); // HEADERS END_HEADERS|END_STREAM
            d
        };
        let response = |enc: &mut hpack::Encoder<'static>| {
            let h = enc.encode([(b":status".as_slice(), b"200".as_slice())]);
            frame(0x1, 0x4 | 0x1, 1, &h)
        };
        let paths = |r: Option<FsmResult>| match r {
            Some(FsmResult::Messages(m)) => m.into_iter().map(|m| m.path).collect::<Vec<_>>(),
            Some(FsmResult::MessageComplete(m)) => vec![m.path],
            _ => vec![],
        };
        let m = ConnectionFsmManager::new(16);
        let (client, server) = ((0, 1), (0, 2));
        // What the worker does for a TLS event on socket `sock` (event_loop
        // `feed_event`).
        let on_socket = |sock: u64| {
            m.note_socket(9, sock);
            if !m.contains(9) {
                m.get_or_create_with_server(9, Protocol::Http2, Some(server));
                m.note_socket(9, sock);
                m.mark_joined_late(9);
            }
        };
        // First connection: one exchange, then it closes...
        let (mut c1, mut s1) = (hpack::Encoder::new(), hpack::Encoder::new());
        on_socket(101);
        m.process_packet_from(9, client, Direction::Egress, &preface(&mut c1, "/one"), 1);
        let first =
            paths(m.process_packet_from(9, server, Direction::Ingress, &response(&mut s1), 2));
        assert_eq!(first, vec![Some("/one".to_string())]);
        // ...and a new one, on another socket, gets the same key (freed and
        // reallocated SSL*).
        let (mut c2, mut s2) = (hpack::Encoder::new(), hpack::Encoder::new());
        on_socket(102);
        m.process_packet_from(9, client, Direction::Egress, &preface(&mut c2, "/two"), 3);
        let second =
            paths(m.process_packet_from(9, server, Direction::Ingress, &response(&mut s2), 4));
        assert_eq!(second, vec![Some("/two".to_string())]);
    }

    /// Codex R8 #3: `process_packet` uses the direction it is given, even on
    /// a connection whose server endpoint is known.
    #[test]
    fn test_process_packet_keeps_the_given_direction() {
        let m = ConnectionFsmManager::new(4);
        m.get_or_create_with_server(1, Protocol::Redis, Some((0x0A00_0001, 6379)));
        m.process_packet(1, Direction::Egress, b"*2\r\n$3\r\nGET\r\n$1\r\nk\r\n", 1);
        let out = m.process_packet(1, Direction::Ingress, b"$3\r\nbob\r\n", 2);
        let method = match &out {
            Some(FsmResult::MessageComplete(msg)) => msg.method.clone(),
            Some(FsmResult::Messages(ms)) => ms.first().and_then(|m| m.method.clone()),
            _ => None,
        };
        assert_eq!(method.as_deref(), Some("GET"), "{out:?}");
    }

    #[test]
    #[ignore = "timing probe, run by hand"]
    fn probe_insert_cost_at_capacity() {
        let cap = 65_536;
        let m = ConnectionFsmManager::new(cap);
        for id in 0..cap as u64 {
            m.get_or_create(id, Protocol::Dns);
        }
        let t = std::time::Instant::now();
        for id in 0..2_000u64 {
            m.get_or_create(1_000_000 + id, Protocol::Dns);
        }
        eprintln!(
            "PROBE insert at capacity: {:?} per new connection",
            t.elapsed() / 2_000
        );
    }

    fn seg(seq: u32, len: u32) -> TcpSegment {
        TcpSegment {
            seq,
            ack: None,
            len,
            syn: false,
            fin: false,
            rst: false,
        }
    }

    fn rst(seq: u32) -> TcpSegment {
        TcpSegment {
            rst: true,
            ..seg(seq, 0)
        }
    }

    const CLIENT: Endpoint = (0x0A00_0002, 51000);
    const SERVER: Endpoint = (0x0A00_0001, 80);

    fn tcp_manager() -> ConnectionFsmManager {
        let m = ConnectionFsmManager::new(16);
        m.get_or_create_with_server(1, Protocol::Http1, Some(SERVER));
        m
    }

    fn admit(m: &ConnectionFsmManager, src: Endpoint, s: TcpSegment) -> SegmentVerdict {
        m.admit_segment(1, src, Direction::Ingress, s).unwrap()
    }

    const ACCEPT: SegmentVerdict = SegmentVerdict::Accept { gap: 0, trim: 0 };

    #[test]
    fn tcp_retransmissions_are_dropped_and_overlaps_trimmed() {
        let m = tcp_manager();
        assert_eq!(admit(&m, CLIENT, seg(1000, 100)), ACCEPT);
        assert_eq!(admit(&m, CLIENT, seg(1100, 100)), ACCEPT);
        // Exact and partial retransmissions of bytes already parsed.
        assert_eq!(admit(&m, CLIENT, seg(1000, 100)), SegmentVerdict::Drop);
        assert_eq!(admit(&m, CLIENT, seg(1100, 50)), SegmentVerdict::Drop);
        // A coalesced retransmission that also carries new bytes: only the
        // new tail is parsed.
        assert_eq!(
            admit(&m, CLIENT, seg(1150, 100)),
            SegmentVerdict::Accept { gap: 0, trim: 50 }
        );
        assert_eq!(admit(&m, CLIENT, seg(1250, 10)), ACCEPT);
        // The other direction is tracked on its own.
        assert_eq!(admit(&m, SERVER, seg(5_000_000, 10)), ACCEPT);
        assert_eq!(admit(&m, SERVER, seg(5_000_000, 10)), SegmentVerdict::Drop);
        assert_eq!(
            m.admit_segment(99, CLIENT, Direction::Egress, seg(0, 1)),
            None
        );
    }

    #[test]
    fn tcp_sequence_wraparound() {
        let m = tcp_manager();
        assert_eq!(admit(&m, CLIENT, seg(u32::MAX - 49, 100)), ACCEPT);
        assert_eq!(
            admit(&m, CLIENT, seg(50, 10)),
            ACCEPT,
            "next byte after the wrap"
        );
        assert_eq!(
            admit(&m, CLIENT, seg(u32::MAX - 49, 100)),
            SegmentVerdict::Drop
        );
        assert_eq!(
            admit(&m, CLIENT, seg(u32::MAX - 9, 80)),
            SegmentVerdict::Accept { gap: 0, trim: 70 }
        );
    }

    #[test]
    fn tcp_forged_segments_out_of_window_are_dropped() {
        let m = tcp_manager();
        assert_eq!(admit(&m, CLIENT, seg(1000, 100)), ACCEPT);
        // Missed bytes (ring drops) within the window: skipped as a gap.
        assert_eq!(
            admit(&m, CLIENT, seg(1100 + 3000, 100)),
            SegmentVerdict::Accept { gap: 3000, trim: 0 }
        );
        // A forged segment far from the stream, ahead or behind.
        assert_eq!(
            admit(&m, CLIENT, seg(1_000_000_000, 100)),
            SegmentVerdict::Drop
        );
        assert_eq!(
            admit(&m, CLIENT, seg(4200 + TCP_WINDOW, 1)),
            SegmentVerdict::Drop
        );
        assert_eq!(
            admit(&m, CLIENT, seg(4200u32.wrapping_sub(1 << 30), 100)),
            SegmentVerdict::Drop
        );
        // The stream goes on.
        assert_eq!(admit(&m, CLIENT, seg(4200, 5)), ACCEPT);
    }

    #[test]
    fn tcp_rst_counts_only_in_window() {
        let m = tcp_manager();
        let mut req = seg(1000, 100);
        req.ack = Some(7_000_000); // the server's next byte
        assert_eq!(admit(&m, CLIENT, req), ACCEPT);
        // The server never sent data: its RST is checked against the
        // client's acknowledgment. A spoofed one with a guessed sequence
        // number is out of window...
        assert_eq!(admit(&m, SERVER, rst(123_456)), SegmentVerdict::Drop);
        assert_eq!(admit(&m, SERVER, rst(6_999_999)), SegmentVerdict::Drop);
        // Inside the window but not at the next byte: still not honoured.
        assert_eq!(admit(&m, SERVER, rst(7_000_010)), SegmentVerdict::Drop);
        // ...the real one, at the acknowledged sequence number, is.
        assert_eq!(admit(&m, SERVER, rst(7_000_000)), ACCEPT);
        // A client RST behind the stream (stale) is dropped.
        assert_eq!(admit(&m, CLIENT, rst(1050)), SegmentVerdict::Drop);
        assert_eq!(admit(&m, CLIENT, rst(1100)), ACCEPT);
    }

    #[test]
    fn tcp_acknowledgment_must_match_the_other_stream() {
        let m = tcp_manager();
        let with_ack = |seq, len, ack| TcpSegment {
            ack: Some(ack),
            ..seg(seq, len)
        };
        assert_eq!(admit(&m, CLIENT, with_ack(1000, 100, 50_000)), ACCEPT);
        assert_eq!(admit(&m, SERVER, with_ack(50_000, 10, 1100)), ACCEPT);
        // A forger whose sequence number landed in the window, but whose
        // acknowledgment is far from the server's stream, is rejected.
        assert_eq!(
            admit(&m, CLIENT, with_ack(1600, 10, 50_010 + TCP_WINDOW)),
            SegmentVerdict::Drop
        );
        assert_eq!(
            admit(
                &m,
                CLIENT,
                with_ack(1100, 10, 50_010u32.wrapping_sub(TCP_WINDOW))
            ),
            SegmentVerdict::Drop,
            "lagging that far is never genuine"
        );
        assert_eq!(admit(&m, CLIENT, with_ack(1100, 10, 50_010)), ACCEPT);
    }

    #[test]
    fn tcp_syn_and_fin_take_one_sequence_number() {
        let m = tcp_manager();
        // TCP Fast Open: data in the SYN starts at ISN + 1.
        let mut syn = seg(999, 10);
        syn.syn = true;
        assert_eq!(admit(&m, CLIENT, syn), ACCEPT);
        assert_eq!(admit(&m, CLIENT, seg(1010, 10)), ACCEPT);
        let mut fin = seg(1020, 0);
        fin.fin = true;
        assert_eq!(admit(&m, CLIENT, fin), ACCEPT);
        assert_eq!(
            admit(&m, CLIENT, fin),
            SegmentVerdict::Drop,
            "retransmitted FIN"
        );
    }

    #[test]
    fn tcp_loss_beyond_the_window_resyncs_on_the_peers_ack() {
        let m = tcp_manager();
        assert_eq!(admit(&m, CLIENT, seg(1, 10)), ACCEPT);
        assert_eq!(admit(&m, SERVER, seg(0, 100)), ACCEPT);
        // 20 MB of the server's data were lost: out of window...
        let far = 100 + 20_000_000;
        assert_eq!(admit(&m, SERVER, seg(far, 100)), SegmentVerdict::Drop);
        // ...until the client, at its next byte, acknowledges past it. The
        // same acknowledgment on a guessed sequence number is rejected.
        let ack = |seq| TcpSegment {
            ack: Some(far + 100),
            ..seg(seq, 10)
        };
        assert_eq!(admit(&m, CLIENT, ack(5000)), SegmentVerdict::Drop);
        assert_eq!(admit(&m, CLIENT, ack(11)), ACCEPT);
        assert_eq!(
            admit(&m, SERVER, seg(far + 100, 10)),
            SegmentVerdict::Accept { gap: far, trim: 0 }
        );
    }

    #[test]
    fn fin_from_both_sides_finishes_connection() {
        let m = ConnectionFsmManager::new(16);
        let client = (0x0A000002, 51000);
        let server = (0x0A000001, 80);
        m.get_or_create_with_server(7, Protocol::Http1, Some(server));
        // Half-close: the server may still answer.
        assert!(!m.note_fin(7, client, Direction::Ingress));
        assert!(!m.note_fin(7, client, Direction::Ingress), "repeat FIN");
        assert!(m.note_fin(7, server, Direction::Egress));
        assert!(
            !m.note_fin(99, client, Direction::Egress),
            "unknown connection"
        );
    }

    #[test]
    fn test_new_buffer_is_empty() {
        let buf = StreamBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.data(), &[] as &[u8]);
    }

    #[test]
    fn test_extend_and_data() {
        let mut buf = StreamBuffer::new();
        buf.extend(b"hello").unwrap();
        assert_eq!(buf.data(), b"hello");
        assert_eq!(buf.len(), 5);

        buf.extend(b" world").unwrap();
        assert_eq!(buf.data(), b"hello world");
        assert_eq!(buf.len(), 11);
    }

    #[test]
    fn test_consume_partial() {
        let mut buf = StreamBuffer::new();
        buf.extend(b"hello world").unwrap();

        buf.consume(6);
        assert_eq!(buf.data(), b"world");
        assert_eq!(buf.len(), 5);
    }

    #[test]
    fn test_consume_all() {
        let mut buf = StreamBuffer::new();
        buf.extend(b"hello").unwrap();

        buf.consume(5);
        assert!(buf.is_empty());
    }

    #[test]
    #[should_panic(expected = "consume(10) exceeds buffer length 5")]
    fn test_consume_overflow_panics() {
        let mut buf = StreamBuffer::new();
        buf.extend(b"hello").unwrap();
        buf.consume(10);
    }

    #[test]
    fn test_clear() {
        let mut buf = StreamBuffer::new();
        buf.extend(b"hello world").unwrap();
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_max_size_overflow_returns_err() {
        let mut buf = StreamBuffer::with_max_size(10);
        assert!(buf.extend(b"12345").is_ok());
        assert!(buf.extend(b"12345").is_ok());
        assert!(buf.extend(b"x").is_err());
        assert_eq!(buf.len(), 10);
        assert_eq!(buf.data(), b"1234512345");
    }

    #[test]
    fn test_max_size_exact_fit() {
        let mut buf = StreamBuffer::with_max_size(5);
        assert!(buf.extend(b"12345").is_ok());
        assert_eq!(buf.len(), 5);
        assert!(buf.extend(b"6").is_err());
    }

    #[test]
    fn test_extend_consume_extend_cycle() {
        let mut buf = StreamBuffer::with_max_size(10);
        buf.extend(b"12345678").unwrap();
        buf.consume(5);
        assert_eq!(buf.data(), b"678");
        buf.extend(b"abcdefg").unwrap();
        assert_eq!(buf.data(), b"678abcdefg");
        assert_eq!(buf.len(), 10);
    }

    #[test]
    fn test_default_max_size() {
        let buf = StreamBuffer::new();
        let mut large = StreamBuffer::with_max_size(DEFAULT_MAX_SIZE);
        let chunk = vec![0u8; 1024];
        for _ in 0..256 {
            large.extend(&chunk).unwrap();
        }
        assert_eq!(large.len(), 256 * 1024);
        assert!(large.extend(b"x").is_err());
        drop(buf);
    }

    // ── FsmResult Tests ─────────────────────────────────────────────────────

    #[test]
    fn test_fsm_result_waiting_for_more() {
        let result = FsmResult::WaitingForMore;
        match result {
            FsmResult::WaitingForMore => {}
            _ => panic!("Expected WaitingForMore"),
        }
    }

    #[test]
    fn test_fsm_result_message_complete() {
        let msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        let result = FsmResult::MessageComplete(msg);
        if let FsmResult::MessageComplete(m) = result {
            assert_eq!(m.protocol, Protocol::Http1);
        } else {
            panic!("Expected MessageComplete");
        }
    }

    #[test]
    fn test_fsm_result_messages() {
        let msg1 = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        let msg2 = L7Message::new(Protocol::Http1, Direction::Ingress, 2000);
        let result = FsmResult::Messages(vec![msg1, msg2]);
        if let FsmResult::Messages(msgs) = result {
            assert_eq!(msgs.len(), 2);
        } else {
            panic!("Expected Messages");
        }
    }

    #[test]
    fn test_fsm_result_error() {
        let result = FsmResult::Error("parse failed".to_string());
        if let FsmResult::Error(e) = result {
            assert_eq!(e, "parse failed");
        } else {
            panic!("Expected Error");
        }
    }

    #[test]
    fn test_fsm_result_connection_closed() {
        let result = FsmResult::ConnectionClosed;
        match result {
            FsmResult::ConnectionClosed => {}
            _ => panic!("Expected ConnectionClosed"),
        }
    }

    // ── ConnectionFsmManager Tests ───────────────────────────────────────────

    #[test]
    fn test_manager_new() {
        let manager = ConnectionFsmManager::new(1000);
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_manager_default() {
        let manager = ConnectionFsmManager::default();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_manager_get_or_create_returns_created() {
        let manager = ConnectionFsmManager::new(1000);

        let result = manager.get_or_create(1, Protocol::Http1);

        assert_eq!(result, CreateResult::Created);
        assert!(manager.contains(1));
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_manager_get_or_create_same_conn_id() {
        let manager = ConnectionFsmManager::new(1000);

        manager.get_or_create(1, Protocol::Http1);
        let result = manager.get_or_create(1, Protocol::Redis);

        assert_eq!(result, CreateResult::AlreadyExists);
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_manager_multiple_connections() {
        let manager = ConnectionFsmManager::new(1000);

        manager.get_or_create(1, Protocol::Http1);
        manager.get_or_create(2, Protocol::Redis);
        manager.get_or_create(3, Protocol::Mysql);

        assert_eq!(manager.len(), 3);
        assert!(manager.contains(1));
        assert!(manager.contains(2));
        assert!(manager.contains(3));
    }

    #[test]
    fn test_manager_close_connection() {
        let manager = ConnectionFsmManager::new(1000);

        manager.get_or_create(1, Protocol::Http1);
        assert_eq!(manager.len(), 1);

        manager.close_connection(1);

        assert!(manager.is_empty());
        assert!(!manager.contains(1));
    }

    #[test]
    fn test_manager_close_nonexistent_connection() {
        let manager = ConnectionFsmManager::new(1000);

        manager.close_connection(999);

        assert!(manager.is_empty());
    }

    #[test]
    fn test_manager_connection_state() {
        let manager = ConnectionFsmManager::new(1000);

        manager.get_or_create(1, Protocol::Http1);

        let state = manager.connection_state(1);
        assert!(state.is_some());

        let state = manager.connection_state(999);
        assert!(state.is_none());
    }

    #[test]
    fn test_manager_process_packet_missing_connection() {
        let manager = ConnectionFsmManager::new(1000);

        let result = manager.process_packet(999, Direction::Egress, b"data", 1000);

        assert!(result.is_none());
    }

    #[test]
    fn test_manager_evict_idle_no_effect_on_recent() {
        let manager = ConnectionFsmManager::new(1000);

        manager.get_or_create(1, Protocol::Http1);
        manager.get_or_create(2, Protocol::Redis);

        assert_eq!(manager.len(), 2);

        manager.evict_idle(std::time::Duration::from_secs(3600));

        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn test_manager_max_connections_eviction() {
        let manager = ConnectionFsmManager::new(2);

        manager.get_or_create(1, Protocol::Http1);
        manager.get_or_create(2, Protocol::Redis);

        assert_eq!(manager.len(), 2);

        let result = manager.get_or_create(3, Protocol::Mysql);

        assert_eq!(result, CreateResult::CreatedWithEviction(1));
        assert_eq!(manager.len(), 2);
        assert!(manager.contains(3));
    }

    #[test]
    fn test_eviction_removes_least_recently_seen_in_batches() {
        let cap = 64;
        let manager = ConnectionFsmManager::new(cap);
        for id in 0..cap as u64 {
            manager.get_or_create(id, Protocol::Dns);
        }
        // Touch the first half so the second half is older.
        std::thread::sleep(std::time::Duration::from_millis(2));
        for id in 0..32u64 {
            manager.process_packet(id, Direction::Egress, b"", 0);
        }
        let result = manager.get_or_create(1000, Protocol::Dns);
        assert_eq!(result, CreateResult::CreatedWithEviction(cap / 16));
        assert_eq!(manager.len(), cap - cap / 16 + 1);
        assert!(
            (0..32u64).all(|id| manager.contains(id)),
            "recent ones kept"
        );
        // The next inserts fit without another scan.
        for id in 0..(cap / 16 - 1) as u64 {
            assert_eq!(
                manager.get_or_create(2000 + id, Protocol::Dns),
                CreateResult::Created
            );
        }
    }
}
