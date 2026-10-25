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
}

pub struct ProtocolFsmAdapter {
    parser: Box<dyn ProtocolParser>,
}

impl ProtocolFsmAdapter {
    pub fn new(protocol: Protocol) -> Self {
        Self {
            parser: create_parser(protocol),
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
}

/// An `(IPv4 address, port)` pair as carried in `DataEvent`.
pub type Endpoint = (u32, u16);

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
    max_connections: usize,
}

impl ConnectionFsmManager {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: DashMap::new(),
            max_connections,
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

        let fsm: Box<dyn ProtocolFsm> = Box::new(ProtocolFsmAdapter::new(protocol));
        self.connections.insert(
            conn_id,
            ConnectionEntry {
                fsm,
                last_seen: Instant::now(),
                server,
                fin: [false; 2],
            },
        );

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

    pub fn process_packet(
        &self,
        conn_id: u64,
        direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> Option<FsmResult> {
        let mut entry = self.connections.get_mut(&conn_id)?;
        entry.last_seen = Instant::now();
        Some(entry.fsm.process_packet(direction, data, timestamp_ns))
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
        entry.last_seen = Instant::now();
        let direction = entry.direction_of(src, capture_direction);
        // A connection key can be reused by a new connection: TLS keys are
        // the library's connection object address, which the allocator hands
        // to the next connection once the old one is freed. A client preface
        // means a new HTTP/2 connection started; its frames and HPACK state
        // must not be read as a continuation of the old one.
        if direction == Direction::Egress
            && matches!(entry.fsm.protocol(), Protocol::Http2 | Protocol::Grpc)
            && data.starts_with(super::detect::HTTP2_PREFACE)
        {
            let protocol = entry.fsm.protocol();
            entry.fsm = Box::new(ProtocolFsmAdapter::new(protocol));
            entry.fin = [false; 2];
        }
        Some(entry.fsm.process_packet(direction, data, timestamp_ns))
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
        match entry.fsm.skip(direction, n, timestamp_ns) {
            Some(result) => Some(result),
            None => {
                let protocol = entry.fsm.protocol();
                entry.fsm = Box::new(ProtocolFsmAdapter::new(protocol));
                None
            }
        }
    }

    /// Record a FIN sent by `src`. Returns true once both sides have sent
    /// one, i.e. the connection is finished and can be closed.
    pub fn note_fin(&self, conn_id: u64, src: Endpoint, capture_direction: Direction) -> bool {
        let Some(mut entry) = self.connections.get_mut(&conn_id) else {
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
        m.get_or_create_with_server(9, Protocol::Http2, Some(server));
        // First connection: one exchange, then it closes...
        let (mut c1, mut s1) = (hpack::Encoder::new(), hpack::Encoder::new());
        m.process_packet_from(9, client, Direction::Egress, &preface(&mut c1, "/one"), 1);
        let first =
            paths(m.process_packet_from(9, server, Direction::Ingress, &response(&mut s1), 2));
        assert_eq!(first, vec![Some("/one".to_string())]);
        // ...and a new one gets the same key (freed and reallocated SSL*).
        let (mut c2, mut s2) = (hpack::Encoder::new(), hpack::Encoder::new());
        m.process_packet_from(9, client, Direction::Egress, &preface(&mut c2, "/two"), 3);
        let second =
            paths(m.process_packet_from(9, server, Direction::Ingress, &response(&mut s2), 4));
        assert_eq!(second, vec![Some("/two".to_string())]);
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
