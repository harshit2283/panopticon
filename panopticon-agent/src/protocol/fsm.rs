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
    /// A new entry was created, but an old connection had to be evicted due to capacity.
    CreatedWithEviction,
}

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
}

/// Unified entry combining the FSM instance and last-seen timestamp.
struct ConnectionEntry {
    fsm: Box<dyn ProtocolFsm>,
    last_seen: Instant,
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
        if let Some(mut entry) = self.connections.get_mut(&conn_id) {
            entry.last_seen = Instant::now();
            return CreateResult::AlreadyExists;
        }

        let mut evicted = false;

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
            let oldest_id = self
                .connections
                .iter()
                .min_by_key(|e| e.value().last_seen)
                .map(|e| *e.key());

            if let Some(id) = oldest_id {
                self.connections.remove(&id);
                evicted = true;
            }
        }

        let fsm: Box<dyn ProtocolFsm> = Box::new(ProtocolFsmAdapter::new(protocol));
        self.connections.insert(
            conn_id,
            ConnectionEntry {
                fsm,
                last_seen: Instant::now(),
            },
        );

        if evicted {
            CreateResult::CreatedWithEviction
        } else {
            CreateResult::Created
        }
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

        assert_eq!(result, CreateResult::CreatedWithEviction);
        assert_eq!(manager.len(), 2);
        assert!(manager.contains(3));
    }
}
