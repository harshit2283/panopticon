#![allow(dead_code)]

//! Protocol parsing layer — FSM-based parsers that reassemble multi-packet
//! protocol transactions into structured `L7Message`s.
//!
//! Each connection gets a `Box<dyn ProtocolParser>` after protocol detection.
//! Parsers handle Keep-Alive reset internally (no separate reset method).

pub mod amqp;
pub mod detect;
pub mod dns;
pub mod fsm;
pub mod grpc;
pub mod http1;
pub mod http2;
pub mod kafka;
pub mod mysql;
pub mod postgres;
pub mod redis;

pub use panopticon_common::Direction;

// ── Protocol Enum ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http1,
    Http2,
    Grpc,
    Mysql,
    Postgres,
    Redis,
    Dns,
    Kafka,
    Amqp,
    Unknown,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Http1 => write!(f, "HTTP/1.1"),
            Protocol::Http2 => write!(f, "HTTP/2"),
            Protocol::Grpc => write!(f, "gRPC"),
            Protocol::Mysql => write!(f, "MySQL"),
            Protocol::Postgres => write!(f, "PostgreSQL"),
            Protocol::Redis => write!(f, "Redis"),
            Protocol::Dns => write!(f, "DNS"),
            Protocol::Kafka => write!(f, "Kafka"),
            Protocol::Amqp => write!(f, "AMQP"),
            Protocol::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── L7Message ────────────────────────────────────────────────────────────

/// A fully parsed application-layer message, ready for PII scanning (Phase 5)
/// and service graph building (Phase 6).
///
/// Uses `String` (not `Cow<str>`) to avoid lifetime propagation through
/// async channels. The allocation cost is negligible compared to protocol parsing.
#[derive(Debug, Clone)]
pub struct L7Message {
    pub protocol: Protocol,
    pub direction: Direction,
    pub timestamp_ns: u64,
    /// Request→response delta, computed by the parser.
    pub latency_ns: Option<u64>,
    /// HTTP method, SQL command, Redis command.
    pub method: Option<String>,
    /// URI path, table name, Redis key.
    pub path: Option<String>,
    /// HTTP status code, MySQL/PG error code.
    pub status: Option<u32>,
    pub content_type: Option<String>,
    /// Decoded payload text for PII scanning (Phase 5).
    pub payload_text: Option<String>,
    pub headers: Vec<(String, String)>,
    pub request_size_bytes: u64,
    pub response_size_bytes: u64,
}

impl L7Message {
    /// Create a new L7Message with required fields, optional fields set to None/empty.
    pub fn new(protocol: Protocol, direction: Direction, timestamp_ns: u64) -> Self {
        Self {
            protocol,
            direction,
            timestamp_ns,
            latency_ns: None,
            method: None,
            path: None,
            status: None,
            content_type: None,
            payload_text: None,
            headers: Vec::new(),
            request_size_bytes: 0,
            response_size_bytes: 0,
        }
    }
}

// ── ParseResult ──────────────────────────────────────────────────────────

/// Result of feeding data to a protocol parser.
#[derive(Debug)]
pub enum ParseResult {
    /// Parser needs more data to produce a complete message.
    NeedMoreData,
    /// One or more complete L7 messages parsed.
    Messages(Vec<L7Message>),
    /// Unrecoverable parse error. Parser should be discarded.
    Error(String),
}

// ── ProtocolParser Trait ─────────────────────────────────────────────────

/// Trait for FSM-based protocol parsers.
///
/// Implementations must be `Send` (moved to worker tasks via `Box<dyn ProtocolParser>`).
/// The vtable dispatch cost (~2ns) is negligible vs the ~2µs per-event budget.
pub trait ProtocolParser: Send {
    /// Feed raw payload bytes to the parser.
    ///
    /// `direction` indicates whether data is from client (Egress) or server (Ingress).
    /// `timestamp_ns` is used for latency calculation (request→response delta).
    fn feed(&mut self, data: &[u8], direction: Direction, timestamp_ns: u64) -> ParseResult;

    /// The protocol this parser handles.
    fn protocol(&self) -> Protocol;

    /// Human-readable FSM state name (for debugging/logging).
    fn state_name(&self) -> &'static str;

    /// Protocol version string, if detected (e.g., "8.0.32" for MySQL).
    fn protocol_version(&self) -> Option<&str> {
        None
    }
}

// ── Parser Factory ───────────────────────────────────────────────────────

/// Create a parser for the given protocol.
///
/// # Panics
/// Panics if called with `Protocol::Unknown` — detect_protocol() should
/// never return Unknown; it returns `None` instead.
pub fn create_parser(proto: Protocol) -> Box<dyn ProtocolParser> {
    match proto {
        Protocol::Http1 => Box::new(http1::Http1Parser::new()),
        Protocol::Http2 => Box::new(http2::Http2Parser::new(false)),
        Protocol::Grpc => Box::new(grpc::GrpcParser::new()),
        Protocol::Mysql => Box::new(mysql::MysqlParser::new()),
        Protocol::Postgres => Box::new(postgres::PostgresParser::new()),
        Protocol::Redis => Box::new(redis::RedisParser::new()),
        Protocol::Dns => Box::new(dns::DnsParser::new()),
        Protocol::Kafka => Box::new(kafka::KafkaParser::new()),
        Protocol::Amqp => Box::new(amqp::AmqpParser::new()),
        Protocol::Unknown => unreachable!("create_parser called with Unknown protocol"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_display() {
        assert_eq!(format!("{}", Protocol::Http1), "HTTP/1.1");
        assert_eq!(format!("{}", Protocol::Grpc), "gRPC");
        assert_eq!(format!("{}", Protocol::Mysql), "MySQL");
        assert_eq!(format!("{}", Protocol::Postgres), "PostgreSQL");
        assert_eq!(format!("{}", Protocol::Redis), "Redis");
    }

    #[test]
    fn test_l7message_new() {
        let msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        assert_eq!(msg.protocol, Protocol::Http1);
        assert!(msg.method.is_none());
        assert!(msg.headers.is_empty());
        assert_eq!(msg.request_size_bytes, 0);
    }

    #[test]
    fn test_create_parser_http1() {
        let parser = create_parser(Protocol::Http1);
        assert_eq!(parser.protocol(), Protocol::Http1);
    }

    #[test]
    fn test_create_parser_redis() {
        let parser = create_parser(Protocol::Redis);
        assert_eq!(parser.protocol(), Protocol::Redis);
    }

    #[test]
    #[should_panic(expected = "Unknown protocol")]
    fn test_create_parser_unknown_panics() {
        create_parser(Protocol::Unknown);
    }
}
