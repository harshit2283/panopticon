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
mod secrets;

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
    /// Decoded payload text for PII scanning (Phase 5). For HTTP this is the
    /// response body.
    pub payload_text: Option<String>,
    /// Decoded request body (e.g. HTTP POST/PUT payload, form data), when the
    /// protocol has one. Scanned and redacted like `payload_text`.
    pub request_text: Option<String>,
    /// Wire headers (HTTP, HTTP/2, gRPC metadata, AMQP/Kafka fields).
    pub headers: Vec<(String, String)>,
    /// DNS A answers, filled only by the DNS parser: kept apart from wire
    /// headers, which a peer controls.
    pub dns_answers: Vec<DnsAnswer>,
    pub request_size_bytes: u64,
    pub response_size_bytes: u64,
}

/// An A record answering a query seen on the same flow: feeds the DNS
/// cache that names services in the graph.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DnsAnswer {
    pub name: String,
    /// IPv4 address as a host-order integer, like `src_addr`.
    pub ip: u32,
    pub ttl_secs: u32,
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
            request_text: None,
            headers: Vec::new(),
            dns_answers: Vec::new(),
            request_size_bytes: 0,
            response_size_bytes: 0,
        }
    }
}

/// `s` cut to at most `max` bytes, on a character boundary (slicing a
/// `&str` at an arbitrary byte index panics inside a multi-byte character).
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// What a masked credential value is replaced with, at the parser and in
/// the PII engine.
pub const REDACTED_CREDENTIAL: &str = "<REDACTED>";

pub use secrets::{
    STATEMENT_WITHHELD, has_credential_context, is_credential_name, protect_text,
    withheld_statement,
};

// ponytail: process-wide switch so parsers need no config plumbing; fine
// while there is one agent per process. Set once at startup by
// `set_mask_credentials`; only ever flipped false -> true at runtime.
static MASK_CREDENTIALS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Whether login secrets (Redis AUTH, SQL credential statements, credential
/// headers, fields with credential context) are protected before any sink. `[privacy]
/// mask_credentials`, default true; false is only allowed in `full` mode.
pub fn mask_credentials_enabled() -> bool {
    MASK_CREDENTIALS.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_mask_credentials(on: bool) {
    MASK_CREDENTIALS.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// A SQL statement (query text and its bound values) as a parser exports
/// it. With credential context and `mask_credentials` on: only its verb as
/// method and `VERB <statement withheld>` as text, no bound value, and
/// `true` (its error text is withheld too). The query is wiped.
pub fn export_statement(
    mut query: String,
    bound: Option<String>,
) -> (Option<String>, String, Option<String>, bool) {
    if mask_credentials_enabled() && has_credential_context(&query) {
        let shown = withheld_statement(&query);
        zeroize::Zeroize::zeroize(&mut query);
        if let Some(mut b) = bound {
            zeroize::Zeroize::zeroize(&mut b);
        }
        let verb = shown
            .strip_suffix(STATEMENT_WITHHELD)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string);
        return (verb, shown, None, true);
    }
    let verb = query.split_whitespace().next().map(str::to_uppercase);
    let shown = truncate_utf8(&query, 4096).to_string();
    (verb, shown, bound, false)
}

/// A server error message as a SQL parser exports it: withheld when its
/// statement was, or when it shows credential context itself.
pub fn export_error_text(text: String, statement_withheld: bool) -> String {
    if mask_credentials_enabled() && (statement_withheld || has_credential_context(&text)) {
        let mut text = text;
        zeroize::Zeroize::zeroize(&mut text);
        STATEMENT_WITHHELD.to_string()
    } else {
        text
    }
}

/// [`protect_text`] in place: credential values masked, or the field
/// replaced by [`secrets::FIELD_WITHHELD`].
pub fn protect_text_in(text: &mut String) {
    if let Some(out) = protect_text(text) {
        zeroize::Zeroize::zeroize(text);
        *text = out;
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

    /// `n` bytes of the stream in `direction` were never captured (the packet
    /// or TLS buffer was larger than the capture cap). Account for them if the
    /// parser can stay in sync — e.g. by counting them against a known body
    /// length — and return the result. `None` means the parser cannot resync
    /// and must be replaced with a fresh one.
    fn skip(
        &mut self,
        _direction: Direction,
        _n: usize,
        _timestamp_ns: u64,
    ) -> Option<ParseResult> {
        None
    }

    /// Protocol version string, if detected (e.g., "8.0.32" for MySQL).
    fn protocol_version(&self) -> Option<&str> {
        None
    }

    /// The parser did not see a direction of the stream from its first
    /// byte (capture joined an open connection, TLS, or bytes were lost).
    /// A parser that pairs replies with requests by order must stop
    /// trusting that pairing.
    fn joined_late(&mut self) {}
}

// ── Parser Factory ───────────────────────────────────────────────────────

/// Create a parser for the given protocol.
///
/// # Panics
/// Panics if called with `Protocol::Unknown` — detect_protocol() should
/// never return Unknown; it returns `None` instead.
/// `topics` is the pipeline's Kafka topic ID map.
pub fn create_parser(proto: Protocol, topics: &kafka::KafkaTopics) -> Box<dyn ProtocolParser> {
    match proto {
        Protocol::Http1 => Box::new(http1::Http1Parser::new()),
        Protocol::Http2 => Box::new(http2::Http2Parser::new(false)),
        Protocol::Grpc => Box::new(grpc::GrpcParser::new()),
        Protocol::Mysql => Box::new(mysql::MysqlParser::new()),
        Protocol::Postgres => Box::new(postgres::PostgresParser::new()),
        Protocol::Redis => Box::new(redis::RedisParser::new()),
        Protocol::Dns => Box::new(dns::DnsParser::new()),
        Protocol::Kafka => Box::new(kafka::KafkaParser::with_topics(topics.clone())),
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
        let parser = create_parser(Protocol::Http1, &Default::default());
        assert_eq!(parser.protocol(), Protocol::Http1);
    }

    #[test]
    fn test_create_parser_redis() {
        let parser = create_parser(Protocol::Redis, &Default::default());
        assert_eq!(parser.protocol(), Protocol::Redis);
    }

    #[test]
    #[should_panic(expected = "Unknown protocol")]
    fn test_create_parser_unknown_panics() {
        create_parser(Protocol::Unknown, &Default::default());
    }
}
