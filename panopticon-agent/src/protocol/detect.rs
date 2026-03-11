#![allow(dead_code)]

//! Protocol detection — magic byte inspection + port-based fallback.
//!
//! Called once per connection on the first non-empty payload. Returns `None`
//! for unrecognised traffic (connection continues without parsing).

use super::{Direction, Protocol};

/// HTTP/2 connection preface (24 bytes), sent by client.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Detect the application-layer protocol from packet payload and port hints.
///
/// **Priority**: magic bytes first (highest confidence), port fallback second.
/// Returns `None` for unknown traffic — caller should set detection state to Unknown.
pub fn detect_protocol(
    payload: &[u8],
    src_port: u16,
    dst_port: u16,
    _direction: Direction,
) -> Option<Protocol> {
    if payload.is_empty() {
        return None;
    }

    // ── Magic byte checks (highest confidence) ───────────────────────

    // HTTP/2 client connection preface
    if payload.len() >= HTTP2_PREFACE.len() && payload.starts_with(HTTP2_PREFACE) {
        return Some(Protocol::Http2);
    }

    // HTTP/1.x request methods
    if is_http1_request(payload) || is_http1_response(payload) {
        return Some(Protocol::Http1);
    }

    // MySQL server greeting: seq_id=0x00 (byte 3) + protocol_version=0x0a (byte 4)
    if payload.len() >= 5 && payload[3] == 0x00 && payload[4] == 0x0a {
        return Some(Protocol::Mysql);
    }

    // PostgreSQL: startup messages or backend message types
    if is_postgres(payload) {
        return Some(Protocol::Postgres);
    }

    // Redis RESP: type prefix byte followed by \r\n within 128 bytes
    if is_redis(payload) {
        return Some(Protocol::Redis);
    }

    // AMQP 0-9-1 protocol header: "AMQP\x00\x00\x09\x01" (8 bytes)
    if payload.len() >= 8 && payload.starts_with(b"AMQP") {
        return Some(Protocol::Amqp);
    }

    // ── Port-based fallback (lower confidence) ───────────────────────
    // Check dst_port first (usually the server/service port), then src_port.

    for &port in &[dst_port, src_port] {
        match port {
            3306 => return Some(Protocol::Mysql),
            5432 => return Some(Protocol::Postgres),
            6379 => return Some(Protocol::Redis),
            50051 => return Some(Protocol::Grpc),
            80 | 8080 | 8000 | 443 | 8443 => return Some(Protocol::Http1),
            53 => return Some(Protocol::Dns),
            9092 => return Some(Protocol::Kafka),
            5672 => return Some(Protocol::Amqp),
            _ => {}
        }
    }
    None
}

/// Check for HTTP/1.x request method prefixes.
fn is_http1_request(payload: &[u8]) -> bool {
    payload.starts_with(b"GET ")
        || payload.starts_with(b"POST ")
        || payload.starts_with(b"PUT ")
        || payload.starts_with(b"DELETE ")
        || payload.starts_with(b"HEAD ")
        || payload.starts_with(b"OPTIONS ")
        || payload.starts_with(b"PATCH ")
        || payload.starts_with(b"CONNECT ")
}

/// Check for HTTP/1.x response prefix.
fn is_http1_response(payload: &[u8]) -> bool {
    payload.starts_with(b"HTTP/1.")
}

/// Detect PostgreSQL wire protocol.
///
/// Checks for:
/// 1. SSLRequest: 8 bytes, code 80877103
/// 2. StartupMessage: 8+ bytes, protocol version 196608 (v3.0)
/// 3. Backend message types with valid 4-byte length
fn is_postgres(payload: &[u8]) -> bool {
    // Check for startup messages (no type byte, length + protocol code)
    if payload.len() >= 8 {
        let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        // SSLRequest
        if len == 8 && code == 80877103 {
            return true;
        }
        // StartupMessage v3.0
        if code == 196608 && (8..=10000).contains(&len) {
            return true;
        }
    }

    // Backend message types: R(auth), K(key), Z(ready), T(row desc),
    // D(data row), C(cmd complete), E(error), N(notice), S(param status)
    if payload.len() >= 5 {
        let msg_type = payload[0];
        if matches!(
            msg_type,
            b'R' | b'K' | b'Z' | b'T' | b'D' | b'C' | b'E' | b'N' | b'S'
        ) {
            let len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            // Sanity check: length should be reasonable
            if (4..=1_000_000).contains(&len) {
                return true;
            }
        }
    }

    false
}

/// Detect Redis RESP protocol.
///
/// RESP messages start with a type prefix (`+`, `-`, `:`, `$`, `*`)
/// followed by data and `\r\n`. We check for the prefix and a `\r\n`
/// within the first 128 bytes.
fn is_redis(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let first = payload[0];
    if !matches!(first, b'+' | b'-' | b':' | b'$' | b'*') {
        return false;
    }
    // Look for \r\n within first 128 bytes
    let search_len = payload.len().min(128);
    payload[..search_len].windows(2).any(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HTTP/2 ───────────────────────────────────────────────────────

    #[test]
    fn test_detect_http2_preface() {
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";
        assert_eq!(
            detect_protocol(preface, 54321, 8080, Direction::Egress),
            Some(Protocol::Http2)
        );
    }

    // ── HTTP/1.x ─────────────────────────────────────────────────────

    #[test]
    fn test_detect_http1_get() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            detect_protocol(payload, 54321, 8080, Direction::Egress),
            Some(Protocol::Http1)
        );
    }

    #[test]
    fn test_detect_http1_post() {
        let payload = b"POST /api/users HTTP/1.1\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(
            detect_protocol(payload, 54321, 80, Direction::Egress),
            Some(Protocol::Http1)
        );
    }

    #[test]
    fn test_detect_http1_response() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            detect_protocol(payload, 80, 54321, Direction::Ingress),
            Some(Protocol::Http1)
        );
    }

    // ── MySQL ────────────────────────────────────────────────────────

    #[test]
    fn test_detect_mysql_greeting() {
        // MySQL greeting: length(3) + seq_id(0x00) + protocol_version(0x0a) + server version...
        let mut payload = vec![0u8; 64];
        // 3-byte length (little-endian), say 58 bytes
        payload[0] = 58;
        payload[1] = 0;
        payload[2] = 0;
        // seq_id = 0
        payload[3] = 0x00;
        // protocol_version = 10 (0x0a)
        payload[4] = 0x0a;
        // Server version string "8.0.32\0"
        let ver = b"8.0.32\0";
        payload[5..5 + ver.len()].copy_from_slice(ver);

        assert_eq!(
            detect_protocol(&payload, 54321, 3306, Direction::Ingress),
            Some(Protocol::Mysql)
        );
    }

    // ── PostgreSQL ───────────────────────────────────────────────────

    #[test]
    fn test_detect_postgres_ssl_request() {
        // SSLRequest: length=8, code=80877103
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&8u32.to_be_bytes());
        payload[4..8].copy_from_slice(&80877103u32.to_be_bytes());
        assert_eq!(
            detect_protocol(&payload, 54321, 5432, Direction::Egress),
            Some(Protocol::Postgres)
        );
    }

    #[test]
    fn test_detect_postgres_startup() {
        // StartupMessage: length=some, code=196608 (v3.0)
        let mut payload = vec![0u8; 64];
        payload[0..4].copy_from_slice(&64u32.to_be_bytes());
        payload[4..8].copy_from_slice(&196608u32.to_be_bytes());
        assert_eq!(
            detect_protocol(&payload, 54321, 5432, Direction::Egress),
            Some(Protocol::Postgres)
        );
    }

    #[test]
    fn test_detect_postgres_backend_ready() {
        // ReadyForQuery: 'Z' + length(5) + status('I')
        let payload = [b'Z', 0, 0, 0, 5, b'I'];
        assert_eq!(
            detect_protocol(&payload, 5432, 54321, Direction::Ingress),
            Some(Protocol::Postgres)
        );
    }

    // ── Redis ────────────────────────────────────────────────────────

    #[test]
    fn test_detect_redis_simple_string() {
        let payload = b"+OK\r\n";
        assert_eq!(
            detect_protocol(payload, 6379, 54321, Direction::Ingress),
            Some(Protocol::Redis)
        );
    }

    #[test]
    fn test_detect_redis_array() {
        let payload = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        assert_eq!(
            detect_protocol(payload, 54321, 6379, Direction::Egress),
            Some(Protocol::Redis)
        );
    }

    #[test]
    fn test_detect_redis_error() {
        let payload = b"-ERR unknown command\r\n";
        assert_eq!(
            detect_protocol(payload, 6379, 54321, Direction::Ingress),
            Some(Protocol::Redis)
        );
    }

    // ── Port fallback ────────────────────────────────────────────────

    #[test]
    fn test_detect_port_fallback_mysql() {
        // Binary data that doesn't match any magic bytes, but port hint works
        let payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert_eq!(
            detect_protocol(&payload, 54321, 3306, Direction::Egress),
            Some(Protocol::Mysql)
        );
    }

    #[test]
    fn test_detect_port_fallback_postgres() {
        let payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert_eq!(
            detect_protocol(&payload, 54321, 5432, Direction::Egress),
            Some(Protocol::Postgres)
        );
    }

    #[test]
    fn test_detect_port_fallback_redis() {
        let payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert_eq!(
            detect_protocol(&payload, 54321, 6379, Direction::Egress),
            Some(Protocol::Redis)
        );
    }

    #[test]
    fn test_detect_port_fallback_grpc() {
        let payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert_eq!(
            detect_protocol(&payload, 54321, 50051, Direction::Egress),
            Some(Protocol::Grpc)
        );
    }

    #[test]
    fn test_detect_port_fallback_http() {
        let payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert_eq!(
            detect_protocol(&payload, 54321, 80, Direction::Egress),
            Some(Protocol::Http1)
        );
    }

    // ── Unknown ──────────────────────────────────────────────────────

    #[test]
    fn test_detect_unknown() {
        let payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
        assert_eq!(
            detect_protocol(&payload, 54321, 12345, Direction::Egress),
            None
        );
    }

    #[test]
    fn test_detect_empty_payload() {
        assert_eq!(detect_protocol(&[], 54321, 80, Direction::Egress), None);
    }
}
