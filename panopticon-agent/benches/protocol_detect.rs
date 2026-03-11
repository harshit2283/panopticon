//! Benchmark for `detect_protocol()` on various payload samples.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

// Re-use agent types. The agent is a binary crate, so we import protocol
// detection via the module path by including the source directly.
// Since panopticon-agent is a binary, we replicate the minimal types needed.

// We need to access the protocol detection function. Since the agent is a binary
// crate without a lib.rs, we test via the same approach as the unit tests:
// include the modules directly.

#[allow(dead_code)]
mod protocol {
    pub use panopticon_common::Direction;

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

    /// HTTP/2 connection preface (24 bytes), sent by client.
    const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    pub fn detect_protocol(
        payload: &[u8],
        src_port: u16,
        dst_port: u16,
        _direction: Direction,
    ) -> Option<Protocol> {
        if payload.is_empty() {
            return None;
        }
        if payload.len() >= HTTP2_PREFACE.len() && payload.starts_with(HTTP2_PREFACE) {
            return Some(Protocol::Http2);
        }
        if is_http1_request(payload) || is_http1_response(payload) {
            return Some(Protocol::Http1);
        }
        if payload.len() >= 5 && payload[3] == 0x00 && payload[4] == 0x0a {
            return Some(Protocol::Mysql);
        }
        if is_postgres(payload) {
            return Some(Protocol::Postgres);
        }
        if is_redis(payload) {
            return Some(Protocol::Redis);
        }
        if payload.len() >= 8 && payload.starts_with(b"AMQP") {
            return Some(Protocol::Amqp);
        }
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

    fn is_http1_response(payload: &[u8]) -> bool {
        payload.starts_with(b"HTTP/1.")
    }

    fn is_postgres(payload: &[u8]) -> bool {
        if payload.len() >= 8 {
            let len = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            if len == 8 && code == 80877103 {
                return true;
            }
            if code == 196608 && (8..=10000).contains(&len) {
                return true;
            }
        }
        if payload.len() >= 5 {
            let msg_type = payload[0];
            if matches!(
                msg_type,
                b'R' | b'K' | b'Z' | b'T' | b'D' | b'C' | b'E' | b'N' | b'S'
            ) {
                let len = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                if (4..=1_000_000).contains(&len) {
                    return true;
                }
            }
        }
        false
    }

    fn is_redis(payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        let first = payload[0];
        if !matches!(first, b'+' | b'-' | b':' | b'$' | b'*') {
            return false;
        }
        let search_len = payload.len().min(128);
        payload[..search_len].windows(2).any(|w| w == b"\r\n")
    }
}

use panopticon_common::Direction;
use protocol::detect_protocol;

fn bench_protocol_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_detect");

    // HTTP/1.1 GET request
    let http_get =
        b"GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n";
    group.bench_function("http1_get", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(http_get),
                black_box(54321),
                black_box(80),
                black_box(Direction::Egress),
            )
        })
    });

    // HTTP/1.1 response
    let http_resp =
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n";
    group.bench_function("http1_response", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(http_resp),
                black_box(80),
                black_box(54321),
                black_box(Direction::Ingress),
            )
        })
    });

    // HTTP/2 preface
    let h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00";
    group.bench_function("http2_preface", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(h2_preface),
                black_box(54321),
                black_box(8080),
                black_box(Direction::Egress),
            )
        })
    });

    // MySQL greeting
    let mut mysql_greeting = vec![0u8; 64];
    mysql_greeting[0] = 58;
    mysql_greeting[3] = 0x00;
    mysql_greeting[4] = 0x0a;
    group.bench_function("mysql_greeting", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(&mysql_greeting),
                black_box(54321),
                black_box(3306),
                black_box(Direction::Ingress),
            )
        })
    });

    // PostgreSQL startup
    let mut pg_startup = vec![0u8; 64];
    pg_startup[0..4].copy_from_slice(&64u32.to_be_bytes());
    pg_startup[4..8].copy_from_slice(&196608u32.to_be_bytes());
    group.bench_function("postgres_startup", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(&pg_startup),
                black_box(54321),
                black_box(5432),
                black_box(Direction::Egress),
            )
        })
    });

    // Redis RESP array
    let redis_cmd = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
    group.bench_function("redis_resp", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(redis_cmd),
                black_box(54321),
                black_box(6379),
                black_box(Direction::Egress),
            )
        })
    });

    // DNS (port fallback)
    let dns_payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
    group.bench_function("dns_port_fallback", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(&dns_payload),
                black_box(54321),
                black_box(53),
                black_box(Direction::Egress),
            )
        })
    });

    // Kafka (port fallback)
    let kafka_payload = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
    group.bench_function("kafka_port_fallback", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(&kafka_payload),
                black_box(54321),
                black_box(9092),
                black_box(Direction::Egress),
            )
        })
    });

    // AMQP magic bytes
    let amqp_header = b"AMQP\x00\x00\x09\x01";
    group.bench_function("amqp_magic", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(amqp_header.as_slice()),
                black_box(54321),
                black_box(5672),
                black_box(Direction::Egress),
            )
        })
    });

    // Unknown (no match)
    let unknown = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB];
    group.bench_function("unknown", |b| {
        b.iter(|| {
            detect_protocol(
                black_box(&unknown),
                black_box(54321),
                black_box(12345),
                black_box(Direction::Egress),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_protocol_detection);
criterion_main!(benches);
