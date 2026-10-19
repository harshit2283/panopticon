//! Benchmark for `detect_protocol()` on various payload samples.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

// The agent is a binary crate, so the real protocol module is compiled into
// the benchmark directly (no hand-copied detection code that can drift).
#[allow(unused_imports)]
#[path = "../src/protocol/mod.rs"]
mod protocol;

use protocol::Direction;
use protocol::detect::detect_protocol;

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
