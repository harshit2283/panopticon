//! Throughput of the real L7 parsers on complete request/response exchanges.
//!
//! The agent is a binary crate, so the protocol module is compiled into the
//! benchmark directly (as the fuzz targets do). Each benchmark feeds one full
//! exchange on a keep-alive connection through `ProtocolFsmAdapter` — the
//! same path the agent's workers use — and asserts, before timing, that the
//! exchange actually produces exactly one message.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

#[allow(unused_imports)]
#[path = "../src/protocol/mod.rs"]
mod protocol;

use protocol::fsm::{FsmResult, ProtocolFsm, ProtocolFsmAdapter};
use protocol::{Direction, Protocol};

/// One exchange: (direction, segment) pairs as they would arrive.
type Exchange = Vec<(Direction, Vec<u8>)>;

fn feed_exchange(fsm: &mut ProtocolFsmAdapter, exchange: &Exchange) -> usize {
    let mut messages = 0;
    for (dir, seg) in exchange {
        match fsm.process_packet(*dir, seg, 1_000) {
            FsmResult::MessageComplete(_) => messages += 1,
            FsmResult::Messages(m) => messages += m.len(),
            _ => {}
        }
    }
    messages
}

fn http1_exchange(body_len: usize) -> Exchange {
    let req = b"GET /api/users?page=1&limit=50 HTTP/1.1\r\n\
        Host: api.example.com\r\n\
        Accept: application/json\r\n\
        User-Agent: panopticon-bench/1.0\r\n\
        Connection: keep-alive\r\n\r\n"
        .to_vec();
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body_len}\r\n\r\n"
    )
    .into_bytes();
    resp.extend(std::iter::repeat_n(b'a', body_len));
    vec![(Direction::Egress, req), (Direction::Ingress, resp)]
}

fn redis_exchange() -> Exchange {
    vec![
        (
            Direction::Egress,
            b"*3\r\n$3\r\nSET\r\n$9\r\nuser:1001\r\n$42\r\n{\"name\":\"Alice\",\"email\":\"alice@test.com\"}\r\n"
                .to_vec(),
        ),
        (Direction::Ingress, b"+OK\r\n".to_vec()),
    ]
}

fn postgres_exchange() -> Exchange {
    let query = b"SELECT id, name, email FROM users WHERE active = true LIMIT 100\0";
    let mut q = vec![b'Q'];
    q.extend(((4 + query.len()) as u32).to_be_bytes());
    q.extend_from_slice(query);
    // RowDescription (empty) + CommandComplete + ReadyForQuery
    let mut resp = vec![b'T'];
    resp.extend(6u32.to_be_bytes());
    resp.extend([0, 0]);
    let tag = b"SELECT 0\0";
    resp.push(b'C');
    resp.extend(((4 + tag.len()) as u32).to_be_bytes());
    resp.extend_from_slice(tag);
    resp.push(b'Z');
    resp.extend(5u32.to_be_bytes());
    resp.push(b'I');
    vec![(Direction::Egress, q), (Direction::Ingress, resp)]
}

fn mysql_exchange() -> Exchange {
    let query = b"SELECT id, name, email FROM users WHERE active = 1 ORDER BY id LIMIT 100";
    let mut q = ((query.len() + 1) as u32).to_le_bytes()[..3].to_vec();
    q.push(0x00); // sequence id
    q.push(0x03); // COM_QUERY
    q.extend_from_slice(query);
    // OK packet: header, 0x00, affected rows, last insert id, status, warnings
    let ok = vec![7, 0, 0, 1, 0x00, 0, 0, 2, 0, 0, 0];
    vec![(Direction::Egress, q), (Direction::Ingress, ok)]
}

fn bench_parsers(c: &mut Criterion) {
    let cases: Vec<(&str, Protocol, Exchange)> = vec![
        ("http1_get_156b_body", Protocol::Http1, http1_exchange(156)),
        (
            "http1_get_16kb_body",
            Protocol::Http1,
            http1_exchange(16 * 1024),
        ),
        ("redis_set", Protocol::Redis, redis_exchange()),
        (
            "postgres_simple_query",
            Protocol::Postgres,
            postgres_exchange(),
        ),
        ("mysql_com_query", Protocol::Mysql, mysql_exchange()),
    ];

    let mut group = c.benchmark_group("parser_exchange");
    for (name, proto, exchange) in &cases {
        let mut fsm = ProtocolFsmAdapter::new(*proto);
        // Guard against benchmarking a parser that never completes a message.
        for _ in 0..3 {
            assert_eq!(
                feed_exchange(&mut fsm, exchange),
                1,
                "{name}: exchange must yield exactly one message"
            );
        }
        let bytes: usize = exchange.iter().map(|(_, s)| s.len()).sum();
        group.throughput(Throughput::Bytes(bytes as u64));
        group.bench_function(*name, |b| {
            b.iter(|| black_box(feed_exchange(&mut fsm, black_box(exchange))))
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parsers);
criterion_main!(benches);
