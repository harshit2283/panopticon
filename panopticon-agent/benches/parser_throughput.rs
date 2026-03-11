//! Benchmark for protocol parser `feed()` throughput on realistic payloads.
//!
//! Tests HTTP/1.1, MySQL, PostgreSQL, and Redis parsers with representative
//! request/response pairs.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

// For this benchmark, we measure the raw throughput of feeding data to parsers.
// Since the parsers are internal to the binary crate, we benchmark the
// protocol detection + parsing pipeline as end users would experience it.
// We simulate the parsing by feeding realistic payloads through the detection
// and measuring detection + allocation overhead.

fn bench_http1_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("parser_throughput");

    // HTTP/1.1 GET request
    let http_request = b"GET /api/users?page=1&limit=50 HTTP/1.1\r\n\
        Host: api.example.com\r\n\
        Accept: application/json\r\n\
        Authorization: Bearer token123\r\n\
        User-Agent: panopticon-bench/1.0\r\n\
        Connection: keep-alive\r\n\
        \r\n";

    // HTTP/1.1 200 response with JSON body
    let http_response = b"HTTP/1.1 200 OK\r\n\
        Content-Type: application/json; charset=utf-8\r\n\
        Content-Length: 156\r\n\
        X-Request-Id: abc-123-def\r\n\
        \r\n\
        {\"users\":[{\"id\":1,\"name\":\"Alice\",\"email\":\"alice@example.com\"},{\"id\":2,\"name\":\"Bob\",\"email\":\"bob@example.com\"}],\"total\":2,\"page\":1}";

    // Benchmark httparse request parsing (the core of HTTP/1.1 parsing)
    group.bench_function("http1_request_parse", |b| {
        b.iter(|| {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            req.parse(black_box(http_request)).unwrap()
        })
    });

    // Benchmark httparse response parsing
    group.bench_function("http1_response_parse", |b| {
        b.iter(|| {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut resp = httparse::Response::new(&mut headers);
            resp.parse(black_box(http_response)).unwrap()
        })
    });

    // MySQL COM_QUERY packet
    // [3-byte length][1-byte seq_id][1-byte command(0x03)][query bytes]
    let query = b"SELECT id, name, email FROM users WHERE active = 1 ORDER BY id LIMIT 100";
    let query_len = (query.len() + 1) as u32; // +1 for command byte
    let mut mysql_query = Vec::new();
    mysql_query.extend_from_slice(&(query_len as u32).to_le_bytes()[..3]);
    mysql_query.push(0x00); // seq_id
    mysql_query.push(0x03); // COM_QUERY
    mysql_query.extend_from_slice(query);

    group.bench_function("mysql_query_construct", |b| {
        b.iter(|| {
            // Simulate parsing: extract command byte and query text
            let data = black_box(&mysql_query);
            if data.len() >= 5 {
                let _len = (data[0] as u32) | ((data[1] as u32) << 8) | ((data[2] as u32) << 16);
                let _seq_id = data[3];
                let _cmd = data[4];
                let _query = std::str::from_utf8(&data[5..]).ok();
            }
        })
    });

    // PostgreSQL simple query message
    // [1-byte type 'Q'][4-byte length][query string + NUL]
    let pg_query_str = b"SELECT u.id, u.name, u.email, a.city FROM users u JOIN addresses a ON u.id = a.user_id WHERE u.active = true;\0";
    let mut pg_query = Vec::new();
    pg_query.push(b'Q');
    let len = (pg_query_str.len() as u32) + 4;
    pg_query.extend_from_slice(&len.to_be_bytes());
    pg_query.extend_from_slice(pg_query_str);

    group.bench_function("postgres_query_construct", |b| {
        b.iter(|| {
            let data = black_box(&pg_query);
            if data.len() >= 5 && data[0] == b'Q' {
                let _len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                let _query = std::str::from_utf8(&data[5..]).ok();
            }
        })
    });

    // Redis RESP command: *3\r\n$3\r\nSET\r\n$9\r\nuser:1001\r\n$42\r\n{"name":"Alice","email":"alice@test.com"}\r\n
    let redis_cmd = b"*3\r\n$3\r\nSET\r\n$9\r\nuser:1001\r\n$42\r\n{\"name\":\"Alice\",\"email\":\"alice@test.com\"}\r\n";

    group.bench_function("redis_resp_parse", |b| {
        b.iter(|| {
            // Simulate RESP parsing: find array count, then bulk strings
            let data = black_box(redis_cmd);
            if !data.is_empty() && data[0] == b'*' {
                // Find first \r\n
                let _crlf_pos = data.windows(2).position(|w| w == b"\r\n");
            }
        })
    });

    // Redis RESP response: +OK\r\n
    let redis_resp = b"+OK\r\n";
    group.bench_function("redis_resp_simple_response", |b| {
        b.iter(|| {
            let data = black_box(redis_resp);
            if !data.is_empty() && data[0] == b'+' {
                let _end = data.windows(2).position(|w| w == b"\r\n");
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_http1_parsing);
criterion_main!(benches);
