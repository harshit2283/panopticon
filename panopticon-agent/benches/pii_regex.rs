//! Cost of the real PII engine (regex path, default config) on the agent's
//! hot path.
//!
//! The agent is a binary crate, so its `config`, `pii` and `protocol` modules
//! are compiled into the benchmark directly. Benchmarks call the same
//! `PiiEngine` the workers use:
//! - `scan` on 4KB payloads with and without PII (most traffic has none);
//! - `scan_message` on a typical HTTP exchange: path + headers + body,
//!   including in-place redaction.

use criterion::{BatchSize, Criterion, Throughput, black_box, criterion_group, criterion_main};

#[allow(unused_imports)]
#[path = "../src/config.rs"]
mod config;
#[allow(unused_imports)]
#[path = "../src/pii/mod.rs"]
mod pii;
#[allow(unused_imports)]
#[path = "../src/protocol/mod.rs"]
mod protocol;

use config::PiiConfig;
use pii::PiiEngine;
use protocol::{Direction, L7Message, Protocol};

fn payload_4kb(with_pii: bool) -> String {
    let mut s = String::with_capacity(4096);
    let mut i = 0;
    while s.len() < 4000 {
        s.push_str(&format!(
            "{{\"id\":{i},\"status\":\"active\",\"plan\":\"pro\",\"region\":\"eu-west\"}},"
        ));
        if with_pii && i % 20 == 0 {
            s.push_str(&format!(
                "{{\"email\":\"user{i}@example.com\",\"ssn\":\"123-45-67{:02}\"}},",
                i % 100
            ));
        }
        i += 1;
    }
    s
}

fn http_message() -> L7Message {
    let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, 1);
    msg.method = Some("GET".into());
    msg.path = Some("/api/users?email=jane%40example.com&page=2".into());
    msg.headers = vec![
        ("host".into(), "api.example.com".into()),
        (
            "authorization".into(),
            "Bearer eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl".into(),
        ),
        ("accept".into(), "application/json".into()),
        ("content-type".into(), "application/json".into()),
    ];
    msg.payload_text = Some(
        r#"{"users":[{"id":1,"name":"Alice","email":"alice@example.com"},{"id":2,"name":"Bob"}],"total":2}"#
            .into(),
    );
    msg
}

fn bench_pii(c: &mut Criterion) {
    let engine = PiiEngine::new(&PiiConfig::default(), &[]);
    let clean = payload_4kb(false);
    let dirty = payload_4kb(true);
    assert!(
        engine.scan(&clean).is_none(),
        "clean payload must have no findings"
    );
    assert!(
        engine.scan(&dirty).is_some(),
        "dirty payload must have findings"
    );

    let mut group = c.benchmark_group("pii_engine");
    group.throughput(Throughput::Bytes(clean.len() as u64));
    group.bench_function("scan_4kb_clean", |b| {
        b.iter(|| engine.scan(black_box(&clean)))
    });
    group.throughput(Throughput::Bytes(dirty.len() as u64));
    group.bench_function("scan_4kb_with_pii", |b| {
        b.iter(|| engine.scan(black_box(&dirty)))
    });

    let template = http_message();
    assert!(
        engine.scan_message(&mut template.clone()).is_some(),
        "HTTP message must have findings"
    );
    group.throughput(Throughput::Elements(1));
    group.bench_function("scan_message_http_exchange", |b| {
        b.iter_batched(
            || template.clone(),
            |mut msg| engine.scan_message(black_box(&mut msg)),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

criterion_group!(benches, bench_pii);
criterion_main!(benches);
