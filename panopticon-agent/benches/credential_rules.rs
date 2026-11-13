//! Cost of credential protection on the message path (`pii::mask_credentials`,
//! what every exported message goes through with `mask_credentials` on):
//! `[credentials] builtin = "full"` vs `"names_only"`, with no user
//! patterns and with 256.
//!
//! The agent is a binary crate, so its `config`, `pii` and `protocol`
//! modules are compiled into the benchmark directly (as in `pii_regex`).

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
// `pii` reaches the external-service client through `io_gate`, which
// writes through `export::open_private` (unused here) and `test_hooks`.
#[allow(dead_code, unused_imports)]
#[path = "../src/io_gate.rs"]
mod io_gate;
#[allow(dead_code, unused_imports)]
#[path = "../src/test_hooks.rs"]
mod test_hooks;
#[allow(dead_code)]
mod export {
    pub fn open_private(_path: &str, _append: bool) -> anyhow::Result<std::fs::File> {
        anyhow::bail!("not used by the benchmark")
    }
}

use protocol::{Builtin, CredentialRules, Direction, L7Message, Protocol, set_credential_rules};

/// A 4 KiB JSON body of ordinary words; `with_context` adds a credential
/// member every 20 records.
fn body_4kb(with_context: bool) -> String {
    let mut s = String::with_capacity(4096);
    let mut i = 0;
    while s.len() < 4000 {
        s.push_str(&format!(
            "{{\"id\":{i},\"status\":\"active\",\"note\":\"shipped to the eu west depot\"}},"
        ));
        if with_context && i % 20 == 0 {
            s.push_str(&format!("{{\"api_key\":\"k{i}x9q\"}},"));
        }
        i += 1;
    }
    s
}

fn message(body: &str) -> L7Message {
    let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, 1);
    msg.method = Some("POST".into());
    msg.path = Some("/api/orders?page=2&sort=desc".into());
    msg.content_type = Some("application/json".into());
    msg.headers = vec![
        ("host".into(), "api.example.com".into()),
        (
            "authorization".into(),
            "Bearer eyJhbGciOi.eyJzdWIiOi.c2ln".into(),
        ),
        ("accept".into(), "application/json".into()),
        ("x-request-id".into(), "5f0c2a7e-1d1b-4c55-9a0e-3c1f".into()),
    ];
    msg.payload_text = Some(body.to_string());
    msg.request_text = Some(r#"{"items":[{"sku":"A-1","qty":2}],"coupon":"SPRING"}"#.into());
    msg
}

fn patterns(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("pfx{i}_[a-z0-9]{{24}}")).collect()
}

fn bench_credentials(c: &mut Criterion) {
    let mut group = c.benchmark_group("credential_rules");
    for (body_name, body) in [("clean", body_4kb(false)), ("context", body_4kb(true))] {
        let template = message(&body);
        for (builtin_name, builtin) in [("full", Builtin::Full), ("names_only", Builtin::NamesOnly)]
        {
            for n in [0, 256] {
                set_credential_rules(CredentialRules::compile(&patterns(n), builtin).unwrap());
                group.throughput(Throughput::Bytes(body.len() as u64));
                group.bench_function(
                    format!("mask_credentials_{body_name}_{builtin_name}_{n}_patterns"),
                    |b| {
                        b.iter_batched(
                            || template.clone(),
                            |mut msg| pii::mask_credentials(black_box(&mut msg)),
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_credentials);
criterion_main!(benches);
