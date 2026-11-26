//! Duplicated TLS plaintext (USER-GUIDE §5.3, ADR-014): without the overlay
//! dedupe, a library or Go binary that several containers of one image map
//! is attached once per container mount, so one call fires several copies
//! of a probe. Which copies emit (tls_probes.rs): OpenSSL writes with an
//! unrestricted capture scope (`ssl_write_entry` emits at entry), Go reads
//! (`go_tls_decrypt_ret`) and unguarded Go writes (`go_tls_write_entry`)
//! are emitted once per copy; OpenSSL reads, OpenSSL writes under a
//! restricted scope (the first return consumes the call) and
//! guarded Go writes (the second entry meets `Guard::Again`) once. The
//! copies of one call are adjacent in the key's ring, so a key's stream in
//! one direction becomes each record repeated back to back. The `_dedup`
//! probe variants emit once per hit where the kernel has attach cookies
//! (tls_probes.rs `first_copy`). Kernels without them (upstream before
//! 5.15, RHEL 8's 4.18) attach a file once per inode the probes were shown
//! to land on (proc_scanner.rs `Attached::covers`). This is the second line,
//! for the copies those leave (no landed inode shown, a ctime change
//! without a copy-up) and for any copy that misses.
//!
//! Every conversation below runs on a TLS key (`start_tls`) split into
//! records at many points, once as captured and once with the records of
//! one direction (or both) repeated. The duplicated run may fail closed or
//! export repeated records, but must never export a credential the same
//! records without duplicates did not: no value under a weaker rule.

use super::fsm::{ConnectionFsmManager, Endpoint, FsmResult};
use super::{Direction, Protocol};

type Msg = (Direction, Vec<u8>);

const CLIENT: Endpoint = (0x0A00_0002, 40000);
const SERVER: Endpoint = (0x0A00_0001, 443);

/// Everything exported for `recs` on one TLS key, as text: the parsers'
/// records after the credential masking every export path applies
/// (`pii::mask_credentials`, with `mask_credentials` on, the default).
fn run(proto: Protocol, recs: &[Msg]) -> String {
    let m = ConnectionFsmManager::new(4);
    m.get_or_create_with_server(1, proto, Some(SERVER));
    m.start_tls(1);
    let mut out = String::new();
    for (i, (d, b)) in recs.iter().enumerate() {
        let src = if *d == Direction::Egress {
            CLIENT
        } else {
            SERVER
        };
        let msgs = match m.process_packet_from(1, src, *d, b, 1 + i as u64 * 1000) {
            Some(FsmResult::Messages(ms)) => ms,
            Some(FsmResult::MessageComplete(x)) => vec![x],
            _ => vec![],
        };
        for mut x in msgs {
            crate::pii::mask_credentials(&mut x);
            out += &format!("{x:?}\n");
        }
    }
    out
}

/// The secrets (or a half of one, 5 bytes or more) in `out`.
fn leaked<'a>(out: &str, secrets: &[&'a str]) -> Vec<&'a str> {
    secrets
        .iter()
        .copied()
        .filter(|s| {
            let h = s.len() / 2;
            out.contains(s) || out.contains(&s[..h]) || out.contains(&s[h..])
        })
        .collect()
}

/// The ways a conversation's messages are cut into records: whole; one
/// message cut in two at several points; every message cut into chunks;
/// consecutive messages of one direction written as one record.
fn splits(msgs: &[Msg]) -> Vec<Vec<Msg>> {
    let mut out = vec![msgs.to_vec()];
    for i in 0..msgs.len() {
        let (d, b) = &msgs[i];
        let n = b.len();
        let mut cuts = vec![
            1,
            2,
            3,
            5,
            n / 3,
            n / 2,
            2 * n / 3,
            n.saturating_sub(2),
            n.saturating_sub(1),
        ];
        cuts.sort();
        cuts.dedup();
        for k in cuts.into_iter().filter(|&k| k > 0 && k < n) {
            let mut v = msgs[..i].to_vec();
            v.push((*d, b[..k].to_vec()));
            v.push((*d, b[k..].to_vec()));
            v.extend_from_slice(&msgs[i + 1..]);
            out.push(v);
        }
    }
    for size in [3, 7, 16, 61] {
        out.push(
            msgs.iter()
                .flat_map(|(d, b)| b.chunks(size).map(move |c| (*d, c.to_vec())))
                .collect(),
        );
    }
    let mut merged: Vec<Msg> = vec![];
    for (d, b) in msgs {
        match merged.last_mut() {
            Some((ld, lb)) if ld == d => lb.extend_from_slice(b),
            _ => merged.push((*d, b.clone())),
        }
    }
    out.push(merged);
    out
}

/// Each record of the directions `dup` names twice, back to back.
fn duplicate(recs: &[Msg], dup: &[Direction]) -> Vec<Msg> {
    recs.iter()
        .flat_map(|r| {
            let n = if dup.contains(&r.0) { 2 } else { 1 };
            std::iter::repeat_n(r.clone(), n)
        })
        .collect()
}

/// The check: for every split and every duplicated direction, the
/// duplicated run leaks no secret its split did not. Returns the secrets
/// the undivided conversation exports (the parsers' own rules).
fn check(proto: Protocol, msgs: &[Msg], secrets: &[&str]) -> Vec<String> {
    let mut failures = vec![];
    let mut variants = 0;
    let (mut differ, mut records) = (0, 0);
    for recs in splits(msgs) {
        let base_out = run(proto, &recs);
        let base = leaked(&base_out, secrets);
        for dup in [
            &[Direction::Egress][..],
            &[Direction::Ingress][..],
            &[Direction::Egress, Direction::Ingress][..],
        ] {
            variants += 1;
            let out = run(proto, &duplicate(&recs, dup));
            differ += (out != base_out) as usize;
            records += out.lines().count();
            let extra: Vec<_> = leaked(&out, secrets)
                .into_iter()
                .filter(|s| !base.contains(s))
                .collect();
            if !extra.is_empty() {
                let cuts: Vec<_> = recs
                    .iter()
                    .map(|(d, b)| (*d == Direction::Egress, b.len()))
                    .collect();
                failures.push(format!(
                    "{proto:?} dup {dup:?} cuts {cuts:?}: {extra:?}\n{out}"
                ));
            }
        }
    }
    // The duplicates do reach the parsers, and records are still exported.
    assert!(variants > 20 && differ > variants / 2 && records > 0);
    assert!(
        failures.is_empty(),
        "{} of {variants} variants leak:\n{}",
        failures.len(),
        failures[..failures.len().min(3)].join("\n")
    );
    leaked(&run(proto, msgs), secrets)
        .into_iter()
        .map(String::from)
        .collect()
}

fn c(b: &[u8]) -> Msg {
    (Direction::Egress, b.to_vec())
}
fn s(b: &[u8]) -> Msg {
    (Direction::Ingress, b.to_vec())
}

#[test]
fn duplicated_http1_records_leak_nothing_new() {
    let body = br#"{"password":"Sx1Dq8mVpLw"}"#;
    let mut req = format!(
        "POST /api/token/Sx1Pa7nQzRk?token=Sx1Qb4tYuHe HTTP/1.1\r\nHost: a\r\n\
         Authorization: Bearer Sx1Ac2wErTy\r\nCookie: sid=Sx1Cg6hJkLz\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    let rbody = br#"{"api_key":"Sx1Kv9bNmXc"}"#;
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\nSet-Cookie: s=Sx1Sf3dGhJq\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        rbody.len()
    )
    .into_bytes();
    resp.extend_from_slice(rbody);
    let get = b"GET /health?api_key=Sx1Ge5rTyUi HTTP/1.1\r\nHost: a\r\n\r\n";
    let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let secrets = [
        "Sx1Pa7nQzRk",
        "Sx1Qb4tYuHe",
        "Sx1Ac2wErTy",
        "Sx1Cg6hJkLz",
        "Sx1Dq8mVpLw",
        "Sx1Sf3dGhJq",
        "Sx1Kv9bNmXc",
        "Sx1Ge5rTyUi",
    ];
    let base = check(
        Protocol::Http1,
        &[c(&req), s(&resp), c(get), s(ok)],
        &secrets,
    );
    assert!(base.is_empty(), "{base:?}");
}

fn resp_cmd(args: &[&str]) -> Vec<u8> {
    let mut b = format!("*{}\r\n", args.len()).into_bytes();
    for a in args {
        b.extend(format!("${}\r\n{a}\r\n", a.len()).into_bytes());
    }
    b
}

#[test]
fn duplicated_redis_records_leak_nothing_new() {
    let secrets = ["Sx2Au7pLmQw", "Sx2Va3kJhGf", "Sx2Hb8nBvCx"];
    check(
        Protocol::Redis,
        &[
            c(&resp_cmd(&["AUTH", "Sx2Au7pLmQw"])),
            s(b"+OK\r\n"),
            c(&resp_cmd(&["SET", "session:1", "Sx2Va3kJhGf"])),
            s(b"+OK\r\n"),
            c(&resp_cmd(&["HSET", "user:1", "password", "Sx2Hb8nBvCx"])),
            s(b":1\r\n"),
            c(&resp_cmd(&["GET", "session:1"])),
            s(b"$11\r\nSx2Va3kJhGf\r\n"),
        ],
        &secrets,
    );
}

fn pg_front(t: u8, payload: &[u8]) -> Vec<u8> {
    let mut m = vec![t];
    m.extend(((payload.len() + 4) as u32).to_be_bytes());
    m.extend_from_slice(payload);
    m
}

#[test]
fn duplicated_postgres_records_leak_nothing_new() {
    let mut startup = vec![];
    let params = b"user\0alice\0database\0db\0\0";
    startup.extend(((params.len() + 8) as u32).to_be_bytes());
    startup.extend(196608u32.to_be_bytes());
    startup.extend_from_slice(params);
    let mut bind = b"\0\0\0\0\0\x01".to_vec();
    bind.extend(11u32.to_be_bytes());
    bind.extend_from_slice(b"Sx3Bk2mNqWe\0\0");
    let mut extended = pg_front(b'P', b"\0SELECT * FROM notes WHERE body = $1\0\0\0");
    extended.extend(pg_front(b'B', &bind));
    extended.extend(pg_front(b'E', b"\0\0\0\0\0"));
    extended.extend(pg_front(b'S', b""));
    let mut answers = pg_front(b'1', b"");
    answers.extend(pg_front(b'2', b""));
    answers.extend(pg_front(b'C', b"SELECT 0\0"));
    answers.extend(pg_front(b'Z', b"I"));
    let mut auth_ok = pg_front(b'R', &0u32.to_be_bytes());
    auth_ok.extend(pg_front(b'Z', b"I"));
    let mut err = pg_front(
        b'E',
        b"SERROR\0C42P01\0Mrelation Sx3Ee5tGhJk does not exist\0\0",
    );
    err.extend(pg_front(b'Z', b"I"));
    let secrets = [
        "Sx3Pw9vBnMq",
        "Sx3Bk2mNqWe",
        "Sx3Lt4rFdSa",
        "Sx3Ee5tGhJk",
        "Sx3Ux6yHjKl",
    ];
    check(
        Protocol::Postgres,
        &[
            c(&startup),
            s(&pg_front(b'R', &3u32.to_be_bytes())),
            c(&pg_front(b'p', b"Sx3Pw9vBnMq\0")),
            s(&auth_ok),
            c(&extended),
            s(&answers),
            c(&pg_front(b'Q', b"ALTER USER bob PASSWORD 'Sx3Ux6yHjKl'\0")),
            s(&[pg_front(b'C', b"ALTER ROLE\0"), pg_front(b'Z', b"I")].concat()),
            c(&pg_front(
                b'Q',
                b"SELECT * FROM Sx3Ee5tGhJk WHERE note = 'Sx3Lt4rFdSa'\0",
            )),
            s(&err),
        ],
        &secrets,
    );
}

fn my_pkt(seq: u8, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut p = vec![n as u8, (n >> 8) as u8, (n >> 16) as u8, seq];
    p.extend_from_slice(payload);
    p
}

#[test]
fn duplicated_mysql_records_leak_nothing_new() {
    let mut greet = vec![0x0a];
    greet.extend_from_slice(b"8.0.32\0");
    greet.extend([1, 0, 0, 0]);
    greet.extend([0xAA; 8]);
    greet.push(0);
    greet.extend([0xFF, 0xF7, 0x21, 0x02, 0x00, 0xFF, 0x81, 21]);
    greet.extend([0; 10]);
    greet.extend([0xBB; 13]);
    greet.extend_from_slice(b"mysql_native_password\0");
    // Handshake response: PROTOCOL_41 | SECURE_CONNECTION | PLUGIN_AUTH.
    let mut hr = (0x0000_0200u32 | 0x0000_8000 | 0x0008_0000)
        .to_le_bytes()
        .to_vec();
    hr.extend(16_777_216u32.to_le_bytes());
    hr.push(33);
    hr.extend([0; 23]);
    hr.extend_from_slice(b"alice\0");
    hr.push(11);
    hr.extend_from_slice(b"Sx4Au8kLpOi");
    hr.extend_from_slice(b"mysql_native_password\0");
    let ok = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    let mut prep = vec![0x16];
    prep.extend_from_slice(b"UPDATE notes SET body = ? WHERE id = 1");
    let mut prep_ok = vec![0x00];
    prep_ok.extend(1u32.to_le_bytes());
    prep_ok.extend(0u16.to_le_bytes());
    prep_ok.extend(1u16.to_le_bytes());
    prep_ok.extend([0, 0, 0]);
    let mut exec = vec![0x17, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0x00, 0x01, 0x0f, 0x00, 11];
    exec.extend_from_slice(b"Sx4Bv3nMqWs");
    let mut q = vec![0x03];
    q.extend_from_slice(b"SET PASSWORD FOR bob = 'Sx4Pq6wErTy'");
    let mut q2 = vec![0x03];
    q2.extend_from_slice(b"SELECT * FROM notes WHERE body = 'Sx4Lz1xCvBn'");
    let err = b"\xff\x7a\x04#42S02Table Sx4Ee7rTyUi doesn't exist";
    let secrets = [
        "Sx4Au8kLpOi",
        "Sx4Bv3nMqWs",
        "Sx4Pq6wErTy",
        "Sx4Lz1xCvBn",
        "Sx4Ee7rTyUi",
    ];
    check(
        Protocol::Mysql,
        &[
            s(&my_pkt(0, &greet)),
            c(&my_pkt(1, &hr)),
            s(&my_pkt(2, &ok)),
            c(&my_pkt(0, &prep)),
            s(&[my_pkt(1, &prep_ok), my_pkt(2, b"param-def")].concat()),
            c(&my_pkt(0, &exec)),
            s(&my_pkt(1, &ok)),
            c(&my_pkt(0, &q)),
            s(&my_pkt(1, &ok)),
            c(&my_pkt(0, &q2)),
            s(&my_pkt(1, err)),
        ],
        &secrets,
    );
}

fn kafka_req(key: i16, version: i16, cid: i32, body: &[u8]) -> Vec<u8> {
    let mut b = key.to_be_bytes().to_vec();
    b.extend(version.to_be_bytes());
    b.extend(cid.to_be_bytes());
    b.extend(3i16.to_be_bytes());
    b.extend_from_slice(b"app");
    b.extend_from_slice(body);
    let mut f = (b.len() as i32).to_be_bytes().to_vec();
    f.extend(b);
    f
}

fn kafka_resp(cid: i32, body: &[u8]) -> Vec<u8> {
    let mut b = cid.to_be_bytes().to_vec();
    b.extend_from_slice(body);
    let mut f = (b.len() as i32).to_be_bytes().to_vec();
    f.extend(b);
    f
}

#[test]
fn duplicated_kafka_records_leak_nothing_new() {
    let mut hs = 5i16.to_be_bytes().to_vec();
    hs.extend_from_slice(b"PLAIN");
    let mut hs_resp = 0i16.to_be_bytes().to_vec();
    hs_resp.extend(1i32.to_be_bytes());
    hs_resp.extend(5i16.to_be_bytes());
    hs_resp.extend_from_slice(b"PLAIN");
    let token = b"\0alice\0Sx5Pw4mNbVc";
    let mut auth = (token.len() as i32).to_be_bytes().to_vec();
    auth.extend_from_slice(token);
    let mut auth_resp = 0i16.to_be_bytes().to_vec();
    auth_resp.extend((-1i16).to_be_bytes());
    auth_resp.extend(0i32.to_be_bytes());
    let secrets = ["Sx5Pw4mNbVc"];
    check(
        Protocol::Kafka,
        &[
            c(&kafka_req(17, 1, 1, &hs)),
            s(&kafka_resp(1, &hs_resp)),
            c(&kafka_req(36, 0, 2, &auth)),
            s(&kafka_resp(2, &auth_resp)),
            c(&kafka_req(18, 0, 3, b"")),
            s(&kafka_resp(3, &[0, 0, 0, 0, 0, 0])),
        ],
        &secrets,
    );
}

fn amqp_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![kind, 0, 1];
    f.extend((payload.len() as u32).to_be_bytes());
    f.extend_from_slice(payload);
    f.push(0xCE);
    f
}

#[test]
fn duplicated_amqp_records_leak_nothing_new() {
    let body = br#"{"password":"Sx6Bd5vCxZa"}"#;
    let mut args = vec![0, 0, 0, 4];
    args.extend_from_slice(b"jobs");
    args.push(0);
    let mut m = vec![0, 60, 0, 40];
    m.extend(args);
    let mut h = vec![0, 60, 0, 0];
    h.extend((body.len() as u64).to_be_bytes());
    h.extend(0x8000u16.to_be_bytes());
    h.push(16);
    h.extend_from_slice(b"application/json");
    let mut start_ok = vec![0, 10, 0, 11, 0, 0, 0, 0, 5];
    start_ok.extend_from_slice(b"PLAIN");
    let resp = b"\0alice\0Sx6Pw2nMbVq";
    start_ok.extend((resp.len() as u32).to_be_bytes());
    start_ok.extend_from_slice(resp);
    start_ok.extend([5]);
    start_ok.extend_from_slice(b"en_US");
    let secrets = ["Sx6Bd5vCxZa", "Sx6Pw2nMbVq"];
    check(
        Protocol::Amqp,
        &[
            c(b"AMQP\x00\x00\x09\x01"),
            c(&amqp_frame(1, &start_ok)),
            c(&[amqp_frame(1, &m), amqp_frame(2, &h), amqp_frame(3, body)].concat()),
        ],
        &secrets,
    );
}

fn h2_frame(t: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut f = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8, t, flags];
    f.extend(stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

#[test]
fn duplicated_http2_records_leak_nothing_new() {
    let mut enc = hpack::Encoder::new();
    let req = enc.encode(vec![
        (&b":method"[..], &b"POST"[..]),
        (b":path", b"/api/token/Sx7Pa1sDfGh"),
        (b"authorization", b"Bearer Sx7Ah3jKlZx"),
        (b"content-type", b"application/json"),
    ]);
    let mut senc = hpack::Encoder::new();
    let rsp = senc.encode(vec![
        (&b":status"[..], &b"200"[..]),
        (b"content-type", b"application/json"),
        (b"set-cookie", b"s=Sx7Sc6vBnMq"),
    ]);
    let mut client = super::detect::HTTP2_PREFACE.to_vec();
    client.extend(h2_frame(0x4, 0, 0, &[]));
    client.extend(h2_frame(0x1, 0x4, 1, &req));
    client.extend(h2_frame(0x0, 0x1, 1, br#"{"password":"Sx7Dp8wErTy"}"#));
    let mut server = h2_frame(0x4, 0, 0, &[]);
    server.extend(h2_frame(0x1, 0x4, 1, &rsp));
    server.extend(h2_frame(0x0, 0x1, 1, br#"{"api_key":"Sx7Rk4tYuIo"}"#));
    let secrets = [
        "Sx7Pa1sDfGh",
        "Sx7Ah3jKlZx",
        "Sx7Sc6vBnMq",
        "Sx7Dp8wErTy",
        "Sx7Rk4tYuIo",
    ];
    for proto in [Protocol::Http2, Protocol::Grpc] {
        let base = check(proto, &[c(&client), s(&server)], &secrets);
        assert!(base.is_empty(), "{base:?}");
    }
}
