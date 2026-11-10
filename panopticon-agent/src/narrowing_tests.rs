//! Narrowing tests without a kernel (DESIGN §10 T-2, user-space part):
//! real pipelines with every sink on (JSON file, PII audit log, raw
//! capture, OTLP to a local tonic collector, gated logs), fed synthetic
//! `DataEvent`s through the ring readers' admission path, narrowed mid
//! stream with the test pause points. Pass: after the change is reported
//! applied, nothing captured under the old generation reaches any output.
//!
//! One collector and one long-lived client connection per test.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use panopticon_common::{DataEvent, Direction, EventType, TCP_FLAG_ACK};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::config::{AgentConfig, PrivacyGate, PrivacyMode};
use crate::event_loop::{AdmissionFloor, RateLimiter};
use crate::pipeline::{Scope, Shared};
use crate::test_hooks;

// ── A fake OTLP collector that records every byte it receives ──────────

struct Recorder {
    io: tokio::net::TcpStream,
    seen: Arc<Mutex<Vec<u8>>>,
    reads: Arc<ReadGate>,
}

/// Whether the collector reads its sockets yet (a paused collector leaves
/// the agent's request bytes in its own buffers, as a slow peer would).
#[derive(Default)]
struct ReadGate {
    paused: std::sync::atomic::AtomicBool,
    waiting: Mutex<Vec<std::task::Waker>>,
}

impl ReadGate {
    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
        for w in self.waiting.lock().unwrap().drain(..) {
            w.wake();
        }
    }
}

impl AsyncRead for Recorder {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.reads.paused.load(Ordering::SeqCst) {
            this.reads.waiting.lock().unwrap().push(cx.waker().clone());
            if this.reads.paused.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        let before = buf.filled().len();
        let r = Pin::new(&mut this.io).poll_read(cx, buf);
        this.seen
            .lock()
            .unwrap()
            .extend_from_slice(&buf.filled()[before..]);
        r
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl tonic::transport::server::Connected for Recorder {
    type ConnectInfo = ();
    fn connect_info(&self) {}
}

/// How the collector answers.
#[derive(Clone, Copy, PartialEq)]
enum Reply {
    Accept,
    /// Never answer.
    Hang,
    /// Raw HTTP/2: send the response headers, then never the body or the
    /// trailers.
    Stall,
    /// As `Stall`, and read nothing until resumed.
    Paused,
}

struct Accept {
    reply: Reply,
}

#[tonic::async_trait]
impl opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceService
    for Accept
{
    async fn export(
        &self,
        _request: tonic::Request<
            opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest,
        >,
    ) -> Result<
        tonic::Response<
            opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceResponse,
        >,
        tonic::Status,
    > {
        if self.reply == Reply::Hang {
            std::future::pending::<()>().await;
        }
        Ok(tonic::Response::new(Default::default()))
    }
}

/// A local OTLP collector: its endpoint, the bytes it received, a writable
/// clone of each accepted socket (to inject raw frames), and its reads.
struct Collector {
    endpoint: String,
    port: u16,
    seen: Arc<Mutex<Vec<u8>>>,
    conns: Arc<Mutex<Vec<std::net::TcpStream>>>,
    reads: Arc<ReadGate>,
}

/// Start the collector.
async fn collector(reply: Reply) -> Collector {
    use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceServiceServer;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let conns = Arc::new(Mutex::new(Vec::new()));
    let reads = Arc::new(ReadGate::default());
    reads.paused.store(reply == Reply::Paused, Ordering::SeqCst);
    let (s, c, r) = (Arc::clone(&seen), Arc::clone(&conns), Arc::clone(&reads));
    let accept = move |io: tokio::net::TcpStream| {
        let std = io.into_std().unwrap();
        c.lock().unwrap().push(std.try_clone().unwrap());
        Recorder {
            io: tokio::net::TcpStream::from_std(std).unwrap(),
            seen: Arc::clone(&s),
            reads: Arc::clone(&r),
        }
    };
    if matches!(reply, Reply::Stall | Reply::Paused) {
        tokio::spawn(async move {
            while let Ok((io, _)) = listener.accept().await {
                tokio::spawn(h2_stalling(accept(io)));
            }
        });
    } else {
        let incoming = futures_util::stream::unfold(listener, move |l| {
            let accept = accept.clone();
            async move { Some((l.accept().await.map(|(io, _)| accept(io)), l)) }
        });
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(Accept { reply }))
                .serve_with_incoming(incoming),
        );
    }
    Collector {
        endpoint,
        port,
        seen,
        conns,
        reads,
    }
}

/// Serve one HTTP/2 connection: read each request whole (granting the
/// client flow-control credit), answer with response headers only, and
/// never send the body or the trailers.
async fn h2_stalling(io: Recorder) {
    let Ok(mut conn) = h2::server::handshake(io).await else {
        return;
    };
    while let Some(Ok((req, mut respond))) = conn.accept().await {
        tokio::spawn(async move {
            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let _stream = respond.send_response(response, false);
            let mut body = req.into_body();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
            }
            std::future::pending::<()>().await; // keep the stream open
        });
    }
}

/// An HTTP/2 GOAWAY frame (error INTERNAL_ERROR, no stream processed)
/// carrying `debug` as its debug data.
fn goaway(debug: &[u8]) -> Vec<u8> {
    let len = 8 + debug.len();
    let mut f = vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        0x7,
        0,
        0,
        0,
        0,
        0,
    ];
    f.extend_from_slice(&0u32.to_be_bytes());
    f.extend_from_slice(&2u32.to_be_bytes());
    f.extend_from_slice(debug);
    f
}

// ── The environment: every sink on ─────────────────────────────────────

/// The process-wide log subscriber of the test binary, at every level,
/// writing into a buffer: what the agent would print outside any pipeline
/// (its global subscriber writes to stdout). Installed once; the agent's
/// own code never installs one in tests.
fn global_log() -> &'static Mutex<Vec<u8>> {
    static GLOBAL_LOG: std::sync::OnceLock<Mutex<Vec<u8>>> = std::sync::OnceLock::new();
    let mut fresh = false;
    let buf = GLOBAL_LOG.get_or_init(|| {
        fresh = true;
        Mutex::new(Vec::new())
    });
    if fresh {
        struct W;
        impl std::io::Write for W {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                if child() {
                    std::io::stdout().write_all(b)?;
                }
                global_log().lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sub = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_thread_names(true)
            .with_ansi(false)
            .with_writer(|| W)
            .finish();
        tracing::subscriber::set_global_default(sub).expect("no other global subscriber");
    }
    buf
}

struct Env {
    dir: PathBuf,
    scope: Arc<Scope>,
    floor: AdmissionFloor,
    shared: Arc<Shared>,
    rate: RateLimiter,
    logs: Arc<Mutex<Vec<u8>>>,
    otlp: Arc<Mutex<Vec<u8>>>,
    collector: Collector,
}

fn tmpdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("panopticon-t2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config(dir: &Path, otlp: &str) -> AgentConfig {
    let mut c = AgentConfig::default();
    let path = |f: &str| Some(dir.join(f).to_string_lossy().into_owned());
    c.json_export_path = path("events.jsonl");
    c.pii_audit_log_path = path("audit.jsonl");
    c.capture_raw_path = path("raw.pncap");
    c.privacy_mode = PrivacyMode::Full;
    c.log_events = true;
    c.otlp.enabled = true;
    c.otlp.endpoint = otlp.to_string();
    c.max_worker_count = 2;
    c.worker_channel_capacity = 4096;
    c
}

impl Env {
    async fn new(name: &str) -> Self {
        Self::with(name, "info", Reply::Accept).await
    }

    /// `log_filter`: the pipelines' log filter; `reply`: the collector's.
    async fn with(name: &str, log_filter: &str, reply: Reply) -> Self {
        global_log();
        let dir = tmpdir(name);
        let collector = collector(reply).await;
        let otlp = Arc::clone(&collector.seen);
        let cfg = config(&dir, &collector.endpoint);
        let privacy = Arc::new(PrivacyGate::new(cfg.privacy_mode));
        let mut shared = Shared::open(cfg, privacy, None, log_filter.to_string()).unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let l = Arc::clone(&logs);
        if !child() {
            shared.log_sink = Arc::new(move |b: &[u8]| l.lock().unwrap().extend_from_slice(b));
        }
        let shared = Arc::new(shared);
        let floor = AdmissionFloor::default();
        let scope = Scope::start(Arc::clone(&shared), floor.clone()).unwrap();
        Self {
            dir,
            scope,
            floor,
            shared,
            rate: RateLimiter::new(0),
            logs,
            otlp,
            collector,
        }
    }

    /// One drained batch through the ring readers' admission path.
    fn feed(&self, events: &[DataEvent]) {
        let slot = self.scope.slot();
        let mut a = crate::event_loop::Admission::new(&slot, &self.floor, &self.shared.stats, 0, 1);
        for e in events {
            a.offer(e, &self.rate);
        }
        a.finish();
    }

    /// The output file and every file it rotated into (`<name>.<n>`), in
    /// order: what the agent wrote under that path.
    fn file(&self, name: &str) -> Vec<u8> {
        let mut out = std::fs::read(self.dir.join(name)).unwrap_or_default();
        for n in 1.. {
            match std::fs::read(self.dir.join(format!("{name}.{n}"))) {
                Ok(b) => out.extend_from_slice(&b),
                Err(_) => break,
            }
        }
        out
    }

    /// Every output, by name. `global` is everything logged through the
    /// process-wide subscriber (the agent's stdout outside pipelines), by
    /// every test (its markers are unique per test); `socket` every byte the
    /// pipelines' gated sockets wrote to this test's collector. (Real stdout/stderr: see
    /// `process_streams_carry_nothing_old_after_applied`.)
    fn outputs(&self) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("json", self.file("events.jsonl")),
            ("audit", self.file("audit.jsonl")),
            ("raw", self.file("raw.pncap")),
            ("logs", self.logs.lock().unwrap().clone()),
            ("otlp", self.otlp.lock().unwrap().clone()),
            ("global", global_log().lock().unwrap().clone()),
            ("socket", test_hooks::tapped(self.collector.port)),
        ]
    }

    /// Output lengths now, to check what is written after this point.
    fn marks(&self) -> Vec<usize> {
        self.outputs().iter().map(|(_, b)| b.len()).collect()
    }

    /// Wait until every output named in `sinks` contains `needle`.
    async fn wait_for(&self, needle: &str, sinks: &[&str]) {
        self.wait_for_within(needle, sinks, Duration::from_secs(10))
            .await
    }

    async fn wait_for_within(&self, needle: &str, sinks: &[&str], limit: Duration) {
        for _ in 0..limit.as_millis() / 50 {
            if self
                .outputs()
                .iter()
                .filter(|(n, _)| sinks.contains(n))
                .all(|(_, b)| contains(b, needle))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let missing: Vec<_> = self
            .outputs()
            .into_iter()
            .filter(|(n, b)| sinks.contains(n) && !contains(b, needle))
            .map(|(n, _)| n)
            .collect();
        panic!("{needle} never reached {missing:?}");
    }

    /// No output holds `needle` anywhere.
    fn assert_absent(&self, needle: &str) {
        for (name, bytes) in self.outputs() {
            assert!(!contains(&bytes, needle), "{needle} reached {name}");
        }
    }

    /// Nothing written after `marks` holds `needle`.
    /// A marker straddling the mark counts as written after it.
    fn assert_absent_after(&self, marks: &[usize], needle: &str) {
        self.assert_absent_after_except(marks, needle, &[]);
    }

    /// As [`assert_absent_after`](Self::assert_absent_after), skipping the
    /// outputs named in `skip`.
    fn assert_absent_after_except(&self, marks: &[usize], needle: &str, skip: &[&str]) {
        for ((name, bytes), &at) in self.outputs().iter().zip(marks) {
            if skip.contains(name) {
                continue;
            }
            let from = at.saturating_sub(needle.len().saturating_sub(1));
            let after = &bytes[from.min(bytes.len())..];
            assert!(
                !contains(after, needle),
                "{needle} reached {name} after applied"
            );
        }
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

// ── Synthetic events ───────────────────────────────────────────────────

const CLIENT: u32 = 0x0A63_0002; // 10.99.0.2
const SERVER: u32 = 0x0A63_0001; // 10.99.0.1

fn packet(from: (u32, u16), to: (u32, u16), proto: u8, payload: &[u8], gen_: u32) -> DataEvent {
    // SAFETY: all-zero is a valid DataEvent (every enum has a 0 variant).
    let mut e: DataEvent = unsafe { std::mem::zeroed() };
    e.event_type = EventType::TcPacket;
    e.direction = if from.0 == CLIENT {
        Direction::Ingress
    } else {
        Direction::Egress
    };
    (e.src_addr, e.src_port, e.dst_addr, e.dst_port) = (from.0, from.1, to.0, to.1);
    e.ip_proto = proto;
    e.socket_cookie = panopticon_common::tc_flow_cookie(0, from.0, to.0, from.1, to.1, proto);
    e.payload[..payload.len()].copy_from_slice(payload);
    (e.payload_len, e.orig_len) = (payload.len() as u32, payload.len() as u32);
    e.scope_gen = gen_;
    e.timestamp_ns = 1;
    e
}

/// An HTTP exchange on its own connection to `SERVER:port`: the request
/// path is `/<marker>` and carries an email address (so the audit log gets
/// a line naming `SERVER:port`).
fn exchange(marker: &str, port: u16, gen_: u32) -> Vec<DataEvent> {
    exchange_to(SERVER, marker, port, gen_)
}

fn exchange_to(server: u32, marker: &str, port: u16, gen_: u32) -> Vec<DataEvent> {
    let req = format!("GET /{marker}?u=a.person@example.com HTTP/1.1\r\nHost: shop\r\n\r\n");
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    tcp_exchange(
        (CLIENT, 40_000 + port % 20_000),
        (server, port),
        req.as_bytes(),
        resp,
        gen_,
    )
}

/// One request and its response on a fresh TCP connection.
fn tcp_exchange(
    cli: (u32, u16),
    srv: (u32, u16),
    req: &[u8],
    resp: &[u8],
    gen_: u32,
) -> Vec<DataEvent> {
    let mut a = packet(cli, srv, 6, req, gen_);
    (a.tcp_seq, a.tcp_ack, a.tcp_flags) = (100, 900, TCP_FLAG_ACK);
    let mut b = packet(srv, cli, 6, resp, gen_);
    (b.tcp_seq, b.tcp_ack, b.tcp_flags) = (900, 100 + req.len() as u32, TCP_FLAG_ACK);
    vec![a, b]
}

/// Outputs that carry the request path (the audit log names the server).
const PATHS: &[&str] = &["json", "raw", "logs", "otlp"];
const WAIT: Duration = Duration::from_secs(10);

// ── Tests ──────────────────────────────────────────────────────────────

/// A hung test aborts the test process (with its name) instead of
/// blocking CI.
const HANG: Duration = Duration::from_secs(120);

/// Run `body` on a fresh multi-threaded runtime of `workers` threads,
/// under a watchdog that also covers the runtime's shutdown.
fn t2(name: &'static str, workers: usize, body: impl std::future::Future<Output = ()>) {
    let (alive, done) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = done.recv_timeout(HANG) {
            eprintln!("{name}: still running after {HANG:?}; aborting");
            std::process::abort();
        }
    });
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(body);
    drop(rt);
    drop(alive);
}

/// A worker paused after admission, before its sink hand-off, and an
/// old-generation event at the ring read after the change: neither leaves.
#[test]
fn paused_worker_and_stale_events_reach_no_output_after_applied() {
    t2(
        "paused_worker_and_stale_events_reach_no_output_after_applied",
        4,
        async {
            let env = Env::new("worker").await;
            env.feed(&exchange("old-before", 18001, 1));
            env.wait_for("old-before", PATHS).await;
            env.wait_for(":18001", &["audit"]).await;

            let old = env.scope.gate().await.unwrap();
            let hook = test_hooks::arm(test_hooks::WORKER_BEFORE_SINK, &old);
            env.feed(&exchange("old-held", 18002, 1));
            assert!(
                hook.wait_reached(WAIT),
                "worker never reached the pause point"
            );

            assert!(env.scope.narrow(2).await, "a new pipeline is installed");
            let applied = env.marks();
            assert!(old.is_revoked());
            drop(hook); // the worker resumes with the old event

            env.feed(&exchange("old-stale", 18003, 1));
            env.feed(&exchange("new-after", 18004, 2));
            env.wait_for("new-after", PATHS).await;
            env.wait_for(":18004", &["audit"]).await;
            tokio::time::sleep(Duration::from_millis(500)).await;

            for marker in ["old-held", "old-stale", ":18002", ":18003"] {
                env.assert_absent(marker);
            }
            env.assert_absent_after(&applied, "old-");
            env.assert_absent_after(&applied, ":18001");
            assert!(
                env.shared
                    .stats
                    .drops_stale_scope_gen
                    .load(Ordering::Relaxed)
                    >= 2
            );
            env.scope.shutdown().await;
        },
    );
}

/// The connections a discarded pipeline tracked leave the
/// `active_connections` gauge; the new pipeline's are counted.
#[test]
fn narrowing_releases_the_old_pipelines_connections() {
    t2(
        "narrowing_releases_the_old_pipelines_connections",
        4,
        async {
            let env = Env::new("gauge").await;
            let active = || env.shared.stats.active_connections.load(Ordering::Relaxed);
            for port in [18091, 18092, 18093] {
                env.feed(&exchange("old-open", port, 1));
            }
            env.wait_for(":18093", &["audit"]).await;
            assert_eq!(active(), 3, "three open connections");
            env.scope.narrow(2).await;
            for _ in 0..200 {
                if active() == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(active(), 0, "the old pipeline's connections are gone");
            env.feed(&exchange("new-open", 18094, 2));
            env.wait_for(":18094", &["audit"]).await;
            assert_eq!(active(), 1);
            env.scope.shutdown().await;
            assert_eq!(active(), 0, "a drained pipeline leaves nothing either");
        },
    );
}

/// A ring reader paused after admitting an event, its batch pending across
/// the swap: the batch keeps its (revoked) destination.
#[test]
fn reader_paused_after_admission_keeps_its_old_destination() {
    t2(
        "reader_paused_after_admission_keeps_its_old_destination",
        4,
        async {
            let env = Arc::new(Env::new("reader").await);
            env.feed(&exchange("old-before", 18011, 1));
            env.wait_for("old-before", PATHS).await;

            let old = env.scope.gate().await.unwrap();
            let hook = test_hooks::arm(test_hooks::READER_AFTER_ADMISSION, &old);
            let e = Arc::clone(&env);
            let reader = std::thread::spawn(move || e.feed(&exchange("old-pending", 18012, 1)));
            assert!(
                hook.wait_reached(WAIT),
                "reader never reached the pause point"
            );

            env.scope.narrow(2).await;
            let applied = env.marks();
            drop(hook);
            reader.join().unwrap();

            env.feed(&exchange("new-after", 18013, 2));
            env.wait_for("new-after", PATHS).await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            env.assert_absent("old-pending");
            env.assert_absent(":18012");
            env.assert_absent_after(&applied, "old-");
            env.scope.shutdown().await;
        },
    );
}

/// An OTLP export writing to its socket when the change lands (paused
/// before the socket gate), and the old SDK's shutdown export: refused.
#[test]
fn in_flight_otlp_export_is_refused_after_applied() {
    t2("in_flight_otlp_export_is_refused_after_applied", 4, async {
        let env = Env::new("otlp").await;
        env.feed(&exchange("old-before", 18021, 1));
        env.wait_for("old-before", PATHS).await;

        let old = env.scope.gate().await.unwrap();
        let hook = test_hooks::arm(test_hooks::OTLP_IN_FLIGHT_EXPORT, &old);
        env.feed(&exchange("old-inflight", 18022, 1));
        env.wait_for("old-inflight", &["json", "logs"]).await;
        assert!(
            hook.wait_reached(WAIT),
            "no OTLP write reached the pause point"
        );

        env.scope.narrow(2).await;
        let applied = env.marks();
        drop(hook);

        env.feed(&exchange("new-after", 18023, 2));
        env.wait_for("new-after", &["otlp"]).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        env.assert_absent_after(&applied, "old-");
        assert!(!contains(&env.otlp.lock().unwrap(), "old-inflight"));
        env.scope.shutdown().await;
    });
}

/// The process-wide log's lines that hold `needle` (up to three).
fn global_lines_with(needle: &str) -> Vec<String> {
    String::from_utf8_lossy(&global_log().lock().unwrap())
        .lines()
        .filter(|l| l.contains(needle))
        .take(3)
        .map(|l| l.chars().take(400).collect())
        .collect()
}

/// An export in flight across the change fails after it is applied with a
/// collector error that quotes captured data (an HTTP/2 GOAWAY whose debug
/// data carries the marker, which tonic's decoder logs with the failed
/// stream's status). The pipelines log at every level. The error reaches
/// only the old pipeline's (revoked) log: never the process-wide log, never
/// any output. Positive control: the same error on the new pipeline's
/// export reaches the new pipeline's log.
#[test]
fn otlp_errors_log_only_through_the_pipeline() {
    t2("otlp_errors_log_only_through_the_pipeline", 4, async {
        let env = Env::with("otlp-errors", "trace", Reply::Stall).await;
        env.feed(&exchange("goaway-old", 18101, 1));
        // The request is read and answered with headers; the body stalls.
        env.wait_for("goaway-old", &["otlp"]).await;
        env.scope.narrow(2).await;
        let applied = env.marks();
        let inject = |debug: &[u8]| {
            use std::io::Write;
            let conns = env.collector.conns.lock().unwrap();
            conns
                .last()
                .unwrap()
                .try_clone()
                .unwrap()
                .write_all(&goaway(debug))
                .unwrap();
        };
        inject(b"collector error quoting goaway-old-echo");
        tokio::time::sleep(Duration::from_millis(500)).await;

        env.feed(&exchange("goaway-new", 18102, 2));
        env.wait_for("goaway-new", &["otlp"]).await;
        inject(b"collector error quoting goaway-new-echo");
        env.wait_for("goaway-new-echo", &["logs"]).await;

        env.assert_absent_after(&applied, "goaway-old");
        let leaked = global_lines_with("goaway-");
        assert!(
            leaked.is_empty(),
            "reached the process-wide log: {leaked:#?}"
        );
        let bsp = global_lines_with("OpenTelemetry.Traces.BatchProcessor");
        assert!(
            bsp.is_empty(),
            "the SDK batch thread logged globally: {bsp:?}"
        );
        env.scope.shutdown().await;
    });
}

/// A collector that sends the response headers and then stalls the body
/// does not hold the exporter: the export's deadline ends it and the next
/// batch is exported.
#[test]
fn a_stalled_response_body_does_not_hold_the_exporter() {
    t2(
        "a_stalled_response_body_does_not_hold_the_exporter",
        4,
        async {
            let env = Env::with("otlp-stall", "info", Reply::Stall).await;
            env.feed(&exchange("stall-first", 18141, 1));
            env.wait_for("stall-first", &["otlp"]).await;
            env.feed(&exchange("stall-second", 18142, 1));
            env.wait_for_within("stall-second", &["otlp"], Duration::from_secs(20))
                .await;
            env.scope.shutdown().await;
        },
    );
}

/// A full SDK queue and an in-flight export blocked by the collector (it
/// reads nothing: the request's bytes wait in the agent's HTTP/2 buffers)
/// across the change. After applied nothing of the old generation leaves
/// through any socket, any file or any log, even once the collector reads
/// again and grants the credit the old connection was waiting for.
#[test]
fn a_blocked_export_and_a_full_queue_send_nothing_after_applied() {
    t2(
        "a_blocked_export_and_a_full_queue_send_nothing_after_applied",
        4,
        async {
            let env = Env::with("otlp-backlog", "info", Reply::Paused).await;
            // Past the SDK queue (2048 spans) and many times the 64 KiB a
            // connection may send unacknowledged.
            for i in 0..2500u16 {
                env.feed(&exchange("old-backlog", 20000 + i, 1));
            }
            env.wait_for("old-backlog", &["socket"]).await;
            // The premise: writes are blocked with the batch part-sent, its
            // remaining bytes retained in the agent's HTTP/2 buffers.
            let sent = || {
                String::from_utf8_lossy(&test_hooks::tapped(env.collector.port))
                    .matches("old-backlog")
                    .count()
            };
            let before = sent();
            tokio::time::sleep(Duration::from_secs(1)).await;
            assert_eq!(sent(), before, "writes are not blocked");
            assert!(before < 512, "the whole batch was sent ({before} spans)");
            env.scope.narrow(2).await;
            let applied = env.marks();
            env.collector.reads.resume();
            env.feed(&exchange("new-after", 18151, 2));
            env.wait_for_within("new-after", &["socket"], Duration::from_secs(20))
                .await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            // The collector's own copy may show bytes written before
            // applied that sat in the kernel; `socket` is what left the
            // agent, and when.
            env.assert_absent_after_except(&applied, "old-backlog", &["otlp"]);
            env.scope.shutdown().await;
        },
    );
}

/// A DNS query and its answer, `name` -> `ip`, on the resolver's UDP flow.
fn dns_exchange(name: &str, ip: u32, id: u16, gen_: u32) -> Vec<DataEvent> {
    use crate::protocol::dns::test_helpers::{
        build_dns_query, build_dns_response, encode_dns_name,
    };
    let resolver = (0x0A63_0035, 53);
    let cli = (CLIENT, 5300 + id);
    let q = packet(cli, resolver, 17, &build_dns_query(id, name, 1), gen_);
    let rdata = ip.to_be_bytes();
    let answer = build_dns_response(id, 0, name, 1, &[(&encode_dns_name(name), 1, 300, &rdata)]);
    vec![q, packet(resolver, cli, 17, &answer, gen_)]
}

/// A hostname the old pipeline retains (its DNS cache) never names a flow
/// the new pipeline exports, even when the old worker inserts it after the
/// change is applied and before the new flow is looked up.
#[test]
fn dns_answer_inserted_after_applied_names_nothing_new() {
    t2(
        "dns_answer_inserted_after_applied_names_nothing_new",
        4,
        async {
            let env = Env::new("dns").await;
            // Positive control: a name the pipeline learned names its flows.
            let other = 0x0A63_0007;
            env.feed(&dns_exchange("seen-dns.example", other, 6, 1));
            env.wait_for("seen-dns.example", &["json"]).await; // the answer
            env.feed(&exchange_to(other, "old-before", 18031, 1));
            env.wait_for("old-before", PATHS).await;
            env.wait_for("seen-dns.example", &["audit"]).await; // names the flow

            // old-dns.example -> SERVER, inserted by the old pipeline only once
            // the change is applied.
            let old = env.scope.gate().await.unwrap();
            let before = test_hooks::arm(test_hooks::BEFORE_DNS_INSERT, &old);
            let after = test_hooks::arm(test_hooks::AFTER_DNS_INSERT, &old);
            env.feed(&dns_exchange("old-dns.example", SERVER, 7, 1));
            assert!(
                before.wait_reached(WAIT),
                "worker never reached the DNS insert"
            );
            env.scope.narrow(2).await;
            let applied = env.marks();
            drop(before);
            assert!(
                after.wait_reached(WAIT),
                "the old worker never inserted the answer"
            );
            drop(after);

            env.feed(&exchange("new-after", 18032, 2));
            env.wait_for(":18032", &["audit"]).await;
            env.wait_for("new-after", &["json"]).await;
            env.assert_absent_after(&applied, "old-dns");
            env.assert_absent_after(&applied, "seen-dns");
            env.assert_absent_after(&applied, "old-");
            env.scope.shutdown().await;
        },
    );
}

/// A worker holds a service name it resolved from the old pipeline's DNS
/// cache (a local, before the audit entries carrying it are written) across
/// the change: the name is written nowhere after applied. Positive control:
/// the same name names the flow's audit entry before the change.
#[test]
fn a_hostname_held_by_an_old_worker_is_written_nowhere_after_applied() {
    t2(
        "a_hostname_held_by_an_old_worker_is_written_nowhere_after_applied",
        4,
        async {
            let env = Env::new("held-name").await;
            let other = 0x0A63_0008;
            env.feed(&dns_exchange("held-name.example", other, 9, 1));
            env.wait_for("held-name.example", &["json"]).await; // the answer
            env.feed(&exchange_to(other, "old-control", 18161, 1));
            env.wait_for(":18161", &["audit"]).await;
            assert!(
                contains(&env.file("audit.jsonl"), "held-name.example"),
                "the audit entry names the server"
            );

            let old = env.scope.gate().await.unwrap();
            let hook = test_hooks::arm(test_hooks::WORKER_HOLDING_RESOLVED, &old);
            env.feed(&exchange_to(other, "old-held", 18162, 1));
            assert!(hook.wait_reached(WAIT), "worker never resolved the name");
            env.scope.narrow(2).await;
            let applied = env.marks();
            drop(hook); // the worker resumes, holding the old name

            env.feed(&exchange_to(other, "new-after", 18163, 2));
            env.wait_for(":18163", &["audit"]).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            env.assert_absent_after(&applied, "held-name");
            env.assert_absent_after(&applied, ":18162");
            env.scope.shutdown().await;
        },
    );
}

/// An old audit write is torn (the output continues in `audit.jsonl.1`),
/// then an old worker held across the change resumes: it writes nothing
/// into the rotated file, while the new pipeline does.
#[test]
fn a_torn_old_audit_write_then_a_held_worker_write_nothing_after_applied() {
    t2(
        "a_torn_old_audit_write_then_a_held_worker_write_nothing_after_applied",
        4,
        async {
            let env = Env::new("torn").await;
            let rotated = env.dir.join("audit.jsonl.1");
            env.shared.audit.as_ref().unwrap().fail_next_write_after(10);
            env.feed(&exchange("old-torn", 18171, 1));
            env.wait_for("old-torn", &["json"]).await;
            for _ in 0..100 {
                if rotated.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(rotated.exists(), "the torn write did not rotate");

            let old = env.scope.gate().await.unwrap();
            let hook = test_hooks::arm(test_hooks::WORKER_HOLDING_RESOLVED, &old);
            env.feed(&exchange("old-held", 18172, 1));
            assert!(hook.wait_reached(WAIT), "worker never reached the audit");
            env.scope.narrow(2).await;
            let applied = env.marks();
            drop(hook);

            env.feed(&exchange("new-after", 18173, 2));
            env.wait_for(":18173", &["audit"]).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            let continued = std::fs::read(&rotated).unwrap();
            assert!(contains(&continued, ":18173"), "the new pipeline writes on");
            assert!(!contains(&env.file("audit.jsonl"), ":18172"));
            env.assert_absent_after(&applied, "old-");
            env.assert_absent_after(&applied, ":18171");
            env.scope.shutdown().await;
        },
    );
}

/// Set in the child process of `process_streams_carry_nothing_old_after_applied`.
const T2_CHILD: &str = "PANOPTICON_T2_CHILD";
/// Printed on stdout and stderr by the child once the change is applied.
const T2_APPLIED: &str = "T2-APPLIED";

fn child() -> bool {
    std::env::var_os(T2_CHILD).is_some()
}

/// The agent's real stdout and stderr (file descriptors 1 and 2) carry
/// nothing of the old generation after applied. A child process (this test
/// binary, running only `t2_child_process_streams`) runs a narrowing with
/// the agent's own stdout logging, global and per pipeline, at trace level,
/// and prints a delimiter on both streams once the change is applied.
/// Positive control: the old markers are on stdout before the delimiter,
/// the new one after.
#[test]
fn process_streams_carry_nothing_old_after_applied() {
    if child() {
        return;
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "narrowing_tests::t2_child_process_streams",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(T2_CHILD, "1")
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "child failed:\n{stdout}\n{stderr}");
    let split = |s: &str| {
        let at = s.find(T2_APPLIED).expect("delimiter printed");
        (s[..at].to_string(), s[at..].to_string())
    };
    let (before, after) = split(&stdout);
    assert!(
        before.contains("old-before"),
        "stdout carries the old pipeline"
    );
    assert!(
        after.contains("new-after"),
        "stdout carries the new pipeline"
    );
    for (name, after) in [("stdout", after), ("stderr", split(&stderr).1)] {
        if let Some(i) = after.find("old-") {
            let line = after[i.saturating_sub(200)..].lines().next().unwrap_or("");
            panic!("old marker on {name} after applied: {line}");
        }
    }
}

/// The child half of `process_streams_carry_nothing_old_after_applied`
/// (returns at once unless run as that child).
#[test]
fn t2_child_process_streams() {
    if !child() {
        return;
    }
    t2("t2_child_process_streams", 4, async {
        let env = Env::with("streams", "trace", Reply::Accept).await;
        env.feed(&exchange("old-before", 18181, 1));
        env.wait_for("old-before", &["json", "otlp"]).await;
        let old = env.scope.gate().await.unwrap();
        let hook = test_hooks::arm(test_hooks::WORKER_BEFORE_SINK, &old);
        env.feed(&exchange("old-held", 18182, 1));
        assert!(hook.wait_reached(WAIT), "worker never reached the sink");
        env.scope.narrow(2).await;
        {
            use std::io::Write;
            let line = format!("\n{T2_APPLIED}\n");
            std::io::stdout().write_all(line.as_bytes()).unwrap();
            std::io::stderr().write_all(line.as_bytes()).unwrap();
        }
        drop(hook);
        env.feed(&exchange("old-stale", 18183, 1));
        env.feed(&exchange("new-after", 18184, 2));
        env.wait_for("new-after", &["json", "otlp"]).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        env.scope.shutdown().await;
    });
}

/// Kafka topic names a pipeline learned (Metadata) name nothing the next
/// pipeline exports: its Fetch of the same topic ID shows the raw ID.
#[test]
fn kafka_topic_names_do_not_outlive_their_pipeline() {
    use crate::protocol::kafka::tests::{fetch_v16_exchange, metadata_v12_exchange};
    t2(
        "kafka_topic_names_do_not_outlive_their_pipeline",
        4,
        async {
            let env = Env::new("kafka").await;
            let id = [0x5au8; 16];
            let broker = (SERVER, 9092);
            let kafka = |port: u16, [req, resp]: [Vec<u8>; 2], gen_: u32| {
                tcp_exchange((CLIENT, port), broker, &req, &resp, gen_)
            };
            env.feed(&kafka(
                41001,
                metadata_v12_exchange(1, "old-topic.secret", id),
                1,
            ));
            // The Fetch runs on another connection (and worker): only once
            // the Metadata is parsed does the pipeline know the topic.
            env.wait_for("Metadata", &["json"]).await;
            env.feed(&kafka(41002, fetch_v16_exchange(2, id, "k", "v"), 1));
            env.wait_for("old-topic.secret", &["json"]).await; // the Fetch, named
            env.scope.narrow(2).await;
            let applied = env.marks();
            env.feed(&kafka(41003, fetch_v16_exchange(3, id, "k", "v"), 2));
            env.wait_for(&"5a".repeat(16), &["json"]).await;
            env.assert_absent_after(&applied, "old-topic");
            env.scope.shutdown().await;
        },
    );
}

/// An audit write of the old pipeline that failed (nothing written) is
/// never retried: the line is not written after applied.
#[test]
fn a_failed_old_audit_write_is_not_retried_after_applied() {
    t2(
        "a_failed_old_audit_write_is_not_retried_after_applied",
        4,
        async {
            let env = Env::new("auditfail").await;
            env.shared.audit.as_ref().unwrap().fail_next_write_after(0);
            env.feed(&exchange("old-unaudited", 18121, 1));
            env.wait_for("old-unaudited", &["json"]).await;
            env.scope.narrow(2).await;
            env.feed(&exchange("new-after", 18122, 2));
            env.wait_for(":18122", &["audit"]).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(!contains(&env.file("audit.jsonl"), ":18121"));
            env.scope.shutdown().await;
        },
    );
}

/// The collector never answers: an old export stays unanswered across the
/// change, and nothing of the old generation reaches the collector after
/// applied (the transport's retained bytes included) while the new
/// pipeline exports.
#[test]
fn an_unanswered_old_export_sends_nothing_after_applied() {
    t2(
        "an_unanswered_old_export_sends_nothing_after_applied",
        4,
        async {
            let env = Env::with("otlp-hang", "info", Reply::Hang).await;
            env.feed(&exchange("old-unanswered", 18131, 1));
            env.wait_for("old-unanswered", &["otlp"]).await; // sent, never answered
            env.feed(&exchange("old-queued", 18132, 1));
            env.wait_for("old-queued", &["json"]).await;
            env.scope.narrow(2).await;
            let applied = env.marks();
            env.feed(&exchange("new-after", 18133, 2));
            env.wait_for("new-after", &["otlp"]).await;
            // The old export times out (3 s in tests); the old batch thread
            // then exports what it kept queued, into the revoked gate.
            tokio::time::sleep(Duration::from_secs(5)).await;
            env.assert_absent_after(&applied, "old-");
            env.scope.shutdown().await;
        },
    );
}

/// A failed build keeps the floor raised and the old pipeline revoked;
/// readers drop until a later change builds one (Revision 1 item 7).
#[test]
fn failed_build_drops_everything_until_a_later_change_builds() {
    t2(
        "failed_build_drops_everything_until_a_later_change_builds",
        4,
        async {
            let env = Env::new("build").await;
            let old = env.scope.gate().await.unwrap();
            env.shared.fail_builds.store(1, Ordering::SeqCst);
            assert!(!env.scope.narrow(2).await);
            assert!(old.is_revoked());
            assert_eq!(env.floor.get(), 2);
            env.feed(&exchange("lost", 18041, 2));
            assert!(env.shared.stats.drops_no_pipeline.load(Ordering::Relaxed) >= 2);
            // The next change (here: none, a widening, or a narrowing) builds.
            assert!(env.scope.ensure_installed().await);
            env.feed(&exchange("new-after", 18042, 2));
            env.wait_for("new-after", PATHS).await;
            env.assert_absent("lost");
            env.scope.shutdown().await;
        },
    );
}

// ── Replay and close records (Stage A1 review) ─────────────────────────

fn replay_config(dir: &Path, toml: &str) -> AgentConfig {
    let mut c = crate::config::load_config_from_str(toml).unwrap();
    c.json_export_path = Some(dir.join("replay.jsonl").to_string_lossy().into_owned());
    c
}

async fn replay_once(dir: &Path, toml: &str) -> String {
    let cfg = replay_config(dir, toml);
    let shared =
        Shared::for_replay(cfg, Arc::new(PrivacyGate::new(PrivacyMode::Redacted))).unwrap();
    let p = crate::pipeline::Pipeline::build(&shared).unwrap();
    p.replay(&exchange("replayed", 18051, 0)).await;
    p.shutdown().await;
    std::fs::read_to_string(dir.join("replay.jsonl")).unwrap()
}

/// Replaying a recording applies the user-space scope rules even with the
/// cgroup_skb backend (no kernel decided them): rate 0 exports nothing.
#[test]
fn replay_with_cgroup_skb_applies_user_space_scope() {
    t2(
        "replay_with_cgroup_skb_applies_user_space_scope",
        2,
        async {
            let dir = tmpdir("replay");
            let cg = "[capture]\nbackend = \"cgroup_skb\"\n";
            let sampled = format!("sampling_mode = \"connection_sample\"\nsample_rate = 0.0\n{cg}");
            let out = replay_once(&dir, &sampled).await;
            assert!(!out.contains("replayed"), "{out}");
            // Positive control: the same recording unscoped is exported.
            let out = replay_once(&dir, cg).await;
            assert!(out.contains("replayed"), "{out}");
            std::fs::remove_dir_all(&dir).ok();
        },
    );
}

/// Live cgroup_skb close records free state, count as processed and reach
/// no output.
#[test]
fn live_close_records_are_counted_and_reach_no_output() {
    t2(
        "live_close_records_are_counted_and_reach_no_output",
        4,
        async {
            let dir = tmpdir("close");
            let collector = collector(Reply::Accept).await;
            let mut cfg = config(&dir, &collector.endpoint);
            cfg.capture_backend = crate::config::CaptureBackend::CgroupSkb;
            let shared = Arc::new(
                Shared::open(
                    cfg,
                    Arc::new(PrivacyGate::new(PrivacyMode::Full)),
                    None,
                    "info".into(),
                )
                .unwrap(),
            );
            let floor = AdmissionFloor::default();
            let scope = Scope::start(Arc::clone(&shared), floor.clone()).unwrap();
            let mut close = packet((CLIENT, 40_001), (SERVER, 18061), 6, b"close-marker", 0);
            close.event_type = EventType::SockClose;
            let slot = scope.slot();
            let mut a = crate::event_loop::Admission::new(&slot, &floor, &shared.stats, 0, 1);
            a.offer(&close, &RateLimiter::new(0));
            a.finish();
            for _ in 0..100 {
                if shared.stats.events_processed.load(Ordering::Relaxed) == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(shared.stats.events_processed.load(Ordering::Relaxed), 1);
            scope.shutdown().await;
            let raw = std::fs::read(dir.join("raw.pncap")).unwrap();
            assert!(!contains(&raw, "close-marker"));
            std::fs::remove_dir_all(&dir).ok();
        },
    );
}

// ── The scope publisher ────────────────────────────────────────────────

/// In-memory `CGROUP_ALLOW` / `CONFIG`, with injected failures.
#[derive(Default)]
struct FakeMaps {
    ids: BTreeSet<u64>,
    generation: u64,
    disarmed: bool,
    fail_publish: bool,
    fail_disarm: bool,
}

#[derive(Clone, Default)]
struct Maps(Arc<Mutex<FakeMaps>>);

impl crate::scope_select::AllowMap for FakeMaps {
    fn insert(&mut self, id: u64) -> anyhow::Result<()> {
        if self.fail_publish {
            anyhow::bail!("injected insert failure");
        }
        self.ids.insert(id);
        Ok(())
    }
    fn remove(&mut self, id: u64) -> anyhow::Result<()> {
        if self.fail_publish {
            anyhow::bail!("injected remove failure");
        }
        self.ids.remove(&id);
        Ok(())
    }
    fn bump_gen(&mut self) -> anyhow::Result<()> {
        self.generation += 1;
        Ok(())
    }
    fn ids(&mut self) -> anyhow::Result<BTreeSet<u64>> {
        Ok(self.ids.clone())
    }
    fn generation(&mut self) -> anyhow::Result<u64> {
        Ok(self.generation)
    }
    fn disarm(&mut self) -> anyhow::Result<()> {
        if self.fail_disarm {
            anyhow::bail!("injected disarm failure");
        }
        self.disarmed = true;
        Ok(())
    }
}

impl crate::scope_publisher::ScopeMaps for Maps {
    fn with(
        &mut self,
        f: &mut dyn FnMut(&mut dyn crate::scope_select::AllowMap) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        f(&mut *self.0.lock().unwrap())
    }
}

/// The publisher task ending in any way while the agent runs (a panic, an
/// error, a return) is a fatal stop: kernel disarmed, pipeline revoked; a
/// failed disarm is reported with the exit error.
#[test]
fn publisher_ending_any_way_is_a_fatal_stop() {
    t2("publisher_ending_any_way_is_a_fatal_stop", 4, async {
        for (case, disarm_fails) in [("panic", false), ("return", false), ("error", true)] {
            let env = Env::new(&format!("supervise-{case}")).await;
            let maps = Maps::default();
            maps.0.lock().unwrap().fail_disarm = disarm_fails;
            let gate = env.scope.gate().await.unwrap();
            let task = tokio::spawn(async move {
                match case {
                    "panic" => panic!("a publisher bug"),
                    "return" => Ok(()),
                    _ => Err(anyhow::anyhow!("publication failed")),
                }
            });
            let e = crate::scope_publisher::supervise(task, maps.clone(), &env.scope).await;
            let e = format!("{e:#}");
            assert!(gate.is_revoked(), "{case}");
            assert!(
                env.shared.stats.capture_stopped.load(Ordering::Relaxed),
                "{case}: reported not ready"
            );
            assert!(
                env.scope.gate().await.is_none(),
                "{case}: no pipeline after"
            );
            assert_eq!(maps.0.lock().unwrap().disarmed, !disarm_fails, "{case}");
            assert_eq!(
                e.contains("disarming the kernel failed"),
                disarm_fails,
                "{e}"
            );
            env.feed(&exchange("after-stop", 18081, 0));
            assert!(env.shared.stats.drops_no_pipeline.load(Ordering::Relaxed) >= 2);
            env.scope.shutdown().await;
        }
    });
}

/// The publisher resolves cgroups with openat2 (`scope_select::resolve`):
/// Linux only.
#[cfg(target_os = "linux")]
mod publisher {
    use super::*;

    const UID_A: &str = "0f3c1a2b-4d5e-6f70-8192-a3b4c5d6e7f8";
    const UID_B: &str = "1f3c1a2b-4d5e-6f70-8192-a3b4c5d6e7f8";

    fn ino(p: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).unwrap().ino()
    }

    fn pod(name: &str, uid: &str, app: &str) -> crate::k8s::model::Pod {
        serde_json::from_value(serde_json::json!({
            "metadata": {"name": name, "namespace": "pay", "uid": uid, "labels": {"app": app}},
            "spec": {"nodeName": "n1"},
            "status": {"phase": "Running", "podIP": "10.0.0.9"}
        }))
        .unwrap()
    }

    struct PubEnv {
        env: Env,
        root: PathBuf,
        maps: Maps,
        meta: Arc<crate::k8s::K8sMetadata>,
    }

    impl PubEnv {
        async fn new(name: &str) -> Self {
            let env = Env::new(name).await;
            let root = env.dir.join("cg");
            for d in [
                "system.slice",
                "other.slice",
                &format!("kubepods/pod{UID_A}"),
                &format!("kubepods/pod{UID_B}"),
            ] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            let meta = crate::k8s::K8sMetadata::new("http://test");
            Self {
                env,
                root,
                maps: Maps::default(),
                meta,
            }
        }

        fn publisher(
            &self,
            cgroup_filter: &[String],
            pods: &[crate::config::PodFilter],
        ) -> crate::scope_publisher::Publisher<Maps> {
            crate::scope_publisher::Publisher::new(
                self.maps.clone(),
                Arc::clone(&self.env.scope),
                self.root.clone(),
                Some(Arc::clone(&self.meta)),
                Some("n1".into()),
                cgroup_filter,
                pods,
            )
            .unwrap()
        }

        fn set_pods(&self, pods: &[crate::k8s::model::Pod]) {
            self.meta.replace_pods(pods);
            self.meta.publish_if_dirty();
        }

        fn ids(&self) -> BTreeSet<u64> {
            self.maps.0.lock().unwrap().ids.clone()
        }
    }

    fn app_filter(app: &str) -> crate::config::PodFilter {
        crate::config::load_config_from_str(&format!(
        "[capture]\nbackend = \"cgroup_skb\"\n[[pod_filter]]\nnamespace = \"pay\"\nlabels = {{ app = \"{app}\" }}\n"
    ))
    .unwrap()
    .pod_filter
    .unwrap()
    .remove(0)
    }

    /// Stage A6 review, HIGH 1: a pod whose labels stop matching leaves
    /// CGROUP_ALLOW, as a narrowing (the pipeline is revoked); a pod that
    /// starts matching is added (a widening, no revocation).
    #[test]
    fn pod_label_change_narrows_and_revokes() {
        t2("pod_label_change_narrows_and_revokes", 4, async {
            let p = PubEnv::new("pods").await;
            let a = ino(&p.root.join(format!("kubepods/pod{UID_A}")));
            let b = ino(&p.root.join(format!("kubepods/pod{UID_B}")));
            p.set_pods(&[pod("a", UID_A, "co"), pod("b", UID_B, "web")]);
            let mut publisher = p.publisher(&[], &[app_filter("co")]);
            publisher.pods_changed().await.unwrap();
            assert_eq!(p.ids(), BTreeSet::from([a]));
            let first = p.env.scope.gate().await.unwrap();

            // b starts matching: widening, same pipeline.
            p.set_pods(&[pod("a", UID_A, "co"), pod("b", UID_B, "co")]);
            publisher.pods_changed().await.unwrap();
            assert_eq!(p.ids(), BTreeSet::from([a, b]));
            assert!(!first.is_revoked());

            // a's labels change: narrowing, floor raised, old pipeline revoked.
            p.set_pods(&[pod("a", UID_A, "web"), pod("b", UID_B, "co")]);
            publisher.pods_changed().await.unwrap();
            assert_eq!(p.ids(), BTreeSet::from([b]));
            assert!(first.is_revoked());
            let generation = p.maps.0.lock().unwrap().generation as u32;
            assert_eq!(p.env.floor.get(), generation);
            let second = p.env.scope.gate().await.unwrap();
            assert!(!second.is_revoked());

            // b is deleted: narrowing to nothing.
            p.set_pods(&[pod("a", UID_A, "web")]);
            publisher.pods_changed().await.unwrap();
            assert!(p.ids().is_empty());
            assert!(second.is_revoked());
            p.env.scope.shutdown().await;
        });
    }

    /// Reloads are serialised: two narrowings in either order and a widening
    /// racing a narrowing all end in the last requested set, each reported
    /// only once applied.
    #[test]
    fn reloads_are_serialised_and_reported_after_applied() {
        t2(
            "reloads_are_serialised_and_reported_after_applied",
            4,
            async {
                use crate::scope_publisher::{ScopeMsg, run};
                let p = PubEnv::new("reload").await;
                let (sys, other) = (
                    ino(&p.root.join("system.slice")),
                    ino(&p.root.join("other.slice")),
                );
                let both = vec!["system.slice".to_string(), "other.slice".to_string()];
                p.maps.0.lock().unwrap().ids = BTreeSet::from([sys, other]);
                let publisher = p.publisher(&both, &[]);
                let (tx, rx) = tokio::sync::mpsc::channel(16);
                let task = tokio::spawn(run(publisher, rx));

                let reload = |paths: &[&str]| {
                    let (reply, applied) = tokio::sync::oneshot::channel();
                    let msg = ScopeMsg::Reload {
                        cgroup_filter: Some(paths.iter().map(|s| s.to_string()).collect()),
                        pod_filter: None,
                        reply,
                    };
                    (msg, applied)
                };
                let first = p.env.scope.gate().await.unwrap();
                // Narrow to `other`, then (sent before the first is applied) to
                // `system`: processed in order, each its own revocation.
                let (m1, a1) = reload(&["other.slice"]);
                let (m2, a2) = reload(&["system.slice"]);
                tx.send(m1).await.unwrap();
                tx.send(m2).await.unwrap();
                assert_eq!(a1.await.unwrap(), Ok(()));
                assert!(
                    first.is_revoked(),
                    "reported applied only after the revocation"
                );
                assert_eq!(a2.await.unwrap(), Ok(()));
                assert_eq!(p.ids(), BTreeSet::from([sys]));

                // A widening racing a narrowing: the last one wins, the narrowing
                // revokes the pipeline the widening left in place.
                let second = p.env.scope.gate().await.unwrap();
                let (m3, a3) = reload(&["system.slice", "other.slice"]);
                let (m4, a4) = reload(&["other.slice"]);
                tx.send(m3).await.unwrap();
                tx.send(m4).await.unwrap();
                assert_eq!(a3.await.unwrap(), Ok(()));
                assert_eq!(a4.await.unwrap(), Ok(()));
                assert_eq!(p.ids(), BTreeSet::from([other]));
                assert!(second.is_revoked());
                assert_eq!(
                    p.env.floor.get(),
                    p.maps.0.lock().unwrap().generation as u32
                );

                // A selector that does not resolve is rejected; nothing changes.
                let (m5, a5) = reload(&["missing.slice"]);
                tx.send(m5).await.unwrap();
                assert!(a5.await.unwrap().is_err());
                assert_eq!(p.ids(), BTreeSet::from([other]));

                drop(tx);
                task.await.unwrap().unwrap();
                p.env.scope.shutdown().await;
            },
        );
    }

    /// The net_cls watch's narrowing is sticky: later pod changes cannot
    /// re-widen.
    #[test]
    fn net_cls_disable_is_a_sticky_narrowing() {
        t2("net_cls_disable_is_a_sticky_narrowing", 4, async {
            let p = PubEnv::new("netcls").await;
            p.set_pods(&[pod("a", UID_A, "co")]);
            let mut publisher = p.publisher(&["system.slice".into()], &[app_filter("co")]);
            publisher.pods_changed().await.unwrap();
            assert_eq!(p.ids().len(), 2);
            let first = p.env.scope.gate().await.unwrap();
            publisher
                .handle(crate::scope_publisher::ScopeMsg::Disable("test".into()))
                .await
                .unwrap();
            assert!(p.ids().is_empty());
            assert!(first.is_revoked());
            p.set_pods(&[pod("a", UID_A, "co"), pod("b", UID_B, "co")]);
            publisher.pods_changed().await.unwrap();
            assert!(p.ids().is_empty());
            p.env.scope.shutdown().await;
        });
    }

    /// Stage A6 review, HIGH 2: a failed runtime publication disarms the
    /// kernel and revokes the pipeline before the stop is logged; nothing is
    /// published afterwards. A failed disarm makes the task fail (the agent
    /// exits).
    #[test]
    fn publication_failure_is_a_fatal_capture_stop() {
        t2("publication_failure_is_a_fatal_capture_stop", 4, async {
            let p = PubEnv::new("fatal").await;
            p.set_pods(&[pod("a", UID_A, "co")]);
            let mut publisher = p.publisher(&[], &[app_filter("co")]);
            publisher.pods_changed().await.unwrap();
            let gate = p.env.scope.gate().await.unwrap();

            p.maps.0.lock().unwrap().fail_publish = true;
            p.set_pods(&[]);
            publisher.pods_changed().await.unwrap();
            assert!(publisher.is_stopped());
            assert!(p.maps.0.lock().unwrap().disarmed);
            assert!(gate.is_revoked());
            assert!(p.env.scope.gate().await.is_none());
            p.env.feed(&exchange("after-stop", 18071, 99));
            assert!(p.env.shared.stats.drops_no_pipeline.load(Ordering::Relaxed) >= 2);
            // Nothing more is published, and a reload is refused.
            p.maps.0.lock().unwrap().fail_publish = false;
            p.set_pods(&[pod("b", UID_B, "co")]);
            publisher.pods_changed().await.unwrap();
            assert_eq!(p.ids().len(), 1, "unchanged since the failure");
            let (reply, rejected) = tokio::sync::oneshot::channel();
            publisher
                .handle(crate::scope_publisher::ScopeMsg::Reload {
                    cgroup_filter: None,
                    pod_filter: Some(vec![app_filter("co")]),
                    reply,
                })
                .await
                .unwrap();
            assert!(rejected.await.unwrap().is_err());

            // Disarming fails too: the publisher reports it, for the agent to exit.
            let q = PubEnv::new("fatal2").await;
            q.set_pods(&[pod("a", UID_A, "co")]);
            let mut publisher = q.publisher(&[], &[app_filter("co")]);
            publisher.pods_changed().await.unwrap();
            {
                let mut m = q.maps.0.lock().unwrap();
                m.fail_publish = true;
                m.fail_disarm = true;
            }
            q.set_pods(&[]);
            assert!(publisher.pods_changed().await.is_err());
            assert!(
                q.env.scope.gate().await.is_none(),
                "pipeline revoked anyway"
            );
        });
    }

    /// The publisher subscribes to Kubernetes changes when it is created:
    /// a change after the first reconciliation (run by the agent before it
    /// starts the readers) and before the task runs is applied.
    #[test]
    fn a_change_before_the_task_starts_is_not_missed() {
        t2("a_change_before_the_task_starts_is_not_missed", 4, async {
            let p = PubEnv::new("startup").await;
            let a = ino(&p.root.join(format!("kubepods/pod{UID_A}")));
            let b = ino(&p.root.join(format!("kubepods/pod{UID_B}")));
            p.set_pods(&[pod("a", UID_A, "co")]);
            let mut publisher = p.publisher(&[], &[app_filter("co")]);
            publisher.pods_changed().await.unwrap();
            assert_eq!(p.ids(), BTreeSet::from([a]));
            p.set_pods(&[pod("a", UID_A, "co"), pod("b", UID_B, "co")]);
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let task = tokio::spawn(crate::scope_publisher::run(publisher, rx));
            for _ in 0..100 {
                if p.ids().len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(p.ids(), BTreeSet::from([a, b]));
            drop(tx);
            task.await.unwrap().unwrap();
            p.env.scope.shutdown().await;
        });
    }
}
