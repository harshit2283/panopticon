//! Narrowing tests without a kernel (DESIGN §10 T-2, user-space part):
//! real pipelines with every sink on (JSON file, PII audit log, raw
//! capture, OTLP to a local tonic collector, gated logs), fed synthetic
//! `DataEvent`s through the ring readers' admission path, narrowed mid
//! stream with the test pause points. Pass: after the change is reported
//! applied, nothing captured under the old generation reaches any output.
//!
//! One collector and one long-lived client connection per test.

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
}

impl AsyncRead for Recorder {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
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

struct Accept;

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
        Ok(tonic::Response::new(Default::default()))
    }
}

/// Start the collector; returns its endpoint and the bytes it received.
async fn collector() -> (String, Arc<Mutex<Vec<u8>>>) {
    use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceServiceServer;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let incoming = futures_util::stream::unfold(listener, move |l| {
        let s = Arc::clone(&s);
        async move {
            let r = l.accept().await.map(|(io, _)| Recorder { io, seen: s });
            Some((r, l))
        }
    });
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(TraceServiceServer::new(Accept))
            .serve_with_incoming(incoming),
    );
    (format!("http://{addr}"), seen)
}

// ── The environment: every sink on ─────────────────────────────────────

struct Env {
    dir: PathBuf,
    scope: Arc<Scope>,
    floor: AdmissionFloor,
    shared: Arc<Shared>,
    rate: RateLimiter,
    logs: Arc<Mutex<Vec<u8>>>,
    otlp: Arc<Mutex<Vec<u8>>>,
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
        let dir = tmpdir(name);
        let (endpoint, otlp) = collector().await;
        let cfg = config(&dir, &endpoint);
        let privacy = Arc::new(PrivacyGate::new(cfg.privacy_mode));
        let mut shared = Shared::open(cfg, privacy, None, "info".to_string()).unwrap();
        let logs = Arc::new(Mutex::new(Vec::new()));
        let l = Arc::clone(&logs);
        shared.log_sink = Arc::new(move |b: &[u8]| l.lock().unwrap().extend_from_slice(b));
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

    fn file(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(name)).unwrap_or_default()
    }

    /// Every output, by name.
    fn outputs(&self) -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("json", self.file("events.jsonl")),
            ("audit", self.file("audit.jsonl")),
            ("raw", self.file("raw.pncap")),
            ("logs", self.logs.lock().unwrap().clone()),
            ("otlp", self.otlp.lock().unwrap().clone()),
        ]
    }

    /// Output lengths now, to check what is written after this point.
    fn marks(&self) -> Vec<usize> {
        self.outputs().iter().map(|(_, b)| b.len()).collect()
    }

    /// Wait until every output named in `sinks` contains `needle`.
    async fn wait_for(&self, needle: &str, sinks: &[&str]) {
        for _ in 0..200 {
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
    fn assert_absent_after(&self, marks: &[usize], needle: &str) {
        for ((name, bytes), &at) in self.outputs().iter().zip(marks) {
            let after = &bytes[at.min(bytes.len())..];
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
    let (cli, srv) = ((CLIENT, 40_000 + port % 20_000), (SERVER, port));
    let req = format!("GET /{marker}?u=a.person@example.com HTTP/1.1\r\nHost: shop\r\n\r\n");
    let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let mut a = packet(cli, srv, 6, req.as_bytes(), gen_);
    (a.tcp_seq, a.tcp_ack, a.tcp_flags) = (100, 900, TCP_FLAG_ACK);
    let mut b = packet(srv, cli, 6, resp, gen_);
    (b.tcp_seq, b.tcp_ack, b.tcp_flags) = (900, 100 + req.len() as u32, TCP_FLAG_ACK);
    vec![a, b]
}

/// Outputs that carry the request path (the audit log names the server).
const PATHS: &[&str] = &["json", "raw", "logs", "otlp"];
const WAIT: Duration = Duration::from_secs(10);

// ── Tests ──────────────────────────────────────────────────────────────

/// A worker paused after admission, before its sink hand-off, and an
/// old-generation event at the ring read after the change: neither leaves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paused_worker_and_stale_events_reach_no_output_after_applied() {
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
}

/// A ring reader paused after admitting an event, its batch pending across
/// the swap: the batch keeps its (revoked) destination.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reader_paused_after_admission_keeps_its_old_destination() {
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
}

/// An OTLP export writing to its socket when the change lands (paused
/// before the socket gate), and the old SDK's shutdown export: refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_flight_otlp_export_is_refused_after_applied() {
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
}

/// A DNS answer the old pipeline inserts after the change never names a
/// flow the new pipeline exports.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_answer_inserted_after_applied_names_nothing_new() {
    use crate::protocol::dns::test_helpers::{
        build_dns_query, build_dns_response, encode_dns_name,
    };
    let env = Env::new("dns").await;
    env.feed(&exchange("old-before", 18031, 1));
    env.wait_for("old-before", PATHS).await;

    // old-dns.example -> 10.99.0.1 (SERVER), learned by the old pipeline.
    let resolver = (0x0A63_0035, 53);
    let cli = (CLIENT, 5353);
    let name = "old-dns.example";
    let q = packet(cli, resolver, 17, &build_dns_query(7, name, 1), 1);
    let rdata = SERVER.to_be_bytes();
    let answer = build_dns_response(7, 0, name, 1, &[(&encode_dns_name(name), 1, 300, &rdata)]);
    let r = packet(resolver, cli, 17, &answer, 1);

    let old = env.scope.gate().await.unwrap();
    let hook = test_hooks::arm(test_hooks::BEFORE_DNS_INSERT, &old);
    env.feed(&[q, r]);
    assert!(
        hook.wait_reached(WAIT),
        "worker never reached the DNS insert"
    );
    env.scope.narrow(2).await;
    let applied = env.marks();
    drop(hook); // the old pipeline's cache gets the answer now

    env.feed(&exchange("new-after", 18032, 2));
    env.wait_for(":18032", &["audit"]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    env.assert_absent_after(&applied, "old-dns");
    env.assert_absent_after(&applied, "old-");
    env.scope.shutdown().await;
}

/// A failed build keeps the floor raised and the old pipeline revoked;
/// readers drop until a later change builds one (Revision 1 item 7).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_build_drops_everything_until_a_later_change_builds() {
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_with_cgroup_skb_applies_user_space_scope() {
    let dir = tmpdir("replay");
    let cg = "[capture]\nbackend = \"cgroup_skb\"\n";
    let sampled = format!("sampling_mode = \"connection_sample\"\nsample_rate = 0.0\n{cg}");
    let out = replay_once(&dir, &sampled).await;
    assert!(!out.contains("replayed"), "{out}");
    // Positive control: the same recording unscoped is exported.
    let out = replay_once(&dir, cg).await;
    assert!(out.contains("replayed"), "{out}");
    std::fs::remove_dir_all(&dir).ok();
}

/// Live cgroup_skb close records free state, count as processed and reach
/// no output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_close_records_are_counted_and_reach_no_output() {
    let dir = tmpdir("close");
    let (endpoint, _otlp) = collector().await;
    let mut cfg = config(&dir, &endpoint);
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
}

// ── The scope publisher ────────────────────────────────────────────────

/// The publisher resolves cgroups with openat2 (`scope_select::resolve`):
/// Linux only.
#[cfg(target_os = "linux")]
mod publisher {
    use super::*;
    use std::collections::BTreeSet;

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
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pod_label_change_narrows_and_revokes() {
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
    }

    /// Reloads are serialised: two narrowings in either order and a widening
    /// racing a narrowing all end in the last requested set, each reported
    /// only once applied.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reloads_are_serialised_and_reported_after_applied() {
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
    }

    /// The net_cls watch's narrowing is sticky: later pod changes cannot
    /// re-widen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn net_cls_disable_is_a_sticky_narrowing() {
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
    }

    /// Stage A6 review, HIGH 2: a failed runtime publication disarms the
    /// kernel and revokes the pipeline before the stop is logged; nothing is
    /// published afterwards. A failed disarm makes the task fail (the agent
    /// exits).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn publication_failure_is_a_fatal_capture_stop() {
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
    }
}
