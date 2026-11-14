//! JSONL file exporter for integration testing and debugging.
//! Writes one JSON object per line to a file.

#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::mpsc;

use std::sync::Arc;

use crate::config::{PrivacyGate, PrivacyMode};
use crate::io_gate::{IoGate, RecordFile, Refused};
use crate::k8s::K8sMetadata;
use crate::pii::PiiReport;
use crate::protocol::{Direction, L7Message, Protocol};
use panopticon_common::{DataEvent, TlsLibrary};

/// A single exported event combining L7 message + optional PII report.
#[derive(Serialize)]
struct JsonEvent<'a> {
    protocol: ProtocolStr,
    direction: DirectionStr,
    timestamp_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    headers: Vec<(&'a str, &'a str)>,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    dns_answers: &'a [crate::protocol::DnsAnswer],
    request_size_bytes: u64,
    response_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_addr: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_addr: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_port: Option<u16>,
    /// Kubernetes identity of `src_addr` / `dst_addr` (`namespace/workload`,
    /// `svc:namespace/service`, `node:name`), when Kubernetes identity is on.
    #[serde(skip_serializing_if = "Option::is_none")]
    src_workload: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_workload: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_library: Option<TlsLibraryStr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pii: Option<&'a PiiReport>,
}

/// Serializable wrapper for Protocol (which is in a no_std crate).
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ProtocolStr {
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

impl From<Protocol> for ProtocolStr {
    fn from(p: Protocol) -> Self {
        match p {
            Protocol::Http1 => ProtocolStr::Http1,
            Protocol::Http2 => ProtocolStr::Http2,
            Protocol::Grpc => ProtocolStr::Grpc,
            Protocol::Mysql => ProtocolStr::Mysql,
            Protocol::Postgres => ProtocolStr::Postgres,
            Protocol::Redis => ProtocolStr::Redis,
            Protocol::Dns => ProtocolStr::Dns,
            Protocol::Kafka => ProtocolStr::Kafka,
            Protocol::Amqp => ProtocolStr::Amqp,
            Protocol::Unknown => ProtocolStr::Unknown,
        }
    }
}

/// Serializable wrapper for Direction (which is in a no_std crate).
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum DirectionStr {
    Ingress,
    Egress,
}

impl From<Direction> for DirectionStr {
    fn from(d: Direction) -> Self {
        match d {
            Direction::Ingress => DirectionStr::Ingress,
            Direction::Egress => DirectionStr::Egress,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct TransportContext {
    pub src_addr: Option<u32>,
    pub dst_addr: Option<u32>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub pid: Option<u32>,
    pub tls_library: Option<TlsLibrary>,
}

impl TransportContext {
    pub fn from_data_event(event: &DataEvent) -> Self {
        Self {
            src_addr: (event.src_addr != 0).then_some(event.src_addr),
            dst_addr: (event.dst_addr != 0).then_some(event.dst_addr),
            src_port: (event.src_port != 0).then_some(event.src_port),
            dst_port: (event.dst_port != 0).then_some(event.dst_port),
            pid: (event.pid != 0).then_some(event.pid),
            tls_library: match event.tls_library {
                TlsLibrary::None => None,
                other => Some(other),
            },
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TlsLibraryStr {
    OpenSsl,
    GoTls,
    JavaSsl,
}

impl From<TlsLibrary> for TlsLibraryStr {
    fn from(value: TlsLibrary) -> Self {
        debug_assert_ne!(
            value,
            TlsLibrary::None,
            "TlsLibrary::None should be filtered out by TransportContext::from_data_event"
        );
        match value {
            TlsLibrary::OpenSsl => TlsLibraryStr::OpenSsl,
            TlsLibrary::GoTls => TlsLibraryStr::GoTls,
            TlsLibrary::JavaSsl => TlsLibraryStr::JavaSsl,
            TlsLibrary::None => {
                unreachable!(
                    "TlsLibrary::None is filtered out by TransportContext::from_data_event"
                )
            }
        }
    }
}

/// Serialises exported events as JSON lines. One JSON object per line.
#[derive(Default)]
pub struct JsonExporter {
    k8s: Option<Arc<K8sMetadata>>,
}

impl JsonExporter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create the export file: a fresh owner-only (0600) file replacing any
    /// existing one on Unix (in `full` privacy mode it holds unredacted
    /// payloads). Opened once and shared by every capture pipeline.
    pub fn open(path: &str) -> Result<Arc<RecordFile>> {
        RecordFile::create(path, b"", u64::MAX, false).context("JSON export file")
    }

    /// Add `src_workload` / `dst_workload` from Kubernetes metadata. The
    /// lookups run here, on the writer thread, not on the workers.
    pub fn with_k8s(mut self, k8s: Option<Arc<K8sMetadata>>) -> Self {
        self.k8s = k8s;
        self
    }

    /// Append an L7Message with optional PII report to `out` as a single
    /// JSON line.
    pub fn emit(
        &self,
        out: &mut Vec<u8>,
        msg: &L7Message,
        pii: Option<&PiiReport>,
        context: Option<&TransportContext>,
    ) -> Result<()> {
        let workload =
            |addr: Option<u32>| self.k8s.as_ref().zip(addr).and_then(|(k, a)| k.display(a));
        let src_workload = workload(context.and_then(|ctx| ctx.src_addr));
        let dst_workload = workload(context.and_then(|ctx| ctx.dst_addr));
        let event = JsonEvent {
            protocol: msg.protocol.into(),
            direction: msg.direction.into(),
            timestamp_ns: msg.timestamp_ns,
            latency_ns: msg.latency_ns,
            method: msg.method.as_deref(),
            path: msg.path.as_deref(),
            status: msg.status,
            content_type: msg.content_type.as_deref(),
            payload_text: msg.payload_text.as_deref(),
            request_body: msg.request_text.as_deref(),
            headers: msg
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            dns_answers: &msg.dns_answers,
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: context.and_then(|ctx| ctx.src_addr),
            dst_addr: context.and_then(|ctx| ctx.dst_addr),
            src_port: context.and_then(|ctx| ctx.src_port),
            dst_port: context.and_then(|ctx| ctx.dst_port),
            src_workload: src_workload.as_deref(),
            dst_workload: dst_workload.as_deref(),
            pid: context.and_then(|ctx| ctx.pid),
            tls_library: context.and_then(|ctx| ctx.tls_library).map(Into::into),
            pii,
        };

        let start = out.len();
        if let Err(e) = serde_json::to_writer(&mut *out, &event) {
            out.truncate(start); // never leave half a line
            return Err(e).context("Failed to serialize JSON event");
        }
        out.push(b'\n');
        Ok(())
    }
}

/// Write the batched lines once they reach this size, so the batch buffer
/// stays bounded under load.
const EXPORT_WRITE_BYTES: usize = 64 * 1024;

/// Owned message for the channel-based export pipeline.
/// Contains cloned data since L7Message isn't Send-safe across tasks.
#[derive(Clone)]
pub struct ExportEvent {
    pub msg: L7Message,
    pub pii: Option<PiiReport>,
    pub context: TransportContext,
    /// The privacy mode the record was produced under.
    pub mode: PrivacyMode,
}

/// How often the export writer drains its channel while events flow (bounds
/// export latency).
const EXPORT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);
/// Poll interval ceiling while idle: the first event after a quiet period
/// is written within this delay.
const EXPORT_IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Channel-based handle for sending events to a dedicated writer task.
/// Eliminates per-event Mutex contention on the hot path.
#[derive(Clone)]
pub struct JsonExportHandle {
    tx: mpsc::Sender<ExportEvent>,
}

impl JsonExportHandle {
    /// Spawn a writer on a new file at `path` with its own open gate
    /// (replay, tests). See [`spawn_on`](Self::spawn_on).
    pub fn spawn(
        path: &str,
        buffer_size: usize,
        privacy: Arc<PrivacyGate>,
    ) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        Ok(Self::spawn_on(
            JsonExporter::open(path)?,
            IoGate::new(),
            buffer_size,
            None,
            privacy,
            tracing::Dispatch::default(),
        ))
    }

    /// Spawn one capture pipeline's writer and return the handle.
    ///
    /// The writer drains the channel and appends whole lines to a batch
    /// buffer it owns, then writes the batch to the shared `file` under the
    /// pipeline's `gate` once the channel is empty: a revoked pipeline's
    /// batch is refused whole, and dropping the pipeline drops its buffer
    /// unwritten. It runs on the blocking pool: file writes on a runtime
    /// thread stalled the parser workers sharing it. It polls every
    /// EXPORT_POLL_INTERVAL instead of blocking on the channel, so workers'
    /// sends never have to wake it. It logs through `dispatch`.
    ///
    /// Each record is checked against the privacy mode now in effect
    /// (`privacy`): one produced under a wider mode before a reload
    /// tightened it is dropped, not written. Once the mode is
    /// `metrics_only` the writer stops and closes the file.
    pub fn spawn_on(
        file: Arc<RecordFile>,
        gate: Arc<IoGate>,
        buffer_size: usize,
        k8s: Option<Arc<K8sMetadata>>,
        privacy: Arc<PrivacyGate>,
        dispatch: tracing::Dispatch,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let exporter = JsonExporter::new().with_k8s(k8s);
        let (tx, mut rx) = mpsc::channel::<ExportEvent>(buffer_size);

        let handle = tokio::task::spawn_blocking(move || {
            tracing::dispatcher::with_default(&dispatch, || {
                use tokio::sync::mpsc::error::TryRecvError;
                let mut poll = EXPORT_POLL_INTERVAL;
                let mut batch = Vec::with_capacity(EXPORT_WRITE_BYTES);
                // False once the file or the pipeline refuses for good.
                let write = |batch: &mut Vec<u8>| -> bool {
                    let r = file.write(&gate, batch);
                    batch.clear();
                    match r {
                        Ok(()) => true,
                        Err(Refused::Io(e)) => {
                            tracing::warn!(error = %e, "JSON export write failed");
                            true
                        }
                        Err(_) => false,
                    }
                };
                loop {
                    let mut wrote = false;
                    let mut closed = loop {
                        if privacy.get() == PrivacyMode::MetricsOnly {
                            break true; // no per-request export any more
                        }
                        match rx.try_recv() {
                            Ok(event) if !privacy.allows(event.mode) => {}
                            Ok(event) => {
                                if let Err(e) = exporter.emit(
                                    &mut batch,
                                    &event.msg,
                                    event.pii.as_ref(),
                                    Some(&event.context),
                                ) {
                                    tracing::warn!(error = %e, "JSON export write failed");
                                }
                                wrote = true;
                                if batch.len() >= EXPORT_WRITE_BYTES && !write(&mut batch) {
                                    break true;
                                }
                            }
                            Err(TryRecvError::Empty) => break false,
                            Err(TryRecvError::Disconnected) => break true,
                        }
                    };
                    // Write once per drained batch.
                    if !batch.is_empty() && privacy.get() != PrivacyMode::MetricsOnly {
                        closed |= !write(&mut batch);
                    }
                    if closed {
                        if privacy.get() == PrivacyMode::MetricsOnly {
                            file.close();
                            tracing::warn!("Privacy mode is metrics_only: JSON export closed");
                        }
                        break;
                    }
                    // Back off while idle (a fixed 5ms poll cost ~1% of a core
                    // with no traffic); tighten again as soon as events flow.
                    poll = if wrote {
                        EXPORT_POLL_INTERVAL
                    } else {
                        (poll * 2).min(EXPORT_IDLE_POLL_INTERVAL)
                    };
                    std::thread::sleep(poll);
                }
            })
        });

        (Self { tx }, handle)
    }

    /// Send an event, produced under privacy mode `mode`, to the writer
    /// task. Returns false if the channel is full (backpressure).
    pub fn try_send(
        &self,
        msg: L7Message,
        pii: Option<PiiReport>,
        context: TransportContext,
        mode: PrivacyMode,
    ) -> bool {
        self.tx
            .try_send(ExportEvent {
                msg,
                pii,
                context,
                mode,
            })
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::{PiiCategory, PiiEntity, PiiSource};
    use panopticon_common::TlsLibrary;

    fn make_test_msg() -> L7Message {
        let mut msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        msg.method = Some("GET".to_string());
        msg.path = Some("/api/users".to_string());
        msg.status = Some(200);
        msg
    }

    fn make_transport_context() -> TransportContext {
        TransportContext {
            src_addr: Some(0x0A000001),
            dst_addr: Some(0x0A000002),
            src_port: Some(54321),
            dst_port: Some(8080),
            pid: Some(1234),
            tls_library: None,
        }
    }

    /// Codex #2: records queued under a wider mode are not written after a
    /// reload tightened it, and `metrics_only` closes the export.
    #[test]
    fn test_writer_drops_records_the_tightened_mode_forbids() {
        let path =
            std::env::temp_dir().join(format!("panopticon_json_tight_{}", std::process::id()));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let gate = Arc::new(PrivacyGate::new(PrivacyMode::Full));
        let written = rt.block_on(async {
            let (h, writer) =
                JsonExportHandle::spawn(path.to_str().unwrap(), 64, Arc::clone(&gate)).unwrap();
            let rec = |p: &str, mode| {
                let mut msg = make_test_msg();
                msg.path = Some(p.to_string());
                assert!(h.try_send(msg, None, make_transport_context(), mode));
            };
            // Queued unredacted under full, then the reload tightens.
            gate.tighten(PrivacyMode::Redacted);
            rec("/raw?ssn=123-45-6789", PrivacyMode::Full);
            rec("/redacted?ssn=<SSN>", PrivacyMode::Redacted);
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            gate.tighten(PrivacyMode::MetricsOnly);
            rec("/after-metrics-only", PrivacyMode::Redacted);
            // The writer stops on its own (the handle is still alive).
            tokio::time::timeout(std::time::Duration::from_secs(5), writer)
                .await
                .expect("writer closed on metrics_only")
                .unwrap();
            std::fs::read_to_string(&path).unwrap()
        });
        std::fs::remove_file(&path).ok();
        assert!(!written.contains("123-45-6789"), "{written}");
        assert!(!written.contains("after-metrics-only"), "{written}");
        assert!(written.contains("/redacted"), "{written}");
    }

    #[cfg(unix)]
    #[test]
    fn test_export_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("panopticon_json_{}", std::process::id()));
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        JsonExporter::open(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        std::fs::remove_file(&path).ok();
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_json_serialize_roundtrip() {
        let msg = make_test_msg();
        let event = JsonEvent {
            protocol: msg.protocol.into(),
            direction: msg.direction.into(),
            timestamp_ns: msg.timestamp_ns,
            latency_ns: msg.latency_ns,
            method: msg.method.as_deref(),
            path: msg.path.as_deref(),
            status: msg.status,
            content_type: msg.content_type.as_deref(),
            payload_text: msg.payload_text.as_deref(),
            request_body: msg.request_text.as_deref(),
            headers: vec![],
            dns_answers: &[],
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: Some(0x0A000001),
            dst_addr: Some(0x0A000002),
            src_port: Some(54321),
            dst_port: Some(8080),
            src_workload: None,
            dst_workload: None,
            pid: Some(1234),
            tls_library: None,
            pii: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"protocol\":\"http1\""));
        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("\"path\":\"/api/users\""));
        assert!(json.contains("\"status\":200"));
        assert!(json.contains("\"src_addr\":167772161"));
        assert!(json.contains("\"dst_port\":8080"));
        assert!(json.contains("\"pid\":1234"));
    }

    #[test]
    fn test_json_skips_none_fields() {
        let msg = L7Message::new(Protocol::Redis, Direction::Ingress, 500);
        let event = JsonEvent {
            protocol: msg.protocol.into(),
            direction: msg.direction.into(),
            timestamp_ns: msg.timestamp_ns,
            latency_ns: msg.latency_ns,
            method: msg.method.as_deref(),
            path: msg.path.as_deref(),
            status: msg.status,
            content_type: msg.content_type.as_deref(),
            payload_text: msg.payload_text.as_deref(),
            request_body: msg.request_text.as_deref(),
            headers: vec![],
            dns_answers: &[],
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            src_workload: None,
            dst_workload: None,
            pid: None,
            tls_library: None,
            pii: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"method\""));
        assert!(!json.contains("\"path\""));
        assert!(!json.contains("\"status\""));
        assert!(!json.contains("\"pii\""));
        assert!(!json.contains("\"headers\""));
    }

    #[test]
    fn test_json_exporter_writes_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("panopticon_test_export.jsonl");
        let path_str = path.to_str().unwrap();

        {
            let file = JsonExporter::open(path_str).unwrap();
            let mut out = Vec::new();
            JsonExporter::new()
                .emit(
                    &mut out,
                    &make_test_msg(),
                    None,
                    Some(&make_transport_context()),
                )
                .unwrap();
            file.write(&IoGate::new(), &out).unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["protocol"], "http1");
        assert_eq!(parsed["src_port"], 54321);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_json_exporter_multiple_lines() {
        let dir = std::env::temp_dir();
        let path = dir.join("panopticon_test_multi.jsonl");
        let path_str = path.to_str().unwrap();

        {
            let file = JsonExporter::open(path_str).unwrap();
            let exporter = JsonExporter::new();
            let msg1 = make_test_msg();
            let mut msg2 = L7Message::new(Protocol::Mysql, Direction::Ingress, 2000);
            msg2.method = Some("QUERY".to_string());
            let mut out = Vec::new();
            exporter
                .emit(&mut out, &msg1, None, Some(&make_transport_context()))
                .unwrap();
            exporter.emit(&mut out, &msg2, None, None).unwrap();
            file.write(&IoGate::new(), &out).unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        let p1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let p2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(p1["protocol"], "http1");
        assert_eq!(p2["protocol"], "mysql");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_json_with_pii_report() {
        let msg = make_test_msg();
        let report = PiiReport {
            entities: vec![PiiEntity {
                category: PiiCategory::Email,
                source: PiiSource::Regex,
                start: 0,
                end: 16,
                confidence: 1.0,
                text: "john@example.com".to_string(),
            }],
            redacted_text: Some("contact <EMAIL> for details".to_string()),
            scanned_bytes: 35,
            redacted: true,
        };

        let event = JsonEvent {
            protocol: msg.protocol.into(),
            direction: msg.direction.into(),
            timestamp_ns: msg.timestamp_ns,
            latency_ns: msg.latency_ns,
            method: msg.method.as_deref(),
            path: msg.path.as_deref(),
            status: msg.status,
            content_type: msg.content_type.as_deref(),
            payload_text: msg.payload_text.as_deref(),
            request_body: msg.request_text.as_deref(),
            headers: vec![],
            dns_answers: &[],
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            src_workload: None,
            dst_workload: None,
            pid: None,
            tls_library: Some(TlsLibrary::OpenSsl.into()),
            pii: Some(&report),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"pii\""));
        assert!(json.contains("\"email\"") || json.contains("\"Email\""));
        assert!(!json.contains("john@example.com"));
        assert!(json.contains("\"tls_library\":\"open_ssl\""));
    }

    #[test]
    fn test_json_with_headers() {
        let mut msg = make_test_msg();
        msg.headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ];
        let event = JsonEvent {
            protocol: msg.protocol.into(),
            direction: msg.direction.into(),
            timestamp_ns: msg.timestamp_ns,
            latency_ns: msg.latency_ns,
            method: msg.method.as_deref(),
            path: msg.path.as_deref(),
            status: msg.status,
            content_type: msg.content_type.as_deref(),
            payload_text: msg.payload_text.as_deref(),
            request_body: msg.request_text.as_deref(),
            headers: msg
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            dns_answers: &msg.dns_answers,
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
            src_workload: None,
            dst_workload: None,
            pid: None,
            tls_library: None,
            pii: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("content-type"));
        assert!(json.contains("application/json"));
    }

    #[test]
    fn test_transport_context_from_data_event() {
        let event = DataEvent {
            src_addr: 0x0A000001,
            dst_addr: 0x0A000002,
            src_port: 12345,
            dst_port: 443,
            pid: 77,
            tls_library: TlsLibrary::GoTls,
            ..unsafe { std::mem::zeroed() }
        };
        let ctx = TransportContext::from_data_event(&event);
        assert_eq!(ctx.src_addr, Some(0x0A000001));
        assert_eq!(ctx.dst_port, Some(443));
        assert_eq!(ctx.pid, Some(77));
        assert_eq!(ctx.tls_library, Some(TlsLibrary::GoTls));
    }

    #[test]
    fn test_transport_context_omits_missing_data() {
        let event: DataEvent = unsafe { std::mem::zeroed() };
        let ctx = TransportContext::from_data_event(&event);
        assert!(ctx.src_addr.is_none());
        assert!(ctx.dst_addr.is_none());
        assert!(ctx.src_port.is_none());
        assert!(ctx.dst_port.is_none());
        assert!(ctx.pid.is_none());
        assert!(ctx.tls_library.is_none());
    }

    #[test]
    fn test_json_exporter_adds_k8s_workloads() {
        let meta = K8sMetadata::new("http://test");
        let pods: Vec<crate::k8s::model::Pod> = vec![
            serde_json::from_value(serde_json::json!({
                "metadata": {"name": "web-0", "namespace": "shop",
                    "ownerReferences": [{"kind": "StatefulSet", "name": "web", "controller": true}]},
                "status": {"phase": "Running", "podIP": "10.0.0.1"}
            }))
            .unwrap(),
        ];
        meta.replace_pods(&pods);
        meta.publish_if_dirty();

        let mut out = Vec::new();
        JsonExporter::new()
            .with_k8s(Some(meta))
            .emit(
                &mut out,
                &make_test_msg(),
                None,
                Some(&make_transport_context()),
            )
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["src_workload"], "shop/web");
        // 10.0.0.2 is unknown to Kubernetes: no field.
        assert!(v.get("dst_workload").is_none());
    }
}
