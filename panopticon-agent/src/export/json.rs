//! JSONL file exporter for integration testing and debugging.
//! Writes one JSON object per line to a file.

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::mpsc;

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    headers: Vec<(&'a str, &'a str)>,
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

/// JSONL file writer. One JSON object per line.
pub struct JsonExporter {
    writer: BufWriter<File>,
}

impl JsonExporter {
    /// Create a new exporter writing to the given path.
    /// Creates or truncates the file.
    pub fn new(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("Failed to open JSON export file: {}", path))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    /// Write an L7Message with optional PII report as a single JSON line.
    pub fn emit(
        &mut self,
        msg: &L7Message,
        pii: Option<&PiiReport>,
        context: Option<&TransportContext>,
    ) -> Result<()> {
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
            headers: msg
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: context.and_then(|ctx| ctx.src_addr),
            dst_addr: context.and_then(|ctx| ctx.dst_addr),
            src_port: context.and_then(|ctx| ctx.src_port),
            dst_port: context.and_then(|ctx| ctx.dst_port),
            pid: context.and_then(|ctx| ctx.pid),
            tls_library: context.and_then(|ctx| ctx.tls_library).map(Into::into),
            pii,
        };

        serde_json::to_writer(&mut self.writer, &event)
            .context("Failed to serialize JSON event")?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    /// Flush the underlying buffer without writing an event.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Owned message for the channel-based export pipeline.
/// Contains cloned data since L7Message isn't Send-safe across tasks.
#[derive(Clone)]
pub struct ExportEvent {
    pub msg: L7Message,
    pub pii: Option<PiiReport>,
    pub context: TransportContext,
}

/// Channel-based handle for sending events to a dedicated writer task.
/// Eliminates per-event Mutex contention on the hot path.
#[derive(Clone)]
pub struct JsonExportHandle {
    tx: mpsc::Sender<ExportEvent>,
}

impl JsonExportHandle {
    /// Spawn a dedicated writer task and return the handle.
    /// The writer task drains the channel and batches writes,
    /// flushing only when the channel is empty (no more pending events).
    pub fn spawn(path: &str, buffer_size: usize) -> Result<(Self, tokio::task::JoinHandle<()>)> {
        let mut exporter = JsonExporter::new(path)?;
        let (tx, mut rx) = mpsc::channel::<ExportEvent>(buffer_size);

        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(e) = exporter.emit(&event.msg, event.pii.as_ref(), Some(&event.context))
                {
                    tracing::warn!(error = %e, "JSON export write failed");
                }
                // Batch: drain any pending events before flushing
                while let Ok(event) = rx.try_recv() {
                    if let Err(e) =
                        exporter.emit(&event.msg, event.pii.as_ref(), Some(&event.context))
                    {
                        tracing::warn!(error = %e, "JSON export write failed");
                    }
                }
                // Flush once after draining the batch
                if let Err(e) = exporter.flush() {
                    tracing::warn!(error = %e, "JSON export flush failed");
                }
            }
            // Final flush on shutdown
            let _ = exporter.flush();
        });

        Ok((Self { tx }, handle))
    }

    /// Send an event to the writer task. Returns false if the channel is full (backpressure).
    pub fn try_send(
        &self,
        msg: L7Message,
        pii: Option<PiiReport>,
        context: TransportContext,
    ) -> bool {
        self.tx.try_send(ExportEvent { msg, pii, context }).is_ok()
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
            headers: vec![],
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: Some(0x0A000001),
            dst_addr: Some(0x0A000002),
            src_port: Some(54321),
            dst_port: Some(8080),
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
            headers: vec![],
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
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
            let mut exporter = JsonExporter::new(path_str).unwrap();
            let msg = make_test_msg();
            exporter
                .emit(&msg, None, Some(&make_transport_context()))
                .unwrap();
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
            let mut exporter = JsonExporter::new(path_str).unwrap();
            let msg1 = make_test_msg();
            let mut msg2 = L7Message::new(Protocol::Mysql, Direction::Ingress, 2000);
            msg2.method = Some("QUERY".to_string());
            exporter
                .emit(&msg1, None, Some(&make_transport_context()))
                .unwrap();
            exporter.emit(&msg2, None, None).unwrap();
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
            headers: vec![],
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
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
            headers: msg
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect(),
            request_size_bytes: msg.request_size_bytes,
            response_size_bytes: msg.response_size_bytes,
            src_addr: None,
            dst_addr: None,
            src_port: None,
            dst_port: None,
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
}
