//! OTLP exporter over gRPC.
//!
//! One exporter per capture pipeline, on its own gRPC channel whose socket
//! writes go through the pipeline's gate (DESIGN §3, Revision 1 items 1, 2,
//! 5): the channel is built only from [`GatedConnector`] via
//! `with_channel`, never from the exporter's own transport, and refuses to
//! start otherwise.
//!
//! The SDK's batch processor calls the exporter and polls its futures on a
//! thread of its own, where tonic decodes the collector's response and logs
//! (a `Status` can quote what the collector sent back). The exporter is
//! wrapped ([`DispatchExporter`]) so that every call and every poll runs
//! under the pipeline's log subscriber, whose writer is gated. The SDK's
//! own internal logs are compiled out (`opentelemetry_sdk` and
//! `opentelemetry-otlp` without their `internal-logs` feature).

#![allow(dead_code)]

use std::{
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use opentelemetry::KeyValue;
use opentelemetry::trace::{Span, Tracer, TracerProvider};
use opentelemetry_otlp::WithTonicConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tokio::sync::mpsc;
use tracing::instrument::WithSubscriber;

use crate::config::{OtlpConfig, PrivacyGate, PrivacyMode};
use crate::io_gate::{DispatchExecutor, GatedConnector, IoGate};
use crate::protocol::L7Message;

/// An event to be exported via OTLP.
#[derive(Debug)]
pub enum OtlpEvent {
    /// L7 message -> OTLP span
    Span(L7Message),
    /// PII finding -> OTLP span event on a short-lived span
    PiiFinding {
        timestamp_ns: u64,
        category: String,
        confidence: f32,
    },
}

/// Cloneable, bounded-channel OTLP export handle.
#[derive(Clone)]
pub struct OtlpExportHandle {
    /// Each event with the privacy mode it was produced under.
    tx: mpsc::Sender<(PrivacyMode, OtlpEvent)>,
}

/// One pipeline's exporter task and its SDK provider.
pub struct OtlpWorker {
    task: tokio::task::JoinHandle<()>,
    provider: SdkTracerProvider,
}

impl OtlpWorker {
    /// Graceful stop (agent shutdown; the pipeline was not revoked): once
    /// every handle is gone the task drains, then queued spans are flushed.
    pub async fn finish(self, timeout: Duration) {
        let _ = tokio::time::timeout(timeout, self.task).await;
        let provider = self.provider;
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = provider.force_flush() {
                tracing::warn!(error = ?e, "OTLP force_flush failed");
            }
            if let Err(e) = provider.shutdown() {
                tracing::warn!(error = ?e, "OTLP provider shutdown failed");
            }
        })
        .await;
    }

    /// Discard a revoked pipeline's exporter. The gate must already be
    /// revoked (Revision 1 item 5): the SDK's shutdown still exports what
    /// it queued, and that export fails at the socket gate and is
    /// discarded. Nothing is flushed on purpose.
    pub fn discard(self) {
        self.task.abort();
        let provider = self.provider;
        // Shutdown blocks on the batch processor thread.
        tokio::task::spawn_blocking(move || {
            let _ = provider.shutdown();
        });
    }
}

/// How long one export may wait for the collector (tests: shorter, so
/// an unanswered export's successor runs within the test).
const EXPORT_TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(1)
} else {
    Duration::from_secs(10)
};

/// The pipeline's gRPC channel: lazily connected through `GatedConnector`,
/// tonic's internal tasks spawned under `dispatch`. Only `http://`
/// endpoints: TLS would have to sit above the gate, and this exporter has
/// no TLS setup, so `https://` refuses to start.
fn gated_channel(
    endpoint: &str,
    gate: Arc<IoGate>,
    dispatch: tracing::Dispatch,
) -> Result<tonic::transport::Channel> {
    let uri: http::Uri = endpoint
        .parse()
        .with_context(|| format!("invalid OTLP endpoint {endpoint}"))?;
    if uri.scheme_str() != Some("http") {
        bail!("OTLP endpoint {endpoint}: only http:// endpoints are supported");
    }
    let ep = tonic::transport::Endpoint::from_shared(endpoint.to_string())
        .with_context(|| format!("invalid OTLP endpoint {endpoint}"))?
        .executor(DispatchExecutor(dispatch))
        .connect_timeout(Duration::from_secs(10))
        // An export the collector never answers fails instead of holding
        // the SDK's batch thread (and the spans it retains) for good.
        .timeout(EXPORT_TIMEOUT);
    Ok(ep.connect_with_connector_lazy(
        GatedConnector::plain(gate).with_pause_point(crate::test_hooks::OTLP_IN_FLIGHT_EXPORT),
    ))
}

/// A span exporter whose calls and futures run under the pipeline's
/// tracing `Dispatch` (see the module docs).
#[derive(Debug)]
struct DispatchExporter<E> {
    inner: E,
    dispatch: tracing::Dispatch,
}

impl<E: opentelemetry_sdk::trace::SpanExporter> opentelemetry_sdk::trace::SpanExporter
    for DispatchExporter<E>
{
    fn export(
        &mut self,
        batch: Vec<opentelemetry_sdk::trace::SpanData>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = opentelemetry_sdk::error::OTelSdkResult> + Send>,
    > {
        let dispatch = self.dispatch.clone();
        let inner = &mut self.inner;
        let export = tracing::dispatcher::with_default(&dispatch, || inner.export(batch));
        Box::pin(export.with_subscriber(dispatch))
    }

    fn shutdown(&mut self) -> opentelemetry_sdk::error::OTelSdkResult {
        tracing::dispatcher::with_default(&self.dispatch, || self.inner.shutdown())
    }

    fn force_flush(&mut self) -> opentelemetry_sdk::error::OTelSdkResult {
        tracing::dispatcher::with_default(&self.dispatch, || self.inner.force_flush())
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

impl OtlpExportHandle {
    /// Spawn one pipeline's OTLP exporter, writing under `gate` and logging
    /// through `dispatch`. An event produced under a wider privacy mode
    /// than the one now in effect (`privacy`, tightened by a reload while
    /// it was queued) is dropped, not exported.
    pub fn spawn(
        config: &OtlpConfig,
        buffer_size: usize,
        privacy: std::sync::Arc<PrivacyGate>,
        gate: Arc<IoGate>,
        dispatch: tracing::Dispatch,
    ) -> Result<(Self, OtlpWorker)> {
        let channel = gated_channel(&config.endpoint, gate, dispatch.clone())?;
        let span_exporter = DispatchExporter {
            inner: opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_channel(channel)
                .build()
                .context("failed to build OTLP gRPC span exporter")?,
            dispatch: dispatch.clone(),
        };

        let resource = Resource::builder_empty()
            .with_service_name(config.service_name.clone())
            .build();
        let provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(span_exporter)
            .build();
        let tracer = provider.tracer("panopticon-agent.otlp");

        let (tx, mut rx) = mpsc::channel::<(PrivacyMode, OtlpEvent)>(buffer_size);
        let task = tokio::spawn(
            async move {
                let emit = |(mode, event)| {
                    if privacy.allows(mode) {
                        emit_event(&tracer, event);
                    }
                };
                while let Some(event) = rx.recv().await {
                    emit(event);
                    while let Ok(event) = rx.try_recv() {
                        emit(event);
                    }
                }
            }
            .with_subscriber(dispatch),
        );

        Ok((Self { tx }, OtlpWorker { task, provider }))
    }

    /// Try to enqueue a span produced under privacy mode `mode`. Returns
    /// false if queue is full.
    pub fn try_send_span(&self, msg: L7Message, mode: PrivacyMode) -> bool {
        self.tx.try_send((mode, OtlpEvent::Span(msg))).is_ok()
    }

    /// Try to enqueue a PII finding event produced under privacy mode
    /// `mode`. Returns false if queue is full.
    pub fn try_send_pii_finding(
        &self,
        timestamp_ns: u64,
        category: String,
        confidence: f32,
        mode: PrivacyMode,
    ) -> bool {
        self.tx
            .try_send((
                mode,
                OtlpEvent::PiiFinding {
                    timestamp_ns,
                    category,
                    confidence,
                },
            ))
            .is_ok()
    }
}

fn emit_event(tracer: &impl Tracer, event: OtlpEvent) {
    match event {
        OtlpEvent::Span(msg) => emit_l7_span(tracer, msg),
        OtlpEvent::PiiFinding {
            timestamp_ns,
            category,
            confidence,
        } => emit_pii_event(tracer, timestamp_ns, category, confidence),
    }
}

fn emit_l7_span(tracer: &impl Tracer, msg: L7Message) {
    let start = ns_to_system_time(msg.timestamp_ns);
    let end = span_end_time(start, msg.latency_ns);
    let attrs = l7_span_attributes(&msg);
    let mut span = tracer
        .span_builder("panopticon.l7")
        .with_start_time(start)
        .start(tracer);

    for attr in attrs {
        span.set_attribute(attr);
    }

    if let Some(end) = end {
        span.end_with_timestamp(end);
    } else {
        span.end();
    }
}

fn emit_pii_event(tracer: &impl Tracer, timestamp_ns: u64, category: String, confidence: f32) {
    let ts = ns_to_system_time(timestamp_ns);
    let mut span = tracer
        .span_builder("panopticon.pii")
        .with_start_time(ts)
        .start(tracer);

    span.add_event(
        "pii.finding",
        pii_finding_event_attributes(&category, confidence),
    );
    span.end_with_timestamp(ts);
}

fn l7_span_attributes(msg: &L7Message) -> Vec<KeyValue> {
    let mut attrs = Vec::with_capacity(8);
    attrs.push(KeyValue::new(
        "panopticon.protocol",
        msg.protocol.to_string(),
    ));
    attrs.push(KeyValue::new(
        "panopticon.direction",
        format!("{:?}", msg.direction),
    ));
    if let Some(v) = &msg.method {
        attrs.push(KeyValue::new("panopticon.method", v.clone()));
    }
    if let Some(v) = &msg.path {
        attrs.push(KeyValue::new("panopticon.path", v.clone()));
    }
    if let Some(v) = msg.status {
        attrs.push(KeyValue::new("panopticon.status", v as i64));
    }
    if let Some(v) = &msg.content_type {
        attrs.push(KeyValue::new("panopticon.content_type", v.clone()));
    }
    if let Some(v) = msg.latency_ns {
        attrs.push(KeyValue::new("panopticon.latency_ns", v as i64));
    }
    attrs.push(KeyValue::new(
        "panopticon.request_size_bytes",
        msg.request_size_bytes as i64,
    ));
    attrs.push(KeyValue::new(
        "panopticon.response_size_bytes",
        msg.response_size_bytes as i64,
    ));
    attrs
}

fn pii_finding_event_attributes(category: &str, confidence: f32) -> Vec<KeyValue> {
    vec![
        KeyValue::new("panopticon.pii.category", category.to_owned()),
        KeyValue::new("panopticon.pii.confidence", confidence as f64),
    ]
}

fn span_end_time(start: SystemTime, latency_ns: Option<u64>) -> Option<SystemTime> {
    latency_ns.map(|latency| start + Duration::from_nanos(latency))
}

fn ns_to_system_time(timestamp_ns: u64) -> SystemTime {
    ns_to_system_time_with_offset(timestamp_ns, monotonic_to_unix_offset())
}

fn ns_to_system_time_with_offset(timestamp_ns: u64, offset: Duration) -> SystemTime {
    UNIX_EPOCH + offset + Duration::from_nanos(timestamp_ns)
}

fn monotonic_to_unix_offset() -> Duration {
    static OFFSET: OnceLock<Duration> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mono = monotonic_now();
        now.saturating_sub(mono)
    })
}

fn monotonic_now() -> Duration {
    // DataEvent.timestamp_ns uses monotonic kernel time (bpf_ktime_get_ns).
    // /proc/uptime provides monotonic uptime seconds on Linux; fall back to zero.
    let Ok(raw) = std::fs::read_to_string("/proc/uptime") else {
        return Duration::ZERO;
    };
    let Some(first) = raw.split_whitespace().next() else {
        return Duration::ZERO;
    };
    let Ok(seconds) = first.parse::<f64>() else {
        return Duration::ZERO;
    };
    if !seconds.is_finite() || seconds.is_sign_negative() {
        return Duration::ZERO;
    }

    Duration::from_nanos((seconds * 1_000_000_000.0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Direction, Protocol};
    use opentelemetry::Value;

    #[test]
    fn test_otlp_exporter_channel_creation() {
        let config = OtlpConfig::default();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let gate = IoGate::new();
            let (exporter, worker) = OtlpExportHandle::spawn(
                &config,
                100,
                std::sync::Arc::new(PrivacyGate::new(PrivacyMode::Redacted)),
                Arc::clone(&gate),
                tracing::Dispatch::default(),
            )
            .unwrap();
            let msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
            assert!(exporter.try_send_span(msg, PrivacyMode::Redacted));
            drop(exporter);
            gate.revoke();
            worker.discard();
        });
    }

    #[test]
    fn https_and_invalid_endpoints_refuse_to_start() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            for endpoint in ["https://collector:4317", "collector:4317", "not a uri"] {
                let config = OtlpConfig {
                    enabled: true,
                    endpoint: endpoint.to_string(),
                    ..OtlpConfig::default()
                };
                let r = OtlpExportHandle::spawn(
                    &config,
                    1,
                    std::sync::Arc::new(PrivacyGate::new(PrivacyMode::Redacted)),
                    IoGate::new(),
                    tracing::Dispatch::default(),
                );
                assert!(r.is_err(), "{endpoint}");
            }
        });
    }

    #[test]
    fn test_otlp_exporter_backpressure() {
        let (tx, _rx) = mpsc::channel(1);
        let exporter = OtlpExportHandle { tx };

        let msg1 = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        let msg2 = L7Message::new(Protocol::Http1, Direction::Egress, 2000);
        assert!(exporter.try_send_span(msg1, PrivacyMode::Redacted));
        assert!(!exporter.try_send_span(msg2, PrivacyMode::Redacted));
    }

    #[test]
    fn test_otlp_exporter_pii_backpressure() {
        let (tx, _rx) = mpsc::channel(1);
        let exporter = OtlpExportHandle { tx };

        assert!(exporter.try_send_pii_finding(
            1_000,
            "email".to_string(),
            0.95,
            PrivacyMode::Redacted
        ));
        assert!(!exporter.try_send_pii_finding(
            2_000,
            "ssn".to_string(),
            0.91,
            PrivacyMode::Redacted
        ));
    }

    #[test]
    fn test_l7_span_attributes_include_expected_fields() {
        let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, 1_000);
        msg.method = Some("GET".to_string());
        msg.path = Some("/healthz".to_string());
        msg.status = Some(200);
        msg.content_type = Some("application/json".to_string());
        msg.latency_ns = Some(5_000);
        msg.request_size_bytes = 128;
        msg.response_size_bytes = 512;

        let attrs = l7_span_attributes(&msg);
        assert_eq!(
            attr_value(&attrs, "panopticon.protocol"),
            Some(&Value::String("HTTP/1.1".into()))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.direction"),
            Some(&Value::String("Ingress".into()))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.method"),
            Some(&Value::String("GET".into()))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.path"),
            Some(&Value::String("/healthz".into()))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.status"),
            Some(&Value::I64(200))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.content_type"),
            Some(&Value::String("application/json".into()))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.latency_ns"),
            Some(&Value::I64(5_000))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.request_size_bytes"),
            Some(&Value::I64(128))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.response_size_bytes"),
            Some(&Value::I64(512))
        );
    }

    #[test]
    fn test_l7_span_attributes_omit_optional_fields_when_absent() {
        let msg = L7Message::new(Protocol::Redis, Direction::Egress, 9_999);
        let attrs = l7_span_attributes(&msg);
        assert!(attr_value(&attrs, "panopticon.method").is_none());
        assert!(attr_value(&attrs, "panopticon.path").is_none());
        assert!(attr_value(&attrs, "panopticon.status").is_none());
        assert!(attr_value(&attrs, "panopticon.content_type").is_none());
        assert!(attr_value(&attrs, "panopticon.latency_ns").is_none());
        assert_eq!(
            attr_value(&attrs, "panopticon.protocol"),
            Some(&Value::String("Redis".into()))
        );
        assert_eq!(
            attr_value(&attrs, "panopticon.direction"),
            Some(&Value::String("Egress".into()))
        );
    }

    #[test]
    fn test_pii_finding_event_attributes() {
        let attrs = pii_finding_event_attributes("email", 0.87);
        assert_eq!(attrs.len(), 2);
        assert_eq!(
            attr_value(&attrs, "panopticon.pii.category"),
            Some(&Value::String("email".into()))
        );
        let confidence = attr_value(&attrs, "panopticon.pii.confidence")
            .and_then(|v| match v {
                Value::F64(v) => Some(*v),
                _ => None,
            })
            .expect("pii confidence should be f64");
        assert!((confidence - 0.87f64).abs() < 1e-5);
    }

    #[test]
    fn test_span_end_time_uses_latency() {
        let start = ns_to_system_time(2_000);
        let end = span_end_time(start, Some(3_000)).expect("end time should be present");
        assert_eq!(end.duration_since(start).unwrap().as_nanos(), 3_000u128);
    }

    #[test]
    fn test_span_end_time_none_without_latency() {
        let start = ns_to_system_time(2_000);
        assert!(span_end_time(start, None).is_none());
    }

    #[test]
    fn test_ns_to_system_time() {
        let ts = ns_to_system_time_with_offset(1_000_000_000, Duration::from_secs(2));
        assert_eq!(ts.duration_since(UNIX_EPOCH).unwrap().as_secs(), 3);
    }

    fn attr_value<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a Value> {
        attrs
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| &kv.value)
    }
}
