//! Prometheus metrics registry for agent observability.
//!
//! `AgentMetrics` wraps prometheus-client counters and gauges. Rather than replacing
//! the hot-path `EventStats` atomics, metrics are snapshotted from `EventStats` at
//! scrape time via `sync_from_stats()`.

#![allow(dead_code)]

use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;

use crate::event_loop::EventStats;

/// Agent metrics backed by prometheus-client.
///
/// These are snapshot-style metrics: `sync_from_stats()` reads the latest values
/// from `EventStats` atomics and sets the prometheus counters accordingly.
#[derive(Clone)]
pub struct AgentMetrics {
    pub events_received: Counter<u64>,
    pub events_dropped: Counter<u64>,
    pub events_processed: Counter<u64>,
    pub active_connections: Gauge<u64, AtomicU64>,
    pub drops_rate_limit: Counter<u64>,
    pub drops_channel_full: Counter<u64>,
    pub drops_parser_error: Counter<u64>,
    pub pii_detections: Counter<u64>,
    // Self-telemetry (6.6)
    pub parse_latency: Histogram,
    // eBPF map monitoring (6.8)
    pub ringbuf_approx_pending: Gauge<i64, std::sync::atomic::AtomicI64>,
}

impl AgentMetrics {
    /// Create a new metrics registry with all agent metrics registered.
    pub fn new() -> (Self, Registry) {
        let mut registry = Registry::default();

        let events_received = Counter::<u64>::default();
        registry.register(
            "panopticon_events_received",
            "Total events received from RingBuf",
            events_received.clone(),
        );

        let events_dropped = Counter::<u64>::default();
        registry.register(
            "panopticon_events_dropped",
            "Total events dropped (all reasons)",
            events_dropped.clone(),
        );

        let events_processed = Counter::<u64>::default();
        registry.register(
            "panopticon_events_processed",
            "Total events processed by workers",
            events_processed.clone(),
        );

        let active_connections: Gauge<u64, AtomicU64> = Gauge::default();
        registry.register(
            "panopticon_active_connections",
            "Currently tracked connections",
            active_connections.clone(),
        );

        let drops_rate_limit = Counter::<u64>::default();
        registry.register(
            "panopticon_drops_rate_limit",
            "Events dropped due to rate limiting",
            drops_rate_limit.clone(),
        );

        let drops_channel_full = Counter::<u64>::default();
        registry.register(
            "panopticon_drops_channel_full",
            "Events dropped due to full worker channel",
            drops_channel_full.clone(),
        );

        let drops_parser_error = Counter::<u64>::default();
        registry.register(
            "panopticon_drops_parser_error",
            "Events dropped due to parser errors",
            drops_parser_error.clone(),
        );

        let pii_detections = Counter::<u64>::default();
        registry.register(
            "panopticon_pii_detections",
            "Total PII entities detected",
            pii_detections.clone(),
        );

        // Parse latency histogram with buckets from 1µs to 100ms
        let parse_latency = Histogram::new(exponential_buckets(0.000_001, 10.0, 6));
        registry.register(
            "panopticon_parse_duration_seconds",
            "Protocol parser latency in seconds",
            parse_latency.clone(),
        );

        let ringbuf_approx_pending: Gauge<i64, std::sync::atomic::AtomicI64> = Gauge::default();
        registry.register(
            "panopticon_ringbuf_approx_pending",
            "Approximate pending events in RingBuf (received - processed)",
            ringbuf_approx_pending.clone(),
        );

        let metrics = Self {
            events_received,
            events_dropped,
            events_processed,
            active_connections,
            drops_rate_limit,
            drops_channel_full,
            drops_parser_error,
            pii_detections,
            parse_latency,
            ringbuf_approx_pending,
        };

        (metrics, registry)
    }

    /// Snapshot current values from `EventStats` atomics into prometheus metrics.
    ///
    /// Called on each `/metrics` scrape. Uses `inner()` to read the current counter
    /// value and sets the prometheus counter to match via delta increment.
    pub fn sync_from_stats(&self, stats: &EventStats) {
        use std::sync::atomic::Ordering;

        // For counters, we need to compute the delta since last sync
        // prometheus-client Counter only supports `inc()` and `inc_by()` —
        // we use `inner().set()` on the underlying atomic to match EventStats values.
        let received = stats.events_received.load(Ordering::Relaxed);
        self.events_received
            .inner()
            .store(received, Ordering::Relaxed);

        let dropped = stats.events_dropped.load(Ordering::Relaxed);
        self.events_dropped
            .inner()
            .store(dropped, Ordering::Relaxed);

        let processed = stats.events_processed.load(Ordering::Relaxed);
        self.events_processed
            .inner()
            .store(processed, Ordering::Relaxed);

        let active = stats.active_connections.load(Ordering::Relaxed);
        self.active_connections
            .inner()
            .store(active, Ordering::Relaxed);

        let rate = stats.drops_rate_limit.load(Ordering::Relaxed);
        self.drops_rate_limit.inner().store(rate, Ordering::Relaxed);

        let channel = stats.drops_channel_full.load(Ordering::Relaxed);
        self.drops_channel_full
            .inner()
            .store(channel, Ordering::Relaxed);

        let parser = stats.drops_parser_error.load(Ordering::Relaxed);
        self.drops_parser_error
            .inner()
            .store(parser, Ordering::Relaxed);

        // Approximate RingBuf pending = received - processed
        let pending = received.saturating_sub(processed) as i64;
        self.ringbuf_approx_pending
            .inner()
            .store(pending, Ordering::Relaxed);
    }
}

/// Encode all metrics in the registry to Prometheus text exposition format.
pub fn encode_metrics(registry: &Registry) -> String {
    let mut buf = String::new();
    encode(&mut buf, registry).expect("prometheus encoding should not fail");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry_creation() {
        let (metrics, _registry) = AgentMetrics::new();
        // Verify initial counter values are zero
        assert_eq!(metrics.events_received.get(), 0);
        assert_eq!(metrics.events_dropped.get(), 0);
        assert_eq!(metrics.events_processed.get(), 0);
        assert_eq!(metrics.drops_rate_limit.get(), 0);
        assert_eq!(metrics.drops_channel_full.get(), 0);
        assert_eq!(metrics.drops_parser_error.get(), 0);
        assert_eq!(metrics.pii_detections.get(), 0);
    }

    #[test]
    fn test_encode_metrics_format() {
        let (metrics, registry) = AgentMetrics::new();
        metrics.events_received.inc_by(42);
        metrics.events_dropped.inc_by(5);

        let output = encode_metrics(&registry);
        assert!(output.contains("panopticon_events_received_total"));
        assert!(output.contains("panopticon_events_dropped_total"));
        assert!(output.contains("panopticon_active_connections"));
        assert!(output.contains("panopticon_parse_duration_seconds"));
    }

    #[test]
    fn test_sync_from_stats() {
        let (metrics, _registry) = AgentMetrics::new();
        let stats = EventStats::new();

        stats
            .events_received
            .fetch_add(100, std::sync::atomic::Ordering::Relaxed);
        stats
            .events_processed
            .fetch_add(90, std::sync::atomic::Ordering::Relaxed);
        stats
            .events_dropped
            .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
        stats
            .drops_rate_limit
            .fetch_add(7, std::sync::atomic::Ordering::Relaxed);
        stats
            .drops_channel_full
            .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        stats
            .drops_parser_error
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        stats
            .active_connections
            .fetch_add(11, std::sync::atomic::Ordering::Relaxed);

        metrics.sync_from_stats(&stats);

        assert_eq!(metrics.events_received.get(), 100);
        assert_eq!(metrics.events_processed.get(), 90);
        assert_eq!(metrics.events_dropped.get(), 10);
        assert_eq!(metrics.drops_rate_limit.get(), 7);
        assert_eq!(metrics.drops_channel_full.get(), 3);
        assert_eq!(metrics.drops_parser_error.get(), 2);
        assert_eq!(metrics.active_connections.get(), 11);
        assert_eq!(metrics.ringbuf_approx_pending.get(), 10);
    }

    #[test]
    fn test_sync_from_stats_updates_values_on_subsequent_calls() {
        let (metrics, _registry) = AgentMetrics::new();
        let stats = EventStats::new();

        stats
            .events_received
            .store(20, std::sync::atomic::Ordering::Relaxed);
        stats
            .events_processed
            .store(5, std::sync::atomic::Ordering::Relaxed);
        metrics.sync_from_stats(&stats);
        assert_eq!(metrics.events_received.get(), 20);
        assert_eq!(metrics.ringbuf_approx_pending.get(), 15);

        stats
            .events_received
            .store(31, std::sync::atomic::Ordering::Relaxed);
        stats
            .events_processed
            .store(22, std::sync::atomic::Ordering::Relaxed);
        metrics.sync_from_stats(&stats);
        assert_eq!(metrics.events_received.get(), 31);
        assert_eq!(metrics.events_processed.get(), 22);
        assert_eq!(metrics.ringbuf_approx_pending.get(), 9);
    }

    #[test]
    fn test_sync_from_stats_ringbuf_pending_saturates_at_zero() {
        let (metrics, _registry) = AgentMetrics::new();
        let stats = EventStats::new();

        stats
            .events_received
            .store(2, std::sync::atomic::Ordering::Relaxed);
        stats
            .events_processed
            .store(5, std::sync::atomic::Ordering::Relaxed);

        metrics.sync_from_stats(&stats);

        assert_eq!(metrics.ringbuf_approx_pending.get(), 0);
    }
}
