#![allow(dead_code)]

//! Edge aggregation with query template normalization.
//!
//! Collects per-flow statistics within a configurable time window (default 10s),
//! deduplicating flows by (src, dst, protocol, normalized_template). On flush,
//! the current window is swapped out and returned as `AggregatedFlow`s for
//! the DAG to ingest.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use regex::Regex;

use crate::protocol::Protocol;

// ── Flow Key & Stats ────────────────────────────────────────────────────

/// Deduplication key for aggregated flows.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src: String,
    pub dst: String,
    pub protocol: Protocol,
    pub template: String,
}

/// Accumulated statistics for a single flow within one aggregation window.
#[derive(Debug, Clone)]
pub struct FlowStats {
    pub request_count: u64,
    pub error_count: u64,
    pub pii_hit_count: u64,
    pub total_request_bytes: u64,
    pub total_response_bytes: u64,
    pub latency_sum_ns: u64,
    pub latency_max_ns: u64,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl FlowStats {
    fn new(timestamp_ns: u64) -> Self {
        Self {
            request_count: 0,
            error_count: 0,
            pii_hit_count: 0,
            total_request_bytes: 0,
            total_response_bytes: 0,
            latency_sum_ns: 0,
            latency_max_ns: 0,
            first_seen: timestamp_ns,
            last_seen: timestamp_ns,
        }
    }
}

/// A completed aggregated flow ready for DAG ingestion.
#[derive(Debug, Clone)]
pub struct AggregatedFlow {
    pub key: FlowKey,
    pub stats: FlowStats,
}

// ── Edge Aggregator ─────────────────────────────────────────────────────

/// Concurrent edge aggregator using a DashMap for lock-free per-key updates.
pub struct EdgeAggregator {
    current_window: DashMap<FlowKey, FlowStats>,
    window_start: AtomicU64,
    window_duration: Duration,
    uuid_re: Regex,
}

impl EdgeAggregator {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            current_window: DashMap::new(),
            window_start: AtomicU64::new(now_epoch_ms()),
            window_duration,
            uuid_re: Regex::new(
                r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            )
            .expect("UUID regex is valid"),
        }
    }

    /// Record a single request/response observation.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        src: &str,
        dst: &str,
        protocol: Protocol,
        method: Option<&str>,
        path: Option<&str>,
        status: Option<u32>,
        latency_ns: Option<u64>,
        req_bytes: u64,
        resp_bytes: u64,
        has_pii: bool,
        timestamp_ns: u64,
    ) {
        let template = self.normalize_template(protocol, method, path);
        let key = FlowKey {
            src: src.to_string(),
            dst: dst.to_string(),
            protocol,
            template,
        };

        let mut entry = self
            .current_window
            .entry(key)
            .or_insert_with(|| FlowStats::new(timestamp_ns));

        let stats = entry.value_mut();
        stats.request_count += 1;
        stats.total_request_bytes += req_bytes;
        stats.total_response_bytes += resp_bytes;
        stats.last_seen = timestamp_ns;

        if let Some(lat) = latency_ns {
            stats.latency_sum_ns += lat;
            if lat > stats.latency_max_ns {
                stats.latency_max_ns = lat;
            }
        }

        // HTTP 4xx/5xx are errors; for other protocols, no status = not an error
        if let Some(code) = status
            && code >= 400
        {
            stats.error_count += 1;
        }

        if has_pii {
            stats.pii_hit_count += 1;
        }
    }

    /// Swap out the current window and return all completed flows.
    pub fn flush(&self) -> Vec<AggregatedFlow> {
        // Drain all entries from the current window
        let mut flows = Vec::new();
        let entries: Vec<_> = self
            .current_window
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect();

        self.current_window.clear();
        self.window_start.store(now_epoch_ms(), Ordering::Relaxed);

        for (key, stats) in entries {
            flows.push(AggregatedFlow { key, stats });
        }
        flows
    }

    /// Normalize a method+path into a deduplication template.
    ///
    /// - HTTP: `GET /api/users/550e8400-...` -> `GET /api/users/?`
    /// - SQL: `SELECT * FROM users WHERE id = 123` -> `SELECT * FROM users WHERE id = ?`
    /// - Other: pass through as-is
    pub fn normalize_template(
        &self,
        protocol: Protocol,
        method: Option<&str>,
        path: Option<&str>,
    ) -> String {
        let method_str = method.unwrap_or("");
        let path_str = path.unwrap_or("");

        if method_str.is_empty() && path_str.is_empty() {
            return String::new();
        }

        match protocol {
            Protocol::Http1 | Protocol::Http2 | Protocol::Grpc => {
                let normalized_path = self.normalize_http_path(path_str);
                if method_str.is_empty() {
                    normalized_path
                } else {
                    format!("{} {}", method_str, normalized_path)
                }
            }
            Protocol::Mysql | Protocol::Postgres => {
                // SQL normalization: replace literals with ?
                normalize_sql(path_str)
            }
            _ => {
                // Redis keys, etc. — pass through
                if method_str.is_empty() {
                    path_str.to_string()
                } else {
                    format!("{} {}", method_str, path_str)
                }
            }
        }
    }

    /// Replace UUIDs and numeric path segments in HTTP paths.
    fn normalize_http_path(&self, path: &str) -> String {
        // Replace UUIDs
        let result = self.uuid_re.replace_all(path, "?");

        // Replace pure-numeric path segments: /users/123/posts -> /users/?/posts
        let mut out = String::with_capacity(result.len());
        for (i, segment) in result.split('/').enumerate() {
            if i > 0 {
                out.push('/');
            }
            if !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()) {
                out.push('?');
            } else {
                out.push_str(segment);
            }
        }
        out
    }

    /// Number of active flow keys in the current window.
    pub fn active_flows(&self) -> usize {
        self.current_window.len()
    }
}

/// Normalize SQL queries by replacing string literals and numeric constants with `?`.
fn normalize_sql(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\'' | '"' => {
                result.push('?');
                for inner in chars.by_ref() {
                    if inner == ch {
                        break;
                    }
                }
            }
            '0'..='9' if is_sql_number_start(&result) => {
                result.push('?');
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_digit() || *c == '.')
                {
                    chars.next();
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Check if the position in the SQL string looks like the start of a numeric literal
/// (preceded by whitespace, =, (, comma, or start of string).
fn is_sql_number_start(preceding: &str) -> bool {
    match preceding.chars().last() {
        None => true,
        Some(c) => matches!(c, ' ' | '=' | '(' | ',' | '\t' | '\n' | '>' | '<'),
    }
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_aggregator() -> EdgeAggregator {
        EdgeAggregator::new(Duration::from_secs(10))
    }

    #[test]
    fn test_record_basic() {
        let agg = make_aggregator();
        agg.record(
            "nginx",
            "api",
            Protocol::Http1,
            Some("GET"),
            Some("/health"),
            Some(200),
            Some(1000),
            100,
            50,
            false,
            1,
        );

        assert_eq!(agg.active_flows(), 1);
    }

    #[test]
    fn test_dedup_same_template() {
        let agg = make_aggregator();
        // Two requests to different user IDs should dedup
        agg.record(
            "nginx",
            "api",
            Protocol::Http1,
            Some("GET"),
            Some("/users/123"),
            Some(200),
            Some(1000),
            100,
            50,
            false,
            1,
        );
        agg.record(
            "nginx",
            "api",
            Protocol::Http1,
            Some("GET"),
            Some("/users/456"),
            Some(200),
            Some(2000),
            100,
            50,
            false,
            2,
        );

        // Both normalize to "GET /users/?" -> 1 flow
        assert_eq!(agg.active_flows(), 1);

        let flows = agg.flush();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].stats.request_count, 2);
        assert_eq!(flows[0].stats.latency_sum_ns, 3000);
    }

    #[test]
    fn test_flush_returns_and_clears() {
        let agg = make_aggregator();
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("GET"),
            Some("/"),
            Some(200),
            None,
            0,
            0,
            false,
            1,
        );

        let flows = agg.flush();
        assert_eq!(flows.len(), 1);
        assert_eq!(agg.active_flows(), 0);

        // Second flush should be empty
        let flows2 = agg.flush();
        assert!(flows2.is_empty());
    }

    #[test]
    fn test_normalize_http_uuid() {
        let agg = make_aggregator();
        let t = agg.normalize_template(
            Protocol::Http1,
            Some("GET"),
            Some("/api/users/550e8400-e29b-41d4-a716-446655440000/profile"),
        );
        assert_eq!(t, "GET /api/users/?/profile");
    }

    #[test]
    fn test_normalize_http_numeric() {
        let agg = make_aggregator();
        let t =
            agg.normalize_template(Protocol::Http1, Some("GET"), Some("/api/posts/42/comments"));
        assert_eq!(t, "GET /api/posts/?/comments");
    }

    #[test]
    fn test_normalize_sql_literals() {
        let agg = make_aggregator();
        let t = agg.normalize_template(
            Protocol::Postgres,
            None,
            Some("SELECT * FROM users WHERE id = 123 AND name = 'alice'"),
        );
        assert_eq!(t, "SELECT * FROM users WHERE id = ? AND name = ?");
    }

    #[test]
    fn test_error_counting() {
        let agg = make_aggregator();
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("GET"),
            Some("/"),
            Some(200),
            None,
            0,
            0,
            false,
            1,
        );
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("GET"),
            Some("/"),
            Some(500),
            None,
            0,
            0,
            false,
            2,
        );
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("GET"),
            Some("/"),
            Some(404),
            None,
            0,
            0,
            false,
            3,
        );

        let flows = agg.flush();
        assert_eq!(flows[0].stats.request_count, 3);
        assert_eq!(flows[0].stats.error_count, 2); // 500 + 404
    }

    #[test]
    fn test_pii_hit_tracking() {
        let agg = make_aggregator();
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("POST"),
            Some("/data"),
            Some(200),
            None,
            0,
            0,
            true,
            1,
        );
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("POST"),
            Some("/data"),
            Some(200),
            None,
            0,
            0,
            false,
            2,
        );
        agg.record(
            "a",
            "b",
            Protocol::Http1,
            Some("POST"),
            Some("/data"),
            Some(200),
            None,
            0,
            0,
            true,
            3,
        );

        let flows = agg.flush();
        assert_eq!(flows[0].stats.pii_hit_count, 2);
    }
}
