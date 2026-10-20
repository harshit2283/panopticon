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

/// Most distinct flows (src, dst, protocol, template) kept per window. Past
/// it, new templates are folded into [`OVERFLOW_TEMPLATE`] for their edge,
/// so memory stays bounded whatever identifiers the normalizer misses.
pub const MAX_FLOWS_PER_WINDOW: usize = 20_000;
/// Template that absorbs flows beyond [`MAX_FLOWS_PER_WINDOW`].
pub const OVERFLOW_TEMPLATE: &str = "<other>";

/// Concurrent edge aggregator using a DashMap for lock-free per-key updates.
pub struct EdgeAggregator {
    current_window: DashMap<FlowKey, FlowStats>,
    window_start: AtomicU64,
    window_duration: Duration,
    uuid_re: Regex,
    /// Observations folded into OVERFLOW_TEMPLATE (cumulative).
    overflowed: AtomicU64,
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
            overflowed: AtomicU64::new(0),
        }
    }

    /// Observations folded into the overflow template so far.
    pub fn overflowed(&self) -> u64 {
        self.overflowed.load(Ordering::Relaxed)
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
        let mut key = FlowKey {
            src: src.to_string(),
            dst: dst.to_string(),
            protocol,
            template,
        };
        // Approximate under concurrency (len() and the insert race), which
        // only lets the cap be exceeded by a few entries.
        if self.current_window.len() >= MAX_FLOWS_PER_WINDOW
            && !self.current_window.contains_key(&key)
        {
            key.template = OVERFLOW_TEMPLATE.to_string();
            self.overflowed.fetch_add(1, Ordering::Relaxed);
        }

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
            Protocol::Redis => {
                // Keys usually embed ids (user:1234, session:9f86d081...)
                let key = normalize_ids(path_str);
                if method_str.is_empty() {
                    key
                } else {
                    format!("{} {}", method_str, key)
                }
            }
            _ => {
                // Kafka topics, DNS names, etc. — pass through
                if method_str.is_empty() {
                    path_str.to_string()
                } else {
                    format!("{} {}", method_str, path_str)
                }
            }
        }
    }

    /// Replace UUIDs, numeric and long-hex path segments in HTTP paths, and
    /// query values (keys kept): `/users/123/posts?page=2` ->
    /// `/users/?/posts?page=?`. Query values left in made every request a
    /// distinct template (cache-busters, request ids).
    fn normalize_http_path(&self, path: &str) -> String {
        let (path, query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path, None),
        };
        // Replace UUIDs
        let result = self.uuid_re.replace_all(path, "?");

        // Replace id-like path segments: /users/123/posts -> /users/?/posts
        let mut out = String::with_capacity(result.len());
        for (i, segment) in result.split('/').enumerate() {
            if i > 0 {
                out.push('/');
            }
            if is_id_segment(segment) {
                out.push('?');
            } else {
                out.push_str(segment);
            }
        }
        if let Some(query) = query {
            out.push('?');
            for (i, pair) in query.split('&').enumerate() {
                if i > 0 {
                    out.push('&');
                }
                match pair.split_once('=') {
                    Some((k, _)) => {
                        out.push_str(k);
                        out.push_str("=?");
                    }
                    None => out.push_str(pair),
                }
            }
        }
        out
    }

    /// Number of active flow keys in the current window.
    pub fn active_flows(&self) -> usize {
        self.current_window.len()
    }
}

/// A path segment that identifies an instance rather than a route: all
/// digits, or a hex string of 12+ characters (hashes, object ids).
fn is_id_segment(segment: &str) -> bool {
    !segment.is_empty()
        && (segment.bytes().all(|b| b.is_ascii_digit())
            || (segment.len() >= 12 && segment.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Replace digit runs, and hex runs of 12+ characters, with `?`:
/// `user:1234:cart` -> `user:?:cart`.
fn normalize_ids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hex_end = bytes[i..]
            .iter()
            .position(|b| !b.is_ascii_hexdigit())
            .map_or(bytes.len(), |n| i + n);
        let run = &bytes[i..hex_end];
        // A hex run is replaced if it is long, or if it is all digits.
        if run.len() >= 12 || (!run.is_empty() && run.iter().all(u8::is_ascii_digit)) {
            out.push('?');
            i = hex_end;
        } else if !run.is_empty() {
            // Short alphanumeric run (e.g. "cafe1"): keep letters, mask digits.
            let mut prev_digit = false;
            for &b in run {
                if b.is_ascii_digit() {
                    if !prev_digit {
                        out.push('?');
                    }
                    prev_digit = true;
                } else {
                    out.push(b as char);
                    prev_digit = false;
                }
            }
            i = hex_end;
        } else {
            // Not hex: copy the whole (possibly multi-byte) character.
            let ch = s[i..].chars().next().expect("in bounds");
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
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

    #[test]
    fn query_values_and_hex_ids_are_normalized() {
        let agg = EdgeAggregator::new(Duration::from_secs(10));
        let t = |p: &str| agg.normalize_template(Protocol::Http1, Some("GET"), Some(p));
        assert_eq!(t("/len/512?id=r123"), "GET /len/??id=?");
        assert_eq!(t("/a?x=1&y=two&flag"), "GET /a?x=?&y=?&flag");
        assert_eq!(t("/blobs/9f86d081884c7d659a2feaa0"), "GET /blobs/?");
        assert_eq!(t("/v1/users"), "GET /v1/users");
        assert_eq!(t("/len/512?id=r1"), t("/len/9?id=r2"));
    }

    #[test]
    fn redis_keys_are_normalized() {
        let agg = EdgeAggregator::new(Duration::from_secs(10));
        let t = |k: &str| agg.normalize_template(Protocol::Redis, Some("GET"), Some(k));
        assert_eq!(t("user:1234:cart"), "GET user:?:cart");
        assert_eq!(t("session:9f86d081884c7d65"), "GET session:?");
        assert_eq!(t("cache:v2:éte"), "GET cache:v?:éte");
    }

    #[test]
    fn flows_per_window_are_capped() {
        let agg = EdgeAggregator::new(Duration::from_secs(10));
        // Distinct templates the normalizer can't collapse (letters only).
        let words: Vec<String> = (0..MAX_FLOWS_PER_WINDOW + 500)
            .map(|n| {
                let mut w = String::new();
                let mut n = n;
                loop {
                    w.push((b'g' + (n % 20) as u8) as char);
                    n /= 20;
                    if n == 0 {
                        break;
                    }
                }
                format!("/{w}")
            })
            .collect();
        for w in &words {
            agg.record(
                "a",
                "b",
                Protocol::Http1,
                Some("GET"),
                Some(w),
                Some(200),
                None,
                0,
                0,
                false,
                1,
            );
        }
        assert_eq!(agg.active_flows(), MAX_FLOWS_PER_WINDOW + 1);
        assert_eq!(agg.overflowed(), 500);
        let flows = agg.flush();
        let other = flows
            .iter()
            .find(|f| f.key.template == OVERFLOW_TEMPLATE)
            .unwrap();
        assert_eq!(other.stats.request_count, 500);
    }

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
