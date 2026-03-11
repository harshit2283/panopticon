#![allow(dead_code)]

use std::time::Duration;

use serde::Deserialize;

/// Sampling mode controls the trade-off between coverage and overhead.
#[derive(Debug, Clone, PartialEq)]
pub enum SamplingMode {
    /// Track ALL packets for all connections (dedicated monitoring).
    Full,
    /// Sample a percentage of connections (low-overhead mode).
    ConnectionSample,
    /// Only track first N bytes per connection (header-only mode).
    HeadOnly { max_bytes: usize },
}

/// Agent configuration controlling resource usage, capture behavior, and export.
///
/// Synced to the eBPF CONFIG array map on startup and config reload.
/// All resource bounds are hard limits — exceeding them causes drops, never blocks.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    // ── Capture control ────────────────────────────
    /// Master switch — disables all capture when false.
    pub capture_enabled: bool,
    /// Network interfaces to attach TC classifiers to.
    pub interfaces: Vec<String>,
    /// If set, only capture traffic from these PIDs.
    pub pid_filter: Option<Vec<u32>>,

    // ── Resource budgets ───────────────────────────
    /// Rate limit in events/sec. 0 = unlimited. Events beyond this are dropped.
    pub max_events_per_sec: u64,
    /// Fixed worker pool size. Each worker drains a bounded channel.
    pub max_worker_count: usize,
    /// Per-worker bounded channel capacity. try_send drops if full.
    pub worker_channel_capacity: usize,
    /// DashMap capacity hint for connection tracking.
    pub max_connections_tracked: usize,
    /// Evict idle connection state after this duration.
    pub idle_connection_timeout: Duration,

    // ── Sampling ───────────────────────────────────
    /// Sampling strategy for connections.
    pub sampling_mode: SamplingMode,
    /// Fraction of connections to track (0.0–1.0), used with ConnectionSample mode.
    pub sample_rate: f64,

    // ── TLS interception ────────────────────────────
    /// Enable TLS library scanning and uprobe attachment.
    pub tls_scan_enabled: bool,
    /// Interval between full /proc rescans.
    pub tls_scan_interval: Duration,

    // ── PII detection ─────────────────────────────
    /// PII detection pipeline configuration.
    pub pii: PiiConfig,
    /// Allowlist of external PII service URL origins (e.g. "https://trusted-service.internal").
    pub pii_external_url_allowlist: Vec<String>,

    // ── Service graph ─────────────────────────────
    /// Service dependency graph configuration.
    pub graph: GraphConfig,

    // ── Export ──────────────────────────────────────
    /// Print events to stdout (dev/debug mode).
    pub log_events: bool,
    /// If set, write events as JSONL to this file path.
    pub json_export_path: Option<String>,
    /// If set, write PII audit entries to this file path.
    pub pii_audit_log_path: Option<String>,
    /// OTLP gRPC export configuration.
    pub otlp: OtlpConfig,

    // ── Observability ──────────────────────────────────
    /// Bind address for HTTP server (health, metrics, debug). None = disabled.
    pub metrics_bind: Option<String>,

    // ── Testing ─────────────────────────────────────
    /// Run smoke test (attach probes, verify events, exit).
    pub smoke_test: bool,

    // ── Map pinning ─────────────────────────────────
    /// If set, pin eBPF maps to this bpffs directory for zero-gap restarts.
    /// Directory must exist and bpffs must be mounted (typically /sys/fs/bpf/).
    pub map_pin_path: Option<String>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            capture_enabled: true,
            interfaces: vec!["eth0".to_string()],
            pid_filter: None,

            max_events_per_sec: 500_000,
            max_worker_count: num_cpus(),
            worker_channel_capacity: 1024,
            max_connections_tracked: 65_536,
            idle_connection_timeout: Duration::from_secs(30),

            sampling_mode: SamplingMode::Full,
            sample_rate: 1.0,

            tls_scan_enabled: true,
            tls_scan_interval: Duration::from_secs(60),

            pii: PiiConfig::default(),
            pii_external_url_allowlist: vec![],

            graph: GraphConfig::default(),

            log_events: false,
            json_export_path: None,
            pii_audit_log_path: None,
            otlp: OtlpConfig::default(),

            metrics_bind: None,

            smoke_test: false,

            map_pin_path: None,
        }
    }
}

/// Configuration for OTLP gRPC export.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// Master switch for OTLP exporter.
    pub enabled: bool,
    /// OTLP collector endpoint, e.g. "http://127.0.0.1:4317".
    pub endpoint: String,
    /// Value used for OpenTelemetry `service.name` resource attribute.
    pub service_name: String,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:4317".to_string(),
            service_name: "panopticon-agent".to_string(),
        }
    }
}

/// PII detection mode: disabled, in-agent ML, or external service.
#[derive(Debug, Clone, PartialEq)]
pub enum PiiMode {
    /// PII detection disabled.
    Disabled,
    /// In-agent ML inference with ONNX model.
    InAgent {
        model_path: String,
        max_inferences_per_sec: u32,
    },
    /// External HTTP service for PII detection.
    External {
        url: String,
        sample_rate: f64,
        timeout_ms: u32,
    },
}

/// Configuration for the PII detection pipeline.
#[derive(Debug, Clone)]
pub struct PiiConfig {
    /// Master switch — disables all PII scanning when false.
    pub enabled: bool,
    /// Enable regex-based pattern matching (fast, ~1µs).
    pub regex_enabled: bool,
    /// PII detection mode (ML, external service, or disabled).
    pub mode: PiiMode,
    /// Replace detected PII with `<CATEGORY>` placeholders.
    pub redact: bool,
    /// Minimum confidence threshold for detected entities.
    pub min_confidence: f32,
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            regex_enabled: true,
            mode: PiiMode::Disabled,
            redact: true,
            min_confidence: 0.7,
        }
    }
}

/// Configuration for the service dependency graph.
#[derive(Debug, Clone)]
pub struct GraphConfig {
    /// Master switch — disables graph building when false.
    pub enabled: bool,
    /// Time window for edge aggregation before flushing to DAG.
    pub aggregation_window: Duration,
    /// Remove edges not seen within this duration.
    pub stale_edge_timeout: Duration,
    /// TTL for identity resolution cache entries.
    pub identity_cache_ttl: Duration,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            aggregation_window: Duration::from_secs(10),
            stale_edge_timeout: Duration::from_secs(300),
            identity_cache_ttl: Duration::from_secs(300),
        }
    }
}

/// Returns available CPU count, falling back to 4.
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

// ── TOML Config File Support ─────────────────────────────────────────────

/// Intermediate struct for TOML deserialization.
/// All fields are `Option<T>` so partial config files work — missing fields keep defaults.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AgentConfigFile {
    pub capture_enabled: Option<bool>,
    pub interfaces: Option<Vec<String>>,
    pub pid_filter: Option<Vec<u32>>,
    pub max_events_per_sec: Option<u64>,
    pub max_worker_count: Option<usize>,
    pub worker_channel_capacity: Option<usize>,
    pub max_connections_tracked: Option<usize>,
    pub idle_connection_timeout_secs: Option<u64>,
    pub sampling_mode: Option<String>,
    pub sample_rate: Option<f64>,
    pub tls_scan_enabled: Option<bool>,
    pub tls_scan_interval_secs: Option<u64>,
    pub pii: Option<PiiConfigFile>,
    pub pii_external_url_allowlist: Option<Vec<String>>,
    pub graph: Option<GraphConfigFile>,
    pub log_events: Option<bool>,
    pub json_export_path: Option<String>,
    pub pii_audit_log_path: Option<String>,
    pub otlp: Option<OtlpConfigFile>,
    pub metrics_bind: Option<String>,
    pub map_pin_path: Option<String>,
}

/// TOML-friendly PII config subset.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PiiConfigFile {
    pub enabled: Option<bool>,
    pub regex_enabled: Option<bool>,
    pub redact: Option<bool>,
    pub min_confidence: Option<f32>,
}

/// TOML-friendly graph config subset.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct GraphConfigFile {
    pub enabled: Option<bool>,
    pub aggregation_window_secs: Option<u64>,
    pub stale_edge_timeout_secs: Option<u64>,
    pub identity_cache_ttl_secs: Option<u64>,
}

/// TOML-friendly OTLP config subset.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct OtlpConfigFile {
    pub enabled: Option<bool>,
    pub endpoint: Option<String>,
    pub service_name: Option<String>,
}

impl AgentConfigFile {
    /// Apply non-None fields from this file config onto a base config.
    pub fn merge_into(self, base: &mut AgentConfig) {
        if let Some(v) = self.capture_enabled {
            base.capture_enabled = v;
        }
        if let Some(v) = self.interfaces {
            base.interfaces = v;
        }
        if let Some(v) = self.pid_filter {
            base.pid_filter = Some(v);
        }
        if let Some(v) = self.max_events_per_sec {
            base.max_events_per_sec = v;
        }
        if let Some(v) = self.max_worker_count {
            base.max_worker_count = v;
        }
        if let Some(v) = self.worker_channel_capacity {
            base.worker_channel_capacity = v;
        }
        if let Some(v) = self.max_connections_tracked {
            base.max_connections_tracked = v;
        }
        if let Some(v) = self.idle_connection_timeout_secs {
            base.idle_connection_timeout = Duration::from_secs(v);
        }
        if let Some(v) = self.sampling_mode {
            base.sampling_mode = match v.as_str() {
                "connection_sample" => SamplingMode::ConnectionSample,
                "head_only" => SamplingMode::HeadOnly { max_bytes: 4096 },
                _ => SamplingMode::Full,
            };
        }
        if let Some(v) = self.sample_rate {
            base.sample_rate = v;
        }
        if let Some(v) = self.tls_scan_enabled {
            base.tls_scan_enabled = v;
        }
        if let Some(v) = self.tls_scan_interval_secs {
            base.tls_scan_interval = Duration::from_secs(v);
        }
        if let Some(pii) = self.pii {
            pii.merge_into(&mut base.pii);
        }
        if let Some(v) = self.pii_external_url_allowlist {
            base.pii_external_url_allowlist = v;
        }
        if let Some(graph) = self.graph {
            graph.merge_into(&mut base.graph);
        }
        if let Some(v) = self.log_events {
            base.log_events = v;
        }
        if let Some(v) = self.json_export_path {
            base.json_export_path = Some(v);
        }
        if let Some(v) = self.pii_audit_log_path {
            base.pii_audit_log_path = Some(v);
        }
        if let Some(otlp) = self.otlp {
            otlp.merge_into(&mut base.otlp);
        }
        if let Some(v) = self.metrics_bind {
            base.metrics_bind = Some(v);
        }
        if let Some(v) = self.map_pin_path {
            base.map_pin_path = Some(v);
        }
    }
}

impl PiiConfigFile {
    fn merge_into(self, base: &mut PiiConfig) {
        if let Some(v) = self.enabled {
            base.enabled = v;
        }
        if let Some(v) = self.regex_enabled {
            base.regex_enabled = v;
        }
        if let Some(v) = self.redact {
            base.redact = v;
        }
        if let Some(v) = self.min_confidence {
            base.min_confidence = v;
        }
    }
}

impl GraphConfigFile {
    fn merge_into(self, base: &mut GraphConfig) {
        if let Some(v) = self.enabled {
            base.enabled = v;
        }
        if let Some(v) = self.aggregation_window_secs {
            base.aggregation_window = Duration::from_secs(v);
        }
        if let Some(v) = self.stale_edge_timeout_secs {
            base.stale_edge_timeout = Duration::from_secs(v);
        }
        if let Some(v) = self.identity_cache_ttl_secs {
            base.identity_cache_ttl = Duration::from_secs(v);
        }
    }
}

impl OtlpConfigFile {
    fn merge_into(self, base: &mut OtlpConfig) {
        if let Some(v) = self.enabled {
            base.enabled = v;
        }
        if let Some(v) = self.endpoint {
            base.endpoint = v;
        }
        if let Some(v) = self.service_name {
            base.service_name = v;
        }
    }
}

/// Load an `AgentConfig` from a TOML file.
///
/// Parses the file into the intermediate `AgentConfigFile` with all-optional fields,
/// then merges onto the defaults. Missing fields retain their default values.
pub fn load_config(path: &str) -> anyhow::Result<AgentConfig> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", path, e))?;
    load_config_from_str(&content)
}

/// Load an `AgentConfig` from a TOML string.
pub fn load_config_from_str(content: &str) -> anyhow::Result<AgentConfig> {
    let file_config: AgentConfigFile =
        toml::from_str(content).map_err(|e| anyhow::anyhow!("Invalid TOML config: {}", e))?;
    let mut config = AgentConfig::default();
    file_config.merge_into(&mut config);
    validate_config(&config)?;
    Ok(config)
}

fn validate_config(config: &AgentConfig) -> anyhow::Result<()> {
    if config.max_worker_count == 0 {
        return Err(anyhow::anyhow!("max_worker_count must be >= 1"));
    }
    if config.worker_channel_capacity == 0 {
        return Err(anyhow::anyhow!("worker_channel_capacity must be >= 1"));
    }
    if !(0.0..=1.0).contains(&config.sample_rate) {
        return Err(anyhow::anyhow!("sample_rate must be between 0.0 and 1.0"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AgentConfig::default();
        assert!(config.capture_enabled);
        assert_eq!(config.max_events_per_sec, 500_000);
        assert!(config.max_worker_count >= 1);
        assert_eq!(config.worker_channel_capacity, 1024);
        assert_eq!(config.max_connections_tracked, 65_536);
        assert_eq!(config.idle_connection_timeout, Duration::from_secs(30));
        assert_eq!(config.sampling_mode, SamplingMode::Full);
        assert_eq!(config.sample_rate, 1.0);
        assert!(!config.log_events);
        assert!(config.pid_filter.is_none());
        assert!(config.tls_scan_enabled);
        assert_eq!(config.tls_scan_interval, Duration::from_secs(60));
        assert!(config.pii.enabled);
        assert!(config.pii.regex_enabled);
        assert_eq!(config.pii.mode, PiiMode::Disabled);
        assert!(config.pii.redact);
        assert!((config.pii.min_confidence - 0.7).abs() < f32::EPSILON);
        assert!(config.json_export_path.is_none());
        assert!(config.pii_audit_log_path.is_none());
        assert!(!config.otlp.enabled);
        assert_eq!(config.otlp.endpoint, "http://127.0.0.1:4317");
        assert_eq!(config.otlp.service_name, "panopticon-agent");
        assert!(config.pii_external_url_allowlist.is_empty());
        assert!(!config.smoke_test);
        assert!(config.graph.enabled);
        assert_eq!(config.graph.aggregation_window, Duration::from_secs(10));
        assert_eq!(config.graph.stale_edge_timeout, Duration::from_secs(300));
        assert_eq!(config.graph.identity_cache_ttl, Duration::from_secs(300));
        assert!(config.metrics_bind.is_none());
    }

    #[test]
    fn test_sampling_mode_variants() {
        let full = SamplingMode::Full;
        let sample = SamplingMode::ConnectionSample;
        let head = SamplingMode::HeadOnly { max_bytes: 256 };

        assert_eq!(full, SamplingMode::Full);
        assert_eq!(sample, SamplingMode::ConnectionSample);
        assert!(matches!(head, SamplingMode::HeadOnly { max_bytes: 256 }));
    }

    #[test]
    fn test_load_config_full_toml() {
        let toml = r#"
            capture_enabled = false
            interfaces = ["wlan0", "eth1"]
            max_events_per_sec = 100000
            max_worker_count = 8
            worker_channel_capacity = 2048
            max_connections_tracked = 10000
            idle_connection_timeout_secs = 60
            sampling_mode = "connection_sample"
            sample_rate = 0.5
            tls_scan_enabled = false
            tls_scan_interval_secs = 120
            log_events = true
            json_export_path = "/tmp/events.jsonl"
            pii_audit_log_path = "/tmp/pii_audit.jsonl"
            metrics_bind = "0.0.0.0:9090"
            map_pin_path = "/sys/fs/bpf/panopticon"

            [otlp]
            enabled = true
            endpoint = "http://collector:4317"
            service_name = "panopticon-prod"

            [pii]
            enabled = true
            regex_enabled = false
            redact = false
            min_confidence = 0.9

            [graph]
            enabled = false
            aggregation_window_secs = 30
            stale_edge_timeout_secs = 600
            identity_cache_ttl_secs = 120
        "#;

        let config = load_config_from_str(toml).unwrap();
        assert!(!config.capture_enabled);
        assert_eq!(config.interfaces, vec!["wlan0", "eth1"]);
        assert_eq!(config.max_events_per_sec, 100_000);
        assert_eq!(config.max_worker_count, 8);
        assert_eq!(config.worker_channel_capacity, 2048);
        assert_eq!(config.max_connections_tracked, 10_000);
        assert_eq!(config.idle_connection_timeout, Duration::from_secs(60));
        assert_eq!(config.sampling_mode, SamplingMode::ConnectionSample);
        assert!((config.sample_rate - 0.5).abs() < f64::EPSILON);
        assert!(!config.tls_scan_enabled);
        assert_eq!(config.tls_scan_interval, Duration::from_secs(120));
        assert!(config.log_events);
        assert_eq!(
            config.json_export_path.as_deref(),
            Some("/tmp/events.jsonl")
        );
        assert_eq!(
            config.pii_audit_log_path.as_deref(),
            Some("/tmp/pii_audit.jsonl")
        );
        assert_eq!(config.metrics_bind.as_deref(), Some("0.0.0.0:9090"));
        assert_eq!(
            config.map_pin_path.as_deref(),
            Some("/sys/fs/bpf/panopticon")
        );
        assert!(config.otlp.enabled);
        assert_eq!(config.otlp.endpoint, "http://collector:4317");
        assert_eq!(config.otlp.service_name, "panopticon-prod");
        assert!(config.pii.enabled);
        assert!(!config.pii.regex_enabled);
        assert!(!config.pii.redact);
        assert!((config.pii.min_confidence - 0.9).abs() < f32::EPSILON);
        assert!(!config.graph.enabled);
        assert_eq!(config.graph.aggregation_window, Duration::from_secs(30));
        assert_eq!(config.graph.stale_edge_timeout, Duration::from_secs(600));
        assert_eq!(config.graph.identity_cache_ttl, Duration::from_secs(120));
    }

    #[test]
    fn test_load_config_partial_toml() {
        let toml = r#"
            max_events_per_sec = 250000
            metrics_bind = "127.0.0.1:8080"
        "#;

        let config = load_config_from_str(toml).unwrap();
        // Overridden values
        assert_eq!(config.max_events_per_sec, 250_000);
        assert_eq!(config.metrics_bind.as_deref(), Some("127.0.0.1:8080"));
        // Defaults preserved
        assert!(config.capture_enabled);
        assert_eq!(config.interfaces, vec!["eth0"]);
        assert_eq!(config.max_worker_count, num_cpus());
        assert!(!config.otlp.enabled);
        assert!(config.pii.enabled);
        assert!(config.graph.enabled);
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let toml = "this is not valid {{{{ toml";
        let result = load_config_from_str(toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_empty_toml() {
        let config = load_config_from_str("").unwrap();
        // All defaults
        assert!(config.capture_enabled);
        assert_eq!(config.max_events_per_sec, 500_000);
        assert!(config.metrics_bind.is_none());
    }

    #[test]
    fn test_merge_into_preserves_defaults() {
        let file_config = AgentConfigFile {
            capture_enabled: Some(false),
            ..AgentConfigFile::default()
        };
        let mut config = AgentConfig::default();
        file_config.merge_into(&mut config);

        assert!(!config.capture_enabled);
        // Everything else untouched
        assert_eq!(config.max_events_per_sec, 500_000);
        assert_eq!(config.interfaces, vec!["eth0"]);
        assert!(config.pii.enabled);
    }

    #[test]
    fn test_load_config_file_not_found() {
        let result = load_config("/nonexistent/path/config.toml");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_zero_worker_count_rejected() {
        let toml = r#"
            max_worker_count = 0
        "#;
        let err = load_config_from_str(toml).unwrap_err().to_string();
        assert!(err.contains("max_worker_count must be >= 1"));
    }

    #[test]
    fn test_invalid_zero_channel_capacity_rejected() {
        let toml = r#"
            worker_channel_capacity = 0
        "#;
        let err = load_config_from_str(toml).unwrap_err().to_string();
        assert!(err.contains("worker_channel_capacity must be >= 1"));
    }

    #[test]
    fn test_invalid_sample_rate_rejected() {
        let toml = r#"
            sample_rate = 1.5
        "#;
        let err = load_config_from_str(toml).unwrap_err().to_string();
        assert!(err.contains("sample_rate must be between 0.0 and 1.0"));
    }
}
