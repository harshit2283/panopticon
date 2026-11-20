#![allow(dead_code)]

use std::time::Duration;

use serde::Deserialize;

/// What part of the traffic is captured (`sampling_mode`). Decided in the
/// kernel per socket (DESIGN §3.3, §3.4) before anything reaches a parser or
/// a sink.
#[derive(Debug, Clone, PartialEq)]
pub enum SamplingMode {
    /// Every connection, whole.
    Full,
    /// Each connection is kept or dropped whole; `sample_rate` of them kept.
    ConnectionSample,
    /// Only the first `max_bytes` of each connection, per direction.
    HeadOnly { max_bytes: u64 },
}

impl SamplingMode {
    pub const NAMES: [&'static str; 3] = ["full", "connection_sample", "head_only"];
}

/// `pid_filter_listener`: which process of an accepted (server) connection
/// `pid_filter` selects it by (DESIGN §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ListenerRule {
    /// Only the process that accepted it is listed (the default).
    #[default]
    Acceptor,
    /// Its acceptor, or the process that created its listener while the
    /// agent ran, is listed.
    Creator,
}

/// The scope settings a reload may change in either direction besides the
/// cgroup selectors: kernel `CONFIG` values, applied
/// by the scope publisher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeOptions {
    /// `capture_loopback` (`CONFIG_CAPTURE_LOOPBACK`).
    pub capture_loopback: bool,
    /// `pid_filter_listener = "creator"` (`CONFIG_PID_CREATOR_RULE`).
    pub creator_rule: bool,
}

impl ScopeOptions {
    pub fn of(config: &AgentConfig) -> Self {
        Self {
            capture_loopback: config.capture_loopback,
            creator_rule: config.pid_filter_listener == ListenerRule::Creator,
        }
    }

    /// Whether moving to `to` takes scope away (a narrowing, DESIGN §3):
    /// loopback capture turned off, or the creator rule replaced by the
    /// acceptor rule. Either can stop a connection that was captured.
    pub fn narrows_to(self, to: Self) -> bool {
        (self.capture_loopback && !to.capture_loopback) || (self.creator_rule && !to.creator_rule)
    }
}

/// Default `head_only_bytes`.
pub const DEFAULT_HEAD_ONLY_BYTES: u64 = 4096;
/// Upper bound for `head_only_bytes`: keeps TCP stream offsets far from
/// sequence-number wraparound.
pub const MAX_HEAD_ONLY_BYTES: u64 = 1 << 30;

/// What captured data may leave the agent: the one data-handling setting.
///
/// Ordered from strictest to widest, so `a < b` means `a` is stricter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    /// Only metrics, the service map (service names and protocols) and the
    /// PII audit log (type, never value). No per-request export, no raw dump,
    /// no payload-derived strings in any sink or in logs at info and above.
    MetricsOnly = 0,
    /// Per-request export with every detected PII value masked (default).
    Redacted = 1,
    /// Unredacted export and the raw (decrypted) payload dump are allowed.
    Full = 2,
}

impl PrivacyMode {
    pub const NAMES: [&'static str; 3] = ["full", "redacted", "metrics_only"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetricsOnly => "metrics_only",
            Self::Redacted => "redacted",
            Self::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "metrics_only" => Some(Self::MetricsOnly),
            "redacted" => Some(Self::Redacted),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::MetricsOnly,
            1 => Self::Redacted,
            _ => Self::Full,
        }
    }
}

impl std::fmt::Display for PrivacyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The privacy mode in effect, shared by every worker. It can only become
/// stricter at runtime; widening it needs a restart.
#[derive(Debug)]
pub struct PrivacyGate(std::sync::atomic::AtomicU8);

/// Whether a config reload may move the running agent from `current` to
/// `requested`. The mode may only get stricter, and tightening to
/// `redacted` needs the redactor the agent was started with
/// (`running_can_redact`): workers keep the PII engine built at startup, so
/// a reload cannot install one.
pub fn check_reload(
    current: PrivacyMode,
    requested: PrivacyMode,
    running_can_redact: bool,
) -> Result<(), String> {
    if (requested as u8) > (current as u8) {
        return Err(format!(
            "a wider privacy mode ({current} -> {requested}) needs a restart"
        ));
    }
    if requested == PrivacyMode::Redacted && current != requested && !running_can_redact {
        return Err(format!(
            "the agent was started without regex PII redaction ([pii] enabled / \
             regex_enabled off), so it cannot switch to {requested} at runtime; restart it"
        ));
    }
    Ok(())
}

/// Whether a PII engine built from `pii` masks values in redacted mode.
pub fn can_redact(pii: &PiiConfig) -> bool {
    pii.enabled && pii.regex_enabled && !matches!(pii.mode, PiiMode::External { .. })
}

impl PrivacyGate {
    pub fn new(mode: PrivacyMode) -> Self {
        Self(std::sync::atomic::AtomicU8::new(mode as u8))
    }

    pub fn get(&self) -> PrivacyMode {
        PrivacyMode::from_u8(self.0.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Whether a record produced under `mode` may still be written: `mode`
    /// is at least as strict as the mode now in effect. Exporters check it
    /// per record, so what was queued before a tighten is not written after.
    pub fn allows(&self, mode: PrivacyMode) -> bool {
        mode as u8 <= self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Switch to `mode` if it is at least as strict as the current one.
    /// Returns false (and changes nothing) for a wider mode.
    pub fn tighten(&self, mode: PrivacyMode) -> bool {
        self.0
            .fetch_min(mode as u8, std::sync::atomic::Ordering::Relaxed)
            >= mode as u8
    }
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
    /// If set, only capture traffic of these processes (PIDs, i.e. kernel
    /// tgids): at most `MAX_PID_FILTER`, none 0. Restart-only.
    pub pid_filter: Option<Vec<u32>>,
    /// `cgroup_filter`: cgroup v2 paths, relative to the cgroup2 root (a
    /// leading `/` is allowed and means the same, as in `/proc/<pid>/cgroup`).
    /// Their sockets and those of every descendant cgroup are captured
    /// (DESIGN §3.2). Restart-only for now.
    pub cgroup_filter: Option<Vec<String>>,
    /// `[[pod_filter]]`: pods on this node whose pod-level cgroup is
    /// captured (DESIGN §3.2). Restart-only for now.
    pub pod_filter: Option<Vec<PodFilter>>,
    /// `capture_loopback` (default false): capture packets on node-local
    /// paths (`lo`, VRF; DESIGN §3.7). TLS plaintext is scoped by process regardless.
    /// A reload may change it.
    pub capture_loopback: bool,
    /// `pid_filter_listener` (default `"acceptor"`, DESIGN §3.1). A reload
    /// may change it.
    pub pid_filter_listener: ListenerRule,
    /// `[capture] cgroup2_path`: the cgroup v2 root the capture programs
    /// attach to, or `"auto"`. Restart-only.
    pub cgroup2_path: String,

    // ── Resource budgets ───────────────────────────
    /// Rate limit in events/sec. 0 = unlimited. Events beyond this are dropped.
    pub max_events_per_sec: u64,
    /// Fixed worker pool size. Each worker drains a bounded channel.
    pub max_worker_count: usize,
    /// Per-worker bounded channel capacity, in events (queued in batches of
    /// up to 64 events / 64 KB). try_send drops if full. 4096 absorbs a
    /// ring shard drained in one burst; 1024 dropped 5% at 4K connections.
    pub worker_channel_capacity: usize,
    /// DashMap capacity hint for connection tracking.
    pub max_connections_tracked: usize,
    /// Evict idle connection state after this duration.
    pub idle_connection_timeout: Duration,

    // ── Sampling ───────────────────────────────────
    /// Sampling strategy for connections. Restart-only.
    pub sampling_mode: SamplingMode,
    /// Fraction of connections kept (0.0–1.0) in ConnectionSample mode;
    /// 1.0 otherwise. Restart-only.
    pub sample_rate: f64,

    // ── TLS interception ────────────────────────────
    /// Enable TLS library scanning and uprobe attachment.
    pub tls_scan_enabled: bool,
    /// Interval between full /proc rescans.
    pub tls_scan_interval: Duration,

    // ── Privacy ───────────────────────────────────
    /// What captured data may leave the agent (`[privacy] mode`).
    /// `apply_privacy` derives `pii.redact` from it and rejects settings
    /// that contradict it.
    pub privacy_mode: PrivacyMode,
    /// `[pii] redact` as written in the config file, if it was. Only checked
    /// against `privacy_mode`; redaction itself follows the mode.
    pub pii_redact_setting: Option<bool>,
    /// `[privacy] mask_credentials` (default true): protect known credential
    /// forms in every export (best effort; USER-GUIDE §5.3). false is only
    /// accepted in `full` with PII redaction off.
    pub mask_credentials: bool,
    /// `[credentials] patterns`: the user's own credential formats (Rust
    /// `regex` syntax), validated at load: every match is masked.
    pub credential_patterns: Vec<String>,
    /// `[credentials] builtin`: `full` (default) or `names_only`.
    pub credential_builtin: crate::protocol::Builtin,

    // ── PII detection ─────────────────────────────
    /// PII detection pipeline configuration.
    pub pii: PiiConfig,
    /// Allowlist of external PII service URL origins (e.g. "https://trusted-service.internal").
    pub pii_external_url_allowlist: Vec<String>,

    // ── Service graph ─────────────────────────────
    /// Service dependency graph configuration.
    pub graph: GraphConfig,

    // ── Kubernetes metadata ───────────────────────
    /// Pod/Service metadata from the Kubernetes API, used to name graph
    /// nodes and exported endpoints `namespace/workload`.
    pub kubernetes: KubernetesConfig,

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

    // ── Message bodies ──────────────────────────────
    /// Bytes of request/response body text kept per exchange; PII scanning,
    /// redaction and export all see the same bounded text. Parsers buffer up
    /// to 64 KiB; larger values are clamped to that.
    pub max_body_bytes: usize,

    // ── Raw capture ─────────────────────────────────
    /// If set, write every processed event, unredacted, to this PNCAP file.
    pub capture_raw_path: Option<String>,
    /// Stop raw capture once the file reaches this size.
    pub capture_raw_max_bytes: u64,

    // ── Map pinning ─────────────────────────────────
    /// If set, pin eBPF maps to this bpffs directory for zero-gap restarts.
    /// Directory must exist and bpffs must be mounted (typically /sys/fs/bpf/).
    pub map_pin_path: Option<String>,
}

/// Default `max_body_bytes`: one capture window. Scanning and exporting up
/// to 64 KiB per exchange made large-response traffic (e.g. 200 KB
/// downloads at 1.5 GB/s) overload the PII scanner and the JSON writer.
pub const DEFAULT_MAX_BODY_BYTES: usize = 4096;
/// Upper bound for `max_body_bytes` (what parsers buffer).
pub const MAX_BODY_BYTES_LIMIT: usize = 64 * 1024;

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            capture_enabled: true,
            pid_filter: None,
            cgroup_filter: None,
            pod_filter: None,
            capture_loopback: false,
            pid_filter_listener: ListenerRule::Acceptor,
            cgroup2_path: "auto".into(),

            max_events_per_sec: 500_000,
            max_worker_count: num_cpus(),
            worker_channel_capacity: 4096,
            max_connections_tracked: 65_536,
            idle_connection_timeout: Duration::from_secs(30),

            sampling_mode: SamplingMode::Full,
            sample_rate: 1.0,

            tls_scan_enabled: true,
            tls_scan_interval: Duration::from_secs(60),

            privacy_mode: PrivacyMode::Redacted,
            pii_redact_setting: None,
            mask_credentials: true,
            credential_patterns: Vec::new(),
            credential_builtin: crate::protocol::Builtin::Full,

            pii: PiiConfig::default(),
            pii_external_url_allowlist: vec![],

            graph: GraphConfig::default(),
            kubernetes: KubernetesConfig::default(),

            log_events: false,
            json_export_path: None,
            pii_audit_log_path: None,
            otlp: OtlpConfig::default(),

            metrics_bind: None,

            smoke_test: false,

            map_pin_path: None,
            capture_raw_path: None,
            capture_raw_max_bytes: 1 << 30,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
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
    /// Replace detected PII with `<CATEGORY>` placeholders. Derived from
    /// `privacy_mode` by `apply_privacy` (false only in `full`).
    pub redact: bool,
    /// Protect known credential forms even when `redact` is off. Copied
    /// from `[privacy] mask_credentials` by `apply_privacy`.
    pub mask_credentials: bool,
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
            mask_credentials: true,
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

/// Whether to use Kubernetes metadata for endpoint identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KubernetesMode {
    /// On when the in-cluster environment is present
    /// (`KUBERNETES_SERVICE_HOST`/`PORT` and a mounted service account token).
    Auto,
    /// Always try; logs a warning and falls back to DNS/IP names when the
    /// in-cluster environment or the API server is not available.
    Enabled,
    /// Never contact the Kubernetes API.
    Disabled,
}

/// Configuration for Kubernetes-aware endpoint identity.
#[derive(Debug, Clone)]
pub struct KubernetesConfig {
    pub mode: KubernetesMode,
    /// Full re-list period for pods and services. With `watch` on, changes
    /// arrive in between as they happen; without it this is the refresh rate.
    pub relist_interval: Duration,
    /// Stream changes between re-lists (list + watch, like an informer).
    pub watch: bool,
}

impl Default for KubernetesConfig {
    fn default() -> Self {
        Self {
            mode: KubernetesMode::Auto,
            relist_interval: Duration::from_secs(300),
            watch: true,
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
    /// Removed with the TC capture: refused (see `merge_into`).
    pub interfaces: Option<Vec<String>>,
    pub pid_filter: Option<Vec<u32>>,
    pub cgroup_filter: Option<Vec<String>>,
    pub pod_filter: Option<Vec<PodFilterFile>>,
    pub capture_loopback: Option<bool>,
    pub pid_filter_listener: Option<String>,
    pub capture: Option<CaptureConfigFile>,
    pub max_events_per_sec: Option<u64>,
    pub max_worker_count: Option<usize>,
    pub worker_channel_capacity: Option<usize>,
    pub max_connections_tracked: Option<usize>,
    pub idle_connection_timeout_secs: Option<u64>,
    pub sampling_mode: Option<String>,
    pub sample_rate: Option<f64>,
    pub head_only_bytes: Option<u64>,
    pub tls_scan_enabled: Option<bool>,
    pub tls_scan_interval_secs: Option<u64>,
    pub privacy: Option<PrivacyConfigFile>,
    pub credentials: Option<CredentialsConfigFile>,
    pub pii: Option<PiiConfigFile>,
    pub pii_external_url_allowlist: Option<Vec<String>>,
    pub graph: Option<GraphConfigFile>,
    pub kubernetes: Option<KubernetesConfigFile>,
    pub log_events: Option<bool>,
    pub json_export_path: Option<String>,
    pub pii_audit_log_path: Option<String>,
    pub otlp: Option<OtlpConfigFile>,
    pub metrics_bind: Option<String>,
    pub map_pin_path: Option<String>,
    pub capture_raw_path: Option<String>,
    pub capture_raw_max_bytes: Option<u64>,
    pub max_body_bytes: Option<usize>,
}

/// `[privacy]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PrivacyConfigFile {
    /// `"full"`, `"redacted"` or `"metrics_only"`.
    pub mode: Option<PrivacyMode>,
    /// Protect known credential forms in exports (default true, best
    /// effort). Only `full` may set false.
    pub mask_credentials: Option<bool>,
}

/// `[credentials]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CredentialsConfigFile {
    /// Credential formats to mask wherever they appear (Rust `regex`).
    pub patterns: Option<Vec<String>>,
    /// `"full"` (default) or `"names_only"`.
    pub builtin: Option<String>,
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

/// One `[[pod_filter]]` entry: `namespace` plus exactly one of `labels`
/// (every label must match) or `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodFilter {
    pub namespace: String,
    pub select: PodSelect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodSelect {
    Labels(std::collections::BTreeMap<String, String>),
    Name(String),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PodFilterFile {
    pub namespace: Option<String>,
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    pub name: Option<String>,
}

impl PodFilterFile {
    fn validate(self) -> anyhow::Result<PodFilter> {
        let namespace = self.namespace.unwrap_or_default();
        if namespace.is_empty() {
            anyhow::bail!("[[pod_filter]] needs a non-empty namespace");
        }
        let select = match (self.labels, self.name) {
            (Some(l), None) if l.is_empty() => anyhow::bail!(
                "[[pod_filter]] namespace = \"{namespace}\": labels = {{}} would match every pod; \
                 list at least one label, or use name"
            ),
            (Some(l), None) => PodSelect::Labels(l),
            (None, Some(n)) if !n.is_empty() => PodSelect::Name(n),
            (None, Some(_)) => {
                anyhow::bail!("[[pod_filter]] namespace = \"{namespace}\": name is empty")
            }
            _ => anyhow::bail!(
                "[[pod_filter]] namespace = \"{namespace}\" needs exactly one of labels or name"
            ),
        };
        Ok(PodFilter { namespace, select })
    }
}

/// Check one `cgroup_filter` entry and return it relative to the cgroup2
/// root (without the optional leading `/`). Refused: the root itself (empty
/// or `/`), and any `.`/`..` or empty component, so a path can never leave
/// the root or name it.
pub fn cgroup_filter_rel(path: &str) -> anyhow::Result<&str> {
    let rel = path.strip_prefix('/').unwrap_or(path);
    if rel.is_empty() {
        anyhow::bail!(
            "cgroup_filter = \"{path}\" names the cgroup2 root, which would capture every process"
        );
    }
    if rel
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == ".." || c.contains('\0'))
    {
        anyhow::bail!(
            "cgroup_filter = \"{path}\": use a plain path relative to the cgroup2 root \
             (no `.`, `..` or empty components)"
        );
    }
    Ok(rel)
}

/// `[capture]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfigFile {
    /// Removed: `"cgroup_skb"`, the only backend, is accepted with a
    /// warning; anything else is refused (see `merge_into`).
    pub backend: Option<String>,
    /// `"auto"` or a cgroup v2 mount point.
    pub cgroup2_path: Option<String>,
}

/// TOML-friendly Kubernetes config subset.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct KubernetesConfigFile {
    /// `"auto"`, `true` or `false` (the strings `"true"`/`"false"` work too).
    pub enabled: Option<KubernetesModeValue>,
    pub relist_interval_secs: Option<u64>,
    pub watch: Option<bool>,
}

/// `enabled = "auto" | true | false` in TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KubernetesModeValue(pub KubernetesMode);

impl<'de> Deserialize<'de> for KubernetesModeValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Bool(bool),
            Str(String),
        }
        let mode = match Raw::deserialize(d)? {
            Raw::Bool(true) => KubernetesMode::Enabled,
            Raw::Bool(false) => KubernetesMode::Disabled,
            Raw::Str(s) => match s.to_ascii_lowercase().as_str() {
                "auto" => KubernetesMode::Auto,
                "true" | "on" => KubernetesMode::Enabled,
                "false" | "off" => KubernetesMode::Disabled,
                other => {
                    return Err(serde::de::Error::custom(format!(
                        "kubernetes.enabled must be \"auto\", true or false, got \"{other}\""
                    )));
                }
            },
        };
        Ok(Self(mode))
    }
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
    /// Fails on a sampling setting that would not do what it says.
    pub fn merge_into(self, base: &mut AgentConfig) -> anyhow::Result<()> {
        if let Some(v) = self.capture_enabled {
            base.capture_enabled = v;
        }
        // Removed keys. `interfaces` narrowed TC capture to some devices;
        // cgroup_skb sees every local socket, so ignoring it would widen
        // what is captured: refused. `backend = "tc"` likewise.
        if self.interfaces.is_some() {
            anyhow::bail!(
                "`interfaces` is no longer supported: the TC backend was removed and capture \
                 now covers every socket in the cgroup v2 hierarchy; remove the key and select \
                 traffic with pid_filter, cgroup_filter or pod_filter"
            );
        }
        if let Some(v) = self.pid_filter {
            base.pid_filter = Some(v);
        }
        if let Some(v) = self.cgroup_filter {
            base.cgroup_filter = Some(v);
        }
        if let Some(v) = self.pod_filter {
            base.pod_filter = Some(
                v.into_iter()
                    .map(PodFilterFile::validate)
                    .collect::<anyhow::Result<_>>()?,
            );
        }
        if let Some(capture) = self.capture {
            match capture.backend.as_deref() {
                None => {}
                Some("cgroup_skb") => tracing::warn!(
                    "[capture] backend = \"cgroup_skb\" is no longer needed (the only backend); \
                     remove it"
                ),
                Some(other) => anyhow::bail!(
                    "[capture] backend = \"{other}\" is not supported: the TC backend was \
                     removed and cgroup_skb is the only backend; remove the key"
                ),
            }
            if let Some(path) = capture.cgroup2_path {
                base.cgroup2_path = path;
            }
        }
        if let Some(v) = self.capture_loopback {
            base.capture_loopback = v;
        }
        match self.pid_filter_listener.as_deref() {
            None => {}
            Some("acceptor") => base.pid_filter_listener = ListenerRule::Acceptor,
            Some("creator") => base.pid_filter_listener = ListenerRule::Creator,
            Some(other) => anyhow::bail!(
                "pid_filter_listener = \"{other}\" is not valid; use \"acceptor\" or \"creator\""
            ),
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
        let mode = self.sampling_mode.as_deref().unwrap_or("full");
        base.sampling_mode = match mode {
            "full" => SamplingMode::Full,
            "connection_sample" => SamplingMode::ConnectionSample,
            "head_only" => SamplingMode::HeadOnly {
                max_bytes: self.head_only_bytes.unwrap_or(DEFAULT_HEAD_ONLY_BYTES),
            },
            other => anyhow::bail!(
                "sampling_mode = \"{other}\" is not valid; use \"{}\"",
                SamplingMode::NAMES.join("\", \"")
            ),
        };
        // A rate or a size the mode would ignore: the user expects a
        // reduction that would not happen.
        match (self.sample_rate, mode) {
            (Some(v), "connection_sample") => base.sample_rate = v,
            (None, "connection_sample") => anyhow::bail!(
                "sampling_mode = \"connection_sample\" needs sample_rate (0.0 to 1.0)"
            ),
            (Some(_), _) => anyhow::bail!(
                "sample_rate is only used with sampling_mode = \"connection_sample\", \
                 but sampling_mode is \"{mode}\""
            ),
            (None, _) => {}
        }
        if self.head_only_bytes.is_some() && mode != "head_only" {
            anyhow::bail!(
                "head_only_bytes is only used with sampling_mode = \"head_only\", \
                 but sampling_mode is \"{mode}\""
            );
        }
        if let Some(v) = self.tls_scan_enabled {
            base.tls_scan_enabled = v;
        }
        if let Some(v) = self.tls_scan_interval_secs {
            base.tls_scan_interval = Duration::from_secs(v);
        }
        if let Some(privacy) = self.privacy {
            if let Some(mode) = privacy.mode {
                base.privacy_mode = mode;
            }
            if let Some(mask) = privacy.mask_credentials {
                base.mask_credentials = mask;
            }
        }
        if let Some(credentials) = self.credentials {
            if let Some(patterns) = credentials.patterns {
                base.credential_patterns = patterns;
            }
            if let Some(builtin) = credentials.builtin {
                base.credential_builtin =
                    crate::protocol::Builtin::parse(&builtin).ok_or_else(|| {
                        anyhow::anyhow!(
                            "[credentials] builtin = \"{builtin}\" is not valid; use \"full\" \
                             or \"names_only\""
                        )
                    })?;
            }
        }
        if let Some(pii) = self.pii {
            if pii.redact.is_some() {
                base.pii_redact_setting = pii.redact;
            }
            pii.merge_into(&mut base.pii);
        }
        if let Some(v) = self.pii_external_url_allowlist {
            base.pii_external_url_allowlist = v;
        }
        if let Some(graph) = self.graph {
            graph.merge_into(&mut base.graph);
        }
        if let Some(k8s) = self.kubernetes {
            k8s.merge_into(&mut base.kubernetes);
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
        if let Some(v) = self.capture_raw_path {
            base.capture_raw_path = Some(v);
        }
        if let Some(v) = self.capture_raw_max_bytes {
            base.capture_raw_max_bytes = v;
        }
        if let Some(v) = self.max_body_bytes {
            base.max_body_bytes = v.min(MAX_BODY_BYTES_LIMIT);
        }
        if let Some(v) = self.map_pin_path {
            base.map_pin_path = Some(v);
        }
        Ok(())
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

impl KubernetesConfigFile {
    fn merge_into(self, base: &mut KubernetesConfig) {
        if let Some(v) = self.enabled {
            base.mode = v.0;
        }
        if let Some(v) = self.relist_interval_secs {
            base.relist_interval = Duration::from_secs(v);
        }
        if let Some(v) = self.watch {
            base.watch = v;
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
    file_config.merge_into(&mut config)?;
    validate_config(&config)?;
    Ok(config)
}

/// The compiled `[credentials]` rules of `config`; an invalid or oversized
/// pattern is an error (a reload carrying one is refused).
pub fn credential_rules(config: &AgentConfig) -> anyhow::Result<crate::protocol::CredentialRules> {
    crate::protocol::CredentialRules::compile(
        &config.credential_patterns,
        config.credential_builtin,
    )
    .map_err(|e| anyhow::anyhow!("[credentials] patterns: {e}"))
}

fn validate_config(config: &AgentConfig) -> anyhow::Result<()> {
    credential_rules(config)?;
    if config.max_worker_count == 0 {
        return Err(anyhow::anyhow!("max_worker_count must be >= 1"));
    }
    if config.worker_channel_capacity == 0 {
        return Err(anyhow::anyhow!("worker_channel_capacity must be >= 1"));
    }
    if !(0.0..=1.0).contains(&config.sample_rate) {
        return Err(anyhow::anyhow!("sample_rate must be between 0.0 and 1.0"));
    }
    if let SamplingMode::HeadOnly { max_bytes } = config.sampling_mode
        && !(1..=MAX_HEAD_ONLY_BYTES).contains(&max_bytes)
    {
        anyhow::bail!("head_only_bytes must be between 1 and {MAX_HEAD_ONLY_BYTES}");
    }
    if let Some(pids) = &config.pid_filter {
        let max = panopticon_common::MAX_PID_FILTER as usize;
        if pids.is_empty() {
            anyhow::bail!(
                "pid_filter = [] would capture nothing; list the process IDs to capture, \
                 or remove pid_filter to capture every process"
            );
        }
        if pids.len() > max {
            anyhow::bail!(
                "pid_filter lists {} PIDs; at most {max} are allowed",
                pids.len()
            );
        }
        if pids.contains(&0) {
            anyhow::bail!("pid_filter cannot contain 0 (not a process)");
        }
    }
    if let Some(paths) = &config.cgroup_filter {
        if paths.is_empty() {
            anyhow::bail!(
                "cgroup_filter = [] would capture nothing; list cgroup paths, or remove it"
            );
        }
        let max = panopticon_common::MAX_CGROUP_ALLOW as usize;
        if paths.len() > max {
            anyhow::bail!(
                "cgroup_filter lists {} paths; at most {max} are allowed",
                paths.len()
            );
        }
        for p in paths {
            cgroup_filter_rel(p)?;
        }
    }
    if config.pod_filter.as_ref().is_some_and(|p| p.is_empty()) {
        anyhow::bail!(
            "pod_filter = [] would capture nothing; add [[pod_filter]] entries, or remove it"
        );
    }
    if config.pod_filter.is_some() && config.kubernetes.mode == KubernetesMode::Disabled {
        anyhow::bail!("pod_filter needs Kubernetes metadata, but [kubernetes] enabled = false");
    }
    if config.kubernetes.relist_interval < Duration::from_secs(5) {
        return Err(anyhow::anyhow!(
            "kubernetes.relist_interval_secs must be >= 5"
        ));
    }
    Ok(())
}

/// Settings a `SIGHUP` reload cannot change: the PID filter is loaded into
/// the kernel and the workers' capture gates are built once, at startup.
pub fn check_restart_only(running: &AgentConfig, new: &AgentConfig) -> Result<(), String> {
    let pids = |c: &AgentConfig| {
        c.pid_filter.as_ref().map(|p| {
            let mut p = p.clone();
            p.sort_unstable();
            p.dedup();
            p
        })
    };
    if pids(running) != pids(new) {
        return Err("changing pid_filter needs a restart".into());
    }
    // The cgroup_filter / pod_filter selectors may change at runtime: the
    // scope publisher applies them (a narrowing revokes the capture
    // pipeline). Whether the cgroup selector exists at all is part of the
    // kernel scope mode, set at startup.
    let selector = |c: &AgentConfig| c.cgroup_filter.is_some() || c.pod_filter.is_some();
    if selector(running) != selector(new) {
        return Err(
            "turning cgroup selection (cgroup_filter or pod_filter) on or off needs a restart"
                .into(),
        );
    }
    if running.cgroup2_path != new.cgroup2_path {
        return Err("changing [capture] cgroup2_path needs a restart".into());
    }
    if running.sampling_mode != new.sampling_mode || running.sample_rate != new.sample_rate {
        return Err(
            "changing sampling_mode, sample_rate or head_only_bytes needs a restart".into(),
        );
    }
    Ok(())
}

/// Make the config obey its privacy mode. Call once the config file and the
/// CLI overrides have both been applied (before anything is opened).
///
/// Sets `pii.redact` from the mode and fails with a clear message on any
/// setting that would contradict it, so the mode is the only thing a reader
/// of the config has to check. The one combination kept from the old flags:
/// `[pii] redact = true` under `full` keeps the event export redacted while
/// the raw dump stays unredacted (a setting may narrow the mode, never widen).
pub fn apply_privacy(config: &mut AgentConfig) -> anyhow::Result<()> {
    let mode = config.privacy_mode;
    if mode != PrivacyMode::Full && config.pii_redact_setting == Some(false) {
        anyhow::bail!(
            "[pii] redact = false contradicts [privacy] mode = \"{mode}\", which redacts \
             the PII values it detects (detection is best effort). Remove `redact`, or use \
             mode = \"full\" for unredacted export"
        );
    }
    config.pii.redact = mode != PrivacyMode::Full || config.pii_redact_setting == Some(true);
    config.pii.mask_credentials = config.mask_credentials;
    if !config.mask_credentials && config.pii.redact {
        anyhow::bail!(
            "[privacy] mask_credentials = false turns credential masking off, which \
             [privacy] mode = \"{mode}\"{} requires. Masking is best effort for known \
             credential forms; only mode = \"metrics_only\" guarantees that no login secret \
             is exported. Turning it off is only allowed with mode = \"full\" and PII \
             redaction off",
            if mode == PrivacyMode::Full {
                " with [pii] redact = true"
            } else {
                ""
            }
        );
    }

    if mode != PrivacyMode::Full && config.capture_raw_path.is_some() {
        anyhow::bail!(
            "capture_raw_path / --capture-raw writes every payload, including decrypted TLS, \
             unredacted; it needs [privacy] mode = \"full\" (--privacy-mode full), \
             but the mode is \"{mode}\""
        );
    }
    // The external service is sent raw field values: never wire it up
    // where the mode promises they stay on the node.
    if mode != PrivacyMode::Full && matches!(config.pii.mode, PiiMode::External { .. }) {
        anyhow::bail!(
            "the external PII service is sent raw, unredacted values; it needs \
             [privacy] mode = \"full\", but the mode is \"{mode}\""
        );
    }
    match mode {
        PrivacyMode::MetricsOnly => {
            for (enabled, setting) in [
                (
                    config.json_export_path.is_some(),
                    "json_export_path / --json-export",
                ),
                (config.otlp.enabled, "[otlp] enabled"),
                (config.log_events, "log_events / --log-events"),
            ] {
                if enabled {
                    anyhow::bail!(
                        "{setting} exports per-request data, which \
                         [privacy] mode = \"metrics_only\" does not allow"
                    );
                }
            }
        }
        PrivacyMode::Redacted => {
            if !config.pii.enabled || !config.pii.regex_enabled {
                anyhow::bail!(
                    "[privacy] mode = \"redacted\" needs PII detection ([pii] enabled = true and \
                     regex_enabled = true): without it nothing would be masked. Use \
                     mode = \"full\" to export unredacted, or \"metrics_only\""
                );
            }
        }
        PrivacyMode::Full => {}
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
        assert_eq!(config.worker_channel_capacity, 4096);
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

            [privacy]
            mode = "full"

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

            [kubernetes]
            enabled = false
            relist_interval_secs = 30
            watch = false
        "#;

        let mut config = load_config_from_str(toml).unwrap();
        apply_privacy(&mut config).unwrap();
        assert_eq!(config.privacy_mode, PrivacyMode::Full);
        assert!(!config.capture_enabled);
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
        assert_eq!(config.kubernetes.mode, KubernetesMode::Disabled);
        assert_eq!(config.kubernetes.relist_interval, Duration::from_secs(30));
        assert!(!config.kubernetes.watch);
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
        file_config.merge_into(&mut config).unwrap();

        assert!(!config.capture_enabled);
        // Everything else untouched
        assert_eq!(config.max_events_per_sec, 500_000);
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
        for rate in ["1.5", "-0.1", "nan"] {
            let toml = format!("sampling_mode = \"connection_sample\"\nsample_rate = {rate}\n");
            let err = load_config_from_str(&toml).unwrap_err().to_string();
            assert!(
                err.contains("sample_rate must be between 0.0 and 1.0"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_sampling_config_errors() {
        let err = |toml: &str| load_config_from_str(toml).unwrap_err().to_string();
        // An unknown mode names the valid ones instead of meaning "full".
        let e = err("sampling_mode = \"headonly\"\n");
        assert!(
            e.contains("\"headonly\"")
                && e.contains("\"full\", \"connection_sample\", \"head_only\""),
            "{e}"
        );
        // A rate or a size that the mode would ignore.
        for toml in [
            "sample_rate = 0.5\n",
            "sampling_mode = \"full\"\nsample_rate = 0.5\n",
            "sampling_mode = \"head_only\"\nsample_rate = 0.5\n",
        ] {
            assert!(err(toml).contains("only used with sampling_mode = \"connection_sample\""));
        }
        assert!(err("sampling_mode = \"connection_sample\"\n").contains("needs sample_rate"));
        for toml in [
            "head_only_bytes = 100\n",
            "sampling_mode = \"connection_sample\"\nsample_rate = 1.0\nhead_only_bytes = 100\n",
        ] {
            assert!(err(toml).contains("only used with sampling_mode = \"head_only\""));
        }
        for n in ["0", "1073741825"] {
            let e = err(&format!(
                "sampling_mode = \"head_only\"\nhead_only_bytes = {n}\n"
            ));
            assert!(e.contains("head_only_bytes must be between 1 and"), "{e}");
        }
    }

    #[test]
    fn test_sampling_config_values() {
        let load = |toml: &str| load_config_from_str(toml).unwrap();
        let c = load("sampling_mode = \"full\"\n");
        assert_eq!((c.sampling_mode, c.sample_rate), (SamplingMode::Full, 1.0));
        let c = load("sampling_mode = \"head_only\"\n");
        assert_eq!(
            c.sampling_mode,
            SamplingMode::HeadOnly {
                max_bytes: DEFAULT_HEAD_ONLY_BYTES
            }
        );
        let c = load("sampling_mode = \"head_only\"\nhead_only_bytes = 300\n");
        assert_eq!(c.sampling_mode, SamplingMode::HeadOnly { max_bytes: 300 });
        let c = load("sampling_mode = \"connection_sample\"\nsample_rate = 0\n");
        assert_eq!(c.sampling_mode, SamplingMode::ConnectionSample);
        assert_eq!(c.sample_rate, 0.0);
    }

    #[test]
    fn test_pid_filter_config() {
        let c = load_config_from_str("pid_filter = [42, 7]\n").unwrap();
        assert_eq!(c.pid_filter, Some(vec![42, 7]));
        let max = panopticon_common::MAX_PID_FILTER as usize;
        let list = |n: usize| (1..=n).map(|p| p.to_string()).collect::<Vec<_>>().join(",");
        assert!(load_config_from_str(&format!("pid_filter = [{}]\n", list(max))).is_ok());
        let err = |toml: &str| load_config_from_str(toml).unwrap_err().to_string();
        let e = err(&format!("pid_filter = [{}]\n", list(max + 1)));
        assert!(e.contains(&format!("at most {max}")), "{e}");
        assert!(err("pid_filter = []\n").contains("would capture nothing"));
        assert!(err("pid_filter = [1, 0]\n").contains("cannot contain 0"));
        assert!(err("pid_filter = [-1]\n").contains("Invalid TOML"));
    }

    #[test]
    fn test_reload_rejects_restart_only_changes() {
        let load = |toml: &str| load_config_from_str(toml).unwrap();
        let running = load(
            "pid_filter = [10, 20]\nsampling_mode = \"connection_sample\"\nsample_rate = 0.5\n",
        );
        // Same settings (the PID list in another order): accepted.
        let same = load(
            "pid_filter = [20, 10, 10]\nsampling_mode = \"connection_sample\"\nsample_rate = 0.5\n",
        );
        assert_eq!(check_restart_only(&running, &same), Ok(()));
        for (toml, what) in [
            (
                "sampling_mode = \"connection_sample\"\nsample_rate = 0.5\n",
                "pid_filter",
            ),
            (
                "pid_filter = [10]\nsampling_mode = \"connection_sample\"\nsample_rate = 0.5\n",
                "pid_filter",
            ),
            ("pid_filter = [10, 20]\n", "sampling_mode"),
            (
                "pid_filter = [10, 20]\nsampling_mode = \"connection_sample\"\nsample_rate = 0.6\n",
                "sample_rate",
            ),
            (
                "pid_filter = [10, 20]\nsampling_mode = \"head_only\"\n",
                "sampling_mode",
            ),
        ] {
            let err = check_restart_only(&running, &load(toml)).unwrap_err();
            assert!(
                err.contains(what) && err.contains("needs a restart"),
                "{err}"
            );
        }
        let head = load("sampling_mode = \"head_only\"\n");
        let err = check_restart_only(
            &head,
            &load("sampling_mode = \"head_only\"\nhead_only_bytes = 9\n"),
        )
        .unwrap_err();
        assert!(err.contains("head_only_bytes"), "{err}");
    }

    #[test]
    fn test_capture_config_and_removed_keys() {
        let load = |toml: &str| load_config_from_str(toml).unwrap();
        let d = load("");
        assert_eq!(d.cgroup2_path, "auto");
        let x = load("[capture]\ncgroup2_path = \"/x\"\n");
        assert_eq!(x.cgroup2_path, "/x");
        // The only backend, named: accepted (a warning is logged).
        assert_eq!(
            load("[capture]\nbackend = \"cgroup_skb\"\n").cgroup2_path,
            "auto"
        );
        // The removed TC backend and its interface list are refused, never
        // ignored: ignoring `interfaces` would widen capture.
        for (toml, what) in [
            ("[capture]\nbackend = \"tc\"\n", "TC backend was removed"),
            ("[capture]\nbackend = \"xdp\"\n", "not supported"),
            (
                "interfaces = [\"eth0\"]\n",
                "`interfaces` is no longer supported",
            ),
            ("interfaces = []\n", "`interfaces` is no longer supported"),
        ] {
            let e = load_config_from_str(toml).unwrap_err().to_string();
            assert!(e.contains(what), "{toml}: {e}");
        }
        assert!(load_config_from_str("[capture]\nbogus = 1\n").is_err());
        let err = check_restart_only(&d, &x).unwrap_err();
        assert!(err.contains("cgroup2_path"), "{err}");
    }

    #[test]
    fn test_cgroup_and_pod_filter_config() {
        const CG: &str = "";
        let ok = |toml: &str| load_config_from_str(&format!("{toml}{CG}")).unwrap();
        let err = |toml: &str| {
            load_config_from_str(&format!("{toml}{CG}"))
                .unwrap_err()
                .to_string()
        };
        let c = ok("cgroup_filter = [\"/kubepods.slice/a.slice\", \"system.slice\"]\n");
        assert_eq!(
            c.cgroup_filter.as_deref().unwrap(),
            ["/kubepods.slice/a.slice", "system.slice"]
        );
        assert_eq!(cgroup_filter_rel("/a/b").unwrap(), "a/b");
        assert_eq!(cgroup_filter_rel("a/b").unwrap(), "a/b");
        for bad in [
            "\"\"",
            "\"/\"",
            "\"a/../b\"",
            "\"..\"",
            "\"a//b\"",
            "\"./a\"",
            "\"a/\"",
        ] {
            let e = err(&format!("cgroup_filter = [{bad}]\n"));
            assert!(e.contains("cgroup_filter"), "{bad}: {e}");
        }
        assert!(err("cgroup_filter = []\n").contains("would capture nothing"));

        let c = ok(
            "[[pod_filter]]\nnamespace = \"pay\"\nlabels = { app = \"co\", tier = \"web\" }\n\
             [[pod_filter]]\nnamespace = \"pay\"\nname = \"co-1\"\n",
        );
        let pods = c.pod_filter.unwrap();
        assert_eq!(pods[0].namespace, "pay");
        assert!(matches!(&pods[0].select, PodSelect::Labels(l) if l.len() == 2));
        assert_eq!(pods[1].select, PodSelect::Name("co-1".into()));
        for (toml, what) in [
            (
                "[[pod_filter]]\nlabels = { a = \"b\" }\n",
                "non-empty namespace",
            ),
            (
                "[[pod_filter]]\nnamespace = \"\"\nname = \"x\"\n",
                "non-empty namespace",
            ),
            ("[[pod_filter]]\nnamespace = \"n\"\n", "exactly one"),
            (
                "[[pod_filter]]\nnamespace = \"n\"\nname = \"x\"\nlabels = { a = \"b\" }\n",
                "exactly one",
            ),
            (
                "[[pod_filter]]\nnamespace = \"n\"\nlabels = {}\n",
                "every pod",
            ),
            (
                "[[pod_filter]]\nnamespace = \"n\"\nname = \"\"\n",
                "name is empty",
            ),
            (
                "[[pod_filter]]\nnamespace = \"n\"\nuid = \"x\"\n",
                "Invalid TOML",
            ),
            (
                "[kubernetes]\nenabled = false\n[[pod_filter]]\nnamespace = \"n\"\nname = \"x\"\n",
                "enabled = false",
            ),
        ] {
            let e = load_config_from_str(&format!("{CG}{toml}"))
                .unwrap_err()
                .to_string();
            assert!(e.contains(what), "{toml}: {e}");
        }

        // The selectors change at runtime (the scope publisher applies
        // them), including switching from one form to the other or
        // combining them; turning cgroup selection on or off needs a
        // restart.
        let running = ok("cgroup_filter = [\"a\"]\n");
        assert_eq!(
            check_restart_only(&running, &ok("cgroup_filter = [\"b\"]\n")),
            Ok(())
        );
        let pods = load_config_from_str(&format!(
            "{CG}[[pod_filter]]\nnamespace = \"n\"\nname = \"x\"\n"
        ))
        .unwrap();
        assert_eq!(check_restart_only(&running, &pods), Ok(()));
        let both = load_config_from_str(&format!(
            "cgroup_filter = [\"a\"]\n{CG}[[pod_filter]]\nnamespace = \"n\"\nname = \"x\"\n"
        ))
        .unwrap();
        assert_eq!(check_restart_only(&pods, &both), Ok(()));
        let none = load_config_from_str(CG).unwrap();
        for (from, to) in [(&running, &none), (&none, &pods)] {
            let e = check_restart_only(from, to).unwrap_err();
            assert!(
                e.contains("cgroup selection") && e.contains("on or off"),
                "{e}"
            );
        }
    }

    #[test]
    fn scope_options_config() {
        const CG: &str = "";
        let load = |toml: &str| load_config_from_str(&format!("{toml}{CG}"));
        // Defaults: loopback dropped, acceptor rule.
        let d = load("").unwrap();
        assert_eq!(ScopeOptions::of(&d), ScopeOptions::default());
        assert_eq!(d.pid_filter_listener, ListenerRule::Acceptor);
        let c = load("capture_loopback = true\npid_filter_listener = \"creator\"\n").unwrap();
        let wide = ScopeOptions {
            capture_loopback: true,
            creator_rule: true,
        };
        assert_eq!(ScopeOptions::of(&c), wide);
        assert_eq!(
            load("pid_filter_listener = \"acceptor\"\n")
                .unwrap()
                .pid_filter_listener,
            ListenerRule::Acceptor
        );
        let e = load("pid_filter_listener = \"owner\"\n")
            .unwrap_err()
            .to_string();
        assert!(e.contains("acceptor") && e.contains("creator"), "{e}");
        // Both reload; turning either off is a narrowing, on a widening.
        assert_eq!(check_restart_only(&d, &c), Ok(()));
        assert!(!ScopeOptions::default().narrows_to(wide));
        assert!(wide.narrows_to(ScopeOptions::default()));
        for one in [
            ScopeOptions {
                capture_loopback: true,
                creator_rule: false,
            },
            ScopeOptions {
                capture_loopback: false,
                creator_rule: true,
            },
        ] {
            assert!(wide.narrows_to(one) && !one.narrows_to(wide));
            assert!(!one.narrows_to(one));
        }
        // One widened and one narrowed: a narrowing.
        let lo = ScopeOptions {
            capture_loopback: true,
            creator_rule: false,
        };
        let cr = ScopeOptions {
            capture_loopback: false,
            creator_rule: true,
        };
        assert!(lo.narrows_to(cr) && cr.narrows_to(lo));
    }

    fn privacy(toml: &str) -> anyhow::Result<AgentConfig> {
        let mut config = load_config_from_str(toml)?;
        apply_privacy(&mut config)?;
        Ok(config)
    }

    #[test]
    fn test_privacy_mode_default_and_values() {
        let config = privacy("").unwrap();
        assert_eq!(config.privacy_mode, PrivacyMode::Redacted);
        assert!(config.pii.redact);
        for name in PrivacyMode::NAMES {
            let config = privacy(&format!("[privacy]\nmode = \"{name}\"\n")).unwrap();
            assert_eq!(config.privacy_mode.as_str(), name);
            assert_eq!(PrivacyMode::parse(name), Some(config.privacy_mode));
            assert_eq!(config.pii.redact, name != "full", "{name}");
        }
        assert!(load_config_from_str("[privacy]\nmode = \"everything\"\n").is_err());
    }

    #[test]
    fn test_privacy_redact_may_narrow_never_widen() {
        assert!(privacy("[pii]\nredact = true\n").unwrap().pii.redact);
        let full = "[privacy]\nmode = \"full\"\n[pii]\n";
        assert!(
            !privacy(&format!("{full}redact = false\n"))
                .unwrap()
                .pii
                .redact
        );
        // full with a redacted export (the raw dump stays unredacted).
        assert!(
            privacy(&format!("{full}redact = true\n"))
                .unwrap()
                .pii
                .redact
        );
        for mode in ["redacted", "metrics_only"] {
            let toml = format!("[privacy]\nmode = \"{mode}\"\n[pii]\nredact = false\n");
            let err = privacy(&toml).unwrap_err().to_string();
            assert!(err.contains("contradicts") && err.contains(mode), "{err}");
            // Codex R5 H6: best effort, no absolute promise.
            assert!(
                !err.contains("never") && err.contains("best effort"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_privacy_raw_capture_needs_full() {
        for mode in ["redacted", "metrics_only"] {
            let toml = format!("capture_raw_path = \"/tmp/x\"\n[privacy]\nmode = \"{mode}\"\n");
            let err = privacy(&toml).unwrap_err().to_string();
            assert!(
                err.contains("capture_raw_path") && err.contains(mode),
                "{err}"
            );
        }
        assert!(privacy("capture_raw_path = \"/tmp/x\"\n[privacy]\nmode = \"full\"\n").is_ok());
        // A CLI override applied after the file is checked the same way.
        let mut config = load_config_from_str("").unwrap();
        config.capture_raw_path = Some("/tmp/x".into());
        assert!(apply_privacy(&mut config).is_err());
    }

    #[test]
    fn test_privacy_metrics_only_rejects_event_sinks() {
        let base = "\n[privacy]\nmode = \"metrics_only\"\n";
        assert!(privacy(&format!("pii_audit_log_path = \"/tmp/a\"\n{base}")).is_ok());
        for (extra, what) in [
            ("json_export_path = \"/tmp/e\"\n", "json_export_path"),
            ("log_events = true\n", "log_events"),
            ("[otlp]\nenabled = true\n", "otlp"),
        ] {
            let err = privacy(&format!("{extra}{base}")).unwrap_err().to_string();
            assert!(err.contains(what) && err.contains("metrics_only"), "{err}");
        }
    }

    #[test]
    fn test_privacy_redacted_needs_pii_detection() {
        for extra in ["enabled = false", "regex_enabled = false"] {
            let err = privacy(&format!("[pii]\n{extra}\n"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("redacted"), "{err}");
            let ok = format!("[privacy]\nmode = \"metrics_only\"\n[pii]\n{extra}\n");
            assert!(privacy(&ok).is_ok());
        }
    }

    #[test]
    fn test_privacy_gate_only_tightens() {
        let gate = PrivacyGate::new(PrivacyMode::Redacted);
        assert!(!gate.tighten(PrivacyMode::Full));
        assert_eq!(gate.get(), PrivacyMode::Redacted);
        assert!(gate.tighten(PrivacyMode::Redacted));
        assert!(gate.tighten(PrivacyMode::MetricsOnly));
        assert_eq!(gate.get(), PrivacyMode::MetricsOnly);
        assert!(!gate.tighten(PrivacyMode::Redacted));
        assert_eq!(gate.get(), PrivacyMode::MetricsOnly);
    }

    #[test]
    fn test_privacy_gate_allows_only_records_as_strict_as_the_mode() {
        use PrivacyMode::*;
        let gate = PrivacyGate::new(Full);
        assert!(gate.allows(Full) && gate.allows(Redacted));
        gate.tighten(Redacted);
        assert!(!gate.allows(Full), "queued unredacted before the tighten");
        assert!(gate.allows(Redacted) && gate.allows(MetricsOnly));
        gate.tighten(MetricsOnly);
        assert!(!gate.allows(Redacted));
    }

    #[test]
    fn test_reload_cannot_tighten_without_a_redactor() {
        use PrivacyMode::*;
        // full, started with [pii] enabled = false: no engine in the workers.
        let started = privacy("[privacy]\nmode = \"full\"\n[pii]\nenabled = false\n").unwrap();
        assert!(!can_redact(&started.pii));
        assert!(check_reload(Full, Redacted, false).is_err());
        // metrics_only drops every payload string: no redactor needed.
        assert!(check_reload(Full, MetricsOnly, false).is_ok());
        assert!(check_reload(Full, Redacted, true).is_ok());
        assert!(check_reload(Redacted, Redacted, true).is_ok());
        assert!(check_reload(Redacted, Full, true).is_err());
        assert!(check_reload(MetricsOnly, Redacted, true).is_err());
    }

    #[test]
    fn test_mask_credentials_only_off_in_full_without_redaction() {
        // Default: masked, in every mode.
        for mode in [
            PrivacyMode::Full,
            PrivacyMode::Redacted,
            PrivacyMode::MetricsOnly,
        ] {
            let mut config = AgentConfig::default();
            config.privacy_mode = mode;
            apply_privacy(&mut config).unwrap();
            assert!(config.pii.mask_credentials, "{mode}");
        }
        let off = |mode, redact: Option<bool>| {
            let mut config = AgentConfig::default();
            config.privacy_mode = mode;
            config.pii_redact_setting = redact;
            config.mask_credentials = false;
            apply_privacy(&mut config).map(|()| config.pii.mask_credentials)
        };
        assert_eq!(off(PrivacyMode::Full, None).unwrap(), false);
        // Codex round 5 #9: the refusal promises best effort in `redacted`
        // and `full`, a guarantee only in `metrics_only`.
        for (mode, redact) in [
            (PrivacyMode::Full, Some(true)),
            (PrivacyMode::Redacted, None),
            (PrivacyMode::MetricsOnly, None),
        ] {
            let err = off(mode, redact).unwrap_err().to_string();
            assert!(!err.contains("never"), "{err}");
            assert!(err.contains("best effort"), "{err}");
            assert!(
                err.contains("only mode = \"metrics_only\" guarantees"),
                "{err}"
            );
        }
    }

    /// `[credentials]` parses; an invalid or oversized pattern, or an
    /// unknown builtin level, refuses the config (a SIGHUP reload of it is
    /// refused the same way: reload goes through `load_config`).
    #[test]
    fn test_credentials_section() {
        let config = load_config_from_str(
            "[credentials]\npatterns = [\"(?i)acme_[a-z0-9]{32}\", \"AKIA[0-9A-Z]{16}\"]\n\
             builtin = \"names_only\"\n",
        )
        .unwrap();
        assert_eq!(config.credential_patterns.len(), 2);
        assert_eq!(
            config.credential_builtin,
            crate::protocol::Builtin::NamesOnly
        );
        assert!(credential_rules(&config).is_ok());
        // The USER-GUIDE §5.3 example.
        let guide = include_str!("../../docs/USER-GUIDE.md");
        let example = guide
            .split("```toml\n[credentials]\npatterns = [\n")
            .nth(1)
            .and_then(|rest| rest.split("```").next())
            .expect("the [credentials] example in USER-GUIDE.md");
        let config =
            load_config_from_str(&format!("[credentials]\npatterns = [\n{example}")).unwrap();
        assert_eq!(config.credential_patterns.len(), 4);
        assert!(config.credential_patterns[1].contains(r"\s*=\s*\S+"));
        assert_eq!(
            load_config_from_str("").unwrap().credential_builtin,
            crate::protocol::Builtin::Full
        );
        for (bad, why) in [
            ("[credentials]\npatterns = [\"acme_[a-z\"]\n", "pattern 0"),
            ("[credentials]\npatterns = [\"x*\"]\n", "empty span"),
            (
                "[credentials]\npatterns = [\"\\\\w{1000}{1000}\"]\n",
                "pattern 0",
            ),
            ("[credentials]\nbuiltin = \"some\"\n", "names_only"),
            ("[credentials]\npattern = [\"x\"]\n", "unknown field"),
        ] {
            let err = load_config_from_str(bad).unwrap_err().to_string();
            assert!(err.contains(why), "{bad}: {err}");
        }
    }

    #[test]
    fn test_mask_credentials_parses_from_toml() {
        let config =
            load_config_from_str("[privacy]\nmode = \"full\"\nmask_credentials = false\n").unwrap();
        assert!(!config.mask_credentials);
    }

    #[test]
    fn test_external_pii_service_needs_full() {
        for mode in [
            PrivacyMode::Redacted,
            PrivacyMode::MetricsOnly,
            PrivacyMode::Full,
        ] {
            let mut config = AgentConfig::default();
            config.privacy_mode = mode;
            config.pii.mode = PiiMode::External {
                url: "http://localhost:8080/pii".into(),
                sample_rate: 1.0,
                timeout_ms: 100,
            };
            assert_eq!(
                apply_privacy(&mut config).is_ok(),
                mode == PrivacyMode::Full
            );
        }
    }

    #[test]
    fn test_kubernetes_defaults() {
        let config = AgentConfig::default();
        assert_eq!(config.kubernetes.mode, KubernetesMode::Auto);
        assert_eq!(config.kubernetes.relist_interval, Duration::from_secs(300));
        assert!(config.kubernetes.watch);
    }

    #[test]
    fn test_kubernetes_enabled_values() {
        for (value, mode) in [
            ("\"auto\"", KubernetesMode::Auto),
            ("\"AUTO\"", KubernetesMode::Auto),
            ("true", KubernetesMode::Enabled),
            ("\"true\"", KubernetesMode::Enabled),
            ("false", KubernetesMode::Disabled),
            ("\"false\"", KubernetesMode::Disabled),
        ] {
            let toml = format!("[kubernetes]\nenabled = {value}\n");
            let config = load_config_from_str(&toml).unwrap();
            assert_eq!(config.kubernetes.mode, mode, "enabled = {value}");
        }
    }

    #[test]
    fn test_kubernetes_invalid_enabled_rejected() {
        let err = load_config_from_str("[kubernetes]\nenabled = \"sometimes\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("kubernetes.enabled"), "{err}");
    }

    #[test]
    fn test_kubernetes_relist_interval_too_small_rejected() {
        let err = load_config_from_str("[kubernetes]\nrelist_interval_secs = 1\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("relist_interval_secs"), "{err}");
    }
}
