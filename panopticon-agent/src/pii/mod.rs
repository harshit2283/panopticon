#![allow(dead_code)]
//! PII detection pipeline: regex prefilter -> optional ML inference -> redaction.

#[cfg(test)]
mod accuracy;
pub mod classifier;
pub mod external;
pub mod redactor;
pub mod regex_prefilter;
pub mod sampler;

#[cfg(feature = "ml")]
pub mod inference;
#[cfg(feature = "ml")]
pub mod tokenizer;

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(feature = "ml")]
use tracing::warn;

use self::external::ExternalPiiClient;
use self::redactor::redact;
use self::regex_prefilter::RegexPrefilter;
use self::sampler::{InferenceSampler, template_hash};
use crate::config::{PiiConfig, PiiMode};
use crate::protocol::{L7Message, Protocol};

use crate::protocol::{REDACTED_CREDENTIAL, protect_text_in};

/// Headers whose values are credentials or session tokens, masked wholesale
/// when redaction is on: regexes cannot recognise opaque tokens and session
/// cookies. Matched by name: any name containing one of [`CREDENTIAL_NAME_PARTS`],
/// so vendor headers (`X-Vault-Token`, `PRIVATE-TOKEN`, `X-Goog-Api-Key`,
/// `X-Hub-Signature-256`, `X-CSRF-Token`, ...) are covered without a list.
fn is_credential_header(name: &str) -> bool {
    const CREDENTIAL_NAME_PARTS: &[&str] = &[
        "token",
        "auth",
        "key",
        "secret",
        "session",
        "csrf",
        "xsrf",
        "signature",
        "password",
        "passwd",
        "cookie",
        "credential",
    ];
    // Names that match a part but carry nothing secret: the HTTP/2 authority
    // (the host) and the WebSocket handshake nonce.
    const READABLE: &[&str] = &[":authority", "sec-websocket-key"];
    let name = name.to_ascii_lowercase();
    !READABLE.contains(&name.as_str()) && CREDENTIAL_NAME_PARTS.iter().any(|p| name.contains(p))
}

/// Mask the credentials that are whole fields: the arguments of an `AUTH`
/// command and the values of credential-named headers (HTTP header names
/// by [`is_credential_header`], any protocol's by
/// [`crate::protocol::is_credential_name`]); drop DNS answers whose name has
/// credential context.
fn mask_credential_fields(msg: &mut L7Message) {
    let wipe = |f: &mut String| {
        f.zeroize();
        *f = REDACTED_CREDENTIAL.to_string();
    };
    if msg
        .method
        .as_deref()
        .is_some_and(|m| m.eq_ignore_ascii_case("AUTH"))
    {
        [&mut msg.path, &mut msg.request_text]
            .into_iter()
            .flatten()
            .for_each(wipe);
    }
    let http = matches!(
        msg.protocol,
        Protocol::Http1 | Protocol::Http2 | Protocol::Grpc
    );
    msg.headers
        .iter_mut()
        .filter(|(name, _)| {
            (http && is_credential_header(name)) || crate::protocol::is_credential_name(name)
        })
        .for_each(|(_, value)| {
            crate::protocol::count_builtin();
            wipe(value)
        });
    msg.dns_answers
        .retain(|a| !crate::protocol::has_credential_context(&a.name));
}

/// Protect login secrets in every string field of `msg` without the PII
/// engine (see [`crate::protocol::protect_text`]): what
/// [`PiiEngine::scan_message_with`] does when `mask_credentials` is on, for
/// `full` mode with `[pii] enabled = false`.
pub fn mask_credentials(msg: &mut L7Message) {
    mask_credential_fields(msg);
    for field in [
        &mut msg.method,
        &mut msg.path,
        &mut msg.content_type,
        &mut msg.request_text,
        &mut msg.payload_text,
    ]
    .into_iter()
    .flatten()
    {
        protect_text_in(field);
    }
    for (name, value) in msg.headers.iter_mut() {
        // A wiped credential header keeps its name readable.
        if value != REDACTED_CREDENTIAL {
            protect_text_in(name);
            protect_text_in(value);
        }
    }
}

/// Decode `%XX` escapes and `+` (form encoding) for PII scanning.
/// Invalid escapes are kept verbatim; invalid UTF-8 is replaced lossily.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(feature = "ml")]
use self::inference::OnnxInference;

/// PII entity categories detected by regex or ML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiCategory {
    Email,
    PhoneUs,
    PhoneIn,
    PhoneIntl,
    Ssn,
    CreditCard,
    IpV4,
    Jwt,
    ApiKey,
    AwsKey,
    Aadhaar,
    Pan,
    Upi,
    Gstin,
    PassportIn,
    Iban,
    PersonName,
    Location,
    Organization,
    DateOfBirth,
}

impl std::fmt::Display for PiiCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiCategory::Email => write!(f, "EMAIL"),
            PiiCategory::PhoneUs => write!(f, "PHONE_US"),
            PiiCategory::PhoneIn => write!(f, "PHONE_IN"),
            PiiCategory::PhoneIntl => write!(f, "PHONE_INTL"),
            PiiCategory::Ssn => write!(f, "SSN"),
            PiiCategory::CreditCard => write!(f, "CREDIT_CARD"),
            PiiCategory::IpV4 => write!(f, "IP_V4"),
            PiiCategory::Jwt => write!(f, "JWT"),
            PiiCategory::ApiKey => write!(f, "API_KEY"),
            PiiCategory::AwsKey => write!(f, "AWS_KEY"),
            PiiCategory::Aadhaar => write!(f, "AADHAAR"),
            PiiCategory::Pan => write!(f, "PAN"),
            PiiCategory::Upi => write!(f, "UPI"),
            PiiCategory::Gstin => write!(f, "GSTIN"),
            PiiCategory::PassportIn => write!(f, "PASSPORT_IN"),
            PiiCategory::Iban => write!(f, "IBAN"),
            PiiCategory::PersonName => write!(f, "PERSON_NAME"),
            PiiCategory::Location => write!(f, "LOCATION"),
            PiiCategory::Organization => write!(f, "ORGANIZATION"),
            PiiCategory::DateOfBirth => write!(f, "DATE_OF_BIRTH"),
        }
    }
}

/// Where the PII entity was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PiiSource {
    Regex,
    Ml,
    External,
}

/// A single PII entity found in text.
#[derive(Debug, Clone, Serialize)]
pub struct PiiEntity {
    pub category: PiiCategory,
    pub source: PiiSource,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
    #[serde(skip_serializing)]
    pub text: String,
}

impl Drop for PiiEntity {
    fn drop(&mut self) {
        self.text.zeroize();
    }
}

/// Report of all PII entities found in a payload.
#[derive(Debug, Clone, Serialize)]
pub struct PiiReport {
    pub entities: Vec<PiiEntity>,
    pub redacted_text: Option<String>,
    pub scanned_bytes: usize,
    /// True when the detected values were replaced in the message before it
    /// was logged or exported (redaction enabled).
    pub redacted: bool,
}

impl Drop for PiiReport {
    fn drop(&mut self) {
        if let Some(ref mut text) = self.redacted_text {
            text.zeroize();
        }
    }
}

/// Findings accumulated over the fields of one message.
#[derive(Default)]
struct Found {
    entities: Vec<PiiEntity>,
    scanned_bytes: usize,
}

/// Thread-safe PII detection engine. Cloneable (Arc internals).
///
/// Built once at startup; each capture pipeline then takes its own copy
/// ([`for_pipeline`](Self::for_pipeline)): the regexes and the ONNX model
/// session are immutable and shared, while everything that holds captured
/// state (the sampler's seen templates, the tokenizer, the external client
/// and its connections) is per pipeline (DESIGN §3, Revision 1 item 6).
#[derive(Clone)]
pub struct PiiEngine {
    config: PiiConfig,
    regex: Arc<RegexPrefilter>,
    sampler: Arc<InferenceSampler>,
    max_inferences: u32,
    external: Option<Arc<ExternalPiiClient>>,
    /// The validated external service settings: (url, timeout_ms, rate).
    external_service: Option<(String, u32, f64)>,
    #[cfg(feature = "ml")]
    onnx: Option<Arc<OnnxInference>>,
}

impl PiiEngine {
    pub fn new(config: &PiiConfig, allowlist: &[String]) -> Self {
        let max_inferences = match &config.mode {
            PiiMode::InAgent {
                max_inferences_per_sec,
                ..
            } => *max_inferences_per_sec,
            _ => 100,
        };

        let external_service = match &config.mode {
            PiiMode::External {
                url,
                sample_rate,
                timeout_ms,
            } => {
                if reqwest::Url::parse(url).is_err() {
                    tracing::warn!(url = %url, "External PII URL is invalid; external mode disabled");
                    None
                } else {
                    let mut allowed = allowlist.is_empty();
                    if !allowed {
                        allowed = Self::pii_url_allowed(url, allowlist);
                    }

                    if allowed {
                        Some((url.clone(), *timeout_ms, *sample_rate))
                    } else {
                        tracing::warn!(url = %url, "External PII URL rejected by allowlist");
                        None
                    }
                }
            }
            _ => None,
        };

        #[cfg(feature = "ml")]
        let onnx = Self::init_onnx(config);

        let mut engine = Self {
            config: config.clone(),
            regex: Arc::new(RegexPrefilter::new()),
            sampler: Arc::new(InferenceSampler::new(max_inferences)),
            max_inferences,
            external: None,
            external_service,
            #[cfg(feature = "ml")]
            onnx,
        };
        // Standalone use (tests, replay): an external client on a gate of
        // its own. The agent gives each pipeline its own instead.
        engine.external =
            engine.external_client(crate::io_gate::IoGate::new(), tracing::Dispatch::default());
        engine
    }

    fn external_client(
        &self,
        gate: Arc<crate::io_gate::IoGate>,
        dispatch: tracing::Dispatch,
    ) -> Option<Arc<ExternalPiiClient>> {
        let (url, timeout_ms, rate) = self.external_service.clone()?;
        Some(Arc::new(ExternalPiiClient::new(
            url, timeout_ms, rate, gate, dispatch,
        )))
    }

    /// This engine for one capture pipeline: shared regexes and model, a
    /// fresh sampler, tokenizer and external client (writing under `gate`,
    /// logging through `dispatch`).
    pub fn for_pipeline(
        &self,
        gate: Arc<crate::io_gate::IoGate>,
        dispatch: tracing::Dispatch,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            config: self.config.clone(),
            regex: Arc::clone(&self.regex),
            sampler: Arc::new(InferenceSampler::new(self.max_inferences)),
            max_inferences: self.max_inferences,
            external: self.external_client(gate, dispatch),
            external_service: self.external_service.clone(),
            // A tokenizer that does not build fails the pipeline build:
            // ML detection never silently turns into regex alone.
            #[cfg(feature = "ml")]
            onnx: match &self.onnx {
                Some(o) => Some(Arc::new(o.for_pipeline()?)),
                None => None,
            },
        })
    }

    fn pii_url_allowed(url: &str, allowlist: &[String]) -> bool {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };

        let host = parsed.host_str().unwrap_or("").to_ascii_lowercase();
        let target_origin = Self::canonical_origin(&parsed);
        let target_url = Self::canonical_url(&parsed);

        allowlist.iter().any(|entry| {
            let trimmed = entry.trim();
            if trimmed.eq_ignore_ascii_case(&host) {
                return true;
            }

            if target_origin
                .as_deref()
                .is_some_and(|origin| trimmed.eq_ignore_ascii_case(origin))
            {
                return true;
            }

            let Ok(allow_url) = reqwest::Url::parse(trimmed) else {
                return false;
            };

            let allow_is_origin_scoped = allow_url.path() == "/" && allow_url.query().is_none();
            if allow_is_origin_scoped
                && Self::canonical_origin(&allow_url).as_deref() == target_origin.as_deref()
            {
                return true;
            }

            Self::canonical_url(&allow_url).as_deref() == target_url.as_deref()
        })
    }

    fn canonical_origin(url: &reqwest::Url) -> Option<String> {
        let host = url.host_str()?.to_ascii_lowercase();
        let scheme = url.scheme().to_ascii_lowercase();
        let port = url.port_or_known_default()?;
        Some(format!("{scheme}://{host}:{port}"))
    }

    fn canonical_url(url: &reqwest::Url) -> Option<String> {
        let origin = Self::canonical_origin(url)?;
        let mut canonical = format!("{origin}{}", url.path());
        if let Some(query) = url.query() {
            canonical.push('?');
            canonical.push_str(query);
        }
        Some(canonical)
    }

    #[cfg(feature = "ml")]
    fn init_onnx(config: &PiiConfig) -> Option<Arc<OnnxInference>> {
        let model_path = match &config.mode {
            PiiMode::InAgent { model_path, .. } => model_path,
            _ => return None,
        };

        let model_file = format!("{}/model.onnx", model_path);
        let tokenizer_file = format!("{}/tokenizer.json", model_path);

        match OnnxInference::new(&model_file, &tokenizer_file) {
            Ok(inference) => Some(Arc::new(inference)),
            Err(e) => {
                warn!(error = %e, "Failed to load ONNX model, ML inference disabled");
                None
            }
        }
    }

    /// Whether the engine's config asks for redaction (`pii.redact`).
    pub fn redacts(&self) -> bool {
        self.config.redact
    }

    /// Scan text for PII. Returns None if PII detection is disabled or no PII found.
    pub fn scan(&self, text: &str) -> Option<PiiReport> {
        self.scan_with(text, self.config.redact)
    }

    /// [`scan`](Self::scan) with redaction decided by the caller (the
    /// privacy mode in effect) instead of the engine's config.
    pub fn scan_with(&self, text: &str, redact_enabled: bool) -> Option<PiiReport> {
        if !self.config.enabled || text.is_empty() {
            return None;
        }

        let mut entities = Vec::new();

        if self.config.regex_enabled {
            entities.extend(self.regex.scan(text));
        }

        #[cfg(feature = "ml")]
        if let Some(ref onnx) = self.onnx {
            if self.sampler.should_invoke(text) {
                match onnx.predict_entities(text, self.config.min_confidence) {
                    Ok(ml_entities) => {
                        Self::merge_entities(&mut entities, ml_entities);
                    }
                    Err(e) => {
                        warn!(error = %e, "ML inference failed");
                    }
                }
            }
        }

        if entities.is_empty() {
            return None;
        }

        let redacted_text = if redact_enabled {
            Some(redact(text, &entities))
        } else {
            None
        };

        Some(PiiReport {
            scanned_bytes: text.len(),
            entities,
            redacted: redacted_text.is_some(),
            redacted_text,
        })
    }

    /// Scan every user-controlled field of a message — path/query, HTTP header
    /// values and payload — and, when redaction is enabled, rewrite those
    /// fields in place so that no exporter (JSON, OTLP, logs) or the service
    /// graph ever sees the raw values.
    ///
    /// Entity offsets in the returned report are relative to the field they
    /// were found in. `redacted_text` is the redacted payload, if any.
    pub fn scan_message(&self, msg: &mut L7Message) -> Option<PiiReport> {
        self.scan_message_with(msg, self.config.redact)
    }

    /// [`scan_message`](Self::scan_message) with redaction decided by the
    /// caller (the privacy mode in effect).
    ///
    /// Every string field an exporter can carry is scanned: method, path,
    /// content type, header names and values (all protocols), request and
    /// response body. A DNS answer (`dns_a_record`, `domain|ip|ttl`) is not
    /// rewritten, since it feeds the DNS cache; with redaction on, one whose
    /// name holds PII (`123-45-6789.example.com`) is removed instead, so the
    /// name never becomes a service identity. Its PII is counted once,
    /// from the query name in `path`. With redaction on, credentials
    /// are also masked whatever the protocol: credential-named HTTP headers
    /// wholesale, the arguments of an `AUTH` command, and keyword-introduced
    /// secrets (`PASSWORD '…'`, `IDENTIFIED BY '…'`, `requirepass …`,
    /// `password=…`) in any field.
    pub fn scan_message_with(
        &self,
        msg: &mut L7Message,
        redact_enabled: bool,
    ) -> Option<PiiReport> {
        if !self.config.enabled {
            return None;
        }
        let mut found = Found::default();
        // Login secrets are masked whenever values are redacted, and also in
        // `full` mode unless `[privacy] mask_credentials = false`.
        let mask_creds = redact_enabled || self.config.mask_credentials;

        if mask_creds {
            mask_credential_fields(msg);
        }

        if let Some(path) = msg.path.as_mut() {
            // Query strings are usually percent-encoded (alice%40example.com),
            // which the regexes would miss: scan the decoded form.
            self.scan_field(path, true, redact_enabled, &mut found);
        }
        for field in [&mut msg.method, &mut msg.content_type]
            .into_iter()
            .flatten()
        {
            self.scan_field(field, false, redact_enabled, &mut found);
        }

        if redact_enabled {
            msg.dns_answers
                .retain(|a| self.scan_with(&a.name, false).is_none());
        }
        for (name, value) in msg.headers.iter_mut() {
            // A wiped credential header keeps its name readable.
            if mask_creds && value == REDACTED_CREDENTIAL {
                continue;
            }
            self.scan_field(value, false, redact_enabled, &mut found);
            self.scan_field(name, false, redact_enabled, &mut found);
        }

        if let Some(body) = msg.request_text.as_mut() {
            self.scan_field(body, false, redact_enabled, &mut found);
        }

        let mut redacted_payload = None;
        if let Some(text) = msg.payload_text.as_mut() {
            let before = found.entities.len();
            self.scan_field(text, false, redact_enabled, &mut found);
            if redact_enabled && found.entities.len() > before {
                redacted_payload = Some(text.clone());
            }
        }

        if found.entities.is_empty() {
            return None;
        }
        Some(PiiReport {
            entities: found.entities,
            redacted_text: redacted_payload,
            scanned_bytes: found.scanned_bytes,
            redacted: redact_enabled,
        })
    }

    /// Scan one field (percent-decoded first when `decode`); with redaction
    /// on, replace it by its redacted form; then protect credentials in it
    /// (masked or the field withheld, see [`crate::protocol::protect_text`]).
    /// Entity offsets stay relative to the field as scanned.
    fn scan_field(&self, field: &mut String, decode: bool, redact: bool, found: &mut Found) {
        let decoded = decode.then(|| percent_decode(field));
        let text = decoded.as_deref().unwrap_or(field.as_str());
        if let Some(mut report) = self.scan_with(text, redact) {
            found.scanned_bytes += report.scanned_bytes;
            if let Some(redacted) = report.redacted_text.take() {
                field.zeroize();
                *field = redacted;
            }
            found.entities.append(&mut report.entities);
        }
        if redact || self.config.mask_credentials {
            protect_text_in(field);
        }
    }

    /// Scan text with external service (async).
    /// Returns None if external service not configured or on error.
    pub async fn scan_external(&self, text: &str) -> Option<Vec<PiiEntity>> {
        let external = self.external.as_ref()?;
        let hash = template_hash(text);
        external.scan(text, Some(hash)).await
    }

    /// Check if external service is configured.
    pub fn has_external(&self) -> bool {
        self.external.is_some()
    }

    /// Merge ML entities with regex entities, deduplicating by overlapping spans.
    /// Regex entities take precedence for overlapping spans (higher precision).
    #[cfg(feature = "ml")]
    fn merge_entities(entities: &mut Vec<PiiEntity>, ml_entities: Vec<PiiEntity>) {
        for ml_entity in ml_entities {
            let overlaps = entities
                .iter()
                .any(|e| ml_entity.start < e.end && ml_entity.end > e.start);
            if !overlaps {
                entities.push(ml_entity);
            }
        }
    }

    /// Merge external entities into existing entity list.
    pub fn merge_external_entities(
        entities: &mut Vec<PiiEntity>,
        external_entities: Vec<PiiEntity>,
    ) {
        for ext_entity in external_entities {
            let overlaps = entities
                .iter()
                .any(|e| ext_entity.start < e.end && ext_entity.end > e.start);
            if !overlaps {
                entities.push(ext_entity);
            }
        }
    }

    /// Refill the inference sampler budget. Called every 1s from event loop.
    pub fn refill_sampler(&self) {
        self.sampler.refill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PiiConfig;

    #[test]
    fn test_pii_engine_disabled() {
        let mut config = PiiConfig::default();
        config.enabled = false;
        let engine = PiiEngine::new(&config, &[]);
        assert!(engine.scan("my email is test@example.com").is_none());
    }

    #[test]
    fn test_pii_engine_empty_text() {
        let config = PiiConfig::default();
        let engine = PiiEngine::new(&config, &[]);
        assert!(engine.scan("").is_none());
    }

    #[test]
    fn test_pii_engine_no_pii() {
        let config = PiiConfig::default();
        let engine = PiiEngine::new(&config, &[]);
        assert!(engine.scan("hello world no sensitive data here").is_none());
    }

    #[test]
    fn test_pii_engine_detects_email() {
        let config = PiiConfig::default();
        let engine = PiiEngine::new(&config, &[]);
        let report = engine.scan("contact john@example.com for details").unwrap();
        assert!(!report.entities.is_empty());
        assert!(
            report
                .entities
                .iter()
                .any(|e| e.category == PiiCategory::Email)
        );
    }

    #[test]
    fn test_pii_engine_redacts() {
        let config = PiiConfig::default();
        let engine = PiiEngine::new(&config, &[]);
        let report = engine.scan("ssn is 123-45-6789").unwrap();
        assert!(report.redacted_text.is_some());
        let redacted = report.redacted_text.as_ref().unwrap();
        assert!(!redacted.contains("123-45-6789"));
        assert!(redacted.contains("<SSN>"));
    }

    fn http_msg() -> L7Message {
        use panopticon_common::Direction;
        let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, 1);
        msg.path = Some("/login?user=alice%40example.com&ssn=123-45-6789".to_string());
        msg.headers = vec![
            (
                "authorization".to_string(),
                "Bearer opaque-token-xyz".to_string(),
            ),
            ("Cookie".to_string(), "session=abc123".to_string()),
            (
                "x-forwarded-for-user".to_string(),
                "bob@example.com".to_string(),
            ),
            ("accept".to_string(), "*/*".to_string()),
        ];
        msg.payload_text = Some("card 4111 1111 1111 1111".to_string());
        msg
    }

    #[test]
    fn test_scan_message_redacts_path_headers_and_payload() {
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut msg = http_msg();
        let report = engine.scan_message(&mut msg).expect("PII found");

        let path = msg.path.as_deref().unwrap();
        assert!(!path.contains("alice"), "path: {path}");
        assert!(!path.contains("123-45-6789"), "path: {path}");
        assert!(path.contains("<EMAIL>") && path.contains("<SSN>"));

        let header = |n: &str| msg.headers.iter().find(|(k, _)| k == n).unwrap().1.clone();
        assert_eq!(header("authorization"), REDACTED_CREDENTIAL);
        assert_eq!(header("Cookie"), REDACTED_CREDENTIAL);
        assert_eq!(header("x-forwarded-for-user"), "<EMAIL>");
        assert_eq!(header("accept"), "*/*");

        assert!(!msg.payload_text.as_deref().unwrap().contains("4111"));
        assert_eq!(report.redacted_text.as_deref(), msg.payload_text.as_deref());
        assert!(report.redacted);
        let cats: Vec<_> = report.entities.iter().map(|e| e.category).collect();
        assert!(cats.contains(&PiiCategory::Email));
        assert!(cats.contains(&PiiCategory::Ssn));
        assert!(cats.contains(&PiiCategory::CreditCard));
    }

    #[test]
    fn test_scan_message_redacts_request_body() {
        use panopticon_common::Direction;
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut msg = L7Message::new(Protocol::Http1, Direction::Ingress, 1);
        msg.request_text =
            Some(r#"{"email":"bob@example.com","card":"4111 1111 1111 1111"}"#.to_string());
        let report = engine.scan_message(&mut msg).expect("PII in request body");
        let body = msg.request_text.as_deref().unwrap();
        assert!(
            !body.contains("bob@example.com") && !body.contains("4111"),
            "{body}"
        );
        assert!(
            body.contains("<EMAIL>") && body.contains("<CREDIT_CARD>"),
            "{body}"
        );
        assert!(report.redacted);
    }

    #[test]
    fn test_scan_message_detects_without_rewriting_when_redact_off() {
        let config = PiiConfig {
            redact: false,
            mask_credentials: false,
            ..PiiConfig::default()
        };
        let engine = PiiEngine::new(&config, &[]);
        let mut msg = http_msg();
        let original = msg.clone();
        assert!(!engine.scan_message(&mut msg).unwrap().redacted);
        assert_eq!(msg.path, original.path);
        assert_eq!(msg.headers, original.headers);
        assert_eq!(msg.payload_text, original.payload_text);
    }

    #[test]
    fn test_scan_message_leaves_dns_answers_alone() {
        use panopticon_common::Direction;
        // DNS answers feed the DNS cache; the address must not be rewritten.
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut msg = L7Message::new(Protocol::Dns, Direction::Ingress, 1);
        msg.dns_answers = vec![answer("api.internal", 167772161)];
        let _ = engine.scan_message(&mut msg);
        assert_eq!(msg.dns_answers, vec![answer("api.internal", 167772161)]);
    }

    /// Codex #4: a DNS name carrying PII must not become a service name
    /// (audit `service_identity`, graph nodes) or reach the export when
    /// redacting; in full mode it is kept like any other payload.
    #[test]
    fn test_dns_answer_naming_pii_is_dropped_when_redacting() {
        use panopticon_common::Direction;
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let dns = || {
            let mut msg = L7Message::new(Protocol::Dns, Direction::Ingress, 1);
            msg.path = Some("123-45-6789.attacker.test".to_string());
            msg.headers = vec![("qtype".to_string(), "A".to_string())];
            msg.dns_answers = vec![
                answer("123-45-6789.attacker.test", 167772161),
                answer("api.internal", 167772162),
            ];
            msg
        };
        let mut msg = dns();
        let report = engine.scan_message_with(&mut msg, true).unwrap();
        assert_eq!(report.entities.len(), 1, "the SSN, counted once (path)");
        let all = format!("{:?} {:?}", msg.path, msg.dns_answers);
        assert!(!all.contains("123-45-6789"), "{all}");
        assert_eq!(
            msg.dns_answers,
            vec![answer("api.internal", 167772162)],
            "the clean answer stays"
        );
        let mut full = dns();
        engine.scan_message_with(&mut full, false);
        assert_eq!(full.dns_answers, dns().dns_answers);
    }

    fn answer(name: &str, ip: u32) -> crate::protocol::DnsAnswer {
        crate::protocol::DnsAnswer {
            name: name.into(),
            ip,
            ttl_secs: 30,
        }
    }

    #[test]
    fn test_credential_header_names() {
        for name in [
            "Authorization",
            "proxy-authorization",
            "Cookie",
            "set-cookie",
            "x-api-key",
            "X-Auth-Token",
            "x-amz-security-token",
            "X-Vault-Token",
            "PRIVATE-TOKEN",
            "x-goog-api-key",
            "x-csrf-token",
            "X-XSRF-TOKEN",
            "x-hub-signature-256",
            "x-session-id",
            "x-client-secret",
            "x-db-password",
            "x-amz-credential",
        ] {
            assert!(is_credential_header(name), "{name} must be masked");
        }
        for name in [
            "content-type",
            "keep-alive",
            "accept-encoding",
            "accept",
            "host",
            ":authority",
            ":path",
            "sec-websocket-key",
            "user-agent",
            "x-request-id",
            "content-length",
        ] {
            assert!(!is_credential_header(name), "{name} must stay readable");
        }
    }

    #[test]
    fn test_vendor_token_headers_are_masked() {
        use panopticon_common::Direction;
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut msg = L7Message::new(Protocol::Http2, Direction::Egress, 1);
        msg.headers = vec![
            ("x-vault-token".into(), "hvs.CAESIJopaqueVaultToken".into()),
            ("private-token".into(), "glpat-opaqueGitlabToken".into()),
            ("content-type".into(), "application/json".into()),
        ];
        let _ = engine.scan_message_with(&mut msg, true);
        assert_eq!(msg.headers[0].1, REDACTED_CREDENTIAL);
        assert_eq!(msg.headers[1].1, REDACTED_CREDENTIAL);
        assert_eq!(msg.headers[2].1, "application/json");
    }

    /// Credential-named parameters (percent-encoded names too), JSON
    /// fields, header-style values and URI passwords are masked with and
    /// without the engine, in every copy (HTTP/2 keeps `:path` as a header
    /// too); ordinary values stay readable.
    #[test]
    fn test_credential_params_and_uri_passwords_are_masked() {
        use panopticon_common::Direction;
        let msg = || {
            let mut m = L7Message::new(Protocol::Http2, Direction::Egress, 1);
            let path = "/login?%70assword=canary-1&token=canary-2&api_key=canary-3&q=keep";
            m.path = Some(path.into());
            m.headers = vec![
                (":path".into(), path.into()),
                ("x-note".into(), "Authorization: Bearer canary-6".into()),
                (
                    "x-redirect".into(),
                    "/cb?access_token=canary-7&state=keep".into(),
                ),
            ];
            m.request_text = Some(
                r#"{"dsn":"postgresql://app:canary-4@db/app","client_secret": "canary-5","note":"don't","keyword":"keep"}"#
                    .into(),
            );
            m.payload_text = Some("redis://:canary-8@cache:6379/0 and pass%77ord=canary-9".into());
            m
        };
        let check = |m: &L7Message, how: &str| {
            let all = format!(
                "{:?} {:?} {:?} {:?}",
                m.path, m.headers, m.request_text, m.payload_text
            );
            assert!(!all.contains("canary"), "{how}: {all}");
            assert!(
                all.contains("q=keep") && all.contains("state=keep"),
                "{how}: {all}"
            );
            assert!(all.contains(r#"\"note\":\"don't\""#), "{how}: {all}");
            assert!(all.contains(r#"\"keyword\":\"keep\""#), "{how}: {all}");
            assert!(all.contains("postgresql://app:"), "{how}: {all}");
        };
        let mut m = msg();
        mask_credentials(&mut m);
        check(&m, "no engine");
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        for redact in [true, false] {
            let mut m = msg();
            let _ = engine.scan_message_with(&mut m, redact);
            check(&m, &format!("engine, redact {redact}"));
        }
    }

    /// A wire header that borrows the DNS-answer name gets no exemption.
    #[test]
    fn test_wire_header_named_like_dns_metadata_is_masked() {
        use panopticon_common::Direction;
        let msg = || {
            let mut m = L7Message::new(Protocol::Http1, Direction::Egress, 1);
            m.headers = vec![("dns_a_record".into(), "password=canary-dns".into())];
            m
        };
        let mut m = msg();
        mask_credentials(&mut m);
        assert_eq!(m.headers[0].1, "password=<REDACTED>");
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        for redact in [true, false] {
            let mut m = msg();
            let _ = engine.scan_message_with(&mut m, redact);
            assert_eq!(m.headers[0].1, "password=<REDACTED>", "redact {redact}");
        }
    }

    /// `[credentials] patterns` mask in every field of every protocol, with
    /// and without the engine, and are counted. The only test that installs
    /// global rules (its pattern matches no other test's data).
    #[test]
    fn test_user_patterns_mask_every_field() {
        use crate::protocol::{Builtin, CredentialRules, credential_matches, set_credential_rules};
        let token = "acmetok_q7w8e9r0t1y2";
        let pattern = vec!["acmetok_[a-z0-9]{12}".to_string()];
        set_credential_rules(CredentialRules::compile(&pattern, Builtin::Full).unwrap());
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let (user_before, builtin_before) = credential_matches();
        let mut checked = 0;
        for protocol in [
            Protocol::Http1,
            Protocol::Http2,
            Protocol::Mysql,
            Protocol::Postgres,
            Protocol::Redis,
            Protocol::Kafka,
        ] {
            for engine_on in [false, true] {
                let mut msg = L7Message::new(protocol, crate::protocol::Direction::Egress, 0);
                msg.method = Some(format!("GET{token}"));
                msg.path = Some(format!("/v1/{token}/x"));
                msg.content_type = Some(format!("text/{token}"));
                msg.headers = vec![
                    ("x-note".into(), format!("a {token} b")),
                    (format!("x-{token}"), "v".into()),
                ];
                // SQL text, Redis arguments, bound values, bodies.
                msg.payload_text = Some(format!("SELECT * FROM t WHERE k = '{token}'"));
                msg.request_text = Some(format!("{token}, 42"));
                if engine_on {
                    engine.scan_message_with(&mut msg, false);
                } else {
                    mask_credentials(&mut msg);
                }
                let dump = format!("{msg:?}");
                assert!(!dump.contains(token), "{protocol:?} {engine_on}: {dump}");
                checked += 1;
            }
        }
        let (user_after, builtin_after) = credential_matches();
        // 7 fields per message.
        assert!(
            user_after - user_before >= 7 * checked,
            "{user_before} {user_after}"
        );
        // A plain Authorization header counts as builtin.
        let mut msg = L7Message::new(Protocol::Http1, crate::protocol::Direction::Egress, 0);
        msg.headers = vec![("authorization".into(), "Bearer x".into())];
        mask_credentials(&mut msg);
        assert!(credential_matches().1 > builtin_after.max(builtin_before));
        set_credential_rules(CredentialRules::default());
    }

    /// Codex round 3: credential context the value masker could not
    /// delimit. Each field must leave without its secret, with and without
    /// the engine.
    #[test]
    fn test_credential_context_fields_leave_no_secret() {
        use panopticon_common::Direction;
        let long = format!("{}_password", "a".repeat(70));
        let cases: Vec<(&str, String)> = vec![
            ("json", r#"{"password":"canary-1"}"#.into()),
            ("long name", format!("{long}=canary-2&q=1")),
            ("double-encoded", "/x?%2570assword=canary-3".into()),
            (
                "array",
                r#"{"access_tokens":["canary-4a","canary-4b"]}"#.into(),
            ),
            ("object", r#"{"password":{"value":"canary-5"}}"#.into()),
            ("scheme-less authority", "//alice:canary-6@[::1]/db".into()),
            (
                "userinfo in a query value",
                "/cb?next=alice:canary-7@db.internal".into(),
            ),
        ];
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut leaks = Vec::new();
        for (what, text) in &cases {
            for how in ["no engine", "redact", "full"] {
                let mut m = L7Message::new(Protocol::Http1, Direction::Egress, 1);
                m.path = Some(text.clone());
                m.request_text = Some(text.clone());
                match how {
                    "no engine" => mask_credentials(&mut m),
                    h => {
                        let _ = engine.scan_message_with(&mut m, h == "redact");
                    }
                }
                let all = format!("{:?} {:?}", m.path, m.request_text);
                if all.contains("canary") {
                    leaks.push(format!("{what} ({how}): {all}"));
                }
            }
        }
        assert!(leaks.is_empty(), "{leaks:#?}");
    }

    #[test]
    fn test_protocol_credentials_masked_when_redacting() {
        use panopticon_common::Direction;
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        // A Redis AUTH as a parser that did not mask it would emit it.
        let auth = || {
            let mut m = L7Message::new(Protocol::Redis, Direction::Ingress, 1);
            m.method = Some("AUTH".into());
            m.path = Some("alice".into());
            m.request_text = Some("r3dis-s3cret".into());
            m
        };
        let mut msg = auth();
        let _ = engine.scan_message_with(&mut msg, true);
        assert_eq!(msg.path.as_deref(), Some(REDACTED_CREDENTIAL));
        assert_eq!(msg.request_text.as_deref(), Some(REDACTED_CREDENTIAL));

        let mut msg = L7Message::new(Protocol::Mysql, Direction::Ingress, 1);
        msg.payload_text = Some("CREATE USER bob IDENTIFIED BY 'sql-s3cret'".into());
        msg.request_text = Some("requirepass r3dis-s3cret".into());
        let _ = engine.scan_message_with(&mut msg, true);
        let all = format!("{:?} {:?}", msg.payload_text, msg.request_text);
        assert!(!all.contains("s3cret"), "{all}");

        // full mode, redaction off: login secrets still masked by default
        // ([privacy] mask_credentials = true), PII left as captured.
        let mut msg = auth();
        msg.payload_text = Some("mail alice@example.com".into());
        let _ = engine.scan_message_with(&mut msg, false);
        assert_eq!(msg.request_text.as_deref(), Some(REDACTED_CREDENTIAL));
        assert_eq!(msg.payload_text.as_deref(), Some("mail alice@example.com"));

        // full mode with mask_credentials = false: exported as captured.
        let raw = PiiEngine::new(
            &PiiConfig {
                mask_credentials: false,
                ..PiiConfig::default()
            },
            &[],
        );
        let mut msg = auth();
        let _ = raw.scan_message_with(&mut msg, false);
        assert_eq!(msg.request_text.as_deref(), Some("r3dis-s3cret"));
    }

    #[test]
    fn test_every_exported_field_is_scanned() {
        use panopticon_common::Direction;
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut msg = L7Message::new(Protocol::Kafka, Direction::Ingress, 1);
        msg.method = Some("/pkg.Svc/carol@example.com".into());
        msg.content_type = Some("text/plain; owner=dave@example.com".into());
        msg.headers = vec![
            ("client_id".into(), "erin@example.com".into()),
            ("frank@example.com".into(), "v".into()),
        ];
        let report = engine.scan_message_with(&mut msg, true).expect("PII found");
        let all = format!("{:?} {:?} {:?}", msg.method, msg.content_type, msg.headers);
        assert!(!all.contains("example.com"), "{all}");
        assert_eq!(report.entities.len(), 4);
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("a%40b.com"), "a@b.com");
        assert_eq!(percent_decode("x+y"), "x y");
        assert_eq!(percent_decode("bad%zzescape%4"), "bad%zzescape%4");
        assert_eq!(percent_decode("%"), "%");
    }

    #[test]
    fn test_pii_engine_no_redact_when_disabled() {
        let mut config = PiiConfig::default();
        config.redact = false;
        let engine = PiiEngine::new(&config, &[]);
        let report = engine.scan("ssn is 123-45-6789").unwrap();
        assert!(report.redacted_text.is_none());
    }

    #[test]
    fn test_pii_engine_cloneable() {
        let config = PiiConfig::default();
        let engine = PiiEngine::new(&config, &[]);
        let cloned = engine.clone();
        let report = cloned.scan("email: user@test.org").unwrap();
        assert!(!report.entities.is_empty());
    }

    #[test]
    fn pipeline_copies_share_regexes_but_not_captured_state() {
        let config = PiiConfig {
            mode: PiiMode::External {
                url: "http://pii.local/detect".to_string(),
                sample_rate: 1.0,
                timeout_ms: 100,
            },
            ..PiiConfig::default()
        };
        let engine = PiiEngine::new(&config, &[]);
        let gate = crate::io_gate::IoGate::new();
        let p = engine
            .for_pipeline(gate, tracing::Dispatch::default())
            .unwrap();
        assert!(Arc::ptr_eq(&engine.regex, &p.regex));
        assert!(!Arc::ptr_eq(&engine.sampler, &p.sampler));
        assert!(!Arc::ptr_eq(
            engine.external.as_ref().unwrap(),
            p.external.as_ref().unwrap()
        ));
    }

    #[test]
    fn test_pii_engine_with_external_mode() {
        let mut config = PiiConfig::default();
        config.mode = PiiMode::External {
            url: "http://localhost:8080/pii".to_string(),
            sample_rate: 0.01,
            timeout_ms: 5000,
        };
        let engine = PiiEngine::new(&config, &[]);
        assert!(engine.has_external());
    }

    #[test]
    fn test_pii_engine_external_rejects_invalid_url_without_allowlist() {
        let mut config = PiiConfig::default();
        config.mode = PiiMode::External {
            url: "not a valid url".to_string(),
            sample_rate: 0.01,
            timeout_ms: 5000,
        };
        let engine = PiiEngine::new(&config, &[]);
        assert!(!engine.has_external());
    }

    #[test]
    fn test_pii_engine_external_none_when_not_configured() {
        let config = PiiConfig::default();
        let engine = PiiEngine::new(&config, &[]);
        assert!(!engine.has_external());
    }

    #[test]
    fn test_pii_url_allowlist_rejects_prefix_bypass() {
        let allowlist = vec!["https://trusted.example".to_string()];
        assert!(!PiiEngine::pii_url_allowed(
            "https://trusted.example.attacker.com/pii",
            &allowlist
        ));
    }

    #[test]
    fn test_pii_url_allowlist_accepts_exact_origin() {
        let allowlist = vec!["https://trusted.example:8443".to_string()];
        assert!(PiiEngine::pii_url_allowed(
            "https://trusted.example:8443/pii",
            &allowlist
        ));
    }

    #[test]
    fn test_pii_url_allowlist_accepts_mixed_case_origin() {
        let allowlist = vec!["HTTPS://Trusted.Example:8443".to_string()];
        assert!(PiiEngine::pii_url_allowed(
            "https://trusted.example:8443/pii",
            &allowlist
        ));
    }

    #[test]
    fn test_pii_url_allowlist_path_scope_does_not_widen_origin() {
        let allowlist = vec!["https://trusted.example/pii".to_string()];
        assert!(PiiEngine::pii_url_allowed(
            "https://trusted.example/pii",
            &allowlist
        ));
        assert!(!PiiEngine::pii_url_allowed(
            "https://trusted.example/admin",
            &allowlist
        ));
    }

    #[cfg(feature = "ml")]
    #[test]
    fn test_merge_entities_no_overlap() {
        let mut entities = vec![PiiEntity {
            category: PiiCategory::Email,
            source: PiiSource::Regex,
            start: 0,
            end: 10,
            confidence: 1.0,
            text: "test@test.com".to_string(),
        }];
        let ml_entities = vec![PiiEntity {
            category: PiiCategory::PersonName,
            source: PiiSource::Ml,
            start: 20,
            end: 30,
            confidence: 0.9,
            text: "John".to_string(),
        }];
        PiiEngine::merge_entities(&mut entities, ml_entities);
        assert_eq!(entities.len(), 2);
    }

    #[cfg(feature = "ml")]
    #[test]
    fn test_merge_entities_overlap_discarded() {
        let mut entities = vec![PiiEntity {
            category: PiiCategory::Email,
            source: PiiSource::Regex,
            start: 0,
            end: 15,
            confidence: 1.0,
            text: "test@test.com".to_string(),
        }];
        let ml_entities = vec![PiiEntity {
            category: PiiCategory::PersonName,
            source: PiiSource::Ml,
            start: 5,
            end: 10,
            confidence: 0.9,
            text: "test".to_string(),
        }];
        PiiEngine::merge_entities(&mut entities, ml_entities);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].source, PiiSource::Regex);
    }

    #[test]
    fn test_merge_external_entities() {
        let mut entities = vec![PiiEntity {
            category: PiiCategory::Email,
            source: PiiSource::Regex,
            start: 0,
            end: 10,
            confidence: 1.0,
            text: "test@test.com".to_string(),
        }];
        let external_entities = vec![PiiEntity {
            category: PiiCategory::Ssn,
            source: PiiSource::External,
            start: 20,
            end: 30,
            confidence: 0.95,
            text: "123-45-6789".to_string(),
        }];
        PiiEngine::merge_external_entities(&mut entities, external_entities);
        assert_eq!(entities.len(), 2);
    }
}
