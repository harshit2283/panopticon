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

use crate::protocol::{REDACTED_CREDENTIAL, mask_secrets_in};

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
#[derive(Clone)]
pub struct PiiEngine {
    config: PiiConfig,
    regex: Arc<RegexPrefilter>,
    sampler: Arc<InferenceSampler>,
    external: Option<Arc<ExternalPiiClient>>,
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

        let external = match &config.mode {
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
                        Some(Arc::new(ExternalPiiClient::new(
                            url.clone(),
                            *timeout_ms,
                            *sample_rate,
                        )))
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

        Self {
            config: config.clone(),
            regex: Arc::new(RegexPrefilter::new()),
            sampler: Arc::new(InferenceSampler::new(max_inferences)),
            external,
            #[cfg(feature = "ml")]
            onnx,
        }
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

        if redact_enabled
            && msg
                .method
                .as_deref()
                .is_some_and(|m| m.eq_ignore_ascii_case("AUTH"))
        {
            for f in [&mut msg.path, &mut msg.request_text].into_iter().flatten() {
                f.zeroize();
                *f = REDACTED_CREDENTIAL.to_string();
            }
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

        let http = matches!(
            msg.protocol,
            Protocol::Http1 | Protocol::Http2 | Protocol::Grpc
        );
        if redact_enabled {
            msg.headers.retain(|(name, value)| {
                name != "dns_a_record" || {
                    let domain = value.split('|').next().unwrap_or_default();
                    self.scan_with(domain, false).is_none()
                }
            });
        }
        for (name, value) in msg.headers.iter_mut() {
            // DNS answers (domain|ip|ttl) feed the DNS cache: an IP-shaped
            // value there must not be rewritten.
            if name == "dns_a_record" {
                continue;
            }
            if redact_enabled && http && is_credential_header(name) {
                value.zeroize();
                *value = REDACTED_CREDENTIAL.to_string();
            } else {
                self.scan_field(value, false, redact_enabled, &mut found);
            }
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
    /// on, replace it by its redacted form and then mask credentials in it.
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
        if redact {
            mask_secrets_in(field);
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
    fn test_scan_message_leaves_non_http_headers_alone() {
        use panopticon_common::Direction;
        // DNS answers travel as synthetic headers (domain|ip|ttl) feeding the
        // DNS cache; IP-shaped values there must not be rewritten.
        let engine = PiiEngine::new(&PiiConfig::default(), &[]);
        let mut msg = L7Message::new(Protocol::Dns, Direction::Ingress, 1);
        msg.headers = vec![(
            "dns_a_record".to_string(),
            "api.internal|167772161|30".to_string(),
        )];
        let _ = engine.scan_message(&mut msg);
        assert_eq!(msg.headers[0].1, "api.internal|167772161|30");
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
            msg.headers = vec![
                ("qtype".to_string(), "A".to_string()),
                (
                    "dns_a_record".to_string(),
                    "123-45-6789.attacker.test|167772161|30".to_string(),
                ),
                (
                    "dns_a_record".to_string(),
                    "api.internal|167772162|30".to_string(),
                ),
            ];
            msg
        };
        let mut msg = dns();
        let report = engine.scan_message_with(&mut msg, true).unwrap();
        assert_eq!(report.entities.len(), 1, "the SSN, counted once (path)");
        let all = format!("{:?} {:?}", msg.path, msg.headers);
        assert!(!all.contains("123-45-6789"), "{all}");
        assert_eq!(
            msg.headers
                .iter()
                .filter(|(k, _)| k == "dns_a_record")
                .count(),
            1,
            "the clean answer stays"
        );
        let mut full = dns();
        engine.scan_message_with(&mut full, false);
        assert_eq!(full.headers, dns().headers);
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

        // full mode with redaction off: exported as captured.
        let mut msg = auth();
        let _ = engine.scan_message_with(&mut msg, false);
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
