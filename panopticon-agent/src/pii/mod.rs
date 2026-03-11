#![allow(dead_code)]
//! PII detection pipeline: regex prefilter -> optional ML inference -> redaction.

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

#[cfg(feature = "ml")]
use self::inference::OnnxInference;

/// PII entity categories detected by regex or ML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PiiCategory {
    Email,
    PhoneUs,
    PhoneIntl,
    Ssn,
    CreditCard,
    IpV4,
    Jwt,
    ApiKey,
    AwsKey,
    Aadhaar,
    Pan,
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
            PiiCategory::PhoneIntl => write!(f, "PHONE_INTL"),
            PiiCategory::Ssn => write!(f, "SSN"),
            PiiCategory::CreditCard => write!(f, "CREDIT_CARD"),
            PiiCategory::IpV4 => write!(f, "IP_V4"),
            PiiCategory::Jwt => write!(f, "JWT"),
            PiiCategory::ApiKey => write!(f, "API_KEY"),
            PiiCategory::AwsKey => write!(f, "AWS_KEY"),
            PiiCategory::Aadhaar => write!(f, "AADHAAR"),
            PiiCategory::Pan => write!(f, "PAN"),
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
}

impl Drop for PiiReport {
    fn drop(&mut self) {
        if let Some(ref mut text) = self.redacted_text {
            text.zeroize();
        }
    }
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

    /// Scan text for PII. Returns None if PII detection is disabled or no PII found.
    pub fn scan(&self, text: &str) -> Option<PiiReport> {
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

        let redacted_text = if self.config.redact {
            Some(redact(text, &entities))
        } else {
            None
        };

        Some(PiiReport {
            scanned_bytes: text.len(),
            entities,
            redacted_text,
        })
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
