#![allow(dead_code)]
//! External PII service client for offloading detection to HTTP endpoint.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{PiiCategory, PiiEntity, PiiSource};

/// Client for calling external PII detection service.
pub struct ExternalPiiClient {
    url: String,
    timeout_ms: u32,
    sample_rate: f64,
    client: reqwest::Client,
}

/// Request body sent to external PII service.
#[derive(Debug, Serialize)]
pub struct PiiServiceRequest {
    pub text: String,
    pub template_hash: Option<u64>,
}

/// Response from external PII service.
#[derive(Debug, Deserialize)]
pub struct PiiServiceResponse {
    pub entities: Vec<PiiServiceEntity>,
}

/// Single entity from external service response.
#[derive(Debug, Deserialize)]
pub struct PiiServiceEntity {
    pub category: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
    #[serde(default)]
    pub text: Option<String>,
}

impl ExternalPiiClient {
    pub fn new(url: String, timeout_ms: u32, sample_rate: f64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(timeout_ms as u64))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            url,
            timeout_ms,
            sample_rate,
            client,
        }
    }

    /// Check if this payload should be sampled based on hash.
    /// Uses deterministic hash-based sampling for reproducibility.
    pub fn should_sample(&self, text: &str) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        let hash = crate::pii::sampler::template_hash(text);
        let threshold = (self.sample_rate * u64::MAX as f64) as u64;
        hash < threshold
    }

    /// Scan text via external HTTP service.
    /// Returns None on error or if not sampled.
    pub async fn scan(&self, text: &str, template_hash: Option<u64>) -> Option<Vec<PiiEntity>> {
        if !self.should_sample(text) {
            return None;
        }

        let request = PiiServiceRequest {
            text: text.to_string(),
            template_hash,
        };

        let response = match self.client.post(&self.url).json(&request).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("External PII service request failed: {}", e);
                return None;
            }
        };

        if !response.status().is_success() {
            warn!("External PII service returned status {}", response.status());
            return None;
        }

        let pii_response: PiiServiceResponse = match response.json().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to parse external PII response: {}", e);
                return None;
            }
        };

        let entities: Vec<PiiEntity> = pii_response
            .entities
            .into_iter()
            .filter_map(|e| {
                let category = parse_category(&e.category)?;
                if e.start >= e.end
                    || e.end > text.len()
                    || !text.is_char_boundary(e.start)
                    || !text.is_char_boundary(e.end)
                {
                    warn!(
                        start = e.start,
                        end = e.end,
                        text_len = text.len(),
                        "Dropping malformed external PII span"
                    );
                    return None;
                }
                Some(PiiEntity {
                    category,
                    source: PiiSource::External,
                    start: e.start,
                    end: e.end,
                    confidence: e.confidence,
                    text: e.text.unwrap_or_else(|| text[e.start..e.end].to_string()),
                })
            })
            .collect();

        if entities.is_empty() {
            None
        } else {
            debug!("External PII service found {} entities", entities.len());
            Some(entities)
        }
    }
}

fn parse_category(s: &str) -> Option<PiiCategory> {
    match s.to_uppercase().as_str() {
        "EMAIL" => Some(PiiCategory::Email),
        "PHONE_US" | "PHONEUS" => Some(PiiCategory::PhoneUs),
        "PHONE_INTL" | "PHONEINTL" => Some(PiiCategory::PhoneIntl),
        "SSN" => Some(PiiCategory::Ssn),
        "CREDIT_CARD" | "CREDITCARD" => Some(PiiCategory::CreditCard),
        "IP_V4" | "IPV4" => Some(PiiCategory::IpV4),
        "JWT" => Some(PiiCategory::Jwt),
        "API_KEY" | "APIKEY" => Some(PiiCategory::ApiKey),
        "AWS_KEY" | "AWSKEY" => Some(PiiCategory::AwsKey),
        "AADHAAR" => Some(PiiCategory::Aadhaar),
        "PAN" => Some(PiiCategory::Pan),
        "PERSON_NAME" | "PERSONNAME" => Some(PiiCategory::PersonName),
        "LOCATION" => Some(PiiCategory::Location),
        "ORGANIZATION" => Some(PiiCategory::Organization),
        "DATE_OF_BIRTH" | "DATEOFBIRTH" | "DOB" => Some(PiiCategory::DateOfBirth),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_sample_always() {
        let client = ExternalPiiClient::new("http://localhost".to_string(), 5000, 1.0);
        assert!(client.should_sample("any text"));
        assert!(client.should_sample("another text"));
    }

    #[test]
    fn test_should_sample_never() {
        let client = ExternalPiiClient::new("http://localhost".to_string(), 5000, 0.0);
        assert!(!client.should_sample("any text"));
        assert!(!client.should_sample("another text"));
    }

    #[test]
    fn test_should_sample_deterministic() {
        let client = ExternalPiiClient::new("http://localhost".to_string(), 5000, 0.5);
        let text = "test payload";
        let first = client.should_sample(text);
        let second = client.should_sample(text);
        assert_eq!(first, second);
    }

    #[test]
    fn test_parse_category() {
        assert_eq!(parse_category("EMAIL"), Some(PiiCategory::Email));
        assert_eq!(parse_category("email"), Some(PiiCategory::Email));
        assert_eq!(parse_category("SSN"), Some(PiiCategory::Ssn));
        assert_eq!(parse_category("CREDIT_CARD"), Some(PiiCategory::CreditCard));
        assert_eq!(parse_category("unknown"), None);
    }

    #[test]
    fn test_client_creation() {
        let client =
            ExternalPiiClient::new("http://pii.example.com/detect".to_string(), 3000, 0.01);
        assert_eq!(client.url, "http://pii.example.com/detect");
        assert_eq!(client.timeout_ms, 3000);
        assert!((client.sample_rate - 0.01).abs() < f64::EPSILON);
    }
}
