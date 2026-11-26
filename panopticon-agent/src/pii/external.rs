#![allow(dead_code)]
//! External PII service client for offloading detection to HTTP endpoint.
//!
//! The payload text it sends is captured data, so the client belongs to
//! one capture pipeline and its connections are made by `GatedConnector`:
//! every socket write (TLS records included, TLS sits above the gate) goes
//! through the pipeline's gate, and nothing is sent once it is revoked
//! (Revision 1 item 6).

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{PiiCategory, PiiEntity, PiiSource};
use crate::io_gate::{DispatchExecutor, GatedConnector, IoGate};

/// Client for calling external PII detection service.
pub struct ExternalPiiClient {
    url: String,
    timeout_ms: u32,
    sample_rate: f64,
    client: Client<GatedConnector, Full<bytes::Bytes>>,
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
    /// A client whose connections write through `gate`; its connection
    /// tasks log through `dispatch`.
    pub fn new(
        url: String,
        timeout_ms: u32,
        sample_rate: f64,
        gate: Arc<IoGate>,
        dispatch: tracing::Dispatch,
    ) -> Self {
        let client = Client::builder(DispatchExecutor(dispatch))
            .pool_max_idle_per_host(4)
            .build(GatedConnector::with_tls(gate));
        Self {
            url,
            timeout_ms,
            sample_rate,
            client,
        }
    }

    /// POST `body` as JSON and read the whole response, within the timeout.
    async fn post(&self, body: Vec<u8>) -> Result<(http::StatusCode, bytes::Bytes), String> {
        let request = http::Request::post(self.url.as_str())
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(|e| e.to_string())?;
        let exchange = async {
            let response = self
                .client
                .request(request)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status();
            let body = response
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?
                .to_bytes();
            Ok((status, body))
        };
        tokio::time::timeout(Duration::from_millis(self.timeout_ms as u64), exchange)
            .await
            .map_err(|_| "timed out".to_string())?
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

        let body = serde_json::to_vec(&request).ok()?;
        let (status, response) = match self.post(body).await {
            Ok(r) => r,
            Err(e) => {
                warn!("External PII service request failed: {}", e);
                return None;
            }
        };

        if !status.is_success() {
            warn!("External PII service returned status {}", status);
            return None;
        }

        let pii_response: PiiServiceResponse = match serde_json::from_slice(&response) {
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
        "PHONE_IN" | "PHONEIN" => Some(PiiCategory::PhoneIn),
        "PHONE_INTL" | "PHONEINTL" => Some(PiiCategory::PhoneIntl),
        "SSN" => Some(PiiCategory::Ssn),
        "CREDIT_CARD" | "CREDITCARD" => Some(PiiCategory::CreditCard),
        "IP_V4" | "IPV4" => Some(PiiCategory::IpV4),
        "JWT" => Some(PiiCategory::Jwt),
        "API_KEY" | "APIKEY" => Some(PiiCategory::ApiKey),
        "AWS_KEY" | "AWSKEY" => Some(PiiCategory::AwsKey),
        "AADHAAR" => Some(PiiCategory::Aadhaar),
        "PAN" => Some(PiiCategory::Pan),
        "UPI" | "VPA" => Some(PiiCategory::Upi),
        "GSTIN" => Some(PiiCategory::Gstin),
        "PASSPORT_IN" | "PASSPORTIN" => Some(PiiCategory::PassportIn),
        "IBAN" => Some(PiiCategory::Iban),
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

    impl ExternalPiiClient {
        fn open(url: String, timeout_ms: u32, sample_rate: f64) -> Self {
            Self::new(
                url,
                timeout_ms,
                sample_rate,
                IoGate::new(),
                tracing::Dispatch::default(),
            )
        }
    }

    /// One fake service; every request on one kept-alive client.
    #[tokio::test]
    async fn requests_go_through_the_gate_and_stop_at_revocation() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let s = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let s = Arc::clone(&s);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = conn.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        s.lock().unwrap().extend_from_slice(&buf[..n]);
                        let body = br#"{"entities":[{"category":"EMAIL","start":0,"end":5,"confidence":0.9}]}"#;
                        let head =
                            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
                        let _ = conn.write_all(head.as_bytes()).await;
                        let _ = conn.write_all(body).await;
                    }
                });
            }
        });
        let gate = IoGate::new();
        let client = ExternalPiiClient::new(
            format!("http://{addr}/detect"),
            2000,
            1.0,
            Arc::clone(&gate),
            tracing::Dispatch::default(),
        );
        let found = client.scan("alice-before", None).await.unwrap();
        assert_eq!(found[0].category, PiiCategory::Email);
        gate.revoke();
        assert!(client.scan("bobby-after", None).await.is_none());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let seen = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert!(seen.contains("alice-before"), "{seen}");
        assert!(!seen.contains("bobby-after"), "{seen}");
    }

    #[test]
    fn test_should_sample_always() {
        let client = ExternalPiiClient::open("http://localhost".to_string(), 5000, 1.0);
        assert!(client.should_sample("any text"));
        assert!(client.should_sample("another text"));
    }

    #[test]
    fn test_should_sample_never() {
        let client = ExternalPiiClient::open("http://localhost".to_string(), 5000, 0.0);
        assert!(!client.should_sample("any text"));
        assert!(!client.should_sample("another text"));
    }

    #[test]
    fn test_should_sample_deterministic() {
        let client = ExternalPiiClient::open("http://localhost".to_string(), 5000, 0.5);
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
            ExternalPiiClient::open("http://pii.example.com/detect".to_string(), 3000, 0.01);
        assert_eq!(client.url, "http://pii.example.com/detect");
        assert_eq!(client.timeout_ms, 3000);
        assert!((client.sample_rate - 0.01).abs() < f64::EPSILON);
    }
}
