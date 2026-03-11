#![allow(dead_code)]
//! Regex-based PII prefilter using RegexSet for O(1) multi-pattern matching.
//!
//! Scans text against 11 patterns (email, phone, SSN, credit card, JWT, etc.)
//! in a single pass via RegexSet, then uses individual Regex for extraction.
//! Expected throughput: ~1us per payload for the quick-reject path.

use regex::{Regex, RegexSet};

use super::{PiiCategory, PiiEntity, PiiSource};

/// Fast regex-based PII scanner with 11 pattern categories.
pub struct RegexPrefilter {
    set: RegexSet,
    patterns: Vec<(PiiCategory, Regex)>,
}

impl RegexPrefilter {
    pub fn new() -> Self {
        let pattern_defs: Vec<(PiiCategory, &str)> = vec![
            (
                PiiCategory::Email,
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            ),
            (
                PiiCategory::PhoneUs,
                r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            ),
            (
                PiiCategory::PhoneIntl,
                r"\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}",
            ),
            (PiiCategory::Ssn, r"\b\d{3}-\d{2}-\d{4}\b"),
            (PiiCategory::CreditCard, r"\b(?:\d[ -]*?){13,19}\b"),
            (
                PiiCategory::IpV4,
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            ),
            (
                PiiCategory::Jwt,
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            ),
            (
                PiiCategory::ApiKey,
                r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\s:="']+[A-Za-z0-9_\-]{20,}"#,
            ),
            (PiiCategory::AwsKey, r"(?:AKIA|ASIA)[A-Z0-9]{16}"),
            (PiiCategory::Aadhaar, r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),
            (PiiCategory::Pan, r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        ];

        let raw_patterns: Vec<&str> = pattern_defs.iter().map(|(_, p)| *p).collect();
        let set = RegexSet::new(&raw_patterns).expect("invalid regex in PII pattern set");

        let patterns: Vec<(PiiCategory, Regex)> = pattern_defs
            .into_iter()
            .map(|(cat, p)| (cat, Regex::new(p).expect("invalid regex in PII pattern")))
            .collect();

        Self { set, patterns }
    }

    /// Quick check: does text contain any PII pattern?
    pub fn has_pii(&self, text: &str) -> bool {
        self.set.is_match(text)
    }

    /// Extract all PII entities from text.
    pub fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let matches: Vec<usize> = self.set.matches(text).into_iter().collect();
        if matches.is_empty() {
            return Vec::new();
        }

        let mut entities = Vec::new();
        for idx in matches {
            let (category, regex) = &self.patterns[idx];
            for m in regex.find_iter(text) {
                // For credit cards, validate with Luhn algorithm
                if *category == PiiCategory::CreditCard {
                    let digits: String =
                        m.as_str().chars().filter(|c| c.is_ascii_digit()).collect();
                    if !luhn_check(&digits) {
                        continue;
                    }
                }
                entities.push(PiiEntity {
                    category: *category,
                    source: PiiSource::Regex,
                    start: m.start(),
                    end: m.end(),
                    confidence: 1.0,
                    text: m.as_str().to_string(),
                });
            }
        }
        entities
    }
}

/// Luhn algorithm for credit card number validation.
fn luhn_check(digits: &str) -> bool {
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for ch in digits.chars().rev() {
        let mut d = ch.to_digit(10).unwrap_or(0);
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefilter() -> RegexPrefilter {
        RegexPrefilter::new()
    }

    #[test]
    fn test_email_detection() {
        let pf = prefilter();
        let entities = pf.scan("send to alice@example.com please");
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].category, PiiCategory::Email);
        assert_eq!(entities[0].text, "alice@example.com");
    }

    #[test]
    fn test_phone_us_detection() {
        let pf = prefilter();
        let entities = pf.scan("call me at (555) 123-4567");
        assert!(entities.iter().any(|e| e.category == PiiCategory::PhoneUs));
    }

    #[test]
    fn test_phone_intl_detection() {
        let pf = prefilter();
        let entities = pf.scan("reach me at +44 20 7946 0958");
        assert!(
            entities
                .iter()
                .any(|e| e.category == PiiCategory::PhoneIntl)
        );
    }

    #[test]
    fn test_ssn_detection() {
        let pf = prefilter();
        let entities = pf.scan("my ssn is 123-45-6789");
        assert!(entities.iter().any(|e| e.category == PiiCategory::Ssn));
        assert_eq!(
            entities
                .iter()
                .find(|e| e.category == PiiCategory::Ssn)
                .unwrap()
                .text,
            "123-45-6789"
        );
    }

    #[test]
    fn test_credit_card_valid_luhn() {
        let pf = prefilter();
        // 4111111111111111 is a well-known Luhn-valid test number
        let entities = pf.scan("card: 4111111111111111");
        assert!(
            entities
                .iter()
                .any(|e| e.category == PiiCategory::CreditCard)
        );
    }

    #[test]
    fn test_credit_card_invalid_luhn() {
        let pf = prefilter();
        // 4111111111111112 fails Luhn check
        let entities = pf.scan("card: 4111111111111112");
        assert!(
            !entities
                .iter()
                .any(|e| e.category == PiiCategory::CreditCard)
        );
    }

    #[test]
    fn test_ipv4_detection() {
        let pf = prefilter();
        let entities = pf.scan("server at 192.168.1.100");
        assert!(entities.iter().any(|e| e.category == PiiCategory::IpV4));
        assert_eq!(
            entities
                .iter()
                .find(|e| e.category == PiiCategory::IpV4)
                .unwrap()
                .text,
            "192.168.1.100"
        );
    }

    #[test]
    fn test_jwt_detection() {
        let pf = prefilter();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123_XYZ-def";
        let text = format!("Authorization: Bearer {}", jwt);
        let entities = pf.scan(&text);
        assert!(entities.iter().any(|e| e.category == PiiCategory::Jwt));
    }

    #[test]
    fn test_api_key_detection() {
        let pf = prefilter();
        let entities = pf.scan("api_key: abcdefghij1234567890klmnop");
        assert!(entities.iter().any(|e| e.category == PiiCategory::ApiKey));
    }

    #[test]
    fn test_aws_key_detection() {
        let pf = prefilter();
        let entities = pf.scan("credentials: AKIAIOSFODNN7EXAMPLE");
        assert!(entities.iter().any(|e| e.category == PiiCategory::AwsKey));
    }

    #[test]
    fn test_aadhaar_detection() {
        let pf = prefilter();
        let entities = pf.scan("aadhaar: 1234 5678 9012");
        assert!(entities.iter().any(|e| e.category == PiiCategory::Aadhaar));
    }

    #[test]
    fn test_pan_detection() {
        let pf = prefilter();
        let entities = pf.scan("PAN: ABCDE1234F");
        assert!(entities.iter().any(|e| e.category == PiiCategory::Pan));
        assert_eq!(
            entities
                .iter()
                .find(|e| e.category == PiiCategory::Pan)
                .unwrap()
                .text,
            "ABCDE1234F"
        );
    }

    #[test]
    fn test_no_false_positives_on_random_text() {
        let pf = prefilter();
        let entities = pf.scan("the quick brown fox jumps over the lazy dog");
        // Should not detect any PII in plain English
        assert!(
            entities.is_empty(),
            "unexpected PII in plain text: {:?}",
            entities
        );
    }

    #[test]
    fn test_multiple_patterns_in_one_text() {
        let pf = prefilter();
        let entities = pf.scan("email: alice@test.com, ssn: 123-45-6789");
        let categories: Vec<PiiCategory> = entities.iter().map(|e| e.category).collect();
        assert!(categories.contains(&PiiCategory::Email));
        assert!(categories.contains(&PiiCategory::Ssn));
    }

    #[test]
    fn test_has_pii_quick_check() {
        let pf = prefilter();
        assert!(pf.has_pii("user@example.com"));
        assert!(!pf.has_pii("no sensitive data"));
    }

    #[test]
    fn test_luhn_check_valid() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5500000000000004"));
        assert!(luhn_check("378282246310005")); // Amex
    }

    #[test]
    fn test_luhn_check_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890")); // too short
        assert!(!luhn_check("1234567890123"));
    }
}
