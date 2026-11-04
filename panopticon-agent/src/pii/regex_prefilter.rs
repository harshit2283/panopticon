#![allow(dead_code)]
//! Regex-based PII prefilter.
//!
//! One `RegexSet` pass over the text finds which of the 16 patterns can
//! match (clean text stops here). Candidates are then validated: checksums
//! (Luhn, Verhoeff, GSTIN, IBAN mod-97), number-plan rules (card IIN, NANP),
//! and, for numbers that are only PII in context (bare 10-digit phones,
//! passport numbers), a keyword just before the value. Overlapping
//! candidates resolve to the longest, so one value yields one finding.
//! Accuracy is measured against `tests/pii/corpus.jsonl` (`pii::accuracy`).

use std::cmp::Reverse;

use regex::{Regex, RegexSet};

use super::{PiiCategory, PiiEntity, PiiSource};

const UPI_HANDLES: &str = "okaxis|oksbi|okhdfcbank|okicici|okbizaxis|ybl|ibl|axl|paytm|upi|apl|yapl|\
    ptyes|ptsbi|pthdfc|ptaxis|icici|hdfcbank|sbi|axisbank|axisb|kotak|fbl|rapl|freecharge|\
    jupiteraxis|slc|abfspay|idfcbank|indus|federal|barodampay|aubank|yesbank|airtel|jio|naviaxis|\
    superyes|kbl|pnb|unionbank|boi|cnrb|ikwik|waicici|wahdfcbank|wasbi|waaxis|timecosmos|\
    tapicici|dbs|hsbc|citi|rbl|equitas|dlb";

/// Patterns in priority order: on two overlapping candidates of equal
/// length, the earlier pattern wins.
fn pattern_defs() -> Vec<(PiiCategory, String)> {
    vec![
        (
            PiiCategory::Jwt,
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+".into(),
        ),
        (PiiCategory::AwsKey, r"(?:AKIA|ASIA)[A-Z0-9]{16}".into()),
        (
            PiiCategory::ApiKey,
            r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\s:="']+[A-Za-z0-9_\-]{20,}"#
                .into(),
        ),
        (
            PiiCategory::Email,
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}".into(),
        ),
        (
            PiiCategory::Upi,
            format!(r"[a-zA-Z0-9][a-zA-Z0-9._-]*@(?:{UPI_HANDLES})\b"),
        ),
        (
            PiiCategory::Gstin,
            r"\b(?:0[1-9]|[12]\d|3[0-8]|97|99)[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]\b".into(),
        ),
        (
            PiiCategory::Iban,
            r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b".into(),
        ),
        // 4th character is the holder type (P person, C company, ...).
        (PiiCategory::Pan, r"\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b".into()),
        (PiiCategory::PassportIn, r"\b[A-PR-WY][1-9]\d{5}[1-9]\b".into()),
        (PiiCategory::CreditCard, r"\b(?:\d[ -]*?){13,19}\b".into()),
        (
            PiiCategory::Aadhaar,
            r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b".into(),
        ),
        (PiiCategory::Ssn, r"\b\d{3}-\d{2}-\d{4}\b".into()),
        (
            PiiCategory::PhoneIn,
            r"(?:\+91[\s-]?|\b0|\b)[6-9]\d{4}[\s-]?\d{5}\b".into(),
        ),
        (
            PiiCategory::PhoneUs,
            r"(?:\+1[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b".into(),
        ),
        (
            PiiCategory::PhoneIntl,
            r"\+[1-9]\d{0,2}(?:[-.\s]?\d{1,5}){1,5}\b".into(),
        ),
        (
            PiiCategory::IpV4,
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b".into(),
        ),
    ]
}

/// Fast regex-based PII scanner (16 patterns).
pub struct RegexPrefilter {
    set: RegexSet,
    patterns: Vec<(PiiCategory, Regex)>,
}

impl Default for RegexPrefilter {
    fn default() -> Self {
        Self::new()
    }
}

impl RegexPrefilter {
    pub fn new() -> Self {
        let defs = pattern_defs();
        let set =
            RegexSet::new(defs.iter().map(|(_, p)| p)).expect("invalid regex in PII pattern set");
        let patterns = defs
            .into_iter()
            .map(|(cat, p)| (cat, Regex::new(&p).expect("invalid regex in PII pattern")))
            .collect();
        Self { set, patterns }
    }

    /// Quick check: can text contain PII? (May be true for candidates that
    /// `scan` then rejects.)
    pub fn has_pii(&self, text: &str) -> bool {
        self.set.is_match(text)
    }

    /// Extract all PII entities from text, ordered by position.
    pub fn scan(&self, text: &str) -> Vec<PiiEntity> {
        let matches = self.set.matches(text);
        if !matches.matched_any() {
            return Vec::new();
        }

        let mut candidates: Vec<(usize, PiiEntity)> = Vec::new();
        for idx in matches.iter() {
            let (category, regex) = &self.patterns[idx];
            for m in regex.find_iter(text) {
                if !validate(*category, text, m.start(), m.end()) {
                    continue;
                }
                candidates.push((
                    idx,
                    PiiEntity {
                        category: *category,
                        source: PiiSource::Regex,
                        start: m.start(),
                        end: m.end(),
                        confidence: 1.0,
                        text: m.as_str().to_string(),
                    },
                ));
            }
        }

        // One finding per value: longest candidate first, then pattern
        // priority; drop anything overlapping a kept one.
        candidates.sort_by_key(|(idx, e)| (Reverse(e.end - e.start), *idx, e.start));
        let mut kept: Vec<PiiEntity> = Vec::with_capacity(candidates.len());
        for (_, e) in candidates {
            if !kept.iter().any(|k| e.start < k.end && k.start < e.end) {
                kept.push(e);
            }
        }
        kept.sort_by_key(|e| e.start);
        kept
    }
}

/// Checks a regex candidate must pass to count as PII.
fn validate(category: PiiCategory, text: &str, start: usize, end: usize) -> bool {
    let m = &text[start..end];
    let digits = || -> Vec<u8> {
        m.bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect()
    };
    match category {
        // Retina assets and the like: logo@2x.png.
        PiiCategory::Email => {
            let tld = m
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            !matches!(
                tld.as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "svg" | "webp" | "ico" | "bmp" | "js" | "css"
            )
        }
        PiiCategory::CreditCard => {
            let d = digits();
            luhn_valid(&d) && card_iin_valid(&d)
        }
        PiiCategory::Aadhaar => {
            let d = digits();
            verhoeff_valid(&d) && !continues_digit_group(text, start, end)
        }
        PiiCategory::Gstin => gstin_valid(m),
        PiiCategory::Iban => {
            let compact: String = m.chars().filter(|c| *c != ' ').collect();
            (15..=34).contains(&compact.len()) && iban_valid(&compact)
        }
        PiiCategory::PassportIn => has_context(text, start, &["passport"]),
        PiiCategory::PhoneIn => m.starts_with("+91") || has_context(text, start, PHONE_WORDS),
        PiiCategory::PhoneUs => {
            let d = digits();
            let d = if m.starts_with("+1") { &d[1..] } else { &d[..] };
            let nanp = d.len() == 10 && d[0] >= 2 && d[3] >= 2;
            let formatted = m.len() > 10;
            nanp && (formatted || has_context(text, start, PHONE_WORDS))
        }
        PiiCategory::PhoneIntl => (8..=15).contains(&digits().len()),
        // Not a run of dotted numbers longer than four (OIDs, versions).
        PiiCategory::IpV4 => {
            let b = text.as_bytes();
            let before = start >= 2 && b[start - 1] == b'.' && b[start - 2].is_ascii_digit();
            let after = end + 1 < b.len() && b[end] == b'.' && b[end + 1].is_ascii_digit();
            !before && !after
        }
        _ => true,
    }
}

/// Words that mark a bare number as a phone number.
const PHONE_WORDS: &[&str] = &[
    "phone", "mobile", "mob", "tel", "msisdn", "contact", "whatsapp", "cell", "sms", "otp",
];

/// How far before a value to look for a context keyword.
const CONTEXT_WINDOW: usize = 32;

/// True if one of `words` appears shortly before `start`, with no digit in
/// between (so the keyword belongs to this value, not an earlier one).
fn has_context(text: &str, start: usize, words: &[&str]) -> bool {
    let window = &text.as_bytes()[start.saturating_sub(CONTEXT_WINDOW)..start];
    let tail = match window.iter().rposition(u8::is_ascii_digit) {
        Some(i) => &window[i + 1..],
        None => window,
    };
    let lower = tail.to_ascii_lowercase();
    words
        .iter()
        .any(|w| lower.windows(w.len()).any(|x| x == w.as_bytes()))
}

/// True if the match is one group of a longer grouped number
/// (`4111 1111 1111 1111` is not an Aadhaar followed by `1111`).
fn continues_digit_group(text: &str, start: usize, end: usize) -> bool {
    let b = text.as_bytes();
    let sep = |c: u8| c == b' ' || c == b'-';
    (start >= 2 && sep(b[start - 1]) && b[start - 2].is_ascii_digit())
        || (end + 1 < b.len() && sep(b[end]) && b[end + 1].is_ascii_digit())
}

/// Luhn checksum (credit cards).
fn luhn_valid(d: &[u8]) -> bool {
    if d.len() < 13 {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            let x = x as u32;
            if i % 2 == 1 {
                if x > 4 { x * 2 - 9 } else { x * 2 }
            } else {
                x
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Issuer prefix and length of a real card scheme (Visa, Mastercard, Amex,
/// Diners, JCB, Discover, RuPay, Maestro).
fn card_iin_valid(d: &[u8]) -> bool {
    let n = d.len();
    let p2 = d[0] as u32 * 10 + d[1] as u32;
    let p4 = p2 * 100 + d[2] as u32 * 10 + d[3] as u32;
    match p2 {
        40..=49 => matches!(n, 13 | 16 | 19),
        51..=55 => n == 16,
        22..=27 => (2221..=2720).contains(&p4) && n == 16,
        34 | 37 => n == 15,
        30 | 36 | 38 | 39 => (14..=19).contains(&n),
        35 => (16..=19).contains(&n),
        50 | 56..=69 | 81 | 82 => (12..=19).contains(&n),
        _ => false,
    }
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff checksum (Aadhaar's last digit).
fn verhoeff_valid(d: &[u8]) -> bool {
    let mut c = 0u8;
    for (i, &x) in d.iter().rev().enumerate() {
        c = VERHOEFF_D[c as usize][VERHOEFF_P[i % 8][x as usize] as usize];
    }
    c == 0
}

/// GSTIN check character (mod 36 over the first 14 characters).
fn gstin_valid(s: &str) -> bool {
    let val = |c: u8| (c as char).to_digit(36);
    let b = s.as_bytes();
    let mut sum = 0;
    for (i, &c) in b[..14].iter().enumerate() {
        let Some(v) = val(c) else { return false };
        let p = v * if i % 2 == 1 { 2 } else { 1 };
        sum += p / 36 + p % 36;
    }
    val(b[14]) == Some((36 - sum % 36) % 36)
}

/// IBAN mod-97 check (ISO 13616).
fn iban_valid(s: &str) -> bool {
    let rotated = s[4..].bytes().chain(s[..4].bytes());
    let mut rem = 0u32;
    for c in rotated {
        let Some(v) = (c as char).to_digit(36) else {
            return false;
        };
        rem = if v < 10 {
            (rem * 10 + v) % 97
        } else {
            (rem * 100 + v) % 97
        };
    }
    rem == 1
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
        let entities = pf.scan("call me at (415) 555-2671");
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
        let entities = pf.scan("aadhaar: 2345 6789 0124");
        assert!(entities.iter().any(|e| e.category == PiiCategory::Aadhaar));
    }

    #[test]
    fn test_pan_detection() {
        let pf = prefilter();
        let entities = pf.scan("PAN: ABCPE1234F");
        assert!(entities.iter().any(|e| e.category == PiiCategory::Pan));
        assert_eq!(
            entities
                .iter()
                .find(|e| e.category == PiiCategory::Pan)
                .unwrap()
                .text,
            "ABCPE1234F"
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

    fn d(s: &str) -> Vec<u8> {
        s.bytes().map(|b| b - b'0').collect()
    }

    #[test]
    fn test_luhn_valid() {
        assert!(luhn_valid(&d("4111111111111111")));
        assert!(luhn_valid(&d("5500000000000004")));
        assert!(luhn_valid(&d("378282246310005"))); // Amex
        assert!(!luhn_valid(&d("4111111111111112")));
        assert!(!luhn_valid(&d("1234567890"))); // too short
    }

    #[test]
    fn test_card_needs_real_issuer_prefix() {
        let pf = prefilter();
        // Luhn-valid 13-digit millisecond epoch: no card scheme starts with 1.
        assert!(luhn_valid(&d("1700000000004")));
        assert!(pf.scan("ts=1700000000004").is_empty());
    }

    #[test]
    fn test_aadhaar_needs_verhoeff_and_stands_alone() {
        let pf = prefilter();
        assert!(verhoeff_valid(&d("234567890124")));
        assert!(pf.scan("uid 2345 6789 0125").is_empty()); // bad check digit
        assert!(pf.scan("uid 1345 6789 0124").is_empty()); // starts with 1
        // First 12 digits of a grouped 16-digit number are not an Aadhaar.
        let e = pf.scan("ref 2345 6789 0124 9999");
        assert!(
            !e.iter().any(|e| e.category == PiiCategory::Aadhaar),
            "{e:?}"
        );
    }

    #[test]
    fn test_pan_holder_type() {
        let pf = prefilter();
        assert!(pf.scan("code ABCDE1234F").is_empty()); // D is no holder type
    }

    #[test]
    fn test_indian_formats() {
        let pf = prefilter();
        let cat = |t: &str| pf.scan(t).iter().map(|e| e.category).collect::<Vec<_>>();
        assert_eq!(cat("gstin 27ABCPE1234F1ZB"), [PiiCategory::Gstin]);
        assert!(cat("gstin 27ABCPE1234F1ZC").is_empty());
        assert_eq!(cat("pay rahul.sharma@okaxis now"), [PiiCategory::Upi]);
        assert_eq!(cat("mail rahul@paytm.com"), [PiiCategory::Email]);
        assert_eq!(
            cat(r#"{"passport_no":"K4823916"}"#),
            [PiiCategory::PassportIn]
        );
        assert!(cat(r#"{"ticket":"K4823916"}"#).is_empty());
        assert_eq!(cat("call +91 98765 43210"), [PiiCategory::PhoneIn]);
        assert_eq!(cat(r#"{"mobile":"9876543210"}"#), [PiiCategory::PhoneIn]);
        assert!(cat(r#"{"order_id":"9876543210"}"#).is_empty());
        // The keyword belongs to the earlier number, not this one.
        assert_eq!(
            cat(r#"{"mobile":"9876543210","id":"8765432109"}"#),
            [PiiCategory::PhoneIn]
        );
    }

    #[test]
    fn test_iban() {
        let pf = prefilter();
        let cat = |t: &str| pf.scan(t).iter().map(|e| e.category).collect::<Vec<_>>();
        assert_eq!(cat("iban GB82WEST12345698765432"), [PiiCategory::Iban]);
        assert_eq!(cat("iban GB82 WEST 1234 5698 7654 32"), [PiiCategory::Iban]);
        assert!(cat("iban GB83WEST12345698765432").is_empty());
    }

    #[test]
    fn test_hard_negatives() {
        let pf = prefilter();
        for t in [
            "oid 1.3.6.1.4.1.311.21",
            "img logo@2x.png",
            "ts 1700000000",
            "id 550e8400-e29b-41d4-a716-446655440000",
        ] {
            assert!(pf.scan(t).is_empty(), "{t}: {:?}", pf.scan(t));
        }
    }

    #[test]
    fn test_one_finding_per_value() {
        let pf = prefilter();
        // A GSTIN embeds a PAN; a spaced card contains Aadhaar-shaped groups.
        assert_eq!(pf.scan("27ABCPE1234F1ZB").len(), 1);
        assert_eq!(pf.scan("card 4111 1111 1111 1111").len(), 1);
    }
}
