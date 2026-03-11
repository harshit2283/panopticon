//! Benchmark for `RegexPrefilter::scan()` on various payload types.
//!
//! Measures:
//! - Clean payload (no PII) -- fast rejection path
//! - Payload with single email
//! - Payload with mixed PII (email + SSN + credit card)
//! - Large 4KB payload with PII scattered throughout

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use regex::{Regex, RegexSet};

/// PII categories (matching the agent's PiiCategory enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PiiCategory {
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
}

/// Regex prefilter matching the agent's implementation.
struct RegexPrefilter {
    set: RegexSet,
    patterns: Vec<(PiiCategory, Regex)>,
}

impl RegexPrefilter {
    fn new() -> Self {
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

    fn has_pii(&self, text: &str) -> bool {
        self.set.is_match(text)
    }

    fn scan(&self, text: &str) -> Vec<(PiiCategory, String)> {
        let matches: Vec<usize> = self.set.matches(text).into_iter().collect();
        if matches.is_empty() {
            return Vec::new();
        }

        let mut entities = Vec::new();
        for idx in matches {
            let (category, regex) = &self.patterns[idx];
            for m in regex.find_iter(text) {
                entities.push((*category, m.as_str().to_string()));
            }
        }
        entities
    }
}

fn bench_pii_regex(c: &mut Criterion) {
    let prefilter = RegexPrefilter::new();
    let mut group = c.benchmark_group("pii_regex");

    // 1. Clean payload (no PII) -- fast rejection path
    let clean_payload = "The quick brown fox jumps over the lazy dog. \
        This is a normal HTTP response body with no sensitive data. \
        Status: 200 OK. Content-Type: application/json. \
        {\"status\":\"healthy\",\"uptime\":\"42h\",\"version\":\"1.2.3\"}";

    group.bench_function("clean_payload_has_pii", |b| {
        b.iter(|| prefilter.has_pii(black_box(clean_payload)))
    });

    group.bench_function("clean_payload_scan", |b| {
        b.iter(|| prefilter.scan(black_box(clean_payload)))
    });

    // 2. Payload with single email
    let email_payload = "User profile: {\"name\": \"Alice Johnson\", \
        \"email\": \"alice.johnson@example.com\", \"role\": \"admin\"}";

    group.bench_function("email_payload_has_pii", |b| {
        b.iter(|| prefilter.has_pii(black_box(email_payload)))
    });

    group.bench_function("email_payload_scan", |b| {
        b.iter(|| prefilter.scan(black_box(email_payload)))
    });

    // 3. Mixed PII payload (email + SSN + credit card)
    let mixed_pii_payload = "Customer record: \
        email=john.doe@company.org, \
        ssn=123-45-6789, \
        card=4111111111111111, \
        phone=(555) 123-4567, \
        ip=192.168.1.100";

    group.bench_function("mixed_pii_has_pii", |b| {
        b.iter(|| prefilter.has_pii(black_box(mixed_pii_payload)))
    });

    group.bench_function("mixed_pii_scan", |b| {
        b.iter(|| prefilter.scan(black_box(mixed_pii_payload)))
    });

    // 4. Large 4KB payload with PII scattered throughout
    let mut large_payload = String::with_capacity(4096);
    for i in 0..20 {
        large_payload.push_str(&format!(
            "Record {}: name=User{}, department=Engineering, location=Building-{}, \
             status=active, created=2024-01-{:02}, updated=2024-06-{:02}. ",
            i,
            i,
            i % 5,
            (i % 28) + 1,
            (i % 28) + 1,
        ));
    }
    // Scatter some PII
    large_payload.push_str("contact: admin@internal.example.com, ");
    large_payload.push_str("backup-ssn: 987-65-4321, ");
    large_payload
        .push_str("token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123XYZdef456, ");
    // Pad to ~4KB
    while large_payload.len() < 4096 {
        large_payload.push_str("padding data to reach 4KB target size. ");
    }
    large_payload.truncate(4096);

    group.bench_function("large_4kb_has_pii", |b| {
        b.iter(|| prefilter.has_pii(black_box(&large_payload)))
    });

    group.bench_function("large_4kb_scan", |b| {
        b.iter(|| prefilter.scan(black_box(&large_payload)))
    });

    // 5. Large 4KB clean payload (no PII)
    let mut large_clean = String::with_capacity(4096);
    while large_clean.len() < 4096 {
        large_clean.push_str(
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
             Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ",
        );
    }
    large_clean.truncate(4096);

    group.bench_function("large_4kb_clean_has_pii", |b| {
        b.iter(|| prefilter.has_pii(black_box(&large_clean)))
    });

    group.bench_function("large_4kb_clean_scan", |b| {
        b.iter(|| prefilter.scan(black_box(&large_clean)))
    });

    group.finish();
}

criterion_group!(benches, bench_pii_regex);
criterion_main!(benches);
