#![allow(dead_code)]
//! Inference budget sampler with template deduplication.
//!
//! Prevents redundant ML invocations by normalizing payloads to templates
//! (replacing literals with `?`) and tracking seen templates. Enforces a
//! per-second budget via atomic counter.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use fxhash::FxHasher;

/// Budget-based sampler that deduplicates by payload template.
pub struct InferenceSampler {
    budget: AtomicU32,
    max_budget: u32,
    seen_templates: Mutex<HashSet<u64>>,
}

impl InferenceSampler {
    pub fn new(max_per_sec: u32) -> Self {
        Self {
            budget: AtomicU32::new(max_per_sec),
            max_budget: max_per_sec,
            seen_templates: Mutex::new(HashSet::new()),
        }
    }

    /// Check if we should invoke ML inference for this text.
    /// Deduplicates by template hash and enforces budget.
    pub fn should_invoke(&self, text: &str) -> bool {
        let tmpl = normalize_template(text);
        let hash = template_hash(&tmpl);

        let mut seen = self.seen_templates.lock().unwrap();
        if seen.contains(&hash) {
            return false; // Already seen this template
        }

        // Try to consume budget
        loop {
            let current = self.budget.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self
                .budget
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                seen.insert(hash);
                return true;
            }
        }
    }

    /// Refill budget (called every 1s from event loop).
    pub fn refill(&self) {
        self.budget.store(self.max_budget, Ordering::Relaxed);
        // Clear seen templates periodically to allow re-scanning
        let mut seen = self.seen_templates.lock().unwrap();
        seen.clear();
    }
}

/// Normalize text to a template for dedup:
/// - Replace quoted strings with `?`
/// - Replace numbers with `?`
/// - Collapse whitespace
pub fn normalize_template(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' | '\'' => {
                result.push('?');
                // Skip until closing quote
                for inner in chars.by_ref() {
                    if inner == ch {
                        break;
                    }
                }
            }
            '0'..='9' => {
                result.push('?');
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                {
                    chars.next();
                }
            }
            _ => result.push(ch),
        }
    }
    result
}

/// Hash a template string using FxHasher for fast, non-cryptographic hashing.
pub fn template_hash(text: &str) -> u64 {
    let mut hasher = FxHasher::default();
    text.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_allows_within_limit() {
        let sampler = InferenceSampler::new(3);
        assert!(sampler.should_invoke("text A"));
        assert!(sampler.should_invoke("text B"));
        assert!(sampler.should_invoke("text C"));
    }

    #[test]
    fn test_budget_exhaustion() {
        let sampler = InferenceSampler::new(2);
        assert!(sampler.should_invoke("text A"));
        assert!(sampler.should_invoke("text B"));
        // Budget exhausted
        assert!(!sampler.should_invoke("text C"));
    }

    #[test]
    fn test_dedup_same_template() {
        let sampler = InferenceSampler::new(100);
        // These normalize to the same template (numbers replaced with ?)
        assert!(sampler.should_invoke("user_id=123"));
        assert!(!sampler.should_invoke("user_id=456"));
    }

    #[test]
    fn test_dedup_different_templates() {
        let sampler = InferenceSampler::new(100);
        assert!(sampler.should_invoke("GET /users/123"));
        assert!(sampler.should_invoke("POST /orders/456"));
    }

    #[test]
    fn test_refill_resets_budget_and_seen() {
        let sampler = InferenceSampler::new(1);
        assert!(sampler.should_invoke("text A"));
        assert!(!sampler.should_invoke("text B")); // budget exhausted

        sampler.refill();

        // After refill, budget is restored and seen templates cleared
        assert!(sampler.should_invoke("text A")); // same template now allowed again
    }

    #[test]
    fn test_normalize_replaces_numbers() {
        assert_eq!(normalize_template("id=12345"), "id=?");
        // "1.2.3" is consumed as a single number token (digits + dots)
        assert_eq!(normalize_template("v1.2.3"), "v?");
    }

    #[test]
    fn test_normalize_replaces_quoted_strings() {
        assert_eq!(normalize_template(r#"name="John""#), "name=?");
        assert_eq!(normalize_template("key='secret'"), "key=?");
    }

    #[test]
    fn test_normalize_mixed() {
        let input = r#"SELECT * FROM users WHERE id=42 AND name="Alice""#;
        let result = normalize_template(input);
        assert_eq!(result, "SELECT * FROM users WHERE id=? AND name=?");
    }
}
