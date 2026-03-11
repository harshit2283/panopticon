#![allow(dead_code)]
//! Redaction: replace PII entity text spans with category placeholders like `<EMAIL>`.
//!
//! Handles overlapping spans by sorting and skipping overlaps (earlier span wins).

use super::PiiEntity;

/// Redact text by replacing entity spans with `<CATEGORY>` placeholders.
/// Handles overlapping spans by merging them (earlier span wins).
pub fn redact(text: &str, entities: &[PiiEntity]) -> String {
    if entities.is_empty() {
        return text.to_string();
    }

    // Sort by start position, then by end (longest first for overlaps)
    let mut sorted: Vec<&PiiEntity> = entities.iter().collect();
    sorted.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut result = String::with_capacity(text.len());
    let mut pos = 0;

    for entity in &sorted {
        if entity.start < pos {
            // Overlapping with previous -- skip
            continue;
        }
        // Append text before this entity
        if entity.start > pos {
            result.push_str(&text[pos..entity.start]);
        }
        // Append placeholder
        result.push('<');
        result.push_str(&entity.category.to_string());
        result.push('>');
        pos = entity.end;
    }

    // Append remaining text
    if pos < text.len() {
        result.push_str(&text[pos..]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::{PiiCategory, PiiSource};

    fn make_entity(category: PiiCategory, start: usize, end: usize, text: &str) -> PiiEntity {
        PiiEntity {
            category,
            source: PiiSource::Regex,
            start,
            end,
            confidence: 1.0,
            text: text.to_string(),
        }
    }

    #[test]
    fn test_basic_redaction() {
        let text = "email is alice@test.com ok";
        let entities = vec![make_entity(PiiCategory::Email, 9, 23, "alice@test.com")];
        let result = redact(text, &entities);
        assert_eq!(result, "email is <EMAIL> ok");
    }

    #[test]
    fn test_multiple_entities() {
        let text = "email: a@b.com ssn: 123-45-6789";
        let entities = vec![
            make_entity(PiiCategory::Email, 7, 14, "a@b.com"),
            make_entity(PiiCategory::Ssn, 20, 31, "123-45-6789"),
        ];
        let result = redact(text, &entities);
        assert_eq!(result, "email: <EMAIL> ssn: <SSN>");
    }

    #[test]
    fn test_overlapping_spans() {
        let text = "data: 123-45-6789-extra";
        // Two overlapping entities sorted by start then longest first --
        // the longer span (PhoneUs 6..23) sorts before the shorter (Ssn 6..17),
        // so PhoneUs wins.
        let entities = vec![
            make_entity(PiiCategory::Ssn, 6, 17, "123-45-6789"),
            make_entity(PiiCategory::PhoneUs, 6, 23, "123-45-6789-extra"),
        ];
        let result = redact(text, &entities);
        assert_eq!(result, "data: <PHONE_US>");
    }

    #[test]
    fn test_empty_entities() {
        let text = "nothing to redact";
        let result = redact(text, &[]);
        assert_eq!(result, text);
    }

    #[test]
    fn test_entity_at_start_and_end() {
        let text = "alice@test.com is an email";
        let entities = vec![make_entity(PiiCategory::Email, 0, 14, "alice@test.com")];
        let result = redact(text, &entities);
        assert_eq!(result, "<EMAIL> is an email");

        let text2 = "send to alice@test.com";
        let entities2 = vec![make_entity(PiiCategory::Email, 8, 22, "alice@test.com")];
        let result2 = redact(text2, &entities2);
        assert_eq!(result2, "send to <EMAIL>");
    }

    #[test]
    fn test_adjacent_entities() {
        let text = "ABCDE1234Falice@x.com";
        let entities = vec![
            make_entity(PiiCategory::Pan, 0, 10, "ABCDE1234F"),
            make_entity(PiiCategory::Email, 10, 21, "alice@x.com"),
        ];
        let result = redact(text, &entities);
        assert_eq!(result, "<PAN><EMAIL>");
    }
}
