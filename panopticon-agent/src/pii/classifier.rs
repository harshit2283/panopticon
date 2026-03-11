#![allow(dead_code)]
//! BIO (Beginning-Inside-Outside) NER label decoder.
//!
//! Converts ML model output (per-token BIO labels) into entity spans.
//! Used by the inference pipeline to group token-level predictions into
//! contiguous named entity spans with confidence scores.

use serde::Serialize;

use super::PiiCategory;

/// NER labels from the DistilBERT-NER model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum NerLabel {
    Outside,
    BPerson,
    IPerson,
    BLocation,
    ILocation,
    BOrganization,
    IOrganization,
    BMisc,
    IMisc,
}

impl NerLabel {
    /// Parse from model output label string.
    pub fn from_label_str(s: &str) -> Self {
        match s {
            "O" => NerLabel::Outside,
            "B-PER" => NerLabel::BPerson,
            "I-PER" => NerLabel::IPerson,
            "B-LOC" => NerLabel::BLocation,
            "I-LOC" => NerLabel::ILocation,
            "B-ORG" => NerLabel::BOrganization,
            "I-ORG" => NerLabel::IOrganization,
            "B-MISC" => NerLabel::BMisc,
            "I-MISC" => NerLabel::IMisc,
            _ => NerLabel::Outside,
        }
    }

    /// Convert to PiiCategory.
    pub fn to_category(self) -> Option<PiiCategory> {
        match self {
            NerLabel::BPerson | NerLabel::IPerson => Some(PiiCategory::PersonName),
            NerLabel::BLocation | NerLabel::ILocation => Some(PiiCategory::Location),
            NerLabel::BOrganization | NerLabel::IOrganization => Some(PiiCategory::Organization),
            _ => None,
        }
    }

    /// Is this a B- (beginning) tag?
    pub fn is_begin(self) -> bool {
        matches!(
            self,
            NerLabel::BPerson | NerLabel::BLocation | NerLabel::BOrganization | NerLabel::BMisc
        )
    }

    /// Is this an I- (inside) continuation?
    pub fn is_inside(self) -> bool {
        matches!(
            self,
            NerLabel::IPerson | NerLabel::ILocation | NerLabel::IOrganization | NerLabel::IMisc
        )
    }
}

/// A decoded NER span.
#[derive(Debug, Clone)]
pub struct NerSpan {
    pub label: NerLabel,
    pub token_start: usize,
    pub token_end: usize,
    pub confidence: f32,
}

/// Decode BIO-tagged token sequence into entity spans.
/// Groups consecutive B-I sequences of the same entity type.
pub fn decode_bio(labels: &[(NerLabel, f32)]) -> Vec<NerSpan> {
    let mut spans = Vec::new();
    let mut current: Option<NerSpan> = None;

    for (i, &(label, conf)) in labels.iter().enumerate() {
        if label.is_begin() {
            // Flush previous span
            if let Some(span) = current.take() {
                spans.push(span);
            }
            current = Some(NerSpan {
                label,
                token_start: i,
                token_end: i + 1,
                confidence: conf,
            });
        } else if label.is_inside() {
            if let Some(ref mut span) = current {
                // Check that I- matches the B- entity type
                let same_type = match (span.label, label) {
                    (NerLabel::BPerson, NerLabel::IPerson) => true,
                    (NerLabel::BLocation, NerLabel::ILocation) => true,
                    (NerLabel::BOrganization, NerLabel::IOrganization) => true,
                    (NerLabel::BMisc, NerLabel::IMisc) => true,
                    // Also allow I- to continue I- of the same type
                    (NerLabel::IPerson, NerLabel::IPerson) => true,
                    (NerLabel::ILocation, NerLabel::ILocation) => true,
                    (NerLabel::IOrganization, NerLabel::IOrganization) => true,
                    (NerLabel::IMisc, NerLabel::IMisc) => true,
                    _ => false,
                };
                if same_type {
                    span.token_end = i + 1;
                    span.confidence = span.confidence.min(conf); // Use minimum confidence
                } else {
                    // Mismatched I- tag: flush current, start new
                    spans.push(current.take().unwrap());
                    // I- without matching B- is treated as B-
                    current = Some(NerSpan {
                        label,
                        token_start: i,
                        token_end: i + 1,
                        confidence: conf,
                    });
                }
            } else {
                // I- without preceding B-: treat as B-
                current = Some(NerSpan {
                    label,
                    token_start: i,
                    token_end: i + 1,
                    confidence: conf,
                });
            }
        } else {
            // Outside label: flush any current span
            if let Some(span) = current.take() {
                spans.push(span);
            }
        }
    }

    // Flush final span
    if let Some(span) = current {
        spans.push(span);
    }

    spans
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_bio_sequence() {
        // "John Smith" => B-PER I-PER
        let labels = vec![
            (NerLabel::BPerson, 0.95),
            (NerLabel::IPerson, 0.90),
            (NerLabel::Outside, 0.99),
        ];
        let spans = decode_bio(&labels);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].label, NerLabel::BPerson);
        assert_eq!(spans[0].token_start, 0);
        assert_eq!(spans[0].token_end, 2);
        assert!((spans[0].confidence - 0.90).abs() < f32::EPSILON); // min confidence
    }

    #[test]
    fn test_multi_entity() {
        // "John lives in Paris"
        let labels = vec![
            (NerLabel::BPerson, 0.95),
            (NerLabel::Outside, 0.99),
            (NerLabel::Outside, 0.99),
            (NerLabel::BLocation, 0.92),
        ];
        let spans = decode_bio(&labels);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].label, NerLabel::BPerson);
        assert_eq!(spans[0].token_start, 0);
        assert_eq!(spans[1].label, NerLabel::BLocation);
        assert_eq!(spans[1].token_start, 3);
    }

    #[test]
    fn test_lone_inside_tag() {
        // I- without preceding B- should still create a span
        let labels = vec![
            (NerLabel::Outside, 0.99),
            (NerLabel::IPerson, 0.88),
            (NerLabel::Outside, 0.99),
        ];
        let spans = decode_bio(&labels);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].token_start, 1);
        assert_eq!(spans[0].token_end, 2);
    }

    #[test]
    fn test_empty_input() {
        let spans = decode_bio(&[]);
        assert!(spans.is_empty());
    }

    #[test]
    fn test_mixed_types_mismatched_inside() {
        // B-PER followed by I-LOC => two separate spans
        let labels = vec![
            (NerLabel::BPerson, 0.95),
            (NerLabel::ILocation, 0.85),
            (NerLabel::Outside, 0.99),
        ];
        let spans = decode_bio(&labels);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].label, NerLabel::BPerson);
        assert_eq!(spans[0].token_end, 1); // only one token
        assert_eq!(spans[1].label, NerLabel::ILocation);
        assert_eq!(spans[1].token_start, 1);
    }

    #[test]
    fn test_confidence_propagation() {
        // Confidence should be the minimum across the span
        let labels = vec![
            (NerLabel::BPerson, 0.95),
            (NerLabel::IPerson, 0.80),
            (NerLabel::IPerson, 0.70),
        ];
        let spans = decode_bio(&labels);
        assert_eq!(spans.len(), 1);
        assert!((spans[0].confidence - 0.70).abs() < f32::EPSILON);
    }

    #[test]
    fn test_consecutive_begin_tags() {
        // Two consecutive B-PER should produce two separate spans
        let labels = vec![(NerLabel::BPerson, 0.90), (NerLabel::BPerson, 0.85)];
        let spans = decode_bio(&labels);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].token_start, 0);
        assert_eq!(spans[0].token_end, 1);
        assert_eq!(spans[1].token_start, 1);
        assert_eq!(spans[1].token_end, 2);
    }

    #[test]
    fn test_all_outside() {
        let labels = vec![
            (NerLabel::Outside, 0.99),
            (NerLabel::Outside, 0.99),
            (NerLabel::Outside, 0.99),
        ];
        let spans = decode_bio(&labels);
        assert!(spans.is_empty());
    }

    #[test]
    fn test_label_parsing() {
        assert_eq!(NerLabel::from_label_str("O"), NerLabel::Outside);
        assert_eq!(NerLabel::from_label_str("B-PER"), NerLabel::BPerson);
        assert_eq!(NerLabel::from_label_str("I-PER"), NerLabel::IPerson);
        assert_eq!(NerLabel::from_label_str("B-LOC"), NerLabel::BLocation);
        assert_eq!(NerLabel::from_label_str("I-LOC"), NerLabel::ILocation);
        assert_eq!(NerLabel::from_label_str("B-ORG"), NerLabel::BOrganization);
        assert_eq!(NerLabel::from_label_str("I-ORG"), NerLabel::IOrganization);
        assert_eq!(NerLabel::from_label_str("B-MISC"), NerLabel::BMisc);
        assert_eq!(NerLabel::from_label_str("I-MISC"), NerLabel::IMisc);
        assert_eq!(NerLabel::from_label_str("UNKNOWN"), NerLabel::Outside);
    }

    #[test]
    fn test_to_category() {
        assert_eq!(
            NerLabel::BPerson.to_category(),
            Some(PiiCategory::PersonName)
        );
        assert_eq!(
            NerLabel::ILocation.to_category(),
            Some(PiiCategory::Location)
        );
        assert_eq!(
            NerLabel::BOrganization.to_category(),
            Some(PiiCategory::Organization)
        );
        assert_eq!(NerLabel::Outside.to_category(), None);
        assert_eq!(NerLabel::BMisc.to_category(), None);
    }
}
