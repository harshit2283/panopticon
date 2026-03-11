//! ONNX Runtime inference for DistilBERT-NER PII detection.
//! Only compiled with the `ml` feature.

use anyhow::{Context, Result};
use ort::session::Session;
use tracing::info;

use super::classifier::{NerLabel, NerSpan, decode_bio};
use super::tokenizer::{PiiTokenizer, TokenizedInput};
use super::{PiiCategory, PiiEntity, PiiSource};

/// ONNX inference engine for NER-based PII detection.
pub struct OnnxInference {
    session: Session,
    tokenizer: PiiTokenizer,
    /// Label mapping from model output indices to NER labels.
    labels: Vec<NerLabel>,
}

impl OnnxInference {
    /// Create a new inference engine from model and tokenizer paths.
    pub fn new(model_path: &str, tokenizer_path: &str) -> Result<Self> {
        let session = Session::builder()
            .context("Failed to create ONNX session builder")?
            .with_optimization_level(ort::session::builder::GraphOptimizationLevel::Level3)
            .context("Failed to set optimization level")?
            .commit_from_file(model_path)
            .context("Failed to load ONNX model")?;

        let tokenizer = PiiTokenizer::from_file(tokenizer_path)?;

        // Standard DistilBERT-NER label order
        let labels = vec![
            NerLabel::Outside,       // 0: O
            NerLabel::BPerson,       // 1: B-PER
            NerLabel::IPerson,       // 2: I-PER
            NerLabel::BLocation,     // 3: B-LOC
            NerLabel::ILocation,     // 4: I-LOC
            NerLabel::BOrganization, // 5: B-ORG
            NerLabel::IOrganization, // 6: I-ORG
            NerLabel::BMisc,         // 7: B-MISC
            NerLabel::IMisc,         // 8: I-MISC
        ];

        info!(model = model_path, "ONNX NER model loaded");

        Ok(Self {
            session,
            tokenizer,
            labels,
        })
    }

    /// Run inference on text. Returns NER spans with character offsets.
    pub fn predict(&self, text: &str) -> Result<Vec<NerSpan>> {
        let encoded = self.tokenizer.encode(text)?;

        let input_ids: Vec<i64> = encoded.input_ids.iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoded.attention_mask.iter().map(|&m| m as i64).collect();

        let seq_len = input_ids.len();

        let input_ids_array = ndarray::Array2::from_shape_vec((1, seq_len), input_ids)
            .context("Failed to create input_ids array")?;
        let attention_mask_array = ndarray::Array2::from_shape_vec((1, seq_len), attention_mask)
            .context("Failed to create attention_mask array")?;

        let outputs = self
            .session
            .run(ort::inputs![input_ids_array, attention_mask_array]?)
            .context("ONNX inference failed")?;

        // Output shape: (1, seq_len, num_labels)
        let logits = outputs[0]
            .try_extract_tensor::<f32>()
            .context("Failed to extract logits tensor")?;
        let logits_view = logits.view();

        // Argmax + softmax confidence per token
        let mut bio_labels: Vec<(NerLabel, f32)> = Vec::with_capacity(seq_len);
        for i in 0..seq_len {
            let mut max_idx = 0;
            let mut max_val = f32::NEG_INFINITY;
            let mut sum_exp = 0.0f32;

            // Find max for numerical stability
            for j in 0..self.labels.len() {
                let val = logits_view[[0, i, j]];
                if val > max_val {
                    max_val = val;
                    max_idx = j;
                }
            }

            // Softmax for confidence
            for j in 0..self.labels.len() {
                sum_exp += (logits_view[[0, i, j]] - max_val).exp();
            }
            let confidence = 1.0 / sum_exp; // exp(0) / sum_exp

            let label = if max_idx < self.labels.len() {
                self.labels[max_idx]
            } else {
                NerLabel::Outside
            };
            bio_labels.push((label, confidence));
        }

        Ok(decode_bio(&bio_labels))
    }

    /// Run inference and return PiiEntity objects directly.
    /// Maps NerSpans to character offsets and filters by min_confidence.
    pub fn predict_entities(&self, text: &str, min_confidence: f32) -> Result<Vec<PiiEntity>> {
        let encoded = self.tokenizer.encode(text)?;
        let spans = self.predict(text)?;

        let mut entities = Vec::new();
        for span in spans {
            if span.confidence < min_confidence {
                continue;
            }

            let category = match span.label.to_category() {
                Some(cat) => cat,
                None => continue,
            };

            let char_offsets = match encoded.get_char_offsets(span.token_start, span.token_end) {
                Some((start, end)) => (start, end),
                None => continue,
            };

            let entity_text = if char_offsets.0 < text.len() && char_offsets.1 <= text.len() {
                text[char_offsets.0..char_offsets.1].to_string()
            } else {
                continue;
            };

            entities.push(PiiEntity {
                category,
                source: PiiSource::Ml,
                start: char_offsets.0,
                end: char_offsets.1,
                confidence: span.confidence,
                text: entity_text,
            });
        }

        Ok(entities)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_mapping() {
        let labels = vec![
            NerLabel::Outside,
            NerLabel::BPerson,
            NerLabel::IPerson,
            NerLabel::BLocation,
            NerLabel::ILocation,
            NerLabel::BOrganization,
            NerLabel::IOrganization,
            NerLabel::BMisc,
            NerLabel::IMisc,
        ];
        assert_eq!(labels.len(), 9);
        assert_eq!(labels[0], NerLabel::Outside);
        assert_eq!(labels[1], NerLabel::BPerson);
    }

    #[test]
    fn test_ner_span_to_pii_entity_conversion() {
        let text = "John lives in Paris";
        let input = TokenizedInput {
            input_ids: vec![101, 2000, 3000, 4000, 102],
            attention_mask: vec![1, 1, 1, 1, 1],
            offsets: vec![(0, 0), (0, 4), (5, 10), (11, 16), (0, 0)],
        };

        let span = NerSpan {
            label: NerLabel::BPerson,
            token_start: 1,
            token_end: 2,
            confidence: 0.95,
        };

        let category = span.label.to_category().unwrap();
        assert_eq!(category, PiiCategory::PersonName);

        let (start, end) = input
            .get_char_offsets(span.token_start, span.token_end)
            .unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 4);
        assert_eq!(&text[start..end], "John");

        let entity = PiiEntity {
            category,
            source: PiiSource::Ml,
            start,
            end,
            confidence: span.confidence,
            text: text[start..end].to_string(),
        };
        assert_eq!(entity.category, PiiCategory::PersonName);
        assert_eq!(entity.text, "John");
        assert!((entity.confidence - 0.95).abs() < f32::EPSILON);
    }

    #[test]
    fn test_confidence_filtering() {
        let spans = vec![
            NerSpan {
                label: NerLabel::BPerson,
                token_start: 1,
                token_end: 2,
                confidence: 0.95,
            },
            NerSpan {
                label: NerLabel::BLocation,
                token_start: 3,
                token_end: 4,
                confidence: 0.50,
            },
        ];

        let min_confidence = 0.7;
        let filtered: Vec<_> = spans
            .into_iter()
            .filter(|s| s.confidence >= min_confidence)
            .collect();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].label, NerLabel::BPerson);
    }
}
