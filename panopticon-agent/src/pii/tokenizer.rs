//! HuggingFace tokenizer wrapper for PII ML inference.
//! Only compiled with the `ml` feature.

use anyhow::{Context, Result};
use tokenizers::Tokenizer;

/// Wraps a HuggingFace tokenizer with a max token limit.
pub struct PiiTokenizer {
    tokenizer: Tokenizer,
    max_tokens: usize,
}

impl PiiTokenizer {
    /// Load tokenizer from a tokenizer.json file.
    pub fn from_file(path: &str) -> Result<Self> {
        let tokenizer = Tokenizer::from_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;
        Ok(Self {
            tokenizer,
            max_tokens: 512,
        })
    }

    /// Tokenize text, truncating to max_tokens.
    /// Returns (input_ids, attention_mask, offsets).
    pub fn encode(&self, text: &str) -> Result<TokenizedInput> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {}", e))?;

        let len = encoding.get_ids().len().min(self.max_tokens);

        Ok(TokenizedInput {
            input_ids: encoding.get_ids()[..len].to_vec(),
            attention_mask: encoding.get_attention_mask()[..len].to_vec(),
            offsets: encoding.get_offsets()[..len].to_vec(),
        })
    }
}

/// Tokenized input ready for ONNX inference.
pub struct TokenizedInput {
    pub input_ids: Vec<u32>,
    pub attention_mask: Vec<u32>,
    /// Character offsets for each token (start, end) — used to map
    /// model output back to text positions.
    pub offsets: Vec<(usize, usize)>,
}

impl TokenizedInput {
    /// Convert token span indices to character offsets in the original text.
    /// Returns (start_char, end_char) for the given token range.
    pub fn get_char_offsets(&self, token_start: usize, token_end: usize) -> Option<(usize, usize)> {
        if token_start >= self.offsets.len()
            || token_end > self.offsets.len()
            || token_start >= token_end
        {
            return None;
        }
        let start_char = self.offsets[token_start].0;
        let end_char = self.offsets[token_end - 1].1;
        Some((start_char, end_char))
    }
}

#[cfg(test)]
mod tests {
    // Tokenizer tests require a model file, so they're integration-only.
    // Unit test just validates the struct layout.
    use super::*;

    #[test]
    fn test_tokenized_input_layout() {
        let input = TokenizedInput {
            input_ids: vec![101, 2023, 102],
            attention_mask: vec![1, 1, 1],
            offsets: vec![(0, 0), (0, 4), (0, 0)],
        };
        assert_eq!(input.input_ids.len(), 3);
        assert_eq!(input.attention_mask.len(), 3);
        assert_eq!(input.offsets.len(), 3);
    }

    #[test]
    fn test_get_char_offsets_valid() {
        let input = TokenizedInput {
            input_ids: vec![101, 2000, 3000, 102],
            attention_mask: vec![1, 1, 1, 1],
            offsets: vec![(0, 0), (0, 5), (6, 11), (0, 0)],
        };
        assert_eq!(input.get_char_offsets(1, 3), Some((0, 11)));
        assert_eq!(input.get_char_offsets(1, 2), Some((0, 5)));
        assert_eq!(input.get_char_offsets(2, 3), Some((6, 11)));
    }

    #[test]
    fn test_get_char_offsets_invalid() {
        let input = TokenizedInput {
            input_ids: vec![101, 2000, 102],
            attention_mask: vec![1, 1, 1],
            offsets: vec![(0, 0), (0, 5), (0, 0)],
        };
        assert_eq!(input.get_char_offsets(5, 6), None);
        assert_eq!(input.get_char_offsets(0, 10), None);
        assert_eq!(input.get_char_offsets(2, 1), None);
        assert_eq!(input.get_char_offsets(1, 1), None);
    }
}
