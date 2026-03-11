# DistilBERT-NER ONNX Model

This directory contains the ONNX model and tokenizer for Named Entity Recognition (NER) based PII detection.

## Model

- **Name**: `dslim/distilbert-ner`
- **Source**: [HuggingFace](https://huggingface.co/dslim/distilbert-ner)
- **Type**: DistilBERT fine-tuned for Named Entity Recognition (CoNLL-2003)
- **Purpose**: Detect PII entities (PER, ORG, LOC, MISC) in network payloads

## Required Files

| File | Size | Description |
|------|------|-------------|
| `model.onnx` | ~265MB | ONNX-optimized model weights |
| `tokenizer.json` | ~450KB | HuggingFace tokenizer configuration |
| `config.json` | ~1KB | Model configuration (optional) |

## Download

```bash
# From project root
./scripts/download_model.sh
```

The script will:
1. Check if model already exists (skip if present)
2. Download model.onnx and tokenizer.json from HuggingFace
3. Verify file sizes

## Manual Download

```bash
# Create directory
mkdir -p models/distilbert-ner

# Download from HuggingFace
curl -L -o models/distilbert-ner/model.onnx \
    "https://huggingface.co/dslim/distilbert-ner/resolve/main/model.onnx"

curl -L -o models/distilbert-ner/tokenizer.json \
    "https://huggingface.co/dslim/distilbert-ner/resolve/main/tokenizer.json"

curl -L -o models/distilbert-ner/config.json \
    "https://huggingface.co/dslim/distilbert-ner/resolve/main/config.json"
```

## Usage in Panopticon

The PII detection pipeline (`panopticon-agent/src/pii/`) uses this model for:

1. **Regex Prefilter**: Fast pattern matching skips ~90% of traffic
2. **Tokenizer**: Converts suspicious text to WordPiece tokens
3. **ONNX Inference**: Batched inference via `ort` crate
4. **Entity Classification**: Maps NER labels to PII types

## Entity Types

The model recognizes:
- **PER**: Person names
- **ORG**: Organizations
- **LOC**: Locations
- **MISC**: Miscellaneous entities

These are mapped to PII categories in the classifier module.

## Alternative Models

If you need different entity types, consider:
- `dslim/bert-base-NER` - Larger, more accurate
- `elastic/distilbert-base-uncased-finetuned-conll03-english` - Elastic's variant

Update `scripts/download_model.sh` with the new model URL.
