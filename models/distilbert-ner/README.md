# DistilBERT-NER ONNX Model

This directory contains the ONNX model and tokenizer for Named Entity Recognition (NER) based PII detection.

## Model

- **Name**: `dslim/distilbert-NER` (ONNX export in its `onnx/` folder)
- **Source**: [HuggingFace](https://huggingface.co/dslim/distilbert-NER)
- **Type**: DistilBERT fine-tuned for Named Entity Recognition (CoNLL-2003)
- **Purpose**: Detect PII entities (PER, ORG, LOC, MISC) in network payloads

## Required Files

| File | Size | Description |
|------|------|-------------|
| `model.onnx` | ~265MB | ONNX-optimized model weights |
| `tokenizer.json` | ~650KB | HuggingFace tokenizer configuration |
| `config.json` | ~1KB | Model configuration |

## Download

```bash
# From project root
./scripts/download_model.sh
```

The script downloads `model.onnx`, `tokenizer.json` and `config.json` from
the `onnx/` folder of the HuggingFace repo, pinned to commit
`dfa2838a127384aabb82ed7719e16dab84c42a2a`, over HTTPS only. Each file goes
to a temporary name and is moved into place only after its SHA-256 matches
the digest in the script; an existing file is kept only if it matches.

## Manual Download

Use the same pinned revision and check the digests before using the files:

```bash
mkdir -p models/distilbert-ner
REV=dfa2838a127384aabb82ed7719e16dab84c42a2a
BASE="https://huggingface.co/dslim/distilbert-NER/resolve/$REV/onnx"
for f in model.onnx tokenizer.json config.json; do
    curl -fL --proto '=https' --proto-redir '=https' \
        -o "models/distilbert-ner/$f" "$BASE/$f"
done

cd models/distilbert-ner && shasum -a 256 -c - <<'EOF'
4440f9fc64cd28ac75d83a38d89716f25947799640cd0e5f1f9f6e57b9c14160  model.onnx
cb26b43c98e8266ae3e99c2a583cf8315d73b33a17e6b20b4df7ff1f22392d34  tokenizer.json
8f9f01d47f61087197f9fa85185d4a7a6248333c15af1b221aa5e8b9b76462b5  config.json
EOF
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
