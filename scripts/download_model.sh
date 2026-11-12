#!/bin/bash
# Download the DistilBERT-NER ONNX model and tokenizer for in-agent PII
# detection, pinned to one HuggingFace commit and checked against SHA-256
# digests before anything lands in $MODEL_DIR.
set -euo pipefail

MODEL_DIR="models/distilbert-ner"
MODEL_NAME="dslim/distilbert-NER"
# Immutable revision: a branch ref (resolve/main) can change under us.
MODEL_REV="dfa2838a127384aabb82ed7719e16dab84c42a2a"
MODEL_URL="https://huggingface.co/${MODEL_NAME}/resolve/${MODEL_REV}"

# local name | path in the repo | SHA-256
FILES=(
    "model.onnx|onnx/model.onnx|4440f9fc64cd28ac75d83a38d89716f25947799640cd0e5f1f9f6e57b9c14160"
    "tokenizer.json|onnx/tokenizer.json|cb26b43c98e8266ae3e99c2a583cf8315d73b33a17e6b20b4df7ff1f22392d34"
    "config.json|onnx/config.json|8f9f01d47f61087197f9fa85185d4a7a6248333c15af1b221aa5e8b9b76462b5"
)

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

sha256_of() {
    if command -v sha256sum &> /dev/null; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# HTTPS only, redirects included (the LFS files redirect to a CDN).
fetch() {
    if command -v curl &> /dev/null; then
        curl -fL --proto '=https' --proto-redir '=https' --progress-bar -o "$2" "$1"
    else
        wget -q --show-progress --https-only -O "$2" "$1"
    fi
}

# Download $1 (repo path) to a temporary file next to $2, verify it against
# $3, and only then move it into place.
download_verified() {
    local url="$MODEL_URL/$1" output="$2" want="$3"
    local tmp
    tmp=$(mktemp "$output.XXXXXX")

    log_info "Downloading $1 @ ${MODEL_REV:0:12}..."
    if ! fetch "$url" "$tmp"; then
        rm -f "$tmp"
        log_error "Failed to download $1"
        return 1
    fi

    local got
    got=$(sha256_of "$tmp")
    if [ "$got" != "$want" ]; then
        rm -f "$tmp"
        log_error "$1: SHA-256 mismatch (expected $want, got $got)"
        return 1
    fi
    mv "$tmp" "$output"
    log_info "Verified $(basename "$output") ($(du -h "$output" | cut -f1))"
}

main() {
    log_info "Setting up DistilBERT-NER model for PII detection"

    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        log_error "curl or wget is required"
        exit 1
    fi
    if ! command -v sha256sum &> /dev/null && ! command -v shasum &> /dev/null; then
        log_error "sha256sum or shasum is required"
        exit 1
    fi

    mkdir -p "$MODEL_DIR"
    for entry in "${FILES[@]}"; do
        IFS='|' read -r name path sha <<< "$entry"
        local output="$MODEL_DIR/$name"
        # An existing file is kept only if it is the pinned one.
        if [ -f "$output" ] && [ "$(sha256_of "$output")" = "$sha" ]; then
            log_info "$name already present and verified, skipping"
            continue
        fi
        download_verified "$path" "$output" "$sha"
    done

    log_info "Download complete!"
    ls -lh "$MODEL_DIR/"
}

main "$@"
