#!/bin/bash
set -euo pipefail

MODEL_DIR="models/distilbert-ner"
MODEL_NAME="dslim/distilbert-ner"
MODEL_URL="https://huggingface.co/${MODEL_NAME}/resolve/main"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is required but not installed"
        exit 1
    fi
}

download_file() {
    local url="$1"
    local output="$2"
    local description="$3"
    
    if [ -f "$output" ]; then
        log_info "$description already exists, skipping"
        return 0
    fi
    
    log_info "Downloading $description..."
    
    if command -v curl &> /dev/null; then
        if ! curl -L --progress-bar -o "$output" "$url" 2>&1; then
            log_error "Failed to download $description"
            rm -f "$output"
            return 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q --show-progress -O "$output" "$url" 2>&1; then
            log_error "Failed to download $description"
            rm -f "$output"
            return 1
        fi
    else
        log_error "Neither curl nor wget is available"
        exit 1
    fi
    
    log_info "Downloaded $description ($(du -h "$output" | cut -f1))"
}

verify_file() {
    local file="$1"
    local min_size="$2"
    
    if [ ! -f "$file" ]; then
        log_error "File not found: $file"
        return 1
    fi
    
    local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    if [ "$size" -lt "$min_size" ]; then
        log_error "File too small: $file (expected >${min_size} bytes, got ${size})"
        rm -f "$file"
        return 1
    fi
    
    return 0
}

main() {
    log_info "Setting up DistilBERT-NER model for PII detection"
    
    check_command curl || check_command wget
    
    if [ -f "$MODEL_DIR/model.onnx" ] && [ -f "$MODEL_DIR/tokenizer.json" ]; then
        log_info "Model already exists at $MODEL_DIR/"
        log_info "To re-download, remove the directory first: rm -rf $MODEL_DIR"
        ls -lh "$MODEL_DIR/"
        exit 0
    fi
    
    mkdir -p "$MODEL_DIR"
    
    log_info "Downloading from HuggingFace: $MODEL_NAME"
    
    local failed=0
    
    if ! download_file "$MODEL_URL/model.onnx" "$MODEL_DIR/model.onnx" "model.onnx"; then
        failed=1
    fi
    
    if ! download_file "$MODEL_URL/tokenizer.json" "$MODEL_DIR/tokenizer.json" "tokenizer.json"; then
        failed=1
    fi
    
    download_file "$MODEL_URL/config.json" "$MODEL_DIR/config.json" "config.json" || true
    
    if [ $failed -eq 1 ]; then
        log_error "Download failed. Check your internet connection and try again."
        exit 1
    fi
    
    log_info "Verifying downloads..."
    
    if ! verify_file "$MODEL_DIR/model.onnx" 100000000; then
        log_error "model.onnx verification failed (expected >100MB)"
        exit 1
    fi
    
    if ! verify_file "$MODEL_DIR/tokenizer.json" 100000; then
        log_error "tokenizer.json verification failed (expected >100KB)"
        exit 1
    fi
    
    log_info "Download complete!"
    echo ""
    echo "Files:"
    ls -lh "$MODEL_DIR/"
    echo ""
    log_info "Total size: $(du -sh "$MODEL_DIR" | cut -f1)"
}

main "$@"
