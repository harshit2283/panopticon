# =============================================================================
# Panopticon — Production Dockerfile
# Multi-stage build: compile eBPF + agent, then copy to minimal runtime image.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
FROM rust:1.93-bookworm AS builder

# Install build dependencies (clang-18 for eBPF compilation)
RUN apt-get update && apt-get install -y \
    clang-18 llvm-18 libelf-dev \
    pkg-config libssl-dev curl \
    && ln -s /usr/bin/clang-18 /usr/bin/clang \
    && ln -s /usr/bin/llvm-strip-18 /usr/bin/llvm-strip \
    && rm -rf /var/lib/apt/lists/*

# Install pinned nightly toolchain components and bpf-linker
ENV BPF_TOOLCHAIN=nightly-2026-02-17
RUN rustup install ${BPF_TOOLCHAIN} \
    && rustup component add rust-src --toolchain ${BPF_TOOLCHAIN} \
    && cargo +${BPF_TOOLCHAIN} install bpf-linker --locked

WORKDIR /build
COPY . .

# Remove any sudo runner from .cargo/config.toml (not needed as root in Docker)
RUN sed -i '/^\[target\."cfg(all())"\]/,/^runner/d' .cargo/config.toml

# Build eBPF programs (target: bpfel-unknown-none)
RUN cargo xtask build-ebpf --release

# Build user-space agent
RUN cargo build -p panopticon-agent --release

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    libelf1 libssl3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Copy agent binary from builder
COPY --from=builder /build/target/release/panopticon-agent /panopticon-agent

# Optional ONNX Runtime support
ARG INCLUDE_ONNX=false

# Create model directory
RUN mkdir -p /opt/panopticon/models

# Conditionally copy ONNX model from build context
# Build with: docker build --build-arg INCLUDE_ONNX=true .
# Requires models/distilbert-ner/ with model.onnx in build context
COPY models/ /tmp/models/
RUN if [ "$INCLUDE_ONNX" = "true" ] && [ -f /tmp/models/distilbert-ner/model.onnx ]; then \
        cp -r /tmp/models/distilbert-ner /opt/panopticon/models/distilbert-ner; \
        echo "ONNX model included in image"; \
    else \
        echo "ONNX model not included (INCLUDE_ONNX=$INCLUDE_ONNX)"; \
    fi \
    && rm -rf /tmp/models

# Environment
ENV RUST_LOG=info
ENV PANOPTICON_MODEL_PATH=/opt/panopticon/models/distilbert-ner

# OCI image labels
LABEL org.opencontainers.image.title="panopticon" \
      org.opencontainers.image.description="eBPF-based network observability and PII detection agent" \
      org.opencontainers.image.source="https://github.com/harshit2283/panopticon" \
      org.opencontainers.image.version="0.1.0"

# Health check — agent serves /healthz on metrics bind address (default 9090)
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:9090/healthz || exit 1

# eBPF requires root (privileged container) — do not switch to non-root user
ENTRYPOINT ["/panopticon-agent"]
CMD ["--metrics-bind", "0.0.0.0:9090"]
