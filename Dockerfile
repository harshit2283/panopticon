# =============================================================================
# Panopticon — Production Dockerfile
# Multi-stage build: compile eBPF + agent, then copy to minimal runtime image.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder
# ---------------------------------------------------------------------------
# Matches rust-toolchain.toml exactly so rustup does not download a second
# stable toolchain inside the build.
FROM rust:1.93.0-bookworm AS builder

# Pinned eBPF toolchain. bpf-linker 0.10.3 uses the nightly's bundled LLVM
# (rust-llvm-22), so no system LLVM is needed. Newer bpf-linker releases link
# against a system LLVM 23 that Debian does not ship.
ARG BPF_TOOLCHAIN=nightly-2026-02-17
ARG BPF_LINKER_VERSION=0.10.3
ENV BPF_TOOLCHAIN=${BPF_TOOLCHAIN}
RUN rustup toolchain install ${BPF_TOOLCHAIN} --profile minimal --component rust-src \
    && cargo +${BPF_TOOLCHAIN} install bpf-linker --locked --version ${BPF_LINKER_VERSION}

WORKDIR /build
COPY . .

# Build + validate the eBPF object (section/map checks), then the agent, which
# embeds the eBPF object via aya-build.
RUN cargo xtask build-ebpf --release \
    && cargo build -p panopticon-agent --release --locked \
    && strip --strip-debug -o /panopticon-agent target/release/panopticon-agent

# ---------------------------------------------------------------------------
# Stage 2: Runtime
# ---------------------------------------------------------------------------
# The agent links only glibc/libgcc (verified with ldd), so distroless/cc is
# sufficient: no shell, no package manager, no curl.
# ML (ONNX) inference is not built into this image; build with
# `--features ml` plus ONNX Runtime for that variant.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /panopticon-agent /panopticon-agent

ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="panopticon" \
      org.opencontainers.image.description="eBPF-based network observability and PII detection agent" \
      org.opencontainers.image.source="https://github.com/harshit2283/panopticon" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

ENV RUST_LOG=info

# Loading eBPF needs root or CAP_BPF/CAP_PERFMON/CAP_NET_ADMIN (+CAP_SYS_ADMIN
# on < 5.8). The distroless "nonroot" base defaults to uid 65532; the Helm
# chart / `docker run --user 0` grants the required privileges explicitly.
USER 0
ENTRYPOINT ["/panopticon-agent"]
# Loopback by default so a bare `docker run --network host` never exposes
# metrics on the host's public interfaces. Helm overrides this.
CMD ["--metrics-bind", "127.0.0.1:9435"]
