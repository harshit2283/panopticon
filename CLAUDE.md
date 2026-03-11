# Panopticon-rs

> Historical/internal engineering reference. For the current open-source MVP
> status, use `README.md` and `docs/CURRENT-STATE.md`. This file still contains
> planning notes and should not be treated as the public release report.

eBPF-based observability and privacy engine in Rust. Intercepts all network traffic
(cleartext + TLS) at the kernel level, parses 12 L7 protocols, runs ML-based PII
detection (DistilBERT-NER via ONNX), and builds a real-time service dependency graph.
Single-binary agent deployed as a Kubernetes DaemonSet.

## Architecture

4-crate Cargo workspace (~17K lines Rust, 55 source files):

| Crate | Role | Environment |
|---|---|---|
| `panopticon-common` | Shared `#[repr(C)]` types between kernel/user space | `#![no_std]` |
| `panopticon-ebpf` | eBPF programs (TC hooks, uprobes, kprobes, tracepoints) | `#![no_std]`, BPF target |
| `panopticon-agent` | User-space agent: event loop, parsers, PII, graph, export | std, async (Tokio) |
| `xtask` | Build orchestration (`cargo xtask build-ebpf`, `test-ebpf`) | std |

**Data flow**: Kernel probes → RingBuf/PerfEventArray → Tokio event loop → per-connection FSM parsers
→ PII pipeline (regex prefilter → ONNX inference) → service graph (petgraph DAG) → export
(Prometheus, JSON, audit log).

**Agent module layout** (`panopticon-agent/src/`):
- `loader.rs` — eBPF program loading, uprobe attachment, kernel compat detection, multi-interface TC, capability probing, map pinning
- `event_loop.rs` — RingBuf/PerfEventArray consumer, dispatches to connection workers via mpsc, backpressure, graceful shutdown
- `config.rs` — TOML config file support, CLI overrides, hot-reload via SIGHUP (arc-swap)
- `protocol/` — `ProtocolParser` trait + FSM-based parsers (http1, http2, grpc, mysql, postgres, redis, kafka, dns, amqp, detect.rs, fsm.rs)
- `pii/` — regex_prefilter → tokenizer → ONNX inference → classifier → redactor + sampler
- `graph/` — identity resolver, DNS cache, edge aggregator, petgraph DAG
- `export/` — JSON log, audit log, Prometheus metrics (http_server.rs, metrics.rs), OTLP (scaffolding)
- `platform/` — proc_scanner (ELF symbol resolution, Go version detection)
- `replay.rs` — deterministic capture/replay system (binary format with CaptureWriter/CaptureReader)
- `compression/` — optional gzip/snappy/zstd compression (feature-gated)
- `util.rs` — shared utilities (format_ipv4)

**eBPF programs** (`panopticon-ebpf/src/`):
- `tc_capture.rs` — TC ingress/egress classifiers, packet parsing, payload capture
- `tls_probes.rs` — OpenSSL SSL_write/SSL_read uprobes, Go TLS write uprobe
- `sock_monitor.rs` — TCP connect/accept/close kprobes, UDP send/recv
- `process_monitor.rs` — sched_process_exec/exit tracepoints
- `maps.rs` — All BPF maps (RingBuf, PerfEventArray, HashMap, Array, PerCpuArray)

**Deployment** (`helm/panopticon/`):
- Helm chart with DaemonSet, RBAC, ConfigMap, Service (Prometheus scraping)
- Production Dockerfile (multi-stage: rust builder → debian:bookworm-slim runtime)

## Tech Stack

- **eBPF framework**: Aya (pinned to git rev `211bb0da`) — pure Rust, no C dependencies
- **Async runtime**: Tokio (macros, rt, rt-multi-thread, net, signal, time, io-util, sync)
- **Protocol parsing**: httparse 1 (HTTP/1.1), hpack (HTTP/2 headers)
- **ML inference**: ort 2 (ONNX Runtime), tokenizers 0.20 (HuggingFace WordPiece)
- **Graph**: petgraph 0.6
- **Observability export**: prometheus-client 0.23, axum 0.8 (HTTP server)
- **Config**: toml 0.8, arc-swap 1, clap 4 (CLI)
- **Concurrency**: dashmap 6, fxhash 0.2, bytes 1, tokio-util 0.7
- **Security**: zeroize 1 (PII memory safety)
- **Benchmarks**: criterion 0.5
- **Toolchain**: Rust nightly (edition 2024), bpf-linker

## Build Commands

```bash
cargo xtask build-ebpf          # Compile eBPF programs (target: bpfel-unknown-none)
cargo xtask build-ebpf --release
cargo build -p panopticon-agent  # Build user-space agent
cargo build -p panopticon-agent --release
cargo test --workspace           # Run all tests (eBPF crate excluded - no test harness)
cargo test -p panopticon-agent   # Agent tests only (291 tests)
cargo clippy -p panopticon-agent -p panopticon-common -p xtask  # Lint (excludes eBPF)
cargo fmt --all -- --check       # Format check
cargo bench -p panopticon-agent  # Run Criterion benchmarks
cargo xtask test-ebpf            # Instructions for eBPF testing on Linux
```

## Prerequisites

- **Linux kernel**: 4.15+ minimum (TC eBPF + PerfEventArray), 5.8+ recommended (RingBuf support)
- **Toolchain**: Rust nightly, `rust-src` component, bpf-linker (`cargo install bpf-linker`)
- **System packages**: clang-18, llvm-18, libelf-dev, linux-headers, pkg-config, libssl-dev
- **ONNX Runtime** (optional): v1.19.2+ at `/opt/onnxruntime` (set `ORT_LIB_LOCATION`)
- **ML model** (optional): DistilBERT-NER ONNX model in `models/distilbert-ner/`
- **macOS note**: Dev builds compile and tests run, but eBPF programs only load on Linux

## Key Design Decisions

- **`#[repr(C)]` for all shared types** — Required for kernel↔user space ABI compatibility. `DataEvent` is ~4.2KB; must use RingBuf reserve or PerCpuArray scratch (not stack, 512-byte limit).
- **RingBuf primary, PerfEventArray fallback** — RingBuf (kernel 5.8+) is zero-copy and ordered. PerfEventArray for older kernels uses PerCpuArray scratch maps for the large DataEvent struct.
- **FSM-based protocol parsers** — Single-packet parsers fail on real traffic (e.g., PostgreSQL queries spanning 17+ packets). Each connection gets its own `ProtocolFsm` instance managed by `ConnectionFsmManager` (DashMap-backed).
- **PII pipeline: regex first, then ML** — Regex prefilter (RegexSet, ~1µs) skips ~90% of traffic. Only suspicious payloads go to DistilBERT-NER (ONNX, batched). Inference sampler limits budget per second.
- **DNS cache for service graph** — Without it, graph shows IPs not names. Fallback chain: observed DNS events → reverse lookup → raw IP. TTL-aware with DashMap.
- **Query template normalization** — SQL literals → `?`, HTTP UUIDs → `?`. Achieves ~90% event reduction via deduplication before export.
- **TC_ACT_OK always** — Never drop packets; passive observer only.
- **PerCpuArray scratch for PerfEventArray path** — DataEvent is ~4.2KB, far exceeding the 512-byte BPF stack limit. All eBPF files use `PERF_SCRATCH: PerCpuArray<DataEvent>` for the fallback path.
- **Generic `EbpfContext` in emit functions** — `emit_tls_event<C: EbpfContext>` and `emit_sock_event<C: EbpfContext>` handle both ProbeContext and RetProbeContext callers.

## Code Conventions

- **`#![no_std]` for eBPF crates** — `panopticon-common` and `panopticon-ebpf` are no_std. No heap allocation in eBPF programs.
- **`#[inline(always)]`** on all eBPF helper functions — required by the BPF verifier for bounded execution.
- **All buffer accesses bounded** — Explicit length checks before every read in eBPF to pass the verifier.
- **Error handling**: `anyhow::Result` in agent, `Result<(), ()>` in eBPF. Probe failures log and skip, never crash the agent.
- **Logging**: `tracing` crate with structured fields.
- **Testing**: 319 tests total (291 agent + 21 common + 5 ABI + 2 xtask). Unit tests in each module, integration tests in `tests/integration/`, E2E with docker-compose.
- **Backpressure**: Bounded mpsc channels everywhere. If full, drop event + increment counter. Never block the event loop.
- **Performance targets**: 500K events/sec sustained, P99 < 5ms kernel→user-space, < 200MB RSS (excluding ML model).
- **Benchmarks**: Criterion benchmarks in `panopticon-agent/benches/` for protocol detection, parser throughput, PII regex.

## Testing Infrastructure

- **Unit tests**: In each module, run via `cargo test --workspace` (319 tests)
- **Benchmarks**: `panopticon-agent/benches/` — protocol_detect, parser_throughput, pii_regex (Criterion)
- **Replay**: `replay.rs` — binary capture format (PNCAP magic) for deterministic event replay
- **Integration**: `tests/integration/` — docker-compose with nginx, MySQL, PostgreSQL, Redis, traffic generators with PII data, automated validation
- **E2E**: `tests/e2e/` — docker-compose with TLS servers (OpenSSL, Go), gRPC, agent verification
- **CI**: `.github/workflows/ci.yml` — build-and-test, build-ebpf, benchmarks, macOS check

## Deployment

- **Dockerfile**: Multi-stage production image (rust:1.93 builder → debian:bookworm-slim)
- **Dockerfile.build-check**: CI-only build verification (not for production)
- **Helm chart**: `helm/panopticon/` — DaemonSet, RBAC, ConfigMap, Service
  - `helm template panopticon helm/panopticon/` to verify
  - Key: hostNetwork, hostPID, privileged, bpffs volume mount, Prometheus scrape annotations

## Historical Implementation Snapshot (2026-03-11, commit `8a91ba8`, PR `#4`)

This section reflects the hardening-era status snapshot captured for the
open-source release preparation on 2026-03-11. It is kept for internal context
and should not be treated as the canonical public release report.

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Critical Bug Fixes (timestamp, cookie, PID filter, gRPC enrichment) | ✅ |
| 2 | Dead Code & Streamlining (unused impls, dedup, compression gating) | ✅ |
| 3 | Architectural Fixes (channel-based export, rate limiter, graceful shutdown, BytesMut) | ✅ |
| 4 | eBPF Correctness (IPv6 counter, payload zeroing, UDP event types, PID_TO_CONN) | ✅ |
| 5 | Security & PII Hardening (zeroize, audit log, core dump protection) | ✅ |
| 6 | Config & Observability (TOML config, hot-reload, Prometheus /metrics, /healthz) | ✅ |
| 7 | Process Events & Connection Lifecycle (TLS rescan, backpressure, self-healing) | ✅ |
| 8 | Protocol Parsers (DNS, Kafka, AMQP) | ✅ |
| 9 | Platform Compatibility (PerfEventArray fallback, multi-interface, capabilities, map pinning) | ✅ |
| 10 | Deployment (Dockerfile, Helm chart, DaemonSet) | ✅ |
| 11 | Testing (replay, benchmarks, integration, E2E, CI) | ✅ |

## Known Issues

- **macOS development**: eBPF programs compile but cannot be loaded (Linux only). All 319 tests pass on macOS.
- **eBPF tests**: Disabled via `test = false` in Cargo.toml (no test harness for `bpfel-unknown-none` target). Use `cargo xtask test-ebpf` for instructions.
- **`ort` version**: Pinned to `2.0.0-rc.11` (only RC available for ort 2.x)
- **Rust 2024 compatibility warnings**: `unsafe_op_in_unsafe_fn` warnings in eBPF crate — cosmetic only, does not affect correctness
