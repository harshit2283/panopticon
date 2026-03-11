# Panopticon (Rust)

## HIGHLY EXPERIMENTAL / UNSTABLE / NOT PRODUCTION READY

Panopticon is an experimental eBPF-based observability and privacy engine for
Linux hosts. It captures network traffic at the kernel boundary, reconstructs
selected application protocols, detects likely PII, and exports evidence about
what systems are actually doing behind the packet.

Do **not** deploy it in production or compliance-critical environments. This
repo is an honest MVP with explicit gaps, partial validation, and ongoing
hardening work.

## What Panopticon Does

- Captures cleartext traffic with TC eBPF hooks.
- Captures some TLS plaintext paths through targeted uprobes.
- Parses HTTP/1.1, HTTP/2, gRPC, MySQL, PostgreSQL, Redis, Kafka, DNS, and AMQP.
- Runs regex-first PII detection with optional ONNX-backed ML inference.
- Builds a DNS/IP-based service graph.
- Exports JSONL, Prometheus metrics, OTLP spans, and a PII audit log.

## Public Source Of Truth

- Current status and explicit gaps: `docs/CURRENT-STATE.md`
- Release boundary: `docs/adr/ADR-013-mvp-release-scope-and-test-contract.md`
- ADR index: `docs/adr/README.md`
- Protocol notes: `docs/protocol/README.md`

The files `CLAUDE.md` and `docs/Panopticon Rust Implementation Plan*.md` are
kept as internal or historical planning references. Do not treat them as the
current release report.

## MVP Support Matrix

| Capability | MVP Status | Notes |
|---|---|---|
| Linux x86_64 on kernel 5.8+ | Supported | Primary development path with RingBuf support. |
| Linux x86_64 on kernel 4.15-5.7 | Partial | Works through PerfEventArray fallback with higher overhead. |
| Linux ARM64 | Partial | Build/runtime path exists, but validation coverage is still limited. |
| macOS agent development | Partial | User-space code compiles and tests run, but eBPF loading is Linux-only. |
| Windows runtime | Unsupported | No Windows eBPF/runtime support. |
| HTTP/1.1 parsing | Supported | FSM parser with multi-packet handling. |
| HTTP/2 parsing | Supported | Stream handling works; some edge cases remain. |
| gRPC parsing | Partial | Compression and schema-dependent decoding gaps remain. |
| MySQL parsing | Partial | Core query flows supported; binary protocol gaps remain. |
| PostgreSQL parsing | Partial | Core query flows supported; COPY and large-object paths remain incomplete. |
| Redis parsing | Partial | RESP core supported; advanced command families remain incomplete. |
| Kafka parsing | Supported | Covered by cleartext integration traffic and validator gating. |
| AMQP parsing | Partial | Parser exists with unit coverage; no integration gating yet. |
| DNS parsing | Partial | Parser exists with unit coverage; integration assertions remain limited. |
| OpenSSL TLS plaintext capture | Partial | Targeted path support with runtime-specific caveats. |
| Go TLS plaintext capture | Partial | Write-path capture only. |
| Regex-first PII detection | Supported | Baseline detection path. |
| ONNX-backed ML inference | Partial | Optional runtime/model dependency with throughput trade-offs. |
| Kubernetes deployment hardening | Out of scope | Helm chart exists, but production hardening is not part of this MVP. |

## Explicitly Not Done Yet

- IPv6 capture is not implemented.
- Kubernetes pod/service identity resolution is not implemented; graph identity
  is DNS/IP-based today.
- Go TLS read-path capture is not implemented.
- Broad TLS library coverage beyond the current OpenSSL and partial Go paths is
  not implemented.
- Full runtime hot-reload is not implemented end to end.
- Process-exit cleanup for connection state is incomplete.
- Audit-log tamper evidence is not implemented.

## Quickstart

### macOS or non-Linux development

```bash
cargo test -p panopticon-common
cargo test -p xtask
cargo test -p panopticon-agent
```

This validates most user-space logic, parser behavior, exporters, and shared
ABI types, but it does **not** validate live eBPF attachment.

### Linux build and smoke-test path

```bash
cargo xtask build-ebpf
cargo build -p panopticon-agent
sudo ./target/debug/panopticon-agent --interface lo --log-events --smoke-test
```

For TLS or cleartext harnesses, see `tests/e2e/README.md` and
`tests/integration/README.md`.

## Verification Layers

- Fast correctness: `cargo test -p panopticon-common`, `cargo test -p xtask`,
  `cargo test -p panopticon-agent`
- eBPF build correctness: `cargo xtask build-ebpf`
- Cleartext integration: `tests/integration/`
- TLS behavior: `tests/e2e/`
- Multi-kernel compatibility: `.github/workflows/multi-kernel.yml`

The multi-kernel workflow is currently a smoke layer, not full protocol
correctness across every kernel.

## Security Guidance

- Do **not** expose `/healthz`, `/readyz`, `/metrics`, or `/debug/state` to
  public or untrusted networks.
- Prefer loopback or a private management network for observability endpoints.
- OTLP should stay on trusted internal networks for the current MVP. If the
  exposure boundary grows, use TLS or mTLS and stronger endpoint
  authentication.
- Treat JSONL export and the PII audit log as sensitive artifacts.

## Open Source

- Contribution guide: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Licenses: `LICENSE-MIT`, `LICENSE-APACHE`
