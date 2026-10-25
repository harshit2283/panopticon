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
- Captures TLS plaintext through uprobes: OpenSSL (shared `libssl`, including
  the `SSL_read_ex`/`SSL_write_ex` API used by OpenSSL 3 applications) and Go
  `crypto/tls` (reads and writes, Go 1.17+ binaries with symbols).
- Parses HTTP/1.1, HTTP/2, gRPC, MySQL, PostgreSQL, Redis, Kafka, DNS, and AMQP.
- Runs regex-first PII detection with optional ONNX-backed ML inference.
- Builds a service graph named by Kubernetes workload (`namespace/workload`)
  in a cluster, else by DNS name or IP.
- Exports JSONL, Prometheus metrics, OTLP spans, and a PII audit log.

## Documentation

- [User guide](docs/USER-GUIDE.md): first run, configuration, reading the
  event log, PII audit log and metrics, troubleshooting.
- [Deployment](docs/DEPLOYMENT.md): Kubernetes (Helm), Docker, systemd,
  hardening, upgrades and releases.
- [Benchmarks](docs/BENCHMARKS.md): measured capture accuracy, kernel and
  agent overhead, parser/PII micro-benchmarks, fuzzing, and how to reproduce.

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
| Linux x86_64 on kernel 4.15-5.7 | Unsupported | A PerfEventArray fallback path exists, but the eBPF object always creates a RingBuf map and uses 5.5+ helpers, so it fails to load below 5.8. |
| Linux ARM64 | Partial | Build/runtime path exists, but validation coverage is still limited. |
| macOS agent development | Partial | User-space code compiles and tests run, but eBPF loading is Linux-only. |
| Windows runtime | Unsupported | No Windows eBPF/runtime support. |
| HTTP/1.1 parsing | Supported | 100% recall against ground truth, incl. keep-alive, chunked and >4KB bodies ([benchmarks](docs/BENCHMARKS.md)). |
| HTTP/2 parsing | Supported | Per-direction HPACK; headers are lost when the agent joins an existing connection. |
| gRPC parsing | Supported | 100% recall, method path and `grpc-status` against ground truth; payloads shown as printable strings (no schema decoding, no compressed messages). |
| MySQL parsing | Supported | Text protocol (incl. MySQL 8 query attributes) and prepared statements (binary protocol, with bound parameter values) at 100% recall against ground truth on plaintext connections. MySQL 8 clients default to TLS, which needs the OpenSSL uprobe path. |
| PostgreSQL parsing | Supported | Simple, extended and named prepared statements at 100% recall; COPY and large objects not parsed. |
| Redis parsing | Supported | RESP2 and RESP3, pipelining; 100% recall against ground truth. |
| Kafka parsing | Supported | Classic and flexible (KIP-482) versions, topic IDs; 100% recall, topic and error code against ground truth (librdkafka, kafka-python). Record keys/values of uncompressed batches are PII-scanned; compressed batches are not decoded. Detected on port 9092 only. |
| AMQP parsing | Supported | AMQP 0-9-1 (RabbitMQ): publish, deliver, get, return with bodies, synchronous methods with reply codes; 100% recall against ground truth. |
| DNS parsing | Supported | UDP and TCP; query name, type, rcode and answers at 100% against ground truth. |
| OpenSSL TLS plaintext capture | Supported | Shared `libssl` 1.1.1/3.x, `SSL_read`/`SSL_write` and `_ex` variants; 100% recall against ground truth from both client and server processes. Exchanges carry socket addresses (validated on kernels with the `sock_send/recv_length` tracepoints, 6.3+; fentry/kprobe fallback untested). Statically linked OpenSSL/BoringSSL is not found. |
| Go TLS plaintext capture | Supported | `crypto/tls` reads and writes (Go 1.17+, amd64 validated; binaries stripped of symbols are not found); 100% recall against ground truth from both client and server processes. |
| Regex-first PII detection | Supported | Baseline detection path. |
| ONNX-backed ML inference | Partial | Optional runtime/model dependency with throughput trade-offs. |
| Kubernetes identity (`namespace/workload` names) | Partial | Pod/Service list + watch with owner → workload mapping; validated only against a fake API server in unit tests, not on a real cluster yet. IPv4 only. |
| Kubernetes deployment hardening | Out of scope | Helm chart exists, but production hardening is not part of this MVP. |

## Explicitly Not Done Yet

- IPv6 capture is not implemented.
- Kubernetes pod/service identity has not been validated on a real cluster
  (only against a fake API server).
- On kernels older than 6.3, TLS socket addresses come from an fentry/kprobe
  fallback that has not been validated yet.
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

Requires the pinned eBPF toolchain (`nightly-2026-02-17` with `rust-src`) and
`bpf-linker` 0.10.3 (newer releases need a system LLVM 23):

```bash
rustup toolchain install nightly-2026-02-17 --component rust-src
cargo +nightly-2026-02-17 install bpf-linker --locked --version 0.10.3
cargo xtask build-ebpf
cargo build -p panopticon-agent
# --smoke-test exits 0 on the first captured event, 1 after 30s without one.
sudo ./target/debug/panopticon-agent --interface lo --log-events --smoke-test
```

Without `--interface` (and no `interfaces` in the config file) the agent
attaches to the host's IPv4 default-route interface(s).

### Kubernetes (Helm)

Releases publish a signed image to `ghcr.io/harshit2283/panopticon` and the
chart as an OCI artifact:

```bash
helm install panopticon oci://ghcr.io/harshit2283/charts/panopticon \
  --version 0.1.0 -n panopticon --create-namespace
```

The DaemonSet runs privileged with `hostNetwork`/`hostPID`, serves
`/healthz`, `/readyz` and `/metrics` on the node IP at port 9435, and
auto-detects each node's uplink interface. See `helm/panopticon/values.yaml`.

For TLS or cleartext harnesses, see `tests/e2e/README.md` and
`tests/integration/README.md`.

## Verification Layers

- Fast correctness: `cargo test -p panopticon-common`, `cargo test -p xtask`,
  `cargo test -p panopticon-agent`
- Capture accuracy against ground truth: `sudo tests/oracle/run.sh`
- Parser robustness: `cd fuzz && cargo +nightly-2026-02-17 fuzz run parsers`
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
