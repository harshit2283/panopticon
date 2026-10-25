# Panopticon Current State

This document is the canonical current-state report for the open-source MVP.
It is intentionally narrower than the historical implementation plans.

## Release Posture

Panopticon is **HIGHLY EXPERIMENTAL / UNSTABLE / NOT PRODUCTION READY**.
The project is usable as an exploratory observability agent, but it is not a
production-hardened compliance platform.

## Validated

- Shared ABI types and user-space logic are covered by Rust unit tests.
- Parser and exporter tests run with `cargo test -p panopticon-agent`.
- Cleartext integration traffic validates HTTP/1.1, MySQL, PostgreSQL, Redis,
  and Kafka in the integration harness.
- Prometheus and OTLP exporter behavior has unit-test coverage.
- Host-mode TLS E2E exists for local Linux debugging.
- HTTP/1.1 capture is scored against a ground-truth traffic generator on a
  veth (server-side view, keep-alive, chunked and >4KB bodies): 100% recall
  across 15,000+ exchanges (`tests/oracle/`, see `BENCHMARKS.md`).
- Redis, PostgreSQL (simple, extended, prepared), MySQL (text protocol and
  prepared statements, plaintext) and gRPC are scored the same way: 100% recall, PII flagged in
  every request that carried it, and no raw PII values in the export
  (`tests/oracle/run_protocols.sh`).
- Sustained load is measured (`tests/load/`): 23K HTTP requests/s over 64
  connections with 99.99% recall, and 8K new connections/s with 99.98%
  recall and bounded connection state. Drops are counted per cause,
  including in the kernel ring buffer.
- Agent overhead is measured: about 1.2-2µs of kernel time per captured
  packet, 2.3% of one core and 122 MiB peak RSS under the HTTP load run.
- All parsers are fuzzed with libFuzzer (`fuzz/`): 16M+ executions without a
  crash after the fixes in this release.

## Partial

- Linux kernel support:
  - 5.8+ is the supported floor (validated by loading on 6.18).
  - 4.15-5.7 does not load today: the PerfEventArray fallback exists in code,
    but the object always creates a RingBuf map and uses 5.5+ helpers.
  - ARM64 support exists but validation remains limited; no arm64 image yet.
- TLS plaintext capture:
  - OpenSSL via a shared `libssl` (including the `_ex` API) is validated
    against ground truth: 100% recall from both client and server processes
    (`tests/oracle/run_tls.sh`). Statically linked TLS libraries are not
    found.
  - TLS exchanges carry their socket addresses and join the service graph:
    validated via the `sock_send/recv_length` tracepoints (kernel 6.3+); the
    fentry/kprobe fallback for older kernels is not validated yet.
  - Go `crypto/tls` reads and writes (Go 1.17+ register ABI) are validated
    the same way: 100% recall from both processes. Binaries built with `-s`
    (no symbol table) are not found; arm64 is untested.
- Protocol depth:
  - PostgreSQL COPY, gRPC schema decoding and compressed messages are not
    parsed. MySQL statements prepared before the agent started are
    reported as `EXECUTE` without their SQL.
  - HTTP/2 headers cannot be decoded when the agent joins a connection that
    was already open (HPACK state is lost).
  - Kafka, AMQP and DNS have unit coverage but are not scored against ground
    truth yet.
- PII detection:
  - Regex-first scanning is the stable baseline.
  - ONNX-backed ML inference is optional and throughput-sensitive.
- Service graphing:
  - DNS/IP-based identity works.
  - Kubernetes-aware identity (`namespace/workload`, `svc:namespace/service`,
    `node:name`) is implemented and tested against a fake API server only;
    not yet validated on a real cluster.
- CI coverage:
  - Multi-kernel coverage is a smoke layer, not complete feature validation.

## Not Done

- IPv6 capture
- Kubernetes identity validated on a real cluster (and for IPv6 pods)
- Broad TLS library support beyond the current OpenSSL and partial Go paths
- Full runtime hot-reload for all tunable settings
- Complete connection-state cleanup on process exit
- Tamper-evident audit logging
- Production-grade Kubernetes hardening and policy guidance

## Out Of MVP Scope

- Production deployment guarantees
- Windows support
- Real-time dashboard UI
- Full APM or profiling features
- Replacing service meshes or acting as an inline proxy

## What To Read Next

- Public entrypoint: `README.md`
- MVP release boundary: `docs/adr/ADR-013-mvp-release-scope-and-test-contract.md`
- Limitations and constraints: `docs/adr/ADR-009-known-limitations.md`
- Protocol notes: `docs/protocol/README.md`
- Integration harness: `tests/integration/`
- TLS harness: `tests/e2e/README.md`
