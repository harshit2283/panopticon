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

## Partial

- Linux kernel support:
  - 5.8+ is the primary path.
  - 4.15-5.7 works through the PerfEventArray fallback.
  - ARM64 support exists but validation remains limited.
- TLS plaintext capture:
  - OpenSSL is supported on targeted attach paths.
  - Go TLS is write-path only.
- Protocol depth:
  - HTTP/2, gRPC, MySQL, PostgreSQL, Redis, AMQP, and DNS still have feature
    gaps even where parsing exists.
- PII detection:
  - Regex-first scanning is the stable baseline.
  - ONNX-backed ML inference is optional and throughput-sensitive.
- Service graphing:
  - DNS/IP-based identity works.
  - Kubernetes-aware identity does not.
- CI coverage:
  - Multi-kernel coverage is a smoke layer, not complete feature validation.

## Not Done

- IPv6 capture
- Kubernetes pod or service identity resolution
- Go TLS read-path capture
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
