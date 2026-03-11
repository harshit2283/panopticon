# Architecture Decision Records (ADRs)

This directory contains records of significant architectural decisions made in
Panopticon. Read these as design rationale, then use `README.md` and
`docs/CURRENT-STATE.md` for the current public MVP boundary.

## ADR Index

| Number | Title | Status | Date |
|--------|-------|--------|------|
| 000 | [ADR Template](ADR-000-template.md) | Template | - |
| 001 | [FSM Architecture: ConnectionFsmManager Pattern](ADR-001-fsm-architecture.md) | Accepted | 2025-02-18 |
| 002 | [Protocol Parser Lifecycle](ADR-002-protocol-lifecycle.md) | Proposed | 2026-02-18 |
| 003 | [PostgreSQL Multi-Packet Query Handling](ADR-003-postgres-multi-packet.md) | Accepted | 2026-02-18 |
| 004 | [HTTP/2 Stream Multiplexing](ADR-004-http2-streams.md) | Accepted | 2025-02-18 |
| 005 | [gRPC Compression Handling](ADR-005-grpc-compression.md) | Proposed | 2026-02-18 |
| 006 | [TLS Interception Architecture](ADR-006-tls-interception.md) | Accepted | 2026-02-19 |
| 007 | [PII Detection Pipeline Architecture](ADR-007-pii-detection-pipeline.md) | Accepted | 2026-02-19 |
| 008 | [External PII Service Architecture](ADR-008-external-pii-service.md) | Accepted | 2026-02-19 |
| 009 | [Known Limitations and Constraints](ADR-009-known-limitations.md) | Accepted | 2026-02-19 |
| 010 | [Pin eBPF Nightly and Split CI eBPF vs Non-eBPF Jobs](ADR-010-ebpf-toolchain-and-ci-split.md) | Accepted | 2026-03-07 |
| 011 | [Add Local Host-Mode E2E Harness](ADR-011-host-mode-e2e-harness.md) | Accepted | 2026-03-07 |
| 012 | [Validate eBPF ELF Object in `xtask`](ADR-012-xtask-ebpf-elf-validation.md) | Accepted | 2026-03-07 |
| 013 | [MVP Release Scope and Test Contract](ADR-013-mvp-release-scope-and-test-contract.md) | Accepted | 2026-03-07 |

## ADR Lifecycle

```
Proposed -> Accepted -> (Deprecated | Superseded)
                |
                -> Implemented
```

- `Proposed`: under discussion or partially adopted
- `Accepted`: approved architectural direction
- `Implemented`: code changes are complete
- `Deprecated`: still present but no longer recommended
- `Superseded`: replaced by a newer ADR

## Related Docs

- [Project Overview](../../README.md)
- [Current State](../CURRENT-STATE.md)
- [Protocol Documentation](../protocol/README.md)
- [MVP Release Scope](ADR-013-mvp-release-scope-and-test-contract.md)
