# ADR-011: Add Local Host-Mode E2E Harness

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-03-07 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `tests/e2e/run_tests_host.sh`, `tests/e2e/README.md`, `tests/e2e/output-host/` |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

Docker Compose E2E tests validate full-stack behavior, but local debugging of eBPF capture and loopback traffic needed a faster path without container orchestration.

## Decision

We will maintain a host-mode E2E harness that runs directly on Linux host networking (`lo`) and:

1. Builds eBPF + agent locally.
2. Starts local HTTP and TLS test endpoints.
3. Generates test traffic.
4. Validates emitted JSON artifacts.

## Consequences

### Positive

- Faster local iteration for eBPF and parser debugging.
- Better coverage for host-network behavior.
- Deterministic output artifacts under `tests/e2e/output-host/`.

### Negative

- Linux-only and requires elevated privileges.
- Additional test path to maintain alongside Compose-based E2E.

## References

- `tests/e2e/run_tests_host.sh`
- `tests/e2e/README.md`
