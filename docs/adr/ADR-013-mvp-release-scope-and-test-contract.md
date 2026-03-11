# ADR-013: MVP Release Scope and Test Contract

| Field | Value |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-03-07 |
| **Decision Makers** | Panopticon maintainers |
| **Affected Components** | `README.md`, `tests/integration/*`, protocol parsers, observability exporters |

## Context

The project needs an explicit MVP release boundary that matches actual automated validation.
Historically, protocol support claims, security posture, and deployment expectations were broader than what tests guaranteed.

For MVP, we must:

1. Keep the release intentionally experimental.
2. Focus on Linux host capture and parser correctness.
3. Validate critical protocol paths in automated tests.
4. Exclude Kubernetes production hardening from current release criteria.

## Decision

We define the MVP contract as follows:

1. **Release posture**
   - The project is explicitly marked as **HIGHLY EXPERIMENTAL / UNSTABLE / NOT PRODUCTION READY**.

2. **In-scope protocol coverage**
   - HTTP/1.1, HTTP/2, gRPC, MySQL, PostgreSQL, Redis, Kafka.
   - Unit tests remain the baseline for parser correctness.
   - Integration test validation must assert presence of required protocol events for cleartext integration traffic.

3. **Kafka E2E requirement (integration path)**
   - Integration stack includes Kafka broker traffic generation.
   - Validator requires Kafka events when Kafka traffic marker is present.

4. **Observability test requirement**
   - Prometheus endpoint behavior is tested (status/content-type/metric values sync behavior).
   - OTLP exporter behavior is tested (channel/backpressure/attribute construction helpers).

5. **Security baseline for MVP**
   - HPACK dependency uses patched crate (`hpack-patched`) to remove known panic vulnerability from the prior crate line.
   - Additional hardening remains required post-MVP (RBAC/network/policy hardening outside scope here).

6. **Out of scope for this MVP**
   - Kubernetes/Helm production readiness and hardening.
   - Broad platform matrix hardening beyond current validated host paths.

## Consequences

### Positive

- Support statements are tied to executable tests.
- Kafka is no longer optional in integration claims when traffic is generated.
- Observability paths (OTLP/Prometheus) have explicit regression tests.
- MVP expectations are clearer for operators and reviewers.

### Negative

- Some existing docs may still describe broader capabilities than this MVP contract and must be reconciled over time.
- Production deployment remains intentionally blocked by policy, not just by implementation.

## Verification

Minimum verification for this ADR:

1. `AYA_BUILD_SKIP=1 cargo test -p panopticon-agent protocol::`
2. `AYA_BUILD_SKIP=1 cargo test -p panopticon-agent export::`
3. `python3 -m py_compile tests/integration/traffic/kafka_traffic.py tests/integration/validation/validate.py`
4. Integration runner path includes Kafka traffic and validator gating.

