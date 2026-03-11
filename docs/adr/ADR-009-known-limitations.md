# ADR-009: Known Limitations and Constraints

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-02-19 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | All |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

Panopticon needs a blunt limitations document so operators do not infer more
coverage, platform support, or safety guarantees than the current MVP actually
provides.

This ADR is a constraint disclosure document, not a production certification.

## Live Support Matrix

The canonical, up-to-date support matrix lives in `docs/CURRENT-STATE.md`.
This ADR records the long-lived constraints that shape that matrix, not the
mutable per-release status table.

## Platform Constraints

- Linux is the only runtime target for live eBPF attachment.
- IPv6 capture is not implemented.
- Multi-kernel CI is a smoke layer, not exhaustive protocol correctness across
  every kernel. Use `docs/CURRENT-STATE.md` for the current validated kernel and
  platform coverage.

## TLS Constraints

- OpenSSL support exists for targeted `SSL_read` and `SSL_write` attach paths.
- Go TLS support is limited to write-path capture.
- Broad TLS library coverage is not implemented.

## Identity And Graph Constraints

- Service identity is DNS/IP based.
- Kubernetes pod or service identity resolution is not implemented.
- Graph output should be read as network-observed identity, not cluster-aware
  service topology.

## Runtime Constraints

- Full runtime hot-reload is not implemented end to end.
- Process-exit cleanup for connection state is incomplete.
- PII audit logs are append-only but not tamper-evident.

## Validation Constraints

- Validation depth changes over time; `docs/CURRENT-STATE.md` is the source of
  truth for the current integration, TLS, and multi-kernel test surface.
- TLS behavior still requires dedicated E2E validation and should not be read as
  universal TLS coverage.

## Consequences

- The project can be useful for exploratory observability and evidence capture.
- The project should not be described as a production-ready compliance control.
- Public docs must stay aligned to this MVP boundary.

## Related Docs

- `README.md`
- `docs/CURRENT-STATE.md`
- `docs/adr/ADR-013-mvp-release-scope-and-test-contract.md`
