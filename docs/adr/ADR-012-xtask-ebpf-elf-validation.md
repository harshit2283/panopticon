# ADR-012: Validate eBPF ELF Object in `xtask`

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-03-07 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `xtask/src/main.rs` |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

A successful compile step is not sufficient if the produced eBPF object is malformed or missing required sections. Failures were previously discovered later during load/attach.

## Decision

After `build-ebpf`, `xtask` will parse and validate the generated ELF object and fail fast when required sections are missing.

Validation includes:

1. Object parse success.
2. Presence of required sections (for programs/maps used by loader).
3. Clear error messages tied to the artifact path.

## Consequences

### Positive

- Earlier failure for invalid eBPF artifacts.
- Better error locality in CI and local builds.
- Reduced chance of shipping unusable eBPF outputs.

### Negative

- Slight extra work in eBPF build pipeline.
- Section policy must stay aligned with loader expectations.

## References

- `xtask/src/main.rs`
