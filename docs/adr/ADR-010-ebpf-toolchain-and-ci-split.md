# ADR-010: Pin eBPF Nightly and Split CI eBPF vs Non-eBPF Jobs

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-03-07 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `.github/workflows/ci.yml`, `.github/workflows/integration.yml`, `.github/workflows/multi-kernel.yml`, `panopticon-agent/build.rs`, `xtask/src/main.rs` |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

eBPF compilation depends on nightly Rust + `bpf-linker`, while most Rust checks do not. Running all CI steps with eBPF build requirements caused unnecessary failures and slower feedback for non-eBPF changes.

## Decision

We will:

1. Pin the eBPF toolchain to `nightly-2026-02-17` via `BPF_TOOLCHAIN`.
2. Split CI responsibilities:
   - non-eBPF jobs run clippy/tests without eBPF compilation using `AYA_BUILD_SKIP=1` where needed.
   - dedicated eBPF jobs install nightly + `bpf-linker` and run `cargo xtask build-ebpf`.

## Consequences

### Positive

- Stable and reproducible eBPF builds across CI environments.
- Faster, less fragile feedback for non-eBPF checks.
- Clear ownership of eBPF failures in dedicated jobs.

### Negative

- CI configuration is more complex.
- `AYA_BUILD_SKIP` can hide eBPF integration issues in non-eBPF jobs.

## References

- `.github/workflows/ci.yml`
- `.github/workflows/integration.yml`
- `.github/workflows/multi-kernel.yml`
- `panopticon-agent/build.rs`
- `xtask/src/main.rs`
