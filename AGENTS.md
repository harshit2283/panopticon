# AGENTS.md

This repository follows the guidance in `CLAUDE.md` and extends it with execution rules used during hardening work.

## Source Of Truth
- Primary implementation guidance: `CLAUDE.md`
- Architecture/spec references: `docs/`, especially `docs/adr/`

## Combined Working Rules
- Follow all technical and architectural constraints in `CLAUDE.md`.
- Prefer a tiered verification model:
  1. Fast Rust correctness (`fmt`, `clippy`, unit tests)
  2. eBPF build correctness (`cargo xtask build-ebpf`)
  3. Cleartext integration correctness (`tests/integration`)
  4. TLS-focused behavior (`tests/e2e`)
  5. Multi-kernel compatibility + deployment checks
- Treat each CI job as a single failure domain; avoid mixing unrelated assertions.
- Keep eBPF build validation explicit and reproducible via pinned `BPF_TOOLCHAIN`.
- Do not bypass safety checks with broad skips; use scoped controls only where intentional (for example, `AYA_BUILD_SKIP=1` only in non-eBPF lint/test jobs).

## Security And Reliability Baselines
- Never expose secrets, credentials, or arbitrary host file contents via HTTP endpoints.
- Keep runtime behavior non-blocking on hot paths; use bounded channels and drop counters under backpressure.
- Validate generated eBPF ELF artifacts (sections/program/map presence) as part of build checks.
- Document any material behavior/platform decision in ADRs under `docs/adr/`.

## Git Hygiene
- Commit in logical increments with passing checks for the touched scope.
- Use explicit author identity when requested by repository owner.
