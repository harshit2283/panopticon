# Contributing

Panopticon is an experimental eBPF observability project.

## Contribution Status

External contributions are **not being accepted at the moment**.

The repository is being opened for transparency, review, and reference while
the project surface is still being tightened. Please do not open pull requests
expecting active review or merge right now.

If you find a bug, limitation, or security issue, use the reporting guidance in
`SECURITY.md` or open an issue if the problem is appropriate for public
tracking.

## Ground Rules

- Keep the MVP posture explicit. Do not broaden public claims beyond code and
  tests.
- Do not bypass safety checks with broad skips. Use scoped controls only where
  intentional.
- Keep hot paths non-blocking and memory-bounded.
- Prefer small, reviewable changes over large mixed refactors.

## Local Verification

Fast path:

```bash
cargo test -p panopticon-common
cargo test -p xtask
cargo test -p panopticon-agent
```

eBPF build path:

```bash
cargo xtask build-ebpf
```

Formatting and linting:

```bash
cargo +nightly-2026-02-17 fmt --all -- --check
cargo clippy -p panopticon-common -p xtask -- -D warnings
AYA_BUILD_SKIP=1 cargo clippy -p panopticon-agent -- -D warnings
```

Optional integration layers:

```bash
bash tests/integration/runner.sh
bash tests/e2e/run_tests.sh
```

## Pull Requests

- Explain the user-visible effect of the change.
- Call out any limitation or support-matrix change explicitly.
- If you update protocol behavior, update the relevant public docs in the same
  change.
- If you touch deployment or test surfaces, explain what is now guaranteed and
  what remains out of scope.

## Scope Discipline

Do not widen a change into unrelated work such as IPv6 support, Kubernetes
identity resolution, or full runtime hot-reload unless that is the explicit
goal of the patch.
