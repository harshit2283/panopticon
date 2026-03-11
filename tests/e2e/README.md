# TLS And E2E Test Harness

This directory contains the TLS-focused and end-to-end validation harnesses for
Panopticon.

## Modes

- `run_tests.sh`
  - Docker Compose-based E2E run.
  - Validates emitted artifacts rather than relying only on agent logs.
  - Covers the OpenSSL TLS path and current Go TLS expectations.
- `run_tests_host.sh`
  - Linux host-mode run without container orchestration.
  - Builds eBPF and the agent locally, runs the agent on `lo`, generates HTTP
    and TLS traffic, and validates JSON output.

## What This Harness Validates

- The agent can start and attach in an E2E environment.
- Cleartext and TLS traffic produce structured output artifacts.
- TLS behavior is validated within the current support boundary:
  - OpenSSL path
  - Go TLS write-path expectations

This harness does **not** imply broad TLS library support or full
production-readiness.

## Host-Mode Prerequisites

- Linux host with kernel 5.8+
- `sudo` access with a primed non-interactive session (`sudo -v`)
- Rust toolchain + Cargo
- Nightly toolchain for eBPF build (`nightly-2026-02-17` by default)
- `bpf-linker`
- `curl`, `openssl`, `python3`, `ss`, `timeout`, `capsh`

## Running Host-Mode E2E

```bash
./run_tests_host.sh
```

Artifacts are written to `tests/e2e/output-host/`.

## Running Docker Compose E2E

```bash
./run_tests.sh
```

Artifacts are written to `tests/e2e/output/`.

## Troubleshooting

- If the agent fails to start, verify kernel version, capabilities, toolchain,
  and `bpf-linker`.
- If TLS validation fails, inspect:
  - `tests/e2e/output/events.jsonl`
  - `tests/e2e/output/agent.log`
  - compose service logs
