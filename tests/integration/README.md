# Cleartext Integration Harness

This directory contains the cleartext integration test stack for Panopticon.

## Purpose

The integration harness validates that Panopticon can observe and export
structured events for the core cleartext MVP protocols under containerized test
traffic.

## What It Covers

- HTTP/1.1
- MySQL
- PostgreSQL
- Redis
- Kafka

These protocols are hard-gated by the validator when their traffic is part of
the run.

## What It Does Not Fully Cover Yet

- DNS
- AMQP
- HTTP/2
- gRPC

These may appear in output and are reported when present, but they are not all
hard-gated to the same level as the core cleartext protocols.

## Running The Harness

```bash
bash tests/integration/runner.sh
```

The runner:

- starts the integration stack
- launches traffic generation
- collects JSONL output
- validates the output with `tests/integration/validation/validate.py`

## Output

Artifacts are written to `tests/integration/output/`, including:

- `events.jsonl`
- `agent.log` on failure
- service logs on failure

## Notes

- This is the primary cleartext integration gate for the experimental MVP.
- TLS behavior belongs to `tests/e2e/`.
