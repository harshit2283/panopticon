# Protocol Parsing Layer

Panopticon turns captured packet payloads into structured `L7Message` records
for PII detection, service-graph construction, and export. This layer is part
of the experimental MVP and should be read as current implementation notes, not
as a blanket promise of complete protocol coverage.

## Current Protocol Set

| Protocol | Current State | Validation Notes |
|---|---|---|
| HTTP/1.1 | Supported | Core parser path with strong unit coverage and cleartext integration traffic. |
| HTTP/2 | Supported | Implemented with stream handling; validation is lighter than HTTP/1.1. |
| gRPC | Partial | Built on HTTP/2 parsing; compression and schema-dependent decoding remain limited. |
| MySQL | Partial | Core flows covered; binary protocol gaps remain. |
| PostgreSQL | Partial | Core query flows covered; COPY and large-object paths remain incomplete. |
| Redis | Partial | RESP core covered; advanced command families remain incomplete. |
| Kafka | Supported | Included in cleartext integration traffic and validator gating. |
| DNS | Partial | Parser exists with unit coverage; integration assertions are limited. |
| AMQP | Partial | Parser exists with unit coverage; integration gating is not yet equivalent to the core protocols. |

## Parsing Model

Panopticon uses FSM-style parsers because packet boundaries do not line up with
application message boundaries.

Core pieces in the current implementation:

- `ProtocolParser`
  - Per-protocol parser interface used by worker tasks.
  - Accepts bytes plus traffic direction and timestamp.
  - Produces `ParseResult`.
- `StreamBuffer`
  - Reassembly buffer used by parsers that need multi-packet accumulation.
- `ConnectionFsmManager`
  - Tracks per-connection parser instances keyed by connection identity.
  - Handles capacity limits and idle eviction.
- `detect_protocol()`
  - Detects protocol from magic bytes first, then limited port fallback.

## What Gets Emitted

Parsers emit `L7Message` values with fields such as:

- protocol
- direction
- timestamp
- optional latency
- method
- path
- status
- content type
- payload text
- headers
- request and response sizes

Export layers may attach transport context from the underlying `DataEvent`,
but that context is separate from parser correctness.

## Detection Strategy

Protocol detection is intentionally conservative:

- prefer protocol signatures or handshake bytes
- fall back to well-known ports only when the payload is not conclusive
- keep protocol-specific state per connection once detected

This avoids over-claiming protocol identity when traffic is ambiguous.

## Current Validation Shape

- Strongest cleartext integration coverage:
  - HTTP/1.1
  - MySQL
  - PostgreSQL
  - Redis
  - Kafka
- Lighter validation:
  - HTTP/2
  - gRPC
  - DNS
  - AMQP

For the current release boundary and explicit gaps, prefer:

- `README.md`
- `docs/CURRENT-STATE.md`
- `docs/adr/ADR-013-mvp-release-scope-and-test-contract.md`
- `docs/adr/ADR-009-known-limitations.md`

## Related Docs

- [HTTP/1.1 Parser](./http1.md)
- [Compression Handling](./compression.md)
- [ADR-001: FSM Architecture](../adr/ADR-001-fsm-architecture.md)
- [ADR-002: Protocol Parser Lifecycle](../adr/ADR-002-protocol-lifecycle.md)
- [ADR-003: PostgreSQL Multi-Packet Handling](../adr/ADR-003-postgres-multi-packet.md)
- [ADR-004: HTTP/2 Stream Multiplexing](../adr/ADR-004-http2-streams.md)
- [ADR-005: gRPC Compression](../adr/ADR-005-grpc-compression.md)
