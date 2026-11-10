# Panopticon Current State

This document is the canonical current-state report for the open-source MVP.
It is intentionally narrower than the historical implementation plans.

## Release Posture

Panopticon is **HIGHLY EXPERIMENTAL / UNSTABLE / NOT PRODUCTION READY**.
The project is usable as an exploratory observability agent, but it is not a
production-hardened compliance platform.

## Validated

- Shared ABI types and user-space logic are covered by Rust unit tests.
- Parser and exporter tests run with `cargo test -p panopticon-agent`.
- Cleartext integration traffic validates HTTP/1.1, MySQL, PostgreSQL, Redis,
  and Kafka in the integration harness.
- Prometheus and OTLP exporter behavior has unit-test coverage.
- Host-mode TLS E2E exists for local Linux debugging.
- HTTP/1.1 capture is scored against a ground-truth traffic generator on a
  veth (server-side view, keep-alive, chunked and >4KB bodies): 100% recall
  across 15,000+ exchanges (`tests/oracle/`, see `BENCHMARKS.md`).
- Redis, PostgreSQL (simple, extended, prepared), MySQL (text protocol and
  prepared statements, plaintext) and gRPC are scored the same way: 100% recall, PII flagged in
  every request that carried it, and no raw PII values in the export
  (`tests/oracle/run_protocols.sh`).
- The privacy modes (`[privacy] mode` / `--privacy-mode`: `full`,
  `redacted`, `metrics_only`) are checked with planted PII and credentials
  in HTTP and OpenSSL TLS traffic (bodies, query strings, headers, a
  Content-Type parameter, an X-Vault-Token, a JWT behind an overlapping
  `access_token=`) and in Redis AUTH / HELLO AUTH and Kafka client ids,
  searched for in every output (export, raw dump and
  its pcap conversion, audit log, agent log at debug level, `/metrics`,
  `/debug/state`): values appear only where the mode allows, recall 100%
  (`tests/oracle/run_modes.sh`, kernel 7.0).
- The capture-scope settings are checked the same way, with every sink on
  (`tests/oracle/run_sampling.sh`, kernel 7.0): `pid_filter` naming the
  HTTP and TLS servers captures 100% of their exchanges and nothing of the
  TLS client process; naming an unrelated process exports nothing and
  leaves none of 6,440 planted values in any sink. `connection_sample`
  at 0.0, 0.5 and 1.0 kept 0, 47 and 96 of 96 connections, never part of
  one. `head_only` kept no direction past its limit, captured every
  connection's first request, and left none of the values planted past
  the limit in any sink. Not yet run on 5.15 or the RHEL kernels.
- Sustained load is measured (`tests/load/`): 23K HTTP requests/s over 64
  connections with 99.99% recall, and 8K new connections/s with 99.98%
  recall and bounded connection state, on 4 vCPUs. On 64 vCPUs (agent
  pinned to 16 of them): 223K requests/s over 1K connections at 100%
  recall, 237K over 4K connections at 99.8% (about 470K events/s, limited
  by the load generator), and 200 KB bodies at 99.7-99.9%. Drops are
  counted per cause, including in the kernel ring buffers.
- Agent overhead is measured: about 1.2-2µs of kernel time per captured
  packet, 2.3% of one core and 122 MiB peak RSS under the HTTP load run on
  4 vCPUs; about 0.7µs per packet under 1K-4K connections on 64 vCPUs,
  with 176-252 MiB peak RSS (above the 200 MB target at 4K connections and
  200 KB bodies). At fixed rates the agent costs about 0.37 cores at 20K
  requests/s (64 or 4K connections). Kernel-to-worker P99 latency
  (preliminary) is 2-4 ms at 64 connections and at 4K connections up to
  20K requests/s, and 8-10 ms at 4K connections from 50K requests/s
  (docs/BENCHMARKS.md, scaling study). These figures are for the default TC
  backend.
- The `cgroup_skb` backend (not the default) is measured on five kernels
  (preliminary): scoped by `pid_filter`, it matches TC's throughput, recall
  and agent CPU at 64 keep-alive connections, and at 1K uses slightly less agent CPU
  than TC with no kernel ring drops (records are sized to what they carry),
  at 1.4-1.8x TC's kernel time per request. Unscoped, it also captures
  loopback and both ends of node-local connections, about twice the events
  and agent CPU. `pid_filter` matches TC's recall only for a server whose
  listener was created after the agent started. On a listener that predates
  the agent (any server not restarted since), a connection is captured from
  the moment a listed process accepts it, and earlier bytes are dropped:
  56.6% recall with a new connection per request (TC 100%), 100% with
  keep-alive connections. Restart the server after the agent, or use
  `cgroup_filter` / `pod_filter`, which has no such gap. A listener created
  by a listed process selects every connection accepted on it, also by
  processes not in the list (docs/USER-GUIDE.md).
- All parsers are fuzzed with libFuzzer (`fuzz/`): 16M+ executions without a
  crash after the fixes in this release.

## Partial

- Linux kernel support:
  - 5.8+ is the supported floor. Full accuracy suites pass on 5.15, 6.8 and 7.0 (also loaded on 6.18).
  - RHEL 8 and 9 are supported: their 4.18 and 5.14 kernels carry the BPF
    ring buffer and 5.5+ probe-read helpers. Measured on Rocky Linux 8.10
    (4.18.0-553) and 9.8 (5.14.0-687), SELinux enforcing with no AVC denials
    (agent run as root from an unconfined shell): HTTP, HTTPS, Redis,
    PostgreSQL, MySQL, gRPC, Kafka and DNS at 99.4-100% recall with no raw PII
    exported, every TLS exchange carrying its socket addresses (via fentry).
    The agent probes the ring buffer by creating one rather than trusting the
    version number; before that, RHEL 8 fell to the PerfEventArray path and
    captured nothing.
  - RHEL 8.10 caveat: AMQP `Basic.Deliver` recall was 77-98% over seven lab
    runs (other AMQP methods 100%). The broker-to-consumer stream there
    carries GSO segments up to 18 KB, and frames past the 4 KB capture window
    are lost. Retransmitted segments are now parsed once (see TCP stream
    integrity below), so deliveries are no longer duplicated; replaying two
    of these captures with and without sequence tracking gave the same
    deliveries, so the remaining loss is the capture window.
    RHEL 9 passed (100%, one earlier run at 85%).
  - RHEL 9's `sock:sock_send_length` / `sock_recv_length` tracepoints have a
    different record layout (an extra `common_preempt_lazy_count` field moves
    every field by 8 bytes). The agent checks each tracepoint's tracefs
    `format` against the offsets its programs read and uses fentry instead
    when they differ.
  - Upstream 4.15-5.7 does not load today: the PerfEventArray fallback exists
    in code, but the object always creates a RingBuf map and uses 5.5+ helpers.
  - ARM64 support exists but validation remains limited; no arm64 image yet.
- TLS plaintext capture:
  - OpenSSL via a shared `libssl` (including the `_ex` API) is validated
    against ground truth: 100% recall from both client and server processes
    (`tests/oracle/run_tls.sh`). Statically linked TLS libraries are not
    found.
  - TLS exchanges carry their socket addresses and join the service graph:
    validated via the `sock_send/recv_length` tracepoints (kernel 6.3+) and
    via the fentry fallback (RHEL 8 and 9); the kprobe fallback for kernels
    without BTF is not validated yet.
  - Go `crypto/tls`: writes only (Go 1.17+ register ABI). Reads are no
    longer captured: the arguments saved at a read's entry cannot be proven
    to still belong to that call at its return (a stack-backed buffer moves
    when the goroutine's stack grows; a read that unwinds without returning
    leaves them for a later call), and abandoned entries could not be
    reclaimed on the supported kernels. Earlier read-and-write recall figures
    no longer apply. Binaries built with `-s` (no symbol table) are not
    found; arm64 is untested.
- TCP stream integrity (TC capture):
  - Each direction's next expected sequence number is tracked
    (`protocol/fsm.rs` `TcpTracker`): retransmitted bytes are parsed once,
    segments whose sequence or acknowledgment number is far from the stream
    (blind forgeries) are ignored, and an RST counts only at the next
    expected byte. Bytes the agent never saw are skipped as a gap, up to
    8 MiB ahead, or further once the peer acknowledges them.
  - TCP and IP checksums are not checked: TC ingress runs before the kernel
    validates them, and with checksum offload the packet's checksum state is
    not reliable there. A segment with a bad checksum and the right sequence
    numbers is parsed although the receiver discards it, and the genuine
    retransmission is then dropped as a duplicate. Forging one needs the
    connection's current sequence numbers (an on-path attacker).
  - Segments are not reordered: one that arrives before an earlier one is
    taken as a gap, and the earlier one is then ignored. SYNs are not
    tracked (`sampling_mode = "head_only"` captures them, but only to count
    each direction's bytes), so a new connection on a 5-tuple whose old state is still held
    (its FIN or RST not seen) is ignored until that state expires
    (`idle_connection_timeout`, 30 s).
- Protocol depth:
  - PostgreSQL COPY, gRPC schema decoding and compressed messages are not
    parsed. MySQL statements prepared before the agent started are
    reported as `EXECUTE` without their SQL.
  - HTTP/2 headers cannot be decoded when the agent joins a connection that
    was already open (HPACK state is lost).
  - Kafka, AMQP and DNS are scored against ground truth
    (`tests/oracle/run_messaging.sh`). Compressed Kafka record batches are
    not decoded, and Kafka is recognised on port 9092 only.
- PII detection:
  - Regex-first scanning is the stable baseline: 16 validated patterns
    (checksums, issuer prefixes, context keywords), including Indian
    identifiers. On the labelled corpus (`tests/pii/`), 1.1% of clean
    payloads produce a finding, down from 54%. Remaining misses are numbers
    with no context; see `BENCHMARKS.md` §3.
  - ONNX-backed ML inference is optional and throughput-sensitive.
  - In `redacted` mode, header names and values are scanned for every
    protocol, and credentials (credential-named HTTP headers, Redis `AUTH`,
    SQL password clauses) are masked; `full` masks login secrets too unless
    `[privacy] mask_credentials = false`. The leak test covers HTTP, OpenSSL
    TLS, Redis AUTH and Kafka client ids; SQL password clauses and AMQP
    metadata are covered by unit tests only.
- Service graphing:
  - DNS/IP-based identity works. DNS names come only from answers to
    queries seen on the same flow, are validated hostnames, last at most an
    hour, and are dropped when they hold PII (except in `full`); there is no
    list of trusted resolvers, so a workload can still name an address of
    its choosing through a resolver it runs. The audit log records the
    address beside the name (`service_addr`).
  - Kubernetes-aware identity (`namespace/workload`, `svc:namespace/service`,
    `node:name`) is implemented and tested against a fake API server only;
    not yet validated on a real cluster.
- CI coverage:
  - Multi-kernel coverage is a smoke layer, not complete feature validation.

## Not Done

- IPv6 capture
- Kubernetes identity validated on a real cluster (and for IPv6 pods)
- Broad TLS library support beyond the current OpenSSL and partial Go paths
- Full runtime hot-reload for all tunable settings
- Complete connection-state cleanup on process exit
- Tamper-evident audit logging
- Production-grade Kubernetes hardening and policy guidance

## Out Of MVP Scope

- Production deployment guarantees
- Windows support
- Real-time dashboard UI
- Full APM or profiling features
- Replacing service meshes or acting as an inline proxy

## What To Read Next

- Public entrypoint: `README.md`
- MVP release boundary: `docs/adr/ADR-013-mvp-release-scope-and-test-contract.md`
- Limitations and constraints: `docs/adr/ADR-009-known-limitations.md`
- Protocol notes: `docs/protocol/README.md`
- Integration harness: `tests/integration/`
- TLS harness: `tests/e2e/README.md`
