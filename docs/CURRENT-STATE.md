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
- Capture is by `cgroup_skb` programs on the host's cgroup v2 root, the
  only backend: every local socket, in every network namespace, with every
  scope decision made in the kernel per socket
  ([ADR-014](adr/ADR-014-cgroup-skb-capture-scope.md); its trade-offs are
  listed in docs/USER-GUIDE.md §4.2, "Capture scope"). The TC backend, which
  captured on network interfaces, was removed. The ground-truth accuracy,
  load and overhead figures below were measured with TC unless they say
  `cgroup_skb` or name the scope tests, and have not been re-run since.
- HTTP/1.1 capture is scored against a ground-truth traffic generator on a
  veth (server-side view, keep-alive, chunked and >4KB bodies): 100% recall
  across 15,000+ exchanges (`tests/oracle/`, see `BENCHMARKS.md`).
- Redis, PostgreSQL (simple, extended, prepared), MySQL (text protocol
  and prepared statements, plaintext) and gRPC are scored the same way:
  100% recall, PII flagged in every request that carried it, and no raw
  PII values in the export (`tests/oracle/run_protocols.sh`). PostgreSQL
  was re-measured on 2026-11-21 after large packets were captured in
  several records: 100% at the default `max_packet_bytes` 16384 (seeds 7
  and 11 on 6.8) and at 65536 (seeds 7, 11 and 23 on 6.8, seed 7 on 7.0);
  before that, a 500-row
  result cut at the 4 KiB per-packet window cost the bound values of the
  rest of the connection (83.8-84.6%, PII in 38-42%).
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
  the limit in any sink. Not yet run on 5.15 or the RHEL kernels. Measured
  when TC was the default backend; the kernel scope rules are checked on
  five kernels by `tests/oracle/run_scope.sh`, `tests/oracle/scope_lab.py`
  and the `scope_attach` lab test.
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
  (docs/BENCHMARKS.md, scaling study). These figures are for the TC
  backend (removed; historical).
- The `cgroup_skb` capture (the only backend) is measured on five kernels
  (preliminary), against TC in the same runs: scoped by `pid_filter`, it
  matches TC's throughput, recall
  and agent CPU at 64 keep-alive connections, and at 1K uses slightly less agent CPU
  than TC with no kernel ring drops (records are sized to what they carry),
  at 1.4-1.8x TC's kernel time per request. Unscoped, it also captures
  both ends of node-local connections, about twice the events and agent
  CPU; node-local packets (127/8, the host's own address, and sockets
  seen on a VRF device) only with
  `capture_loopback = true` (default false; it covers packets only: TLS
  plaintext over loopback is scoped by process either way). IPv6 is not
  captured. Large packets (GSO, TSO, GRO) are captured in 4 KiB records
  up to `max_packet_bytes` (default 16384, at most 65536); bytes past it
  are counted, not captured. That costs kernel time in the sending
  application and ring space: at 200 KB bodies on 200 connections (7.0,
  16 vCPUs) nothing is lost at 2,000 requests/s at any setting, but at
  full rate the application completed 974K requests at 16384 and 595K at
  65536 (1.09M before), and the export kept 34% and 15% of exchanges (79%
  before) (BENCHMARKS.md, "Large packets"); a node moving bulk data at
  line rate should set 4096 or scope the capture.
  `pid_filter` matches TC's
  recall only for a server whose listener was created after the agent
  started, with `pid_filter_listener = "creator"`; under the default
  `"acceptor"` every listener loses the bytes before `accept()`, like a
  pre-agent listener. On a listener that predates
  the agent (any server not restarted since), a connection is captured from
  the moment a listed process accepts it, and earlier bytes are dropped:
  56.6% recall with a new connection per request (TC 100%), 100% with
  keep-alive connections. Use `cgroup_filter` / `pod_filter`, which has
  no such gap, or `pid_filter_listener = "creator"` with the server
  restarted after the agent. Under
  `"creator"`, a listener created by a listed process selects every
  connection accepted on it, also by processes not in the list; under
  `"acceptor"`, only what listed processes accept (docs/USER-GUIDE.md).
  Both settings change on reload. `pod_filter` takes a pod's cgroup only
  from where kubelet makes it (a top-level kubepods root and its
  `burstable` / `besteffort` level, either cgroup driver), with every
  directory on the way owned by root and not group- or other-writable,
  plus `pod_cgroup_root` when an operator names a custom kubelet cgroup
  root (inside a recognised root too: a pod reached twice counts once);
  a pod with no such directory, or with several, is not captured, logged
  as an error once per pod and reason and counted, on every
  re-resolution, in `panopticon_pod_filter_unresolved_total{reason}`.
  Static pods are not supported (kubelet names their cgroup by the
  manifest's hash). Replay (`--replay-bench`) refuses every
  scope setting. The `client_pid` / `server_pid` export fields, filled
  from TC's connect / accept probes, are gone; packet events in the raw
  dump carry the kernel's `owner_tgid` / `acceptor_tgid`.
- All parsers are fuzzed with libFuzzer (`fuzz/`): 16M+ executions without a
  crash after the fixes in this release.

## Partial

- Linux kernel support:
  - 5.8+ is the supported floor. Full accuracy suites pass on 5.15, 6.8 and 7.0 (also loaded on 6.18).
  - RHEL 8 and 9 are supported: their 4.18 and 5.14 kernels carry the BPF
    ring buffer and 5.5+ probe-read helpers. Measured on Rocky Linux 8.10
    (4.18.0-553) and 9.8 (5.14.0-687), SELinux enforcing with no AVC denials
    (agent run as root from an unconfined shell): HTTP, HTTPS, Redis,
    PostgreSQL, MySQL, gRPC, Kafka and DNS at 99.4-100% recall
    (2026-11-04, before the PostgreSQL bound-value rules of 2026-11-13;
    see the PostgreSQL oracle above for current figures) with no raw PII
    exported (Kafka on 8.10: see below), every TLS exchange carrying its
    socket addresses (via fentry).
    The agent probes the ring buffer by creating one rather than trusting the
    version number; before that, RHEL 8 fell to the PerfEventArray path and
    captured nothing.
  - RHEL 8.10: AMQP `Basic.Deliver` recall was 17-35% in the CI messaging
    oracle (300 operations, seed 7) until 2026-11-20. The broker-to-consumer
    stream there carries GSO packets of up to 13-24 KB, each holding
    several deliveries, and each packet was captured as one record cut at
    4 KB; the parser lost frame sync and the consumer direction stopped
    exporting AMQP text (fail closed, USER-GUIDE §5.3). Not a ring or
    helper limit: no ring drops, no failed loads. Large packets are now sent
    as consecutive 4 KB records with exact stream positions, up to
    `max_packet_bytes`. At the default 16384 that is not enough here: one
    broker-to-consumer packet in about 300 is 23 KB, is still cut, and
    deliveries at seed 7 were 27-63% in four runs (139/139 in one run at
    seed 42). At 32768 deliveries are 164/164 in three of three runs at
    seed 7, and at 65536 in six of six, with nothing truncated (see
    BENCHMARKS.md). AMQP consumers on RHEL 8 should set
    `max_packet_bytes = 32768` (USER-GUIDE §4.2).
    Kafka `Fetch` was 100% at 16384 (two runs at seed 7, one at seed 42)
    and at 65536 in five of six runs; the sixth, 94.9%, lost no bytes: its
    13 missing records were in one Fetch response of about 20 records,
    whose exported text ends at the per-exchange body cap (`max_body_bytes`,
    default 4096, an export limit kept on purpose). On a slow node, where
    records pile up in one fetch, records past that cap are not exported.
    RHEL 9 passed (100%, one earlier run at 85%); measured before the AMQP
    fail-closed change and not re-run since.
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
    found. A workload's mapped file is first pinned without being opened
    (`O_PATH`, resolved inside the workload's own root with `openat2`; a
    kernel without `openat2` gets no workload file opened, and every lab
    kernel, RHEL 8.10 included, has it), and that same file is opened for
    reading only if it is a regular file; a mapping whose file was deleted,
    or whose process root the agent cannot use, is skipped. A FIFO or
    device put at a mapped path is refused without being opened, so it can
    neither hang the agent nor run a driver's open.
  - TLS exchanges carry their socket addresses and join the service graph:
    validated via the `sock_send/recv_length` tracepoints (kernel 6.3+) and
    via the fentry fallback (RHEL 8 and 9); the kprobe fallback for kernels
    without BTF is not validated yet.
  - Go `crypto/tls` reads and writes, for binaries whose build information
    (`.go.buildinfo`) shows the gc toolchain at Go 1.18+, `GOARCH` amd64 or
    arm64 matching the node, and the register ABI not turned off by a
    `GOEXPERIMENT`; any other Go binary gets no Go probe at all. Received
    plaintext is taken per TLS record as `(*halfConn).decrypt` returns it,
    decrypted in place in the connection's own input buffer, never from the
    caller's `Read` buffer, whose lifetime a probe cannot establish. The
    entry of `(*Conn).readRecordOrCCS` names the connection, keyed by
    goroutine and process instance (no uretprobe: Go moves goroutine stacks,
    so returns are probed at their `RET` instructions). A record that
    decrypts as application data but that the connection then refuses (sent
    before the handshake completed) is still emitted. Validated on kernels
    7.0, 6.8, 5.15, RHEL 9 and RHEL 8 (`scope_attach` `go_tls_reads`:
    records captured byte-exact over TLS 1.3 and TLS 1.2 with AEAD and CBC
    suites, including while the reader's stack moved; nothing from an
    out-of-scope process, after a narrowing or after capture is switched
    off; no slots left after goroutine churn or process exit) and with the
    scope oracle
    (`tests/oracle/run_scope.sh`: 100% of reads from both processes in
    unscoped `full`, `pid_filter` and `cgroup_filter`, the last not on
    RHEL 8, where `cgroup_filter` is refused); `run_tls.sh` scores 100%
    recall in both views for the `go` and `go-h2` stacks in 30 runs of
    seeds 42–51 (Go 1.22.2 and 1.25.4, kernel 7.0, docs/BENCHMARKS.md),
    after two fixes: a Go connection's first handshake now starts a new
    connection on a reused `*tls.Conn` key (`go-h2` scored 56.6% / 41.6%
    without it), and a `Write` whose entry probe fires again (Go's
    stack-growth prologue) is emitted once. The measured server starts
    after the agent attached its binary: a server already running keeps
    reused keys latched (USER-GUIDE §5.3). Record reads in flight at once are
    capped at 65,536 node-wide (a goroutine parked waiting for a record on
    an idle keep-alive connection holds one); past that, further reads are
    not captured until some return; likewise past 8,192 processes doing Go TLS reads at once
    (new ones are not captured until some exit). Reads in flight when their process's main thread exits, or
    when it execs, are not captured. Go TLS events carry no socket address
    under a restricted capture scope. Binaries built with `-s` (no symbol
    table) are not found; arm64 is untested. Reads need `readRecordOrCCS`
    and `decrypt` as functions of their own: a build where the compiler
    inlined them (possible with profile-guided optimisation) or that lacks
    their symbols has its reads lost, never wrongly attributed; its writes
    are unaffected.
- TCP stream integrity:
  - Each direction's next expected sequence number is tracked
    (`protocol/fsm.rs` `TcpTracker`): retransmitted bytes are parsed once,
    segments whose sequence or acknowledgment number is far from the stream
    (blind forgeries) are ignored, and an RST counts only at the next
    expected byte. Bytes the agent never saw are skipped as a gap, up to
    8 MiB ahead, or further once the peer acknowledges them.
  - TCP and IP checksums are not checked by the agent. Whether a segment
    with a bad checksum reaches the capture hook before the kernel discards
    it has not been measured on `cgroup_skb` (on TC it did: such a segment
    was parsed and the genuine retransmission dropped as a duplicate).
    Forging one needs the connection's current sequence numbers (an
    on-path attacker).
  - Segments are not reordered: one that arrives before an earlier one is
    taken as a gap, and the earlier one is then ignored. The kernel's
    stream offset places each direction's first byte. A connection is
    keyed by its socket, so a new connection on a reused 5-tuple is a new
    socket with no state from the old one.
- Protocol depth:
  - PostgreSQL COPY, gRPC schema decoding and compressed messages are not
    parsed. MySQL statements prepared before the agent started are
    reported as `EXECUTE` without their SQL, and so is a PostgreSQL
    `Bind` of a statement whose SQL the agent does not know (prepared
    before capture, or forgotten). PostgreSQL bound values are
    not exported on a connection the agent joined mid-stream or lost
    server bytes on. A simple Query forgets the unnamed statement, and SQL
    naming `PREPARE`, `DEALLOCATE` or `DISCARD` (simple Query or `Parse`)
    forgets every statement. Known limit: a server-side function that
    runs `PREPARE` / `DEALLOCATE` dynamically redefines a statement
    unseen; a reused statement's values then need a `CommandComplete` of
    the same command, which misses a same-command redefinition
    (USER-GUIDE §5.3).
  - HTTP/2 headers are not decoded on a connection the agent did not see
    whole: one already open when the agent started, a side whose start
    was not captured, or one whose parser restarted after lost bytes; a
    later client preface on it does not lift this. Over TLS a new
    connection that reuses a closed one's key starts clean only once the
    agent has seen the library create the new object: OpenSSL's `SSL_new`
    return, or the entry of a Go connection's first handshake
    (`clientHandshake-fm` / `serverHandshake-fm`; a renegotiation is
    never one). With a static or renamed libssl, `SSL_clear` reuse, I/O
    inside `SSL_new` (a creation callback), a Go binary whose handshake
    or guards cannot be probed (stripped, renamed), a Go process that was
    running when the agent started or attached its binary (the first
    process of every Go binary included: it keeps reused keys latched
    for its life), a Go connection whose handshake runs inside its first
    `Write`, a Go process that lost a guard, or when that record was
    lost, it is not decoded either. While credential masking is on its bodies are not exported
    either.
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
    protocol. Credentials are protected by withholding: a SQL statement
    with credential context is exported as its verb and `<statement
    withheld>`, without bound values; any other field with credential
    context is exported as `<field withheld>` unless each credential is a
    form parameter, a scalar JSON member or URI userinfo, whose value is
    then masked; credential-named headers are masked, and Redis
    credential commands and replies are masked before the same rule (so
    `AUTH` stays readable, while `CONFIG GET requirepass` and its reply
    are withheld: with renamed commands a reply cannot be tied to its
    request). A credential word that is a bare name is not credential
    context, by an allowlist tied to the field's kind: in an HTTP/1 or
    HTTP/2 request path, the last segment of a captured path part
    (before any `?` or `#`) of ASCII letters-only segments, any query or
    fragment after it replaced by `?<query withheld>`; in a MySQL or PostgreSQL statement, a projection item of
    `SELECT item, … FROM table [rest]` read on its raw tokens, each item
    `*` or a plain identifier (not a value keyword such as `TRUE`) and
    no credential word from the table on
    (exported without bound values or error text). No other field has a
    bare name; anything outside the allowlist is withheld as before.
    Short credential names are also matched with `.` and `-` as
    boundaries (`users.pwd`). A letters-only segment before the word
    (`/reset/abcdef/token`) is a known limit.
    Redis reply text is exported only on connections seen from their
    first byte (the kernel's stream offset, no bytes lost):
    not on connections open before the agent started, nor over TLS.
    A Redis command with credential context in its key or any argument,
    or a key or hash field name containing a credential word, or with a
    short name as a whole segment (`user:1:otp`, not `mykey`), is
    withheld as one unit (key, arguments and reply
    text, and its result inside `EXEC`), so `SET otp:<id> <code>`,
    `SET otp <code>` and `HSET u:1 pin <pin>` export no value.
    Bodies with bytes kept after a capture gap (HTTP/1, HTTP/2 and AMQP
    message bodies; a cut end keeps its prefix), any AMQP text (path,
    headers, body) of a direction after it lost frame sync, for the rest
    of the connection, HTTP/2 headers after a lost HPACK block or on a connection
    the agent did not see whole (and, while masking is on, HTTP/2 bodies
    on such a connection until a new connection is observed from its
    start, over TLS on a reused key only after the agent saw the library
    create the new object as above,
    and bodies whose content type is repeated or over 256 bytes),
    over-long header names and gRPC/protobuf body text are not exported;
    PostgreSQL bound values are exported only under the SQL their
    statement had when the Bind was sent, once confirmed, even if it is
    redefined later (SQL naming `PREPARE`, `DEALLOCATE` or `DISCARD`
    forgets every statement, a simple Query the unnamed one; a reused
    statement needs a `CommandComplete` of the same command), and not at
    all on a connection joined mid-stream, after lost server bytes or
    past 4096 retained Bind snapshots;
    only known SQL keywords are exported as methods. `[credentials]
    patterns` adds the user's own formats (masked in every field, matching
    DNS answers dropped, counted in `panopticon_credential_matches_total`;
    every rule sees the field as captured and one rule set covers a whole
    message), and `builtin = "names_only"`
    skips the free-text scan. `full` does this too, with or without PII
    detection, unless `[privacy] mask_credentials = false`.
  - Credential protection is a hard guarantee only in `metrics_only`
    (no path, header or body leaves the agent). In `redacted` and `full`
    it is best-effort defence in depth for known credential forms: it does
    not catch opaque secrets under unrecognised names, base64 `Basic`
    credentials outside `Authorization`, compressed or non-ASCII UTF-16/32
    bodies, PostgreSQL `U&` identifiers, or packets forged into a
    connection (USER-GUIDE §5.3). The leak test covers HTTP, OpenSSL TLS,
    Redis AUTH and Kafka client ids; withheld SQL statements and AMQP
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
