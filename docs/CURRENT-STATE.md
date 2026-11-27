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
  PII values in the export (`tests/oracle/run_protocols.sh`; on 7.0, 6.8,
  RHEL 9 and RHEL 8 on 2026-11-21; on 5.15 the other protocols were 100%
  that day and gRPC 0%, fixed on 2026-11-22: 100% in three of three runs
  on 5.15, two of two on 6.8 and on 7.0, and three of three on RHEL 8 on
  2026-11-26, each call `grpc` with its path in both views). The 5.15 failure: the gRPC
  server writes its SETTINGS on accept, and there it reached the agent
  before the client's preface, which the agent read as a connection it
  had joined late. A server preface at its stream's start is now read as
  HTTP/2 and the client's preface after it starts the connection.
  PostgreSQL
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
  (`tests/oracle/run_modes.sh`, kernel 7.0; on 7.0, 6.8, 5.15 and RHEL 9
  with `cgroup_skb`, where the Redis AUTH / HELLO and Kafka ApiVersions
  legs count 600 records for 300 operations: one per socket, client and
  server, both on the node).
- The capture-scope settings are checked the same way, with every sink on
  (`tests/oracle/run_sampling.sh`, on 7.0, 6.8, 5.15, RHEL 9 and RHEL 8,
  2026-11-21): `pid_filter` naming the
  HTTP and TLS servers captures their TLS exchanges in full (600 of 600)
  and nothing of the TLS client process; their HTTP exchanges in full
  under both `pid_filter_listener` settings: under the default
  `"acceptor"` the bytes before `accept()` are held in the kernel and
  sent once the listed server accepts (every server connection from offset
  0 and 600 of 600 HTTP exchanges with method and path on 7.0, 6.8, 5.15
  and RHEL 9 on 2026-11-22 and on RHEL 8 on 2026-11-26, against 85 of 85
  connections past offset 0 and no path before).
  Naming an unrelated process exports nothing and leaves none of 6,440
  planted values in any sink; its servers' pre-accept bytes are held
  and discarded in the kernel.
  `connection_sample` at 0.0, 0.5 and 1.0 kept 0, 82 to 110 and 192 of
  192 sockets (each connection is seen at its client and its server
  socket), never part of one. `head_only` kept no direction past its
  limit, captured every connection's first request, and left none of
  4,506 values planted past the limit in any sink. `cgroup_filter`
  selecting both servers captures them in full (600 of 600; not on RHEL
  8, where it is refused). The kernel scope rules are also checked on
  the five kernels by `tests/oracle/run_scope.sh`,
  `tests/oracle/scope_lab.py` and the `scope_attach` lab test.
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
  matches TC's throughput, recall (counted by path, before connections
  that lost their first bytes were held unproven: see below)
  and agent CPU at 64 keep-alive connections, and at 1K uses slightly less agent CPU
  than TC with no kernel ring drops (records are sized to what they carry),
  at 1.4-1.8x TC's kernel time per request. Unscoped, it also captures
  both ends of node-local connections, about twice the events and agent
  CPU; node-local packets (127/8, the host's own address, and sockets
  seen on a VRF device) only with
  `capture_loopback = true` (default false; it covers packets only: TLS
  plaintext over loopback is scoped by process either way). IPv6 is not
  captured. Large TCP packets (GSO, TSO, GRO) are captured in 4 KiB records
  up to `max_packet_bytes` (default 16384, at most 65536); bytes past it
  are counted, not captured. That costs kernel time in the sending
  application and ring space: at 200 KB bodies on 200 connections (7.0,
  16 vCPUs) nothing is lost at 2,000 requests/s at any setting, but at
  full rate the application completed 974K requests at 16384 and 595K at
  65536 (1.09M before), and the export kept 34% and 15% of exchanges (79%
  before) (BENCHMARKS.md, "Large packets"); a node moving bulk data at
  line rate should set 4096 or scope the capture. Connections of every
  protocol but HTTP/1.1 (AMQP, Kafka, HTTP/2, gRPC, PostgreSQL, MySQL,
  Redis, DNS over TCP) capture whole packets, up to 64 KiB, whatever the
  setting (`raise_packet_cap`, default on, USER-GUIDE §4.2): their parsers
  lose frame sync on a cut that crosses a message boundary, which a large
  packet of those protocols usually holds. The kernel reads that
  per-connection cap after the scope decision, so it only adds bytes of
  in-scope sockets' large packets (exported subject to the privacy mode
  and body cap); HTTP/1.1 throughput at 200 KB bodies is unchanged
  (BENCHMARKS.md, "Per-connection packet cap").
  `pid_filter`, under the default `pid_filter_listener = "acceptor"`,
  holds the bytes a connection receives before `accept()` returns in the
  kernel and sends them, from offset 0, once a listed process accepts it
  (an unlisted acceptor's are discarded there), on any listener, also one
  that predates the agent. The hold keeps two packets (4 KiB each) per
  connection within a node-wide budget (`preaccept_hold_bytes`, 16 MiB)
  shared with every server, listed or not, by listener (local address
  and port): each listener may always take its share (1 MiB, 64
  connections) and, past it, an overflow pool all listeners share
  (8 MiB). So one server's slow or unaccepted connections, from any
  client, take at most 9 MiB and drop the rest (`pending_overflow`),
  and other listeners keep their shares; it takes eight such listeners
  on the node, each with 64 connections waiting, to spend the budget,
  and listed servers then lose their pre-accept bytes until those
  connections are accepted or closed.
  It does not hold data carried by the handshake (TCP Fast Open). It is
  off when its program does not load or install (pre-accept bytes
  dropped, `pre-accept hold unavailable` logged); without the accept
  hook (loaded in neither variant, or not attached) it is off and
  `"acceptor"` selects no accepted connection at all. Bytes past
  those limits are dropped and counted (`pending_overflow`,
  `pending_race`; a held packet's bytes past 4 KiB in
  `panopticon_capture_truncated_total`). When a connection's first bytes
  are lost, a protocol where the client speaks first keeps that
  connection's parser in its unproven state for its life (USER-GUIDE
  §4.2, §5.3): HTTP/1 method and sizes, never a path; Redis error flag
  and sizes; HTTP/2 and gRPC timing and sizes; PostgreSQL the keyword at
  most, nothing when the startup message was lost. A later gap inside an
  HTTP/1 body of known length is counted, and that exchange's path and
  every later exchange are exported; a later gap elsewhere in an HTTP/1
  stream unsyncs the connection from there, and other protocols follow
  their own lost-byte rule (USER-GUIDE §5.3). A thread already blocked in `accept()` when the
  agent attached never releases its connections' holds: they stay
  charged to the budget until close, later packets counted as
  `pending_overflow`. Under
  `"creator"` nothing is held: a listed acceptor on a listener that
  predates the agent, or one an unlisted process created, loses its
  bytes before `accept()`. Recall figures in BENCHMARKS.md measured
  before the hold (56.6% with a new connection per request, 100% with
  keep-alive connections) are kept as measured. `cgroup_filter` /
  `pod_filter` has none of these limits. Under
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
  - 5.8+ is the supported floor. The messaging, protocol and TLS oracles
    (`run_messaging.sh`, `run_protocols.sh`, `run_tls.sh`) pass on 5.15,
    6.8 and 7.0, and on RHEL 8.10 (2026-11-26, at the default config); the
    program matrix (`scope_attach`) loads on those and RHEL 9.8 (also
    loaded on 6.18).
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
    `max_packet_bytes`. At the default 16384 that was not enough here: one
    broker-to-consumer packet in about 300 is 23 KB, was still cut, and
    deliveries at seed 7 were 27-63% in four runs (139/139 in one run at
    seed 42), and 20.8% (58/279) and 25.4% (71/279) in 500-operation gate
    runs on 2026-11-21 and 2026-11-26; 32768 still missed packets over
    32 KB in two of five runs, and only 65536 captured every run whole
    (BENCHMARKS.md). Since 2026-11-26 AMQP connections (and every protocol
    but HTTP/1.1) capture whole packets at the default (`raise_packet_cap`,
    USER-GUIDE §4.2): 279/279 deliveries in 17 of 17 messaging-oracle
    runs on 8.10 at the default, nothing truncated, 2-8 packets over
    16 KiB captured whole in 15 of them; the oracle runs every leg at the
    default on every kernel.
    Kafka `Fetch` at 16384 was 100% in three of four runs (seeds 7 and 42)
    and 96.5% in one (no truncated packet, no ignored segment, no reorder
    gap), and at 65536 100% in five of six runs; the sixth, 94.9%, lost no
    bytes: its
    13 missing records were in one Fetch response of about 20 records,
    whose exported text ends at the per-exchange body cap (`max_body_bytes`,
    default 4096, an export limit kept on purpose). On a slow node, where
    records pile up in one fetch, records past that cap are not exported.
    In two 500-operation gate runs at 32768 (2026-11-21, seed 7) `Fetch`
    was 99.5% and 97.2% (Kafka 99.7% and 98.4%, the second below the 99%
    bar; 99.8% at 16384 in the same gate). Rerun with counters and the
    export kept (2026-11-26, 500 operations, seed 7, 32768): at the
    default `max_body_bytes` 4096 `Fetch` was 100%, 96.8% and 100% (Kafka
    98.1% in the second run, below the bar), at 65536 100% in three of
    three. The 96.8% run lost no bytes: kernel ring drops, truncated
    packets, reorder gaps, parser errors and every other drop counter 0.
    Both views miss the same 14 records, all in one 12,706-byte Fetch
    response of four topics whose exported text is cut at 4,096 bytes
    inside a record value (the partial value dropped): the body cap
    again. No counter marks a body-cap cut, so this rests on the export
    and the zero loss counters. Whether a run reaches the cap depends on
    how many records the slower VM lets pile up in one fetch; it is not
    capture loss. Kafka consumers that need every record exported should
    raise `max_body_bytes`. Since 2026-11-26 the messaging oracle scores
    `Fetch` against the configured cap: a record after the cut of the
    response that carried it is reported as "past body cap", apart from
    recall, when the leg's loss counters (ring drops, reorder gaps,
    truncated captures, parser errors, channel, export-queue and
    rate-limit drops) are all zero; any other missing
    record, and every one in a leg with any loss, is still lost
    (BENCHMARKS.md, Kafka, AMQP, DNS). Rescored that way the 96.8% run is 419/419 with 14 past
    body cap.
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
  - Each container of an image is attached separately (no overlay
    dedupe: matching an overlay file to its image layer inode cannot be
    proven from user space, and a wrong match hid another file's
    probes). A shared image file then carries one copy of each probe per
    container; the probes that emit at the hit are deduplicated in the
    kernel by attach cookie (tls_probes.rs `first_copy`), and a real call
    repeated with identical bytes is kept. Validated by the lab matrix
    (`tls_probe_copies_emit_once`) on 7.0, 6.8, 5.15 and 5.14 (RHEL 9), and
    with two server containers and a client container of one Go image:
    100% of 300 HTTP/1.1-over-TLS exchanges in both views, no duplicate
    (9.0% client and 41.3% server before, on 7.0), and gated since by
    `tests/oracle/run_overlay.sh` on 7.0, 6.8, 5.15 and 5.14 (no duplicate,
    no unmatched record, HTTP/2 one record per exchange). Kernels without attach
    cookies (upstream before 5.15, such as 5.10 on Debian 11 or Amazon
    Linux 2, and RHEL 8's 4.18; RHEL 9's 5.14 has them) would export those
    records once per copy, so there each attach also records the inode
    its probes landed on, as the kernel shows the agent's own mapping of
    the attach descriptor, taken after the attach and only if the file is
    unchanged by then (proc_scanner.rs `landed_inode`); a container whose
    process maps that inode is not attached again (`Attached::covers`).
    On RHEL 8.10 (`tests/oracle/run_overlay.sh`, the same two-container
    case, 2026-11-22 and again on the merged build on 2026-11-26): 100% of
    300 HTTP/1.1 exchanges in both views, no duplicate and
    no unmatched record, and HTTP/2 one record per exchange (before: 6.7%
    and 12.7% client, 37.7% and 39.7% server, 92 and 99 duplicates, in two
    runs). Each mount is still attached, and OpenSSL writes with an
    unrestricted capture scope, Go reads and unguarded Go writes are
    exported once per copy, where such a kernel's maps show an overlay's
    own inode instead of the one behind it (as the Ubuntu kernels do; none
    without attach cookies was measured) or the file changed during the
    attach. Upstream kernels before 5.15 name the inode behind an overlay
    file in their maps, as RHEL does, but were not measured. Parsers on
    TLS keys export nothing more from repeated records than from the
    records alone (`protocol/dup_tests.rs`).
  - A file is recorded as attached under its whole identity (device,
    inode, mtime, size and ctime) and the device and inode of the
    process's mapping (proc_scanner.rs `target_file_id`): an overlay file
    copied up (chmod, touch, open for writing) to a new upper inode, or a
    recycled device and inode number, is attached again. The lab matrix
    (`tls_copied_up_file_attached_again`) shows the mechanism on the five
    lab kernels; the agent was run on one container of a Go image copied
    up under it, on 7.0 (the new server's view 0 of 300 exchanges before,
    100% in both views now), and by `run_overlay.sh` (copyup) on all five
    lab kernels. Each new key adds a copy of each probe: on
    RHEL a process still mapping the lower inode adds a second copy on the
    upper one, and a chmod alone adds one. Without attach cookies (RHEL 8)
    the attach after a copy-up records the upper inode it landed on, which
    covers the processes mapping that inode: on 8.10, 100% of 300
    exchanges in both views, no duplicate (before: 7.3% and 9.3% client,
    39.3% and 41.7% server, 95 and 100 duplicates, in two runs). A ctime
    change without a copy-up (a chmod of a host library already attached)
    still adds a copy there, whose records are then exported twice. Not
    covered (ADR-014):
    a process that mapped the lower file before the copy-up, if the agent
    had not attached it by then (no path reaches that inode); a copy-up
    between the attach check and the attach (the lower inode's processes
    stay unprobed); a FUSE file in a user namespace on a recycled
    anonymous device, which can forge an attached key on kernels whose
    maps show the overlay's inode (needs `/dev/fuse` and user namespaces,
    denied by default Docker and Kubernetes); copies that grow with every
    ctime change, whose cookies repeat past 63 on one uprobe; and a
    process still running a deleted (replaced) library, skipped until it
    restarts.
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
    RHEL 8, where `cgroup_filter` is refused); `run_tls.sh` gates
    recall in both views for the `openssl` and `go` (HTTP/1.1) stacks
    (docs/BENCHMARKS.md §7). A `Write` whose entry probe fires again
    (Go's stack-growth prologue) is emitted once. Every TLS connection
    starts latched (nothing proves a TLS record is its connection's
    first), so HTTP/2 over TLS decodes no headers: both `go-h2` stacks
    are gated on no raw PII in the export, no record matching a request
    (its path decoded) and no path, status, content type or header on
    any record (`score.py --withheld`), and their recall is reported
    only.
    Record reads in flight at once are
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
    (blind forgeries) are ignored, and an RST counts only when its own
    sequence number (not moved by a SYN flag, not trimmed) is the next
    expected byte, or, after that side's FIN, the FIN's number. Bytes the agent never saw are skipped as a gap, up to
    8 MiB ahead, or further once the peer acknowledges them.
  - TCP and IP checksums are not checked by the agent. Whether a segment
    with a bad checksum reaches the capture hook before the kernel discards
    it has not been measured on `cgroup_skb` (on TC it did: such a segment
    was parsed and the genuine retransmission dropped as a duplicate).
    Forging one needs the connection's current sequence numbers (an
    on-path attacker).
  - Reordering is bounded: a segment that arrives ahead of the next
    expected byte is held, with the rest of its connection's records, for
    at most 5 ms (128 KiB per connection, 1,024 records per worker) until
    the missing bytes arrive. This covers the chunk records of two packets
    of one socket captured on two CPUs at once. Past those bounds it is
    taken as a gap, and an earlier segment arriving later is ignored
    (`panopticon_tcp_reorder_gaps_total`). The kernel's
    stream offset places each direction's first byte. A connection is
    keyed by its socket, so a new connection on a reused 5-tuple is a new
    socket with no state from the old one.
- Protocol depth:
  - PostgreSQL COPY, gRPC schema decoding and compressed messages are not
    parsed. MySQL statements prepared before the agent started are
    reported as `EXECUTE` without their SQL, and so is a PostgreSQL
    `Bind` of a statement whose SQL the agent does not know (prepared
    before capture, or forgotten). Each `Execute` is paired with its own
    answer, also under one `Sync`; FunctionCalls are tracked. PostgreSQL
    error and notice text is never exported: an error adds only its
    SQLSTATE and severity. PostgreSQL bound values are not exported on a
    connection the agent joined mid-stream or did not see from its first
    byte, after lost server bytes, or after a client message the parser
    does not model (for the rest of the connection), nor after an answer
    that matches nothing until a `ReadyForQuery` that can be attributed
    (exactly one group waiting). After lost server bytes the SQLSTATE
    goes too. Where the client stream is unproven (joined mid-stream,
    client bytes lost, a TLS key, an unknown client message) records
    keep the statement keyword only: a message found there may be a
    header inside a `Bind` value.
    A simple Query forgets the unnamed statement, and SQL
    naming `PREPARE`, `DEALLOCATE` or `DISCARD` (simple Query or `Parse`)
    forgets every statement. Known limit: a server-side function that
    runs `PREPARE` / `DEALLOCATE` dynamically redefines a statement
    unseen (also SQL assembled at run time); a reused statement's values
    then need a `CommandComplete` of the same command word, which misses a
    same-command redefinition (USER-GUIDE §5.3).
  - HTTP/2 headers are not decoded on a connection the agent did not see
    whole: one already open when the agent started, a side whose start
    was not captured, or one whose parser restarted after lost bytes; a
    later client preface on it does not lift this. Over TLS no
    connection counts as seen whole: every TLS key (OpenSSL and Go)
    starts latched, so HTTP/2 and gRPC over TLS export no headers. The
    same latch costs Redis over TLS its command and reply text, AMQP
    over TLS its text, and PostgreSQL and MySQL over TLS all but the
    statement keyword (a packet on the key may be framed from inside a
    bound value). HTTP/1.1 and Kafka over TLS are not latched (HTTPS
    paths and Kafka records stay readable) but follow TLS rules: an
    HTTP/1.1 path with any credential word is withheld (no bare name),
    and Kafka Metadata names topic IDs on its own connection only; DNS is
    never parsed over TLS (no DNS-over-TLS decoding, and a TLS key on port
    53 is not read as DNS).
    Integrity limit: a TLS key first seen mid-connection or a lost TLS
    record can misattribute HTTP/1.1 replies, let bytes from inside a
    message be read as one, and (open, review finding) export the rest
    of an HTTP/1.1 body whose start was lost as the whole body
    (USER-GUIDE §5.3).
    Detecting a lost record per TLS key, like proving a TLS connection's
    start, is a separate design. The bodies of such an HTTP/2
    connection are not exported either, whether or not credential
    masking is on.
  - Kafka, AMQP and DNS are scored against ground truth
    (`tests/oracle/run_messaging.sh`; Kafka `Fetch` records past the body
    cap are reported apart as "past body cap" when the leg lost nothing,
    and every leg prints the
    agent's loss counters and `raise_packet_cap` counters). Compressed Kafka record batches are
    not decoded, and Kafka is recognised on port 9092 only.
  - Pairing and late joins (USER-GUIDE §5.3). MySQL error text is never
    exported: an error adds only its code and SQLSTATE. MySQL replies
    pair with commands only for commands whose replies are modelled
    (multi-result queries, `CALL` and `LOAD DATA LOCAL INFILE` are one
    exchange each); after any other command (`COM_CHANGE_USER`,
    `COM_STMT_FETCH`, a cursor `EXECUTE`, replication, unknown), a reply
    out of sequence or unsolicited, on a connection joined mid-stream,
    or on a TLS key, records keep only the statement keyword (a closed
    set of SQL verbs) for the rest of the connection; a TCP connection that switches to TLS or compression is not parsed past
    the switch. HTTP/1 pairs pipelined requests in order and frames
    `1xx`, `HEAD`, `204`/`304`, `CONNECT`, `Upgrade` and close-delimited
    responses per RFC 9112; on a connection joined mid-stream
    (TCP only; TLS has the integrity limit above), after bytes it
    cannot place, ambiguous framing or a response with no request
    waiting, records keep only a known method and sizes. Kafka pairs by
    correlation ID (`acks=0` Produce shifts nothing); a late join, a
    reused pending correlation ID or `SaslHandshake` v0 leaves only a
    known API name and the sizes (no `api_version`; an unknown key is
    `Unknown`). Unsynced AMQP keeps known method names and reply codes
    only. DNS pairs by ID and name; a late parser
    reads only whole datagrams, and a DNS-over-TCP connection joined
    mid-stream exports no name, record, status or answer. After an
    agent restart, connections open before it (keep-alive clients,
    pools, producers) export method or statement keyword only until
    they reconnect; verified on Linux for
    HTTP/1.1, MySQL, PostgreSQL and Kafka. gRPC/HTTP/2
    pair by stream ID.
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
    credential commands are masked before the same rule (so `AUTH` stays
    readable, while `CONFIG GET requirepass` is withheld). A credential word that is a bare name is not credential
    context, by an allowlist tied to the field's kind: in an HTTP/1 or
    HTTP/2 request path, the last segment of a captured path part
    (before any `?` or `#`) of ASCII letters-only segments, any query or
    fragment after it replaced by `?<query withheld>`; in a MySQL or PostgreSQL statement, a projection item of
    `SELECT item, … FROM table [rest]` read on its raw tokens, each item
    `*` or a plain identifier (not a value keyword such as `TRUE`) and
    no credential word from the table on
    (exported without bound values). No other field has a
    bare name, nor does an HTTP/1.1 path over TLS; anything outside the
    allowlist is withheld as before.
    Short credential names are also matched with `.` and `-` as
    boundaries (`users.pwd`), and as a segment of a name split at `_` and
    at case and digit boundaries (`old_pwd`, `newPwd`, `card_pin`,
    `sms_otp`; a segment ending in `pin` or `otp`, `cardpin`, `smsotp`,
    `mpin`, and `pwd` anywhere, `x-newpwd`, as lowercased header names
    arrive; not `spinner` or `pinned`, and no plural); two-word
    credential parts match camelCase too (`privateKey`, `accessKey`,
    `clientAssertion`), in bodies, header names, form and query names and
    SQL columns alike. A name in a position that delimits it (JSON member,
    form or query parameter, `name="…"` field, XML element) is read whole,
    `-` and `.` included (`{"pin-code":"7392"}` is masked,
    `name="old-pwd"` and `<ns:newPwd>` withhold); once a field's certain
    clauses are masked, a credential name left in such a position or any
    word with a short name as a segment withholds it. In a field with no
    other context, free text with a short name before a `-` or `.` is not
    a name (`pin-code: 7392` alone is exported, as a host and port
    `auth-service:8080` must be). A URI password before an empty host
    (`postgres://u:pw@/db`) is masked. A letters-only segment before the word
    (`/reset/abcdef/token`) is a known limit.
    Redis reply text is never exported: a reply is exported as its type
    and size only (`(bulk, 6 bytes)`, `(array, 3)`, `(error)`), a status
    only when it is a fixed protocol word (`OK`, `PONG`, `QUEUED`, ...).
    A reply is paired with its command only on connections seen from
    their first byte (the kernel's stream offset, no bytes lost): not on
    connections open before the agent started, nor over TLS. After
    `MONITOR`, `SYNC`, `PSYNC` or `REPLCONF`, or a request that is not a
    RESP array, nothing more is exported for the connection.
    A Redis command with credential context in any argument, or with any
    argument (key, name or value, of any command) containing a credential
    word or a short name as a whole segment, plural `s` included
    (segments split on every character that is not an ASCII letter or
    digit and at case and digit boundaries: `user:1:otp`, `u|otp`,
    `pinCode`, `OTPCode`, `otp2`, `sessions`; not `mykey` or `otpcode`), is
    withheld as one unit (key, arguments and the reply's shape), so `SET otp:<id> <code>`, `SET otp <code>`,
    `HSET u:1 pin <pin>`, `EVAL <script> 1 otp` and `XADD s * otp <code>`
    export no value. A value that only mentions a credential word
    withholds its command too.
    Bodies with bytes kept after a capture gap (HTTP/1, HTTP/2 and AMQP
    message bodies; a cut end keeps its prefix), any AMQP text (path,
    headers, body) of a direction after it lost frame sync, for the rest
    of the connection, and of both directions of an AMQP connection the
    agent did not see from its first byte, HTTP/2 headers after a lost HPACK block or on a connection
    the agent did not see whole (and HTTP/2 bodies on such a connection,
    whether or not masking is on, until a new connection is observed
    from its start, never over TLS; with masking on, also bodies whose
    content type is repeated or over 256 bytes),
    over-long header names and gRPC/protobuf body text are not exported;
    PostgreSQL bound values are exported only under the SQL their
    statement had when the Bind was sent, once confirmed, even if it is
    redefined later (SQL naming `PREPARE`, `DEALLOCATE` or `DISCARD`
    forgets every statement, a simple Query the unnamed one; a reused
    statement needs a `CommandComplete` of the same command), and not at
    all on a connection joined mid-stream, after lost server bytes or
    past 4096 messages awaiting an answer, nor after an unmatched answer
    until an attributable `ReadyForQuery`; PostgreSQL error text is never
    exported (SQLSTATE and severity only);
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
