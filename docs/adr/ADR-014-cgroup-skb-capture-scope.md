# ADR-014: Capture With `cgroup_skb` and Decide Scope in the Kernel

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-11-14 |
| **Decision Makers** | Panopticon maintainers |
| **Affected Components** | `panopticon-ebpf` (`sock_capture.rs`, `tls_probes.rs`, `maps.rs`), `panopticon-agent` (`loader.rs`, `scope_loader.rs`, `scope_select.rs`, `scope_publisher.rs`, `event_loop.rs`, `config.rs`), Helm chart |
| **Supersedes** | The TC capture backend (`tc_capture.rs`), its owner probes (`sock_monitor.rs`) and the user-space capture gate (`capture_gate.rs`) |
| **Superseded by** | - |

## Context

Panopticon is a map of where sensitive data flows. What it may capture is
set by the operator: a process list (`pid_filter`), cgroups or Kubernetes
pods (`cgroup_filter`, `[[pod_filter]]`), and sampling (`connection_sample`,
`head_only`). Any byte captured outside that scope can reach an export, so
a scope rule that fails open is a privacy defect, not a coverage gap.

Until this decision the agent captured with TC classifiers on network
interfaces. A TC program runs in softirq on the NIC with no process and,
for forwarded or NATed pod traffic, no socket (`skb->sk` is NULL). Every
scope rule therefore ran in user space after the bytes had left the
kernel: a `pid_filter` connection passed once a connect or accept probe
had named a listed owner for its 5-tuple, packets were held until then,
and sampling and the head cut were applied per connection key. That design
had open findings that follow from it: an owner record keyed by a reusable
5-tuple could admit an unlisted process's connection (security scan F1),
the TC path published the PID list before the exit tracepoint could keep
it current (F10), and TC took packet lengths from the IP header rather
than the packet (F5). It also never saw loopback or other node-local
traffic, and needed an interface list per node.

## Decision

We capture packets with `cgroup_skb` ingress and egress programs attached,
as multi programs, to the root of the host's cgroup v2 hierarchy. There is
no other capture backend: TC, its interface selection (`interfaces`,
`--interface`, default-route detection), its owner probes, and the
user-space capture gate are removed.

Every scope decision is made in the kernel, per socket, from state kept in
a socket-local storage map and written only by kernel events: socket
creation (`cgroup/sock_create`), establishment and close (`sockops`),
accept (fexit `inet_csk_accept`) and kTLS key install. User space only
publishes the selectors (`PID_FILTER`, `CGROUP_ALLOW`) before arming, and
a single serialised publisher applies reloads; a narrowing replaces the
capture pipeline and raises an admission floor so nothing captured under
the old scope can still leave. TLS plaintext (uprobes) is scoped by the
calling process at each call, and in a restricted mode is captured only in
`full` sampling.

The one invariant: every rule errs toward not capturing under event loss,
races, missing hooks, unknown history and unexpected kernel behaviour. A
missing hook is a refusal to start, never a fallback. Every drop is counted
in `panopticon_scope_dropped_events_total{reason}`.

Removed configuration is refused, never ignored: `interfaces` and the CLI
flag `--interface` stop the agent (ignoring them would widen capture to
every socket), `[capture] backend` other than `"cgroup_skb"` stops it, and
`backend = "cgroup_skb"` is accepted with a warning. The Helm value
`agent.interfaces` fails the render. Replay (`--replay-bench`) refuses
every scope setting, since nothing would apply it to replayed events.

## Consequences

### Positive
- Scope is decided before any byte leaves the kernel; nothing out of scope
  reaches a parser, a sink or a log.
- Every local socket is seen in every network namespace with its cgroup,
  owner and stream position, with no per-node interface configuration.
- `cgroup_filter` / `pod_filter` select by a cgroup fixed at socket
  creation, so they have no accept-time gap.
- Security findings F1, F5 and F10 are removed with the code they lived in.
- Ring records are sized to what they carry; close records exist only for
  sockets that emitted data.
- The per-connection packet cap (`raise_packet_cap`: the `CONN_CAP` map,
  written by user space when it detects a protocol that loses frame sync
  on a cut packet) is read only after the verdict, for a packet over
  `max_packet_bytes`: it raises how many bytes of an in-scope socket's
  packet are captured, up to 64 KiB, and never selects a socket or changes
  a packet's attribution. Its entry is deleted at TCP close.

### Negative

These trade-offs are deliberate; each errs toward not capturing. The user
guide states them for operators (docs/USER-GUIDE.md §4.2, "Capture scope").

- **`pid_filter_listener = "acceptor"` (default) holds pre-accept bytes in
  the kernel, within limits.** An accepted connection is selected only once
  a listed process's `accept()` returns. The bytes that arrive before that
  are held in the socket's kernel storage (`PENDING`) and sent from offset
  0 when a listed process accepts it, or discarded in the kernel when an
  unlisted one does, or when it closes unaccepted: they never leave the
  kernel unless the acceptor is listed, so scope is still decided before any
  byte leaves it. The hold keeps two packets (4 KiB each) per connection
  within a node-wide budget (`preaccept_hold_bytes`, 16 MiB) that every
  server's waiting connections share, listed or not. That budget is a
  limit any remote client can reach: about 1,024 slow or unaccepted
  connections to any server on the node, listed or not, spend it, and
  listed servers' pre-accept bytes are then dropped (`pending_overflow`)
  until those connections are accepted or closed (`scope_lab.py` T-23).
  The hold does not cover data carried by the handshake itself (TCP Fast
  Open, data on the final ACK). It is off when its program does not
  load or install (pre-accept bytes dropped, `pre-accept hold
  unavailable` logged); without the accept hook (loaded in neither
  variant, or not attached) it is off too, and `"acceptor"` selects no
  accepted connection at all. A third packet, the
  budget or option memory spent, and the race at release are counted
  (`pending_overflow`, `pending_race`); a held packet's bytes past 4 KiB
  are a cut (`panopticon_capture_truncated_total`). What leaves the node
  then follows the parsers' rule for lost bytes: when a connection's
  first bytes are lost, its client-speaks-first parser (HTTP/1, HTTP/2
  and gRPC, PostgreSQL, Redis, Kafka, AMQP, DNS over TCP) stays in its
  unproven state for its life (HTTP/1 method and sizes, no path;
  PostgreSQL no record when the startup message was lost); a later gap
  inside an HTTP/1 body of known length is counted
  (`Http1Parser::skip`), so that exchange's path and every later
  exchange are exported; a later gap elsewhere in an HTTP/1 stream
  unsyncs the connection from there (closed-set values only), and other
  protocols place a gap by their own `skip` (Kafka and AMQP inside a
  frame of known length, HTTP/2 inside a DATA frame). A thread already
  blocked in `accept()` when the agent attached is never seen to
  accept: its connections' holds stay charged to the budget until they
  close, and their later packets count as `pending_overflow`.
  `run_sampling.sh` `pid_servers`: every server connection from offset 0
  and 600 of 600 HTTP exchanges with method and path on 7.0, 6.8, 5.15
  and RHEL 9 (2026-11-22) and RHEL 8 (2026-11-26), against 85 of 85
  connections past offset 0 and no path before. `"creator"` holds
  nothing; it selects every child of a listener a listed process created,
  whoever accepts it, and on other listeners drops a listed acceptor's
  pre-accept bytes. `cgroup_filter` / `pod_filter` has no such limit.
- **`pid_filter` is best-effort.** It is restart-only, names PIDs (not
  programs or process trees), cannot place sockets that existed before the
  agent started, and a thread already blocked in `accept()` when the agent
  attached never records its accepts.
- **`capture_loopback = false` (default), packets only.** Loopback and VRF
  packets are dropped; TLS plaintext of such a connection is scoped by
  process as everywhere.
- **Looped VRF multicast / broadcast is never seen.** The kernel does not
  run the capture hook for a sender's looped copy on a VRF member
  interface, whatever `capture_loopback` says.
- **IPv6 is not captured.**
- **HTTP/2 late join or loss withholds the stream.** On a connection the
  agent did not see whole (every HTTP/2 connection over TLS, below), or
  after a lost header block, headers are not
  decoded and bodies are not exported (after a lost header block alone,
  with credential masking on, bodies of unknown type), for the
  connection's life.
- **HTTP/2 content type over 256 bytes, or repeated.** With credential
  masking on, that stream's body is withheld.
- **Every TLS key starts latched.** A TLS record is keyed by the library's
  connection object (OpenSSL `SSL*`, Go `*tls.Conn`) and carries no stream
  position, so nothing in it shows that it is its connection's first: a
  key the agent first sees can be mid-connection (the agent started after
  it, its entry was evicted, records were lost, the object's address was
  reused), and a Write there can begin with bytes that look like a client
  preface. Every new TLS entry therefore starts latched, OpenSSL and Go
  alike, whatever came before it (protocol/fsm.rs `start_tls`). What the
  latch withholds depends on the parser (its `tls_unproven_start`, applied
  again to a parser that replaces the key's parser after a gap):
  - HTTP/2 and gRPC: no header is decoded (no path, method, `:status`,
    `grpc-status` or content type) and no body is exported, for the
    connection's life; records keep timing, sizes and addresses.
  - Redis: replies no longer pair with commands; each record keeps only
    its error flag, timing and sizes (no command, key, arguments or reply
    text).
  - AMQP: both directions count as unsynced; known method names, reply
    codes, timing and sizes stay, no text.
  - PostgreSQL and MySQL: untrusted, as for a late join; records keep
    the statement keyword only (a closed set of SQL verbs).
  - HTTP/1.1 and Kafka: not latched; a request path with a credential
    word is withheld (HTTP/1.1), and Metadata responses name topic IDs on
    their own connection only (Kafka). USER-GUIDE §5.3 lists the
    integrity limit this leaves.
  - DNS: never parsed. Detection never picks DNS for a TLS key
    (protocol/detect.rs `detect_tls_protocol`: the port-53 fallback would
    read a TLS key's learned port), and a DNS parser given one parses
    nothing (dns.rs `DnsParser::tls_unproven_start`). DNS over TLS (port
    853) is not decoded.

  A `TlsNew` record (`SSL_new`'s return) still ends its key's connection,
  so a new object at a reused address gets a new, latched entry. Proving
  that a key starts at its connection's first record (and so decoding
  HTTP/2 over TLS) is a separate design: each proof tried so far (a Go
  handshake boundary, process stamps with loss marks, tombstones and
  floors, an OpenSSL per-process loss mark) had a hole a reviewer could
  show. Go records still carry their `PROC_EPOCH` stamp with
  `GO_EPOCH_LOST` (tls_probes.rs `go_lose`); user space does not read it.
- **Go `(*Conn).Write` probes.** `(*Conn).Write` is probed at its entry, at the first instruction of its
  body (past the stack-check prologue: go_read.rs `body_start`, amd64
  `JBE`, arm64 `B.LS`) and at every RET, all or nothing per binary
  (otherwise the unguarded entry probe is used, which can emit a Write
  twice). The entry is emitted once per call: Go's stack-growth prologue
  (`morestack`) jumps back to the entry before the body runs, and an
  entry is suppressed only when the goroutine's innermost recorded call
  is on the same connection at the same frame depth and has not reached
  its body (tls_probes.rs `guard_call`, `go_tls_write_body`). A recorded
  call found past its body at the entry's depth ended without a RET (a
  panic): the new Write is emitted and the instance marked lost. A body
  probe that cannot read its call's `*tls.Conn` or frame depth marks the
  innermost recorded call as begun all the same, so a failed mark costs
  at most a duplicate record, never a suppressed Write.
  - Concurrent Writes on one connection are emitted at their entries,
    before `crypto/tls` takes the connection's write lock (`c.out`), so
    two that overlap may be emitted in an order other than the wire's.
    The lock keeps each Write's bytes contiguous: only whole Writes can
    swap. This is a documented limit, not a leak. HTTP/2 needs its writer
    serialised: every header block shares one HPACK state, so an
    application whose header-carrying Writes could overlap would corrupt
    its own stream for its peer too, and Go's `net/http` HTTP/2 encodes
    and writes under one lock (client `cc.wmu`; the server writes one
    frame at a time). Overlap can only swap Writes whose relative order
    the protocol leaves open, PII redaction does not depend on record
    order, and a swap that breaks parsing latches the entry.
- **Files are attached and recorded by the file examined and the inode
  mapped**: the file the agent opened inside the workload's root and read
  the offsets from, attached through that open file (`open_examined`),
  never a fresh stat of a workload path, and never forgotten. OpenSSL
  libraries and Go binaries alike. The key (proc_scanner.rs
  `target_file_id`) is the file's whole identity (device, inode, mtime,
  size and ctime: `FileKey`) with the device and inode
  `/proc/<pid>/maps` shows for the process's mapping, so a changed or
  recycled file is attached again, within the limits below. A chmod, touch or
  open for writing copies a lower-layer overlay file up to a new upper
  inode, which processes mapping it from then on run, while the probes
  stay on the lower one; overlayfs keeps the device, inode, mtime and size
  it shows. Its ctime is that of the inode behind the file, so a copy-up
  changes the key on every lab kernel; the mapping's device and inode name
  that inode too on RHEL 9 and RHEL 8, while the Ubuntu kernels (7.0,
  6.8, 5.15) show the overlay's own, unchanged. A new key attaches again,
  through the path, onto the upper inode. The lab matrix
  (`tls_copied_up_file_attached_again`, attaching by hand as the agent
  does) shows on the five lab kernels that the lower probes see nothing of
  a process started after the copy-up, that the key differs, and that a
  second attach captures it while the first process is still captured;
  the agent itself, on one container of a Go image copied up under it
  (kernel 7.0): 100% of 300 exchanges in both views, the new server's view
  0% before (BENCHMARKS). On the RHEL kernels a process still mapping the
  lower inode and one mapping the upper inode give two keys after a
  copy-up, both attached onto the upper inode: two copies there, which
  RHEL 9 deduplicates; on RHEL 8 the first of those attaches records the
  upper inode it landed on and covers the other (below). A ctime change
  alone (a chmod of a file not copied up) also adds a copy, which RHEL 8
  exports twice. A device and inode number
  recycled for another file differs in mtime, size or ctime and attaches
  too. Any change of the key costs at most another copy of each probe on
  one inode (below). Limits:
  - a process that mapped a lower-layer file before it was copied up, if
    the agent had not attached it by then, runs an inode no path reaches
    any more, and is not probed;
  - a copy-up between the check in `open_examined` and the attach lands
    the probes on the upper inode under the lower inode's key, so the
    processes mapping the lower inode stay unprobed;
  - a file in a FUSE mount inside a user namespace chooses its inode,
    mtime, size and ctime, and its anonymous device can be one an overlay
    mount used before; on kernels whose maps show the overlay's own inode
    (the Ubuntu ones) it can then forge the key of a file attached earlier
    and be skipped. This needs `/dev/fuse` and user namespaces, which
    default Docker and Kubernetes deny;
  - each ctime change adds a copy of each probe on the inode, without
    bound; past 63 copies on one uprobe, attach cookies repeat and those
    copies emit twice;
  - a mapping whose file was deleted (`(deleted)`, a library replaced
    under a running process) is skipped, so that process is not probed
    until it restarts.

  A container's
  overlay root shows an image file under a device of its own, while the
  uprobes land on the layer inode every container of the image shares, so
  each container mount is attached and the shared inode carries one copy
  of each probe per attach (on a kernel without attach cookies, only
  where the inode the probes landed on cannot be shown, below). Finding
  the layer inode behind an overlay file by a lookup from user space (an
  overlay dedupe, since removed) cannot be proven: a
  layer file with the examined file's inode number, size and mtime does
  not show that it backs the examined file (a privately mounted layer can
  show them for another file), and a wrong match attached another file at
  this one's offsets and recorded it as attached, hiding its own target.
  Each attach is a copy of each probe, and the copies emit once per hit: the
  kernel registers every copy on one uprobe (`trace_uprobe_enable` takes
  `d_real_inode`, and uprobes are keyed by inode and offset) and at each
  hit runs every copy once, in sequence, on the hitting thread, with the
  same registers (`handler_chain`). The probes that emit at the hit itself
  (`ssl_write_entry` and `ssl_write_ex_entry` with an unrestricted capture
  scope, `go_tls_decrypt_ret`, the unguarded `go_tls_write_entry`) are
  attached as `_dedup` variants with an attach cookie per copy (bits
  1..=63; loader.rs `attach_uprobe_once`). A copy suppresses only when the
  thread's state for that site (maps.rs `TLS_HIT`) is of a hit at the same
  instruction and stack pointer, under 10 ms old, and lacks the copy's bit
  (tls_probes.rs `first_copy`). A copy that finds its own bit set has
  already run for that hit, so the hit is new and it emits: a real call
  repeated with the same stack pointer and arguments (the same goroutine
  reading its next record, an identical `SSL_write` from the same frame)
  is never merged. Every hit emits at least once, since its copies include
  the one whose bit the state was started with (copies are not detached
  while the agent runs); a miss (no cookie, no state, a bit shared by two
  copies, an evicted entry) emits, a duplicate rather than a lost record.
  The other probes emit once anyway: OpenSSL reads and restricted-scope
  writes (the first return consumes the call), guarded Go writes (the
  second entry meets `Guard::Again`). The lab matrix
  (`tls_probe_copies_emit_once`) shows the mechanism and the dedupe on
  7.0, 6.8, 5.15 and 5.14 (RHEL 9): two plain copies emit each call twice,
  two or three `_dedup` copies once, for identical calls back to back
  (OpenSSL) and for 20 identical exchanges on one Go connection. Attach
  cookies are probed: upstream kernels before 5.15 (5.10 on Debian 11 or
  Amazon Linux 2, for example) have no BPF perf links, and RHEL 8 (4.18)
  no `bpf_get_attach_cookie` (RHEL 9's 5.14 has both); there the plain
  programs are attached and every copy emits, so copies are avoided in
  user space instead, where that can be proven. After each attach the
  agent maps one page of the attach descriptor itself (never read) and
  takes the device and inode the kernel shows for that mapping in
  `/proc/self/maps`, then checks the file still has the key it was
  examined with (proc_scanner.rs `landed_inode`). A copy-up only moves a
  file to a new upper inode and changes its ctime, so an unchanged key
  proves the attach resolved the inode mapped. A later target whose
  process maps that device and inode, with the same inode number, mtime,
  size and ctime, is covered (`Attached::covers`) and not attached. The
  identity comes from the kernel, not from a lookup a workload controls,
  and on RHEL names the inode the probes hold (its number cannot be
  reused while they are attached); it is never the target's own maps line
  at scan time (after a copy-up a process still shows the lower inode
  while its path reaches the upper one). On RHEL 8 and 9 the maps of an
  overlay file name the layer inode behind it; on the Ubuntu kernels they
  name an inode of the overlay mount itself, different per container, so
  there nothing is merged and the ctime still tells a copy-up. Anything
  unproven (the key changed during the attach, the mapping failed)
  attaches as before: a duplicate, never a skip. A FUSE mount can only
  make its own files covered. RHEL 8.10, `tests/oracle/run_overlay.sh`
  (2026-11-22, and the same on the merged build on 2026-11-26):
  two server containers and a client container, 100% of 300 HTTP/1.1
  exchanges in both views, no duplicate, no unmatched record, HTTP/2 one
  record per exchange (6.7-12.7% client, 37.7-39.7% server and 92-99
  duplicates before, two runs); copy-up, 100% in both views, no duplicate
  (7.3-9.3% client, 39.3-41.7% server, 95-100 duplicates before). Where
  the copies remain (a kernel without attach cookies whose maps show the
  overlay's own inode, a file changed during the attach, a ctime change
  without a copy-up), a repeated record can only repeat an
  exported record or make its parser withhold more: every parser, on a TLS
  key, with each direction's records repeated over many record splits,
  exports no credential the same records without repeats do not
  (protocol/dup_tests.rs). Two server containers and a client container of
  one Go image (HTTP/1.1 over TLS, 300 exchanges, the binary attached
  twice): 100% of the exchanges in both views, no duplicate (9.0% client,
  41.3% server and 102 duplicates before the dedupe, kernel 7.0). Gated
  by `tests/oracle/run_overlay.sh` (two containers and copy-up) on 7.0,
  6.8, 5.15 and 5.14 (RHEL 9), 2026-11-22: 100% in both views, no
  duplicate, no unmatched record, HTTP/2 one record per exchange.
  A Go binary that attached no probe is retried after 2, 4, 8 and 16 scans,
  then every 32 (proc_scanner.rs `GoRetry`).
- **PostgreSQL bound values are dropped** when the statement has credential
  context.
- **Credential masking is narrowed** to fields where a credential value
  could be present; bare names (`/oauth/token`, `SELECT password FROM
  users`) are exported (docs/USER-GUIDE.md §5.3).
- **Relayed plaintext is the relaying socket's payload.** An application
  that moves TLS plaintext to another socket (a terminating proxy,
  `splice`, its own sockmap program) sends it as that socket's cleartext,
  captured per that socket's scope. No mark follows plaintext through an
  application's relaying.
- Unscoped, both ends of a node-local connection are captured (two views),
  about twice the events and agent CPU of TC on a veth.
- The host's cgroup v2 hierarchy and kernel BTF are required. On a cgroup
  v1 host (RHEL 8) the agent mounts a private cgroup2 and the cgroup
  selectors are refused. Scoped capture is validated on x86_64 only.
- The `client_pid` / `server_pid` export fields (fed by TC's owner probes)
  are gone.

### Neutral
- Kernel cost per request is 1.4-1.8x TC's when scoped (preliminary, five
  kernels; docs/BENCHMARKS.md). TC figures elsewhere in BENCHMARKS.md are
  historical.
- CONFIG indices 6 and 7 (TC's cookie key and SYN switch) stay reserved,
  since CONFIG may be pinned across runs.

## Alternatives Considered

### Alternative 1: Keep TC on the node's interfaces

**Description**: Capture with TC classifiers on chosen or default-route
interfaces, with connect/accept probes naming owners and a user-space gate
applying `pid_filter`, sampling and `head_only`.

**Pros**:
- One program run per packet on the NIC; lower kernel cost per request.
- Sees forwarded and bridged traffic without a local socket.

**Cons**:
- `skb->sk` is NULL for forwarded/NATed pod traffic: no cgroup, process or
  socket to scope by.
- Scope decided after the bytes left the kernel, from events that can be
  lost or reordered; owner records keyed by a reusable 5-tuple (F1), PID
  list published before the exit tracepoint (F10), lengths from the IP
  header (F5).
- No loopback or node-local traffic; an interface list per node.

**Why rejected**: it cannot enforce scope in the kernel, and its user-space
enforcement fails open on event loss and tuple reuse.

### Alternative 2: TC on each pod's veth, with a netns table

**Description**: Attach TC per veth and map ifindex to network namespace in
user space to find each packet's socket.

**Pros**:
- Per-pod attribution without cgroup v2.

**Cons**:
- Per-veth attach lifecycle; on ifindex or namespace-id reuse a packet can
  be looked up in the wrong namespace, which is not shown to fail closed.

**Why rejected**: it adds per-namespace state whose failure mode is not
fail-closed.

## Implementation Notes

- Kernel: `panopticon-ebpf/src/sock_capture.rs` (capture, scope writers,
  close records), `tls_probes.rs` (TLS scope at call time), `maps.rs`.
- User space: `scope_loader.rs` (load-check every program a mode needs,
  refuse with the missing one, attach, arm last), `scope_select.rs` and
  `scope_publisher.rs` (selectors and reloads), `event_loop.rs` (admission
  floor; no scope decision).
- Helm mounts the host's `/sys/fs/cgroup` read-only and `/run/panopticon`.
- Tests: `panopticon-agent/tests/scope_attach.rs` (lab, five kernels:
  7.0, 6.8, 5.15, RHEL 9, RHEL 8), `tests/oracle/run_scope.sh` and
  `scope_lab.py` (end-to-end scope oracles), `narrowing_tests.rs`.

## References

- [User guide, "Capture scope"](../USER-GUIDE.md#42-config-file-reference)
- [Current state](../CURRENT-STATE.md)
- [Benchmarks, cgroup_skb capture backend](../BENCHMARKS.md#cgroup_skb-capture-backend-preliminary)

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-11-14 | Panopticon maintainers | Accepted; TC backend removed |
