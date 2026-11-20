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

### Negative

These trade-offs are deliberate; each errs toward not capturing. The user
guide states them for operators (docs/USER-GUIDE.md §4.2, "Capture scope").

- **`pid_filter_listener = "acceptor"` (default) drops pre-accept bytes.** An
  accepted connection is selected only once a listed process's `accept()`
  returns; earlier bytes are dropped (56.6% of requests captured with a
  new connection per request in the T-19 measurement; keep-alive
  connections lose only their first bytes). `"creator"` selects every
  child of a listener a listed process created, whoever accepts it.
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
  agent did not see whole, or after a lost header block, headers are not
  decoded and (with credential masking on) bodies of unknown type are not
  exported, for the connection's life.
- **HTTP/2 content type over 256 bytes, or repeated.** With credential
  masking on, that stream's body is withheld.
- **TLS key reuse boundary at `SSL_new`.** A new TLS connection on a reused
  library object starts clean only after the agent saw OpenSSL's `SSL_new`
  return it; otherwise it is treated as not seen whole (Go TLS has no such
  hook).
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
