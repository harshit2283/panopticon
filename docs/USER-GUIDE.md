# Panopticon User Guide

Panopticon is an eBPF agent that watches the network traffic on a Linux host,
reconstructs application requests (HTTP, databases, caches, queues), finds
personal data in them, and reports what it saw. One setting, the privacy
mode (§4.3), decides how much of it leaves the node: everything including
decrypted TLS, events with personal data redacted (the default), or only
metrics. It never modifies or blocks traffic.

> **Status: experimental.** Read [`CURRENT-STATE.md`](CURRENT-STATE.md) for
> what is validated and what is not before relying on it.

- Deploying it on servers or Kubernetes: [`DEPLOYMENT.md`](DEPLOYMENT.md)
- Measured accuracy and overhead: [`BENCHMARKS.md`](BENCHMARKS.md)

---

## 1. What you get

For every completed request/response exchange it can parse, Panopticon
produces one **event**: protocol, method, path or query, status, latency,
sizes, headers and (for text payloads) the body — after PII redaction unless
the privacy mode is `full`.

| Output | How to enable | Contains | Privacy modes |
|---|---|---|---|
| JSONL event log | `--json-export <file>` | One JSON object per exchange (see §5.1) | `full`, `redacted` |
| PII audit log | `--pii-audit-log <file>` | One line per PII finding: category, action — never the value (§5.2) | all |
| Prometheus metrics | `--metrics-bind <addr:port>` | Capture, drop and PII counters (§5.4) | all |
| Health endpoints | `--metrics-bind <addr:port>` | `/healthz`, `/readyz`, `/debug/state` | all |
| OTLP spans | config file `[otlp]` | One span per exchange to an OTLP/gRPC collector | `full`, `redacted` |
| Console | `--log-events` | Every packet and exchange (development only, very verbose) | `full`, `redacted` |
| Raw capture | `--capture-raw <file>` | Every captured payload, **unredacted, decrypted TLS included**; converts to pcap for Wireshark (§5.5) | `full` only |

Protocols: HTTP/1.1, HTTP/2, gRPC, PostgreSQL, MySQL, Redis, Kafka, AMQP and
DNS are validated against ground truth (see [`BENCHMARKS.md`](BENCHMARKS.md)).
Depth varies — see the support matrix in the [README](../README.md).

## 2. Requirements

- Linux **kernel 5.8 or newer**, or RHEL 8 / 9 (their 4.18 and 5.14 kernels carry
  the BPF ring buffer backport; validated on Rocky Linux 8.10 and 9.8). x86_64;
  arm64 is untested.
- Root, or the capabilities `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` (plus
  `CAP_SYS_PTRACE` for TLS library discovery in other processes).
- The host's cgroup v2 hierarchy (the agent mounts a private one on a cgroup
  v1 host such as RHEL 8, where `cgroup_filter` / `pod_filter` are then
  refused) and kernel BTF (`/sys/kernel/btf/vmlinux`). In a container, mount
  the host's `/sys/fs/cgroup` (the Helm chart does).
- tracefs mounted at `/sys/kernel/tracing` for process events (most distros
  mount it automatically).

## 3. First run (5 minutes)

Build (see the [README](../README.md#linux-build-and-smoke-test-path) for the
pinned toolchain) or use the container image, then:

```bash
# 1. Check the agent can load and see traffic. Exits 0 on the first captured
#    event, 1 after 30s without one — generate some traffic meanwhile.
sudo panopticon-agent --smoke-test

# 2. Run it, exporting events, the PII audit log and metrics.
sudo panopticon-agent \
  --json-export /var/lib/panopticon/events.jsonl \
  --pii-audit-log /var/lib/panopticon/pii-audit.jsonl \
  --metrics-bind 127.0.0.1:9435

# 3. In another shell: make a request and look at what was captured.
curl -s "http://example.com/?email=jane%40example.com" >/dev/null
tail -n1 /var/lib/panopticon/events.jsonl | jq .
curl -s 127.0.0.1:9435/metrics | grep panopticon_
```

The agent captures at every socket on the node (cgroup v2 hooks; §4.2,
"Capture scope"), in every network namespace. Loopback packets are left
out unless you set `capture_loopback = true`.

Stop it with Ctrl-C or `SIGTERM`; exports are flushed on shutdown.

## 4. Configuration

Settings come from, in increasing priority: built-in defaults, a TOML file
(`--config <file>` or `PANOPTICON_CONFIG`), and command-line flags.

### 4.1 Command-line flags

| Flag | Meaning |
|---|---|
| `--config <FILE>` | TOML config file (also `PANOPTICON_CONFIG`). |
| `--json-export <FILE>` | Write events as JSONL. **The file is truncated at startup.** |
| `--pii-audit-log <FILE>` | Write PII audit records as JSONL (appended). |
| `--metrics-bind <ADDR:PORT>` | Serve `/healthz`, `/readyz`, `/metrics`, `/debug/state`. Off by default. |
| `--log-events` | Log every packet and exchange to stdout. Contains traffic (redacted unless the mode is `full`). Not allowed in `metrics_only`. |
| `--smoke-test` | Exit 0 on the first captured event, 1 after 30s. |
| `--kubernetes <auto\|true\|false>` | Kubernetes identity (§5.6); overrides `[kubernetes] enabled`. Also `PANOPTICON_KUBERNETES`. |
| `--privacy-mode <full\|redacted\|metrics_only>` | What may leave the node (§4.3); overrides `[privacy] mode`. Also `PANOPTICON_PRIVACY_MODE`. Default `redacted`. |
| `--capture-raw <FILE>` | Write every captured payload, unredacted and with TLS decrypted, to a binary capture file (§5.5). Needs `--privacy-mode full`. |
| `--decode-capture <FILE>` | Print a raw capture file as JSON lines and exit. Needs no root, but needs `--privacy-mode full` (or `full` in the config file): the output is unredacted. |
| `--decode-capture <FILE> --pcap <OUT>` | Convert a raw capture to a pcap file for Wireshark / tshark (§5.5) and exit. Also needs `--privacy-mode full`. |
| `-v, --verbose` | Debug logging (otherwise `RUST_LOG`, default `info`). |

### 4.2 Config file reference

All keys are optional. Example with the defaults:

```toml
capture_enabled = true
# cgroup_filter = ["kubepods.slice/..."]  # default: unset; see "Capture scope" below
# pid_filter = [1234, 5678]         # default: unset (every process); see "Capture scope" below
# capture_loopback = false          # see "Capture scope" below
# pid_filter_listener = "acceptor"  # "acceptor" | "creator"
sampling_mode = "full"              # "full" | "connection_sample" | "head_only"
# sample_rate = 0.1                 # connection_sample only, and required there
# head_only_bytes = 4096            # head_only only (default 4096)
max_events_per_sec = 500000         # user-space rate limit on records (a TCP packet is up to ceil(max_packet_bytes / 4096) records, 16 on a raised connection); excess is dropped and counted
max_worker_count = 4                # default: number of CPUs
worker_channel_capacity = 4096        # events queued per worker; excess is dropped and counted
max_connections_tracked = 65536
idle_connection_timeout_secs = 30
max_body_bytes = 4096               # body text kept per exchange for PII scan + export (max 65536)
max_packet_bytes = 16384            # bytes captured per packet, in 4 KiB records (4096-65536); restart to change
raise_packet_cap = true             # whole packets (64 KiB) on AMQP, Kafka, HTTP/2, gRPC, PostgreSQL, MySQL, Redis, DNS connections; restart to change
tls_scan_enabled = true             # find OpenSSL/Go TLS libraries and attach uprobes
tls_scan_interval_secs = 60
log_events = false
json_export_path = "/var/lib/panopticon/events.jsonl"     # default: unset (off)
pii_audit_log_path = "/var/lib/panopticon/pii-audit.jsonl" # default: unset (off)
metrics_bind = "127.0.0.1:9435"                           # default: unset (off)
# map_pin_path = "/sys/fs/bpf/panopticon"                 # default: unset (no pinning)
# capture_raw_path = "/var/lib/panopticon/raw.pncap"      # default: unset (off) — UNREDACTED, needs mode = "full"
capture_raw_max_bytes = 1073741824  # raw capture stops at this size (1 GiB)

[privacy]
mode = "redacted"      # "full" | "redacted" | "metrics_only" (§4.3)

[credentials]          # your own credential formats (§5.3); reloadable by SIGHUP
# patterns = ["AKIA[0-9A-Z]{16}", "(?i)acme_[a-z0-9]{32}"]  # default: none
# builtin = "full"     # "full" | "names_only"

[pii]
enabled = true
regex_enabled = true
# redact: follows the privacy mode; leave it out (§4.3)
min_confidence = 0.7   # for ML findings (ML is not in the default build)

[graph]
enabled = true
aggregation_window_secs = 10
stale_edge_timeout_secs = 300
identity_cache_ttl_secs = 300

[otlp]
enabled = false
endpoint = "http://127.0.0.1:4317"   # http:// only: cleartext gRPC, https:// refuses to start
service_name = "panopticon-agent"

[kubernetes]           # pod/service names for endpoints (§5.6)
enabled = "auto"       # "auto" = on when running in a pod with a service account token; true; false
relist_interval_secs = 300  # full re-list of pods and services (min 5)
watch = true           # stream changes between re-lists; false = refresh only by re-listing

# [[pod_filter]]       # default: unset; this node's pods, see "Capture scope" below
# namespace = "payments"
# labels = { app = "checkout" }   # or: name = "checkout-7d9f..."
# pod_cgroup_root = "/custom/kubepods"  # top-level key, before any table:
#                        # kubelet's kubepods directory under a custom --cgroup-root

[capture]
cgroup2_path = "auto"  # the cgroup v2 root to attach to; "auto" = /sys/fs/cgroup,
                       # else /sys/fs/cgroup/unified, else a private mount (RHEL 8)
preaccept_hold_bytes = 16777216  # pid_filter, acceptor rule: kernel memory for
                       # bytes waiting for accept() (16 KiB per connection;
                       # 0 = off; max 1 GiB; restart to change), shared by
                       # every server, 1/16 per listener and a 1/2 overflow
                       # pool: one server takes at most 9/16 (§4.2)
```

**`max_packet_bytes`.** The kernel hands the capture large packets whole
(GSO, TSO and GRO packets of up to 64 KiB). Each TCP packet is sent to the
agent as consecutive 4 KiB records, up to `max_packet_bytes` (4096 to
65536, default 16384; `ceil(max_packet_bytes / 4096)` records at most),
each with its exact stream position; what lies past it is counted, not
captured. A UDP datagram, and a TCP packet carrying RST, stay one record
of at most 4096 bytes whatever the setting. A cut can cost a parser its message boundaries,
and then some fields for the rest of the connection (§5.3). At one record
(4096, the behaviour before this setting) a PostgreSQL 500-row result,
sent in 8 KB packets, was cut, and the connection's bound values are
withheld from then on, and its SQLSTATEs (§5.3); the default covers it.

**`raise_packet_cap`** (default `true`). Every parser accounts for a cut
that falls inside one message of known length, but a cut that crosses a
message boundary costs it frame sync, and then it exports only closed-set
values for the rest of the connection (§5.3). For most protocols a large
packet is several messages: an AMQP delivery is three frames or more and
one packet to a consumer carries several deliveries (on RHEL 8.10 one
broker-to-consumer packet in about 300 is 23 KB, and on 7.0 under load
such packets pass 16 KB too); HTTP/2 and gRPC frames are at most 16 KiB by
default, so a larger packet holds several; Kafka keeps up to five requests
in flight, so a packet can end one response and start the next; and
PostgreSQL, MySQL (client side), Redis and DNS over TCP lose sync on any
lost byte. So when the agent detects one of those protocols on a TCP
connection, at its first packet, it raises that connection's cap in the
kernel to 64 KiB (16 records), the largest packet a GSO send produces
without BIG TCP: such a connection's packets are captured whole, whatever
`max_packet_bytes` is. HTTP/1.1 is not raised: it has one response in
flight (pipelining is rare), and its large packets are body bytes of
known length or a chunk's data, which the parser accounts for; it also
carries most bulk traffic, whose cost is measured below. TLS plaintext is
not affected (16 KiB per read or write, §5.5).

What this changes: the kernel reads the per-connection cap only for a
packet over `max_packet_bytes`, and only after the scope decision, so it
never brings a socket into scope and never changes which process a packet
is attributed to; the entry is deleted when the socket closes or the
agent stops tracking the connection (idle or at capacity). The agent keeps
at most 12,288 raised connections (the kernel map holds 16,384, and would
otherwise drop an old entry to make room): past that a new connection is
not raised (`panopticon_conn_cap_refused_full_total`). The map is written
from a thread of its own, pinned to one CPU (an LRU map can drop entries
early when many CPUs insert), never from the workers; a narrowing's new
pipeline keeps the entries of the connections it takes over. More
bytes of large packets on those connections are captured and reach the
parsers: their messages are exported, subject to the privacy mode (§4.3)
and the body cap (`max_body_bytes`), where before they would have been
withheld after the cut. Ring records per large packet go up to 16 on
those connections (Kafka fetches of bulk data are the case to watch). A
packet that arrives before the agent has detected its connection is cut
at `max_packet_bytes` as before
(`panopticon_conn_cap_truncated_before_raise_total`; 0 in every lab run:
a connection is detected at its first packet, and its large packets come
later). Measured on 2026-11-26 at the default `max_packet_bytes`: on RHEL
8.10, where deliveries were 21-63% at this default before, AMQP
deliveries were 279/279 in 17 of 17 runs of the messaging oracle, with
nothing truncated and 2-8 packets over 16 KiB captured whole in 15 of
them; on 7.0, 279/279 in 18 of 18 (no packet there was over 16 KiB in
those runs). HTTP/1.1 throughput is unchanged (200 KB bodies at full
rate: 1.04-1.05M requests in 20 s with and without the change;
BENCHMARKS.md). Set
`raise_packet_cap = false` to capture every connection at
`max_packet_bytes`. The counters are listed in §5.4
(`panopticon_conn_cap_*`).
The cost is kernel time and ring space per large packet, paid in the
sending application's context. Measured on a 16-vCPU VM (7.0) with 200 KB
HTTP bodies over 200 connections, unscoped: at 2,000 requests/s every
setting captured 100% with no drops (kernel time per packet 1.3 µs before
this setting, 1.7 µs at 16384, 2.7 µs at 32768, 5.2 µs at 65536); at full
rate the application completed 1.09M requests in 20 s before, 974K at
16384, 857K at 32768 and 595K at 65536, and the export kept 79%, 34%, 19%
and 15% of exchanges. On a node that moves bulk data at line rate, set
4096 (or scope the capture, §4.2); where large responses matter more than
bulk throughput, raise it. Changing it needs a restart. Connections raised
by `raise_packet_cap` capture whole packets whatever this is.

`max_events_per_sec` counts records, not packets: a packet at the cap
takes up to `ceil(max_packet_bytes / 4096)` records of the budget (16 on a
connection `raise_packet_cap` raised), a TLS
read or write up to 4. Records are what the agent's work scales with. A record
the limiter drops in the middle of a packet is a gap in that stream, as a
kernel ring drop is.

**Capture scope.** Packets are captured by `cgroup_skb` programs attached
to the root of the host's cgroup v2 hierarchy, the only capture backend
(the TC backend and its `interfaces` / `--interface` settings were removed;
see [ADR-014](adr/ADR-014-cgroup-skb-capture-scope.md)). They see every
socket on the node, in every network namespace, and nothing the node only
forwards or bridges. `pid_filter`, `cgroup_filter` / `pod_filter`,
`sampling_mode`, `capture_loopback` and `pid_filter_listener` narrow what
is captured at all. Every one of these decisions is made in the kernel,
per socket, before a byte is copied out: what they drop never reaches the
agent, so it never reaches the parsers, PII scanning, the service graph,
the event export, OTLP, the PII audit log, the raw dump (and so
`--decode-capture` / `--pcap`), `--log-events` or the agent's logs. They
work the same in every privacy mode (§4.3) and only ever reduce what the
mode allows. Every rule errs toward not capturing: a socket the kernel
cannot place (a missing hook, a torn read) is dropped, and so, with any of
these settings, is every socket that existed before the agent started
(`uninit`); unscoped `full` captures those too. Every drop is counted in
`panopticon_scope_dropped_events_total{reason}` (§5.4).

With any selector or sampling set, TLS plaintext (uprobes) is scoped by
the process making the TLS call (its PID and cgroup), and is captured
only in `full` sampling
(never under `connection_sample` or `head_only`). Scoped capture is
validated on x86_64 only and refused elsewhere.

- `cgroup_filter = ["kubepods.slice/kubepods-burstable.slice/…", ...]`
  (paths relative to the cgroup2 root) and `[[pod_filter]]` (`namespace`
  plus `labels = { app = "…" }` or `name = "…"`, matched against this
  node's pods): capture the sockets of these cgroups and every cgroup
  below them. A socket's cgroup is fixed when it is created, so this has
  none of the accept-time gaps of `pid_filter` below and is the primary
  selector. A pod's cgroup is its directory where kubelet makes it, and
  nowhere else: in a kubepods root at the top of the cgroup2 hierarchy
  (`kubepods` with the cgroupfs driver, `kubepods.slice` with systemd, or
  `<name>.slice/<name>-kubepods.slice` when kubelet's cgroup root is
  `/<name>`, as in kind), directly (guaranteed QoS) or in its
  `burstable` / `besteffort` level, named as that driver names it
  (`pod<uid>`, `kubepods-burstable-pod<uid>.slice`). That directory and
  every one above it up to the root must be owned by root and not group-
  or other-writable, so a directory another user creates (in a subtree
  delegated to them, such as `user@<uid>.service`) is never taken for a
  pod's; a directory removed while the agent looks is simply skipped. If kubelet runs with
  another `--cgroup-root` (`cgroupRoot`), so that its kubepods directory
  is elsewhere, name that directory in `pod_cgroup_root` (an absolute
  cgroup path under the cgroup2 mount, such as `"/custom/kubepods"` or
  `"/a.slice/a-b.slice/a-b-kubepods.slice"`; a last component ending in
  `.slice` is read with the systemd driver's names, anything else with
  cgroupfs's). It is searched the same way, besides the roots above; the
  agent refuses to start unless it is a directory reached without a
  symlink or mount crossing, owned by root and not group- or
  other-writable at every level, and if it stops being one at runtime, no
  selected pod is captured until it is again (logged as an error). It may
  name a directory inside a recognised root (`"/kubepods/burstable"`): a
  pod directory reached from both is the same directory and counts once.
  Changing it needs a restart; set without any `[[pod_filter]]` it is
  unused (a warning says so, and it is still checked at startup), so a
  reload may remove every `[[pod_filter]]` while `cgroup_filter` stays.
  Nothing else widens the search. Static pods (from kubelet's manifest
  directory) are not supported: kubelet names their cgroup by the
  manifest's hash, not the uid of their mirror pod in the API, so they
  are never found. A selected pod with no such directory on this node is
  not captured: an error names the pod and the roots searched (with a
  hint to set `pod_cgroup_root`), and
  `panopticon_pod_filter_unresolved_total{reason="not_found"}` counts it;
  one whose uid matches more than one directory is not captured either,
  logged as a distinct error and counted as `reason="ambiguous"`, since
  only root can create those and neither can be told to be the real one
  (`reason="unusable"`: the one directory found could not be opened or
  is not root's, or is group- or other-writable). The selected pods are
  resolved again on every pod change, so the error is logged once per pod
  and reason (at debug level after that, until the pod resolves), while
  the counter counts every resolution. Pods
  that start, stop or change labels are followed; a reload may change
  either list. Needs the host's unified cgroup2 hierarchy: on a cgroup v1
  host (RHEL 8's default) the agent mounts a private cgroup2 at
  `/run/panopticon/cgroup2` to attach at all, every socket is then in its
  root, and these selectors are refused (use `pid_filter`).
- `pid_filter = [1234, ...]`: capture only these processes (PIDs as the
  node sees them, i.e. in the host PID namespace; at most 4096, not empty,
  no 0). A client connection is selected by the process that created its
  socket; an accepted (server) connection as `pid_filter_listener` says,
  below. `pid_filter` is the secondary, best-effort selector. Its limits:
  - It is restart-only (a reload that changes it is rejected), and it
    names PIDs, not programs: processes started after the agent,
    including children a listed process forks later (pre-fork workers,
    helpers) and a listed process that restarts, have new PIDs and are
    **not** captured. The filter does not follow process trees: list them
    and restart the agent, or select by cgroup or pod.
  - A connection a process accepted is selected by `pid_filter_listener`:
    - `"acceptor"` (the default): only if a listed process `accept()`ed
      it. A listening socket of a listed process selects nothing that an
      unlisted process accepts (a worker it forks later, a process it
      passes the socket to). A client usually sends its first bytes
      before the server's `accept()` returns, so those bytes are **held in
      the kernel** until `accept()` decides them (the pre-accept hold):
      sent, from offset 0, when a listed process accepts the connection;
      discarded in the kernel when an unlisted process accepts it or it
      closes unaccepted (`reason="pending_discarded"`). Bytes of a
      connection an unlisted process accepts never leave the kernel. This
      holds on any listener, also one that predates the agent. Measured
      with `tests/oracle/run_sampling.sh` `pid_servers` (HTTP/1 servers):
      every server connection (96 per run) captured from offset 0 and
      all 600 exchanges exported with method and path, on 7.0, 6.8,
      5.15 and RHEL 9 (2026-11-22) and RHEL 8 (2026-11-26); before the
      hold, on 7.0 the same day, 85 of 85 connections began past
      offset 0 and no exchange had a path. The hold has limits; each one
      drops the bytes it cannot hold and counts them:
      - two packets per connection, the first 4 KiB of each: a third
        packet before `accept()` is dropped (`reason="pending_overflow"`),
        and the rest of a held packet past 4 KiB is not captured
        (counted in `panopticon_capture_truncated_total`, like any cut
        packet);
      - a node-wide budget, `[capture] preaccept_hold_bytes` (default
        16 MiB; 16 KiB per waiting connection, so 1,024 connections
        waiting at once), shared by listener: past it, past a
        listener's share when the overflow pool is spent too, or when
        the socket's option memory (`net.core.optmem_max`) cannot take
        the hold, pre-accept bytes are dropped (`pending_overflow`).
        Every server's waiting connections draw on it, listed or not
        (which server will accept a connection is unknown until it
        does), but by listener (a server socket's local address and
        port): each may always take its share, 1/16 of the budget
        (1 MiB, 64 connections), and past it takes from an overflow
        pool of 1/2 (8 MiB) that all listeners share. So one listener
        whose connections wait (a busy or stalled server, or a remote
        client opening slow connections to it) takes at most 9/16
        (9 MiB, 576 connections), and the other listeners keep their
        shares in the rest (up to seven of them in full).
        **The limit any remote client can still reach:** eight or more
        listeners on the node, each with 64 or more connections waiting
        before it accepts, spend the whole budget, and until they are
        accepted or closed every other listener's pre-accept bytes are
        dropped (`pending_overflow`). Which listeners share one of the
        kernel's 1,024 counters depends on a seed drawn at start, so it
        cannot be chosen from outside the node; two that do share a
        share. `tests/oracle/scope_lab.py` T-23: an unlisted server with
        1,400 connections waiting on its listeners was bounded at its
        shares and the pool (the rest counted `pending_overflow`), and
        every listed connection opened meanwhile was captured from
        offset 0; none of the unlisted server's requests left the
        kernel. Raise the budget, or select by cgroup or pod, where
        nothing is held. `0` turns the hold
        off (all pre-accept bytes dropped, as `out_of_scope` or
        `no_owner`);
      - data carried by the handshake itself (TCP Fast Open SYN data, data
        on the final ACK) reaches the kernel before the connection's socket
        exists and is not held;
      - a packet that races the end of the hold (it arrives on another CPU
        while the held bytes are still being sent) is dropped
        (`reason="pending_race"`): 0 to 2 per 600-exchange
        `run_sampling.sh` run, and 0 of 2,000 connections racing
        `accept()` with receive spread over every CPU
        (`scope_attach`);
      - the hold is off when its kernel program does not load or cannot
        be installed: pre-accept bytes are then dropped (`out_of_scope`
        or `no_owner`) and the agent logs `pre-accept hold unavailable`.
        The hold also needs the accept hook (fexit `inet_csk_accept`),
        which records each acceptor: when it loads in neither variant
        (a warning that `pid_filter` selects no accepted connection) or
        does not attach (`did not attach`), the hold stays off and
        `"acceptor"` selects no accepted connection at all.

      What a connection with dropped bytes then exports depends on where
      they fall, as for any lost bytes (§5.3):
      - **its first bytes** (the budget spent, option memory full,
        handshake data, or its first packet lost to the race): it is
        parsed as one joined part-way, and a protocol where the client
        speaks first (HTTP/1, HTTP/2 and gRPC, PostgreSQL, Redis, Kafka,
        AMQP, DNS over TCP) exports for the connection's life only what
        an unproven parser may (§5.3): HTTP/1 a record per exchange with
        a known method and the sizes, never a path, header, status or
        body; Redis each reply's error flag and sizes; HTTP/2 and gRPC
        timing and sizes; Kafka the API name and sizes; AMQP known
        method names and sizes; PostgreSQL the statement keyword at
        most, and nothing when the startup message was lost;
      - **a later gap** (a third packet dropped, a held packet's bytes
        past 4 KiB, a packet lost to the race): the request line was
        seen from offset 0, and the gap is lost bytes like any other.
        Inside an HTTP/1 body of known length (`Content-Length`, or a
        chunk's data) the parser counts it and stays in sync: that
        exchange keeps its method, path, status and headers (its body's
        text is not exported once bytes follow the gap; its size is),
        and later exchanges on the connection are exported in full.
        Elsewhere in an HTTP/1 stream (inside the request headers,
        across a message boundary) the connection is unsynced from there
        for its life, with the closed-set values above. Other protocols
        place a gap by their own rule for lost bytes (§5.3): Kafka and
        AMQP account for one inside a frame of known length, HTTP/2 and
        gRPC one inside a DATA frame, and lose sync anywhere else.

      Database servers whose
      listeners predate the agent (`tests/oracle/run_protocols.sh`,
      `pid_filter` = the server, kernel 7.0): Redis, PostgreSQL and
      MySQL 500 of 500 in full, with and without the hold; Redis's and
      PostgreSQL's one server connection was captured from offset 0 in
      both runs, so this run did not exercise the hold. gRPC scored 0%
      in both, with 500 records with timing and sizes only; that run
      predates the HTTP/2 fix for a server that sends its SETTINGS
      before the client's preface reaches the agent. On the build with
      that fix (2026-11-22, 7.0 and 5.15) `pid_filter` = the gRPC server
      exported 500 of 500 calls with path and `grpc-status` in the
      server's view (the only one `pid_filter` selects). The figures
      recorded on 2026-11-21 (Redis error flag and sizes only,
      PostgreSQL no record) were not reproduced.
    - `"creator"`: also if a listed process created the listening socket
      while the agent ran. Then it selects every connection accepted on
      it, from the first byte, whoever accepts it: a worker the listed
      process forks later, a process that received the socket
      (`SCM_RIGHTS`, `pidfd_getfd`) or has since exec'd another program,
      and after the listed process has exited. List only processes whose
      listening sockets you want captured.
    - On a listening socket that existed before the agent started (any
      server not restarted since the agent was), both rules select a
      connection only by a listed process's `accept()`: under
      `"acceptor"` its bytes before that are held as above; under
      `"creator"` they are dropped (`no_owner`), with the unproven state
      for client-speaks-first protocols. A thread that was already blocked
      in `accept()` when the agent attached never records its accepts, so
      those connections are not captured at all; under `"acceptor"` such
      a connection's pre-accept hold is never released: it stays charged
      to the budget until the connection closes, and every later packet
      it receives is dropped as `pending_overflow`.
    - The rule governs packets only: TLS plaintext (uprobes) is captured
      when the calling process is listed, whichever process accepted the
      socket.
    Under `"creator"` nothing is held: on a listener it does not select
    (one an unlisted process created, or one that predates the agent) a
    listed acceptor's connection loses the bytes before `accept()`
    (`out_of_scope` or `no_owner`). For recall without the hold's limits,
    select by `cgroup_filter` / `pod_filter`.
- `sampling_mode = "connection_sample"` with `sample_rate = r` (required,
  0.0 to 1.0): each socket is captured whole or not at all, decided once
  in the kernel from a random draw when it is set up. `0.0` captures
  nothing; `1.0` is the same as `full`. The two ends of a connection
  between two sockets on this node are sampled independently. Dropped
  packets are counted as `reason="sampled_out"`.
- `sampling_mode = "head_only"` with `head_only_bytes = N` (default 4096,
  1 to 1073741824): only the first N bytes of each direction of each
  socket are copied out; the kernel cuts the rest (`reason="head_cut"`).
  An exchange that straddles the limit is exported with the part before
  it. For TCP the count is the byte's position in the stream, read from
  the kernel's own counters, so sockets that existed before the agent
  started, and restored (TCP repair) sockets, pass nothing
  (`no_baseline`). For UDP it is the bytes the socket has moved since it
  was created, whatever was captured, so an unconnected UDP server socket
  gets N bytes in total, not N per peer.
- `capture_loopback = false` (the default): packets that stay on the node
  through the loopback device are not captured. That is `127.0.0.0/8`, and
  connections to one of the host's own addresses (or, in a pod, the pod's
  own address), which the kernel also sends over `lo`. Packets on a VRF
  device are node-local too and dropped: local delivery inside a VRF
  travels the VRF device, and so does a VRF's incoming remote traffic. A
  socket is dropped from its first packet seen on a VRF device on; a
  one-way sender whose packets all leave through a VRF's member interface
  to a remote peer is captured. The agent recognises a VRF device on each
  packet from the device's own flags, in every network namespace and
  whenever it was created; it needs kernel BTF to locate those flags, and
  without it the agent refuses to start. A packet whose device cannot be
  read is treated as on a VRF device (dropped while this is off).
  Multicast or broadcast that a sender on a VRF member interface loops back
  to local receivers: the sender's looped copy is never seen (the kernel
  does not run the capture hook for it), the copy that leaves is captured,
  and the local receiver's copy arrives on the VRF device and is dropped
  while this is off. A socket that once carried node-local traffic stays
  dropped (an unconnected UDP socket that talked to a local and a remote
  peer). Same-node pod-to-pod and host-to-pod traffic over veth, a bridge,
  ipvlan, macvlan or tun/tap is not loopback and is captured. Dropped
  packets are counted as `reason="loopback"`. It covers **packets only**:
  TLS plaintext (uprobes) of a loopback connection is captured per
  `pid_filter` / cgroup selection like any other (in a scoped mode without
  its addresses, while loopback packets are dropped). Set it to `true` to
  capture app-to-local-database and sidecar packets.
- IPv6 is not captured.

**Relayed plaintext.** "No TLS plaintext outside `full` sampling" covers a
TLS connection's own plaintext: what the TLS library reads and writes, and
the payload of a socket with kernel TLS keys installed (kTLS payload is
dropped outside unscoped `full`, `reason="ktls_payload"`). An application
can take that plaintext and send it out through another socket, as that
socket's ordinary payload: a TLS-terminating proxy (`recv` then `send`),
`splice` through a pipe, or its own sockmap redirect program. The receiving
socket then carries it unencrypted at the TLS layer, as its own cleartext,
and it is captured according to **that** socket's scope and mode, exactly
like the backend leg of a TLS-terminating proxy. No per-socket mark
follows plaintext through an application's own relaying, so none is
claimed. Encryption below the socket (WireGuard, IPsec, MACsec) is not
TLS: the hook sees the socket's cleartext before the tunnel encrypts it.

**Trade-offs of this design.** Each one errs toward not capturing:

| What | Effect |
|---|---|
| `pid_filter_listener = "acceptor"` (default) | Bytes that arrive before `accept()` returns wait in the kernel, two packets (4 KiB each) per connection within a node-wide budget that every server shares, listed or not, by listener: one listener takes at most 9/16 of it (its share and the overflow pool), so slow or unaccepted connections to one server leave other listeners their shares; eight such listeners, each with 64 connections waiting, spend it, and listed servers then lose their pre-accept bytes. Bytes past those limits, and handshake data (TCP Fast Open), are dropped and counted. A connection whose first bytes were lost keeps a client-speaks-first parser unproven for its life (HTTP/1 method and sizes, no path); a later gap inside an HTTP/1 body of known length is counted and the path and later exchanges are exported; elsewhere in an HTTP/1 stream it unsyncs the connection from there, and other protocols follow their own lost-byte rule (above). |
| `pid_filter_listener = "creator"` | Nothing is held: a listed acceptor on a listener it does not select loses the bytes before `accept()` (above). |
| `capture_loopback = false` (default) | Loopback and VRF packets are not captured; TLS plaintext is not affected (packets only). |
| Looped multicast / broadcast on a VRF member interface | The sender's looped copy is never seen, whatever `capture_loopback` says. |
| IPv6 | Not captured. |
| HTTP/2 joined late or with bytes lost | That connection's headers and bodies are withheld for its life (§5.3). |
| HTTP/2 content type over 256 bytes, or repeated | With credential masking on, that stream's body is withheld (§5.3). |
| Any TLS connection (OpenSSL or Go) | Starts latched: HTTP/2 and gRPC export no headers and no bodies; Redis replies keep status, timing and sizes only; AMQP keeps known method names, reply codes, timing and sizes; PostgreSQL and MySQL keep the statement keyword only. HTTP/1.1 and Kafka are not latched but follow TLS rules: an HTTP/1.1 path with a credential word is withheld, Kafka topic IDs stay on their connection; with an integrity limit (§5.3). |
| Connections open before the agent started (an agent restart) | Export method or statement keyword only until the client reconnects (§5.3); with any scope setting they are not captured at all (`uninit`, above). |
| PostgreSQL statement with credential context | Exported without its bound values (§5.3). |
| Credential masking | Narrowed to fields where a credential value could be present; bare names are exported ([§5.3](#53-what-gets-redacted)). |

An unknown `sampling_mode`, `sample_rate` without `connection_sample`, and
`head_only_bytes` without `head_only` stop the agent with an error, and so
do the removed keys `interfaces` and `[capture] backend = "tc"` (`backend =
"cgroup_skb"` is accepted with a warning; remove it). `--replay-bench`
refuses every scope setting: a recording holds only what was already in
scope.

`SIGHUP` re-reads the file but applies only a stricter privacy mode (§4.3)
and changes to cgroup selection: a reload may change `cgroup_filter` /
`pod_filter`, switch from one to the other, or combine them, but turning
cgroup selection on or off altogether (going from neither to either, or
back) needs a restart. It may also change `capture_loopback` and
`pid_filter_listener`. A reload that narrows the selection (a cgroup or pod
removed, `capture_loopback` turned off, `pid_filter_listener` from
`"creator"` to `"acceptor"`) is reported applied only once nothing captured
under the old scope can still leave the agent. Restart the agent for
anything else. Unknown keys are ignored silently (except inside
`[privacy]` and `[capture]`, where they are an error), so check spelling.

### 4.3 Privacy modes

Panopticon's users range from teams who need every byte, decrypted TLS
included, to teams for whom nothing but counts may leave the node. One
setting covers that range, `[privacy] mode` in the config file or
`--privacy-mode` on the command line:

| Mode | What can leave the agent |
|---|---|
| `full` | Everything: the event export unredacted (known credential forms still masked, best effort, unless `mask_credentials = false`, §5.3), and the raw dump of every payload with TLS decrypted (§5.5). |
| `redacted` (default) | Events with every detected PII value replaced by `<CATEGORY>` (§5.3) in the JSON export, OTLP spans and `--log-events` output. No raw dump. |
| `metrics_only` | Prometheus metrics, `/debug/state` counters and the PII audit log (category and count per service, never values or paths). No per-request export, no raw dump, no OTLP. Paths, query templates, headers and bodies are dropped as soon as PII has been counted, so they reach no sink, and no log at info level or above. The service map still names services (Kubernetes workload, DNS name or `ip:port`) and protocols; the audit log names them by Kubernetes workload or `ip:port` only. |

The mode is enforced, not advisory. Settings that would contradict it stop
the agent at startup with a message saying why:

- `capture_raw_path` / `--capture-raw` in any mode other than `full`;
- `json_export_path` / `--json-export`, `log_events` / `--log-events` or
  `[otlp] enabled` in `metrics_only`;
- `redacted` with `[pii] enabled = false` or `regex_enabled = false` (nothing
  would be masked);
- the external PII service in any mode other than `full` (it is sent raw
  values);
- `[pii] redact = false` outside `full`. `redact` otherwise follows the mode
  and is best left out. The one combination kept from before the mode
  existed: `redact = true` with `mode = "full"` keeps the event export
  redacted while the raw dump stays unredacted.

**Reloading (`SIGHUP`)** can make the mode stricter at runtime (for example
`redacted` → `metrics_only`: exports stop at once, files already written are
left as they are). Records already queued for an exporter when the mode
tightens are checked again before they are written, and dropped if the new
mode forbids them; on `metrics_only` the JSON export and the raw dump close
their files. It cannot make it wider: a reload asking for a wider mode
is rejected with an error and the running config is kept; restart the agent
to widen it. A reload from `full` to `redacted` is rejected the same way when
the agent was started without regex PII detection (`[pii] enabled` or
`regex_enabled` off): it has no redactor to switch on, so restart it. `--privacy-mode` keeps overriding the file on reload.

In `full` mode the agent prints a warning at startup, on stderr and in the
log (so `RUST_LOG=error` cannot hide it), that decrypted payloads are being
written unredacted. The JSON export, the PII audit log and the raw dump are created
readable by their owner only (`0600`). In every mode, panic messages
(which can quote the data being processed) are reduced to where the panic
happened.

Each mode is checked against ground truth: `tests/oracle/run_modes.sh`
plants unique PII values and credentials in HTTP, HTTPS, Redis and Kafka
traffic and searches every output
(export, raw dump, pcap, audit log, agent log at debug level, `/metrics`,
`/debug/state`) for them; results are in [`CURRENT-STATE.md`](CURRENT-STATE.md).

## 5. Reading the output

### 5.1 Event log (`--json-export`)

One JSON object per completed exchange. A real record (body shortened):

```json
{
  "protocol": "http1",
  "direction": "ingress",
  "timestamp_ns": 1805288389778,
  "latency_ns": 4324850,
  "method": "GET",
  "path": "/?user=<EMAIL>&ssn=<SSN>",
  "status": 200,
  "content_type": "text/html; charset=utf-8",
  "payload_text": "HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 ...",
  "headers": [["host", "<IP_V4>:18080"], ["authorization", "<REDACTED>"],
              ["content-length", "741"]],
  "request_size_bytes": 155,
  "response_size_bytes": 741,
  "src_addr": 2130706433, "src_port": 18080,
  "dst_addr": 2130706433, "dst_port": 58966,
  "pii": {
    "entities": [
      {"category": "Email", "source": "Regex", "start": 7, "end": 24, "confidence": 1.0},
      {"category": "Ssn", "source": "Regex", "start": 29, "end": 40, "confidence": 1.0}
    ],
    "redacted": true,
    "scanned_bytes": 55
  }
}
```

| Field | Meaning |
|---|---|
| `protocol` | `http1`, `http2`, `grpc`, `mysql`, `postgres`, `redis`, `kafka`, `amqp`, `dns` |
| `timestamp_ns` | Kernel monotonic clock (ns since boot), not wall-clock time |
| `latency_ns` | Request → response time as observed on this host |
| `method`, `path` | HTTP method and path+query; SQL command and table; Redis command and key. Each of these and every header name and value is kept to at most 8 KB |
| `status` | HTTP status, or database error code |
| `payload_text` | Response body as text, at most `max_body_bytes` (default 4 KB), after redaction; for Redis only the reply's type and size (§5.3) |
| `request_body` | HTTP request body (POST/PUT/PATCH, forms) as text, at most `max_body_bytes`, after redaction |
| `response_size_bytes` | Full body size, even when the body was larger than what was kept |
| `headers` | Header names and values as sent on the wire (HTTP, HTTP/2 and gRPC metadata including `:path`; DNS `qtype`) |
| `dns_answers` | DNS responses: the A records (`name`, `ip` as a 32-bit integer, `ttl_secs`) that answer a query seen on the same flow. They name services in the graph |
| `src_*`, `dst_*` | Addresses of the packet that completed the exchange (usually the response). Addresses are IPv4 as a 32-bit integer (`2130706433` = `127.0.0.1`). |
| `pid` | TLS exchanges: the process whose TLS calls were captured |
| `src_workload`, `dst_workload` | Kubernetes identity of `src_addr` / `dst_addr` (§5.6), e.g. `payments/checkout`. Present only with Kubernetes identity on and the address known to the API. |
| `pii.entities` | What was found; offsets are relative to the field it was found in |
| `pii.redacted` | `true` if values were replaced before export |

### 5.2 PII audit log (`--pii-audit-log`)

One line per finding, with no values:

```json
{"timestamp_ns":1805288389778,"category":"Email","source":"Regex","confidence":1.0,"action":"Redacted","service_identity":"payments/checkout","service_addr":"10.244.1.5:8080"}
```

`service_identity` is the server end of the exchange, named like the service
graph names it: Kubernetes workload when known, else DNS name, else `ip:port`
(`unknown` only for TLS exchanges whose socket addresses were not learned).
In `metrics_only` it is never a DNS name. `service_addr` is always the
server end's `ip:port`: a DNS name comes from answers seen in the traffic
(§5.6 says how far they are trusted), the address does not.

`action` is `Redacted` when the value was masked (privacy modes `redacted`
and `metrics_only`), `Detected` in `full` mode (unless `[pii] redact = true`).
Categories (redaction placeholder in brackets):

| Category | What it matches |
|---|---|
| `Email` (`<EMAIL>`) | Email addresses, `example.com` included; not asset names like `logo@2x.png` |
| `PhoneUs` (`<PHONE_US>`) | North American numbers (valid area and exchange codes) |
| `PhoneIn` (`<PHONE_IN>`) | Indian mobiles: `+91 98765 43210`, `+919876543210`, `09876543210` |
| `PhoneIntl` (`<PHONE_INTL>`) | Other `+`-prefixed numbers, 8–15 digits |
| `Ssn` (`<SSN>`) | US SSNs written `123-45-6789` |
| `CreditCard` (`<CREDIT_CARD>`) | 13–19 digits passing Luhn with a real issuer prefix (Visa, Mastercard, Amex, RuPay, …) |
| `Aadhaar` (`<AADHAAR>`) | 12 digits, first 2–9, valid Verhoeff check digit |
| `Pan` (`<PAN>`) | Indian PAN, `AAAPA9999A` with a valid holder-type letter |
| `Upi` (`<UPI>`) | UPI IDs with a known bank handle: `name@okaxis`, `9876543210@ybl` |
| `Gstin` (`<GSTIN>`) | GSTINs with a valid state code and check character |
| `PassportIn` (`<PASSPORT_IN>`) | Indian passport numbers, only after the word "passport" |
| `Iban` (`<IBAN>`) | IBANs, compact or spaced, passing mod-97 |
| `IpV4` (`<IP_V4>`) | Every IPv4 address (client addresses are personal data) |
| `Jwt` (`<JWT>`) | JSON Web Tokens |
| `ApiKey` (`<API_KEY>`) | A value after `api_key`, `secret_key`, `access_token` and similar |
| `AwsKey` (`<AWS_KEY>`) | AWS access key IDs (`AKIA…`, `ASIA…`) |

A US number written without separators or `+1` (`4155552671`), and an Indian
mobile without `+91` (`9876543210`, `09876543210`), counts as a phone only
when a word like `phone`, `mobile`, `msisdn` or `tel` comes just before it.
Builds with ML (`--features ml` and a model) add `PersonName`, `Location`,
`Organization` and `DateOfBirth`. Per-type precision and recall are in
[BENCHMARKS.md §3](BENCHMARKS.md#3-pii-detection-accuracy).

### 5.3 What gets redacted

In privacy mode `redacted` (the default), before anything is logged or
exported:

- the **path and query string** are scanned (also in percent-decoded form) and
  matches replaced by `<CATEGORY>`, e.g. `<EMAIL>`;
- **header names and values** are scanned the same way, for every protocol
  (HTTP headers, gRPC metadata, Kafka `client_id`, AMQP consumer tags,
  routing keys and reply texts). HTTP, HTTP/2 and gRPC credential headers are
  replaced entirely by `<REDACTED>`: any header whose lowercased name contains
  `token`, `auth`, `key`, `secret`, `session`, `csrf`, `xsrf`, `signature`,
  `password`, `passwd`, `cookie` or `credential` (so `Authorization`,
  `Cookie`, `Set-Cookie`, `X-Api-Key`, `X-Vault-Token`, `PRIVATE-TOKEN`,
  `X-Goog-Api-Key`, `X-Hub-Signature-256`, ...). A header of any protocol
  whose name is a credential name is replaced the same way: a name holding
  a word of the first list below, or one of whose segments is one of the
  short names below or glues one to the word before it, as below
  (segments split at every
  character that is not an ASCII letter or digit and at case and digit
  boundaries). The parsers deliver header names in lower case, so
  `x-old-pwd`, `x-card-pin`, `x-loginpwd`, `x-newpwd`, `x-cardpin`,
  `x-smsotp`, `x_sms_otp`, `x-dbpass`, `x-reqsig`, `x-userjwt` and
  `x-jsessionid` are credential names (`pwd` is a credential part);
  `x-shipping-option`, `x-cache-bypass` and `x-usersid` are not. For
  HTTP, HTTP/2 and gRPC, `:authority` and `Sec-WebSocket-Key` stay
  readable under both rules, and so does AMQP's `routing_key` field (its
  value is still scanned as text);
- the **method** (including a gRPC method path), the **content type**, the
  **request body** (e.g. POST JSON or form data) and the **response body**
  are scanned and redacted;
- **credentials**: any field with *credential context*, where a
  credential value could be present, is withheld whole, whatever the
  protocol, unless every credential in it can be masked with certainty
  (below). A credential word that is a bare name, in one of two
  allowlisted positions of an HTTP request path or a SQL statement, is
  not context.

**What credential protection promises.** In `metrics_only` no path,
header or body leaves the agent, so no credential in one can. In
`redacted` and `full` those fields are exported, and credential protection
is best-effort defence in depth for known credential forms: the names,
encodings and structures below, and your own formats (`[credentials]`,
below). It cannot recognise a secret that nothing tells apart from other
data. Known limits:

- an opaque secret under a name not in the lists (an OAuth `code=`, a
  field called `answer`), or a `Basic` credential (base64 `user:password`)
  outside the `Authorization` header: base64 is not decoded;
- name shapes that cannot be told from ordinary text (below): `sid`
  glued to a word in one case (`x-usersid`, which reads as `users` +
  `id` too), and in free text a short name before `-` or `.` followed by
  a word that is not a qualifier (`pin-entry: 7392`, read like the host
  and port `pin-svc:7392`);
- encodings the agent does not decode: compressed bodies (gzip, deflate,
  compressed gRPC and Kafka batches), UTF-16 or UTF-32 text beyond plain
  ASCII, HTML named entities other than `&amp;` `&quot;` `&apos;` `&lt;`
  `&gt;`, PostgreSQL `U&"…"` identifiers;
- protobuf without its schema: field numbers, not names, so gRPC and
  protobuf body text is not exported at all while credentials are
  protected, nor is an HTTP/2 body whose content type is unknown (that
  direction lost a header block, the agent did not see the connection
  start, or the content type is repeated or over 256 bytes);
- packets forged or injected into a connection by someone who can do so,
  and state from before capture started that the parser cannot see.

If what these miss must not leave the node, use `metrics_only`.

A field has credential context when its *normalised view* contains one of
the words or forms below. The view is the field with NUL bytes dropped
(UTF-16 text of ASCII), then up to three rounds of JSON escapes
(`\u0070`; a `\u` not followed by four hex digits is left as it is, so
`C:\usr&password=…` keeps its name), HTML character references (`&#112;`, `&#x70;`, `&amp;` …)
and percent-encoding (`%70`, `+` as a space), so an encoding revealed by
another is decoded too (`%5Cu0077` is `w`); case folded; SQL comment
markers (`/*`, `/*!`, `*/`, `--`, `#`) ignored so a comment's text counts;
`-` and `.` read as `_`. A backslash before a letter is read both ways,
and context in either reading counts: as JSON (`\t` a tab, `\k` a `k`)
and as a separator with the letter kept, as in a Windows path, prose or
LaTeX (`C:\token` is `C: token`, `dir\key=…` is `dir key=…`). The words
and forms:

- a word containing `password`, `passwd`, `pwd`, `passphrase`, `passcode`, `secret`,
  `token`,
  `apikey`, `api_key`, `accesskey`, `access_key`, `privatekey`,
  `private_key`, `credential`, `signature`, `authorization`,
  `requirepass`, `masterauth`, `csrf`, `xsrf`, `bearer`,
  `clientassertion` or `client_assertion` (so the camelCase `apiKey`,
  `privateKey`, `accessKey` and `clientAssertion` count, case folded),
  or ending in `_pass` or `_auth` (names of any length), or `IDENTIFIED`
  followed by `BY`, `WITH`, `VIA`, `AS` or `USING`;
- one of the names `auth`, `pass`, `key`, `sig`, `session`,
  `sessionid`, `session_id`, `sid`, `cookie`, `jwt`, `masteruser`, `otp`
  or `pin` (`pwd` is in the first list: context anywhere), as the whole
  word or as one of its segments, used as a name: followed by `=` or
  `:`, a form or HTML field name (`name="pin"`, as in multipart form
  data), or an XML element (`<pin>`); in SQL also a column in a list or
  assignment (`users(pin)`, `SET a = 1, pass = $1`) or next to an
  operator (`otp - 0`, `pin+1`). A word's segments are
  split at `_` and at case and digit boundaries of the text as captured
  (decoded, case kept): a lower-case letter or digit followed by an
  upper-case one, an upper-case letter followed by an upper-case one and
  a lower-case one, a letter next to a digit. So `old_pwd`, `new_pwd`,
  `newPwd`, `loginPwd`, `card_pin`, `PIN_CODE`, `sms_otp`, `dbPass`,
  `userSessionId` and `otp2` are names, and so is a segment of more than
  three characters ending in `pin` or `otp`, or longer than the short
  name ending in `sig` or `pass` (not in `bypass`, `compass`,
  `encompass`, `overpass`, `underpass`, `surpass` or `trespass`), or
  holding `jwt`, `sessid` or `sessionid`, for names written in one case
  (`cardpin`, `SMSOTP`, `mpin`, `totp`, `reqsig`, `dbpass`, `storepass`,
  `userjwt`, `phpsessid`, `jsessionid`; `spin`, `hairpin` and `lowpass`
  too, a known over-match). Any other short name inside a segment with no
  boundary is not (`spinner`, `pinned`, `shipping`, `opinion`, `topic`,
  `keyboard`, `otpcode`, `bypass`, `signal`), nor is `sid` glued to a
  word (`x-usersid` reads as `users` + `id` as much as `user` + `sid`,
  like `x-processid`: a known limit), nor is a plural (`keys`, `pins`, `sessions`;
  Redis arguments differ, below), nor a whole name that is exactly
  `sort`, `partition`, `foreign`, `row`, `shard` or `range` and `key`
  (`sort_key`, `partitionKey`, `RowKey`, `row.key`: a record key; not
  `primary_key`, an Azure account key, `routing_key`, PagerDuty's
  integration key, `cache_key`, which can hold a session key, nor
  `hash_key`, `idempotency_key` or a longer name such as `x-sort-key`;
  Redis arguments and HTTP header names, matched by substring above, are
  read as before). These names are also looked for with
  `-` and `.` as word boundaries, as in the field, so a qualified name is
  still one (`users.pwd = …`, `?user.pwd=…`, `old-pwd:`, `pwd-0`), and in
  SQL on the statement as captured too; a short name followed by `-` or
  `.` is not used as a name in free text, so a host and port such as
  `auth-service:8080` is not context, unless the one word after it is
  `code`, `number`, `num`, `no`, `digits` or `id`, ending the token, and
  the whole is used as a name (`pin-code: 7392`, `otp-code:123456`,
  `key-id=…`; a host named exactly so, `pin-code:7392` as a host and
  port, is withheld too, a known over-match). So `/api/auth/login`, a Redis
  `AUTH` command name or "press any key" are not context;
- a credential name (as for header names, above: any word of the first
  list, or a short name as a segment, `-` and `.` splitting segments
  too) in a position that delimits the whole name: a JSON member name
  (`"pin-code":`), a query or form parameter name (`otp-code=`, at the
  start or after `?`, `&`, `;`, a line break or other whitespace:
  `a=1;pin-code=…`, `x=1 pin-code=…`), a form
  or HTML field name (`name="old-pwd"`, `name="user.newPwd"`, as in
  multipart form data) or an XML element name (`<old-pwd>`,
  `<ns:newPwd>`, `<user.pin>`);
- userinfo, `user:password@host`, with or without a scheme (the `:` of
  `scheme://` and `mailto:` do not count), and any `//` authority whose
  userinfo holds a `:` (RFC 3986: `,` and `;` may be part of the
  password), whatever follows the `@` (`postgres://user:pw@/db`, a Unix
  socket, is masked).

A word from the first list is not context when it is a *bare name*: in
one of the two allowlisted positions below, each only in a field of its
kind, which the protocol parser decides (never the text). Each is
checked on text that no decoding has changed: a path on the field as
captured, a `SELECT` on the statement as captured and only when decoding
would change nothing in it, so no encoding can hide a value from the
check. Anything outside the allowlist is context (when in doubt, the
field is withheld). No other field has a bare name: a Redis argument,
a Kafka topic, an AMQP field, a DNS name, a gRPC path, a header,
a body or an error message that reads `/oauth/token` or
`SELECT password FROM users` is withheld. Nor does an HTTP/1.1 path read
over TLS (below: its bytes may lie inside a body).

- **the last segment of an HTTP request path** (HTTP/1, HTTP/2), read
  on the path part as captured (the text before the first `?` or `#`):
  it starts with `/`; every segment is a plain name (ASCII letters, `-`,
  `_`, `.`: no digit, `%`, `+`, space, `U+00A0` or anything else); and
  the word is the last segment (no trailing `/`). A query or fragment
  after a bare path is never exported, whatever it holds: the path part
  is followed by `?<query withheld>` (so `/oauth/token?client_secret=x`
  and `/oauth/token?scope=read` both export as
  `/oauth/token?<query withheld>`, and so does `/oauth/token#x`; one of
  your patterns matching across the `?` or `#` withholds the field). So
  `/oauth/token` and `/users/me/password` are bare, while
  `/reset/token/abc123`, `/reset/token/++++`, `/v1/token`,
  `/oauth/token/` and `https://host/oauth/token` are context, and a
  field whose path part is context is withheld whole, query included. A
  path with no credential word keeps its query, with credential
  parameters masked (`/login?password=<REDACTED>&q=1`);
- **a projection item of an allowlisted `SELECT`** (a MySQL or
  PostgreSQL statement), read on its tokens as captured, with no comment
  marker (`--`, `#`, `/*`), double quote, backtick or backslash anywhere
  and nothing decoding would change (no `%XX`, `+`, `&…;` or NUL byte).
  The statement must be
  `SELECT item, … FROM table [WHERE col op value [AND|OR …]]
  [ORDER BY col [ASC|DESC], …] [LIMIT n [OFFSET n]] [;]`:
  - each item is `*` or a plain identifier (`[a-z_][a-z0-9_]*`, any
    case) that is not a value keyword (`TRUE`, `FALSE`, `NULL`,
    `CURRENT_USER`, `UTC_TIME` and the other niladic value keywords): no qualifier,
    literal, number or hex (`0x68756e74657232`), function or alias;
  - the table is a plain identifier, and from it to the end of the
    statement no credential word appears in any form, short or long,
    whatever splits it (so not `WHERE password = …`, `pwd LIKE 'x'`,
    `session IN (…)`, a table `user_tokens`): credential words may
    appear only as projection items;
  - a `WHERE` column is a plain identifier that is not the table itself
    (a PostgreSQL whole-row value); op is one of `=` `<>` `!=` `<` `<=`
    `>` `>=` `LIKE` or `IS [NOT] NULL`; and a value is a number (digits,
    each `_` between two digits: `1_000`), a bound
    parameter or a `'…'` string without `''`, `(`, `)`, `,`, `{` or `}`
    (no join, alias, subquery, function, row, cast, `UNION` or
    `VALUES`).

  So `SELECT password, email FROM users` and
  `SELECT password FROM users WHERE id = 1` are bare;
  `SELECT password, 123456 FROM users`, `SELECT "password", "hunter2"
  FROM dual`, `SELECT DISTINCT password FROM users`, `WHERE users = $1`,
  `WHERE profile = '\050alice\054…'` and `WHERE password = 'x'` are
  context. A value compared with a column that is not a credential word
  (`WHERE id = 1`) stays exported, as it would without the credential
  column. Such a statement is exported without its bound values. (No
  server error text is exported for any statement: it may echo a bound
  value, `malformed record literal: "(alice,hunter2)"`.)

Redis `CONFIG GET requirepass` is withheld whole: with renamed commands
and `CLIENT REPLY`, a reply cannot be tied to its request, so nothing
shows its argument is a parameter name rather than a value.

In a path the word must also end in a whole credential part (`token`,
`access_token`, `x-api-key`, `passwords`), not have more after it or
before it in the same word (`token_abc`, `hunterpassword`). In both
positions it must have no digit (`token9f8e` may be
a value), and none applies when decoding dropped a NUL byte (it may have
joined a name to its value; UTF-16 text is therefore never a bare name).
Prose is never a bare position: `token abc123`, `your token expired` and
`hunter2 is my password` are context.

What is exported then:

- **SQL** (MySQL, PostgreSQL): the statement becomes its keyword and
  `<statement withheld>` (`ALTER <statement withheld>`) and its bound
  parameter values are not exported. Neither MySQL nor PostgreSQL ever
  exports server error text (below). Only a known SQL statement keyword
  (`SELECT`, `INSERT`, `ALTER`, …) is ever exported as the method: a
  statement starting with anything else exports the method `QUERY`, and
  just `<statement withheld>` when withheld.
- **Any other field** (path, header value, method, content type, bodies,
  Kafka and AMQP fields): `<field withheld>`,
  unless every credential in it is one of these, in which case only the
  value becomes `<REDACTED>` and the rest stays readable: a query or form
  parameter (`name=value` at the start or after `?` or `&`, the value
  running to `&` or the end without a space), a JSON member whose value is
  a string, number, `true`, `false` or `null`, or the password of a `//`
  authority (`scheme://user:<REDACTED>@host`). So `/login?password=x&q=1`
  exports `/login?password=<REDACTED>&q=1`, while a JSON array or object
  under a credential name, a password in prose or `Authorization: Bearer …`
  inside a body withholds the field. A parameter or JSON member of these
  forms whose name is a credential name in a name position (above, so
  also `pin-code`, `otp.code`) has its value masked:
  `{"pin-code":"7392"}` exports `{"pin-code":"<REDACTED>"}`. What is left
  of the field once those are removed is read strictly: a credential name
  left in a name position (an array, object or cut-off value,
  `{"old-pwd":"x","pin-code":["7392"]}`) or any word with a short name as
  a segment, used as a name or not (`{"old-pwd":"x","note":"pin-code:
  7392"}`, `old-pwd=x&x=pin-code+7392`), withholds the field. In a field
  with no other credential context, free text with a short name before a
  `-` or `.` is not read as a name, since it cannot be told from a host
  and port (`auth-service:8080`), unless the one word after it is a
  qualifier (above: `pin-code: 7392` and `otp-code:123456` are withheld).
  Full mode masks every value `names_only` masks, whether or not the
  field has other credential context.
- **A Redis command** with credential context in any argument, or any
  argument (key, name or value, of any command) that names a credential
  read by segments (a credential word in it, or a short name as a whole
  segment), is withheld as one unit: key, arguments and the reply's
  shape (below), even where a field alone would only have a value masked.
  No Redis reply text is exported at all (below).
- **A header whose name is over 8 KiB** is replaced, name and value, by
  `<field withheld>`: a name is classified whole, never cut first.
- **A body with bytes captured after a gap** (bytes lost to ring drops
  or the capture cap, then more of the same body kept), or an HTTP/2 body
  whose stream's headers the agent did not see, is not exported (its size
  is): what is left may hold a credential's value without its name. This
  covers HTTP/1, HTTP/2 and AMQP message bodies; for AMQP, a gap inside a
  body frame that is not the body's last, or a gap that loses frame sync
  while a body is being assembled, followed by more of that body. A gap
  that only cuts a body's end, as the capture cap does to a large
  response, keeps the captured prefix (it is scanned and trimmed like any
  body). A Kafka request or response is decoded only up to a gap inside
  it, and a gap anywhere else restarts the parser, so its record text
  never joins bytes from both sides of a gap. A gap an HTTP/1, MySQL or
  Kafka parser cannot place (outside a body, result set or frame of
  known length) also withholds the connection's text for good (below).
- **AMQP after lost frame sync**: when a gap (or a malformed frame) loses
  AMQP frame boundaries in one direction, the agent looks for the next
  plausible frame, which may lie inside a message body (the gapped body's
  own bytes, or frames forged in a message) and nothing later proves the
  frames found real. For the rest of that connection, messages read from
  that direction export no text: no path (exchange, routing key, queue),
  header, content type or body, only a known method name (`Unknown` for
  any other, without its ids), a status that is an AMQP reply code,
  timing and sizes (a body's size as received, never the size its
  content header declares);
  a request read from it exports no text with its reply either. The other
  direction is unaffected. A connection the agent did not see from its
  first byte (it was open before the agent started, the protocol was
  recognised only after its first bytes, or a side's start was not
  captured, or a client stream that does not begin with the AMQP
  protocol header) is treated the same way in both directions from the
  start: its first frame boundary may lie inside a body.
- **HTTP/2 bodies** are not exported while credential masking is on when
  their content type is unknown, since they may be protobuf: on a
  direction of a connection that lost a header block (a block that failed
  to decode, was skipped or was over the size limit, a final response
  block after an informational `1xx` one included), for the rest of that
  connection, and for a stream whose header block carries more than one
  content type or one over 256 bytes (only the first 256 bytes of one
  content type are ever examined). On both directions of a connection the
  agent did not see whole (joined mid-stream, a side whose start was not
  captured, such as a lost SYN+ACK, bytes lost outside a DATA frame,
  which restarts the parser, or a TLS key) frame boundaries are unproven
  too, so no body is exported, whether or not credential masking is on,
  nor the code of an `RST_STREAM` (4 frame bytes, which may lie inside a
  body). On other connections that code is exported by its RFC 9113 §7
  name (`CANCEL`, `REFUSED_STREAM`, ...), `unknown` for any other value. This lasts for the connection: a
  client preface seen later on it does not lift it (it may be the payload
  of a DATA frame). Only a new connection observed from its start
  exports bodies again. Over TLS no connection is observed from its
  start: a TLS record carries no stream position, and a connection is
  keyed by the library's connection object address (OpenSSL `SSL*`, Go
  `*tls.Conn`), which a new connection can reuse after a closed one, so
  nothing shows that a record is its connection's first. **Every TLS
  connection starts latched**, in every mode, OpenSSL and Go alike: over
  TLS, HTTP/2 and gRPC export no header (no path, method, status,
  `grpc-status` or content type) and no body, whether or not credential
  masking is on; their records keep timing, sizes and addresses.
  A latched TLS connection also costs Redis its commands (each reply is
  exported with its error flag, timing and sizes only), AMQP its text
  (known method names, reply codes, timing and sizes stay), and
  PostgreSQL and MySQL everything but the statement keyword (from a
  closed set of SQL verbs): a packet read on the key may be framed from
  inside a bound value, its "statement" the rest of that value (MySQL 8
  defaults to TLS, so its statements are keyword only when captured
  through the TLS uprobes). HTTP/1.1 and Kafka over TLS are not latched,
  so HTTPS paths and Kafka records stay readable. Since bytes read on a
  TLS key may lie inside a body or a record, each follows a TLS rule:
  - HTTP/1.1: while credential masking is on, a request path holds no
    bare name. A path whose path part (before any `?` or `#`) has any
    credential word, `/oauth/token` included, is withheld whole
    (`<field withheld>`); any other path goes to the usual rules (keyed
    query values masked);
  - Kafka: a Metadata response names topic IDs on its own connection
    only, never for the pipeline's other connections (names learned on
    other connections still resolve on it);
  - DNS: never parsed over TLS. DNS over TLS (port 853) is not decoded,
    and a TLS connection to port 53 is not read as DNS.
  A parser restarted after lost bytes keeps its connection's TLS rule.
  Decoding HTTP/2 over TLS needs a proof that a connection starts at its
  first record, which is planned separately.
- **Integrity limit: HTTP/1.1 and Kafka over TLS.**
  These parsers read a TLS key as if it started at its connection's
  first record, and a TLS record lost to a ring drop leaves no trace on
  its key. So a key first seen in the middle of a connection, or one
  that lost a record, can be read out of step, and a record can be
  exported under the wrong request, or a body's rest as the whole body:
  - HTTP/1.1: a lost response pairs every later response with the
    request before its own (status, body and timing under the wrong
    path), and a key that starts inside a body at bytes that read as a
    request exports them as a request (its path under the TLS rule
    above) with the next real response attached; a record lost inside a
    request or response body leaves the rest of the body exported as if
    it were the whole, so a value whose name was in the lost part (the
    tail of `"password":"…"`) is exported without it;
  - Kafka: responses pair by correlation ID, so a lost record shifts
    nothing; but a response read from inside a record that matches a
    request in flight exports its records under that request.
  A record exported under the wrong request moves no value under a
  weaker rule (a path, a body and a record are protected by the same
  rules wherever they are paired); a body's rest exported as a whole
  body can. (MySQL and PostgreSQL over TLS export keywords only, so
  neither applies to them.) A TLS read or write larger than the
  capture's 16 KiB per call, or one whose bytes could not be read, is
  marked and handled like a TCP gap; what goes unmarked is a record the
  ring could not hold, a call a probe missed, and a call cut by a scope
  change. Detecting a lost record per TLS key is planned, with the
  HTTP/2 over TLS work. A TCP connection is not affected: a connection
  whose start or bytes the agent missed is detected and withheld as
  described for each protocol below.

  Concurrent `Write`s on one Go connection are captured at their start,
  before `crypto/tls` serialises them, so two that overlap may be
  captured in the opposite order to the wire. HTTP/2 encodes and writes
  each frame under one lock, so only writes whose order HTTP/2 leaves
  open can swap; redaction does not depend on order, and a swap that
  breaks parsing latches the connection.

  The agent finds Go binaries by scanning running processes (every 60 s
  by default, `tls_scan_interval_secs`), so a new binary's TLS traffic
  before the scan that finds it is not captured. A Go binary that
  attached no probe is tried again after 2, 4, 8 and 16 scans, then every
  32. New processes and restarts of a binary or library already
  attached share its probes, on the host and inside one container.
  **Each container of an image is attached separately**: its overlay
  root shows the image file under a device of its own, and the agent
  cannot prove from user space which image layer file is behind it (a
  wrong guess would leave another file unprobed). The image file then
  carries one copy of each probe per attached container, and the copies
  are deduplicated in the kernel: each record is exported once, and a
  real call repeated with identical bytes is kept (two server containers
  and a client container of one Go image: 100% of 300 HTTPS exchanges in
  both views, no duplicate). This needs attach cookies (kernel 5.15 or
  newer, or RHEL 9's 5.14). On kernels without them (upstream before
  5.15, such as 5.10 on Debian 11 or Amazon Linux 2, and RHEL 8's 4.18)
  every copy would export its records, so there the agent records the
  inode each attach landed on, as the kernel shows the agent's own
  mapping of the file, and does not attach another container whose
  process maps that inode: on RHEL 8.10 the same lab case gives 100% of
  the exchanges in both views, no duplicate (6.7-12.7% client and
  37.7-39.7% server, 92-99 duplicates before). Where it cannot show that
  (a kernel whose maps show an overlay's own inode, as the Ubuntu ones
  do, or a file that changed during the attach), each container is still
  attached and every copy exports its records: OpenSSL
  writes with an unrestricted capture scope, Go reads, and Go writes of a
  binary without the guarded `Write` probe are exported once per
  container of the image. Upstream kernels before 5.15 show the inode
  behind an overlay file, as RHEL does, but were not measured. A repeated record there repeats an exported
  record or makes its parser withhold more; the TLS rules above hold for
  every record, and no value is exported that the record alone would not
  give, but repeats cost accuracy: records are exported twice, and a
  repeated reply can break request pairing (9.0% of the exchanges matched
  in the client view of the same lab case before the dedupe).
  A file is attached again when it changes under the probes: a chmod,
  touch or open for writing inside a container copies an image file up
  to a new file, and processes started after it run that new file; the
  agent sees the change and attaches it at its next scan. Not covered: a
  process that mapped the image file before the copy-up, if the agent
  had not attached it by then, or if the copy-up came while the agent
  was attaching it; a process still running a library that was replaced
  (deleted) under it, until it restarts; and a FUSE file inside a user
  namespace that imitates a file already attached (this needs
  `/dev/fuse` and user namespaces, which default Docker and Kubernetes
  deny). Each change of a file's ctime adds a copy of each probe; past
  63 copies on one file, some records are exported twice. On RHEL 8 the
  attach after a copy-up covers the processes running the new file
  (copy-up lab on 8.10, 2026-11-22 and 2026-11-26: 100% in both views,
  no duplicate; 7.3-9.3% client, 39.3-41.7% server and 95-100
  duplicates before), but a ctime
  change without a copy-up (a chmod of a host library already attached)
  adds a copy whose records are exported twice.
- **HTTP/2 headers**: after a header block of one direction fails to
  decode or is skipped, that direction's header table may differ from the
  peer's, so no header of it is exported again on that connection; on a
  connection the agent did not see whole (as above, every connection over
  TLS included), no header is decoded at all. Both last for the
  connection.
- **DNS answers** whose name has credential context (any credential
  word: a DNS name holds no bare name, so `db.password.internal`
  included), or matches one of your `[credentials]` patterns, are
  dropped before export and before the name can reach the service graph.
- **Bare names** are exported as written: an HTTP request path
  `/oauth/token` and a SQL statement `SELECT password, email FROM users`
  (without bound values). The query or fragment after a
  bare path is dropped: `/oauth/token?client_secret=x` exports
  `/oauth/token?<query withheld>`. Over TLS an HTTP/1.1 path has no bare
  name (the TLS rules below): `/oauth/token` is withheld.

The price is more withheld text than a value-level mask would leave:
a `SELECT` that compares a `password` column, names a credential word
outside its projection or falls outside the allowlist above (a comment,
a join, a quoted name, a literal item), an `INSERT` or `UPDATE` naming
one, any field of another kind that reads like a bare name, a body that
mentions a token or a secret in prose, a path with a digit or a value
around a credential word (`/v1/token`, `/reset/token/abc123`), a field
that is just a credential name (a Kafka topic `user.password`, a header
value `Authorization`), or a Redis command naming `requirepass`
(`CONFIG GET requirepass`) is withheld whole.

A known limit of the path position: a segment of letters only before a
credential word is exported, as in `/reset/abcdef/token`. With no route
table, a letters-only code there cannot be told apart from a route word
such as `oauth` in `/oauth/token`; it is exposed as much as any
letters-only path segment with no credential word nearby.

Redis reply text is never exported: a reply's `payload_text` is its
type and size only, `(bulk, 6 bytes)`, `(array, 3)`, `(map, 2)`,
`(set, 1)`, `(integer)`, `(error)`, `(nil)`, `(boolean)`, `(double)`.
A status reply is kept only when it is one of a fixed set of protocol
words (`OK`, `PONG`, `QUEUED`, `RESET`, and `TYPE`'s `none`, `string`,
`list`, `set`, `zset`, `hash`, `stream`); any other status is
`(status)`. So no value read (`GET`, `HVALS`, `HGETALL`), password
(`ACL GENPASS`, `CONFIG GET`), error quoting an argument or other
command's arguments (`SLOWLOG GET`) leaves the node, and the result of
an `EXEC` is its shape, `(array, n)`.

Redis commands are masked before this rule runs. The command's secret is
masked in `AUTH`, `HELLO … AUTH`, `MIGRATE … AUTH`/`AUTH2`, `CONFIG SET`
and `SENTINEL SET` of a credential-named parameter, and `ACL SETUSER`
password rules. The rule above then applies to the masked text:
`AUTH <REDACTED>` and `HELLO 3 AUTH default <REDACTED>` stay readable
(`auth` is not used as a name there), while an argument holding a word
from the first list, alone or with a value next to it, masked or not
(`CONFIG GET requirepass`, `CONFIG SET requirepass <REDACTED>`,
`SET k swordfish_password`), is withheld whole: no Redis field has a
bare name (above). A Redis command is protected as one unit: when any of
its arguments has credential context, read together or one by one, or
any argument or the command's own name (a module command such as
`OTP.SET`; not `AUTH`, whose arguments are masked by their own rule,
nor `KEYS`) names a credential read by segments (below), or the
command's name is not a built-in one and holds a credential word or
short name anywhere (below: `SETOTP`), the key
(`path`), the arguments (`request_text`) and the reply's shape are all
exported as `<field withheld>` (method, status, timing and sizes stay).
So `SET otp:+15551234567 482913 EX
300`, `SETEX password_reset_token:alice 3600 <token>` and
`GET otp:+15551234567` export no key, value or reply, however opaque the
value; field-by-field, the key would be withheld and the value next to it
exported. A key, field name or other argument has no free text around
it to show that a short name is used as a name, so every argument of
every command (key, names and values alike, known command or not) is
also read by segments: every character that is not an ASCII letter or
digit separates segments, and so do case and digit boundaries: a
lower-case letter or digit followed by an upper-case one (`pinCode` is
`pin`, `Code`), an upper-case letter followed by an upper-case one and a
lower-case one (`OTPCode` is `OTP`, `Code`), and a letter next to a
digit (`otp2` is `otp`, `2`); case folded. An argument that contains a
word of the first list above anywhere, with separators read as `_`
(`u:1:apikey`, `session_token`, `clientAssertion`), or one of whose
segments is a short name whole or with a plural `s` (`otp`,
`user:1:pin`, `u|otp`, `u otp`, `api-key`, `pinCode`, `pins`, `otps`,
`keys`, Django's `:1:django.contrib.sessions.cache<id>`), names a
credential. A short name joined to other letters with no boundary does
not count, so `mykey`, `spinner`, `author` and `otpcode` name no
credential. A command name is read by segments too (`OTP.SET`,
`PinSet`), and since Redis's built-in command names are a closed set, a
name that is not one of them (a module or custom command) also names a
credential when it holds a credential word or short name anywhere,
glued or not: `SETOTP`, `OTPSET`, `PINSET`, `SESSIONSET` and
`MYAPP.SETPIN` are withheld with their command. The built-in names that
hold such letters (`PING`, `KEYS`, `HKEYS`, `RANDOMKEY`,
`JSON.OBJKEYS`, `FT.DROPINDEX`, KeyDB's `KEYDB.*`) do not count; a
custom command whose name merely holds the letters (`MYKEYS`, `ASSIGN`)
is withheld too, an over-match.
So `SET otp 482913`, `SET user:1:otp 482913`, `HSET u:1 pin 1234`,
`SET session_token abc`, `EVAL <script> 1 otp`, `XADD events * otp
482913`, `LMOVE incoming user:1:otp LEFT RIGHT` and `JSON.GET u:1 $.pin`
are withheld whole, and so is a command whose value only mentions a
credential word (`SET note "my api key"`), while `GET mykey`,
`HSET book:1 author x` and `SET 2fa:alice 123456` are not (`2fa` is not
in the lists). This holds
whatever `builtin` is set to; your own patterns
still apply to every field. Protocol and subscription
state follow the server's replies only, and a subscription
acknowledgement counts only as the reply to the pending subscription
command (a script returning an array of the
same shape changes nothing). A reply that cannot be matched to its command
is exported with neither the command nor its shape (status, timing and
sizes only). Every later reply of the connection is exported that way
after any of: `UNSUBSCRIBE` with no channel; `CLIENT REPLY OFF|SKIP`
(never acknowledged, so a refusal cannot be seen); any `CLIENT REPLY`
other than `CLIENT REPLY ON`; `MULTI`, `EXEC`, `DISCARD` or `RESET` sent
with arguments; `CLIENT`, `HELLO` or a subscription command queued
inside `MULTI`; a transaction past 1024 commands or 64 KiB; an array in
place of a subscription command's acknowledgement. Nothing more at all
is exported for a connection after `MONITOR`, `SYNC`, `PSYNC` or
`REPLCONF` (also queued inside `MULTI`): what follows is a stream of
monitored commands or replication data (a master propagates writes such
as `SET user:1:otp 839201` on the same connection) that answers no
command. The same holds after a request that is not a RESP array (an
inline command, a bare bulk string, a RESP3 null or map): the server
reads it as inline lines, so its replies cannot be paired.

Replies are paired with commands by order, which is only safe when the
agent saw both directions of the connection from their first byte, which
the kernel's stream offset proves; any bytes lost later (ring drops,
capture cap) end the proof. Without it Redis replies are exported
for the rest of the connection without their text or the command they
answer (status, timing and sizes only). That covers every connection
already open when the agent started (pooled clients, until they
reconnect), every TLS-captured Redis connection (TLS plaintext carries no
stream position), and any connection whose SYN events were lost. A reply
that may answer a command sent before capture started, such as an
`ACL GENPASS`, is therefore never exported under the first command
captured. SQL bound values are exported only for a statement whose
prepare the server confirmed on this connection, after the last lost
client byte. In PostgreSQL a `Bind` is tied, when the agent reads it, to
the SQL its statement (the unnamed one included) has at that point of
the client's messages: the latest unanswered `Parse` of that name before
it, which must then be confirmed by its `ParseComplete`, or else the
statement already confirmed. Its values are exported only under that SQL,
once confirmed, when it is the SQL the event shows and is not withheld,
even if the statement is redefined later; a `Bind` of another statement
than the cycle's `Parse`, or of one the server rejected, exports no
values. The agent keeps the client's messages that await an answer in
order and pairs each answer with its own message: every `Execute` gets
its own record, also when several statements share one `Sync` (JDBC
batches, libpq pipelines), with its own values and status. A
FunctionCall (libpq `PQfn`, `lo_*`, the JDBC fastpath) is answered in
the same queue and not reported; a client message the queue does not
model makes the connection's answers untrusted (below). **PostgreSQL
error and notice text is never exported**: an `ErrorResponse` adds only
its SQLSTATE (`sqlstate`, five characters such as `22P02`) and severity
(`severity`, such as `ERROR`) to the record, as headers, and status 1.
Its message, detail, hint and context and the schema, table, column,
type and constraint names are dropped: the server echoes bound values
and rows in them (`invalid input syntax for type integer: "hunter2"`),
and which statement an error answers is only as sure as the pairing. An
error is reported under the message that failed: a failed `Parse` under
its own SQL, a failed `Bind` or `Execute` under the statement it ran; a
failed `Describe` or `Close`, or an error answering the `Sync` (at
commit), with no statement. The statements the server then skips to the
`Sync` are not reported, since they never ran.
At most 4096 messages awaiting an answer are kept, holding at most 1 MiB
of bound values (a `Bind` past that is exported without them); past
4096 the connection is treated as joined mid-stream (below). A `Parse` the server rejects
does not replace a statement, and a re-`Parse` or `Close` forgets it
until confirmed. A simple Query ends the unnamed statement, so the agent
forgets it. SQL that names `PREPARE`, `DEALLOCATE` or `DISCARD` as a
word, in any case and anywhere in its text (comments and string literals
included), may create, redefine or destroy any named statement: when a
simple Query or a `Parse` carries such SQL, every statement is forgotten,
confirmed or pending (unanswered `Parse` messages are cancelled). Other
SQL leaves named statements as they are. Known limit: a server-side
function can run `PREPARE` or `DEALLOCATE` dynamically (a PL/pgSQL
`EXECUTE` of a string built at run time) and redefine a named statement
the agent cannot see. A `Bind` of a statement confirmed in an earlier
exchange (whatever else its group runs) therefore exports its values
only when the server's `CommandComplete` names the same command as the
SQL it was confirmed with (`INSERT 0 1` for an `INSERT`; no values after
an error, or for SQL whose first keyword is not the command, such as
`WITH`). The check compares the command word only. It catches a
redefinition to another command, not one to the same command: a
statement redefined unseen from `INSERT INTO users (note) VALUES ($1)`
to `INSERT INTO accounts (password) VALUES ($1)` would export the
password under the first SQL. `PREPARE` accepts only `SELECT`,
`INSERT`, `UPDATE`, `DELETE`, `MERGE` and `VALUES`, so a statement
cannot become `ALTER ROLE ... PASSWORD`. The keyword test reads the text
the agent sees, so dynamic SQL assembled at run time (`'DEALL' ||
'OCATE s'`) is part of the same limit. A `Bind` of a
statement whose SQL the agent does not know (prepared before capture, or
forgotten) is still exported, as `EXECUTE` without SQL or bound values. Several `Parse` messages may be sent before one `Sync`
(pipelining); each `ParseComplete` confirms the oldest `Parse` still
unanswered. After an error the server skips to the `Sync`, so the
`Parse` messages before it are never confirmed; a `Close` of a name also
cancels an unanswered `Parse` of it. When an answer matches no message
awaiting one (the server's framing intact), the agent drops answers
until a `ReadyForQuery` it can attribute: one that arrives while exactly
one group (up to a `Sync`, a simple Query or a FunctionCall) awaits an
answer. With the framing intact every `ReadyForQuery` is real and
answers one group the agent tracks, in order, so the groups it holds are
never fewer than those really waiting. Until then the groups are
reported without bound values or status, and the names their `Parse`
messages defined are forgotten (they may or may not have been
confirmed); statements confirmed before stay known. A `ReadyForQuery`
that arrives while more groups wait cannot be attributed, so a client
that sends its next query only after each answer can stay in that state.
The connection's answers are untrusted for the rest of its life when
server bytes are lost (the next `ReadyForQuery` is found by its bytes,
which may be row data, and so may every message read after it), when
the agent joined it mid-stream or did not see a side from its first
byte (answers to messages sent before capture may still come; bytes
that look like a startup message may be the inside of one), when the
client sends a message the queue does not model, or past 4096 messages
awaiting an answer: records go on, but no `Parse` is confirmed and no
bound value is exported on it, until a new connection is observed from
its start. After lost server bytes no SQLSTATE is exported either (it
may be row data; the error flag and severity stay). When the client
stream itself is unproven (joined mid-stream, client bytes lost, a TLS
key, or a client message of unknown type), a message found there may
be a header inside a `Bind` value, and its "SQL" the rest of that
value: records keep the statement keyword only, from a closed set of
SQL verbs (`EXECUTE` when the statement is unknown), with no SQL text,
bound value, error, status or latency.

**MySQL error text is never exported** either: an ERR packet adds only
its error code (`status`, such as `1366`) and its SQLSTATE (`sqlstate`,
five letters or digits after `#`, such as `HY000`) to the record. Its
message is dropped, since it echoes statement text and values
(`Incorrect integer value: 'hunter2' for column 'pin'`), and so are the
`info` text of an OK packet and every row (`SHOW WARNINGS` included).
MySQL answers commands in order, and the agent pairs a reply with the
command in flight only for commands whose replies it models: a
`COM_QUERY` or `COM_STMT_EXECUTE` is one record however many result
sets it returns (a multi-statement query or a `CALL`, up to the result
without "more results"), including a `LOAD DATA LOCAL INFILE` file
transfer (the file's packets are never read as commands nor exported);
a `COM_STMT_PREPARE` is reported only when it fails; `COM_PING`,
`COM_INIT_DB`, `COM_STATISTICS` and the other single-reply commands are
not reported; `COM_QUIT`, `COM_STMT_CLOSE` and
`COM_STMT_SEND_LONG_DATA` get no reply. Any other command
(`COM_CHANGE_USER`, `COM_FIELD_LIST`, `COM_STMT_FETCH`, an `EXECUTE`
that opens a cursor, the replication commands, unknown ones), a reply
packet out of sequence, server bytes with no command in flight, a reply
the agent cannot read, lost server bytes on a connection whose client
sends a command before the previous reply ends, or a connection the
agent joined mid-stream or did not see from its first byte (a packet
boundary found there may lie inside a statement or a row), or a TLS
key (its first record may lie inside a bound value) makes the
connection's replies untrusted for the rest of its life: records go on
with the statement's keyword only, from a closed set of SQL verbs (no
statement text, bound value, status or latency). A connection that switches to TLS (`SSLRequest`)
or to the compressed protocol is not parsed past that point.

**HTTP/1** requests are queued in the order they are read, and each
final response answers the oldest (pipelining included). `1xx`
responses other than `101` are interim and answer nothing; a response to
`HEAD`, a `1xx`, `204` or `304` has no body whatever its headers say;
request bodies are read by `Content-Length` or chunked encoding. After
`101 Switching Protocols` (WebSocket, h2c) or a `2xx` to `CONNECT`, and
after a response with neither a length nor chunked encoding (its body
runs to the close; it is exported without the body), nothing more of
the connection is read. Which direction carries requests is learned
once, from the first message start, never from each segment's bytes.
A connection the agent joined mid-stream or did not see from its first
byte (over TCP; over TLS see the integrity limit above), bytes lost
outside a body of known length, a malformed
message, a request whose framing the server may read differently
(conflicting `Content-Length`, or `Transfer-Encoding` with
`Content-Length`) or a response with no request waiting makes the
connection unsynced for the rest of its life: a request line found
there may lie inside a body. Records go on with a known method (`GET`,
`POST`, …) and the sizes only: no path, header, content type, body,
status or latency. Conflicting `Content-Length` values in a request, a
request transfer coding that does not end in `chunked`, or broken chunk
framing also stops the parsing of the connection.

**Kafka** responses are paired by correlation ID, never by order, so an
`acks=0` Produce (no response; exported on the request) moves no other
pair. A connection the agent joined mid-stream or did not see from its
first byte (a frame boundary found there may lie inside a record; over
TCP, as TLS has the integrity limit above), a
correlation ID reused while still awaiting its response, or a
`SaslHandshake` v0 (bare SASL token frames follow, not Kafka requests)
makes the connection unsynced for the rest of its life: records keep
a known API name (`Unknown` for any other key, without its number) and
the sizes only (no `api_version`, which is frame bytes too), and its
Metadata responses name no topic ID for the other connections.

**DNS** responses are paired by transaction ID and query name, never by
order. Over UDP every datagram is a whole message, so there is no
boundary to lose; but a datagram carries no stream position, so a UDP
flow and a TCP connection joined mid-stream look alike to the parser,
and on both it reads only a datagram whose sections account for every
byte. Over TCP (length-prefixed messages) a connection the agent joined
mid-stream exports the method and sizes only for the rest of its life:
a length prefix found there may lie inside a message (a TXT record can
hold a whole forged response), so no name, record, status or DNS answer
is exported from it.

**gRPC and HTTP/2** responses are paired by stream ID, so a call answered
out of order, reset, or never answered moves no other call.

**After an agent restart**, a TCP connection that was open before the
agent started (a keep-alive client, a connection pool, a Kafka
producer) is joined mid-stream: it exports method or statement
keyword only (HTTP/1.1, MySQL, PostgreSQL and Kafka; the other
protocols as described above for a connection joined mid-stream) until
the client reconnects. Connections opened after the
agent started are decoded in full. (With any scope setting, such
connections are not captured at all: `uninit`, §4.2.)

#### Your own credential formats: `[credentials]`

When you know what your secrets look like, list them:

```toml
[credentials]
patterns = [
  "AKIA[0-9A-Z]{16}",                  # AWS access key IDs
  "(?i)aws_secret_access_key\\s*=\\s*\\S+", # an AWS secret in a config dump
  "sk_live_[0-9a-zA-Z]{24,}",          # Stripe-style live keys
  "(?i)acme_[a-z0-9]{32}",             # an internal token format
]
builtin = "full"                       # or "names_only"
```

Patterns use the Rust `regex` syntax (linear time, no backreferences).
Every text field of every protocol is checked: method, path, content type,
header names (also when the value was wiped as a credential header) and
values, request and response bodies, SQL text and bound values, Redis
arguments, Kafka and AMQP fields; a DNS answer whose name a
pattern matches is dropped. A match in the field as captured is replaced
by `<REDACTED>`. When the field has escapes, entities or percent-encoding,
its decoded view (case kept) is matched too: a match there that is not
the same match at the same place in the captured text cannot be placed
there, so the field becomes `<field withheld>`. Your patterns and the built-in rules all look at the
field as captured, before PII redaction rewrites it, and their matches are
replaced together in one pass: the order of your patterns does not matter,
and no pattern hides another's match or a credential name from the
built-in rules. Captured text is matched whatever it reads like, a
literal `<REDACTED>` included, in a header value as in any field. A
field with more than 1024 matches is withheld. Patterns
apply whenever credentials are protected (`mask_credentials` on, the
default).

Limits: at most 256 patterns, each at most 1024 bytes, none able to match
without consuming a character (`x*`, `\b`, `^`), and each and all
together within a compiled-size limit. A pattern that is invalid or over
a limit stops the agent at startup with the regex error, and a SIGHUP
reload carrying one is refused (the running rules stay). A reload that
changes `patterns` or `builtin` applies to every message whose scan starts
after it; each message is protected under one rule set, so a message being
scanned at that moment finishes with the previous rules.

`builtin = "names_only"` keeps the cheap built-in rules: credential-named
headers, the certain structures above (credential-named form parameters
and JSON members, URI userinfo), SQL statement withholding and Redis
whole-command withholding (both decided by the parsers). It skips
looking for credential context in the free text of other fields, so a
body mentioning a token in prose, or a JSON array under a credential name,
is exported. Use it when your own patterns cover the formats that matter
to you and the free-text scan costs too much (BENCHMARKS.md, "Credential
protection").

Your patterns make masking stronger for your formats; they do not change
the best-effort nature of credential protection in `redacted` and `full`.
`panopticon_credential_matches_total{source="user"}` counts your
patterns' matches and `{source="builtin"}` the fields the built-in rules
changed (never values).

All of this applies in every privacy mode by default, `full` included,
and with PII detection off (`[pii] enabled = false`). The raw dump
(`full` mode, §5.5) always keeps credentials. The AMQP and Kafka SASL
exchanges are never exported as events.

To export login secrets too, `full` mode accepts:

```toml
[privacy]
mode = "full"
mask_credentials = false   # default true
```

The agent refuses `mask_credentials = false` in `redacted` and
`metrics_only`, and in `full` with `[pii] redact = true`; it prints a
warning at startup when it is set. Changing it needs a restart (SIGHUP
reloads that change it are rejected).

| `full` mode settings | PII values | Login secrets |
|---|---|---|
| default | exported | masked (best effort) |
| `[pii] redact = true` | masked | masked (best effort) |
| `mask_credentials = false` | exported | exported |

Detection is pattern-based. It will miss PII that does not match a pattern
(names, free-text addresses), a bare phone or passport number with no keyword
before it (e.g. in a positional SQL `VALUES` list), and anything past
`max_body_bytes`. It flags every IPv4 address and PAN-shaped product codes.
Treat the exports as sensitive anyway. If what the patterns miss must not
leave the node, use `metrics_only`.

### 5.4 Metrics and endpoints (`--metrics-bind`)

| Endpoint | Purpose |
|---|---|
| `/healthz` | 200 while the process is up (liveness) |
| `/readyz` | 200 once eBPF programs are attached; 503 during shutdown, and for good after capture was stopped by a failed scope publication (the agent stays up, disarmed; restart it). The body also counts caught worker panics, if any |
| `/metrics` | Prometheus text format |
| `/debug/state` | JSON counters (no traffic content) |

| Metric | Meaning — what to watch |
|---|---|
| `panopticon_events_received_total` | Events read from the kernel. Flat at 0 → nothing is being captured (§6). |
| `panopticon_events_processed_total` | Events handled by workers |
| `panopticon_events_dropped_total` | All drops; should stay near 0 |
| `panopticon_drops_rate_limit_total` | Records over `max_events_per_sec` (a large packet is several records, §4.2) |
| `panopticon_kernel_ringbuf_drops_total` | Lost in the kernel: the agent did not drain the ring buffer fast enough. Give it more CPU |
| `panopticon_drops_channel_full_total` | Parser workers falling behind (bursts or too little CPU) |
| `panopticon_worker_panics_total` | Parser or PII steps that panicked on captured data. The step is skipped (a parser panic closes that connection) and the worker keeps running. Any increase is a bug: please report it |
| `panopticon_drops_export_full_total` | Parsed exchanges the JSON writer could not keep up with (slow disk) |
| `panopticon_drops_parser_error_total` | Streams a parser gave up on |
| `panopticon_tcp_segments_ignored_total` | TCP segments not parsed: retransmissions of bytes already parsed (normal on lossy links), or segments and RSTs outside the connection's sequence window (forged, or stale). Only the next expected bytes of each direction reach the parsers, once |
| `panopticon_tcp_reorder_held_total` | TCP records held briefly because their bytes arrived ahead of the next expected byte: the records of two packets of one socket, captured on two CPUs at once, can reach the agent interleaved. Held with the rest of that connection's records (at most 5 ms, 128 KiB per connection, 1,024 records per worker) until the missing bytes arrive |
| `panopticon_tcp_reorder_gaps_total` | Records that went on with the hole before them still open (the hold's time or space bound was reached, or the hole was wider than 64 KiB): the missing bytes are taken as lost, a gap for the parser (§5.3) |
| `panopticon_capture_truncated_total` | Packets or TLS calls with bytes past the capture cap: `max_packet_bytes` per packet (16 KiB by default; 64 KiB on a connection `raise_packet_cap` raised), 16 KiB per TLS read or write, a `head_only` cut (§5.5), or a packet held before `accept()` past its first 4 KiB (§4.2). Parsers account for the skipped bytes, but one that loses a message boundary there stops exporting some fields for the rest of the connection (§5.3) |
| `panopticon_conn_cap_raised_connections_total` | TCP connections whose packet cap `raise_packet_cap` raised to 64 KiB (§4.2): the kernel map took the write (a refused write counts in `panopticon_conn_cap_write_failures_total` only) |
| `panopticon_conn_cap_raised_packets_total` | Packets over `max_packet_bytes` captured past it on raised connections |
| `panopticon_conn_cap_cut_packets_total` | Packets of raised connections still cut, at 64 KiB (BIG TCP) |
| `panopticon_conn_cap_truncated_before_raise_total` | Records of raised connections cut at `max_packet_bytes` because the kernel sent them before the agent raised the connection (its first packets) |
| `panopticon_conn_cap_write_failures_total` | Raises not written: the kernel map refused the write, the writer thread's queue was full, or the thread is not running; those connections stay at `max_packet_bytes` |
| `panopticon_conn_cap_refused_full_total` | Raises refused because the agent already keeps 12,288 raised connections (§4.2); those connections stay at `max_packet_bytes` |
| `panopticon_scope_dropped_events_total{reason}` | Packets and TLS calls the kernel did not capture because of the capture scope (§4.2), by `reason`: `not_eligible`, `uninit`, `no_owner`, `out_of_scope`, `sampled_out`, `no_baseline`, `head_cut`, `head_incoherent`, `tls_mode`, `tls_out_of_scope`, `ktls_payload`, `loopback`, and for the pre-accept hold (§4.2) `pending_overflow` (not held: two packets already waiting, the budget spent, the listener's share and the overflow pool spent, or the socket's option memory full, or the accept of a thread blocked in `accept()` before the agent attached never seen; a held packet's bytes past 4 KiB count in `panopticon_capture_truncated_total` instead), `pending_race` (lost racing the hold's release), `pending_discarded` (held, then discarded in the kernel: an unlisted acceptor, a scope change, or closed unaccepted) |
| `panopticon_drops_stale_scope_gen_total` | Events dropped because a narrowing of the scope came after the kernel captured them |
| `panopticon_pii_detections_total` | PII values found |
| `panopticon_credential_matches_total` | Credentials protected, by `source`: `user` = matches of your `[credentials] patterns`, `builtin` = fields the built-in rules masked or withheld. Never values |
| `panopticon_pod_filter_unresolved_total` | Resolutions of a pod `pod_filter` selected that left it uncaptured, by `reason`: `not_found` (no cgroup directory in the kubepods roots searched: a pod not started yet, a static pod, or a kubelet cgroup root to name in `pod_cgroup_root`), `ambiguous` (several), `unusable` (the one found cannot be opened, is not root's, or is group- or other-writable). Counts every resolution, not pods: the selected pods are resolved again on every pod change, so a pod that stays unresolved (Pending) adds one each time, while its error is logged once per pod and reason. Rising → check the agent's errors |
| `panopticon_active_connections` | Connections being parsed |
| `panopticon_raw_capture_dropped_total` | Events missing from the raw capture file (writer fell behind) |

The endpoints have no authentication: bind to loopback or a private address.

### 5.5 Raw capture: the full, unredacted payloads

Pattern-based PII detection misses things (names, free-text addresses,
domain-specific identifiers) and flags others it should not. If you need to
run your own classifiers, keep an evidence trail, or check what Panopticon
reported, capture the raw bytes. This needs privacy mode `full` (§4.3):

> **Security warning.** A raw capture holds every payload the agent saw,
> exactly as sent: passwords, session tokens, API keys and personal data,
> and for TLS connections captured through OpenSSL or Go the **decrypted**
> plaintext. Anyone who can read the file, or the pcap made from it, can
> read that traffic. The agent warns at startup whenever mode `full` is on,
> and decoding a capture needs `--privacy-mode full` too.

```bash
sudo panopticon-agent --privacy-mode full --capture-raw /var/lib/panopticon/raw.pncap
# later, anywhere, without root:
panopticon-agent --privacy-mode full --decode-capture /var/lib/panopticon/raw.pncap > raw.jsonl
# or, for Wireshark / tshark:
panopticon-agent --privacy-mode full --decode-capture /var/lib/panopticon/raw.pncap --pcap raw.pcap
```

**Opening it in Wireshark.** `wireshark raw.pcap` (or `tshark -r raw.pcap`)
opens the converted file directly. Captured events hold application payload
only, so the converter writes each one as a raw IPv4 packet (no Ethernet
header) with a TCP or UDP header built from the event's addresses, ports and
direction, and TCP sequence numbers that run per connection and direction.
Wireshark's dissectors therefore see ordinary cleartext traffic: HTTP inside
TLS shows as HTTP, and *Analyze → Follow → TCP Stream* shows each
connection's requests and responses in order. Details:

- TLS connections captured through OpenSSL or Go appear as their
  **plaintext**, under the connection's real addresses once the agent learned
  them. Packets of the same connection seen on the wire (the ciphertext) are
  left out, and when both ends run on the node only the server's view (the
  end with the lower port) is kept. A TLS connection whose addresses were
  never seen is shown as `127.0.0.1:<port> → 127.0.0.2:443`.
- Bytes that were not captured (beyond `max_packet_bytes` of one packet or
  16 KiB of one TLS read or write, see below) show as gaps ("previous segment not
  captured"), not as corrupted streams.
- Packets carry no handshake (SYN/FIN), so Wireshark marks the first one of
  each connection "previous segment not captured"; that is expected.
- Timestamps are the kernel's monotonic clock (time since boot), so dates
  show as January 1970; the intervals between packets are real.
- The pcap is created owner-only (`0600`), like the capture.

Each decoded line is one captured packet or TLS buffer:

```json
{"timestamp_ns":1479319283059,"event_type":"TcPacket","direction":"Ingress",
 "src":"10.99.0.2","src_port":48540,"dst":"10.99.0.1","dst_port":18090,
 "ip_proto":6,"pid":0,"tid":0,"tls_library":"None",
 "connection_id":1600164996631529749,
 "payload_len":164,"orig_len":164,"truncated":false,
 "tcp_seq":3735928559,"tcp_flags":24,"cgroup_id":0,
 "stream_off":18446744073709551615,"owner_tgid":0,"acceptor_tgid":0,
 "scope_gen":0,"role":0,
 "payload_b64":"R0VUIC9sZW4vNTAwMD9lbWFpbD1hbGljZSU0MGV4YW1wbGUuY29t..."}
```

`cgroup_id`, `stream_off` (stream offset of the first byte, 2^64 - 1 when not
computed), `owner_tgid`, `acceptor_tgid`, `scope_gen` and `role` (1 client,
2 server) are set on packet events; on other events they are 0 and
`stream_off` is 2^64 - 1.

- **Nothing is redacted** — passwords, tokens and personal data are written
  as they appeared on the wire (or as plaintext for TLS captured via
  OpenSSL/Go). In mode `full` the JSON event log is unredacted too, unless
  the config sets `[pii] redact = true` (§4.3).
- The file is created readable by its owner only (`0600`), truncated at
  startup, and writing stops at `capture_raw_max_bytes` (default 1 GiB). The
  agent logs a warning at startup whenever raw capture is on.
- If a reload tightens the mode away from `full`, recording stops at once
  and the file is closed: events still queued for it are not written, and
  the file keeps what was written before.
- Group packets of one connection by `connection_id`; `direction` and the
  addresses tell you which side sent each one. For TLS events, `pid`
  identifies the process and `connection_id` is the TLS library's connection
  object (unique per open connection within that process); addresses are
  filled in once the connection has done socket I/O inside a captured call,
  and are zero before that.
- **A record holds at most 4096 payload bytes.** A larger TCP packet (a
  GSO, TSO or GRO packet of up to 64 KiB) is split over consecutive records
  up to `max_packet_bytes` (`ceil(max_packet_bytes / 4096)` records: 4 at
  the default 16384, at most 16; 16 on a connection `raise_packet_cap`
  raised), each with its own `tcp_seq` and
  `stream_off`; a TLS read or write over at most 4 (16 KiB). A UDP
  datagram and a TCP packet carrying RST are one record, cut at 4096.
  `orig_len` is a record's bytes on the wire; in the last record of a
  packet or TLS call it also counts what was not captured, and `truncated`
  is then `true` (a packet past its cap, a TLS call over 16 KiB,
  a `head_only` cut).
- If the disk cannot keep up, events are dropped from the file and counted in
  `panopticon_raw_capture_dropped_total`; the rest of the agent is
  unaffected.

Treat raw capture files like a database dump of production data: restrict
access, encrypt at rest, and delete them when done.

### 5.6 Kubernetes identity

In a cluster, the agent lists and watches Pods and Services (cluster-wide,
read-only) and names endpoints after what owns the IP, in the service graph
and in the event log's `src_workload` / `dst_workload`:

| IP belongs to | Name | Example |
|---|---|---|
| A pod | `namespace/workload` | `payments/checkout` |
| A Service ClusterIP | `svc:namespace/service` | `svc:payments/checkout` |
| A node (host-network pods, node processes) | `node:name` | `node:worker-1` |
| Anything else | DNS name seen in traffic, else `ip:port` (servers) / `ip` (clients) | `10.0.0.9:5432` |

A DNS name is taken only from an answer to a query seen on the same flow
(same transaction ID and question name), only if it is a plain hostname
(not an address, nor anything shaped like the names above), for at most an
hour whatever its TTL, and, unless the mode is `full`, only if it holds no
PII. Any process can still look up a name of its choosing at a resolver it
controls, so a DNS name says what the client asked for, not who answered:
the audit log keeps the address next to it (`service_addr`).

The workload is the pod's controller: a ReplicaSet named
`<deployment>-<pod-template-hash>` counts as its Deployment; StatefulSets,
DaemonSets and Jobs as themselves; a Job named `<name>-<8+ digits>` as the
CronJob `<name>` (a naming heuristic); static pods as their name without the
`-<node>` suffix; a pod without a controller as the pod. Ports are not part
of Kubernetes names — a workload is one graph node however many ports it
serves.

Details worth knowing:

- Host-network pods share the node's IP, so their traffic shows as
  `node:<name>`, never as one of the pods.
- When a pod IP is reused, the new pod's name applies as soon as the API
  reports it (seconds with `watch = true`; up to `relist_interval_secs`
  without). Kubernetes names are not held by `identity_cache_ttl_secs`.
- Only IPv4 addresses are mapped (like capture itself).
- If the API is unreachable or access is denied, the agent logs one warning
  (with an RBAC hint for 401/403), keeps retrying in the background, and
  endpoints keep DNS/IP names; startup is never delayed. Names already
  learned are dropped after twice the re-list interval (at least 60 s)
  without an answer, since pod IPs get reused.
- Each agent lists every pod and service in the cluster (pages of 500) once
  per `relist_interval_secs`, and holds one watch per resource. Memory is on
  the order of 1 KB per pod (estimated, not measured); at most 200,000 pods
  and 100,000 services are indexed.
- Needs `get`/`list`/`watch` on `pods` and `services` and a mounted service
  account token; the Helm chart sets both up (`kubernetes.enabled`, see
  [`DEPLOYMENT.md`](DEPLOYMENT.md)).

Validated only against a fake API server in the unit tests (realistic
PodList/ServiceList/watch responses, pagination, 403, outages); not yet on a
real cluster.

## 6. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `received` stays 0 | The scope drops everything: check `panopticon_scope_dropped_events_total{reason}`. Only loopback traffic (`capture_loopback = false`, `reason="loopback"`), sockets opened before the agent started (`uninit`), or an unlisted process (`out_of_scope`, `no_owner`). The agent's own metrics/health traffic is captured like any other (no port is exempt, so no peer can hide behind one). |
| `unexpected argument '--interface'`, or `` `interfaces` is no longer supported `` | The TC backend was removed: drop the flag or key; capture covers every socket, select with `pid_filter`, `cgroup_filter` or `pod_filter`. |
| `refusing to start: capture needs cgroup_skb ...` or a refusal naming a program | The kernel lacks a hook the capture needs (§2). |
| Fails to start with `has no BPF ring buffer` | Kernel older than 5.8 without the RHEL-style backport. Not supported in this release. |
| `Failed to attach tracepoint ... tracefs not found` | Mount tracefs: `mount -t tracefs nodev /sys/kernel/tracing`. Capture still works; process events don't. |
| `Failed to attach kprobe` | A TLS address hook is unavailable on this kernel/VM; TLS events carry no addresses. Packet capture is not affected. |
| HTTPS traffic not decoded | TLS is decoded only for processes using a shared OpenSSL `libssl` (`SSL_read`/`SSL_write` and their `_ex` variants) or Go's `crypto/tls` (gc builds of Go 1.18+ for amd64 or arm64 with the register ABI, binaries with a symbol table; others are logged at debug level as `Go binary not probed`). Other statically linked TLS stacks (BoringSSL in Envoy/Chrome, rustls, Java) and Go binaries built with `-ldflags=-s` appear as unknown traffic. Uprobes are per library file, so they cover every process using that `libssl`. Libraries are found at startup, when a process execs, and every `tls_scan_interval_secs` (60 s), so one loaded later, e.g. from a new container image, can take up to a minute to appear; look for `TLS uprobes attached` in the log. |
| TLS records exported twice, or HTTPS requests left unpaired, for a containerised workload | On a kernel without BPF attach cookies (upstream before 5.15, such as 5.10 on Debian 11 or Amazon Linux 2, and RHEL 8's 4.18) the agent attaches an image's TLS library or Go binary once for every container that maps the same inode, where the kernel shows that inode in the process's maps (RHEL 8 does; measured there, no duplicate). Where it does not (maps that show an overlay's own inode, as the Ubuntu kernels do), or the file changed during the attach, each container adds a copy of every probe and some records are exported once per copy ([§5.3](#53-what-gets-redacted)). No value is exported that a single copy would not give. Kernels with attach cookies (5.15+, RHEL 9) export each record once. A file changed under the probes (an image file copied up by a chmod, touch or write) is attached again, which adds a copy of each probe; without attach cookies its records are then exported twice, on RHEL 8 only after a ctime change without a copy-up (a chmod of a host library already attached). |
| HTTP/2 or gRPC over TLS shows no path, status or headers | Expected: every TLS connection starts latched, so HTTP/2 and gRPC over TLS export timing, sizes and addresses only (Redis and AMQP over TLS lose their text too, and PostgreSQL and MySQL keep the statement keyword only; [§5.3](#53-what-gets-redacted)). HTTP/1.1 and Kafka over TLS are decoded, with TLS rules (an HTTP/1.1 path with a credential word withheld) and an integrity limit (§5.3). DNS is never parsed over TLS. |
| Each exchange appears twice | Both ends of the connection run on this node: each end's socket is captured (two views). The two records are alike in the JSON export: without NAT between the ends they carry the same addresses, ports and direction, and differ only in timestamp and latency (by microseconds). Select one side with `pid_filter` or `cgroup_filter`. |
| Event log empty after restart | `--json-export` truncates the file at startup; copy it before restarting. |
| `Kubernetes API unavailable` warning, no `src_workload` | `hint` in the log line names the cause: 403 = the ClusterRole lacks `get/list/watch` on pods/services (`rbac.create=true`), 401 = token not mounted or rejected. Endpoints keep IP names meanwhile (§5.6). |

## 7. Limits worth knowing

IPv4 only; the capture-scope trade-offs (§4.2); at most `max_packet_bytes`
(default 16 KiB; 64 KiB on connections `raise_packet_cap` raises, every
protocol but HTTP/1.1) of one packet and 16 KiB of one TLS read or write are
captured (§5.5), and capturing large packets whole costs kernel time and
ring space under bulk transfers (`max_packet_bytes`, §4.2); Kubernetes names not yet validated on a real cluster (§5.6); HTTPS only via
OpenSSL/Go; PII detection is regex-based by default; TCP checksums are not
verified, so a forger who knows a connection's sequence numbers (on path)
can still slip a segment in; DNS-derived names say what a client asked for
(§5.6); see
[`CURRENT-STATE.md`](CURRENT-STATE.md) for the full list.
