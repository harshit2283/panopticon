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

With no `--interface`, the agent attaches to the interface(s) carrying the
host's default route (e.g. `eth0`, `ens5`, `bond0`). Use `-i` (repeatable) to
choose others, e.g. `-i lo` to watch local traffic.

Stop it with Ctrl-C or `SIGTERM`; exports are flushed on shutdown.

## 4. Configuration

Settings come from, in increasing priority: built-in defaults, a TOML file
(`--config <file>` or `PANOPTICON_CONFIG`), and command-line flags.

### 4.1 Command-line flags

| Flag | Meaning |
|---|---|
| `-i, --interface <IF>` | Interface to capture on; repeatable. Default: config `interfaces`, else default-route interface(s). |
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
interfaces = []                     # [] = auto-detect default-route interface(s)
# pid_filter = [1234, 5678]         # default: unset (every process); see "Capture scope" below
# capture_loopback = false          # cgroup_skb backend only; see "Capture scope" below
# pid_filter_listener = "acceptor"  # cgroup_skb backend only: "acceptor" | "creator"
sampling_mode = "full"              # "full" | "connection_sample" | "head_only"
# sample_rate = 0.1                 # connection_sample only, and required there
# head_only_bytes = 4096            # head_only only (default 4096)
max_events_per_sec = 500000         # user-space rate limit; excess is dropped and counted
max_worker_count = 4                # default: number of CPUs
worker_channel_capacity = 4096        # events queued per worker; excess is dropped and counted
max_connections_tracked = 65536
idle_connection_timeout_secs = 30
max_body_bytes = 4096               # body text kept per exchange for PII scan + export (max 65536)
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
```

**Capture scope.** `pid_filter` and `sampling_mode` narrow what is captured
at all. They apply before anything else: what they drop never reaches the
parsers, PII scanning, the service graph, the event export, OTLP, the PII
audit log, the raw dump (and so `--decode-capture` / `--pcap`),
`--log-events` or the agent's logs. They work the same in every privacy
mode (§4.3) and only ever reduce what the mode allows. They are
restart-only: a `SIGHUP` reload that changes them is rejected and the
running config is kept.

- `pid_filter = [1234, ...]`: capture only these processes (PIDs as the
  node sees them, i.e. in the host PID namespace; at most 4096, not empty,
  no 0). TLS plaintext and the connect / accept events of other processes
  are dropped in the kernel. Packets captured on an interface carry no
  process: a connection's packets pass only once a listed process has been
  seen to `connect()` or `accept()` it. So:
  - Connections that were already open when the agent started, and
    connections of processes not in the list, are dropped and counted in
    `panopticon_pid_filter_unknown_owner_connections_total`.
  - A server's `accept()` can return after the client's first bytes have
    arrived. Those packets are held (at most 8 per connection and 256 per
    worker, for about a second) until the accept is seen, and dropped if it
    is not.
  - Processes started after the agent, including children a listed process
    forks later (pre-fork workers, helpers), have new PIDs and are **not**
    captured. The filter does not follow process trees: list them and
    restart the agent.
  - With the `cgroup_skb` backend the decision is made in the kernel, per
    connection, and differs as follows. A connection a process accepted is
    selected by `pid_filter_listener`:
    - `"acceptor"` (the default): only if a listed process `accept()`ed it.
      A listening socket of a listed process selects nothing that an
      unlisted process accepts (a worker it forks later, a process it passes
      the socket to). The connection is captured from the moment the
      `accept()` returns; bytes that arrive before that are dropped (no
      packets are held) and counted in
      `panopticon_scope_dropped_events_total{reason="out_of_scope"}` (or
      `"no_owner"`). Measured (docs/BENCHMARKS.md, pre-agent listener,
      which behaves the same): 56.6% of requests captured with a new
      connection per request, about 100% with keep-alive connections,
      which lose only those first bytes.
      The rule governs packet capture only: TLS plaintext (uprobes) is
      captured when the calling process is listed, whichever process
      accepted the socket.
    - `"creator"`: also if a listed process created the listening socket
      while the agent ran. Then it selects every connection accepted on it,
      from the first byte, whoever accepts it: a worker the listed process
      forks later, a process that received the socket (`SCM_RIGHTS`,
      `pidfd_getfd`) or has since exec'd another program, and after the
      listed process has exited. List only processes whose listening
      sockets you want captured.
    - On a listening socket that existed before the agent started (any
      server not restarted since the agent was), both rules capture a
      connection only from the moment a listed process `accept()`s it, with
      the same drop before that (`no_owner`).
    For full recall with connection-per-request servers, select by
    `cgroup_filter` / `pod_filter`, which has no such gap, or set
    `pid_filter_listener = "creator"` and restart the server after the
    agent. Connections a listed process opens
    (clients) are selected by their creator under both rules.
- `sampling_mode = "connection_sample"` with `sample_rate = r` (required,
  0.0 to 1.0): each connection is captured whole or not at all, decided once
  from a keyed hash of the connection (the key is drawn at agent start, so
  which connections are kept cannot be predicted or steered from outside).
  `0.0` captures nothing; `1.0` is the same as `full`. Dropped connections
  and their events are counted in `panopticon_sampled_out_connections_total`
  and `panopticon_sampled_out_events_total`. A TLS connection seen through
  the uprobes and the same connection's packets on the wire have different
  keys and are sampled independently. Sampled-out traffic is still copied
  out of the kernel and counts against `max_events_per_sec`; the saving is
  in parsing and export.
- `sampling_mode = "head_only"` with `head_only_bytes = N` (default 4096,
  1 to 1073741824): only the first N bytes of each direction of each
  connection pass; the rest is dropped and counted in
  `panopticon_head_only_cut_events_total`. An exchange that straddles the
  limit is exported with the part before it. For TCP the count starts at
  the connection's SYN, so connections already open when the agent started
  pass nothing. For TLS (uprobes) and UDP it starts at the first byte the
  agent sees. A count never starts over: the agent sees no close for TLS
  and UDP connections, so it remembers them (idle or not) until it
  restarts. Each worker remembers at most `max_connections_tracked`
  connections; once full, new connections pass nothing (counted as cut)
  until TCP connections close or go idle and free room. A TLS connection
  that reuses the library object of an earlier one in the same process
  continues that one's count.

- `capture_loopback = false` (the default, `cgroup_skb` backend only):
  packets that stay on the node through the loopback device are not
  captured, as on the TC backend, which never sees them (this is parity
  for the loopback device only: other same-node traffic, below, is
  captured, which TC on the node's NIC did not see either). That is
  `127.0.0.0/8`, and connections to one of the host's own addresses (or,
  in a pod, the pod's own address), which the kernel also sends over
  `lo`; IPv6 packets are not captured on either backend. Packets on a
  VRF device are node-local too and dropped: local delivery inside a VRF
  travels the VRF device, and so does a VRF's incoming remote traffic.
  A socket is dropped from its first packet seen on a VRF device on; a
  one-way sender whose packets all leave through a VRF's member
  interface to a remote peer is captured. The agent recognises VRF
  devices when they are created and deleted, and scans every reachable
  network namespace for existing ones at startup, with fexit/fentry
  hooks that need kernel BTF; without them, or if the scan cannot
  complete, the `cgroup_skb` backend refuses to start. If a VRF device
  ever cannot be recorded (see
  `panopticon_vrf_hook_events_total{event="read_failed"|"map_full"}`),
  every packet is dropped while this is off, counted under
  `reason="vrf_unknown"`; restart the agent. Traffic on a device in
  another network namespace that has the same interface index as a VRF
  device is dropped too, and a socket that once carried node-local
  traffic stays dropped (an unconnected UDP socket that talked to a
  local and a remote peer). Set `capture_loopback = true` if you need
  those. Same-node pod-to-pod and host-to-pod traffic over veth, a
  bridge, ipvlan, macvlan or tun/tap is not loopback and is captured. Dropped
  packets are counted in
  `panopticon_scope_dropped_events_total{reason="loopback"}`. It covers
  packets only: TLS plaintext (uprobes) of a loopback connection is
  captured per `pid_filter` / cgroup selection like any other, as on TC
  (in a scoped mode without its addresses, while loopback packets are
  dropped). Set it to `true` to capture app-to-local-database and
  sidecar packets.

An unknown `sampling_mode`, `sample_rate` without `connection_sample`, and
`head_only_bytes` without `head_only` stop the agent with an error, and so
do `capture_loopback` or `pid_filter_listener` with the TC backend.

`SIGHUP` re-reads the file but applies only a stricter privacy mode (§4.3)
and, with the `cgroup_skb` backend, changes to cgroup selection: a reload may
change `cgroup_filter` / `pod_filter`, switch from one to the other, or
combine them, but turning cgroup selection on or off altogether (going from
neither to either, or back) needs a restart. It may also change
`capture_loopback` and `pid_filter_listener`. A reload that narrows the
selection (a cgroup or pod removed, `capture_loopback` turned off,
`pid_filter_listener` from `"creator"` to `"acceptor"`) is reported applied
only once nothing captured under the old scope can still leave the agent. Restart the agent for anything else. Unknown keys are ignored silently
(except inside `[privacy]`, where they are an error), so check spelling.

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
| `payload_text` | Response body as text, at most `max_body_bytes` (default 4 KB), after redaction |
| `request_body` | HTTP request body (POST/PUT/PATCH, forms) as text, at most `max_body_bytes`, after redaction |
| `response_size_bytes` | Full body size, even when the body was larger than what was kept |
| `headers` | Header names and values as sent on the wire (HTTP, HTTP/2 and gRPC metadata including `:path`; DNS `qtype`) |
| `dns_answers` | DNS responses: the A records (`name`, `ip` as a 32-bit integer, `ttl_secs`) that answer a query seen on the same flow. They name services in the graph |
| `src_*`, `dst_*` | Addresses of the packet that completed the exchange (usually the response). Addresses are IPv4 as a 32-bit integer (`2130706433` = `127.0.0.1`). |
| `pid` | TLS exchanges: the process whose TLS calls were captured |
| `client_pid`, `server_pid` | Packet-captured TCP exchanges: the local process that opened / accepted the connection, when it runs on this node. `server_pid` needs kprobes; on kernels built without them only `client_pid` is filled |
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
  `X-Goog-Api-Key`, `X-Hub-Signature-256`, ...). `:authority` and
  `Sec-WebSocket-Key` stay readable. A header of any protocol whose name is
  a credential name (below) is replaced the same way;
- the **method** (including a gRPC method path), the **content type**, the
  **request body** (e.g. POST JSON or form data) and the **response body**
  are scanned and redacted;
- **credentials**: any field with *credential context*, where a
  credential value could be present, is withheld whole, whatever the
  protocol, unless every credential in it can be masked with certainty
  (below). A credential word that is a bare name, with nothing next to it
  that could be its value, is not context.

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
(`\u0070`), HTML character references (`&#112;`, `&#x70;`, `&amp;` …)
and percent-encoding (`%70`, `+` as a space), so an encoding revealed by
another is decoded too (`%5Cu0077` is `w`); case folded; SQL comment
markers (`/*`, `/*!`, `*/`, `--`, `#`) ignored so a comment's text counts;
`-` and `.` read as `_`. The words and forms:

- a word containing `password`, `passwd`, `passphrase`, `secret`, `token`,
  `apikey`, `api_key`, `access_key`, `private_key`, `credential`,
  `signature`, `authorization`, `requirepass`, `masterauth`, `csrf`,
  `xsrf`, `bearer` or `client_assertion`, or ending in `_pass` or `_auth`
  (names of any length), or `IDENTIFIED` followed by `BY`, `WITH`, `VIA`,
  `AS` or `USING`;
- one of the names `auth`, `pwd`, `pass`, `key`, `sig`, `session`,
  `sessionid`, `session_id`, `sid`, `cookie`, `jwt`, `masteruser`, `otp`
  or `pin` used as a name: followed by `=` or `:`, a form or HTML field
  name (`name="pwd"`, as in multipart form data), or an XML element
  (`<pwd>`); in SQL also a column in a list or assignment (`users(pwd)`,
  `SET a = 1, pass = $1`). So `/api/auth/login`, a Redis `AUTH` command
  name or "press any key" are not context;
- userinfo, `user:password@host`, with or without a scheme (the `:` of
  `scheme://` and `mailto:` do not count), and any `//` authority whose
  userinfo holds a `:` (RFC 3986: `,` and `;` may be part of the
  password).

A word from the first list is not context when it is a *bare name*: in
one of the three positions below, where nothing next to it, on either
side, can be its value. These are recognised on the same normalised view,
so an encoding or a comment that puts a value next to the word makes it
context again. Anything that does not fit one of them exactly is context
(when in doubt, the field is withheld):

- **the whole field** is the word, as in the argument of
  `CONFIG GET requirepass` or `HGET user:1 password`;
- **the last segment of a path**: the field starts with `/` and is
  printable ASCII up to any `?`; the word follows a `/` and is followed by
  the end, by `/` and the end, or by `?` and then the end or a parameter
  name and `=`. So `/oauth/token`, `/users/me/password/` and
  `/oauth/token?scope=read` are bare, while `/reset/token/abc123`,
  `/token?abc123`, `/oauth/token#x` (`#` is read as a comment marker) and
  `https://host/oauth/token` are context;
- **a column of a plain `SELECT` list**: the statement starts with
  `SELECT` (no leading comment); up to its first `FROM` it holds only
  column names (plain, `"quoted"` or `` `quoted` ``, qualified by `.`, or
  `*`) separated by commas; and no `SELECT`, `UNION`, `INTERSECT`,
  `EXCEPT` or `VALUES` follows that `FROM`, so no other query's values
  line up with the columns. `SELECT password, email FROM users` and
  `SELECT pwd, email FROM users` are bare; the same word after `FROM`,
  after `AS` or a literal, inside parentheses (`INSERT INTO users(password)
  VALUES …`, `md5(password)`), or after `DISTINCT` is context, and so is
  `WHERE password = 'x'`.

In the first two positions the word must also end in a whole credential
part (`token`, `access_token`, `x-api-key`, `passwords`), not have more
after it or before it in the same word (`token_abc`, `hunterpassword`). In
all three it must have no digit (`token9f8e` may be a value), and none
applies when decoding dropped a NUL byte (it may have joined a name to its
value; UTF-16 text is therefore never a bare name). Prose is never a bare
position: `token abc123`, `your token expired` and `hunter2 is my
password` are context.

What is exported then:

- **SQL** (MySQL, PostgreSQL): the statement becomes its keyword and
  `<statement withheld>` (`ALTER <statement withheld>`), its bound
  parameter values are not exported, and a server error for it (which may
  quote it) becomes `<statement withheld>`; so does any error message that
  shows credential context itself. Only a known SQL statement keyword
  (`SELECT`, `INSERT`, `ALTER`, …) is ever exported as the method: a
  statement starting with anything else exports the method `QUERY`, and
  just `<statement withheld>` when withheld.
- **Any other field** (path, header value, method, content type, bodies,
  Redis arguments and replies, Kafka and AMQP fields): `<field withheld>`,
  unless every credential in it is one of these, in which case only the
  value becomes `<REDACTED>` and the rest stays readable: a query or form
  parameter (`name=value` at the start or after `?` or `&`, the value
  running to `&` or the end without a space), a JSON member whose value is
  a string, number, `true`, `false` or `null`, or the password of a `//`
  authority (`scheme://user:<REDACTED>@host`). So `/login?password=x&q=1`
  exports `/login?password=<REDACTED>&q=1`, while a JSON array or object
  under a credential name, a password in prose or `Authorization: Bearer …`
  inside a body withholds the field.
- **A header whose name is over 8 KiB** is replaced, name and value, by
  `<field withheld>`: a name is classified whole, never cut first.
- **A body with bytes captured after a gap** (bytes lost to ring drops
  or the capture cap, then more of the same body kept), or an HTTP/2 body
  whose stream's headers the agent did not see, is not exported (its size
  is): what is left may hold a credential's value without its name. A gap
  that only cuts a body's end, as the capture cap does to a large
  response, keeps the captured prefix (it is scanned and trimmed like any
  body).
- **HTTP/2 bodies** are not exported while credential masking is on when
  their content type is unknown, since they may be protobuf: on a
  direction of a connection that lost a header block (a block that failed
  to decode, was skipped or was over the size limit, a final response
  block after an informational `1xx` one included), for the rest of that
  connection; on both directions of a connection the agent did not see
  whole: joined mid-stream, a side whose start was not captured (a lost
  SYN+ACK), or bytes lost outside a DATA frame, which restarts the
  parser; and for a stream whose header block carries more than one
  content type or one over 256 bytes (only the first 256 bytes of one
  content type are ever examined). This lasts for the connection: a
  client preface seen later on it does not lift it (it may be the payload
  of a DATA frame). Only a new connection observed from its start
  exports bodies again. Over TLS a new connection can reuse a closed
  one's key (the library's connection object address). It starts clean
  only once the agent has seen the library create the new object at that
  address (the return of OpenSSL's `SSL_new`, in every mode), which
  proves the old one was destroyed; nothing else resets the key (no
  client preface, wherever it falls, nor `SSL_free`, which may drop one
  reference of several). Otherwise a new connection on the key gets
  neither its headers decoded nor its bodies exported, for as long as
  the agent tracks that key: Go TLS (no such hook), a libssl whose
  `SSL_new` the agent cannot find (static or renamed), an object reused
  through `SSL_clear`, an object created before the agent attached, an
  object read or written inside `SSL_new` (a creation callback, so before
  the agent saw it created), and a record that was lost (ring or channel
  full, rate limit).
- **HTTP/2 headers**: after a header block of one direction fails to
  decode or is skipped, that direction's header table may differ from the
  peer's, so no header of it is exported again on that connection; on a
  connection the agent did not see whole (as above), no header is decoded
  at all. Both last for the connection, and a reused TLS key starts
  clean only after the agent saw `SSL_new` return it, as above.
- **DNS answers** whose name has credential context, a credential word
  even as a bare name included (`db.password.internal`), or matches one
  of your `[credentials]` patterns, are dropped before export and before
  the name can reach the service graph.
- **Bare names** are exported as written: `/oauth/token`,
  `SELECT password, email FROM users` (with its bound values),
  `CONFIG GET requirepass`, a Kafka topic or header value that is just a
  credential name. A credential parameter after a bare path is still
  masked: `/oauth/token?client_secret=x` exports
  `/oauth/token?client_secret=<REDACTED>`.

The price is more withheld text than a value-level mask would leave:
a `SELECT` that compares a `password` column or names it outside its
select list, an `INSERT` or `UPDATE` naming one, a body that mentions a
token or a secret in prose, a path with a segment after a credential
word (`/reset/token/abc123`), or a Redis reply naming `requirepass`
(the `CONFIG GET requirepass` reply) is withheld whole. The other side
of the bare-name rule: a value spelled like a credential name, alone in
a bare position (a Redis value `my-secret-password`), is exported, like
any value under a name that is not in the lists.

Redis commands and replies are masked before this rule runs. The
command's secret is masked in `AUTH`, `HELLO … AUTH`, `MIGRATE … AUTH`/`AUTH2`,
`CONFIG SET` and `SENTINEL SET` of a credential-named parameter, and
`ACL SETUSER` password rules. The reply is masked for `CONFIG GET` of those
parameters, the whole of `ACL LIST|GETUSER|GENPASS` and the same results
inside `EXEC`; in any reply the value after a credential-named element and
`ACL LIST` lines with a password rule are masked too. The rule above then
applies to the masked text: `AUTH <REDACTED>` and `HELLO 3 AUTH default
<REDACTED>` stay readable (`auth` is not used as a name there), and so
does a command whose argument is just such a name, a bare name
(`CONFIG GET requirepass`, `CONFIG GET masterauth`), while an argument
or reply with a value next to a word from the first list, masked or not
(`CONFIG SET requirepass <REDACTED>`, the `CONFIG GET requirepass` reply
`requirepass, <REDACTED>`), is withheld whole. Protocol and subscription
state follow the server's replies only, and a subscription
acknowledgement counts only as the reply to the pending subscription
command (a script returning an array of the
same shape changes nothing). A reply that cannot be matched to its command
is exported without its text. No reply text is exported for the rest of
the connection after any of: `MONITOR`; `UNSUBSCRIBE` with no channel;
`CLIENT REPLY OFF|SKIP` (never acknowledged, so a refusal cannot be seen);
any `CLIENT REPLY` other than `CLIENT REPLY ON`; `MULTI`, `EXEC`,
`DISCARD` or `RESET` sent with arguments; `CLIENT`, `HELLO`, `MONITOR` or
a subscription command queued inside `MULTI`; a transaction past 1024
commands or 64 KiB; an array in place of a subscription command's
acknowledgement. An `EXEC` whose `MULTI` came before capture started has
its whole result masked.

Replies are paired with commands by order, which is only safe when the
agent saw both directions of the connection from their first byte. With
the TC backend that is proved by the connection's SYN and SYN+ACK, with
`cgroup_skb` by the kernel's stream offset; any bytes lost later (ring
drops, capture cap) end the proof. Without it Redis replies are exported
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
values. Past 4096 retained `Bind` snapshots (Binds read but not yet
consumed by their cycle), no bound value is exported on the connection. A `Parse` the server rejects
does not replace a statement, and a re-`Parse` or `Close` forgets it
until confirmed. A simple Query forgets every confirmed statement and
cancels unanswered `Parse` messages: its SQL may `PREPARE` or
`DEALLOCATE` any name, and it ends the unnamed statement. Several `Parse` messages may be sent before one `Sync`
(pipelining); each `ParseComplete` confirms the oldest `Parse` still
unanswered. After an error the server skips to the `Sync`, so the
`Parse` messages before it are never confirmed; a `Close` of a name also
cancels an unanswered `Parse` of it. If the agent ever cannot match the
server's answers to the client's messages on a connection (it joined the
connection mid-stream, server bytes were lost, an answer matches
nothing), no `Parse` is confirmed for the rest of that connection and no
bound value is exported on it, not even for a statement confirmed before,
until a new connection is observed from its start.

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
arguments and replies, Kafka and AMQP fields; a DNS answer whose name a
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
and JSON members, URI userinfo) and SQL statement withholding. It skips
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
| `panopticon_drops_rate_limit_total` | Over `max_events_per_sec` |
| `panopticon_kernel_ringbuf_drops_total` | Lost in the kernel: the agent did not drain the ring buffer fast enough. Give it more CPU |
| `panopticon_drops_channel_full_total` | Parser workers falling behind (bursts or too little CPU) |
| `panopticon_worker_panics_total` | Parser or PII steps that panicked on captured data. The step is skipped (a parser panic closes that connection) and the worker keeps running. Any increase is a bug: please report it |
| `panopticon_drops_export_full_total` | Parsed exchanges the JSON writer could not keep up with (slow disk) |
| `panopticon_drops_parser_error_total` | Streams a parser gave up on |
| `panopticon_tcp_segments_ignored_total` | TCP segments not parsed: retransmissions of bytes already parsed (normal on lossy links), or segments and RSTs outside the connection's sequence window (forged, or stale). Only the next expected bytes of each direction reach the parsers, once |
| `panopticon_capture_truncated_total` | Packets larger than the 4 KB capture window (normal with large transfers; parsers account for the skipped bytes) |
| `panopticon_pid_filter_dropped_events_total` | `pid_filter`: events dropped in user space. TLS and connect / accept events of other processes are dropped in the kernel and not counted |
| `panopticon_pid_filter_unknown_owner_connections_total` | `pid_filter`: packet-captured connections dropped because no listed process was seen to own them (other processes' connections, or opened before the agent started) |
| `panopticon_sampled_out_connections_total` | `connection_sample`: connections not captured |
| `panopticon_sampled_out_events_total` | `connection_sample`: events of those connections |
| `panopticon_head_only_cut_events_total` | `head_only`: events cut or dropped past a direction's first `head_only_bytes` |
| `panopticon_pii_detections_total` | PII values found |
| `panopticon_credential_matches_total` | Credentials protected, by `source`: `user` = matches of your `[credentials] patterns`, `builtin` = fields the built-in rules masked or withheld. Never values |
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
- Bytes that were not captured (beyond 4096 per packet or TLS buffer) show as
  gaps ("previous segment not captured"), not as corrupted streams.
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
2 server) are set by the `cgroup_skb` backend; on TC they are 0 and
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
- **At most 4096 bytes per packet or TLS buffer are captured.** When
  `truncated` is `true`, the original was `orig_len` bytes and the rest was
  not captured (large GSO/TSO packets, big TLS writes).
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
| `received` stays 0 | Wrong interface: check the "Auto-detected default-route interface(s)" or "TC classifier attached" log lines; pass `-i`. The agent's own metrics/health traffic is captured like any other (no port is exempt, so no peer can hide behind one). |
| `No --interface given and no IPv4 default route` | Host has no IPv4 default route; pass `-i`. |
| Fails to start with `has no BPF ring buffer` | Kernel older than 5.8 without the RHEL-style backport. Not supported in this release. |
| `Failed to attach tracepoint ... tracefs not found` | Mount tracefs: `mount -t tracefs nodev /sys/kernel/tracing`. Capture still works; process events don't. |
| `Failed to attach kprobe` | Socket lifecycle events unavailable on this kernel/VM; HTTP/DB capture via TC still works. |
| HTTPS traffic not decoded | TLS is decoded only for processes using a shared OpenSSL `libssl` (`SSL_read`/`SSL_write` and their `_ex` variants) or Go's `crypto/tls` (gc builds of Go 1.18+ for amd64 or arm64 with the register ABI, binaries with a symbol table; others are logged at debug level as `Go binary not probed`). Other statically linked TLS stacks (BoringSSL in Envoy/Chrome, rustls, Java) and Go binaries built with `-ldflags=-s` appear as unknown traffic. Uprobes are per library file, so they cover every process using that `libssl`. Libraries are found at startup, when a process execs, and every `tls_scan_interval_secs` (60 s), so one loaded later, e.g. from a new container image, can take up to a minute to appear; look for `TLS uprobes attached` in the log. |
| Each exchange appears twice on `-i lo` | Loopback shows every packet on both directions; capture a real interface instead. |
| Event log empty after restart | `--json-export` truncates the file at startup; copy it before restarting. |
| `Kubernetes API unavailable` warning, no `src_workload` | `hint` in the log line names the cause: 403 = the ClusterRole lacks `get/list/watch` on pods/services (`rbac.create=true`), 401 = token not mounted or rejected. Endpoints keep IP names meanwhile (§5.6). |

## 7. Limits worth knowing

IPv4 only; Kubernetes names not yet validated on a real cluster (§5.6); HTTPS only via
OpenSSL/Go; PII detection is regex-based by default; TCP checksums are not
verified, so a forger who knows a connection's sequence numbers (on path)
can still slip a segment in; DNS-derived names say what a client asked for
(§5.6); see
[`CURRENT-STATE.md`](CURRENT-STATE.md) for the full list.
