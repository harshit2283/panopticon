# Panopticon User Guide

Panopticon is an eBPF agent that watches the network traffic on a Linux host,
reconstructs application requests (HTTP, databases, caches, queues), finds
personal data in them, and reports what it saw — with that personal data
redacted. It never modifies or blocks traffic.

> **Status: experimental.** Read [`CURRENT-STATE.md`](CURRENT-STATE.md) for
> what is validated and what is not before relying on it.

- Deploying it on servers or Kubernetes: [`DEPLOYMENT.md`](DEPLOYMENT.md)
- Measured accuracy and overhead: [`BENCHMARKS.md`](BENCHMARKS.md)

---

## 1. What you get

For every completed request/response exchange it can parse, Panopticon
produces one **event**: protocol, method, path or query, status, latency,
sizes, headers and (for text payloads) the body — after PII redaction.

| Output | How to enable | Contains |
|---|---|---|
| JSONL event log | `--json-export <file>` | One JSON object per exchange (see §5.1) |
| PII audit log | `--pii-audit-log <file>` | One line per PII finding: category, action — never the value (§5.2) |
| Prometheus metrics | `--metrics-bind <addr:port>` | Capture, drop and PII counters (§5.3) |
| Health endpoints | `--metrics-bind <addr:port>` | `/healthz`, `/readyz`, `/debug/state` |
| OTLP spans | config file `[otlp]` | One span per exchange to an OTLP/gRPC collector |
| Console | `--log-events` | Every packet and exchange (development only, very verbose) |
| Raw capture | `--capture-raw <file>` | Every captured payload, **unredacted**, for your own analysis (§5.5) |

Protocols: HTTP/1.1, HTTP/2, gRPC, PostgreSQL, MySQL, Redis, Kafka, AMQP and
DNS are validated against ground truth (see [`BENCHMARKS.md`](BENCHMARKS.md)).
Depth varies — see the support matrix in the [README](../README.md).

## 2. Requirements

- Linux **kernel 5.8 or newer** (x86_64; arm64 is untested).
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
| `--log-events` | Log every packet and exchange to stdout. Contains (redacted) traffic. |
| `--smoke-test` | Exit 0 on the first captured event, 1 after 30s. |
| `--kubernetes <auto\|true\|false>` | Kubernetes identity (§5.6); overrides `[kubernetes] enabled`. Also `PANOPTICON_KUBERNETES`. |
| `--capture-raw <FILE>` | Write every captured payload, unredacted, to a binary capture file (§5.5). |
| `--decode-capture <FILE>` | Print a raw capture file as JSON lines and exit. Needs no root. |
| `-v, --verbose` | Debug logging (otherwise `RUST_LOG`, default `info`). |

### 4.2 Config file reference

All keys are optional. Example with the defaults:

```toml
capture_enabled = true
interfaces = []                     # [] = auto-detect default-route interface(s)
max_events_per_sec = 500000         # user-space rate limit; excess is dropped and counted
max_worker_count = 4                # default: number of CPUs
worker_channel_capacity = 1024
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
# capture_raw_path = "/var/lib/panopticon/raw.pncap"      # default: unset (off) — UNREDACTED
capture_raw_max_bytes = 1073741824  # raw capture stops at this size (1 GiB)

[pii]
enabled = true
regex_enabled = true
redact = true          # replace detected values before anything is logged/exported
min_confidence = 0.7   # for ML findings (ML is not in the default build)

[graph]
enabled = true
aggregation_window_secs = 10
stale_edge_timeout_secs = 300
identity_cache_ttl_secs = 300

[otlp]
enabled = false
endpoint = "http://127.0.0.1:4317"
service_name = "panopticon-agent"

[kubernetes]           # pod/service names for endpoints (§5.6)
enabled = "auto"       # "auto" = on when running in a pod with a service account token; true; false
relist_interval_secs = 300  # full re-list of pods and services (min 5)
watch = true           # stream changes between re-lists; false = refresh only by re-listing
```

Accepted but **not yet acted on** (so you are not surprised):
`pid_filter`, `sampling_mode`, `sample_rate`; `SIGHUP` re-reads the file but
does not apply changes — restart the agent instead. Unknown keys are ignored
silently, so check spelling.

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
| `method`, `path` | HTTP method and path+query; SQL command and table; Redis command and key |
| `status` | HTTP status, or database error code |
| `payload_text` | Response body as text, at most `max_body_bytes` (default 4 KB), after redaction |
| `request_body` | HTTP request body (POST/PUT/PATCH, forms) as text, at most `max_body_bytes`, after redaction |
| `response_size_bytes` | Full body size, even when the body was larger than what was kept |
| `src_*`, `dst_*` | Addresses of the packet that completed the exchange (usually the response). Addresses are IPv4 as a 32-bit integer (`2130706433` = `127.0.0.1`). |
| `pid` | TLS exchanges: the process whose TLS calls were captured |
| `client_pid`, `server_pid` | Packet-captured TCP exchanges: the local process that opened / accepted the connection, when it runs on this node. `server_pid` needs kprobes; on kernels built without them only `client_pid` is filled |
| `src_workload`, `dst_workload` | Kubernetes identity of `src_addr` / `dst_addr` (§5.6), e.g. `payments/checkout`. Present only with Kubernetes identity on and the address known to the API. |
| `pii.entities` | What was found; offsets are relative to the field it was found in |
| `pii.redacted` | `true` if values were replaced before export |

### 5.2 PII audit log (`--pii-audit-log`)

One line per finding, with no values:

```json
{"timestamp_ns":1805288389778,"category":"Email","source":"Regex","confidence":1.0,"action":"Redacted","service_identity":"payments/checkout"}
```

`service_identity` is the server end of the exchange, named like the service
graph names it: Kubernetes workload when known, else DNS name, else `ip:port`
(`unknown` only for TLS exchanges whose socket addresses were not learned).

`action` is `Redacted` when `pii.redact = true`, else `Detected`.
Categories: `Email`, `PhoneUs`, `PhoneIntl`, `Ssn`, `CreditCard` (Luhn
checked), `IpV4`, `Jwt`, `ApiKey`, `AwsKey`, `Aadhaar`, `Pan`, plus ML-only
categories when built with ML.

### 5.3 What gets redacted

With `pii.redact = true` (the default), before anything is logged or exported:

- the **path and query string** are scanned (also in percent-decoded form) and
  matches replaced by `<CATEGORY>`, e.g. `<EMAIL>`;
- **HTTP header values** are scanned the same way, and credential headers
  (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`,
  `X-Api-Key`, `X-Auth-Token`, `X-Amz-Security-Token`) are replaced entirely
  by `<REDACTED>`;
- the **request body** (e.g. POST JSON or form data) and the **response
  body** are scanned and redacted.

Detection is pattern-based. It will miss PII that does not match a pattern
(names, free-text addresses) and has known false positives (any IPv4 address,
10-digit numbers as US phone numbers). Treat the exports as sensitive anyway.

### 5.4 Metrics and endpoints (`--metrics-bind`)

| Endpoint | Purpose |
|---|---|
| `/healthz` | 200 while the process is up (liveness) |
| `/readyz` | 200 once eBPF programs are attached; 503 during shutdown |
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
| `panopticon_drops_export_full_total` | Parsed exchanges the JSON writer could not keep up with (slow disk) |
| `panopticon_drops_parser_error_total` | Streams a parser gave up on |
| `panopticon_capture_truncated_total` | Packets larger than the 4 KB capture window (normal with large transfers; parsers account for the skipped bytes) |
| `panopticon_pii_detections_total` | PII values found |
| `panopticon_active_connections` | Connections being parsed |
| `panopticon_raw_capture_dropped_total` | Events missing from the raw capture file (writer fell behind) |

The endpoints have no authentication: bind to loopback or a private address.

### 5.5 Raw capture: the full, unredacted payloads

Pattern-based PII detection misses things (names, free-text addresses,
domain-specific identifiers) and flags others it should not. If you need to
run your own classifiers, keep an evidence trail, or check what Panopticon
reported, capture the raw bytes:

```bash
sudo panopticon-agent --capture-raw /var/lib/panopticon/raw.pncap
# later, anywhere, without root:
panopticon-agent --decode-capture /var/lib/panopticon/raw.pncap > raw.jsonl
```

Each decoded line is one captured packet or TLS buffer:

```json
{"timestamp_ns":1479319283059,"event_type":"TcPacket","direction":"Ingress",
 "src":"10.99.0.2","src_port":48540,"dst":"10.99.0.1","dst_port":18090,
 "ip_proto":6,"pid":0,"tid":0,"tls_library":"None",
 "connection_id":1600164996631529749,
 "payload_len":164,"orig_len":164,"truncated":false,
 "payload_b64":"R0VUIC9sZW4vNTAwMD9lbWFpbD1hbGljZSU0MGV4YW1wbGUuY29t..."}
```

- **Nothing is redacted** — passwords, tokens and personal data are written
  as they appeared on the wire (or as plaintext for TLS captured via
  OpenSSL/Go). The JSON event log stays redacted at the same time.
- The file is created readable by its owner only (`0600`), truncated at
  startup, and writing stops at `capture_raw_max_bytes` (default 1 GiB). The
  agent logs a warning at startup whenever raw capture is on.
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
| `received` stays 0 | Wrong interface: check the "Auto-detected default-route interface(s)" or "TC classifier attached" log lines; pass `-i`. Traffic to the agent's own metrics port is deliberately ignored. |
| `No --interface given and no IPv4 default route` | Host has no IPv4 default route; pass `-i`. |
| Fails to start below kernel 5.8 | Not supported in this release. |
| `Failed to attach tracepoint ... tracefs not found` | Mount tracefs: `mount -t tracefs nodev /sys/kernel/tracing`. Capture still works; process events don't. |
| `Failed to attach kprobe` | Socket lifecycle events unavailable on this kernel/VM; HTTP/DB capture via TC still works. |
| HTTPS traffic not decoded | TLS is decoded only for processes using a shared OpenSSL `libssl` (`SSL_read`/`SSL_write` and their `_ex` variants) or Go's `crypto/tls` (Go 1.17+, binaries with a symbol table). Other statically linked TLS stacks (BoringSSL in Envoy/Chrome, rustls, Java) and Go binaries built with `-ldflags=-s` appear as unknown traffic. Uprobes are per library file, so they cover every process using that `libssl`. Libraries are found at startup, when a process execs, and every `tls_scan_interval_secs` (60 s), so one loaded later, e.g. from a new container image, can take up to a minute to appear; look for `TLS uprobes attached` in the log. |
| Each exchange appears twice on `-i lo` | Loopback shows every packet on both directions; capture a real interface instead. |
| Event log empty after restart | `--json-export` truncates the file at startup; copy it before restarting. |
| `Kubernetes API unavailable` warning, no `src_workload` | `hint` in the log line names the cause: 403 = the ClusterRole lacks `get/list/watch` on pods/services (`rbac.create=true`), 401 = token not mounted or rejected. Endpoints keep IP names meanwhile (§5.6). |

## 7. Limits worth knowing

IPv4 only; Kubernetes names not yet validated on a real cluster (§5.6); HTTPS only via
OpenSSL/Go; PII detection is regex-based by default; see
[`CURRENT-STATE.md`](CURRENT-STATE.md) for the full list.
