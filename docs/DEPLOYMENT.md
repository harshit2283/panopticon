# Deploying Panopticon

How to run the agent on Kubernetes (recommended), as a container on a single
host, or as a plain binary — and how to verify, upgrade and remove it.
For day-to-day usage and output formats see [`USER-GUIDE.md`](USER-GUIDE.md).

> **Experimental software.** Panopticon runs privileged on every node and
> exports observed traffic metadata. Start in a non-production cluster and
> read [`CURRENT-STATE.md`](CURRENT-STATE.md) first.

## 1. Requirements

| Requirement | Detail |
|---|---|
| Kernel | **5.8+** on every node (RingBuf, `bpf_probe_read_{kernel,user}`). Older kernels fail at load time. |
| Architecture | x86_64. arm64 builds are not published yet. |
| Privileges | Root/privileged, or `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` (+ `CAP_SYS_ADMIN` for some tracefs/debugfs setups). |
| Host namespaces | Host network (TC hooks on node interfaces) and host PID (finding TLS libraries via `/proc/<pid>/root`). |
| Mounts | `/sys/fs/bpf`, `/sys/kernel/tracing` (process events), `/sys/kernel/debug` (older kernels' tracefs location). |
| Resources | Default request 200m CPU / 256Mi, limit 1 CPU / 512Mi. Measured: ~1.2–2 µs kernel time per captured packet; agent CPU of roughly one core per 60K captured packets/s with JSON export on; 60–120 MiB RSS under load (see [`BENCHMARKS.md`](BENCHMARKS.md)). If `panopticon_kernel_ringbuf_drops_total` or `panopticon_drops_channel_full_total` keep rising, raise the CPU limit. |

## 2. Get the image

**From a release.** Tagged releases publish a signed image and chart:

```bash
IMAGE=ghcr.io/harshit2283/panopticon:0.1.0
cosign verify "$IMAGE" \
  --certificate-identity-regexp 'https://github.com/harshit2283/panopticon/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

> No release has been tagged yet. Until then, build the image yourself.

**From source.** The Dockerfile pins every toolchain (Rust 1.93.0, eBPF
nightly-2026-02-17, bpf-linker 0.10.3) and produces a ~52 MB distroless image:

```bash
docker build -t registry.example.com/panopticon:0.1.0 .
docker push registry.example.com/panopticon:0.1.0
```

## 3. Kubernetes (Helm)

The chart deploys a DaemonSet (one agent per node), a headless metrics
Service, and optionally a ServiceMonitor.

### 3.1 Install

```bash
# From a release (OCI chart):
helm install panopticon oci://ghcr.io/harshit2283/charts/panopticon \
  --version 0.1.0 -n panopticon --create-namespace

# From this repository, with your own image:
helm install panopticon ./helm/panopticon -n panopticon --create-namespace \
  --set image.repository=registry.example.com/panopticon \
  --set image.tag=0.1.0
```

### 3.2 Verify

```bash
kubectl -n panopticon rollout status ds/panopticon
kubectl -n panopticon logs -l app.kubernetes.io/name=panopticon --tail=50 | \
  grep -E 'Auto-detected|TC classifier attached|HTTP server started'
# Events flowing on a node:
NODE_IP=$(kubectl get node <node> -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
curl -s "$NODE_IP:9435/metrics" | grep -E 'events_received_total|drops_'
```

Pods become Ready as soon as the eBPF programs are attached — a quiet node is
still Ready. If a pod crash-loops, loading the eBPF programs failed (usually a
kernel older than 5.8 or missing privileges). If it runs but captures nothing,
look for `Failed to attach TC classifier` in its logs.

### 3.3 Values

| Value | Default | Notes |
|---|---|---|
| `image.repository` / `image.tag` / `image.digest` | `ghcr.io/harshit2283/panopticon` / appVersion / `""` | Set `digest` to pin exactly. |
| `agent.interfaces` | `[]` | Empty = each node auto-detects its default-route interface. |
| `agent.logLevel` | `info` | `RUST_LOG` filter. |
| `agent.logEvents` | `false` | Logs every event to stdout — very verbose. |
| `agent.config` | `""` | Inline TOML (see USER-GUIDE §4.2), mounted as a ConfigMap. |
| `metrics.port` | `9435` | Health, readiness and metrics port. |
| `metrics.bindAddress` | `$(POD_IP)` | With host networking this is the node IP. `0.0.0.0` listens on all interfaces. |
| `metrics.serviceMonitor.enabled` | `false` | Needs the prometheus-operator CRDs. |
| `export.hostPath` | `""` | Host directory for `events.jsonl` / `pii-audit.jsonl`; empty disables file export. |
| `export.jsonEvents` / `export.piiAuditLog` | `true` / `true` | Which files to write when `hostPath` is set. |
| `export.rawCapture` | `false` | Also write `raw.pncap`: every captured payload, **unredacted** (USER-GUIDE §5.5). |
| `securityContext` | `{privileged: true}` | See §6 for a reduced-capability profile. |
| `priorityClassName` | `""` | `system-node-critical` is only admitted in `kube-system`. |
| `tolerations` | `[{operator: Exists}]` | Runs on every node, including tainted ones. |
| `nodeSelector` / `affinity` | `{}` | Limit to a subset of nodes. |
| `resources` | see §1 | |
| `kubernetes.enabled` | `true` | Kubernetes identity: endpoints named `namespace/workload` (USER-GUIDE §5.6). Mounts the service account token and, with `rbac.create`, grants read-only `get/list/watch` on `pods` and `services` cluster-wide. `false`: no token, no ClusterRole, IP/DNS names only. |
| `rbac.create` | `true` | Create the ClusterRole/ClusterRoleBinding for `kubernetes.enabled`. Set `false` to manage RBAC yourself. |
| `serviceAccount.automountToken` | `false` | Mount the token even with `kubernetes.enabled=false`. |

**RBAC.** With the defaults the chart creates one ClusterRole bound to the
agent's service account:

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods", "services"]
    verbs: ["get", "list", "watch"]
```

Nothing else is read or written. Each agent lists all pods and services
every `relist_interval_secs` (default 300 s, pages of 500) and keeps one
watch per resource open; on large clusters raise the interval via
`agent.config` (`[kubernetes] relist_interval_secs = 900`). If the API is
unreachable or access is denied, the agent logs a warning once and carries
on with IP/DNS names.

Example `values-prod.yaml`:

```yaml
image:
  repository: registry.example.com/panopticon
  digest: "sha256:<digest>"
agent:
  config: |
    max_events_per_sec = 200000
    [pii]
    redact = true
export:
  hostPath: /var/lib/panopticon
metrics:
  serviceMonitor:
    enabled: true
nodeSelector:
  panopticon/enabled: "true"
```

### 3.4 Upgrade, roll back, uninstall

```bash
helm upgrade panopticon <chart> -n panopticon -f values-prod.yaml
helm rollback panopticon -n panopticon            # previous revision
helm uninstall panopticon -n panopticon
```

The DaemonSet rolls one node at a time (`maxUnavailable: 1`). On
`SIGTERM` the agent marks itself not-ready, flushes exports and detaches; on
kernels before 6.6, classifiers left behind by a crashed agent are removed
automatically at the next start.

## 4. Single host with Docker

```bash
docker run -d --name panopticon --restart unless-stopped \
  --privileged --network host --pid host \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /sys/kernel/tracing:/sys/kernel/tracing \
  -v /var/lib/panopticon:/var/lib/panopticon \
  registry.example.com/panopticon:0.1.0 \
  --metrics-bind 127.0.0.1:9435 \
  --json-export /var/lib/panopticon/events.jsonl \
  --pii-audit-log /var/lib/panopticon/pii-audit.jsonl

curl -s 127.0.0.1:9435/readyz      # -> ready
docker stop panopticon              # SIGTERM: clean shutdown, exit 0
```

Without arguments the image binds metrics to `127.0.0.1:9435` only.

## 5. Plain binary with systemd

Copy `panopticon-agent` (from a release, or `target/release/` after building)
to `/usr/local/bin`, then:

```ini
# /etc/systemd/system/panopticon.service
[Unit]
Description=Panopticon eBPF observability agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/panopticon-agent --config /etc/panopticon/config.toml
Restart=on-failure
RestartSec=5
# Root is needed to load eBPF programs.
User=root
LimitMEMLOCK=infinity
StateDirectory=panopticon

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now panopticon
journalctl -u panopticon -f
```

## 6. Security hardening

- **Endpoints are unauthenticated.** Keep `metrics.bindAddress` on the node IP
  or loopback, and firewall port 9435 to your Prometheus.
- **Exports are sensitive.** Even redacted, events reveal who talks to whom,
  URL structure and timing. Restrict `export.hostPath` permissions and ship
  them only to systems approved for that data.
- **Reduced privileges (kernel 5.8+).** Instead of `privileged: true`:

  ```yaml
  securityContext:
    privileged: false
    capabilities:
      add: [BPF, PERFMON, NET_ADMIN, SYS_PTRACE, SYS_RESOURCE, SYS_ADMIN]
    seccompProfile: {type: Unconfined}
    appArmorProfile: {type: Unconfined}
  ```

  This profile has not yet been validated on all distributions — test it on
  one node pool first.
- Core dumps are disabled by the agent (`PR_SET_DUMPABLE=0`) so captured data
  cannot leak through them.

## 7. Upgrade notes

- **0.1.0 changed the kernel↔agent event format** (`DataEvent` gained
  `orig_len`, 4160 bytes) and several map types. If you enabled
  `map_pin_path`, remove the old pins before upgrading:
  `rm -rf /sys/fs/bpf/panopticon`.
- Replay capture files (`PNCAP`) are now format version 2; version 1 files
  are rejected.

## 8. Releasing (maintainers)

1. Bump `version` in `panopticon-agent/Cargo.toml` and both `version` and
   `appVersion` in `helm/panopticon/Chart.yaml` to the same value.
2. Push a tag `vX.Y.Z`. `.github/workflows/release.yml` checks the versions
   match, pushes the image to GHCR with SBOM and provenance, signs it with
   cosign (keyless), publishes the chart to
   `oci://ghcr.io/<owner>/charts/panopticon`, and creates a GitHub pre-release
   with the binary and `SHA256SUMS`.
3. Before tagging, run the ground-truth capture check on a Linux host
   (`sudo tests/oracle/run.sh`, see [`BENCHMARKS.md`](BENCHMARKS.md)); it
   fails below 99% recall.
