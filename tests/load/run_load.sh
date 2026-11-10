#!/usr/bin/env bash
# Agent scalability run: drive HTTP/1.1 load through a veth at a given
# concurrency/rate and report what the agent kept up with.
#
# Same topology as tests/oracle/run.sh (client netns -> veth -> server on
# the host, agent on the host end). Reports: achieved load, capture recall
# (completed requests exported), drops by cause from /metrics (kernel ring
# buffer, rate limiter, worker queues), agent CPU and peak RSS, and kernel
# BPF cost per invocation.
#
# Usage: sudo tests/load/run_load.sh [conc=64] [duration=20s] [rate=0] [newconn=0] [size=512]
#   rate=0 means as fast as the client can go; newconn=1 opens a TCP
#   connection per request (connection-tracking stress), newconn=fin does
#   the same but closes with a plain FIN instead of Connection: close.
# Env: MIN_RECALL (unset = report only), PYTHON, AGENT_ARGS,
#      KEEP=1 to keep the (large) export and id list, NO_EXPORT=1 to run
#      without the JSON export (no recall score; isolates its cost),
#      NO_AGENT=1 to run the same load with no agent (application baseline),
#      BACKEND=tc|cgroup_skb ([capture] backend; default tc),
#      SCOPE= (unscoped) | server (pid_filter = the server) | other
#        (pid_filter = an idle process: every packet out of scope) | cgroup
#        (cgroup_filter = a cgroup holding only the server; cgroup_skb on a
#        cgroup2 host) | head (head_only, HEAD_BYTES, default 4096) |
#        sample (connection_sample, SAMPLE_RATE, default 0.5),
#      TOML= extra top-level config lines (e.g. max_events_per_sec = 100000000),
#      LOADGEN= a prebuilt loadgen binary (no Go needed on the host),
#      LOOPBACK=1 to run client and server over 127.0.0.1 in the host
#        namespace: node-local traffic, which TC on an interface never sees
#        and the cgroup_skb backend sees at both sockets.
# The cgroup_skb backend captures every local socket: unscoped, it sees
# both the client's and the server's socket of each exchange (two views,
# about twice the events of TC on the veth, which sees each packet once).
# SCOPE=server is the comparable server-only view.
# With rate>0 the client holds a fixed rate and reports achieved vs target
# (a miss over 2% marks the run invalid) and client latency percentiles.
# Needs: root, go (or LOADGEN), a built agent, python3, iproute2.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
[[ ${LOOPBACK:-0} == 1 ]] && HOST_IP=127.0.0.1
CONC=${1:-64}
DUR=${2:-20s}
RATE=${3:-0}
NEWCONN=${4:-0}
SIZE=${5:-512}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
ORACLE=$ROOT/tests/oracle
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
PY=${PYTHON:-python3}
OUT=$(mktemp -d)
PORT=18090
METRICS=127.0.0.1:9435

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  [[ -n ${SP:-} ]] && kill "$SP" 2>/dev/null || true
  [[ -n ${IDLE:-} ]] && kill "$IDLE" 2>/dev/null || true
  [[ -n ${CG:-} ]] && sleep 0.2 && rmdir "$CG" 2>/dev/null || true
  "$PY" "$ORACLE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n ${LOADGEN:-} ]]; then cp "$LOADGEN" "$OUT/loadgen"; else go build -o "$OUT/loadgen" "$HERE/loadgen.go"; fi
sysctl -qw kernel.bpf_stats_enabled=1
"$PY" "$ORACLE/netns.py" down >/dev/null 2>&1 || true
"$PY" "$ORACLE/netns.py" up
if [[ ${SCOPE:-} == cgroup ]]; then
  CG=/sys/fs/cgroup/${NS}-load
  mkdir -p "$CG"
  # shellcheck disable=SC2016
  bash -c 'echo $$ > "$1/cgroup.procs" && exec "$2" server -addr "$3"' _ "$CG" "$OUT/loadgen" "$HOST_IP:$PORT" &
else
  "$OUT/loadgen" server -addr "$HOST_IP:$PORT" &
fi
SP=$!
CONF=$OUT/load.toml
{
  [[ -n ${TOML:-} ]] && printf '%s\n' "$TOML"
  case ${SCOPE:-} in
    "") ;;
    server) echo "pid_filter = [$SP]" ;;
    other) sleep 100000 & IDLE=$!; echo "pid_filter = [$IDLE]" ;;
    cgroup) echo "cgroup_filter = [\"${CG#/sys/fs/cgroup}\"]" ;;
    head) echo 'sampling_mode = "head_only"'; echo "head_only_bytes = ${HEAD_BYTES:-4096}" ;;
    sample) echo 'sampling_mode = "connection_sample"'; echo "sample_rate = ${SAMPLE_RATE:-0.5}" ;;
    *) echo "unknown SCOPE=$SCOPE" >&2; exit 2 ;;
  esac
  printf '[capture]\nbackend = "%s"\n' "${BACKEND:-tc}"
} >"$CONF"
EXPORT=(--json-export "$OUT/agent.jsonl")
[[ ${NO_EXPORT:-0} == 1 ]] && EXPORT=()
if [[ ${NO_AGENT:-0} != 1 ]]; then
  # shellcheck disable=SC2086
  "$AGENT" -i "$IFACE" --config "$CONF" "${EXPORT[@]}" --metrics-bind "$METRICS" \
    ${AGENT_ARGS:-} >"$OUT/agent.log" 2>&1 &
  AP=$!
fi
sleep 4

NC=()
[[ $NEWCONN == 1 ]] && NC=(-newconn)
[[ $NEWCONN == fin ]] && NC=(-fin)
CLIENT=(nsenter --net=/var/run/netns/$NS)
[[ ${LOOPBACK:-0} == 1 ]] && CLIENT=()
# Kernel cost over the load window only (not startup or earlier traffic).
[[ -n ${AP:-} ]] && python3 -I "$ORACLE/bpf_cost.py" --snap "$AP" >"$OUT/bpf0.json"
START=$(date +%s.%N)
# CPU is counted from here: startup work (TLS scan, map setup) is excluded.
read -r SUT0 SST0 < <(awk '{print $14, $15}' "/proc/$SP/stat")
[[ -n ${AP:-} ]] && read -r UT0 ST0 < <(awk '{print $14, $15}' "/proc/$AP/stat")
"${CLIENT[@]}" "$OUT/loadgen" client \
  -url "http://$HOST_IP:$PORT" -c "$CONC" -d "$DUR" -rate "$RATE" -size "$SIZE" \
  "${NC[@]}" -out "$OUT/ids.txt" | tee "$OUT/client.txt"
# Server CPU over the load (its own process: handlers, plus the softirq and
# TC work charged to it), per request.
read -r SUT SST < <(awk -v u="$SUT0" -v s="$SST0" '{print $14 - u, $15 - s}' "/proc/$SP/stat")
REQS=$(sed -n 's/^requests=\([0-9]*\).*/\1/p' "$OUT/client.txt")
DURS=$(sed -n 's/.* elapsed=\([0-9.]*\)s.*/\1/p' "$OUT/client.txt")
python3 -c 'import sys
ut, st, tck, n, d = map(float, sys.argv[1:6])
cpu = (ut + st) / tck
print(f"server: cpu={cpu:.2f}s cores={cpu / d:.2f} cpu_per_request={cpu / max(n, 1) * 1e6:.1f}us")' \
  "$SUT" "$SST" "$(getconf CLK_TCK)" "$REQS" "$DURS"
if [[ ${NO_AGENT:-0} == 1 ]]; then
  rm -f "$OUT/ids.txt"
  echo "artifacts: $OUT"
  exit 0
fi
sleep 3  # let the agent drain

python3 -I "$ORACLE/bpf_cost.py" "$AP" "$OUT/bpf0.json"
echo "time_wait: host=$(ss -Htan state time-wait | wc -l) client_ns=$(ip netns exec "$NS" ss -Htan state time-wait | wc -l)"
curl -s "http://$METRICS/metrics" >"$OUT/metrics.txt" || true
python3 -I - "$OUT/metrics.txt" <<'EOF'
import re, sys
vals = {}
for line in open(sys.argv[1]):
    m = re.match(r"panopticon_([a-z_]+?)(?:_total)?(?:\{[^}]*\})? ([0-9.e+]+)$", line)
    if m:
        vals[m.group(1)] = vals.get(m.group(1), 0) + float(m.group(2))
keys = ["events_received", "events_dropped", "kernel_ringbuf_drops", "drops_rate_limit",
        "drops_channel_full", "drops_export_full", "drops_parser_error", "capture_truncated",
        "raw_capture_dropped", "pii_detections", "active_connections"]
print("metrics: " + " ".join(f"{k}={int(vals[k])}" for k in keys if k in vals))
scope = re.findall(r'^panopticon_scope_dropped_events_total\{reason="([a-z_]+)"\} ([0-9.e+]+)$',
                   open(sys.argv[1]).read(), re.M)
if scope:
    print("scope_drops: " + " ".join(f"{r}={int(float(v))}" for r, v in scope if float(v)))
open(sys.argv[1] + ".received", "w").write(str(int(vals.get("events_received", 0))))
open(sys.argv[1] + ".pii", "w").write(str(int(vals.get("pii_detections", 0))))
EOF
read -r UT ST < <(awk -v u="$UT0" -v s="$ST0" '{print $14 - u, $15 - s}' "/proc/$AP/stat")
HWM=$(awk '/VmHWM/ {print $2}' "/proc/$AP/status")
# Per request (the client's count) as well as per event: an HTTP exchange is
# two or more events. cores = agent CPU over the load duration (the drain
# after it is in the numerator, so a slight overestimate).
python3 -c 'import sys, time
ut, st, tck, start, hwm, reqs, dur = map(float, sys.argv[1:8])
cpu, wall = (ut + st) / tck, time.time() - start
events = int(open(sys.argv[8]).read() or 0)
per = f" cpu_per_event={cpu / events * 1e6:.1f}us" if events else ""
print(f"agent: cpu={cpu:.2f}s over {wall:.0f}s ({cpu / wall:.0%} of one core){per} peak_rss={hwm / 1024:.0f}MiB")
print(f"agent_per_request: cores={cpu / dur:.2f} cpu_per_request={cpu / max(reqs, 1) * 1e6:.1f}us")' \
  "$UT" "$ST" "$(getconf CLK_TCK)" "$START" "$HWM" "$REQS" "$DURS" "$OUT/metrics.txt.received"
# Recall proxy for runs without the export: each request carries one PII
# entity the scanner finds (the IP address in its Host header) and every 5th
# (id % 5 == 0) is a POST whose body adds an email address, so detections
# over requests + POSTs completed estimates the share parsed and scanned.
python3 -c 'import sys
ids = [int(l.strip()[1:]) for l in open(sys.argv[1]) if l.strip()]
want = len(ids) + sum(1 for i in ids if i % 5 == 0)
pii = int(open(sys.argv[2]).read() or 0)
print(f"pii_recall_proxy={pii / max(want, 1):.2%} ({pii}/{want} expected entities)")' "$OUT/ids.txt" "$OUT/metrics.txt.pii"
kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
status=0
[[ ${NO_EXPORT:-0} == 1 ]] || python3 -I "$HERE/score_load.py" "$OUT/ids.txt" "$OUT/agent.jsonl" ${MIN_RECALL:-} || status=1
# The export and id list run to hundreds of MB per run; keep with KEEP=1.
[[ ${KEEP:-0} == 1 ]] || rm -f "$OUT/agent.jsonl" "$OUT/ids.txt"
echo "artifacts: $OUT"
exit $status
