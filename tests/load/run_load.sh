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
# Env: MIN_RECALL (unset = report only), PYTHON (with pyroute2), AGENT_ARGS,
#      KEEP=1 to keep the (large) export and id list, NO_EXPORT=1 to run
#      without the JSON export (no recall score; isolates its cost).
# Needs: root, go, a built agent, python3 with pyroute2.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
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
  "$PY" "$ORACLE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

go build -o "$OUT/loadgen" "$HERE/loadgen.go"
sysctl -qw kernel.bpf_stats_enabled=1
"$PY" "$ORACLE/netns.py" down >/dev/null 2>&1 || true
"$PY" "$ORACLE/netns.py" up
"$OUT/loadgen" server -addr "$HOST_IP:$PORT" &
SP=$!
EXPORT=(--json-export "$OUT/agent.jsonl")
[[ ${NO_EXPORT:-0} == 1 ]] && EXPORT=()
# shellcheck disable=SC2086
"$AGENT" -i "$IFACE" "${EXPORT[@]}" --metrics-bind "$METRICS" \
  ${AGENT_ARGS:-} >"$OUT/agent.log" 2>&1 &
AP=$!
sleep 4

NC=()
[[ $NEWCONN == 1 ]] && NC=(-newconn)
[[ $NEWCONN == fin ]] && NC=(-fin)
START=$(date +%s.%N)
# CPU is counted from here: startup work (TLS scan, map setup) is excluded.
read -r UT0 ST0 < <(awk '{print $14, $15}' "/proc/$AP/stat")
nsenter --net=/var/run/netns/$NS "$OUT/loadgen" client \
  -url "http://$HOST_IP:$PORT" -c "$CONC" -d "$DUR" -rate "$RATE" -size "$SIZE" \
  "${NC[@]}" -out "$OUT/ids.txt" | tee "$OUT/client.txt"
sleep 3  # let the agent drain

python3 -I "$ORACLE/bpf_cost.py" "$AP"
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
        "active_connections"]
print("metrics: " + " ".join(f"{k}={int(vals[k])}" for k in keys if k in vals))
open(sys.argv[1] + ".received", "w").write(str(int(vals.get("events_received", 0))))
EOF
read -r UT ST < <(awk -v u="$UT0" -v s="$ST0" '{print $14 - u, $15 - s}' "/proc/$AP/stat")
HWM=$(awk '/VmHWM/ {print $2}' "/proc/$AP/status")
python3 -c 'import sys, time
ut, st, tck, start, hwm = map(float, sys.argv[1:6])
cpu, wall = (ut + st) / tck, time.time() - start
events = int(open(sys.argv[6]).read() or 0)
per = f" cpu_per_event={cpu / events * 1e6:.1f}us" if events else ""
print(f"agent: cpu={cpu:.2f}s over {wall:.0f}s ({cpu / wall:.0%} of one core){per} peak_rss={hwm / 1024:.0f}MiB")' \
  "$UT" "$ST" "$(getconf CLK_TCK)" "$START" "$HWM" "$OUT/metrics.txt.received"
kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
status=0
[[ ${NO_EXPORT:-0} == 1 ]] || python3 -I "$HERE/score_load.py" "$OUT/ids.txt" "$OUT/agent.jsonl" ${MIN_RECALL:-} || status=1
# The export and id list run to hundreds of MB per run; keep with KEEP=1.
[[ ${KEEP:-0} == 1 ]] || rm -f "$OUT/agent.jsonl" "$OUT/ids.txt"
echo "artifacts: $OUT"
exit $status
