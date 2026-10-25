#!/usr/bin/env bash
# Score the agent's HTTP/1.1 capture against ground truth, server-side.
#
# A client in a separate netns talks to a server on the host over a veth
# pair; the agent attaches to the host end (like a pod's veth), so it sees
# requests on ingress and responses on egress. The client logs every
# exchange it completed (truth.jsonl); score.py compares the agent's JSONL
# export to it. Also reports kernel-measured TC cost per packet and the
# agent's user-space CPU time and peak RSS over the run.
#
# Usage: sudo tests/oracle/run.sh [requests=2000] [seed=1234] [min_recall=0.99]
# Needs: root, a built agent (target/release/panopticon-agent), python3 with
# pyroute2 (pip install pyroute2), nsenter.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-2000}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)
PY=${PYTHON:-python3}
PORT=18090

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  [[ -n ${SP:-} ]] && kill "$SP" 2>/dev/null || true
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

sysctl -qw kernel.bpf_stats_enabled=1
"$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true  # leftovers from an aborted run
"$PY" "$HERE/netns.py" up
MODE=server HOST=$HOST_IP python3 -I "$HERE/http_oracle.py" "$PORT" &
SP=$!
"$AGENT" -i "$IFACE" --json-export "$OUT/agent.jsonl" >"$OUT/agent.log" 2>&1 &
AP=$!
sleep 4
START=$(date +%s.%N)  # seconds since epoch, compared with time.time()
# nsenter execs the client, so $! is the client's PID (checked against the
# client_pid the agent attributes to each exchange).
SEED=$SEED MODE=client HOST=$HOST_IP nsenter --net=/var/run/netns/$NS \
  python3 -I "$HERE/http_oracle.py" "$PORT" "$N" "$OUT/truth.jsonl" &
CP=$!
wait "$CP"
python3 -I "$HERE/bpf_cost.py" "$AP"
sleep 1
# utime+stime (fields 14/15) cover the whole run, startup included.
read -r UT ST < <(awk '{print $14, $15}' "/proc/$AP/stat")
HWM=$(awk '/VmHWM/ {print $2}' "/proc/$AP/status")
python3 -c 'import sys, time
ut, st, tck, start, hwm = map(float, sys.argv[1:])
cpu, wall = (ut + st) / tck, time.time() - start
print(f"agent: cpu={cpu:.2f}s over {wall:.0f}s ({cpu / wall:.1%} of one core) peak_rss={hwm / 1024:.1f}MiB")' \
  "$UT" "$ST" "$(getconf CLK_TCK)" "$START" "$HWM"
kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
python3 -I "$HERE/score.py" "$OUT/truth.jsonl" "$OUT/agent.jsonl" "$MIN_RECALL"
python3 -I - "$OUT/agent.jsonl" "$CP" "$SP" <<'EOF'
import json, sys
client, server = int(sys.argv[2]), int(sys.argv[3])
recs = [json.loads(l) for l in open(sys.argv[1])]
c = sum(r.get("client_pid") == client for r in recs)
s = sum(r.get("server_pid") == server for r in recs)
print(f"  process attribution: client_pid {c}/{len(recs)}, server_pid {s}/{len(recs)}")
EOF
echo "artifacts: $OUT"
