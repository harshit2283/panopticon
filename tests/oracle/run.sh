#!/usr/bin/env bash
# Score the agent's HTTP/1.1 capture against ground truth, server-side.
#
# A client in a separate netns talks to a server on the host over a veth
# pair; the agent captures at both sockets (cgroup_skb), so each exchange
# is seen from the client and from the server. The client logs every
# exchange it completed (truth.jsonl); score.py compares the agent's JSONL
# export to it. Also reports kernel-measured capture cost per packet and the
# agent's user-space CPU time and peak RSS over the run.
#
# Last, a request sent from the agent's own metrics port (F2: a peer that
# picked that port as its source port used to be skipped) must still be
# captured.
#
# Usage: sudo tests/oracle/run.sh [requests=2000] [seed=1234] [min_recall=0.99]
# Needs: root, a built agent (target/release/panopticon-agent), python3,
# iproute2, nsenter.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
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
MPORT=19435  # the agent's --metrics-bind port

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
"$AGENT" --json-export "$OUT/agent.jsonl" --metrics-bind "$HOST_IP:$MPORT" \
  >"$OUT/agent.log" 2>&1 &
AP=$!
sleep 4
START=$(date +%s.%N)  # seconds since epoch, compared with time.time()
SEED=$SEED MODE=client HOST=$HOST_IP nsenter --net=/var/run/netns/$NS \
  python3 -I "$HERE/http_oracle.py" "$PORT" "$N" "$OUT/truth.jsonl" &
CP=$!
wait "$CP"
nsenter --net=/var/run/netns/$NS curl -s -o /dev/null --local-port "$MPORT" \
  "http://$HOST_IP:$PORT/f2probe" || echo "f2 probe request failed"
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
if grep -q '"path":"/f2probe"' "$OUT/agent.jsonl"; then
  echo "  metrics source port: a request from port $MPORT was captured"
else
  echo "FAIL: a request sent from the agent's metrics port $MPORT was not captured"
  exit 1
fi
echo "artifacts: $OUT"
