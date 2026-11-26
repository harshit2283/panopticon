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
# Needs: root, a built agent (target/release/panopticon-agent), python3 3.7+
# (the first new enough, or set PYTHON), iproute2, nsenter.
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
# One python3 >= 3.7 for every step (RHEL 8's python3 is 3.6): $PYTHON, or
# the first of these that is new enough.
PY=${PYTHON:-}
if [[ -z $PY ]]; then
  for c in python3 python3.12 python3.11 python3.9 python3.8; do
    if command -v "$c" >/dev/null && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 7))'; then
      PY=$c
      break
    fi
  done
fi
[[ -n $PY ]] || { echo "needs python3 >= 3.7 (set PYTHON)" >&2; exit 1; }
PORT=18090
MPORT=19435  # the agent's --metrics-bind port

# stop_bounded PID: SIGINT, then up to 90 s for the process to flush and
# exit; past that SIGKILL and a failure (message, returns 1). Sets
# STOP_EXIT to the process's exit status.
stop_bounded() {
  local p=$1 i
  STOP_EXIT=0
  [[ -n $p ]] || return 0
  if kill -INT "$p" 2>/dev/null; then
    for ((i = 0; i < 900; i++)); do
      kill -0 "$p" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$p" 2>/dev/null; then
      echo "FAIL: pid $p still running 90 s after SIGINT: killed (SIGKILL), its output may be incomplete" >&2
      kill -KILL "$p" 2>/dev/null || true
      wait "$p" 2>/dev/null || true
      STOP_EXIT=137
      return 1
    fi
  fi
  wait "$p" 2>/dev/null || STOP_EXIT=$?
  return 0
}

cleanup() {
  [[ -n ${AP:-} ]] && stop_bounded "$AP" || true
  [[ -n ${SP:-} ]] && kill "$SP" 2>/dev/null || true
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

sysctl -qw kernel.bpf_stats_enabled=1
"$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true  # leftovers from an aborted run
"$PY" "$HERE/netns.py" up
MODE=server HOST=$HOST_IP "$PY" -I "$HERE/http_oracle.py" "$PORT" &
SP=$!
"$AGENT" --json-export "$OUT/agent.jsonl" --metrics-bind "$HOST_IP:$MPORT" \
  >"$OUT/agent.log" 2>&1 &
AP=$!
sleep 4
START=$(date +%s.%N)  # seconds since epoch, compared with time.time()
SEED=$SEED MODE=client HOST=$HOST_IP nsenter --net=/var/run/netns/$NS \
  "$PY" -I "$HERE/http_oracle.py" "$PORT" "$N" "$OUT/truth.jsonl" &
CP=$!
wait "$CP"
nsenter --net=/var/run/netns/$NS curl -s -o /dev/null --local-port "$MPORT" \
  "http://$HOST_IP:$PORT/f2probe" || echo "f2 probe request failed"
"$PY" -I "$HERE/bpf_cost.py" "$AP"
sleep 1
# utime+stime (fields 14/15) cover the whole run, startup included.
read -r UT ST < <(awk '{print $14, $15}' "/proc/$AP/stat")
HWM=$(awk '/VmHWM/ {print $2}' "/proc/$AP/status")
"$PY" -c 'import sys, time
ut, st, tck, start, hwm = map(float, sys.argv[1:])
cpu, wall = (ut + st) / tck, time.time() - start
print(f"agent: cpu={cpu:.2f}s over {wall:.0f}s ({cpu / wall:.1%} of one core) peak_rss={hwm / 1024:.1f}MiB")' \
  "$UT" "$ST" "$(getconf CLK_TCK)" "$START" "$HWM"
stop_bounded "$AP" || stop_failed=1; AP=
"$PY" -I "$HERE/score.py" "$OUT/truth.jsonl" "$OUT/agent.jsonl" "$MIN_RECALL"
[[ -z ${stop_failed:-} ]] || { echo "FAIL: the agent did not stop on SIGINT" >&2; exit 1; }
if grep -q '"path":"/f2probe"' "$OUT/agent.jsonl"; then
  echo "  metrics source port: a request from port $MPORT was captured"
else
  echo "FAIL: a request sent from the agent's metrics port $MPORT was not captured"
  exit 1
fi
echo "artifacts: $OUT"
