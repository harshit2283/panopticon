#!/usr/bin/env bash
# Ground-truth leak test for the privacy modes (full, redacted, metrics_only).
#
# For each mode, one agent run sees two legs of traffic carrying planted,
# unique PII values (in request bodies, query strings and a header):
#   http  http_oracle.py over a veth pair, captured by TC (as run.sh)
#   tls   http_oracle.py over TLS on loopback, captured by the OpenSSL
#         uprobes (as run_tls.sh's openssl stack)
# The agent runs at debug level with every sink the mode allows: the export
# (full, redacted), the raw dump (full; also converted to pcap), the PII
# audit log and the HTTP endpoints (/metrics, /debug/state, scraped before
# it stops). score_modes.py then searches every sink for the planted values
# and fails on a value in a sink the mode forbids, on a full-mode dump that
# misses them, or on recall below MIN_RECALL. With tshark installed, the
# pcap is also checked to open and to show the requests as HTTP.
#
# Usage: sudo tests/oracle/run_modes.sh [requests=300] [seed=1234] [min_recall=0.99] [modes="full redacted metrics_only"]
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# python3 with pyroute2 (set PYTHON), a python3 linked against a shared
# libssl, nsenter, curl.
set -euo pipefail
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-300}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
MODES=${4:-full redacted metrics_only}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)
PY=${PYTHON:-python3}
HTTP_PORT=18091
TLS_PORT=18445
METRICS=127.0.0.1:19190

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  for p in ${SPS:-}; do kill "$p" 2>/dev/null || true; done
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=oracle \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null
"$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true  # leftovers from an aborted run
"$PY" "$HERE/netns.py" up

# Servers first: the agent's initial TLS scan must find the server's libssl.
MODE=server HOST=$HOST_IP python3 -I "$HERE/http_oracle.py" "$HTTP_PORT" &
SPS=$!
env TLS=1 HOST=127.0.0.1 TLS_CERT="$OUT/cert.pem" TLS_KEY="$OUT/key.pem" MODE=server \
  python3 -I "$HERE/http_oracle.py" "$TLS_PORT" &
SPS="$SPS $!"
sleep 1

status=0
for mode in $MODES; do
  D=$OUT/$mode
  mkdir -p "$D/http" "$D/tls"
  args=(-v -i "$IFACE" --privacy-mode "$mode" --metrics-bind "$METRICS"
        --pii-audit-log "$D/audit.jsonl")
  [[ $mode != metrics_only ]] && args+=(--json-export "$D/agent.jsonl")
  [[ $mode == full ]] && args+=(--capture-raw "$D/raw.pncap")
  echo "==== $mode: agent ${args[*]}"
  "$AGENT" "${args[@]}" >"$D/agent.log" 2>&1 &
  AP=$!
  sleep 4
  # Distinct tags per leg: one agent sees both.
  PLANT=${mode}http SEED=$SEED MODE=client HOST=$HOST_IP nsenter --net=/var/run/netns/$NS \
    python3 -I "$HERE/http_oracle.py" "$HTTP_PORT" "$N" "$D/http/truth.jsonl"
  env PLANT=${mode}tls SSN_AREA=234 TLS=1 HOST=127.0.0.1 SEED=$SEED MODE=client \
    python3 -I "$HERE/http_oracle.py" "$TLS_PORT" "$N" "$D/tls/truth.jsonl"
  sleep 12  # past one 10 s stats/graph flush, so its log line is checked too
  curl -sf "http://$METRICS/metrics" >"$D/metrics.txt" || echo "metrics scrape failed"
  curl -sf "http://$METRICS/debug/state" >"$D/debug_state.json" || echo "debug scrape failed"
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  if [[ -f $D/raw.pncap ]]; then
    "$AGENT" --decode-capture "$D/raw.pncap" --pcap "$D/raw.pcap"
    if command -v tshark >/dev/null; then
      reqs=$(tshark -r "$D/raw.pcap" -Y 'http.request' 2>/dev/null | wc -l)
      echo "tshark: $reqs HTTP requests decoded from the pcap (TC and TLS plaintext)"
      [[ $reqs -ge $N ]] || { echo "FAIL: tshark decoded fewer than $N requests"; status=1; }
    fi
  fi
  "$PY" -I "$HERE/score_modes.py" "$mode" "$D" "$MIN_RECALL" || status=1
done
echo "artifacts: $OUT"
exit $status
