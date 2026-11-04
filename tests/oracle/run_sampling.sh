#!/usr/bin/env bash
# Ground-truth test for the capture-scope settings: pid_filter,
# sampling_mode = "connection_sample" and sampling_mode = "head_only".
#
# Traffic legs (as run_modes.sh), with planted PII and credentials:
#   http   http_oracle.py over a veth pair, captured by TC
#   tls    http_oracle.py over TLS on loopback, captured by the OpenSSL
#          uprobes in both the client and the server process
# Runs, each with its own agent, privacy mode full and every sink on (event
# export, raw dump, PII audit log, --log-events at debug level, /metrics):
#   pid_servers   pid_filter = [http server, tls server]: both servers'
#                 traffic is captured; the TLS client's is not (kernel).
#   pid_other     pid_filter = [an unrelated sleep]: nothing is exported and
#                 no planted value reaches any sink.
#   sample_0, sample_50, sample_100   connection_sample at 0.0 / 0.5 / 1.0
#                 (http leg): about 0%, a binomially plausible 50%, and all
#                 connections exported, never part of a connection.
#   head          head_only with head_only_bytes = HEAD: no direction of any
#                 connection passes more than HEAD bytes, values planted
#                 beyond them reach no sink, and each connection's first
#                 request is still captured.
# score_sampling.py scores each run.
#
# Usage: sudo tests/oracle/run_sampling.sh [requests=600] [seed=1234] [min_recall=0.99] [runs="..."]
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# python3 with pyroute2 (set PYTHON), a python3 linked against a shared
# libssl, nsenter, curl.
set -euo pipefail
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-600}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
RUNS=${4:-pid_servers pid_other sample_0 sample_50 sample_100 head}
HEAD=600
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)
PY=${PYTHON:-python3}
HTTP_PORT=18092
TLS_PORT=18446
METRICS=127.0.0.1:19191

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
HTTP_SP=$!
env TLS=1 HOST=127.0.0.1 TLS_CERT="$OUT/cert.pem" TLS_KEY="$OUT/key.pem" MODE=server \
  python3 -I "$HERE/http_oracle.py" "$TLS_PORT" &
TLS_SP=$!
sleep 1000 &
OTHER=$!
SPS="$HTTP_SP $TLS_SP $OTHER"
sleep 1

status=0
for run in $RUNS; do
  D=$OUT/$run
  mkdir -p "$D/http" "$D/tls"
  legs="http tls"
  case $run in
    pid_servers) scope="pid_filter = [$HTTP_SP, $TLS_SP]" ;;
    pid_other)   scope="pid_filter = [$OTHER]" ;;
    sample_0)    scope=$'sampling_mode = "connection_sample"\nsample_rate = 0.0'; legs=http ;;
    sample_50)   scope=$'sampling_mode = "connection_sample"\nsample_rate = 0.5'; legs=http ;;
    sample_100)  scope=$'sampling_mode = "connection_sample"\nsample_rate = 1.0'; legs=http ;;
    head)        scope=$'sampling_mode = "head_only"\nhead_only_bytes = '"$HEAD" ;;
    *) echo "unknown run $run"; exit 2 ;;
  esac
  printf '%s\n\n[privacy]\nmode = "full"\n' "$scope" >"$D/agent.toml"
  echo "==== $run: $(head -c 200 "$D/agent.toml" | tr '\n' ' ')"
  "$AGENT" -v -i "$IFACE" --config "$D/agent.toml" --log-events --metrics-bind "$METRICS" \
    --json-export "$D/agent.jsonl" --pii-audit-log "$D/audit.jsonl" \
    --capture-raw "$D/raw.pncap" >"$D/agent.log" 2>&1 &
  AP=$!
  sleep 4
  PLANT=${run}http SEED=$SEED MODE=client HOST=$HOST_IP nsenter --net=/var/run/netns/$NS \
    python3 -I "$HERE/http_oracle.py" "$HTTP_PORT" "$N" "$D/http/truth.jsonl"
  if [[ $legs == *tls* ]]; then
    env PLANT=${run}tls SSN_AREA=234 TLS=1 HOST=127.0.0.1 SEED=$SEED MODE=client \
      python3 -I "$HERE/http_oracle.py" "$TLS_PORT" "$N" "$D/tls/truth.jsonl"
  fi
  sleep 3
  curl -sf "http://$METRICS/metrics" >"$D/metrics.txt" || echo "metrics scrape failed"
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  "$AGENT" --privacy-mode full --decode-capture "$D/raw.pncap" >"$D/raw.jsonl"
  "$PY" -I "$HERE/score_sampling.py" "$run" "$D" "$MIN_RECALL" "$HTTP_SP" "$TLS_SP" "$HEAD" ||
    status=1
done
echo "artifacts: $OUT"
exit $status
