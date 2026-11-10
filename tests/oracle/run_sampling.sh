#!/usr/bin/env bash
# Ground-truth test for the capture-scope settings: pid_filter,
# sampling_mode = "connection_sample" and sampling_mode = "head_only".
#
# Traffic legs (as run_modes.sh), with planted PII and credentials:
#   http   http_oracle.py over a veth pair, captured by TC (or, with
#          BACKEND=cgroup_skb, at both sockets' cgroup hooks)
#   tls    http_oracle.py over TLS on loopback, captured by the OpenSSL
#          uprobes in both the client and the server process
# Runs, each with its own agent, privacy mode full and every sink on (event
# export, raw dump, PII audit log, --log-events at debug level, /metrics):
#   pid_servers   pid_filter = [http server, tls server]: both servers'
#                 traffic is captured; the TLS client's is not (kernel).
#   pid_other     pid_filter = [an unrelated, idle python3]: nothing is
#                 exported and no planted value reaches any sink.
#   sample_0, sample_50, sample_100   connection_sample at 0.0 / 0.5 / 1.0
#                 (http leg): about 0%, a binomially plausible 50%, and all
#                 connections exported, never part of a connection.
#   head          head_only with head_only_bytes = HEAD: no direction of any
#                 connection passes more than HEAD bytes, values planted
#                 beyond them reach no sink, and each connection's first
#                 request is still captured.
#   cgroup_filter (BACKEND=cgroup_skb on a unified cgroup2 host only; in the
#                 default runs there) cgroup_filter = the cgroup both servers
#                 were started in: as pid_servers, selected by cgroup.
# BACKEND=cgroup_skb ([capture] backend) decides scope in the kernel per
# socket, so each connection has two views, one per endpoint socket, each
# scoped and sampled on its own. score_sampling.py scores each run.
#
# Usage: sudo tests/oracle/run_sampling.sh [requests=600] [seed=1234] [min_recall=0.99] [runs="..."]
# Env: BACKEND (tc | cgroup_skb), AGENT, HTTP_PORT, TLS_PORT, METRICS, and
# ORACLE_NS / ORACLE_IF / ORACLE_NET (netns.py).
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# python3 3.7+ (set PYTHON) linked against a shared libssl, iproute2, nsenter,
# curl.
set -euo pipefail
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-600}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
BACKEND=${BACKEND:-tc}
CGROUP2=/sys/fs/cgroup
SEL=$CGROUP2/$NS-sel  # cgroup_skb: the servers' cgroup
UNIFIED=0
[[ $BACKEND == cgroup_skb && $(stat -fc %T $CGROUP2) == cgroup2fs ]] && UNIFIED=1
DEFAULT_RUNS="pid_servers pid_other sample_0 sample_50 sample_100 head"
[[ $UNIFIED == 1 ]] && DEFAULT_RUNS+=" cgroup_filter"
RUNS=${4:-$DEFAULT_RUNS}
HEAD=600
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)
PY=${PYTHON:-python3}
HTTP_PORT=${HTTP_PORT:-18092}
TLS_PORT=${TLS_PORT:-18446}
METRICS=${METRICS:-127.0.0.1:19191}

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  for p in ${SPS:-}; do kill "$p" 2>/dev/null || true; done
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
  [[ $UNIFIED == 1 ]] && rmdir "$SEL" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=oracle \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null
"$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true  # leftovers from an aborted run
"$PY" "$HERE/netns.py" up

# Servers. With BACKEND=cgroup_skb each run starts its own, before the agent
# (pid_filter lists their pids) but held until the agent is ready, so their
# listeners are created under the agent and carry their owner (a listener
# that predates the agent has none: pid_filter would drop each connection's
# bytes until accept() returns, DESIGN §3.1), and inside the servers'
# cgroup, so their sockets carry it for life (cgroup_filter). The hold is a
# shell that execs the server, so $! stays the server's pid.
start_servers() {
  local hold=()
  if [[ $BACKEND == cgroup_skb ]]; then
    [[ $UNIFIED == 1 ]] && mkdir -p "$SEL"
    hold=(sh -c 'if [ -n "$1" ]; then echo $$ >"$1/cgroup.procs"; fi
      while [ ! -e "$0" ]; do sleep 0.1; done; shift; exec "$@"' "$OUT/go")
    if [[ $UNIFIED == 1 ]]; then hold+=("$SEL"); else hold+=(""); fi
  fi
  rm -f "$OUT/go"
  "${hold[@]}" env MODE=server HOST=$HOST_IP python3 -I "$HERE/http_oracle.py" "$HTTP_PORT" &
  HTTP_SP=$!
  "${hold[@]}" env TLS=1 HOST=127.0.0.1 TLS_CERT="$OUT/cert.pem" TLS_KEY="$OUT/key.pem" \
    MODE=server python3 -I "$HERE/http_oracle.py" "$TLS_PORT" &
  TLS_SP=$!
  SPS="$OTHER $HTTP_SP $TLS_SP"
}
stop_servers() {
  kill "$HTTP_SP" "$TLS_SP" 2>/dev/null || true
  wait "$HTTP_SP" "$TLS_SP" 2>/dev/null || true
}

# An idle python3 with libssl loaded, alive for every run: pid_other's pid,
# and on cgroup_skb (servers start per run) what the agent's start-up TLS
# scan finds libssl in (the probes cover every process mapping it).
python3 -c 'import ssl, time; time.sleep(100000)' &
OTHER=$!
SPS=$OTHER
# Servers first: the agent's initial TLS scan must find the server's libssl.
[[ $BACKEND != cgroup_skb ]] && start_servers
sleep 1

status=0
for run in $RUNS; do
  D=$OUT/$run
  mkdir -p "$D/http" "$D/tls"
  legs="http tls"
  case $run in
    pid_servers) scope="pid_filter = [\$HTTP_SP, \$TLS_SP]" ;;
    pid_other)   scope="pid_filter = [$OTHER]" ;;
    sample_0)    scope=$'sampling_mode = "connection_sample"\nsample_rate = 0.0'; legs=http ;;
    sample_50)   scope=$'sampling_mode = "connection_sample"\nsample_rate = 0.5'; legs=http ;;
    sample_100)  scope=$'sampling_mode = "connection_sample"\nsample_rate = 1.0'; legs=http ;;
    head)        scope=$'sampling_mode = "head_only"\nhead_only_bytes = '"$HEAD" ;;
    cgroup_filter) scope="cgroup_filter = [\"${SEL#"$CGROUP2"/}\"]" ;;
    *) echo "unknown run $run"; exit 2 ;;
  esac
  if [[ $BACKEND == cgroup_skb ]]; then
    start_servers
    capture=$'[capture]\nbackend = "cgroup_skb"\n\n'
    iface=()
  else
    capture=
    iface=(-i "$IFACE")
  fi
  scope=${scope//\$HTTP_SP/$HTTP_SP}
  scope=${scope//\$TLS_SP/$TLS_SP}
  printf '%s\n\n%s[privacy]\nmode = "full"\n' "$scope" "$capture" >"$D/agent.toml"
  echo "==== $run: $(head -c 200 "$D/agent.toml" | tr '\n' ' ')"
  "$AGENT" -v "${iface[@]}" --config "$D/agent.toml" --log-events --metrics-bind "$METRICS" \
    --json-export "$D/agent.jsonl" --pii-audit-log "$D/audit.jsonl" \
    --capture-raw "$D/raw.pncap" >"$D/agent.log" 2>&1 &
  AP=$!
  for _ in $(seq 120); do curl -sf "http://$METRICS/readyz" >/dev/null && break; sleep 0.5; done
  touch "$OUT/go"
  sleep 1
  PLANT=${run}http SEED=$SEED MODE=client HOST=$HOST_IP nsenter --net=/var/run/netns/$NS \
    python3 -I "$HERE/http_oracle.py" "$HTTP_PORT" "$N" "$D/http/truth.jsonl"
  if [[ $legs == *tls* ]]; then
    env PLANT=${run}tls SSN_AREA=234 TLS=1 HOST=127.0.0.1 SEED=$SEED MODE=client \
      python3 -I "$HERE/http_oracle.py" "$TLS_PORT" "$N" "$D/tls/truth.jsonl"
  fi
  sleep 3
  curl -sf "http://$METRICS/metrics" >"$D/metrics.txt" || echo "metrics scrape failed"
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  [[ $BACKEND == cgroup_skb ]] && stop_servers
  "$AGENT" --privacy-mode full --decode-capture "$D/raw.pncap" >"$D/raw.jsonl"
  "$PY" -I "$HERE/score_sampling.py" "$run" "$D" "$MIN_RECALL" "$HTTP_SP" "$TLS_SP" "$HEAD" \
    "$BACKEND" "$HTTP_PORT" ||
    status=1
done
echo "artifacts: $OUT"
exit $status
