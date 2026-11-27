#!/usr/bin/env bash
# Score the agent's Kafka / AMQP (RabbitMQ) / DNS capture against ground
# truth.
#
# Puts a client in a netns behind a veth (the agent attaches to the host end,
# server side), starts Kafka (KRaft, single node) and RabbitMQ in Docker with
# their ports published on the host end's address only, and a small
# authoritative DNS server (mq_oracle.py dns-server) on that address, port 53
# (UDP and TCP). Runs each oracle (mq_oracle.py) with a fresh agent and scores
# it with score_mq.py. Exits non-zero if any protocol's recall is below
# MIN_RECALL or any raw PII value reaches the export.
#
# Usage: sudo tests/oracle/run_messaging.sh [ops=500] [seed=7] [min_recall=0.99] [protos="kafka amqp dns"]
# Needs: root, docker, iproute2, a built agent, python3 3.7+ (the
# first new enough, or set PYTHON) with confluent-kafka,
# kafka-python, pika, dnspython:
#   pip install confluent-kafka kafka-python pika dnspython
# Images can be overridden: KAFKA_IMAGE (default apache/kafka:3.8.0),
# RABBITMQ_IMAGE (default rabbitmq:3.13), e.g.
# KAFKA_IMAGE=mirror.gcr.io/apache/kafka:3.8.0
# RABBITMQ_IMAGE=mirror.gcr.io/library/rabbitmq:3.13.
# Containers are named ${CONTAINER_PREFIX:-o-}kafka / ...rabbit. AGENT_ARGS adds
# agent flags; @PROTO@ in it becomes the protocol, e.g.
# AGENT_ARGS="--privacy-mode full --capture-raw /tmp/@PROTO@.pncap" to record a replayable capture.
#
# Each leg's agent gets its own config file, $OUT/<proto>-agent.toml: a copy
# of the --config file in AGENT_ARGS (or $PANOPTICON_CONFIG), if any, with
# the leg's settings below (no --config at all when that leaves it empty).
# score_mq.py reads the Kafka body cap (max_body_bytes) from it, so Fetch
# records proven past that cap (see its docstring) are reported as "past
# body cap" rather than lost, but only when the leg's saved /metrics shows
# no loss (ring drops, reorder gaps, truncated captures, parser errors,
# channel / export / rate-limit drops all zero: score_mq.py --metrics);
# otherwise, or where the place past the cap is not proven, a missing
# record counts as lost.
# Every leg runs at the config as given, on every kernel: AMQP and Kafka
# connections capture whole packets by default (raise_packet_cap,
# USER-GUIDE.md §4.2), whatever max_packet_bytes is.
#
# Every leg's agent serves /metrics (--metrics-bind from AGENT_ARGS, else
# 127.0.0.1:$METRICS_PORT, default 19190); it is saved just before the agent
# stops ($OUT/<proto>-metrics.txt) and its loss counters, then its
# raise_packet_cap counters, are printed after the leg's score and again in
# the summary. A leg whose metrics cannot be read fails.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-500}
SEED=${2:-7}
MIN_RECALL=${3:-0.99}
PROTOS=${4:-kafka amqp dns}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
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
# The Kafka scorer's past-body-cap proof, on its fixtures, before any leg:
# a scorer that fails them would score every leg wrongly.
"$PY" -I "$HERE/test_score_mq.py" || { echo "score_mq.py self-test FAILED" >&2; exit 1; }
KAFKA_IMAGE=${KAFKA_IMAGE:-apache/kafka:3.8.0}
RABBITMQ_IMAGE=${RABBITMQ_IMAGE:-rabbitmq:3.13}
P=${CONTAINER_PREFIX:-o-}
OUT=$(mktemp -d)

# Split a --config out of AGENT_ARGS: each leg passes its own config file.
BASE_CONFIG=${PANOPTICON_CONFIG:-}
EXTRA_ARGS=()
# shellcheck disable=SC2206  # AGENT_ARGS: extra flags, word-split on purpose
ARGV=(${AGENT_ARGS:-})
for ((i = 0; i < ${#ARGV[@]}; i++)); do
  case ${ARGV[i]} in
    --config) BASE_CONFIG=${ARGV[i + 1]:-}; i=$((i + 1)) ;;
    --config=*) BASE_CONFIG=${ARGV[i]#--config=} ;;
    --metrics-bind) MBIND=${ARGV[i + 1]:-}; i=$((i + 1)) ;;
    --metrics-bind=*) MBIND=${ARGV[i]#--metrics-bind=} ;;
    *) EXTRA_ARGS+=("${ARGV[i]}") ;;
  esac
done
MBIND=${MBIND:-127.0.0.1:${METRICS_PORT:-19190}}
[[ -z $BASE_CONFIG || -r $BASE_CONFIG ]] || { echo "cannot read agent config $BASE_CONFIG" >&2; exit 1; }
# leg_config PROTO: write the leg's agent config (a copy of the base
# config, if any), print its path.
leg_config() {
  local f=$OUT/$1-agent.toml
  : >"$f"
  [[ -n $BASE_CONFIG ]] && cat "$BASE_CONFIG" >>"$f"
  echo "$f"
}

# One name per call: podman's docker removes neither name when one is
# missing, which left the broker of the last run behind.
rm_brokers() {
  local c
  for c in "${P}kafka" "${P}rabbit"; do
    docker rm -f "$c" >/dev/null 2>&1 || true
  done
}

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
  [[ -n ${DP:-} ]] && kill "$DP" 2>/dev/null || true
  rm_brokers
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm_brokers
"$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true  # leftovers from an aborted run
"$PY" "$HERE/netns.py" up  # first: the published ports bind to $HOST_IP

want() { [[ " $PROTOS " == *" $1 "* ]]; }
if want kafka; then
  docker run -d --name "${P}kafka" -p "$HOST_IP:9092:9092" \
    -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
    -e KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,CONTROLLER://localhost:9093 \
    -e KAFKA_ADVERTISED_LISTENERS="PLAINTEXT://$HOST_IP:9092" \
    -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
    -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
    -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
    -e KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
    -e KAFKA_AUTO_CREATE_TOPICS_ENABLE=false \
    "$KAFKA_IMAGE" >/dev/null
fi
if want amqp; then
  docker run -d --name "${P}rabbit" -p "$HOST_IP:5672:5672" \
    -e RABBITMQ_DEFAULT_USER=oracle -e RABBITMQ_DEFAULT_PASS=oracle \
    "$RABBITMQ_IMAGE" >/dev/null
fi
if want dns; then
  "$PY" "$HERE/mq_oracle.py" dns-server "$HOST_IP" >"$OUT/dns-server.log" 2>&1 &
  DP=$!
fi

wait_ready() {
  for _ in $(seq 1 90); do
    HOST_IP=$HOST_IP PROTOS="$PROTOS" nsenter --net=/var/run/netns/$NS "$PY" - <<'EOF' 2>/dev/null && return 0
import os
host, protos = os.environ["HOST_IP"], os.environ["PROTOS"].split()
if "kafka" in protos:
    from confluent_kafka.admin import AdminClient
    md = AdminClient({"bootstrap.servers": f"{host}:9092"}).list_topics(timeout=3)
    assert md.brokers
if "amqp" in protos:
    import pika
    pika.BlockingConnection(pika.ConnectionParameters(
        host=host, credentials=pika.PlainCredentials("oracle", "oracle"))).close()
if "dns" in protos:
    import dns.message, dns.query
    dns.query.udp(dns.message.make_query("a-tok_0_.oracle.test", "A"), host, timeout=1)
EOF
    sleep 2
  done
  echo "servers did not become ready" >&2
  return 1
}
wait_ready

# save_metrics PROTO: one /metrics request to the running agent, saved to
# $OUT/PROTO-metrics.txt; prints the loss counters (summed over labels).
save_metrics() {
  "$PY" - "$MBIND" "$OUT/$1-metrics.txt" "$1" <<'EOF'
import re, sys, urllib.request
bind, out, proto = sys.argv[1:4]
try:
    text = urllib.request.urlopen(f"http://{bind}/metrics", timeout=10).read().decode()
except Exception as e:
    print(f"  {proto} counters: METRICS MISSING ({e!r})")
    sys.exit(1)
open(out, "w").write(text)
names = ["capture_truncated_total", "kernel_ringbuf_drops_total", "events_dropped_total",
         "tcp_reorder_gaps_total", "tcp_segments_ignored_total", "drops_parser_error_total",
         "drops_channel_full_total", "drops_export_full_total", "drops_rate_limit_total"]
total = dict.fromkeys(names, 0)
for line in text.splitlines():
    m = re.match(r"panopticon_(\w+?)(?:\{.*\})? (\S+)$", line)
    if m and m.group(1) in total:
        total[m.group(1)] += float(m.group(2))
cap = ["conn_cap_raised_connections_total", "conn_cap_raised_packets_total",
       "conn_cap_cut_packets_total", "conn_cap_truncated_before_raise_total",
       "conn_cap_write_failures_total"]
raised = dict.fromkeys(cap, 0)
for line in text.splitlines():
    m = re.match(r"panopticon_(\w+?)(?:\{.*\})? (\S+)$", line)
    if m and m.group(1) in raised:
        raised[m.group(1)] += float(m.group(2))
print(f"  {proto} counters: " + " ".join(f"{k[:-6]}={v:g}" for k, v in total.items())
      + " | " + " ".join(f"{k[:-6]}={v:g}" for k, v in raised.items()))
EOF
}

status=0
summary=()
for proto in $PROTOS; do
  cfg=$(leg_config "$proto")
  cfg_args=()
  [[ -s $cfg ]] && cfg_args=(--config "$cfg")  # nothing to set: no --config, as before
  "$AGENT" --json-export "$OUT/$proto-agent.jsonl" ${cfg_args[@]+"${cfg_args[@]}"} \
    --metrics-bind "$MBIND" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]//@PROTO@/$proto}"} \
    >"$OUT/$proto-agent.log" 2>&1 &
  AP=$!
  sleep 4
  nsenter --net=/var/run/netns/$NS "$PY" "$HERE/mq_oracle.py" \
    "$proto" "$HOST_IP" "$N" "$OUT/$proto-truth.jsonl" "$SEED"
  sleep 3
  counters=$(save_metrics "$proto") || status=1
  stop_bounded "$AP" || status=1; AP=
  leg=0
  "$PY" -I "$HERE/score_mq.py" "$OUT/$proto-truth.jsonl" "$OUT/$proto-agent.jsonl" \
    "$MIN_RECALL" --agent-config "$cfg" --metrics "$OUT/$proto-metrics.txt" || leg=1
  echo "$counters"
  [[ $leg == 0 ]] || status=1
  summary+=("$proto $([[ $leg == 0 ]] && echo pass || echo FAIL):${counters#*counters:}")
  echo
done
echo "summary (loss counters per leg, from each agent's /metrics):"
printf '  %s\n' "${summary[@]}"
echo "artifacts: $OUT"
exit $status
