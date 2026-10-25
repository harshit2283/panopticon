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
# Needs: root, docker, a built agent, python3 with pyroute2, confluent-kafka,
# kafka-python, pika, dnspython:
#   pip install pyroute2 confluent-kafka kafka-python pika dnspython
# Images can be overridden: KAFKA_IMAGE (default apache/kafka:3.8.0),
# RABBITMQ_IMAGE (default rabbitmq:3.13), e.g.
# KAFKA_IMAGE=mirror.gcr.io/apache/kafka:3.8.0
# RABBITMQ_IMAGE=mirror.gcr.io/library/rabbitmq:3.13.
# Containers are named ${CONTAINER_PREFIX:-o-}kafka / ...rabbit. AGENT_ARGS adds
# agent flags; @PROTO@ in it becomes the protocol, e.g.
# AGENT_ARGS="--capture-raw /tmp/@PROTO@.pncap" to record a replayable capture.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-500}
SEED=${2:-7}
MIN_RECALL=${3:-0.99}
PROTOS=${4:-kafka amqp dns}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
PY=${PYTHON:-python3}
KAFKA_IMAGE=${KAFKA_IMAGE:-apache/kafka:3.8.0}
RABBITMQ_IMAGE=${RABBITMQ_IMAGE:-rabbitmq:3.13}
P=${CONTAINER_PREFIX:-o-}
OUT=$(mktemp -d)

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  [[ -n ${DP:-} ]] && kill "$DP" 2>/dev/null || true
  docker rm -f "${P}kafka" "${P}rabbit" >/dev/null 2>&1 || true
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f "${P}kafka" "${P}rabbit" >/dev/null 2>&1 || true
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

status=0
for proto in $PROTOS; do
  # shellcheck disable=SC2086  # AGENT_ARGS: extra flags, word-split on purpose
  "$AGENT" -i "$IFACE" --json-export "$OUT/$proto-agent.jsonl" ${AGENT_ARGS:+${AGENT_ARGS//@PROTO@/$proto}} \
    >"$OUT/$proto-agent.log" 2>&1 &
  AP=$!
  sleep 4
  nsenter --net=/var/run/netns/$NS "$PY" "$HERE/mq_oracle.py" \
    "$proto" "$HOST_IP" "$N" "$OUT/$proto-truth.jsonl" "$SEED"
  sleep 3
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  python3 -I "$HERE/score_mq.py" "$OUT/$proto-truth.jsonl" "$OUT/$proto-agent.jsonl" \
    "$MIN_RECALL" || status=1
  echo
done
echo "artifacts: $OUT"
exit $status
