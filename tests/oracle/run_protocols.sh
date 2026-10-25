#!/usr/bin/env bash
# Score the agent's Redis / PostgreSQL / MySQL / gRPC capture against ground
# truth.
#
# Starts the three database servers in Docker on the host network and a gRPC
# server (grpc_oracle.py) on a non-standard port, puts a client in a netns
# behind a veth (the agent attaches to the host end, server side), runs each
# oracle with a fresh agent, and scores with score_db.py / score_h2.py.
# Exits non-zero if any protocol's recall is below MIN_RECALL.
#
# Usage: sudo tests/oracle/run_protocols.sh [ops=500] [seed=7] [min_recall=0.99]
# Needs: root, docker, a built agent, python3 with pyroute2, redis,
# psycopg[binary], pymysql, cryptography (MySQL 8 full auth over plaintext),
# grpcio:
#   pip install pyroute2 redis 'psycopg[binary]' pymysql cryptography grpcio \
#     mysql-connector-python
# Images can be overridden, e.g. REDIS_IMAGE=mirror.gcr.io/library/redis:7.4.
set -euo pipefail
# Topology (see netns.py): override ORACLE_NS / ORACLE_IF / ORACLE_NET to
# run several oracles at once.
NS=${ORACLE_NS:-pclient}
IFACE=${ORACLE_IF:-pv0}
HOST_IP=10.99.${ORACLE_NET:-0}.1
N=${1:-500}
SEED=${2:-7}
MIN_RECALL=${3:-0.99}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
PY=${PYTHON:-python3}
REDIS_IMAGE=${REDIS_IMAGE:-redis:7.4}
POSTGRES_IMAGE=${POSTGRES_IMAGE:-postgres:16}
MYSQL_IMAGE=${MYSQL_IMAGE:-mysql:8.4}
OUT=$(mktemp -d)

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  [[ -n ${GP:-} ]] && kill "$GP" 2>/dev/null || true
  docker rm -f o-redis o-pg o-mysql >/dev/null 2>&1 || true
  "$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker rm -f o-redis o-pg o-mysql >/dev/null 2>&1 || true
docker run -d --name o-redis --network host "$REDIS_IMAGE" --protected-mode no >/dev/null
docker run -d --name o-pg --network host -e POSTGRES_PASSWORD=oracle -e POSTGRES_DB=oracle \
  "$POSTGRES_IMAGE" >/dev/null
docker run -d --name o-mysql --network host -e MYSQL_ROOT_PASSWORD=oracle \
  -e MYSQL_DATABASE=oracle "$MYSQL_IMAGE" >/dev/null
"$PY" "$HERE/netns.py" down >/dev/null 2>&1 || true  # leftovers from an aborted run
"$PY" "$HERE/netns.py" up

wait_ready() {
  for _ in $(seq 1 120); do
    HOST_IP=$HOST_IP nsenter --net=/var/run/netns/$NS "$PY" - <<'EOF' 2>/dev/null && return 0
import os, redis, psycopg, pymysql
host = os.environ["HOST_IP"]
redis.Redis(host=host).ping()
psycopg.connect(host=host, user="postgres", password="oracle", dbname="oracle").close()
pymysql.connect(host=host, user="root", password="oracle", database="oracle",
                ssl_disabled=True).close()
EOF
    sleep 2
  done
  echo "servers did not become ready" >&2
  return 1
}
wait_ready

status=0
# mysql-prepared: MySQL through prepared statements (binary protocol).
for run in redis postgres mysql mysql-prepared; do
  proto=${run%-prepared}
  mode=; [[ $run == *-prepared ]] && mode=prepared
  echo "== $run"
  "$AGENT" -i "$IFACE" --json-export "$OUT/$run-agent.jsonl" >"$OUT/$run-agent.log" 2>&1 &
  AP=$!
  sleep 4
  MYSQL_MODE=$mode nsenter --net=/var/run/netns/$NS "$PY" "$HERE/db_oracle.py" \
    "$proto" "$HOST_IP" "$N" "$OUT/$run-truth.jsonl" "$SEED"
  sleep 3
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  python3 -I "$HERE/score_db.py" "$OUT/$run-truth.jsonl" "$OUT/$run-agent.jsonl" \
    "$MIN_RECALL" || status=1
  echo
done
# gRPC on a non-standard port: identified by the HTTP/2 preface, not the port.
"$PY" "$HERE/grpc_oracle.py" server "$HOST_IP:9443" >"$OUT/grpc-server.log" 2>&1 &
GP=$!
"$AGENT" -i "$IFACE" --json-export "$OUT/grpc-agent.jsonl" >"$OUT/grpc-agent.log" 2>&1 &
AP=$!
sleep 4
nsenter --net=/var/run/netns/$NS "$PY" "$HERE/grpc_oracle.py" \
  client "$HOST_IP:9443" "$N" "$OUT/grpc-truth.jsonl" "$SEED"
sleep 3
kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
python3 -I "$HERE/score_h2.py" "$OUT/grpc-truth.jsonl" "$OUT/grpc-agent.jsonl" \
  "$MIN_RECALL" || status=1
echo
echo "artifacts: $OUT"
exit $status
