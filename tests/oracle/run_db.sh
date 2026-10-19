#!/usr/bin/env bash
# Score the agent's Redis / PostgreSQL / MySQL capture against ground truth.
#
# Starts the three servers in Docker on the host network, puts a client in a
# netns behind a veth (the agent attaches to the host end, server side), runs
# db_oracle.py per protocol with a fresh agent, and scores with score_db.py.
# Exits non-zero if any protocol's recall is below MIN_RECALL.
#
# Usage: sudo tests/oracle/run_db.sh [ops=500] [seed=7] [min_recall=0.99]
# Needs: root, docker, a built agent, python3 with pyroute2, redis,
# psycopg[binary], pymysql, cryptography (MySQL 8 full auth over plaintext):
#   pip install pyroute2 redis 'psycopg[binary]' pymysql cryptography
# Images can be overridden, e.g. REDIS_IMAGE=mirror.gcr.io/library/redis:7.4.
set -euo pipefail
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
"$PY" "$HERE/netns.py" up

wait_ready() {
  for _ in $(seq 1 120); do
    nsenter --net=/var/run/netns/pclient "$PY" - <<'EOF' 2>/dev/null && return 0
import redis, psycopg, pymysql
redis.Redis(host="10.99.0.1").ping()
psycopg.connect(host="10.99.0.1", user="postgres", password="oracle", dbname="oracle").close()
pymysql.connect(host="10.99.0.1", user="root", password="oracle", database="oracle",
                ssl_disabled=True).close()
EOF
    sleep 2
  done
  echo "servers did not become ready" >&2
  return 1
}
wait_ready

status=0
for proto in redis postgres mysql; do
  "$AGENT" -i pv0 --json-export "$OUT/$proto-agent.jsonl" >"$OUT/$proto-agent.log" 2>&1 &
  AP=$!
  sleep 4
  nsenter --net=/var/run/netns/pclient "$PY" "$HERE/db_oracle.py" \
    "$proto" 10.99.0.1 "$N" "$OUT/$proto-truth.jsonl" "$SEED"
  sleep 3
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  python3 -I "$HERE/score_db.py" "$OUT/$proto-truth.jsonl" "$OUT/$proto-agent.jsonl" \
    "$MIN_RECALL" || status=1
  echo
done
echo "artifacts: $OUT"
exit $status
