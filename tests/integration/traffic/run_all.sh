#!/usr/bin/env bash
set -euo pipefail

echo "=== Panopticon Integration Test Traffic Generator ==="
echo "Waiting for services to be ready..."

# ── Health check helpers ─────────────────────────────────────────────
wait_for_tcp() {
    local host="$1"
    local port="$2"
    local service="$3"
    local max_attempts=60
    local attempt=1

    echo "[wait] Checking $service at $host:$port..."
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $attempt -ge $max_attempts ]; then
            echo "[wait] ERROR: $service at $host:$port not ready after ${max_attempts}s"
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "[wait] $service is ready (took ${attempt}s)"
}

wait_for_http() {
    local url="$1"
    local service="$2"
    local max_attempts=60
    local attempt=1

    echo "[wait] Checking $service at $url..."
    while ! curl -sf -o /dev/null "$url" 2>/dev/null; do
        if [ $attempt -ge $max_attempts ]; then
            echo "[wait] ERROR: $service at $url not ready after ${max_attempts}s"
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "[wait] $service is ready (took ${attempt}s)"
}

wait_for_mysql_query() {
    local max_attempts=60
    local attempt=1

    echo "[wait] Checking MySQL query readiness..."
    while ! python3 - <<'PY' >/dev/null 2>&1
import pymysql
conn = pymysql.connect(
    host="mysql",
    port=3306,
    user="test",
    password="testpass",
    database="testdb",
    connect_timeout=3,
    ssl_disabled=True,
)
cur = conn.cursor()
cur.execute("SELECT 1")
cur.fetchone()
cur.close()
conn.close()
PY
    do
        if [ $attempt -ge $max_attempts ]; then
            echo "[wait] ERROR: MySQL query readiness failed after ${max_attempts}s"
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "[wait] MySQL query readiness OK (took ${attempt}s)"
}

wait_for_agent_ready_marker() {
    local max_attempts=120
    local attempt=1

    echo "[wait] Waiting for agent readiness marker..."
    while [ ! -f /output/agent_ready ]; do
        if [ $attempt -ge $max_attempts ]; then
            echo "[wait] ERROR: agent readiness marker not present after ${max_attempts}s"
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "[wait] Agent readiness marker found (took ${attempt}s)"
}

# ── Wait for all services ────────────────────────────────────────────
wait_for_http "http://nginx/api/health" "nginx"
wait_for_tcp "mysql" 3306 "MySQL"
wait_for_mysql_query
wait_for_tcp "postgres" 5432 "PostgreSQL"
wait_for_tcp "redis" 6379 "Redis"
wait_for_tcp "kafka" 9092 "Kafka"
wait_for_agent_ready_marker

echo ""
echo "All services are ready. Starting traffic generation..."
echo ""

# ── Run traffic generators sequentially ──────────────────────────────
echo "--- HTTP Traffic ---"
python3 /traffic/http_traffic.py
echo ""

echo "--- Database Traffic ---"
python3 /traffic/db_traffic.py
echo ""

echo "--- Redis Traffic ---"
python3 /traffic/redis_traffic.py
echo ""

echo "--- Kafka Traffic ---"
rm -f /output/kafka_traffic_ran
python3 /traffic/kafka_traffic.py --wait-ready-only
python3 /traffic/kafka_traffic.py
touch /output/kafka_traffic_ran
echo ""

echo "=== All traffic generated successfully ==="

# Keep container alive briefly so agent can finish processing
sleep 3
echo "Traffic generator exiting."
