#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Overall timeout (default 10 minutes)
TIMEOUT=${E2E_TIMEOUT:-600}

echo "=== Panopticon E2E Integration Tests ==="
echo "Timeout: ${TIMEOUT}s"
echo ""

# Create output directory
mkdir -p output

# Enable BuildKit for better layer reuse when local builds are required.
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

wait_for_service_healthy() {
    local service="$1"
    local timeout="${2:-120}"
    local elapsed=0

    local container_id
    container_id="$(docker compose ps -q "${service}")"
    if [[ -z "${container_id}" ]]; then
        echo "WARN: could not find container id for service '${service}'"
        return 1
    fi

    while [[ "${elapsed}" -lt "${timeout}" ]]; do
        local health
        health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${container_id}" 2>/dev/null || true)"
        if [[ "${health}" == "healthy" ]]; then
            return 0
        fi
        if [[ "${health}" == "unhealthy" ]]; then
            echo "WARN: service '${service}' reported unhealthy"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "WARN: service '${service}' did not become healthy in ${timeout}s"
    return 1
}

wait_for_service_exit() {
    local service="$1"
    local timeout="${2:-120}"
    local elapsed=0

    local container_id
    container_id="$(docker compose ps -q "${service}")"
    if [[ -z "${container_id}" ]]; then
        echo "WARN: could not find container id for service '${service}'" >&2
        return 1
    fi

    while [[ "${elapsed}" -lt "${timeout}" ]]; do
        local state
        state="$(docker inspect --format '{{.State.Status}}' "${container_id}" 2>/dev/null || true)"
        if [[ "${state}" == "exited" ]]; then
            docker inspect --format '{{.State.ExitCode}}' "${container_id}" 2>/dev/null || echo 1
            return 0
        fi
        if [[ "${state}" == "dead" ]]; then
            echo 1
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "WARN: service '${service}' did not exit in ${timeout}s" >&2
    return 1
}

# Clean up from previous runs
docker compose down --remove-orphans 2>/dev/null || true
rm -f output/events.jsonl
rm -f output/kafka_traffic_ran
rm -f output/agent_ready

# Build and start all services
if [[ "${PREBUILT_IMAGES:-0}" == "1" ]]; then
    echo "Using prebuilt traffic-gen/agent images (skipping local compose build)"
else
    echo "Building containers..."
    docker compose build traffic-gen agent
fi

echo "Starting services..."
docker compose up -d nginx mysql postgres redis kafka

echo "Waiting for Kafka healthcheck..."
wait_for_service_healthy kafka 120 || {
    echo "FAIL: Kafka did not become healthy"
    docker compose logs kafka > output/kafka.log 2>&1 || true
    docker compose down --remove-orphans
    exit 1
}

echo "Waiting for MySQL healthcheck..."
wait_for_service_healthy mysql 120 || {
    echo "FAIL: MySQL did not become healthy"
    docker compose logs mysql > output/mysql.log 2>&1 || true
    docker compose down --remove-orphans
    exit 1
}

echo "Waiting for services to initialize (5s)..."
sleep 5

# Start traffic generator and agent together so the agent shares traffic-gen namespaces.
echo "Starting traffic generator and agent..."
docker compose up -d traffic-gen agent
sleep 3

traffic_id="$(docker compose ps -q traffic-gen)"
agent_id="$(docker compose ps -q agent)"
traffic_ns="$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "${traffic_id}")"
agent_ns="$(docker inspect --format '{{.NetworkSettings.SandboxKey}}' "${agent_id}")"
if [[ -n "${traffic_ns}" && -n "${agent_ns}" && "${traffic_ns}" != "${agent_ns}" ]]; then
    echo "WARN: agent/traffic-gen network namespace mismatch detected"
    echo "  traffic-gen ns: ${traffic_ns}"
    echo "  agent ns:      ${agent_ns}"
elif [[ -z "${traffic_ns}" || -z "${agent_ns}" ]]; then
    echo "WARN: could not reliably inspect network namespace (continuing)"
    echo "  traffic-gen ns: ${traffic_ns}"
    echo "  agent ns:      ${agent_ns}"
fi

echo "Waiting for agent attach stabilization (10s)..."
sleep 10
touch output/agent_ready

# Wait for traffic generator completion with timeout.
echo "Waiting for traffic generator to finish..."
traffic_exit_code="$(wait_for_service_exit traffic-gen "${TIMEOUT}")" || {
    echo "FAIL: Traffic generator timed out or failed to exit"
    docker compose logs agent > output/agent.log 2>&1 || true
    docker compose logs traffic-gen > output/traffic-gen.log 2>&1 || true
    docker compose down --remove-orphans
    exit 1
}

if [[ "${traffic_exit_code}" != "0" ]]; then
    echo "FAIL: Traffic generator failed (exit ${traffic_exit_code})"
    docker compose logs agent > output/agent.log 2>&1 || true
    docker compose logs traffic-gen > output/traffic-gen.log 2>&1 || true
    docker compose down --remove-orphans
    exit 1
fi

# Wait for agent to process remaining events
echo "Waiting for agent to flush (5s)..."
sleep 5

# Stop agent gracefully (SIGINT)
docker compose kill -s SIGINT agent 2>/dev/null || true
sleep 2

# Validate results
echo ""
echo "=== Validating Results ==="
EXIT_CODE=0
if [ -f output/events.jsonl ]; then
    python3 validation/validate.py output/events.jsonl || EXIT_CODE=$?
else
    echo "FAIL: No events.jsonl output file found!"
    EXIT_CODE=1
fi

# Collect logs on failure
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "=== Collecting logs ==="
    docker compose logs agent > output/agent.log 2>&1 || true
    docker compose logs traffic-gen > output/traffic-gen.log 2>&1 || true
    echo "Logs saved to output/"
fi

# Cleanup
echo ""
echo "Cleaning up..."
docker compose down --remove-orphans

exit $EXIT_CODE
