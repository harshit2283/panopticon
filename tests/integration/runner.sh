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

# The agent runs as root and creates its JSON export owner-only (0600), a
# privacy control. Hand the file to the user running this script (the
# validator and the CI artifact upload read it as that user) by chowning it
# from a throwaway container on the agent image; the mode stays.
release_export() {
    local cid image
    [[ -e output/events.jsonl && ! -r output/events.jsonl ]] || return 0
    cid="$(docker compose ps -aq agent 2>/dev/null || true)"
    [[ -n "${cid}" ]] || return 0
    image="$(docker inspect --format '{{.Image}}' "${cid}" 2>/dev/null || true)"
    [[ -n "${image}" ]] || return 0
    docker run --rm --network none --entrypoint chown \
        -v "${SCRIPT_DIR}/output:/output" "${image}" \
        "$(id -u):$(id -g)" /output/events.jsonl || true
}

save_logs() {
    docker compose logs agent > output/agent.log 2>&1 || true
    docker compose logs traffic-gen > output/traffic-gen.log 2>&1 || true
}

# Every exit path: release the export, then tear the stack down.
cleanup() {
    local exit_code=$?
    release_export
    docker compose down --remove-orphans || true
    exit "${exit_code}"
}

# Clean up from previous runs
docker compose down --remove-orphans 2>/dev/null || true
rm -f output/events.jsonl
rm -f output/kafka_traffic_ran
rm -f output/agent_ready

trap cleanup EXIT

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
    exit 1
}

echo "Waiting for MySQL healthcheck..."
wait_for_service_healthy mysql 120 || {
    echo "FAIL: MySQL did not become healthy"
    docker compose logs mysql > output/mysql.log 2>&1 || true
    exit 1
}

echo "Waiting for services to initialize (5s)..."
sleep 5

# The agent captures on the host cgroup v2 root, so it sees every
# container's sockets whatever namespaces it runs in. The traffic generator
# holds its traffic until output/agent_ready exists.
echo "Starting traffic generator and agent..."
docker compose up -d traffic-gen agent

echo "Waiting for the agent to attach..."
attached=0
for _ in $(seq 1 90); do
    agent_logs="$(docker compose logs --no-color agent 2>/dev/null || true)"
    if grep -Fq "JSON export enabled" <<<"${agent_logs}" \
        && grep -Fq "capture scope armed" <<<"${agent_logs}"; then
        attached=1
        break
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "$(docker compose ps -aq agent)" 2>/dev/null)" != "true" ]]; then
        break
    fi
    sleep 1
done
if [[ "${attached}" != "1" ]]; then
    echo "FAIL: agent did not attach"
    save_logs
    docker compose logs --tail=100 agent || true
    exit 1
fi
touch output/agent_ready

# Wait for traffic generator completion with timeout.
echo "Waiting for traffic generator to finish..."
traffic_exit_code="$(wait_for_service_exit traffic-gen "${TIMEOUT}")" || {
    echo "FAIL: Traffic generator timed out or failed to exit"
    save_logs
    docker compose logs --tail=100 traffic-gen || true
    exit 1
}

if [[ "${traffic_exit_code}" != "0" ]]; then
    echo "FAIL: Traffic generator failed (exit ${traffic_exit_code})"
    save_logs
    docker compose logs --tail=100 traffic-gen || true
    exit 1
fi

# Wait for agent to process remaining events
echo "Waiting for agent to flush (5s)..."
sleep 5

# Stop agent gracefully (SIGINT) and wait for it to exit, so the export is final.
# The agent is the container's PID 1 and exits 0 on SIGINT; anything else (a
# panic or error at shutdown, or no exit at all) fails the run.
docker compose kill -s SIGINT agent 2>/dev/null || true
agent_exit_code="$(wait_for_service_exit agent 30)" || agent_exit_code="none (no exit within 30s)"
release_export

# Validate results
echo ""
echo "=== Validating Results ==="
EXIT_CODE=0
if [[ "${agent_exit_code}" != "0" ]]; then
    echo "FAIL: agent exit status after SIGINT: ${agent_exit_code}"
    EXIT_CODE=1
fi
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
    save_logs
    echo "Logs saved to output/"
fi

exit $EXIT_CODE
