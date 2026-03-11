#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/tests/e2e/docker-compose.yaml"
OUTPUT_DIR="${REPO_ROOT}/tests/e2e/output"
JSON_OUT="${OUTPUT_DIR}/events.jsonl"
HOST_DEBUG_OUT="${OUTPUT_DIR}/host-debug.txt"

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "No docker compose command found (tried 'docker compose' then 'docker-compose')."
  exit 1
fi

compose() {
  "${COMPOSE_CMD[@]}" -f "${COMPOSE_FILE}" "$@"
}

# Enable BuildKit when local image build is required.
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

wait_for_url() {
  local url="$1"
  local attempts="${2:-60}"
  for _ in $(seq 1 "${attempts}"); do
    if curl -kfsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_for_log_pattern() {
  local service="$1"
  local pattern="$2"
  local attempts="${3:-60}"
  local logs

  for _ in $(seq 1 "${attempts}"); do
    logs="$(compose logs --no-color "${service}" 2>/dev/null || true)"
    if [[ -n "${logs}" ]] && grep -Fq -- "${pattern}" <<<"${logs}"; then
      return 0
    fi
    sleep 1
  done

  return 1
}

wait_for_service_exit() {
  local service="$1"
  local attempts="${2:-30}"
  local cid
  local running
  local exit_code

  cid="$(compose ps -q "${service}" 2>/dev/null || true)"
  if [[ -z "${cid}" ]]; then
    return 125
  fi

  for _ in $(seq 1 "${attempts}"); do
    running="$(docker inspect -f '{{.State.Running}}' "${cid}" 2>/dev/null || echo inspect_error)"
    if [[ "${running}" != "true" ]]; then
      exit_code="$(docker inspect -f '{{.State.ExitCode}}' "${cid}" 2>/dev/null || echo 125)"
      if [[ "${exit_code}" =~ ^[0-9]+$ ]]; then
        return "${exit_code}"
      fi
      return 125
    fi
    sleep 1
  done

  return 124
}

wait_for_file_quiescence() {
  local path="$1"
  local attempts="${2:-30}"
  local last_size="-1"
  local stable_reads=0

  for _ in $(seq 1 "${attempts}"); do
    if [[ -s "${path}" ]]; then
      local size
      size="$(stat -c '%s' "${path}")"
      if [[ "${size}" == "${last_size}" ]]; then
        stable_reads=$((stable_reads + 1))
        if [[ ${stable_reads} -ge 2 ]]; then
          return 0
        fi
      else
        stable_reads=0
        last_size="${size}"
      fi
    fi
    sleep 1
  done

  return 1
}

record_host_debug() {
  {
    echo "=== uname -a ==="
    uname -a || true
    echo
    echo "=== ip -br link ==="
    ip -br link || true
    echo
    echo "=== ip -br addr ==="
    ip -br addr || true
    echo
    echo "=== ss -ltn ==="
    ss -ltn || true
  } > "${HOST_DEBUG_OUT}" 2>&1
}

print_agent_attach_summary() {
  echo "Agent attach summary:"
  compose logs --no-color agent 2>/dev/null \
    | grep -E "Kernel capabilities detected|TC classifier attached|Failed to attach TC classifier|eBPF programs loaded and attached|Initial TLS scan complete" \
    || true
}

print_agent_protocol_summary() {
  echo "Recent agent protocol activity:"
  compose logs --no-color agent 2>/dev/null \
    | grep -E "Protocol detected|L7Message|payload_len=" \
    | tail -n 60 \
    || true
}

dump_debug() {
  compose ps || true
  mkdir -p "${OUTPUT_DIR}"
  record_host_debug
  cat "${HOST_DEBUG_OUT}" || true
  compose logs --no-color agent > "${OUTPUT_DIR}/agent.log" 2>&1 || true
  compose logs --no-color openssl-server > "${OUTPUT_DIR}/openssl-server.log" 2>&1 || true
  compose logs --no-color go-tls-server > "${OUTPUT_DIR}/go-tls-server.log" 2>&1 || true
  compose logs --no-color || true
}

cleanup() {
  local exit_code=$?
  if [[ ${exit_code} -ne 0 ]]; then
    dump_debug
  fi
  compose down --volumes --remove-orphans || true
  exit "${exit_code}"
}

trap cleanup EXIT

mkdir -p "${OUTPUT_DIR}"
rm -f "${JSON_OUT}" \
  "${HOST_DEBUG_OUT}" \
  "${OUTPUT_DIR}/agent.log" \
  "${OUTPUT_DIR}/openssl-server.log" \
  "${OUTPUT_DIR}/go-tls-server.log"

echo "Starting E2E test environment..."
if [[ "${PREBUILT_IMAGES:-0}" == "1" ]]; then
  # Keep the prebuilt fast path for agent while ensuring local helper images exist.
  compose build openssl-server go-tls-server
  compose up -d --no-build
else
  compose up -d
fi

echo "Waiting for services..."
wait_for_url "http://localhost:8080/" 90
wait_for_url "https://localhost:8443/health" 90
wait_for_url "https://localhost:8444/" 90

echo "Waiting for agent readiness..."
wait_for_log_pattern agent "Initial TLS scan complete" 90 || {
  echo "Agent never completed initial TLS scan"
  compose logs --tail=200 agent || true
  exit 1
}
wait_for_log_pattern agent "DATA_EVENTS RingBuf consumer started" 90 || {
  echo "Agent never started the DATA_EVENTS consumer"
  compose logs --tail=200 agent || true
  exit 1
}
wait_for_log_pattern agent "JSON export enabled" 90 || {
  echo "Agent never enabled JSON export"
  compose logs --tail=200 agent || true
  exit 1
}
print_agent_attach_summary

echo "Running traffic generators..."

echo "Generating HTTP traffic..."
curl -s http://localhost:8080/ > /dev/null
curl -s http://localhost:8080/health > /dev/null
curl -s http://localhost:8080/api > /dev/null

echo "Generating TLS traffic..."
for _ in $(seq 1 3); do
  curl -kfsS https://localhost:8443/health > /dev/null
  curl -kfsS https://localhost:8444/ > /dev/null
done

echo "Generating PostgreSQL traffic..."
PGPASSWORD=test psql -h localhost -U test -d testdb -c "SELECT 1;" || echo "psql not installed, skipping"

echo "Generating Redis traffic..."
redis-cli -h localhost PING || echo "redis-cli not installed, skipping"

sleep 3
print_agent_protocol_summary

echo "Stopping agent to flush final JSON..."
compose kill -s SIGINT agent >/dev/null 2>&1 || true
set +e
wait_for_service_exit agent 30
agent_exit=$?
set -e
if [[ ${agent_exit} -ne 0 ]]; then
  case "${agent_exit}" in
    124)
      echo "Agent did not stop after SIGINT"
      ;;
    125)
      echo "Agent container missing while waiting for shutdown"
      ;;
    *)
      echo "Agent exited with unexpected status ${agent_exit}"
      ;;
  esac
  print_agent_protocol_summary
  compose logs --tail=200 agent || true
  exit 1
fi

echo "Waiting for JSON export artifact..."
wait_for_file_quiescence "${JSON_OUT}" 30 || {
  echo "Expected JSON export artifact at ${JSON_OUT}"
  print_agent_protocol_summary
  compose logs --tail=200 agent || true
  exit 1
}

echo "Validating exported TLS artifacts..."
python3 - "${JSON_OUT}" <<'PY'
import json
import sys

path = sys.argv[1]
events = []
with open(path, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            events.append(json.loads(line))

if not events:
    print("No events exported", file=sys.stderr)
    sys.exit(1)

http_events = [e for e in events if str(e.get("protocol", "")).lower() == "http1"]
if not http_events:
    print("No HTTP/1.1 events detected in JSON export", file=sys.stderr)
    sys.exit(1)

tls_counts = {}
for event in events:
    tls_lib = event.get("tls_library")
    if tls_lib:
        tls_counts[str(tls_lib)] = tls_counts.get(str(tls_lib), 0) + 1

for required in ("open_ssl", "go_tls"):
    if tls_counts.get(required, 0) == 0:
        print(f"Missing expected TLS capture path: {required}", file=sys.stderr)
        sys.exit(1)

print(f"Exported {len(events)} events")
print(f"HTTP/1.1 events: {len(http_events)}")
print(f"TLS capture counts: {tls_counts}")
PY

echo "E2E tests complete!"
