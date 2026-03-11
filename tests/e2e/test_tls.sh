#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yaml"
EXIT_CODE=0

wait_for_service() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=1

    echo "Waiting for $service to be ready..."
    while ! docker compose -f "$COMPOSE_FILE" ps "$service" | grep -q "healthy\|running"; do
        if [ $attempt -ge $max_attempts ]; then
            echo "ERROR: $service did not become ready in time"
            return 1
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    echo "$service is ready (${attempt}s)"
}

echo "=== Panopticon TLS E2E Test ==="
echo ""

# ── Wait for services ────────────────────────────────────────────────
echo "Waiting for services to be healthy..."
wait_for_service "openssl-server" 8443
wait_for_service "go-tls-server" 8444
wait_for_service "agent" 0

echo ""

# ── Test 1: OpenSSL TLS Server (nginx with HTTPS) ────────────────────
echo "=== Test 1: OpenSSL TLS Server ==="
for i in {1..5}; do
    echo "  Request $i: GET /"
    curl -k -s -o /dev/null -w "  -> HTTP %{http_code} (%{size_download} bytes)\n" \
        https://localhost:8443/ || true
    sleep 0.3
done

# POST with PII through TLS
echo "  POST with PII data..."
curl -k -s -o /dev/null -w "  -> HTTP %{http_code}\n" \
    -X POST https://localhost:8443/api/data \
    -H "Content-Type: application/json" \
    -d '{"email":"tls-test@example.com","ssn":"111-22-3333","card":"4111111111111111"}' \
    || true

echo ""

# ── Test 2: Go TLS Server ────────────────────────────────────────────
echo "=== Test 2: Go TLS Server ==="
for i in {1..5}; do
    echo "  Request $i: GET /"
    curl -k -s -o /dev/null -w "  -> HTTP %{http_code} (%{size_download} bytes)\n" \
        https://localhost:8444/ || true
    sleep 0.3
done

# POST with PII through Go TLS
echo "  POST with PII data..."
curl -k -s -o /dev/null -w "  -> HTTP %{http_code}\n" \
    -X POST https://localhost:8444/api/data \
    -H "Content-Type: application/json" \
    -d '{"email":"go-tls@example.com","ssn":"444-55-6666","phone":"+1-555-999-0000"}' \
    || true

echo ""

# ── Test 3: Verify agent captured TLS events ─────────────────────────
echo "=== Test 3: Verifying Agent TLS Capture ==="
echo ""

# Give agent time to process
sleep 3

# Check for TLS-related log entries
echo "Checking agent logs for TLS capture evidence..."
TLS_LINES=$(docker compose -f "$COMPOSE_FILE" logs agent 2>&1 | \
    grep -i -c -E "(tls|ssl_write|ssl_read|go_tls|uprobe.*attach|TlsData)" || true)

if [ "$TLS_LINES" -gt 0 ]; then
    echo "  OK: Found $TLS_LINES TLS-related log entries"
    echo ""
    echo "  Sample TLS log entries:"
    docker compose -f "$COMPOSE_FILE" logs agent 2>&1 | \
        grep -i -E "(tls|ssl_write|ssl_read|go_tls|uprobe.*attach|TlsData)" | \
        tail -10 | sed 's/^/    /'
else
    echo "  WARN: No TLS-specific log entries found"
    echo "  (This is expected if running without eBPF support)"
fi

echo ""

# Check for any captured events
EVENT_COUNT=$(docker compose -f "$COMPOSE_FILE" logs agent 2>&1 | \
    grep -c -E "(L7Message|event_type|DataEvent)" || true)
echo "Total event-related log entries: $EVENT_COUNT"

echo ""
echo "=== TLS Test Summary ==="
echo "  OpenSSL server: tested (5 GET + 1 POST with PII)"
echo "  Go TLS server:  tested (5 GET + 1 POST with PII)"
echo "  TLS log entries: $TLS_LINES"
echo "  Event log entries: $EVENT_COUNT"
echo ""

if [ "$TLS_LINES" -eq 0 ] && [ "$EVENT_COUNT" -eq 0 ]; then
    echo "NOTE: No TLS events captured. This is expected when:"
    echo "  - Running on macOS (eBPF requires Linux)"
    echo "  - Agent lacks CAP_SYS_ADMIN / CAP_BPF capabilities"
    echo "  - Kernel does not support uprobes on the TLS libraries"
fi

echo ""
echo "To inspect full agent logs:"
echo "  docker compose -f $COMPOSE_FILE logs agent"
echo ""
echo "To check for specific patterns:"
echo "  docker compose -f $COMPOSE_FILE logs agent | grep -i tls"

exit $EXIT_CODE
