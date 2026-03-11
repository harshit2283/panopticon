#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${SCRIPT_DIR}/output-host"
TMP_DIR=""

HTTP_PORT="${HOST_E2E_HTTP_PORT:-18080}"
TLS_PORT="${HOST_E2E_TLS_PORT:-18443}"
JSON_OUT="${OUT_DIR}/events.host.jsonl"
AGENT_LOG="${OUT_DIR}/agent.host.log"
HTTP_LOG="${OUT_DIR}/http-server.log"
TLS_LOG="${OUT_DIR}/openssl-server.log"
AGENT_PID_FILE=""
HTTP_PID=""
TLS_PID=""
AGENT_SUDO_PID=""

# Ensure Rust cargo-installed tools are resolvable across environments (local, CI, Sprite).
export PATH="$HOME/.cargo/bin:/.sprite/languages/rust/cargo/bin:${PATH}"

log() {
    printf '[host-e2e] %s\n' "$*"
}

fail() {
    printf '[host-e2e] ERROR: %s\n' "$*" >&2
    exit 1
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

require_capability() {
    local cap="$1"
    if ! sudo -n capsh --print 2>/dev/null | grep -Eq "Current: .*\\b${cap}\\b"; then
        fail "Missing required Linux capability: ${cap} (run with elevated privileges that include it)"
    fi
}

kernel_major_minor() {
    local release major minor
    release="$(uname -r)"
    if [[ "${release}" =~ ^([0-9]+)\.([0-9]+) ]]; then
        major="${BASH_REMATCH[1]}"
        minor="${BASH_REMATCH[2]}"
        printf '%s %s\n' "${major}" "${minor}"
        return 0
    fi
    return 1
}

kernel_has_cap_bpf_support() {
    local major minor
    read -r major minor < <(kernel_major_minor) || return 1
    if (( major > 5 )); then
        return 0
    fi
    if (( major == 5 && minor >= 8 )); then
        return 0
    fi
    return 1
}

require_bpf_or_sys_admin_for_legacy_kernel() {
    if sudo -n capsh --print 2>/dev/null | grep -Eq "Current: .*\\bcap_bpf\\b"; then
        return 0
    fi

    if kernel_has_cap_bpf_support; then
        fail "Missing required Linux capability: cap_bpf (kernel supports CAP_BPF)"
    fi

    if ! sudo -n capsh --print 2>/dev/null | grep -Eq "Current: .*\\bcap_sys_admin\\b"; then
        fail "Missing required Linux capability: cap_bpf (preferred) or cap_sys_admin (fallback for kernels older than 5.8)"
    fi
}

is_port_in_use() {
    local port="$1"
    ss -H -ltn "sport = :${port}" | grep -q "." || return 1
}

wait_for_http() {
    local url="$1"
    local attempts=30
    local i
    for i in $(seq 1 "$attempts"); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_https_insecure() {
    local url="$1"
    local attempts=30
    local i
    for i in $(seq 1 "$attempts"); do
        if curl -kfsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

stop_agent() {
    set +e
    if [[ -n "${AGENT_PID_FILE}" && -f "${AGENT_PID_FILE}" ]]; then
        local pid
        pid="$(cat "${AGENT_PID_FILE}" 2>/dev/null)"
        if [[ -n "${pid}" ]]; then
            sudo kill -INT "${pid}" >/dev/null 2>&1 || true
            for _ in $(seq 1 50); do
                if ! sudo kill -0 "${pid}" >/dev/null 2>&1; then
                    break
                fi
                sleep 0.1
            done
            if sudo kill -0 "${pid}" >/dev/null 2>&1; then
                sudo kill -TERM "${pid}" >/dev/null 2>&1 || true
            fi
        fi
    fi

    if [[ -n "${AGENT_SUDO_PID}" ]]; then
        for _ in $(seq 1 20); do
            if ! kill -0 "${AGENT_SUDO_PID}" >/dev/null 2>&1; then
                break
            fi
            sleep 0.1
        done
        if kill -0 "${AGENT_SUDO_PID}" >/dev/null 2>&1; then
            kill "${AGENT_SUDO_PID}" >/dev/null 2>&1 || true
        fi
        wait "${AGENT_SUDO_PID}" >/dev/null 2>&1 || true
    fi
    set -e
}

cleanup() {
    set +e

    stop_agent

    if [[ -n "${HTTP_PID}" ]]; then
        kill "${HTTP_PID}" >/dev/null 2>&1 || true
        wait "${HTTP_PID}" >/dev/null 2>&1 || true
    fi

    if [[ -n "${TLS_PID}" ]]; then
        kill "${TLS_PID}" >/dev/null 2>&1 || true
        wait "${TLS_PID}" >/dev/null 2>&1 || true
    fi

    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
    fi
}

trap cleanup EXIT INT TERM

log "Starting host-mode E2E test harness"

# Preflight
[[ "$(uname -s)" == "Linux" ]] || fail "Host-mode eBPF tests require Linux"

require_cmd cargo
require_cmd rustup
require_cmd sudo
require_cmd curl
require_cmd openssl
require_cmd python3
require_cmd ss
require_cmd timeout
require_cmd bpf-linker
require_cmd capsh

if ! sudo -n true >/dev/null 2>&1; then
    fail "sudo non-interactive access is required (run once: sudo -v)"
fi
require_capability cap_net_admin
require_bpf_or_sys_admin_for_legacy_kernel

BPF_TOOLCHAIN="${BPF_TOOLCHAIN:-nightly-2026-02-17}"
export BPF_TOOLCHAIN
if ! rustup run "${BPF_TOOLCHAIN}" rustc --version >/dev/null 2>&1; then
    log "Installing missing Rust toolchain '${BPF_TOOLCHAIN}' (rust-src, rustfmt)"
    rustup toolchain install "${BPF_TOOLCHAIN}" --component rust-src --component rustfmt || true
    rustup run "${BPF_TOOLCHAIN}" rustc --version >/dev/null 2>&1 \
        || fail "Failed to install usable Rust toolchain '${BPF_TOOLCHAIN}'"
fi

if is_port_in_use "${HTTP_PORT}"; then
    fail "HTTP test port ${HTTP_PORT} is already in use"
fi
if is_port_in_use "${TLS_PORT}"; then
    fail "TLS test port ${TLS_PORT} is already in use"
fi

mkdir -p "${OUT_DIR}"
rm -f "${JSON_OUT}" "${AGENT_LOG}" "${HTTP_LOG}" "${TLS_LOG}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/panopticon-host-e2e.XXXXXX")"
AGENT_PID_FILE="${TMP_DIR}/agent.pid"

log "Building eBPF programs"
(
    cd "${REPO_ROOT}"
    cargo xtask build-ebpf --release
)

log "Building panopticon-agent"
(
    cd "${REPO_ROOT}"
    cargo build -p panopticon-agent --release
)

AGENT_BIN="${REPO_ROOT}/target/release/panopticon-agent"
[[ -x "${AGENT_BIN}" ]] || fail "Agent binary not found: ${AGENT_BIN}"

log "Starting local HTTP server on 127.0.0.1:${HTTP_PORT}"
mkdir -p "${TMP_DIR}/http"
printf 'ok\n' > "${TMP_DIR}/http/index.html"
printf 'healthy\n' > "${TMP_DIR}/http/health"
python3 -m http.server "${HTTP_PORT}" --bind 127.0.0.1 --directory "${TMP_DIR}/http" \
    >"${HTTP_LOG}" 2>&1 &
HTTP_PID="$!"

log "Starting local OpenSSL TLS server on 127.0.0.1:${TLS_PORT}"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -keyout "${TMP_DIR}/tls.key" -out "${TMP_DIR}/tls.crt" \
    -subj '/CN=localhost' >/dev/null 2>&1
openssl s_server -accept "127.0.0.1:${TLS_PORT}" -www \
    -cert "${TMP_DIR}/tls.crt" -key "${TMP_DIR}/tls.key" \
    >"${TLS_LOG}" 2>&1 &
TLS_PID="$!"

wait_for_http "http://127.0.0.1:${HTTP_PORT}/" || fail "HTTP server failed to become ready"
wait_for_https_insecure "https://127.0.0.1:${TLS_PORT}/" || fail "TLS server failed to become ready"

log "Starting agent on loopback with JSON export"
sudo -E bash -c "echo \$\$ > '${AGENT_PID_FILE}'; exec '${AGENT_BIN}' --interface lo --json-export '${JSON_OUT}' --log-events" \
    >"${AGENT_LOG}" 2>&1 &
AGENT_SUDO_PID="$!"

for _ in $(seq 1 10); do
    [[ -s "${AGENT_PID_FILE}" ]] && break
    sleep 1
done
[[ -s "${AGENT_PID_FILE}" ]] || fail "Could not determine agent PID"

log "Generating loopback HTTP/TLS traffic"
for i in $(seq 1 10); do
    curl -fsS "http://127.0.0.1:${HTTP_PORT}/?n=${i}" >/dev/null
    curl -fsS "http://127.0.0.1:${HTTP_PORT}/health?n=${i}" >/dev/null
    curl -kfsS "https://127.0.0.1:${TLS_PORT}/" >/dev/null
    sleep 0.1
done

# Give the agent time to flush ring buffer events.
sleep 3

log "Stopping agent"
stop_agent

[[ -f "${JSON_OUT}" ]] || fail "Expected JSON output file not found: ${JSON_OUT}"

log "Validating JSON output contains HTTP protocol events"
python3 - "${JSON_OUT}" <<'PY'
import json
import sys

path = sys.argv[1]
http_protocols = {"http1", "http2", "http"}
http_events = 0
total_events = 0

with open(path, "r", encoding="utf-8") as f:
    for line_num, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        total_events += 1
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            print(f"ERROR: invalid JSON line {line_num}: {exc}", file=sys.stderr)
            sys.exit(1)
        protocol = str(event.get("protocol", "")).lower()
        if protocol in http_protocols:
            http_events += 1

print(f"Total events: {total_events}")
print(f"HTTP events: {http_events}")

if http_events < 25:
    print(
        "ERROR: expected at least 25 HTTP protocol events "
        "(combined HTTP + decrypted HTTPS)",
        file=sys.stderr,
    )
    sys.exit(1)
PY

log "PASS: host-mode E2E complete"
log "Artifacts:"
log "  JSON:  ${JSON_OUT}"
log "  Agent: ${AGENT_LOG}"
log "  HTTP:  ${HTTP_LOG}"
log "  TLS:   ${TLS_LOG}"
