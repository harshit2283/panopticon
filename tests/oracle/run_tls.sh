#!/usr/bin/env bash
# Score the agent's TLS plaintext capture against ground truth, for both
# hooked TLS stacks:
#   openssl  http_oracle.py over TLS with the system python3, whose ssl
#            module uses the shared libssl (SSL_read_ex / SSL_write_ex)
#   go       go_tls_oracle.go: Go net/http + crypto/tls, client and server
#            (Conn.Write entry probe; reads at halfConn.decrypt's RETs), HTTP/1.1
#   go-h2    the same over HTTP/2 (ALPN h2, Go's default), every connection
#            held open until the client exits (REUSE=0), so no *tls.Conn
#            address, the agent's key, is reused in either process
#   go-h2-reuse
#            HTTP/2 with each connection closed before the next opens, so
#            Go reallocates *tls.Conn addresses
# Each runs on loopback. The uprobes see both ends, so every exchange is
# exported twice: once from the client process and once from the server.
# Each view is scored separately and must reach MIN_RECALL, as must the
# share of its exchanges that carry the socket's addresses (HTTP/1.1 parses
# a latched TLS key in full). Every TLS key starts latched, so HTTP/2 over
# TLS decodes no header (docs/adr/ADR-014-cgroup-skb-capture-scope.md):
# both go-h2 stacks report recall without gating it, and are gated instead
# (score.py --withheld) on no raw PII in the export, on no record matching a
# request (its path decoded), and on no record of any protocol carrying a
# path, status, content type or header. go-h2 also checks that
# no address was reused (tls_conns.py --distinct), go-h2-reuse that no
# client exchange decoded on a reused key (tls_conns.py --reused-latched).
#
# Usage: sudo tests/oracle/run_tls.sh [requests=500] [seed=1234] [min_recall=0.99] [stacks="openssl go go-h2 go-h2-reuse"]
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# python3 3.7+ (the first new enough, or set PYTHON) linked against a
# shared libssl, go for the go stack (sudo resets
# PATH: use `sudo env PATH="$PATH" ...` or set GO=/path/to/go).
set -euo pipefail
N=${1:-500}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
STACKS=${4:-openssl go go-h2 go-h2-reuse}
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
OUT=$(mktemp -d)

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
  [[ -n ${SP:-} ]] && kill "$SP" 2>/dev/null || true
  [[ -n ${HP:-} ]] && kill "$HP" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=oracle \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null

status=0
for stack in $STACKS; do
  D=$OUT/$stack
  mkdir -p "$D"
  case $stack in
    openssl)
      PORT=18443
      server=(env TLS=1 HOST=127.0.0.1 TLS_CERT="$OUT/cert.pem" TLS_KEY="$OUT/key.pem" MODE=server
              "$PY" -I "$HERE/http_oracle.py")
      client=(env TLS=1 HOST=127.0.0.1 SEED="$SEED" MODE=client
              "$PY" -I "$HERE/http_oracle.py" "$PORT" "$N" "$D/truth.jsonl")
      ;;
    go | go-h2 | go-h2-reuse)
      PORT=18444
      h2=0; [[ $stack == go-h2* ]] && h2=1
      reuse=1; [[ $stack == go-h2 ]] && reuse=0
      GO=${GO:-$(command -v go || echo /usr/local/go/bin/go)}
      [[ -x $OUT/go_tls_oracle ]] || "$GO" build -o "$OUT/go_tls_oracle" "$HERE/go_tls_oracle.go"
      server=(env H2=$h2 "$OUT/go_tls_oracle" server)
      client=(env H2=$h2 REUSE=$reuse "$OUT/go_tls_oracle" client "127.0.0.1:$PORT" "$N" "$D/truth.jsonl" "$SEED")
      ;;
    *) echo "unknown stack $stack" >&2; exit 2 ;;
  esac
  echo "==== $stack"
  # A copy of the server (another port) runs before the agent starts so
  # the initial TLS scan finds its library. The measured server starts
  # after the probes are attached.
  if [[ $stack == openssl ]]; then holder=("${server[@]}" $((PORT + 1000))); else holder=("${server[@]}" "127.0.0.1:$((PORT + 1000))"); fi
  if [[ $stack == openssl ]]; then server+=("$PORT"); else server=(env CONNLOG="$D/server_conns.txt" "${server[@]:1}" "127.0.0.1:$PORT"); fi
  "${holder[@]}" &
  HP=$!
  sleep 1
  "$AGENT" --json-export "$D/agent.jsonl" >"$D/agent.log" 2>&1 &
  AP=$!
  # Wait for the attach, not a fixed time.
  ready() { grep -q 'Initial TLS scan complete' "$D/agent.log"; }
  for _ in $(seq 120); do
    ready && break
    kill -0 "$AP" 2>/dev/null || break
    sleep 0.5
  done
  ready || { echo "agent not ready" >&2; cat "$D/agent.log" >&2; exit 1; }
  "${server[@]}" &
  SP=$!
  SP_PID=$SP
  sleep 1
  "${client[@]}" &
  CP=$!
  wait "$CP"
  sleep 1
  stop_bounded "$AP" || status=1; AP=
  kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=
  kill "$HP" 2>/dev/null; wait "$HP" 2>/dev/null || true; HP=
  echo "uprobes attached: $(grep -c 'uprobe attached' "$D/agent.log")"
  # `env` execs the server, so $SP is its PID; same for the client.
  "$PY" -I "$HERE/split_tls.py" "$D" "$SP_PID" "$CP" "$PORT" "$MIN_RECALL" || status=1
  gate=("$MIN_RECALL")
  case $stack in
    go-h2)
      "$PY" -I "$HERE/tls_conns.py" "$D/truth.jsonl" "$D/server_conns.txt" --distinct || status=1
      gate=(0 --withheld) ;;
    go-h2-reuse)
      "$PY" -I "$HERE/tls_conns.py" "$D/truth.jsonl" "$D/server_conns.txt" \
        --reused-latched "$D/client.jsonl" || status=1
      gate=(0 --withheld) ;;
  esac
  for view in client server; do
    echo "== $stack, $view process view"
    "$PY" -I "$HERE/score.py" "$D/truth.jsonl" "$D/$view.jsonl" "${gate[@]}" || status=1
  done
done
echo "artifacts: $OUT"
exit $status
