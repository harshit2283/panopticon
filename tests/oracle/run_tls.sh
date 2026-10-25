#!/usr/bin/env bash
# Score the agent's TLS plaintext capture against ground truth, for both
# hooked TLS stacks:
#   openssl  http_oracle.py over TLS with the system python3, whose ssl
#            module uses the shared libssl (SSL_read_ex / SSL_write_ex)
#   go       go_tls_oracle.go: Go net/http + crypto/tls, client and server
#            (Conn.Write entry probe, Conn.Read entry + RET probes)
# Each runs on loopback. The uprobes see both ends, so every exchange is
# exported twice: once from the client process and once from the server.
# Each view is scored separately and must reach MIN_RECALL, as must the
# share of its exchanges that carry the socket's addresses.
#
# Usage: sudo tests/oracle/run_tls.sh [requests=500] [seed=1234] [min_recall=0.99] [stacks="openssl go"]
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# a python3 linked against a shared libssl, go for the go stack (sudo resets
# PATH: use `sudo env PATH="$PATH" ...` or set GO=/path/to/go).
set -euo pipefail
N=${1:-500}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
STACKS=${4:-openssl go}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  [[ -n ${SP:-} ]] && kill "$SP" 2>/dev/null || true
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
              python3 -I "$HERE/http_oracle.py" "$PORT")
      client=(env TLS=1 HOST=127.0.0.1 SEED="$SEED" MODE=client
              python3 -I "$HERE/http_oracle.py" "$PORT" "$N" "$D/truth.jsonl")
      ;;
    go)
      PORT=18444
      GO=${GO:-$(command -v go || echo /usr/local/go/bin/go)}
      "$GO" build -o "$OUT/go_tls_oracle" "$HERE/go_tls_oracle.go"
      server=("$OUT/go_tls_oracle" server "127.0.0.1:$PORT")
      client=("$OUT/go_tls_oracle" client "127.0.0.1:$PORT" "$N" "$D/truth.jsonl" "$SEED")
      ;;
    *) echo "unknown stack $stack" >&2; exit 2 ;;
  esac
  echo "==== $stack"
  # The server must be running before the agent starts so the initial TLS
  # scan finds its library (later processes are picked up on exec).
  "${server[@]}" &
  SP=$!
  SP_PID=$SP
  sleep 1
  "$AGENT" -i lo --json-export "$D/agent.jsonl" >"$D/agent.log" 2>&1 &
  AP=$!
  sleep 4
  "${client[@]}" &
  CP=$!
  wait "$CP"
  sleep 1
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=
  echo "uprobes attached: $(grep -c 'uprobe attached' "$D/agent.log")"
  # `env` execs the server, so $SP is its PID; same for the client.
  python3 -I "$HERE/split_tls.py" "$D" "$SP_PID" "$CP" "$PORT" "$MIN_RECALL" || status=1
  for view in client server; do
    echo "== $stack, $view process view"
    python3 -I "$HERE/score.py" "$D/truth.jsonl" "$D/$view.jsonl" "$MIN_RECALL" || status=1
  done
done
echo "artifacts: $OUT"
exit $status
