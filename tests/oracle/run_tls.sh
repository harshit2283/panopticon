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
#            Go reallocates *tls.Conn addresses: a reused key never decodes
#            again (docs/adr/014-capture-scope.md), recall is reported, not
#            gated
# Each runs on loopback. The uprobes see both ends, so every exchange is
# exported twice: once from the client process and once from the server.
# Each view is scored separately and must reach MIN_RECALL, as must the
# share of its exchanges that carry the socket's addresses. go-h2 must also
# show as many distinct keys as connections (tls_conns.py). go-h2-reuse is
# gated instead on no raw PII in the export and on every record it could not
# attribute carrying no path, status, content type or header.
#
# Usage: sudo tests/oracle/run_tls.sh [requests=500] [seed=1234] [min_recall=0.99] [stacks="openssl go go-h2 go-h2-reuse"]
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# a python3 linked against a shared libssl, go for the go stack (sudo resets
# PATH: use `sudo env PATH="$PATH" ...` or set GO=/path/to/go).
set -euo pipefail
N=${1:-500}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
STACKS=${4:-openssl go go-h2 go-h2-reuse}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
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
              python3 -I "$HERE/http_oracle.py")
      client=(env TLS=1 HOST=127.0.0.1 SEED="$SEED" MODE=client
              python3 -I "$HERE/http_oracle.py" "$PORT" "$N" "$D/truth.jsonl")
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
  kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=
  kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=
  kill "$HP" 2>/dev/null; wait "$HP" 2>/dev/null || true; HP=
  echo "uprobes attached: $(grep -c 'uprobe attached' "$D/agent.log")"
  # `env` execs the server, so $SP is its PID; same for the client.
  python3 -I "$HERE/split_tls.py" "$D" "$SP_PID" "$CP" "$PORT" "$MIN_RECALL" || status=1
  gate=("$MIN_RECALL")
  case $stack in
    go-h2) python3 -I "$HERE/tls_conns.py" "$D/truth.jsonl" "$D/server_conns.txt" --distinct || status=1 ;;
    go-h2-reuse)
      python3 -I "$HERE/tls_conns.py" "$D/truth.jsonl" "$D/server_conns.txt"
      gate=(0 --withheld) ;;
  esac
  for view in client server; do
    echo "== $stack, $view process view"
    python3 -I "$HERE/score.py" "$D/truth.jsonl" "$D/$view.jsonl" "${gate[@]}" || status=1
  done
done
echo "artifacts: $OUT"
exit $status
