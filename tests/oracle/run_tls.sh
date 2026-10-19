#!/usr/bin/env bash
# Score the agent's TLS plaintext capture (OpenSSL uprobes) against ground
# truth.
#
# Runs http_oracle.py over TLS on loopback with the system python3, whose ssl
# module uses the system libssl (SSL_read_ex / SSL_write_ex on OpenSSL 3).
# The uprobes see both ends, so every exchange is exported twice: once from
# the client process and once from the server process. Each view is scored
# separately and must reach MIN_RECALL.
#
# Usage: sudo tests/oracle/run_tls.sh [requests=500] [seed=1234] [min_recall=0.99]
# Needs: root, a built agent (target/release/panopticon-agent), openssl,
# a python3 linked against a shared libssl.
set -euo pipefail
N=${1:-500}
SEED=${2:-1234}
MIN_RECALL=${3:-0.99}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
OUT=$(mktemp -d)
PORT=18443

cleanup() {
  [[ -n ${AP:-} ]] && kill -INT "$AP" 2>/dev/null && wait "$AP" 2>/dev/null || true
  [[ -n ${SP:-} ]] && kill "$SP" 2>/dev/null || true
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=oracle \
  -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null
export TLS=1 HOST=127.0.0.1
# The server must be running before the agent starts so the initial TLS scan
# finds its libssl (later processes are picked up on exec).
TLS_CERT=$OUT/cert.pem TLS_KEY=$OUT/key.pem MODE=server python3 -I "$HERE/http_oracle.py" "$PORT" &
SP=$!
sleep 1
"$AGENT" -i lo --json-export "$OUT/agent.jsonl" >"$OUT/agent.log" 2>&1 &
AP=$!
sleep 4
SEED=$SEED MODE=client python3 -I "$HERE/http_oracle.py" "$PORT" "$N" "$OUT/truth.jsonl" &
CP=$!
wait "$CP"
sleep 1
kill -INT "$AP"; wait "$AP" 2>/dev/null || true; AP=

echo "uprobes attached: $(grep -c 'uprobe attached' "$OUT/agent.log")"
python3 -I - "$OUT" "$SP" "$CP" <<'EOF'
import json, sys
out, views = sys.argv[1], {sys.argv[2]: "server", sys.argv[3]: "client"}
files = {name: open(f"{out}/{name}.jsonl", "w") for name in views.values()}
for line in open(f"{out}/agent.jsonl"):
    view = views.get(str(json.loads(line).get("pid")))
    if view:
        files[view].write(line)
EOF
status=0
for view in client server; do
  echo "== $view process view"
  python3 -I "$HERE/score.py" "$OUT/truth.jsonl" "$OUT/$view.jsonl" "$MIN_RECALL" || status=1
done
echo "artifacts: $OUT"
exit $status
