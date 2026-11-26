#!/usr/bin/env bash
# Score Go TLS capture where one binary is reached through overlayfs, as
# container images are (go_tls_oracle.go in a Docker image of its own):
#   containers  three containers of the image: a server started before
#               the agent, then a measured server and its client. Each
#               container shows the binary under an overlay device of its
#               own, over one layer inode, which the probes land on.
#               HTTP/1.1, then HTTP/2 (H2=1).
#   copyup      one container: a server P1 maps the binary from the image
#               layer and is attached; a chmod then copies the binary up
#               to a new upper inode, and a server P2 and its client
#               started in the same container map that one. HTTP/1.1.
# Every case is scored per process view (split_tls.py, score.py --exact):
# each exchange exported once and as itself, whatever the number of mounts
# or copies. HTTP/1.1 views must reach MIN_RECALL with no duplicate and no
# record that matches no request. HTTP/2 over TLS decodes no header (every
# key starts latched, docs/adr/ADR-014-cgroup-skb-capture-scope.md): its
# views are gated (score.py --withheld) on no record matching a request
# (its path decoded), no path, status, content type or header in any
# record of any protocol, no raw PII, and between MIN_RECALL and 1 record
# per request. copyup also checks that the chmod did copy the binary up
# (/o absent from the container's overlay upper directory before it,
# present after; a chmod changes ctime whether or not it copies up, and on
# 7.0, 6.8 and 5.15 /proc/PID/maps shows P1 and P2 at the same overlay
# inode, so neither tells a copy-up), and that both P1 and P2 map /o.
#
# Usage: sudo tests/oracle/run_overlay.sh [requests=300] [seed=42] [min_recall=0.99] [cases="containers copyup"]
# Needs: root, docker, a built agent (target/release/panopticon-agent),
# python3 3.7+ (the first new enough, or set PYTHON), go to build the
# oracle (sudo resets PATH: use `sudo env PATH="$PATH" ...`, set GO, or
# set ORACLE to a statically linked go_tls_oracle).
set -euo pipefail
N=${1:-300}
SEED=${2:-42}
MIN_RECALL=${3:-0.99}
CASES=${4:-containers copyup}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
AGENT=${AGENT:-$ROOT/target/release/panopticon-agent}
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
IMG=panopticon-overlay-oracle:$$
CTRS=()

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
  [[ ${#CTRS[@]} -gt 0 ]] && docker rm -f "${CTRS[@]}" >/dev/null 2>&1 || true
  docker rmi "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n ${ORACLE:-} ]]; then
  cp "$ORACLE" "$OUT/o"
else
  GO=${GO:-$(command -v go || echo /usr/local/go/bin/go)}
  CGO_ENABLED=0 "$GO" build -o "$OUT/o" "$HERE/go_tls_oracle.go"
fi
mkdir -p "$OUT/root"
cp "$OUT/o" "$OUT/root/o"
tar -C "$OUT/root" -cf "$OUT/img.tar" .
docker import "$OUT/img.tar" "$IMG" >/dev/null
echo 'tls_scan_interval_secs = 3' >"$OUT/agent.toml"

start_agent() { # DIR
  "$AGENT" --config "$OUT/agent.toml" --json-export "$1/agent.jsonl" >"$1/agent.log" 2>&1 &
  AP=$!
  for _ in $(seq 120); do
    grep -q 'Initial TLS scan complete' "$1/agent.log" && return 0
    kill -0 "$AP" 2>/dev/null || break
    sleep 0.5
  done
  echo "agent not ready" >&2
  cat "$1/agent.log" >&2
  exit 1
}
stop_agent() {
  stop_bounded "$AP" || status=1
  AP=
}
ctr_pid() { docker inspect -f '{{.State.Pid}}' "$1"; }
# The device and inode a process maps its /o from.
mapped() { awk '$2 ~ /x/ && $6 == "/o" {print $4, $5; exit}' "/proc/$1/maps"; }
# The upperdir of the overlay mounted at a process's root (mountinfo: the
# super options are the third field after "-").
upper_dir() {
  awk '$5 == "/" { for (i = 7; i <= NF; i++) if ($i == "-") { print $(i + 3); exit } }' \
    "/proc/$1/mountinfo" | tr ',' '\n' | sed -n 's/^upperdir=//p'
}

status=0
# score DIR SERVER_PID CLIENT_PID H2 LABEL
score() {
  local d=$1 h2=$4 view gate
  echo "uprobes attached: $(grep -c 'uprobe attached' "$d/agent.log")"
  sed 's/\x1b\[[0-9;]*m//g' "$d/agent.log" | grep -E 'TLS uprobes attached' | sed 's/.*INFO //' | cut -c1-160 || true
  "$PY" -I "$HERE/split_tls.py" "$d" "$2" "$3" 18444 "$MIN_RECALL" || status=1
  gate=("$MIN_RECALL" --exact)
  [[ $h2 == 1 ]] && gate=(0 --withheld --exact "--min-records=$MIN_RECALL")
  for view in client server; do
    echo "== $5, $view process view"
    "$PY" -I "$HERE/score.py" "$d/truth.jsonl" "$d/$view.jsonl" "${gate[@]}" || status=1
  done
}

for case in $CASES; do
  case $case in
    containers)
      for h2 in 0 1; do
        D=$OUT/containers-h2-$h2
        mkdir -p "$D"
        chmod 777 "$D"
        echo "==== containers H2=$h2"
        A=$(docker run -d --network host -e H2=$h2 "$IMG" /o server 127.0.0.1:19444)
        CTRS+=("$A")
        sleep 1
        start_agent "$D"
        B=$(docker run -d --network host -e H2=$h2 "$IMG" /o server 127.0.0.1:18444)
        CTRS+=("$B")
        sleep 8 # a periodic scan finds B
        C=$(docker run -d --network host -e H2=$h2 -e REUSE=1 -v "$D:/out" "$IMG" \
          /o client 127.0.0.1:18444 "$N" /out/truth.jsonl "$SEED")
        CTRS+=("$C")
        CP=$(ctr_pid "$C")
        BP=$(ctr_pid "$B")
        echo "maps: A $(mapped "$(ctr_pid "$A")"), B $(mapped "$BP"), C $(mapped "$CP" || true)"
        docker wait "$C" >/dev/null
        sleep 6
        stop_agent
        docker rm -f "$A" "$B" "$C" >/dev/null
        CTRS=()
        score "$D" "$BP" "$CP" "$h2" "containers H2=$h2"
      done
      ;;
    copyup)
      D=$OUT/copyup
      mkdir -p "$D"
      chmod 777 "$D"
      echo "==== copyup"
      A=$(docker run -d --network host -e H2=0 -v "$D:/out" "$IMG" /o server 127.0.0.1:19444)
      CTRS+=("$A")
      sleep 1
      P1=$(ctr_pid "$A")
      start_agent "$D"
      sleep 4
      UP=$(upper_dir "$P1" || true)
      if [[ -z $UP ]]; then
        echo "FAIL: no overlay upper directory at P1's root (no copy-up possible)"
        status=1
      elif [[ -e $UP/o ]]; then
        echo "FAIL: /o is in the upper directory before the chmod (already copied up)"
        status=1
      fi
      chmod 755 "/proc/$P1/root/o" # copies /o up to a new upper inode
      if [[ -n $UP && -e $UP/o ]]; then
        echo "copy-up: /o now in the upper directory ($(stat -c '%d %i' "$UP/o"))"
      else
        echo "FAIL: /o not in the upper directory after the chmod (no copy-up)"
        status=1
      fi
      docker exec -d "$A" /o server 127.0.0.1:18444
      P2=
      for _ in $(seq 100); do
        P2=$(pgrep -f '^/o server 127.0.0.1:18444' | head -1) && break
        sleep 0.1
      done
      M1=$(mapped "$P1" || true)
      M2=$(mapped "${P2:-0}" 2>/dev/null || true)
      echo "maps: P1 $M1, P2 $M2"
      if [[ -z $M1 || -z $M2 ]]; then
        echo "FAIL: P1 or P2 does not map /o (P2 ${P2:-not found})"
        status=1
      fi
      sleep 8 # a periodic scan finds P2
      docker exec "$A" /o client 127.0.0.1:18444 "$N" /out/truth.jsonl "$SEED" >/dev/null &
      EP=$!
      CP=
      for _ in $(seq 400); do
        CP=$(pgrep -f '^/o client 127.0.0.1:18444' | head -1) && break
        sleep 0.01
      done
      wait "$EP"
      sleep 6
      stop_agent
      docker rm -f "$A" >/dev/null
      CTRS=()
      score "$D" "$P2" "$CP" 0 copyup
      ;;
    *) echo "unknown case $case" >&2; exit 2 ;;
  esac
done
echo "artifacts: $OUT"
exit $status
