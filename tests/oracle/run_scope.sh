#!/usr/bin/env bash
# Lab tests for the cgroup_skb backend's scope rules on a real kernel
# (DESIGN §10), pass/fail on what leaves the node. Every run has every sink
# on: the event export, the raw dump, the PII audit log, --log-events at
# debug level, /metrics and /debug/state. score_scope.py scores each run.
#
#   t2            T-2: narrowing by SIGHUP (cgroup_filter loses b2/a) under
#                 live traffic, then a widening back
#   tls_full      T-10: unscoped full, OpenSSL and Go TLS plaintext captured
#   tls_pid       T-10: pid_filter; unselected process, socket passed either
#   tls_cgroup    way, PID reused after exit (tls_pid only); TLS addresses
#                 only when the call's own socket is in scope
#   tls_sample    T-10: connection_sample (0.99) / head_only: no TLS plaintext,
#   tls_head      tls_mode counted
#   netcls_start  T-6: a v1 net_cls/net_prio hierarchy is mounted: the
#                 cgroup selector is refused at startup
#   netcls_run    T-6: mounted and activated at runtime: sticky narrowing
#   coexist       T-16: a foreign ALLOW_MULTI root cgroup_skb program and a
#                 systemd IPAddressDeny= unit
#   tuples        T-18: REDIRECT and TPROXY tuple labels, decisions by socket
#   ktls_full     T-21: kTLS (native, 32-bit, io_uring), relays (read+write,
#   ktls_scoped   splice) and WireGuard, in unscoped full, scoped full and
#   ktls_head     head_only
#   refuse_cgroup RHEL 8 (no host cgroup2): cgroup_filter is refused
#
# Usage: sudo tests/oracle/run_scope.sh OUT scenario...
# Env: AGENT (agent binary), PY (python3 with a shared libssl), GO_TLS (a
# built scope_go_tls), KTLS_DRV (dir with ktls_drv64 / ktls_drv32),
# FOREIGN_OBJ (foreign_skb.bpf.o). Netns, veths, cgroups and ports are
# prefixed b2 / 31xxx so the tests can share a VM with other oracles (one
# agent at a time).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(realpath -m "$1"); shift
AGENT=${AGENT:-$HERE/../../target/release/panopticon-agent}
PY=${PY:-python3}
GO_TLS=${GO_TLS:-}
KTLS_DRV=${KTLS_DRV:-}
FOREIGN_OBJ=${FOREIGN_OBJ:-}
TRAFFIC="$PY -I $HERE/scope_traffic.py"
METRICS=127.0.0.1:39190
CGR=/sys/fs/cgroup
[[ $(stat -fc %T $CGR) == cgroup2fs ]] || CGR=
mkdir -p "$OUT"
export NO_COLOR=1
PIDS=""
AP=
STATUS=0

log() { echo "[$(date +%T)] $*"; }

cleanup() {
  agent_kill
  for p in $PIDS; do kill "$p" 2>/dev/null; done
  sleep 0.3
  for p in $PIDS; do kill -9 "$p" 2>/dev/null; done
  PIDS=""
  for n in a b c w1 w2; do ip netns del b2$n 2>/dev/null; done
  for n in a b c; do ip link del b2${n}h 2>/dev/null; done
  iptables -t nat -D PREROUTING -i b2ah -p tcp --dport 31480 -j REDIRECT --to-ports 31001 2>/dev/null
  iptables -t nat -D PREROUTING -i b2ch -p tcp --dport 31480 -j REDIRECT --to-ports 31003 2>/dev/null
  iptables -t mangle -D PREROUTING -i b2bh -p tcp -d 10.99.250.1 --dport 31490 \
    -j TPROXY --on-ip 10.99.202.1 --on-port 31402 --tproxy-mark 0x1/0x1 2>/dev/null
  ip rule del fwmark 0x1/0x1 lookup 1002 2>/dev/null
  ip route flush table 1002 2>/dev/null
  systemctl stop b2-deny 2>/dev/null; systemctl reset-failed b2-deny 2>/dev/null
  foreign_detach
  [[ -e ${FOREIGN_PIN}2 ]] && FOREIGN_PIN=${FOREIGN_PIN}2 foreign_detach
  mountpoint -q /run/b2-cg2 && umount /run/b2-cg2
  netcls_down
  if [[ -n $CGR ]]; then
    for c in a b c; do
      [[ -d $CGR/b2/$c ]] || continue
      for p in $(cat $CGR/b2/$c/cgroup.procs); do kill -9 "$p" 2>/dev/null; done
    done
    sleep 0.2
    for c in a b c; do rmdir $CGR/b2/$c 2>/dev/null; done
    rmdir $CGR/b2 2>/dev/null
  fi
  true
}
trap cleanup EXIT

bg() { "$@" & PIDS="$PIDS $!"; }

# ── fixtures ──────────────────────────────────────────────────────────────

ns_up() { # ns_up NAME OCTET: netns b2NAME; host b2NAMEh 10.99.OCTET.1, peer 10.99.OCTET.2
  ip netns add b2$1
  ip link add b2$1h type veth peer name b2$1p
  ip link set b2$1p netns b2$1
  ip addr add 10.99.$2.1/24 dev b2$1h
  ip link set b2$1h up
  ip -n b2$1 addr add 10.99.$2.2/24 dev b2$1p
  ip -n b2$1 link set b2$1p up
  ip -n b2$1 link set lo up
  ip -n b2$1 route add default via 10.99.$2.1
}

setup() {
  cleanup
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=b2 \
    -keyout "$OUT/key.pem" -out "$OUT/cert.pem" 2>/dev/null
  if [[ -n $CGR ]]; then
    mkdir -p $CGR/b2/a $CGR/b2/b $CGR/b2/c
  fi
  ns_up a 201; ns_up b 202; ns_up c 203
}

# in_ns NS cmd...: run cmd in netns b2NS without remounting /sys (cgroup joins work)
in_ns() { local n=$1; shift; exec nsenter --net=/var/run/netns/b2$n "$@"; }

# ── agent ─────────────────────────────────────────────────────────────────

# agent_start DIR: start with DIR/agent.toml and every sink; 0 once ready,
# 1 if the agent exited (its log says why).
agent_start() {
  local d=$1
  "$AGENT" -v --config "$d/agent.toml" --log-events --metrics-bind $METRICS \
    --json-export "$d/agent.jsonl" --pii-audit-log "$d/audit.jsonl" \
    --capture-raw "$d/raw.pncap" >"$d/agent.log" 2>&1 &
  AP=$!
  for _ in $(seq 150); do
    if ! kill -0 $AP 2>/dev/null; then
      wait $AP; echo "agent exit $?" >"$d/agent.exit"; AP=; return 1
    fi
    curl -sf "http://$METRICS/readyz" >/dev/null && return 0
    sleep 0.2
  done
  log "agent not ready after 30 s"; return 1
}

agent_kill() { [[ -n $AP ]] && kill -INT $AP 2>/dev/null && wait $AP; AP=; true; }

# agent_stop DIR: scrape, stop, decode the raw dump.
agent_stop() {
  local d=$1
  curl -sf "http://$METRICS/metrics" >"$d/metrics.txt" || log "metrics scrape failed"
  curl -sf "http://$METRICS/debug/state" >"$d/debug_state.json" || log "debug scrape failed"
  kill -INT $AP; wait $AP; echo "agent exit $?" >"$d/agent.exit"; AP=
  [[ -f $d/raw.pncap ]] && "$AGENT" --privacy-mode full --decode-capture "$d/raw.pncap" >"$d/raw.jsonl"
}

# applied DIR REGEX: wait (40 s) for REGEX in the agent log; print
# {"t": the line's timestamp, "offsets": each sink's size, the log's at the line's end}.
applied() {
  "$PY" -I - "$@" <<'EOF'
import datetime, json, os, re, sys, time
d, pat = sys.argv[1], re.compile(sys.argv[2].encode())
ansi = re.compile(rb"\x1b\[[0-9;]*m")
end = time.time() + 40
while time.time() < end:
    raw = open(d + "/agent.log", "rb").read()
    pos = 0
    for line in raw.splitlines(True):
        pos += len(line)
        clean = ansi.sub(b"", line)
        if pat.search(clean):
            sizes = {f: os.path.getsize(os.path.join(d, f))
                     for f in ("agent.jsonl", "audit.jsonl", "raw.pncap") if os.path.exists(os.path.join(d, f))}
            sizes["agent.log"] = pos
            ts = clean.split()[0].decode().rstrip("Z")[:26]
            t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=datetime.timezone.utc)
            print(json.dumps({"t": t.timestamp(), "offsets": sizes}))
            sys.exit(0)
    time.sleep(0.01)
sys.exit("timeout waiting for " + sys.argv[2])
EOF
}

score() { # score DIR checks...
  "$PY" -I "$HERE/score_scope.py" "$@" | tee "$1/score.txt"
  [[ ${PIPESTATUS[0]} == 0 ]] || STATUS=1
}

conf() { # conf DIR SCOPE-LINES: backend cgroup_skb, privacy full, plus SCOPE-LINES
  printf '%s\n\n[privacy]\nmode = "full"\n\n[capture]\nbackend = "cgroup_skb"\n' "$2" >"$1/agent.toml"
}

stop_pids() { for p in $PIDS; do kill "$p" 2>/dev/null; done; sleep 0.3; PIDS=""; }

# ── T-2 ───────────────────────────────────────────────────────────────────

run_t2() {
  local d=$OUT/t2; mkdir -p "$d"
  local c
  for c in a:201:31001 b:202:31002 c:203:31003; do
    IFS=: read -r n o p <<<"$c"
    bg env CGROUP=b2/$n HOST=10.99.$o.1 $TRAFFIC server $p
  done
  sleep 0.5
  conf "$d" 'cgroup_filter = ["b2/a", "b2/b"]'
  agent_start "$d" || { score "$d" log:NEVER; return; }
  for c in a:201:31001:A b:202:31002:B c:203:31003:C; do
    IFS=: read -r n o p tag <<<"$c"
    bg in_ns $n env GO=$d/go CGROUP=b2/$n HOST=10.99.$o.1 EVERY=5 GAP=0.02 \
      $TRAFFIC client $p $tag 0 "$d/$tag.truth.jsonl"
  done
  touch "$d/go"; sleep 6
  log "t2: narrowing to b2/b"
  conf "$d" 'cgroup_filter = ["b2/b"]'
  kill -HUP $AP
  applied "$d" 'Scope narrowed: applied' >"$d/narrowed.json" || STATUS=1
  curl -sf "http://$METRICS/metrics" >"$d/metrics_after.txt"
  curl -sf "http://$METRICS/debug/state" >"$d/debug_after.json"
  sleep 8
  log "t2: widening to b2/a, b2/b"
  conf "$d" 'cgroup_filter = ["b2/a", "b2/b"]'
  # Everything before the widening starts is checked: the sinks' sizes and
  # the time just before the SIGHUP.
  "$PY" -I -c 'import json, os, sys, time
d = sys.argv[1]; n = json.load(open(d + "/narrowed.json"))
n["until"] = time.time()
n["until_offsets"] = {f: os.path.getsize(os.path.join(d, f)) for f in n["offsets"]}
json.dump(n, open(d + "/narrowed.json", "w"))' "$d"
  kill -HUP $AP
  applied "$d" 'Scope widened: applied' >"$d/widened.json" || STATUS=1
  sleep 6
  stop_pids
  sleep 11 # past one 10 s stats flush
  agent_stop "$d"
  score "$d" recall:B:0.99 none:C ip:C:10.99.203.1,10.99.203.2 some:A \
    narrow:A:10.99.201.1,10.99.201.2 widened:A:0.97 \
    'log:Scope narrowed: applied' 'log:Scope widened: applied'
}

# ── T-10 ──────────────────────────────────────────────────────────────────

tls_server() { # tls_server PORT [env...]
  local p=$1; shift
  bg env "$@" TLS=1 TLS_CERT="$OUT/cert.pem" TLS_KEY="$OUT/key.pem" $TRAFFIC server $p
}
tls_client() { # tls_client DIR PORT TAG N [env...]
  local d=$1 p=$2 tag=$3 n=$4; shift 4
  bg env "$@" GO=$d/go TLS=1 EVERY=5 GAP=0.02 $TRAFFIC client $p $tag $n "$d/$tag.truth.jsonl"
}
go_pair() { # go_pair DIR PORT TAG N [env...]: server and client
  local d=$1 p=$2 tag=$3 n=$4; shift 4
  bg env "$@" $GO_TLS server 127.0.0.1:$p
  bg env "$@" GO=$d/go EVERY=5 GAP=0.02 $GO_TLS client 127.0.0.1:$p $tag $n "$d/$tag.truth.jsonl"
}

run_tls_full() {
  local d=$OUT/tls_full; mkdir -p "$d"
  tls_server 31101
  go_pair "$d" 31201 GS 200
  sleep 0.5
  tls_client "$d" 31101 OS 200
  conf "$d" ''
  agent_start "$d" || { score "$d" log:NEVER; return; }
  touch "$d/go"; sleep 14
  stop_pids; sleep 2
  agent_stop "$d"
  score "$d" recall:OS:0.98 recall:GS:0.98 addr:OS:0.9
}

# run_tls_scoped DIR pid|cgroup
run_tls_scoped() {
  local how=$1 d=$OUT/tls_$1; mkdir -p "$d"
  local sel=() uns=()
  [[ $how == cgroup ]] && sel=(CGROUP=b2/a) && uns=(CGROUP=b2/c)
  [[ $how == pid ]] && sel=(X=1) && uns=(X=1)
  local L="" # selected pids (pid_filter)
  tls_server 31111 "${sel[@]}"; L="$L $!"
  tls_client "$d" 31111 OSEL 200 "${sel[@]}"; L="$L $!"
  go_pair "$d" 31211 GSEL 200 "${sel[@]}"; L="$L $(echo $PIDS | awk '{print $(NF-1), $NF}')"
  tls_server 31112 "${uns[@]}"
  tls_client "$d" 31112 ON 200 "${uns[@]}"
  # PS: a selected process passes its socket to an unselected one, which
  # does the TLS: nothing. PR: the reverse: captured, without the address.
  bg env TLS=1 "${uns[@]}" $TRAFFIC recv "$d/ps.sock" PS 100 "$d/PS.truth.jsonl"
  bg env TLS=1 "${sel[@]}" $TRAFFIC recv "$d/pr.sock" PR 100 "$d/PR.truth.jsonl"; L="$L $!"
  sleep 0.5
  bg env GO=$d/go "${sel[@]}" $TRAFFIC send 31112 "$d/ps.sock"; L="$L $!"
  bg env GO=$d/go "${uns[@]}" $TRAFFIC send 31112 "$d/pr.sock"
  bg sleep 1000; local dummy=$!; L="$L $dummy"
  sleep 0.5
  if [[ $how == pid ]]; then
    conf "$d" "pid_filter = [$(echo $L | tr ' ' ',')]"
  else
    conf "$d" 'cgroup_filter = ["b2/a"]'
  fi
  agent_start "$d" || { score "$d" log:NEVER; return; }
  touch "$d/go"
  local checks=(recall:OSEL:0.98 recall:GSEL:0.98 none:ON none:PS recall:PR:0.98 noaddr:PR)
  if [[ $how == pid ]]; then
    sleep 1
    kill $dummy; wait $dummy 2>/dev/null
    $TRAFFIC reuse $dummy env TLS=1 EVERY=5 GAP=0.02 $TRAFFIC client 31112 RU 100 "$d/RU.truth.jsonl" \
      >"$d/reuse.txt" 2>&1 || log "pid reuse failed"
    checks+=(none:RU truth:RU)
    sleep 12
  else
    sleep 14
  fi
  stop_pids; sleep 2
  agent_stop "$d"
  score "$d" "${checks[@]}"
}

# run_tls_mode sample|head
run_tls_mode() {
  local d=$OUT/tls_$1; mkdir -p "$d"
  tls_server 31121
  go_pair "$d" 31221 GS 200
  bg $TRAFFIC server 31021
  sleep 0.5
  tls_client "$d" 31121 OS 200
  bg env GO=$d/go EVERY=5 GAP=0.02 $TRAFFIC client 31021 HP 200 "$d/HP.truth.jsonl"
  if [[ $1 == sample ]]; then
    # 0.99: sample_rate = 1.0 is full mode (DESIGN §3.4)
    conf "$d" $'sampling_mode = "connection_sample"\nsample_rate = 0.99'
  else
    conf "$d" $'sampling_mode = "head_only"\nhead_only_bytes = 1048576'
  fi
  agent_start "$d" || { score "$d" log:NEVER; return; }
  touch "$d/go"; sleep 14
  stop_pids; sleep 2
  agent_stop "$d"
  score "$d" recall:HP:0.9 none:OS none:GS drop:tls_mode truth:OS truth:GS
}

# ── T-6 ───────────────────────────────────────────────────────────────────

NETCLS=/run/b2-netcls
netcls_up() { # mount a v1 net_cls,net_prio hierarchy unless one is; prints its mount point
  local mp
  mp=$(awk '$9=="cgroup" && $11 ~ /(^|,)net_(cls|prio)(,|$)/ {print $5; exit}' /proc/self/mountinfo)
  if [[ -z $mp ]]; then
    mkdir -p $NETCLS && mount -t cgroup -o net_cls,net_prio b2netcls $NETCLS && mp=$NETCLS
  fi
  awk '$9=="cgroup" && $11 ~ /net_(cls|prio)/' /proc/self/mountinfo >&2
  echo "$mp"
}
netcls_down() {
  [[ -d $NETCLS/b2x ]] && { cat $NETCLS/b2x/cgroup.procs | xargs -r kill -9; sleep 0.2; rmdir $NETCLS/b2x; }
  mountpoint -q $NETCLS && umount $NETCLS
  true
}

run_netcls_start() {
  local d=$OUT/netcls_start; mkdir -p "$d"
  local mp; mp=$(netcls_up 2>"$d/mountinfo.txt")
  [[ -n $mp ]] || { log "netcls: mount failed"; STATUS=1; return; }
  conf "$d" 'cgroup_filter = ["b2/a"]'
  if agent_start "$d"; then agent_stop "$d"; echo "started" >>"$d/agent.exit"; fi
  netcls_down
  score "$d" 'log:refusing cgroup_filter.*net_cls|net_cls.*refus' 'exit:nonzero'
}

run_netcls_run() {
  local d=$OUT/netcls_run; mkdir -p "$d"
  bg env CGROUP=b2/a HOST=10.99.201.1 $TRAFFIC server 31001
  sleep 0.5
  conf "$d" 'cgroup_filter = ["b2/a"]'
  agent_start "$d" || { score "$d" log:NEVER; return; }
  bg in_ns a env GO=$d/go CGROUP=b2/a HOST=10.99.201.1 EVERY=5 GAP=0.02 \
    $TRAFFIC client 31001 A 0 "$d/A.truth.jsonl"
  touch "$d/go"; sleep 4
  local mp; mp=$(netcls_up 2>"$d/mountinfo.txt")
  [[ -n $mp ]] || { log "netcls: mount failed"; STATUS=1; }
  mkdir -p "$mp/b2x"
  echo 0x100001 >"$mp/b2x/net_cls.classid"
  echo "lo 5" >"$mp/b2x/net_prio.ifpriomap"
  # AV1: new sockets in a v1-activated cgroup and in b2/a. Captured or not
  # before the watcher reacts tells whether this kernel keeps the v2 ancestry.
  bg in_ns a sh -c "echo \$\$ >$mp/b2x/cgroup.procs && exec env CGROUP=b2/a HOST=10.99.201.1 EVERY=1 GAP=0.05 \
    $TRAFFIC client 31001 AV1 0 $d/AV1.truth.jsonl"
  applied "$d" 'Scope narrowed: applied' >"$d/narrowed.json" || STATUS=1
  curl -sf "http://$METRICS/metrics" >"$d/metrics_after.txt"
  curl -sf "http://$METRICS/debug/state" >"$d/debug_after.json"
  sleep 6
  stop_pids; sleep 1
  agent_stop "$d"
  netcls_down
  score "$d" some:A narrow:A:10.99.201.1,10.99.201.2 narrow:AV1 'log:stopped admitting' info:AV1
}

# ── T-16 ──────────────────────────────────────────────────────────────────

FOREIGN_PIN=/sys/fs/bpf/b2_foreign
FOREIGN_ROOT=
foreign_attach() { # foreign_attach ROOT: load (once) and attach to ROOT's ingress and egress, multi
  FOREIGN_ROOT=$1
  [[ -e $FOREIGN_PIN ]] || bpftool prog load "$FOREIGN_OBJ" $FOREIGN_PIN type cgroup/skb || return 1
  bpftool cgroup attach "$1" ingress pinned $FOREIGN_PIN multi &&
    bpftool cgroup attach "$1" egress pinned $FOREIGN_PIN multi
}
foreign_count() { # the (first) foreign program's packet count
  local map; map=$(bpftool -j prog show pinned $FOREIGN_PIN | "$PY" -I -c 'import json, sys; print(json.load(sys.stdin)["map_ids"][0])')
  bpftool -j map dump id "$map" 2>/dev/null | "$PY" -I -c 'import json, sys
v = json.load(sys.stdin)[0]
v = v.get("formatted", v)["value"]
print(v if isinstance(v, int) else int.from_bytes(bytes(int(b, 16) for b in v), "little"))'
}
foreign_detach() {
  [[ -e $FOREIGN_PIN ]] || return 0
  local id; id=$(bpftool prog show pinned $FOREIGN_PIN | awk -F: 'NR==1{print $1}')
  for t in ingress egress; do bpftool cgroup detach "${FOREIGN_ROOT:-/sys/fs/cgroup}" $t id "$id" 2>/dev/null; done
  rm -f $FOREIGN_PIN
}

run_coexist() {
  local d=$OUT/coexist; mkdir -p "$d"
  local root=$CGR checks=()
  if [[ -z $root ]]; then
    mkdir -p /run/b2-cg2; mountpoint -q /run/b2-cg2 || mount -t cgroup2 none /run/b2-cg2; root=/run/b2-cg2
  fi
  foreign_attach $root || { log "foreign program attach failed"; STATUS=1; return; }
  bpftool cgroup show $root >"$d/root-before.txt"
  local c0 c1
  local sb=()
  [[ -n $CGR ]] && sb=(CGROUP=b2/b)
  bg env HOST=10.99.201.1 $TRAFFIC server 31001
  bg env "${sb[@]}" HOST=10.99.202.1 $TRAFFIC server 31002
  # BB: plain traffic from netns b to B's server, selected by the server's
  # cgroup b2/b (RHEL 8: by pid)
  bg in_ns b env GO=$d/go HOST=10.99.202.1 EVERY=5 GAP=0.02 $TRAFFIC client 31002 BB 200 "$d/BB.truth.jsonl"
  sleep 0.5
  if [[ -n $CGR ]]; then
    # A unit denied 10.99.202.0/24: its connections to B fail, those to A pass.
    systemd-run --unit b2-deny -p IPAddressDeny=10.99.202.0/24 /bin/sh -c \
      "env GO=$d/go HOST=10.99.201.1 EVERY=5 GAP=0.02 $TRAFFIC client 31001 SDA 200 $d/SDA.truth.jsonl &
       env GO=$d/go HOST=10.99.202.1 EVERY=5 GAP=0.02 $TRAFFIC client 31002 SDB 50 $d/SDB.truth.jsonl 2>$d/SDB.err &
       wait"
    sleep 0.5
    conf "$d" 'cgroup_filter = ["system.slice/b2-deny.service", "b2/b"]'
    checks=(recall:SDA:0.98 notruth:SDB)
  else
    conf "$d" "pid_filter = [$(echo $PIDS | tr ' ' ',')]"
  fi
  agent_start "$d" || { score "$d" log:NEVER; return; }
  c0=$(foreign_count)
  # a second foreign attachment after the agent's
  bpftool prog load "$FOREIGN_OBJ" ${FOREIGN_PIN}2 type cgroup/skb &&
    bpftool cgroup attach $root egress pinned ${FOREIGN_PIN}2 multi
  touch "$d/go"; sleep 12
  bpftool cgroup show $root >"$d/root-during.txt"
  [[ -n $CGR ]] && bpftool cgroup show $CGR/system.slice/b2-deny.service >"$d/unit-progs.txt"
  stop_pids; systemctl stop b2-deny 2>/dev/null; sleep 1
  c1=$(foreign_count)
  agent_stop "$d"
  bpftool cgroup show $root >"$d/root-after.txt"
  local id2; id2=$(bpftool prog show pinned ${FOREIGN_PIN}2 | awk -F: 'NR==1{print $1}')
  bpftool cgroup detach $root egress id "$id2"; rm -f ${FOREIGN_PIN}2
  # The foreign programs stayed attached (3 attachments) and kept running;
  # every program the agent added is gone.
  local nf agent_ids left
  nf=$(grep -c b2_foreign "$d/root-after.txt")
  agent_ids=$(comm -13 <(awk 'NR>1{print $1}' "$d/root-before.txt" | sort) \
                       <(grep -v b2_foreign "$d/root-during.txt" | awk 'NR>1{print $1}' | sort))
  left=$(for i in $agent_ids; do awk -v i="$i" '$1==i' "$d/root-after.txt"; done)
  {
    echo "foreign attachments after: $nf; packets it counted while the agent ran: $c0 -> $c1"
    echo "agent programs during: $(echo $agent_ids); left after: ${left:-none}"
  } | tee "$d/foreign.txt"
  [[ $nf -eq 3 && ${c1:-0} -gt ${c0:-0} && -n $agent_ids && -z $left ]] ||
    { echo "FAIL coexistence (see foreign.txt)" | tee -a "$d/foreign.txt"; STATUS=1; }
  score "$d" recall:BB:0.98 "${checks[@]}"
}

# ── T-18 ──────────────────────────────────────────────────────────────────

run_tuples() {
  local d=$OUT/tuples; mkdir -p "$d"
  iptables -t nat -A PREROUTING -i b2ah -p tcp --dport 31480 -j REDIRECT --to-ports 31001
  iptables -t nat -A PREROUTING -i b2ch -p tcp --dport 31480 -j REDIRECT --to-ports 31003
  iptables -t mangle -A PREROUTING -i b2bh -p tcp -d 10.99.250.1 --dport 31490 \
    -j TPROXY --on-ip 10.99.202.1 --on-port 31402 --tproxy-mark 0x1/0x1
  ip rule add fwmark 0x1/0x1 lookup 1002 pref 1002
  ip route add local 0.0.0.0/0 dev lo table 1002
  local sa=() sb=() sc=()
  [[ -n $CGR ]] && sa=(CGROUP=b2/a) sb=(CGROUP=b2/b) sc=(CGROUP=b2/c)
  bg env "${sa[@]}" HOST=10.99.201.1 $TRAFFIC server 31001; local L=$!
  bg env "${sb[@]}" HOST=10.99.202.1 TRANSPARENT=1 $TRAFFIC server 31402; L="$L $!"
  bg env "${sc[@]}" HOST=10.99.203.1 $TRAFFIC server 31003
  bg in_ns a env "${sa[@]}" GO=$d/go HOST=10.99.201.1 EVERY=5 GAP=0.02 $TRAFFIC client 31480 RD 200 "$d/RD.truth.jsonl"; L="$L $!"
  bg in_ns b env "${sb[@]}" GO=$d/go HOST=10.99.250.1 EVERY=5 GAP=0.02 $TRAFFIC client 31490 TP 200 "$d/TP.truth.jsonl"; L="$L $!"
  bg in_ns c env "${sc[@]}" GO=$d/go HOST=10.99.203.1 EVERY=5 GAP=0.02 $TRAFFIC client 31480 RC 200 "$d/RC.truth.jsonl"
  sleep 0.5
  if [[ -n $CGR ]]; then conf "$d" 'cgroup_filter = ["b2/a", "b2/b"]'
  else conf "$d" "pid_filter = [$(echo $L | tr ' ' ',')]"; fi
  # §2.3: egress after the socket's own netfilter (the reply is un-NATed in
  # POSTROUTING first); ingress as delivered (REDIRECT: the redirected port;
  # TPROXY: the original tuple). E = the client's ephemeral port.
  cat >"$d/expect.json" <<'EOF'
{"RD": {"client Egress": "10.99.201.2:E>10.99.201.1:31480", "client Ingress": "10.99.201.1:31480>10.99.201.2:E",
        "server Egress": "10.99.201.1:31480>10.99.201.2:E", "server Ingress": "10.99.201.2:E>10.99.201.1:31001",
        "client_ip": "10.99.201.2"},
 "TP": {"client Egress": "10.99.202.2:E>10.99.250.1:31490", "client Ingress": "10.99.250.1:31490>10.99.202.2:E",
        "server Egress": "10.99.250.1:31490>10.99.202.2:E", "server Ingress": "10.99.202.2:E>10.99.250.1:31490",
        "client_ip": "10.99.202.2"}}
EOF
  agent_start "$d" || { score "$d" log:NEVER; return; }
  touch "$d/go"; sleep 12
  stop_pids; sleep 1
  agent_stop "$d"
  score "$d" recall:RD:0.98 recall:TP:0.98 truth:RC none:RC tuples:RD tuples:TP
}

# ── T-21 ──────────────────────────────────────────────────────────────────

wg_up() { # two netns joined by veth, a WireGuard tunnel 10.99.211.1 <-> .2
  ip netns add b2w1; ip netns add b2w2
  ip link add b2w1v type veth peer name b2w2v
  ip link set b2w1v netns b2w1; ip link set b2w2v netns b2w2
  ip -n b2w1 addr add 10.99.210.1/24 dev b2w1v; ip -n b2w1 link set b2w1v up
  ip -n b2w2 addr add 10.99.210.2/24 dev b2w2v; ip -n b2w2 link set b2w2v up
  ip -n b2w1 link set lo up; ip -n b2w2 link set lo up
  local k1 k2; k1=$(wg genkey); k2=$(wg genkey)
  ip -n b2w1 link add wg0 type wireguard || return 1
  ip -n b2w2 link add wg0 type wireguard
  ip netns exec b2w1 wg set wg0 private-key <(echo "$k1") listen-port 51821 \
    peer "$(echo "$k2" | wg pubkey)" allowed-ips 10.99.211.2/32 endpoint 10.99.210.2:51822
  ip netns exec b2w2 wg set wg0 private-key <(echo "$k2") listen-port 51822 \
    peer "$(echo "$k1" | wg pubkey)" allowed-ips 10.99.211.1/32 endpoint 10.99.210.1:51821
  ip -n b2w1 addr add 10.99.211.1/24 dev wg0; ip -n b2w1 link set wg0 up
  ip -n b2w2 addr add 10.99.211.2/24 dev wg0; ip -n b2w2 link set wg0 up
}

# run_ktls full|scoped|head
run_ktls() {
  local m=$1 d=$OUT/ktls_$1; mkdir -p "$d"
  modprobe tls
  local sel=() uns=() L=""
  [[ -n $CGR ]] && sel=(CGROUP=b2/a) uns=(CGROUP=b2/c)
  local wg=0
  if command -v wg >/dev/null && modprobe wireguard 2>/dev/null && wg_up; then wg=1; fi
  bg env "${sel[@]}" $TRAFFIC server 31021; L="$L $!"
  bg env "${sel[@]}" GO=$d/go EVERY=5 GAP=0.02 $TRAFFIC client 31021 HP 200 "$d/HP.truth.jsonl"; L="$L $!"
  if [[ $wg == 1 ]]; then
    bg in_ns w2 env "${sel[@]}" HOST=10.99.211.2 $TRAFFIC server 31320; L="$L $!"
    bg in_ns w1 env "${sel[@]}" GO=$d/go HOST=10.99.211.2 EVERY=5 GAP=0.02 $TRAFFIC client 31320 W 200 "$d/W.truth.jsonl"; L="$L $!"
    bg in_ns w2 env "${uns[@]}" HOST=10.99.211.2 $TRAFFIC server 31321
    bg in_ns w1 env "${uns[@]}" GO=$d/go HOST=10.99.211.2 EVERY=5 GAP=0.02 $TRAFFIC client 31321 W2 200 "$d/W2.truth.jsonl"
  fi
  # The kTLS drivers wait for GO in a shell that execs them (same pid).
  local uring=0
  [[ $(uname -r | cut -d. -f1) -ge 7 || ( $(uname -r | cut -d. -f1) -eq 6 && $(uname -r | cut -d. -f2) -ge 7 ) ]] && uring=1
  local runs="ulp:64:31301:K1 ulp:32:31302:K2 keys:64:31305:K5 recv:64:31310:R1 splice:64:31312:R2"
  [[ $uring == 1 ]] && runs="$runs uring:64:31303:K3 uring:32:31304:K4"
  local r
  for r in $runs; do
    IFS=: read -r mode bits port tag <<<"$r"
    bg env "${sel[@]}" sh -c "[ -n \"\$CGROUP\" ] && echo \$\$ >$CGR/\$CGROUP/cgroup.procs;
      while [ ! -e $d/go ]; do sleep 0.05; done; sleep 2; exec $KTLS_DRV/ktls_drv$bits $mode $port $tag 20" \
      >"$d/$tag.out" 2>&1
    L="$L $!"
  done
  case $m in
    full) conf "$d" '' ;;
    scoped) if [[ -n $CGR ]]; then conf "$d" 'cgroup_filter = ["b2/a"]'
            else conf "$d" "pid_filter = [$(echo $L | tr ' ' ',')]"; fi ;;
    head) conf "$d" $'sampling_mode = "head_only"\nhead_only_bytes = 4096' ;;
  esac
  agent_start "$d" || { score "$d" log:NEVER; return; }
  touch "$d/go"; sleep 14
  stop_pids; sleep 1
  agent_stop "$d"
  ip netns del b2w1 2>/dev/null; ip netns del b2w2 2>/dev/null
  local checks=(recall:HP:0.98)
  for r in $runs; do
    IFS=: read -r mode bits port tag <<<"$r"
    checks+=("drvok:$tag")
    case $m:$mode in
      full:keys) checks+=("someport:$port" "inport:$tag:$port") ;;  # ciphertext: no marker
      full:*) checks+=("someport:$tag:$port") ;;
      *:keys) checks+=("noport:$port") ;;
      *:recv | *:splice) checks+=("inport:$tag:$port" "someport:$tag:$((port + 1))") ;;
      *) checks+=("none:$tag") ;;
    esac
  done
  [[ $m != full ]] && checks+=(drop:ktls_payload)
  if [[ $wg == 1 ]]; then
    checks+=(recall:W:0.98)
    [[ $m == scoped ]] && checks+=(truth:W2 none:W2)
    [[ $m != scoped ]] && checks+=(recall:W2:0.98)
  else
    echo "wireguard: not available" >"$d/wireguard.txt"
  fi
  score "$d" "${checks[@]}"
}

run_refuse_cgroup() {
  local d=$OUT/refuse_cgroup; mkdir -p "$d"
  conf "$d" 'cgroup_filter = ["b2/a"]'
  if agent_start "$d"; then agent_stop "$d"; echo "started" >>"$d/agent.exit"; fi
  score "$d" 'log:refusing cgroup_filter/pod_filter: .* private cgroup2' 'exit:nonzero'
}

setup
for s in "$@"; do
  log "==== $s"
  case $s in
    t2) run_t2 ;;
    tls_full) run_tls_full ;;
    tls_pid) run_tls_scoped pid ;;
    tls_cgroup) run_tls_scoped cgroup ;;
    tls_sample) run_tls_mode sample ;;
    tls_head) run_tls_mode head ;;
    netcls_start) run_netcls_start ;;
    netcls_run) run_netcls_run ;;
    coexist) run_coexist ;;
    tuples) run_tuples ;;
    ktls_full | ktls_scoped | ktls_head) run_ktls "${s#ktls_}" ;;
    refuse_cgroup) run_refuse_cgroup ;;
    *) log "unknown scenario $s"; STATUS=1 ;;
  esac
  agent_kill; stop_pids
done
exit $STATUS
