"""Kernel-measured cost of the agent's BPF programs.

With kernel.bpf_stats_enabled=1 the kernel accounts run_time_ns / run_cnt
for every BPF program; they are exposed in /proc/<pid>/fdinfo/<prog fd>.
Prints total runs, total ns and mean ns per invocation for the packet
programs (per packet: the cgroup_skb programs, which run for every packet
of every local socket on the node, loopback included; TC classifiers too,
for older agents), then the same per program type for the others:
sock_ops and cgroup/sock_create (per connection / socket), tracepoints
(process lifecycle, and the sock_send/recv_length hooks that give TLS
connections their addresses, which run on every TCP send/receive),
uprobes/kprobes and fentry/fexit, then per program by name (from bpftool,
if installed).

Usage: bpf_cost.py PID              totals since the programs were loaded
       bpf_cost.py PID BEFORE.json  deltas since a snapshot
       bpf_cost.py --snap PID > BEFORE.json
Startup traffic and earlier runs count unless a snapshot is subtracted.
"""
import collections
import json
import os
import subprocess
import sys

TYPES = {"3": "tc", "8": "cgroup_skb", "9": "cgroup_sock", "13": "sock_ops",
         "5": "tracepoint", "2": "kprobe/uprobe", "26": "fentry/fexit"}
PACKET = ("tc", "cgroup_skb")


def progs(pid):
    """{prog_id: [type, runs, ns]} for every BPF program fd the agent holds."""
    out = {}
    for fd in os.listdir(f"/proc/{pid}/fd"):
        try:
            info = open(f"/proc/{pid}/fdinfo/{fd}").read()
        except OSError:
            continue
        f = {k.strip(): v.strip() for k, v in (l.split(":", 1) for l in info.splitlines() if ":" in l)}
        kind = TYPES.get(f.get("prog_type", ""))
        if kind:
            out[f.get("prog_id", fd)] = [kind, int(f.get("run_cnt", 0)), int(f.get("run_time_ns", 0))]
    return out


if sys.argv[1] == "--snap":
    json.dump(progs(sys.argv[2]), sys.stdout)
    sys.exit()
now = progs(sys.argv[1])
if len(sys.argv) > 2:
    before = json.load(open(sys.argv[2]))
    for pid_, v in now.items():
        b = before.get(pid_, [v[0], 0, 0])
        v[1] -= b[1]
        v[2] -= b[2]
try:
    shown = json.loads(subprocess.run(["bpftool", "-j", "prog", "show"], stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, universal_newlines=True,
                                      timeout=10).stdout or "[]")
    names = {str(p["id"]): p.get("name", "?") for p in shown}
except (OSError, ValueError, subprocess.SubprocessError):
    names = {}

stats = collections.defaultdict(lambda: [0, 0, 0])  # progs, runs, ns
for kind, runs, ns in now.values():
    s = stats[kind]
    s[0] += 1
    s[1] += runs
    s[2] += ns
kinds = "+".join(k for k in PACKET if k in stats) or "none"
p = [sum(stats[k][i] for k in PACKET) for i in range(3)]
print(f"packet_programs={p[0]} ({kinds}) runs={p[1]} total_ns={p[2]} ns_per_packet={p[2] / max(p[1], 1):.0f}")
for kind, (n, runs, ns) in sorted(stats.items()):
    if kind not in PACKET:
        print(f"  {kind}: programs={n} runs={runs} ns_per_run={ns / max(runs, 1):.0f}")
for id_, (kind, runs, ns) in sorted(now.items(), key=lambda x: -x[1][1]):
    if runs:
        print(f"    prog {names.get(id_, id_)} ({kind}): runs={runs} ns_per_run={ns / runs:.0f}")
