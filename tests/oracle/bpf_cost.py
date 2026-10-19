"""Kernel-measured cost of the agent's BPF programs.

With kernel.bpf_stats_enabled=1 the kernel accounts run_time_ns / run_cnt
for every BPF program; they are exposed in /proc/<pid>/fdinfo/<prog fd>.
Prints total runs, total ns and mean ns per invocation for the TC
classifiers (per packet), then the same per program type for the others:
tracepoints (process lifecycle, and the sock_send/recv_length hooks that give
TLS connections their addresses, which run on every TCP send/receive),
uprobes/kprobes and fentry.
"""
import collections
import os
import sys

TYPES = {"3": "tc", "5": "tracepoint", "2": "kprobe/uprobe", "26": "fentry"}
pid = sys.argv[1]
stats = collections.defaultdict(lambda: [0, 0, 0])  # progs, runs, ns
for fd in os.listdir(f"/proc/{pid}/fd"):
    try:
        info = open(f"/proc/{pid}/fdinfo/{fd}").read()
    except OSError:
        continue
    fields = dict(l.split(":", 1) for l in info.splitlines() if ":" in l)
    kind = TYPES.get(fields.get("prog_type", "").strip())
    if not kind:
        continue
    s = stats[kind]
    s[0] += 1
    s[1] += int(fields.get("run_cnt", "0"))
    s[2] += int(fields.get("run_time_ns", "0"))
progs, runs, ns = stats["tc"]
print(f"tc_programs={progs} runs={runs} total_ns={ns} ns_per_packet={ns / max(runs, 1):.0f}")
for kind, (progs, runs, ns) in sorted(stats.items()):
    if kind != "tc":
        print(f"  {kind}: programs={progs} runs={runs} ns_per_run={ns / max(runs, 1):.0f}")
