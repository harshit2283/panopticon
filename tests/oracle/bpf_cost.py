"""Kernel-measured cost of the agent's TC classifiers.

With kernel.bpf_stats_enabled=1 the kernel accounts run_time_ns / run_cnt
for every BPF program; they are exposed in /proc/<pid>/fdinfo/<prog fd>.
Prints total runs, total ns and mean ns per invocation for sched_cls
(prog_type 3) programs held by the given pid.
"""
import os
import sys

pid = sys.argv[1]
runs = ns = progs = 0
for fd in os.listdir(f"/proc/{pid}/fd"):
    try:
        info = open(f"/proc/{pid}/fdinfo/{fd}").read()
    except OSError:
        continue
    fields = dict(l.split(":", 1) for l in info.splitlines() if ":" in l)
    if fields.get("prog_type", "").strip() != "3":
        continue
    progs += 1
    runs += int(fields.get("run_cnt", "0"))
    ns += int(fields.get("run_time_ns", "0"))
print(f"tc_programs={progs} runs={runs} total_ns={ns} ns_per_packet={ns / max(runs, 1):.0f}")
