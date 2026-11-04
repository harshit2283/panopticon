"""Score one run_modes.sh agent run: does each sink hold only what the
privacy mode promises?

Usage: score_modes.py MODE DIR MIN_RECALL

DIR holds the run's sinks and one truth file per traffic leg:
  http/truth.jsonl, tls/truth.jsonl   ground truth (http_oracle.py, PLANT=...)
  agent.log      agent stdout+stderr (run with -v: debug level)
  audit.jsonl    PII audit log
  metrics.txt    /metrics scrape;  debug_state.json   /debug/state
  agent.jsonl    event export      (full, redacted only)
  raw.pncap      raw dump          (full only), raw.pcap its pcap conversion

Planted values: every PII value in the truth (body, query string, header).
Fails when a planted value is in a sink the mode forbids, when the full-mode
dump misses them, or when recall is below MIN_RECALL. Recall is the share of
truth requests in the export (full, redacted) and, in every mode, PII
detections in the audit log against what was planted (each TLS exchange is
seen from both processes, so twice).
"""
import collections
import json
import os
import re
import sys

mode, d, min_recall = sys.argv[1], sys.argv[2], float(sys.argv[3])
LEGS = {"http": 1, "tls": 2}  # views per exchange
failures = []

truth = {leg: [json.loads(l) for l in open(f"{d}/{leg}/truth.jsonl")] for leg in LEGS}
planted = {leg: [v for t in ts for k in ("body_pii", "query_pii", "header_pii") for v in t[k]]
           for leg, ts in truth.items()}
values = [v.encode() for vs in planted.values() for v in vs]
# A payload-derived string that is not PII: the request id in every path.
ID_RE = re.compile(rb"[?&]id=q\d+")


def read(name):
    p = f"{d}/{name}"
    return open(p, "rb").read() if os.path.exists(p) else None


# Agent log, split by level. Lines without a level (panic output,
# continuation lines) count as info and above.
ansi = re.compile(rb"\x1b\[[0-9;]*m")
levels = re.compile(rb"^\S+\s+(TRACE|DEBUG|INFO|WARN|ERROR)\s")
log_lo, log_hi = [], []
for line in (read("agent.log") or b"").splitlines():
    line = ansi.sub(b"", line)
    m = levels.match(line)
    (log_lo if m and m.group(1) in (b"TRACE", b"DEBUG") else log_hi).append(line)

sinks = {
    "export (agent.jsonl)": read("agent.jsonl"),
    "raw dump (raw.pncap)": read("raw.pncap"),
    "pcap (raw.pcap)": read("raw.pcap"),
    "audit log": read("audit.jsonl"),
    "log info+": b"\n".join(log_hi),
    "log debug": b"\n".join(log_lo),
    "/metrics": read("metrics.txt"),
    "/debug/state": read("debug_state.json"),
}
# Sinks each mode must keep free of planted values (and, for metrics_only,
# of any payload-derived string).
forbidden = {
    "full": set(),
    "redacted": {"export (agent.jsonl)", "audit log", "log info+", "/metrics", "/debug/state"},
    "metrics_only": {"audit log", "log info+", "/metrics", "/debug/state"},
}[mode]
files = {"export (agent.jsonl)", "raw dump (raw.pncap)", "pcap (raw.pcap)"}
must_exist = {
    "full": files,
    "redacted": {"export (agent.jsonl)"},
    "metrics_only": set(),
}[mode] | {"audit log", "/metrics", "/debug/state"}

print(f"==== mode={mode}: {len(values)} planted values "
      f"({', '.join(f'{leg} {len(v)}' for leg, v in planted.items())})")
for name, data in sinks.items():
    if data is None:
        print(f"  {name:22s} absent")
        if name in must_exist:
            failures.append(f"{name} missing")
        continue
    if name in files - must_exist:
        failures.append(f"{name} exists in mode {mode}")
    found = sum(v in data for v in values)
    ids = len(ID_RE.findall(data))
    rule = "forbidden" if name in forbidden else "allowed"
    print(f"  {name:22s} planted values found {found}/{len(values)}, request ids {ids}  [{rule}]")
    if name in forbidden and found:
        examples = [v.decode() for v in values if v in data][:3]
        failures.append(f"{found} planted values in {name}, e.g. {examples}")
    if mode == "metrics_only" and name in forbidden and ids:
        failures.append(f"{ids} request paths (payload-derived) in {name}")
    if mode == "full" and name.startswith(("raw dump", "pcap")) and found < min_recall * len(values):
        failures.append(f"{name} holds only {found}/{len(values)} planted values")

# Recall from the export: truth requests seen at least once.
export = sinks["export (agent.jsonl)"]
if export is not None:
    seen = collections.defaultdict(set)
    for line in export.splitlines():
        e = json.loads(line)
        m = re.search(r"[?&]id=(q\d+)", e.get("path") or "")
        if m and e.get("protocol") in ("http1", "http2"):
            seen[m.group(1)].add(e.get("tls_library") is not None)
    for leg in LEGS:
        tls = leg == "tls"
        n = len(truth[leg])
        hit = sum(tls in seen[t["id"]] for t in truth[leg])
        print(f"  export recall {leg}: {hit}/{n} = {hit / n:.1%}")
        if hit < min_recall * n:
            failures.append(f"export recall {leg} {hit / n:.1%} below {min_recall:.0%}")
    if mode == "redacted":
        redacted = export.count(b"<EMAIL>")
        print(f"  export <EMAIL> placeholders: {redacted}")

# PII recall from the audit log: detections by category vs planted.
audit = collections.Counter(json.loads(l)["category"] for l in (sinks["audit log"] or b"").splitlines())
want = collections.Counter()
for leg, views in LEGS.items():
    for t in truth[leg]:
        want["Email"] += views * (len(t["query_pii"]) + len(t["header_pii"]) + (1 if t["body_pii"] else 0))
        want["Ssn"] += views * (1 if t["body_pii"] else 0)
for cat in ("Email", "Ssn"):
    r = min(audit[cat] / max(want[cat], 1), 1.0)
    print(f"  audit {cat}: {audit[cat]} detections / {want[cat]} planted = {r:.1%}")
    if r < min_recall:
        failures.append(f"audit recall {cat} {r:.1%} below {min_recall:.0%}")

for f in failures:
    print(f"  FAIL: {f}")
sys.exit(1 if failures else 0)
