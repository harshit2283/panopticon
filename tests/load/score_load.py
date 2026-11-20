"""Capture recall at load: completed request ids (loadgen.go -out) vs the
agent's JSONL export.

Usage: score_load.py IDS AGENT_JSONL [MIN_RECALL]
"""
import collections
import json
import re
import sys

sent = set(l.strip() for l in open(sys.argv[1]) if l.strip())
ID = re.compile(r"[?&]id=(r\d+)")
seen = collections.Counter()
other = 0
for line in open(sys.argv[2]):
    e = json.loads(line)
    m = ID.search(e.get("path") or "")
    if m and m.group(1) in sent:
        seen[m.group(1)] += 1
    else:
        other += 1
found = len(seen)
dups = sum(1 for c in seen.values() if c > 1)
recall = found / max(len(sent), 1)
print(f"sent={len(sent)} recall={recall:.2%} ({found}) duplicates={dups} unmatched_records={other}")
if len(sys.argv) > 3 and recall < float(sys.argv[3]):
    sys.exit(f"recall {recall:.2%} below required {float(sys.argv[3]):.2%}")
