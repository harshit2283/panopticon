"""Score the agent's JSONL export against the generator's ground truth.

Per truth request (matched by its unique ?id= tag in the path):
  - recall: emitted at least once
  - duplicates: emitted more than once
  - field accuracy: method, status, response_size_bytes
Also counts agent records whose id is not in the truth (phantoms).
"""
import collections
import json
import re
import sys

truth = {json.loads(l)["id"]: json.loads(l) for l in open(sys.argv[1])}
seen = collections.defaultdict(list)
phantom = 0
for line in open(sys.argv[2]):
    e = json.loads(line)
    if e.get("protocol") != "http1":
        continue
    m = re.search(r"[?&]id=(q\d+)", e.get("path") or "")
    if not m or m.group(1) not in truth:
        phantom += 1
        continue
    seen[m.group(1)].append(e)

n = len(truth)
found = [k for k in truth if seen[k]]
dups = [k for k in found if len(seen[k]) > 1]
wrong = collections.Counter()
examples = collections.defaultdict(list)
for k in found:
    t, e = truth[k], seen[k][0]
    for field, a, b in (("method", t["method"], e.get("method")),
                        ("status", t["status"], e.get("status")),
                        ("response_size", t["response_size"], e.get("response_size_bytes"))):
        if a != b:
            wrong[field] += 1
            if len(examples[field]) < 3:
                examples[field].append(f"{t['path']}: truth={a} agent={b}")

missing = [k for k in truth if not seen[k]]
by_kind = collections.Counter(truth[k]["path"].split("?")[0].rsplit("/", 1)[0] if truth[k]["path"].count("/") > 1 else truth[k]["path"].split("?")[0] for k in missing)
print(f"truth={n} recall={len(found)/n:.1%} ({len(found)}/{n}) duplicates={len(dups)} phantoms={phantom}")
for f in ("method", "status", "response_size"):
    print(f"  {f:14s} accuracy={1 - wrong[f]/max(len(found),1):.1%}  {examples[f]}")
print("  missing by endpoint:", dict(by_kind))

pos_total = collections.Counter(t["pos"] for t in truth.values())
pos_found = collections.Counter(truth[k]["pos"] for k in found)
print("  recall by position in keep-alive connection:",
      {p: f"{pos_found[p]}/{pos_total[p]}" for p in sorted(pos_total)[:6]})
prev_kind = collections.Counter()
for k in missing:
    t = truth[k]
    if t["pos"] > 0:
        prev = next(v for v in truth.values() if v["conn"] == t["conn"] and v["pos"] == t["pos"] - 1)
        prev_kind[prev["path"].split("?")[0]] += 1
print("  missing (pos>0) by PREVIOUS request on same conn:", dict(prev_kind.most_common(8)))

# Optional gate: score.py truth agent MIN_RECALL (e.g. 0.99) exits 1 below it.
if len(sys.argv) > 3 and len(found) / n < float(sys.argv[3]):
    sys.exit(f"recall {len(found)/n:.1%} below required {float(sys.argv[3]):.1%}")
