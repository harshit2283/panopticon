"""Score the agent's JSONL export against db_oracle.py ground truth.

Per truth operation (matched by its `tok_<id>_` token in the agent record's
path / payload / request body):
  recall, duplicates, command-verb accuracy, error-flag accuracy,
  recall by transport ("via": simple / extended / pipeline / text),
  PII visibility: operations that sent PII whose agent record has a PII finding,
  leaks: raw PII values present anywhere in the export.

Usage: score_db.py TRUTH AGENT_JSONL [MIN_RECALL]
"""
import collections
import json
import re
import sys

truth = {}
for line in open(sys.argv[1]):
    t = json.loads(line)
    truth[t["id"]] = t
proto = next(iter(truth.values()))["proto"]
TOKEN = re.compile(r"tok_\d+_")

seen = collections.defaultdict(list)
for line in open(sys.argv[2]):
    e = json.loads(line)
    if e.get("protocol") != proto:
        continue
    text = " ".join(str(e.get(f) or "") for f in ("path", "payload_text", "request_body"))
    for tok in set(TOKEN.findall(text)):
        if tok in truth:
            seen[tok].append(e)

n = len(truth)
found = [k for k in truth if seen[k]]
dups = [k for k in found if len(seen[k]) > 1]
verb_ok = [k for k in found if (seen[k][0].get("method") or "").upper() == truth[k]["verb"]]
err_ok = [k for k in found if ((seen[k][0].get("status") or 0) != 0) == truth[k]["error"]]
print(f"{proto}: truth={n} recall={len(found)/n:.1%} ({len(found)}/{n}) duplicates={len(dups)}")
print(f"  verb accuracy={len(verb_ok)/max(len(found),1):.1%}  "
      f"error-flag accuracy={len(err_ok)/max(len(found),1):.1%}")
wrong_verbs = collections.Counter(
    (truth[k]["verb"], seen[k][0].get("method")) for k in found if k not in verb_ok)
if wrong_verbs:
    print("  verb mismatches (truth, agent):", dict(wrong_verbs.most_common(5)))

by_via = collections.defaultdict(lambda: [0, 0])
for k, t in truth.items():
    by_via[t.get("via") or "-"][1] += 1
    by_via[t.get("via") or "-"][0] += bool(seen[k])
print("  recall by transport:", {v: f"{a}/{b}" for v, (a, b) in sorted(by_via.items())})

by_verb = collections.defaultdict(lambda: [0, 0])
for k, t in truth.items():
    key = t["verb"] + (" (error)" if t["error"] else "")
    by_verb[key][1] += 1
    by_verb[key][0] += bool(seen[k])
print("  recall by operation:", {v: f"{a}/{b}" for v, (a, b) in sorted(by_verb.items())})

with_pii = [k for k in truth if truth[k]["pii"]]
pii_seen = [k for k in with_pii if any((e.get("pii") or {}).get("entities") for e in seen[k])]
export_text = open(sys.argv[2]).read()
leaks = [v for k in with_pii for v in truth[k]["pii"] if v in export_text]
print(f"  PII visibility: flagged in {len(pii_seen)}/{len(with_pii)} operations that sent PII; "
      f"raw PII values in export: {len(leaks)}")
pii_by_via = collections.defaultdict(lambda: [0, 0])
for k in with_pii:
    pii_by_via[truth[k].get("via") or "-"][1] += 1
    pii_by_via[truth[k].get("via") or "-"][0] += k in pii_seen
print("  PII visibility by transport:", {v: f"{a}/{b}" for v, (a, b) in sorted(pii_by_via.items())})

if len(sys.argv) > 3 and len(found) / n < float(sys.argv[3]):
    sys.exit(f"recall {len(found)/n:.1%} below required {float(sys.argv[3]):.1%}")
