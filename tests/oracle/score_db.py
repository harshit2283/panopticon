"""Score the agent's JSONL export against db_oracle.py ground truth.

Per truth operation (matched by its `tok_<id>_` token in the agent record's
path / payload / request body):
  recall, duplicates, command-verb accuracy, error-flag accuracy,
  recall by transport ("via": simple / extended / pipeline / text),
  PII visibility: operations that sent PII whose agent record has a PII finding,
  leaks: raw PII values present anywhere in the export, and the server
  password (env ORACLE_PASSWORD, if set: Redis sends it in AUTH) anywhere in it.

VIEWS (default 1) is how many sockets of each operation the agent sees: 2
when client and server both run on the node (run_protocols.sh). A record
carries no socket identity, so an operation counts as seen in every view
only when exactly VIEWS records with its verb match it; with MIN_RECALL,
that per-view recall must reach it too, so one socket's view failing fails
the run.

Usage: score_db.py TRUTH AGENT_JSONL [MIN_RECALL [VIEWS]]
"""
import collections
import json
import os
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
views = int(sys.argv[4]) if len(sys.argv) > 4 else 1
whole = [k for k in truth
         if len(seen[k]) == views
         and all((e.get("method") or "").upper() == truth[k]["verb"] for e in seen[k])]
print(f"  operations seen in all {views} view(s) with the verb: {len(whole)}/{n} "
      f"({len(whole)/n:.1%})")
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

password = os.environ.get("ORACLE_PASSWORD")
if password and password in export_text:
    sys.exit("the server password reached the export")
if len(sys.argv) > 3 and leaks:
    sys.exit(f"{len(leaks)} raw PII values reached the export")
if len(sys.argv) > 3 and len(found) / n < float(sys.argv[3]):
    sys.exit(f"recall {len(found)/n:.1%} below required {float(sys.argv[3]):.1%}")
if len(sys.argv) > 3 and len(whole) / n < float(sys.argv[3]):
    sys.exit(f"per-view recall {len(whole)/n:.1%} ({views} view(s)) below required "
             f"{float(sys.argv[3]):.1%}")
