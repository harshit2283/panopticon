"""Score the agent's JSONL export against grpc_oracle.py / h2_oracle.py truth.

Per truth call (matched by its `tok_<id>_` token anywhere in the agent
record: path, headers, request or response body): recall, duplicates, path
accuracy, status accuracy (grpc-status for gRPC, :status for HTTP/2), PII
visibility and raw PII leaks.

Usage: score_h2.py TRUTH AGENT_JSONL [MIN_RECALL]
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
protocols = collections.Counter()
for line in open(sys.argv[2]):
    e = json.loads(line)
    protocols[e.get("protocol")] += 1
    if e.get("protocol") not in ("grpc", "http2"):
        continue
    text = json.dumps([e.get("path"), e.get("headers"), e.get("request_body"), e.get("payload_text")])
    for tok in set(TOKEN.findall(text)):
        if tok in truth:
            seen[tok].append(e)

n = len(truth)
found = [k for k in truth if seen[k]]
dups = [k for k in found if len(seen[k]) > 1]
path_ok = [k for k in found if seen[k][0].get("path") == truth[k]["path"]]
expected_status = "grpc_status" if proto == "grpc" else "status"
status_ok = [k for k in found if seen[k][0].get("status") == truth[k][expected_status]]
print(f"{proto}: truth={n} recall={len(found)/n:.1%} ({len(found)}/{n}) duplicates={len(dups)}"
      f"  (agent protocols: {dict(protocols)})")
print(f"  path accuracy={len(path_ok)/max(len(found),1):.1%}  "
      f"status accuracy={len(status_ok)/max(len(found),1):.1%}")
bad = collections.Counter((truth[k][expected_status], seen[k][0].get("status"))
                          for k in found if k not in status_ok)
if bad:
    print("  status mismatches (truth, agent):", dict(bad.most_common(5)))
by_path = collections.defaultdict(lambda: [0, 0])
for k, t in truth.items():
    by_path[t["path"]][1] += 1
    by_path[t["path"]][0] += bool(seen[k])
print("  recall by path:", {p: f"{a}/{b}" for p, (a, b) in sorted(by_path.items())})

with_pii = [k for k in truth if truth[k]["pii"]]
pii_seen = [k for k in with_pii if any((e.get("pii") or {}).get("entities") for e in seen[k])]
export_text = open(sys.argv[2]).read()
leaks = [v for k in with_pii for v in truth[k]["pii"] if v in export_text]
print(f"  PII visibility: flagged in {len(pii_seen)}/{len(with_pii)} calls that sent PII; "
      f"raw PII values in export: {len(leaks)}")

if len(sys.argv) > 3 and len(found) / n < float(sys.argv[3]):
    sys.exit(f"recall {len(found)/n:.1%} below required {float(sys.argv[3]):.1%}")
