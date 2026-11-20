"""Score the agent's JSONL export against the generator's ground truth.

Per truth request (matched by its unique ?id= tag in the path):
  - recall: emitted at least once
  - duplicates: emitted more than once
  - field accuracy: method, status, response_size_bytes
Also counts agent records whose id is not in the truth (phantoms).

Usage: score.py TRUTH AGENT_JSONL [MIN_RECALL] [--withheld]
With MIN_RECALL, exits non-zero below it or if any raw PII value reached
the export. --withheld (connections whose TLS keys were reused, which the
agent never decodes again) also exits non-zero if any phantom carries a
path, status, content type or header: a record the agent could not
attribute must be withheld, not guessed.
"""
import collections
import json
import re
import sys

flags = {a for a in sys.argv[1:] if a.startswith("--")}
sys.argv = [a for a in sys.argv if not a.startswith("--")]
truth = {json.loads(l)["id"]: json.loads(l) for l in open(sys.argv[1])}
seen = collections.defaultdict(list)
phantom = 0
phantom_fields = collections.Counter()
protocols = collections.Counter()
for line in open(sys.argv[2]):
    e = json.loads(line)
    protocols[e.get("protocol")] += 1
    m = re.search(r"[?&]id=(q\d+)", e.get("path") or "")
    if e.get("protocol") not in ("http1", "http2"):  # same HTTP semantics
        # Under --withheld a record of any other protocol is unattributed
        # too: it must carry no header-derived field either.
        if "--withheld" in flags and not (m and m.group(1) in truth):
            for field in ("path", "status", "content_type", "headers"):
                phantom_fields[field] += bool(e.get(field))
        continue
    if not m or m.group(1) not in truth:
        phantom += 1
        for field in ("path", "status", "content_type", "headers"):
            phantom_fields[field] += bool(e.get(field))
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
print("  agent protocols:", dict(protocols))
print("  phantoms carrying path / status / content_type / headers:",
      {f: phantom_fields[f] for f in ("path", "status", "content_type", "headers")})
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

# Request bodies: every POST must carry its (redacted) body, and no raw PII
# value from any request body may appear anywhere in the agent's export.
# Bodies are cut at max_body_bytes (4 KB) before scanning and export. A
# value past the cut is never exported, so it needs no placeholder: Go's
# encoder sorts keys (email, note, ssn), which puts the SSN of the 5 KB
# POSTs past the cut. A complete JSON body ends with "}"; a cut one does not.
posts = [k for k in found if truth[k]["method"] == "POST"]
with_body = [k for k in posts if seen[k][0].get("request_body")]
redacted, cut = [], []
for k in with_body:
    body = seen[k][0]["request_body"]
    complete = body.rstrip().endswith("}")
    marks = [("<EMAIL>" if "@" in v else "<SSN>") in body for v in truth[k]["body_pii"]]
    if all(marks):
        redacted.append(k)
    elif not complete:
        cut.append(k)
export_text = open(sys.argv[2]).read()
leaks = [v for t in truth.values() for v in t.get("body_pii", []) if v in export_text]
print(f"  request bodies: captured {len(with_body)}/{len(posts)} POSTs, "
      f"PII redacted in {len(redacted)}/{len(with_body) - len(cut)} "
      f"({len(cut)} cut at max_body_bytes before a PII value, never exported), "
      f"raw PII values leaked: {len(leaks)}")

# Optional gate: score.py truth agent MIN_RECALL (e.g. 0.99) exits 1 below it.
if len(sys.argv) > 3 and leaks:
    sys.exit(f"{len(leaks)} raw PII values reached the export")
if "--withheld" in flags and sum(phantom_fields.values()):
    sys.exit(f"phantoms carry header-derived fields: {dict(phantom_fields)}")
if len(sys.argv) > 3 and len(found) / n < float(sys.argv[3]):
    sys.exit(f"recall {len(found)/n:.1%} below required {float(sys.argv[3]):.1%}")
