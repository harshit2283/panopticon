"""Score the agent's JSONL export against the generator's ground truth.

Per truth request (matched by its unique ?id= tag in the path):
  - recall: emitted at least once
  - duplicates: emitted more than once
  - field accuracy: method, status, response_size_bytes
Also counts agent records whose id is not in the truth (phantoms).

Usage: score.py TRUTH AGENT_JSONL [MIN_RECALL] [--withheld] [--exact]
                [--min-records=SHARE]
With MIN_RECALL, exits non-zero below it or if any raw PII value reached
the export. --withheld (HTTP/2 over TLS, where every key starts latched
and nothing is decoded) also exits non-zero if any record matches a truth
request (its path carries the request's id: the path was decoded) or any
record, of any protocol, attributed or not, carries a path, status,
content type or header: nothing header-derived may leave the agent.
--exact also exits non-zero on
any duplicate, on more HTTP records than truth requests, or (without
--withheld) on any phantom: each exchange exported once, as itself.
--min-records=SHARE exits non-zero on fewer HTTP records than SHARE of
the truth requests (the bar for --withheld, where no record carries an
id to match).
"""
import collections
import json
import re
import sys

flags = {a.split("=")[0] for a in sys.argv[1:] if a.startswith("--")}
options = dict(a.split("=", 1) for a in sys.argv[1:] if a.startswith("--") and "=" in a)
sys.argv = [a for a in sys.argv if not a.startswith("--")]
truth = {json.loads(l)["id"]: json.loads(l) for l in open(sys.argv[1])}
seen = collections.defaultdict(list)
phantom = 0
phantom_fields = collections.Counter()
phantom_keys = collections.Counter()  # every field a phantom carries
# --withheld: records of any protocol carrying a header-derived field.
withheld_fields = collections.Counter()
HEADER_FIELDS = ("path", "status", "content_type", "headers")
protocols = collections.Counter()
http_records = 0
for line in open(sys.argv[2]):
    e = json.loads(line)
    protocols[e.get("protocol")] += 1
    m = re.search(r"[?&]id=(q\d+)", e.get("path") or "")
    if "--withheld" in flags:
        for field in HEADER_FIELDS:
            withheld_fields[field] += bool(e.get(field))
    if e.get("protocol") not in ("http1", "http2"):  # same HTTP semantics
        continue
    http_records += 1
    if not m or m.group(1) not in truth:
        phantom += 1
        phantom_keys.update(k for k, v in e.items() if v not in (None, "", [], {}))
        for field in HEADER_FIELDS:
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
print("  agent protocols:", dict(protocols), f"HTTP records {http_records} for {n} requests")
print("  phantoms carrying path / status / content_type / headers:",
      {f: phantom_fields[f] for f in HEADER_FIELDS})
if "--withheld" in flags:
    print("  records (any protocol) carrying path / status / content_type / headers:",
          {f: withheld_fields[f] for f in HEADER_FIELDS})
if phantom:
    print("  fields phantoms carry:", dict(sorted(phantom_keys.items())))
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
if "--withheld" in flags and found:
    sys.exit(f"{len(found)} records carry a truth request's path: decoded, not withheld")
if "--withheld" in flags and sum(withheld_fields.values()):
    sys.exit(f"records carry header-derived fields: {dict(withheld_fields)}")
if "--exact" in flags:
    if dups:
        sys.exit(f"{len(dups)} requests exported more than once")
    if http_records > n:
        sys.exit(f"{http_records} HTTP records for {n} requests")
    if phantom and "--withheld" not in flags:
        sys.exit(f"{phantom} records match no request")
if "--min-records" in flags and http_records < float(options["--min-records"]) * n:
    sys.exit(f"{http_records} HTTP records for {n} requests, below "
             f"{float(options['--min-records']):.1%}")
if len(sys.argv) > 3 and len(found) / n < float(sys.argv[3]):
    sys.exit(f"recall {len(found)/n:.1%} below required {float(sys.argv[3]):.1%}")
