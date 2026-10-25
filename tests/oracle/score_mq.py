"""Score the agent's JSONL export against mq_oracle.py ground truth.

Each truth operation is matched to the agent records that carry one of its
tokens (`tok_<id>_`, in path / payload_text / request_body / header values)
*and* whose method belongs to the operation's role, since one token
legitimately travels in several records (a produced Kafka record comes back
in a Fetch; a published AMQP message comes back as Deliver / GetOk / Return):

  kind      records considered
  produce   Kafka records other than Fetch
  fetch     Kafka Fetch records (the record must be in the response)
  metadata  any Kafka record
  publish   AMQP Basic.Publish
  deliver   AMQP Basic.Deliver
  get       AMQP Basic.Get / Basic.GetOk
  return    AMQP Basic.Return
  query     any DNS record
  count     (AMQP Basic.Ack) number of client-sent records vs truth

Reports recall, duplicates (operations matched by more than one record),
accuracy of method, path (topic / exchange/routing-key / queue / qname) and
status (Kafka error code, AMQP reply code, DNS rcode); for DNS the query
type and answers (an IPv4 answer redacted to <IP_V4> by the PII policy
counts as present); for batched Kafka produce whether every record of the
batch is in the export; PII visibility; and leaks (raw PII values anywhere in
the export). Exits non-zero below MIN_RECALL or on any leak.

Usage: score_mq.py TRUTH AGENT_JSONL [MIN_RECALL]
"""
import collections
import json
import re
import sys

PROTO_NAME = {"kafka": "kafka", "amqp": "amqp", "dns": "dns"}
ROLE = {
    "produce": lambda m: m != "Fetch",
    "fetch": lambda m: m == "Fetch",
    "metadata": lambda m: True,
    "publish": lambda m: m == "Basic.Publish",
    "deliver": lambda m: m == "Basic.Deliver",
    "get": lambda m: m in ("Basic.Get", "Basic.GetOk"),
    "return": lambda m: m == "Basic.Return",
    "query": lambda m: True,
}
TOKEN = re.compile(r"tok_\d+_")
IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+")

truth = [json.loads(line) for line in open(sys.argv[1])]
proto = truth[0]["proto"]
records = []
for line in open(sys.argv[2]):
    e = json.loads(line)
    if e.get("protocol") == PROTO_NAME[proto]:
        records.append(e)

by_token = collections.defaultdict(list)
untokened = collections.Counter()
for idx, e in enumerate(records):
    text = " ".join(str(e.get(f) or "") for f in ("path", "payload_text", "request_body"))
    text += " " + " ".join(str(v) for _, v in e.get("headers") or [])
    toks = set(TOKEN.findall(text))
    for tok in toks:
        by_token[tok].append(idx)
    if not toks:
        untokened[e.get("method")] += 1


def matches(t):
    role = ROLE[t["kind"]]
    idx = sorted({i for tok in t["tokens"] for i in by_token[tok]
                  if role(records[i].get("method") or "")})
    return [records[i] for i in idx]


def path_ok(t, e):
    got = e.get("path") or ""
    if t["kind"] == "fetch":  # one Fetch response can carry several topics
        return t["path"] in got.split(",")
    return got == t["path"]


scored = [t for t in truth if t["kind"] != "count"]
counts = [t for t in truth if t["kind"] == "count"]
print(f"{proto}: truth={len(scored)} operations, agent records={len(records)}")
status = 0
min_recall = float(sys.argv[3]) if len(sys.argv) > 3 else None
total_found = total = 0
for kind in sorted({t["kind"] for t in scored}):
    ops = [t for t in scored if t["kind"] == kind]
    seen = {t["id"]: matches(t) for t in ops}
    found = [t for t in ops if seen[t["id"]]]
    total += len(ops)
    total_found += len(found)
    dups = sum(len(seen[t["id"]]) > 1 for t in found)
    nf = max(len(found), 1)
    first = {t["id"]: seen[t["id"]][0] for t in found}
    verb = sum((first[t["id"]].get("method") or "") == t["verb"] for t in found)
    path = sum(path_ok(t, first[t["id"]]) for t in found)
    st = sum((first[t["id"]].get("status") or 0) == t["status"] for t in found)
    print(f"  {kind}: recall={len(found)/len(ops):.1%} ({len(found)}/{len(ops)}) "
          f"duplicates={dups}  method={verb/nf:.1%} path={path/nf:.1%} status={st/nf:.1%}")
    bad = collections.Counter(
        (t["verb"], first[t["id"]].get("method"), t["status"], first[t["id"]].get("status"))
        for t in found
        if (first[t["id"]].get("method") or "") != t["verb"]
        or (first[t["id"]].get("status") or 0) != t["status"])
    if bad:
        print("    method/status mismatches (truth, agent):",
              {f"{a}/{c} -> {b}/{d}": n for (a, b, c, d), n in bad.most_common(4)})
    badp = collections.Counter((str(t["path"])[:40], str(first[t["id"]].get("path"))[:40])
                               for t in found if not path_ok(t, first[t["id"]]))
    if badp:
        print("    path mismatches (truth, agent), e.g.:", dict(badp.most_common(3)))
    by_via = collections.defaultdict(lambda: [0, 0])
    for t in ops:
        by_via[t.get("via") or "-"][1] += 1
        by_via[t.get("via") or "-"][0] += bool(seen[t["id"]])
    if len(by_via) > 1 or "-" not in by_via:
        print("    recall by variant:", {v: f"{a}/{b}" for v, (a, b) in sorted(by_via.items())})
    batches = [t for t in found if len(t["tokens"]) > 1]
    if batches:
        complete = sum(all(any(tok in json.dumps(e) for e in seen[t["id"]]) for tok in t["tokens"])
                       for t in batches)
        print(f"    batches with every record exported: {complete}/{len(batches)}")
    if proto == "dns":
        qt = sum(dict(map(tuple, first[t["id"]].get("headers") or [])).get("qtype") == t["qtype"]
                 for t in found)
        # IPv4 answers are redacted to <IP_V4> by the default PII policy.
        def has(text, a):
            return a in text or (IPV4.fullmatch(a) is not None and "<IP_V4>" in text)
        ans = sum(all(has(first[t["id"]].get("payload_text") or "", a) for a in t["answers"])
                  for t in found)
        print(f"    qtype={qt/nf:.1%} answers={ans/nf:.1%} (IPv4 answers may be redacted)")
    with_pii = [t for t in ops if t["pii"]]
    if with_pii:
        flagged = sum(any((e.get("pii") or {}).get("entities") for e in seen[t["id"]])
                      for t in with_pii)
        print(f"    PII visibility: flagged in {flagged}/{len(with_pii)} operations that sent PII")

for t in counts:
    n = sum(1 for e in records if e.get("method") == t["verb"] and e.get("direction") == "egress")
    print(f"  {t['verb']} sent by the client: agent={n} truth={t['count']}")

if untokened:
    print("  records without a token, by method:", dict(untokened.most_common(8)))
export_text = open(sys.argv[2]).read()
pii_values = {v for t in truth for v in t["pii"]}
leaks = [v for v in pii_values if v in export_text]
print(f"  overall recall={total_found/max(total,1):.1%} ({total_found}/{total}); "
      f"raw PII values in export: {len(leaks)}")
if min_recall is not None and leaks:
    sys.exit(f"{len(leaks)} raw PII values reached the export")
if min_recall is not None and total_found / max(total, 1) < min_recall:
    sys.exit(f"recall {total_found/max(total,1):.1%} below required {min_recall:.1%}")
