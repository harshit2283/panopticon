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

Kafka Fetch and the body cap: the agent exports at most `max_body_bytes` of
a Fetch response's record text (event_loop.rs `scan_with_body_cap`), and
`cut_partial_token` drops a token the cut splits whole (a 2000-char pad can
pull the cut well below the cap). Records past that cut are not exported, by
design. A Fetch record whose text was cut (its byte length is the cap, or it
does not end on a complete record value) marks where its response stopped
being exported (only a response larger than the cap can be cut); a
consumed record that no Fetch record carries is counted as "past body cap",
not lost, only if its place after that cut is proven: it is in the cut
record's partition at a later offset, and its produce was acknowledged (a
Produce record with status 0 and a latency: its time is the response's)
before the cut response's
request left (response time minus latency), so the broker had it when it
built the response and the cut record's partition section runs through it
(the response under librdkafka's 1 MiB `max.partition.fetch.bytes`, which
mq_oracle.py leaves at its default, and the response's latency known). This
also assumes the broker reads past the cut record within one log segment: a
fetch returns data from one segment only, so a section can end at a segment
boundary however much the partition holds. The oracle's topics stay far
below the default `segment.bytes` (1 GiB) and roll no segment in a run; a
run that rolls one breaks this proof. It follows the cut record, the last
record before the cut, so it lies past the cut. Also, that response is in
the record's window (not before its produce, not after a response showing a
later token, not before the response showing its predecessor in the
partition), and no uncut response in that window names its topic in `path`
without showing a record of it (records lost there). Not proven, and so
lost: a record appended after the request left (the response may have been
built before it, its partition section ending at the cut record with the cut
in a later section, and the record dropped from a later response: the same
export), a record of a partition the response shows nothing of (whether its
section came before the cut record's, the record dropped, or after the cut
is not in the export), and a record without partition data.
`test_score_mq.py` checks these cases. Everything else missing is lost.
Recall is found / (operations - past body cap); the past-cap count is
printed beside it.

That exclusion assumes the capture lost nothing: a record lost to the
capture can look like one past the cut. It is made only when the leg's
/metrics (`--metrics PATH`, the file run_messaging.sh saves) shows every
loss counter at zero: kernel ring drops, TCP reorder gaps, truncated
captures, parser errors, and events dropped at the worker channel, the
export queue or the rate limit (`LOSS_COUNTERS`, summed over labels). With no
metrics file, an unreadable or absent counter, or any of them non-zero,
nothing is excluded and every missing record counts as lost.

The cap is `max_body_bytes` from the agent config (`--agent-config PATH`,
the file run_messaging.sh passes the agent), else the agent's default
(`DEFAULT_MAX_BODY_BYTES` in panopticon-agent/src/config.rs), clamped as the
agent clamps it.

Usage: score_mq.py TRUTH AGENT_JSONL [MIN_RECALL] [--agent-config PATH]
                   [--metrics PATH]
"""
import collections
import json
import os
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

args = sys.argv[1:]
agent_config = None
if "--agent-config" in args:
    at = args.index("--agent-config")
    agent_config = args[at + 1]
    del args[at:at + 2]
metrics_path = None
if "--metrics" in args:
    at = args.index("--metrics")
    metrics_path = args[at + 1]
    del args[at:at + 2]
# librdkafka's default `max.partition.fetch.bytes` (mq_oracle.py does not
# set it): a response smaller than this was not cut short by the broker's
# per-partition limit, so a partition section runs to the high watermark
# the broker saw.
PARTITION_MAX_BYTES = 1 << 20
# Loss counters that must all be zero before a missing Fetch record may be
# counted past the body cap rather than lost.
LOSS_COUNTERS = ("kernel_ringbuf_drops_total", "tcp_reorder_gaps_total",
                 "capture_truncated_total", "drops_parser_error_total",
                 "events_dropped_total", "drops_channel_full_total",
                 "drops_export_full_total", "drops_rate_limit_total")


def capture_lossless(path):
    """(True, "") if every LOSS_COUNTERS counter is in the metrics file and
    zero; else (False, why)."""
    if not path:
        return False, "no --metrics file"
    try:
        text = open(path).read()
    except OSError as e:
        return False, f"metrics unreadable ({e})"
    total = {}
    for line in text.splitlines():
        m = re.match(r"panopticon_(\w+?)(?:\{.*\})? (\S+)$", line)
        if m and m.group(1) in LOSS_COUNTERS:
            total[m.group(1)] = total.get(m.group(1), 0) + float(m.group(2))
    absent = [c for c in LOSS_COUNTERS if c not in total]
    if absent:
        return False, f"counters absent: {', '.join(absent)}"
    lost = {c: v for c, v in total.items() if v}
    if lost:
        return False, "loss counters non-zero: " + " ".join(f"{c}={v:g}" for c, v in lost.items())
    return True, ""
truth_path, export_path = args[0], args[1]
min_recall = float(args[2]) if len(args) > 2 else None
AGENT_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                         "panopticon-agent", "src", "config.rs")


def rust_const(name):
    """An integer `pub const NAME: usize = <a * b ...>;` from the agent's config.rs."""
    m = re.search(rf"pub const {name}: usize = ([0-9_ *]+);", open(AGENT_SRC).read())
    if not m:
        sys.exit(f"{name} not found in {AGENT_SRC}")
    value = 1
    for factor in m.group(1).split("*"):
        value *= int(factor.replace("_", ""))
    return value


def body_cap(config):
    """The agent's effective `max_body_bytes` and where it came from."""
    if config:
        for line in open(config):
            line = line.split("#", 1)[0].strip()
            if line.startswith("["):
                break  # top-level keys come before the first table
            m = re.fullmatch(r"max_body_bytes\s*=\s*([0-9_]+)", line)
            if m:
                cap = int(m.group(1).replace("_", ""))
                return min(cap, rust_const("MAX_BODY_BYTES_LIMIT")), config
    return rust_const("DEFAULT_MAX_BODY_BYTES"), "agent default"


truth = [json.loads(line) for line in open(truth_path)]
proto = truth[0]["proto"]
records = []
for line in open(export_path):
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


def seq(tok):
    return int(tok[4:-1])


def complete_value(line):
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


def past_body_cap(ops, cap):
    """Ids of Kafka fetch operations no Fetch record carries that lie past the
    body cap of the response that carried them (see the module docstring)."""
    fetches = sorted((e for e in records if e.get("method") == "Fetch"),
                     key=lambda e: e.get("timestamp_ns") or 0)
    # One response can be exported twice (one copy per capture point): a
    # response's time is its first copy's.
    first_ts = {}
    for e in fetches:
        key = (e.get("payload_text"), e.get("path"), e.get("response_size_bytes"),
               e.get("src_port"), e.get("dst_port"))
        ts = e.get("timestamp_ns") or 0
        if key not in first_ts or ts - first_ts[key] > 50_000_000:
            first_ts[key] = ts
        e["_resp_ts"] = first_ts[key]
    by_tok = {t["tokens"][0]: t for t in ops}
    shown = collections.defaultdict(list)  # token -> response times showing it
    for e in fetches:
        for tok in set(TOKEN.findall(e.get("payload_text") or "")):
            shown[tok].append(e["_resp_ts"])
    produced_at = {}  # token -> earliest time its record can have been appended
    # token -> earliest successful produce response carrying it (status 0
    # and a latency: the record's time is the response's; kafka.rs
    # `build_message`)
    acked_at = {}
    for e in records:
        if e.get("method") == "Fetch":
            continue
        start = (e.get("timestamp_ns") or 0) - (e.get("latency_ns") or 0)
        text = " ".join(str(e.get(f) or "") for f in ("path", "request_body"))
        for tok in set(TOKEN.findall(text)):
            produced_at[tok] = min(produced_at.get(tok, start), start)
            if e.get("method") == "Produce" and e.get("status") == 0 and e.get("latency_ns"):
                acked_at[tok] = min(acked_at.get(tok, e["timestamp_ns"]), e["timestamp_ns"])

    def place(t):
        return (t["path"], t.get("partition"))

    cut = []  # (response time, path topics, cut operation, request start)
    # (response time, topics its path names but none of whose records it
    # shows): an uncut response that lost records of those topics.
    short = []
    for e in fetches:
        text = e.get("payload_text") or ""
        size = len(text.encode())
        toks = TOKEN.findall(text)
        topics = (e.get("path") or "").split(",")
        inside = [by_tok[k] for k in set(toks) if k in by_tok]
        last = text.rsplit("\n", 1)[-1]
        # A response no larger than the cap was not cut by it.
        if (toks and size <= cap < (e.get("response_size_bytes") or 0)
                and (size == cap or text.endswith("\n") or not complete_value(last))):
            c = by_tok.get(toks[-1])
            if c is not None:
                # When the request left. Unknown (no latency), or a response
                # the broker's partition limit may have cut: -inf, which
                # proves no record in it.
                start = float("-inf")
                if e.get("latency_ns") and e["response_size_bytes"] < PARTITION_MAX_BYTES:
                    start = e["timestamp_ns"] - e["latency_ns"]
                cut.append((e["_resp_ts"], topics, c, start))
                continue
        short.append((e["_resp_ts"], set(topics) - {o["path"] for o in inside}))
    if any(len((e.get("payload_text") or "").encode()) > cap for e in fetches):
        print(f"    WARNING: Fetch text longer than the body cap {cap}: wrong cap?")

    def after_cut(t, topics, c, start):
        """Whether `t` is proven past the cut of the response that ends at
        `c` and whose request left at `start`."""
        if t["path"] not in topics or c["path"] not in topics:
            return False
        if t.get("partition") is None or c.get("partition") is None:
            return False  # no position to prove
        # A response is a sequence of partition sections. The record is in
        # this one only if the broker had it when the request arrived (its
        # produce acknowledged before the request left): the cut record's
        # section then runs from at most `c`'s offset through it. Following
        # `c`, the last record before the cut, it lies past the cut. A
        # record of another partition is never proven: whether its section
        # came before the cut record's (the record dropped) or after the
        # cut is not in the export, and neither is a record appended after
        # the request left (the section may end at `c`, the cut in a later
        # one, and the record dropped from a later response).
        return (place(t) == place(c) and t["offset"] > c["offset"]
                and acked_at.get(t["tokens"][0], float("inf")) < start)

    shown_ops = sorted((t for t in ops if shown.get(t["tokens"][0])),
                       key=lambda t: seq(t["tokens"][0]))
    out = set()
    for t in ops:
        tok = t["tokens"][0]
        if shown.get(tok) or tok not in produced_at:
            continue
        n = seq(tok)
        # Not after a response that shows a later-produced record: that one
        # was built after this record was appended, so carried it or later.
        upper = min((min(shown[o["tokens"][0]]) for o in shown_ops
                     if seq(o["tokens"][0]) > n), default=float("inf"))
        # Not before the response showing its predecessor in the topic /
        # partition (records of a partition arrive in offset order).
        prev = [o for o in shown_ops if place(o) == place(t) and seq(o["tokens"][0]) < n]
        lower = max(produced_at[tok], min(shown[prev[-1]["tokens"][0]]) if prev else 0)
        if any(lower <= ts <= upper and t["path"] in missing for ts, missing in short):
            continue  # an uncut response that could have carried it lost records
        if any(lower <= ts <= upper and after_cut(t, topics, c, start)
               for ts, topics, c, start in cut):
            out.add(t["id"])
    return out


def path_ok(t, e):
    got = e.get("path") or ""
    if t["kind"] == "fetch":  # one Fetch response can carry several topics
        return t["path"] in got.split(",")
    return got == t["path"]


scored = [t for t in truth if t["kind"] != "count"]
counts = [t for t in truth if t["kind"] == "count"]
print(f"{proto}: truth={len(scored)} operations, agent records={len(records)}")
status = 0
total_found = total = total_past = 0
for kind in sorted({t["kind"] for t in scored}):
    ops = [t for t in scored if t["kind"] == kind]
    seen = {t["id"]: matches(t) for t in ops}
    found = [t for t in ops if seen[t["id"]]]
    past = set()
    if proto == "kafka" and kind == "fetch":
        cap, cap_from = body_cap(agent_config)
        print(f"  fetch body cap: max_body_bytes={cap} ({cap_from})")
        lossless, why = capture_lossless(metrics_path)
        if lossless:
            past = past_body_cap(ops, cap)
        else:
            print(f"    no past-body-cap exclusion ({why}): every missing record is lost")
    ops_n = len(ops) - len(past)
    total += ops_n
    total_past += len(past)
    total_found += len(found)
    dups = sum(len(seen[t["id"]]) > 1 for t in found)
    nf = max(len(found), 1)
    first = {t["id"]: seen[t["id"]][0] for t in found}
    verb = sum((first[t["id"]].get("method") or "") == t["verb"] for t in found)
    path = sum(path_ok(t, first[t["id"]]) for t in found)
    st = sum((first[t["id"]].get("status") or 0) == t["status"] for t in found)
    past_note = (f" lost={ops_n - len(found)} past body cap={len(past)}"
                 if proto == "kafka" and kind == "fetch" else "")
    print(f"  {kind}: recall={len(found)/max(ops_n, 1):.1%} ({len(found)}/{ops_n}){past_note} "
          f"duplicates={dups}  method={verb/nf:.1%} path={path/nf:.1%} status={st/nf:.1%}")
    if past:
        print(f"    past body cap (not exported by design, not counted as lost): {len(past)}: "
              + " ".join(sorted(past, key=lambda i: seq(i.split(":")[-1]))))
    ops = [t for t in ops if t["id"] not in past]
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
export_text = open(export_path).read()
pii_values = {v for t in truth for v in t["pii"]}
leaks = [v for v in pii_values if v in export_text]
past_note = f", past body cap {total_past}" if proto == "kafka" else ""
print(f"  overall recall={total_found/max(total,1):.1%} ({total_found}/{total}{past_note}); "
      f"raw PII values in export: {len(leaks)}")
if min_recall is not None and leaks:
    sys.exit(f"{len(leaks)} raw PII values reached the export")
if min_recall is not None and total_found / max(total, 1) < min_recall:
    sys.exit(f"recall {total_found/max(total,1):.1%} below required {min_recall:.1%}")
