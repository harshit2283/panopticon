"""Score one run_sampling.sh run: did the capture scope hold in every sink?

Usage: score_sampling.py RUN DIR MIN_RECALL HTTP_SERVER_PID TLS_SERVER_PID HEAD_BYTES

DIR holds http/truth.jsonl (and tls/truth.jsonl for runs with the TLS leg)
from http_oracle.py, and the agent's sinks: agent.jsonl (export),
raw.pncap and its decoded raw.jsonl (raw dump), audit.jsonl, agent.log
(debug level, --log-events) and metrics.txt.
"""
import base64
import collections
import json
import math
import os
import re
import sys

run, d, min_recall = sys.argv[1], sys.argv[2], float(sys.argv[3])
http_sp, tls_sp, head = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6])
failures = []
KEYS = ("body_pii", "query_pii", "header_pii", "secrets")


def read(name):
    p = f"{d}/{name}"
    return open(p, "rb").read() if os.path.exists(p) else b""


def check(ok, what):
    print(f"  {'ok  ' if ok else 'FAIL'} {what}")
    if not ok:
        failures.append(what)


truth = {leg: [json.loads(l) for l in open(f"{d}/{leg}/truth.jsonl")]
         for leg in ("http", "tls") if os.path.exists(f"{d}/{leg}/truth.jsonl")}
export = [json.loads(l) for l in read("agent.jsonl").splitlines()]
raw = [json.loads(l) for l in read("raw.jsonl").splitlines()]
metrics = {m.group(1): float(m.group(2)) for m in
           re.finditer(rb"^(panopticon_\w+)\s+(\S+)$", read("metrics.txt"), re.M)}
metrics = {k.decode(): v for k, v in metrics.items()}
sinks = {name: read(f) for name, f in (("export", "agent.jsonl"), ("raw dump", "raw.pncap"),
                                       ("audit", "audit.jsonl"), ("log", "agent.log"),
                                       ("/metrics", "metrics.txt"))}


def exported_ids(tls):
    ids = collections.Counter()
    for e in export:
        m = re.search(r"[?&]id=(q\d+)", e.get("path") or "")
        if m and e.get("protocol") in ("http1", "http2") and (e.get("tls_library") is not None) == tls:
            ids[m.group(1)] += 1
    return ids


def leaks(values):
    """Sinks holding any of `values`, with a count."""
    out = {}
    for name, data in sinks.items():
        n = sum(v.encode() in data for v in values)
        if n:
            out[name] = n
    return out


def metric(name):
    return int(metrics.get(f"panopticon_{name}_total", -1))


print(f"==== {run}: {len(export)} exported records, {len(raw)} raw events")
print("  counters: " + ", ".join(f"{k}={metric(k)}" for k in (
    "pid_filter_dropped_events", "pid_filter_unknown_owner_connections",
    "sampled_out_connections", "sampled_out_events", "head_only_cut_events")))

if run == "pid_servers":
    for leg, tls in (("http", False), ("tls", True)):
        ids = exported_ids(tls)
        hit = sum(t["id"] in ids for t in truth[leg])
        n = len(truth[leg])
        check(hit >= min_recall * n, f"{leg} recall {hit}/{n} (server traffic captured)")
    # The TLS client process is not listed: its plaintext never left the kernel.
    pids = collections.Counter(e["pid"] for e in raw if e["event_type"] != "TcPacket")
    check(set(pids) <= {http_sp, tls_sp}, f"only listed processes in the raw dump: {dict(pids)}")
    twice = sum(c > 1 for c in exported_ids(True).values())
    check(twice == 0, f"no TLS exchange exported from the client too ({twice})")

elif run == "pid_other":
    check(not export, f"nothing exported ({len(export)})")
    check(not raw, f"nothing in the raw dump ({len(raw)})")
    values = [v for ts in truth.values() for t in ts for k in KEYS for v in t[k]]
    found = leaks(values + [f"id={t['id']}&" for ts in truth.values() for t in ts])
    check(not found, f"no planted value or request id in any sink ({len(values)} planted): {found}")
    check(metric("pid_filter_unknown_owner_connections") > 0,
          "unknown-owner connections counted")

elif run.startswith("sample_"):
    rate = int(run.split("_")[1]) / 100
    conns = collections.defaultdict(list)
    for t in truth["http"]:
        conns[t["conn"]].append(t["id"])
    ids = exported_ids(False)
    kept = [c for c, members in conns.items() if any(i in ids for i in members)]
    partial = [c for c in kept if not all(i in ids for i in conns[c])]
    n = len(conns)
    print(f"  connections kept {len(kept)}/{n} at rate {rate}")
    check(not partial, f"no partially exported connection ({len(partial)}: {partial[:5]})")
    if rate == 0:
        check(not export and not raw, f"nothing captured ({len(export)} exported, {len(raw)} raw)")
    elif rate == 1:
        hit = sum(t["id"] in ids for t in truth["http"])
        check(hit >= min_recall * len(truth["http"]), f"recall {hit}/{len(truth['http'])}")
        check(metric("sampled_out_events") == 0, "nothing sampled out")
    else:
        sd = math.sqrt(n * rate * (1 - rate))
        z = (len(kept) - n * rate) / sd
        check(abs(z) <= 3.5, f"kept share binomially plausible (z = {z:+.2f})")
    if rate < 1:
        out = metric("sampled_out_connections")
        check(abs(out - (n - len(kept))) <= 1,
              f"sampled_out_connections {out} matches the {n - len(kept)} connections not kept")

elif run == "head":
    # The raw dump holds exactly what passed the gate.
    per_dir = collections.Counter()
    for e in raw:
        if e["event_type"] == "TcPacket":
            key = ("tc", e["connection_id"], e["src"], e["src_port"])
        else:
            key = ("tls", e["pid"], e["connection_id"], e["direction"])
        per_dir[key] += len(base64.b64decode(e["payload_b64"]))
    worst = max(per_dir.values(), default=0)
    check(per_dir and worst <= head,
          f"no direction past {head} bytes ({len(per_dir)} directions, largest {worst})")
    payloads = b"".join(base64.b64decode(e["payload_b64"]) for e in raw)
    for leg in truth:
        firsts = [t for t in truth[leg] if t["pos"] == 0]
        hit = sum(f"id={t['id']}&".encode() in payloads for t in firsts)
        check(hit >= min_recall * len(firsts),
              f"{leg}: first request of {hit}/{len(firsts)} connections captured")
    # Requests from the third on start past HEAD bytes (each is > 300 bytes).
    late = [v for ts in truth.values() for t in ts if t["pos"] >= 2 for k in KEYS for v in t[k]]
    found = leaks(late)
    check(late and not found, f"none of {len(late)} values planted past the head in any sink: {found}")
    for e in export:
        for f in ("payload_text", "request_body"):
            if len(e.get(f) or "") > head:
                failures.append(f"exported {f} of {len(e[f])} bytes")
    check(metric("head_only_cut_events") > 0, "cut events counted")

for f in failures:
    print(f"  FAIL: {f}")
sys.exit(1 if failures else 0)
