"""Self-test of score_mq.py's Kafka "past body cap" exclusion.

Runs the scorer as a subprocess on small hand-built truth / export /
metrics / agent-config fixtures (no broker, no agent) and checks how it
classifies a consumed record no Fetch record carries:

  unproven  A cut response R shows one record c (partition 0, offset 10)
            whole and stops at the cut; the next record t (offset 11) is
            shown nowhere; a later uncut response shows t's successor.
            R's request started before t's produce was acknowledged, so R
            may have been built before t was appended: its partition-0
            section may end at c (the cut in another section), with t in
            the later response, dropped there. The same export comes from
            t past R's cut. Not provable: t must count as lost.
  proven    The same, but t's produce was acknowledged before R's request
            started: the broker had t when R was built, so R's section
            runs from c (offset 10) through t, and t, shown nowhere after
            c, the last record before the cut, lies past it. Excused.
  other_partition
            As `proven`, but t is in partition 1, of which R shows
            nothing: whether its section came before c's (t dropped) or
            after the cut is not in the export. Lost.
  no_response
            As `proven`, but t's Produce record has no response (no
            status, no latency): nothing shows when t was appended. Lost.
  no_partition
            As `proven`, but t's truth has no partition or offset: its
            place in R is unknown. Lost.
  large_response
            As `proven`, but R is 1 MiB or more: the broker's per-partition
            limit (`max.partition.fetch.bytes`) may have ended c's section
            at c. Lost.
  no_fetch_latency
            As `proven`, but R has no latency: when its request left is
            unknown. Lost.
  ack_at_request
            t's produce acknowledged exactly when R's request left: not
            before it. Lost.
  ack_after_request
            Acknowledged 1 ns after R's request left. Lost.

Usage: python3 -I test_score_mq.py [SCORER]   (default: score_mq.py beside
this file). Exits non-zero on any failed case.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCORER = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "score_mq.py")
CAP = 256
TOPIC = "o3.a"
LOSS_COUNTERS = ("kernel_ringbuf_drops_total", "tcp_reorder_gaps_total",
                 "capture_truncated_total", "drops_parser_error_total",
                 "events_dropped_total", "drops_channel_full_total",
                 "drops_export_full_total", "drops_rate_limit_total")
MS = 1_000_000


def value(n):
    return json.dumps({"id": f"tok_{n}_", "seq": n})


def produce(n, start, ack, answered=True):
    e = {"protocol": "kafka", "method": "Produce", "path": TOPIC,
         "request_body": f"k-tok_{n}_\n{value(n)}", "timestamp_ns": ack}
    if answered:
        e.update(status=0, latency_ns=ack - start)
    return e


def fetch(text, start, end, size, port):
    e = {"protocol": "kafka", "method": "Fetch", "path": TOPIC, "status": 0,
         "payload_text": text, "response_size_bytes": size,
         "timestamp_ns": end, "src_port": 9092, "dst_port": port}
    if start is not None:
        e["latency_ns"] = end - start
    return e


R_START = 160 * MS  # when R's request left


def fixture(t_ack=150 * MS, t_partition=0, answered=True, r_size=4 * CAP, r_latency=True):
    """(truth, export) of records 1 (c), 2 (t), 3 (t's successor)."""
    truth, export = [], []
    parts = {1: (0, 10), 2: (t_partition, 11), 3: (0, 12)}
    for n, (part, off) in parts.items():
        truth.append({"id": f"tok_{n}_", "proto": "kafka", "kind": "produce",
                      "verb": "Produce", "path": TOPIC, "status": 0,
                      "tokens": [f"tok_{n}_"], "pii": [], "via": "single"})
        where = {} if part is None else {"partition": part, "offset": off}
        truth.append({"id": f"fetch:tok_{n}_", "proto": "kafka", "kind": "fetch",
                      "verb": "Fetch", "path": TOPIC, "status": 0,
                      "tokens": [f"tok_{n}_"], "pii": [], "via": "consume", **where})
    export.append(produce(1, 100 * MS, 110 * MS))
    export.append(produce(2, t_ack - 10 * MS, t_ack, answered))
    export.append(produce(3, 300 * MS, 310 * MS))
    # R: record 1 whole, then the cut inside a record whose token it took.
    cut_text = f"k-tok_1_\n{value(1)}\n" + "{" + "x" * (CAP - len(value(1)) - 11)
    assert len(cut_text.encode()) <= CAP
    export.append(fetch(cut_text, R_START if r_latency else None, 260 * MS, r_size, 40001))
    # A later uncut response with record 3 alone.
    export.append(fetch(f"k-tok_3_\n{value(3)}", 320 * MS, 400 * MS, 120, 40001))
    return truth, export


CASES = {
    # name: (fixture arguments, expected (lost, past body cap))
    "unproven": ({"t_ack": 210 * MS}, (1, 0)),
    "proven": ({}, (0, 1)),
    "other_partition": ({"t_partition": 1}, (1, 0)),
    "no_response": ({"answered": False}, (1, 0)),
    "no_partition": ({"t_partition": None}, (1, 0)),
    "large_response": ({"r_size": 1 << 20}, (1, 0)),
    "no_fetch_latency": ({"r_latency": False}, (1, 0)),
    "ack_at_request": ({"t_ack": R_START}, (1, 0)),
    "ack_after_request": ({"t_ack": R_START + 1}, (1, 0)),
}


def run(name, args, d):
    truth, export = fixture(**args)
    paths = {k: os.path.join(d, f"{name}-{k}") for k in ("truth", "export", "metrics", "cfg")}
    with open(paths["truth"], "w") as f:
        f.writelines(json.dumps(t) + "\n" for t in truth)
    with open(paths["export"], "w") as f:
        f.writelines(json.dumps(e) + "\n" for e in export)
    with open(paths["metrics"], "w") as f:
        f.writelines(f"panopticon_{c} 0\n" for c in LOSS_COUNTERS)
    with open(paths["cfg"], "w") as f:
        f.write(f"max_body_bytes = {CAP}\n")
    out = subprocess.run(
        [sys.executable, "-I", SCORER, paths["truth"], paths["export"],
         "--agent-config", paths["cfg"], "--metrics", paths["metrics"]],
        capture_output=True, text=True)
    m = re.search(r"fetch: recall=.* lost=(\d+) past body cap=(\d+)", out.stdout)
    if not m:
        return None, out.stdout + out.stderr
    return (int(m.group(1)), int(m.group(2))), out.stdout


def main():
    failed = 0
    with tempfile.TemporaryDirectory() as d:
        for name, (args, want) in CASES.items():
            got, out = run(name, args, d)
            ok = got == want
            failed += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name}: (lost, past body cap) "
                  f"want {want} got {got}")
            if not ok:
                print("    " + out.strip().replace("\n", "\n    "))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
