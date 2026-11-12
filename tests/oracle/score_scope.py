"""Score one run_scope.sh agent run against what may leave the node.

Usage: score_scope.py DIR CHECK...

DIR holds the run's sinks: agent.log (stdout + stderr, --log-events, -v),
agent.jsonl (event export), audit.jsonl (PII audit), raw.pncap (raw dump)
and raw.jsonl (its decode), metrics.txt and debug_state.json (scraped at
the end), and one truth file per traffic tag, TAG.truth.jsonl
(scope_traffic.py / scope_go_tls.go). A marker is B2M-<TAG>-<seq>. With
DIR/stop_t (epoch seconds), truth after it is ignored (traffic that ran on
while the agent stopped).

Checks:
  none:TAG            no marker of TAG in any sink
  ip:TAG:IP[,IP]      no IP (dotted, or as the export's u32) in any sink
  some:TAG            at least one TAG marker in the export
  truth:TAG           TAG's traffic ran (its truth file is not empty)
  notruth:TAG         TAG's traffic never completed a request (blocked)
  recall:TAG:R        share of TAG's truth markers in the export >= R
  narrow:TAG[:IP,..]  with DIR/narrowed.json ({"t", "offsets", "until"}): no
                      TAG marker sent at or after t (and over 0.5 s before
                      "until", if set) in any sink; no TAG marker, and not IP, in any
                      sink's bytes written after the change was reported
                      applied (offsets), up to the sizes just before the
                      next change started ("until_offsets")
  restart:TAG:R       TAG's client ran more than once (a container restart);
                      recall of the last run's markers >= R
  widened:TAG:R       with DIR/widened.json ({"t", "until"}): recall of TAG's
                      markers sent from t + 1 s (to "until", if set) >= R
  reads:TAG:R         TLS reads: share of TAG's truth markers in a raw-dump
                      TLS Ingress event of the client process (the reply it
                      read) >= R, and the same in one of another process
                      (the request the server read) >= R
  noaddr:TAG          export events with a TAG marker carry no address
  addr:TAG:R          share of export events with a TAG marker that carry
                      an address >= R
  inport:TAG:PORT     no TAG marker in a raw-dump event on PORT
  someport:TAG:PORT   some TAG marker in a raw-dump event on PORT
  someport:PORT       some raw-dump event on PORT
  noport:PORT         no raw-dump or export event on PORT
  tuples:TAG          the raw dump's tuples of TAG's connections, per view
                      (client: a local address in expect.json's
                      comma-separated client_ip) and direction,
                      are exactly DIR/expect.json's (E: any port it does
                      not name: the client's, possibly NAT-remapped)
  drvok:TAG           DIR/TAG.out says the fixture finished ("OK")
  exit:nonzero        the agent did not start (DIR/agent.exit)
  info:TAG            report (never fails) how many TAG markers were exported
                      and how many of their export events carry an address
  drop:REASON         panopticon_scope_dropped_events_total{reason} > 0
  log:REGEX           the agent log matches REGEX
  nolog:REGEX         the agent log does not match REGEX
Exits non-zero if any check fails.
"""
import base64
import json
import os
import re
import socket
import struct
import sys

d = sys.argv[1]
failures = []


def read(name):
    p = os.path.join(d, name)
    return open(p, "rb").read() if os.path.exists(p) else b""


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        failures.append(what)


def jsonl(name):
    out = []
    for line in read(name).splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


ansi = re.compile(rb"\x1b\[[0-9;]*m")
FILES = ["agent.log", "agent.jsonl", "audit.jsonl", "raw.pncap", "metrics.txt",
         "debug_state.json", "metrics_after.txt", "debug_after.json"]
data = {f: read(f) for f in FILES}
# Raw bytes: narrowed.json's offsets index the file as written.
log_text = ansi.sub(b"", data["agent.log"])
export = jsonl("agent.jsonl")


def sinks():
    yield from data.items()
    yield "raw payloads", raw_payloads


# Traffic that outlives the agent (pods, stopped after it) counts only up
# to 0.5 s before DIR/stop_t, when the run began to stop.
STOP = float(read("stop_t") or "inf") - 0.5


def truth(tag):
    return [t for t in jsonl("%s.truth.jsonl" % tag) if t["t"] < STOP]


def ip_patterns(ips):
    out = []
    for ip in filter(None, ips.split(",")):
        n = struct.unpack("!I", socket.inet_aton(ip))[0]
        out += [re.compile(rb"(?<![\d.])" + re.escape(ip.encode()) + rb"(?![\d])"),
                re.compile(rb"(?<![\d.])%d(?![\d.])" % n)]
    return out


raw_events = jsonl("raw.jsonl")
for e in raw_events:
    e["data"] = base64.b64decode(e.get("payload_b64", ""))


# The raw dump's payloads, decoded (base64 in raw.jsonl).
raw_payloads = b"\n".join(e["data"] for e in raw_events)


def on_port(e, port):
    return port in (e.get("src_port"), e.get("dst_port"))


def scope_drops(reason):
    m = re.search(rb'^panopticon_scope_dropped_events_total\{reason="%s"\} (\S+)' % reason.encode(),
                  data["metrics.txt"], re.M)
    return float(m.group(1)) if m else 0


def exported(tag):
    """Markers of TAG in the export."""
    pat = re.compile(r"B2M-%s-\d+" % re.escape(tag))
    return {m for e in export for m in pat.findall(json.dumps(e))}


for c in sys.argv[2:]:
    kind, _, arg = c.partition(":")
    if kind == "none":
        mark = ("B2M-%s-" % arg).encode()
        hits = [n for n, b in sinks() if mark in b]
        check(not hits, "no %s marker in any sink%s" % (arg, " (found in %s)" % hits if hits else ""))
    elif kind == "ip":
        tag, ip = arg.split(":")
        pats = ip_patterns(ip)
        hits = [n for n, b in sinks() if any(p.search(b) for p in pats)]
        check(not hits, "%s (%s) in no sink%s" % (ip, tag, " (found in %s)" % hits if hits else ""))
    elif kind == "some":
        check(exported(arg), "%s: %d markers in the export (want some)" % (arg, len(exported(arg))))
    elif kind == "info":
        mark = "B2M-%s-" % arg
        evs = [e for e in export if mark in json.dumps(e)]
        print("  info %s: %d markers exported of %d sent; %d of %d export events carry an address"
              % (arg, len(exported(arg)), len(truth(arg)), sum(bool(e.get("src_addr")) for e in evs), len(evs)))
    elif kind == "truth":
        check(truth(arg), "%s traffic ran (%d requests)" % (arg, len(truth(arg))))
    elif kind == "notruth":
        check(not truth(arg), "%s traffic blocked (%d requests completed, want 0)" % (arg, len(truth(arg))))
    elif kind == "drvok":
        out = read("%s.out" % arg)
        check(out.startswith(b"OK"), "%s fixture: %s" % (arg, out.decode(errors="replace").strip()[:200]))
    elif kind == "exit":
        out = read("agent.exit").decode()
        check("started" not in out and re.search(r"agent exit [1-9]", out), "agent refused to start (%s)" % out.strip())
    elif kind in ("inport", "someport", "noport"):
        parts = arg.split(":")
        port = int(parts[-1])
        evs = [e for e in raw_events if on_port(e, port)]
        if kind == "noport":
            ex = [e for e in export if on_port(e, port)]
            check(not evs and not ex, "port %d: %d raw, %d export events (want none)" % (port, len(evs), len(ex)))
        elif len(parts) == 1:
            check(evs, "port %d: %d raw events (want some)" % (port, len(evs)))
        else:
            mark = ("B2M-%s-" % parts[0]).encode()
            n = sum(mark in e["data"] for e in evs)
            if kind == "inport":
                check(n == 0, "port %d: %d of %d raw events carry %s markers (want none)" % (port, n, len(evs), parts[0]))
            else:
                check(n > 0, "port %d: %d of %d raw events carry %s markers (want some)" % (port, n, len(evs), parts[0]))
    elif kind == "tuples":
        want = json.loads(read("expect.json"))[arg]
        client = want.pop("client_ip").split(",")
        # Every port the expectation does not name is the client's own, as
        # bound or as NAT remapped it on a conntrack clash (ingress is seen
        # after every translation, §2.3).
        fixed = {int(p) for v in want.values() for p in re.findall(r":(\d+)", v)}
        mark = ("B2M-%s-" % arg).encode()
        seen = {}
        for e in raw_events:
            if mark not in e["data"]:
                continue
            local = e["src"] if e["direction"] == "Egress" else e["dst"]
            view = "%s %s" % ("client" if local in client else "server", e["direction"])
            fmt = lambda a, p: "%s:%s" % (a, p if p in fixed else "E")
            seen.setdefault(view, set()).add(fmt(e["src"], e["src_port"]) + ">" + fmt(e["dst"], e["dst_port"]))
        for view, t in sorted(want.items()):
            got = seen.pop(view, set())
            check(got == {t}, "%s %s: %s (want %s)" % (arg, view, sorted(got), t))
        check(not seen, "%s: no other views (%s)" % (arg, seen))
    elif kind == "recall":
        tag, r = arg.split(":")
        want = {t["m"] for t in truth(tag)}
        got = exported(tag) & want
        share = len(got) / max(len(want), 1)
        check(want and share >= float(r), "%s recall %d/%d (%.1f%%) >= %s" % (tag, len(got), len(want), 100 * share, r))
    elif kind == "narrow":
        tag, _, ip = arg.partition(":")
        n = json.loads(read("narrowed.json"))
        # A request sent just before the next change (a widening) can get
        # its response after it, legitimately captured: stop 0.5 s short.
        until = n["until"] - 0.5 if n.get("until") else float("inf")
        late = {t["m"] for t in truth(tag) if n["t"] <= t["t"] < until}
        pat = re.compile(rb"B2M-%s-\d+" % re.escape(tag.encode()))
        found = {}
        for name, b in sinks():
            hit = {m.decode() for m in pat.findall(b)} & late
            if hit:
                found[name] = sorted(hit)[:3]
        check(late and not found, "%s: none of %d markers sent after the narrowing in any sink%s"
              % (tag, len(late), " (found %s)" % found if found else ""))
        mark = ("B2M-%s-" % tag).encode()
        pats = ip_patterns(ip) if ip else []
        ends = n.get("until_offsets", {})
        for name, off in n["offsets"].items():
            tail = data.get(name, b"")[off:ends.get(name, None)]
            hits = [mark] if mark in tail else []
            hits += [p.pattern for p in pats if p.search(tail)]
            check(not hits, "%s: written after the narrowing was applied: no %s marker%s (%d bytes)%s"
                  % (name, tag, " or " + ip if ip else "", len(tail), " FOUND %s" % hits if hits else ""))
        for name in ("metrics_after.txt", "debug_after.json"):
            if data[name]:
                hits = [mark] if mark in data[name] else []
                hits += [p.pattern for p in pats if p.search(data[name])]
                check(not hits, "%s (scraped after): no %s marker%s" % (name, tag, " or " + ip if ip else ""))
    elif kind == "restart":
        tag, r = arg.split(":")
        runs = sorted({t["run"] for t in truth(tag)})
        want = {t["m"] for t in truth(tag) if runs and t["run"] == runs[-1]}
        got = exported(tag) & want
        share = len(got) / max(len(want), 1)
        check(len(runs) > 1 and share >= float(r), "%s: %d client runs; the last one's recall %d/%d (%.1f%%) >= %s"
              % (tag, len(runs), len(got), len(want), 100 * share, r))
    elif kind == "widened":
        tag, r = arg.split(":")
        w = json.loads(read("widened.json"))
        t0, t1 = w["t"] + 1.0, w.get("until", float("inf"))
        want = {t["m"] for t in truth(tag) if t0 <= t["t"] < t1}
        got = exported(tag) & want
        share = len(got) / max(len(want), 1)
        check(want and share >= float(r), "%s after widening: recall %d/%d (%.1f%%) >= %s"
              % (tag, len(got), len(want), 100 * share, r))
    elif kind == "reads":
        tag, r = arg.split(":")
        want = {t["m"]: t["pid"] for t in truth(tag)}
        pat = re.compile(rb"B2M-%s-\d+" % re.escape(tag.encode()))
        views = {"client": set(), "server": set()}
        for e in raw_events:
            if e.get("direction") != "Ingress" or e.get("tls_library") in (None, "None"):
                continue
            for m in pat.findall(e["data"]):
                m = m.decode()
                if m in want:
                    views["client" if e.get("pid") == want[m] else "server"].add(m)
        for view, got in sorted(views.items()):
            share = len(got) / max(len(want), 1)
            check(want and share >= float(r), "%s %s-view TLS reads %d/%d (%.1f%%) >= %s"
                  % (tag, view, len(got), len(want), 100 * share, r))
    elif kind in ("noaddr", "addr"):
        tag, _, r = arg.partition(":")
        mark = "B2M-%s-" % tag
        evs = [e for e in export if mark in json.dumps(e)]
        with_addr = [e for e in evs if e.get("src_addr") or e.get("dst_addr")]
        share = len(with_addr) / max(len(evs), 1)
        what = "%s: %d/%d events carry an address" % (tag, len(with_addr), len(evs))
        if kind == "noaddr":
            check(evs and not with_addr, what + " (want none)")
        else:
            check(evs and share >= float(r), "%s (>= %s)" % (what, r))
    elif kind == "drop":
        v = scope_drops(arg)
        check(v > 0, "scope drops %s = %g > 0" % (arg, v))
    elif kind == "log":
        check(re.search(arg.encode(), log_text, re.M), "log matches /%s/" % arg)
    elif kind == "nolog":
        check(not re.search(arg.encode(), log_text, re.M), "log does not match /%s/" % arg)
    else:
        sys.exit("unknown check " + c)

print("RESULT %s %s" % (os.path.basename(d.rstrip("/")), "FAIL" if failures else "PASS"))
sys.exit(1 if failures else 0)
