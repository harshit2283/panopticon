"""Check go_tls_oracle.go's connections against the agent's TLS keys.

The agent keys a Go TLS connection by its *tls.Conn address. The truth
records the client's address per request (tls_conn); the server's CONNLOG
holds each accepted connection's address. Reports, per process, the
connections and the distinct addresses (keys) they used. With --distinct,
exits non-zero unless every connection had its own key in both processes
(no address reused: the no-reuse oracle's precondition). With
--reused-latched CLIENT_VIEW (the client process's agent records), exits
non-zero if any exchange the agent attributed (its ?id= in a path) ran on a
connection whose key an earlier connection of the client had used: a reused
Go key must never decode.

Usage: tls_conns.py TRUTH CONNLOG [--distinct] [--reused-latched CLIENT_VIEW]
"""
import json
import re
import sys

truth = [json.loads(l) for l in open(sys.argv[1])]
conns = {t["conn"] for t in truth}
pairs = {(t["conn"], t["tls_conn"]) for t in truth}
client_keys = {t["tls_conn"] for t in truth}
server = open(sys.argv[2]).read().split()
print(f"connections={len(conns)}  client: distinct keys={len(client_keys)} "
      f"(connection, key) pairs={len(pairs)}  server: accepted={len(server)} "
      f"distinct keys={len(set(server))}")
if "--distinct" in sys.argv[3:]:
    ok = (len(pairs) == len(conns) == len(client_keys)
          and len(server) == len(set(server)) == len(conns))
    if not ok:
        sys.exit("a *tls.Conn address was reused: distinct keys != connections")
if "--reused-latched" in sys.argv:
    view = sys.argv[sys.argv.index("--reused-latched") + 1]
    first = {}
    for t in sorted(truth, key=lambda t: (t["conn"], t["pos"])):
        first.setdefault(t["tls_conn"], t["conn"])
    by_id = {t["id"]: t for t in truth}
    decoded = set()
    for line in open(view):
        m = re.search(r"[?&]id=(q\d+)", json.loads(line).get("path") or "")
        if m and m.group(1) in by_id:
            decoded.add(m.group(1))
    reused = [i for i in decoded if first[by_id[i]["tls_conn"]] != by_id[i]["conn"]]
    on_reused = sum(first[t["tls_conn"]] != t["conn"] for t in truth)
    print(f"client: {len(decoded)} exchanges decoded, {len(reused)} of them on a reused key "
          f"({on_reused} exchanges ran on reused keys)")
    if reused:
        sys.exit(f"{len(reused)} exchanges decoded on a reused key: {sorted(reused)[:5]}")
