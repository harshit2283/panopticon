"""Check go_tls_oracle.go's connections against the agent's TLS keys.

The agent keys a Go TLS connection by its *tls.Conn address. The truth
records the client's address per request (tls_conn); the server's CONNLOG
holds each accepted connection's address. Reports, per process, the
connections and the distinct addresses (keys) they used. With --distinct,
exits non-zero unless every connection had its own key in both processes
(no address reused: the no-reuse oracle's precondition).

Usage: tls_conns.py TRUTH CONNLOG [--distinct]
"""
import json
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
