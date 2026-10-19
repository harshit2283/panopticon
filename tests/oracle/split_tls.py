"""Split run_tls.sh's agent export into client and server process views.

Writes OUT/client.jsonl and OUT/server.jsonl and reports, per view, how many
exchanges carry the socket addresses (the server endpoint 127.0.0.1:PORT on
one side). Exits non-zero if that share is below MIN_RATIO in either view.

Usage: split_tls.py OUT SERVER_PID CLIENT_PID PORT MIN_RATIO
"""
import json
import sys

out = sys.argv[1]
views = {int(sys.argv[2]): "server", int(sys.argv[3]): "client"}
server = (0x7F000001, int(sys.argv[4]))  # 127.0.0.1, host byte order
min_ratio = float(sys.argv[5])

files = {name: open(f"{out}/{name}.jsonl", "w") for name in views.values()}
total = dict.fromkeys(files, 0)
addressed = dict.fromkeys(files, 0)
for line in open(f"{out}/agent.jsonl"):
    e = json.loads(line)
    view = views.get(e.get("pid"))
    if not view:
        continue
    files[view].write(line)
    total[view] += 1
    ends = {(e.get("src_addr"), e.get("src_port")), (e.get("dst_addr"), e.get("dst_port"))}
    addressed[view] += server in ends

bad = False
for view in files:
    ratio = addressed[view] / max(total[view], 1)
    print(f"{view} view: {addressed[view]}/{total[view]} exchanges carry the server address ({ratio:.1%})")
    bad |= ratio < min_ratio
sys.exit(1 if bad else 0)
