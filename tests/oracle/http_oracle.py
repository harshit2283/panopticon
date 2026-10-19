"""Ground-truth HTTP/1.1 traffic generator for scoring the agent.

Runs a local HTTP/1.1 server and a client that issues a seeded random mix of
requests over keep-alive connections: small/large Content-Length bodies,
chunked responses, POST bodies, 204/404. Every exchange the client actually
completed is written to truth.jsonl — the oracle the agent's JSONL export is
scored against (score.py).
"""
import http.client
import json
import os
import random
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18090
# MODE=both (default) | server | client; HOST is the bind/connect address.
MODE = os.environ.get("MODE", "both")
HOST = os.environ.get("HOST", "127.0.0.1")
N = int(sys.argv[2]) if len(sys.argv) > 2 else 400
OUT = sys.argv[3] if len(sys.argv) > 3 else "truth.jsonl"
SEED = int(os.environ.get("SEED", "1234"))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _body(self, n):
        return (b"x" * n)

    def do_GET(self):
        parts = self.path.split("?")[0].strip("/").split("/")
        kind = parts[0]
        n = int(parts[1]) if len(parts) > 1 else 0
        if kind == "len":
            b = self._body(n)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
        elif kind == "chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            left = n
            while left > 0:
                c = min(left, 700)
                self.wfile.write(b"%x\r\n" % c + self._body(c) + b"\r\n")
                left -= c
            self.wfile.write(b"0\r\n\r\n")
        elif kind == "empty":
            self.send_response(204)
            self.end_headers()
        else:
            b = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        b = b'{"ok":true}'
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


def main():
    if MODE == "server":
        ThreadingHTTPServer((HOST, PORT), H).serve_forever()
        return
    srv = None
    if MODE == "both":
        srv = ThreadingHTTPServer((HOST, PORT), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    rnd = random.Random(SEED)
    out = open(OUT, "w")
    conn = None
    conn_no, pos = -1, 0
    for i in range(N):
        if conn is None or rnd.random() < 0.15:  # new connection sometimes
            if conn:
                conn.close()
            conn = http.client.HTTPConnection(HOST, PORT)
            conn_no, pos = conn_no + 1, 0
        else:
            pos += 1
        r = rnd.random()
        tag = f"q{i}"
        if r < 0.35:
            n = rnd.choice([0, 10, 500, 1400, 3000, 9000, 70000])
            method, path, body = "GET", f"/len/{n}?id={tag}", None
        elif r < 0.55:
            n = rnd.choice([100, 2000, 12000])
            method, path, body = "GET", f"/chunked/{n}?id={tag}", None
        elif r < 0.75:
            n = rnd.choice([5, 800, 5000])
            method, path, body = "POST", f"/submit?id={tag}", b"p" * n
        elif r < 0.85:
            method, path, body = "GET", f"/empty?id={tag}", None
        else:
            method, path, body = "GET", f"/missing?id={tag}", None
        conn.request(method, path, body=body)
        resp = conn.getresponse()
        data = resp.read()
        out.write(json.dumps({"id": tag, "method": method, "path": path,
                              "status": resp.status, "response_size": len(data),
                              "conn": conn_no, "pos": pos}) + "\n")
    out.close()
    if srv:
        srv.shutdown()


if __name__ == "__main__":
    main()
