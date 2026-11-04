"""Protocol-credential leg of run_modes.sh: Redis AUTH passwords and Kafka
client ids carrying an email, over minimal fake servers (no Docker).

The agent recognises Redis on port 6379 and Kafka on 9092, so the servers
only need to answer: Redis with +OK to every command, Kafka with an empty
ApiVersions v0 response echoing the correlation id.

Usage:
  MODE=server HOST=ip python3 secrets_oracle.py
  MODE=client HOST=ip PLANT=tag python3 secrets_oracle.py N truth.jsonl

Truth lines: {"id", "secrets": [redis password], "pii": [kafka client id],
"auth": command used}. Every planted value is unique per tag and index.
"""
import json
import os
import socket
import socketserver
import struct
import sys
import threading

HOST = os.environ.get("HOST", "127.0.0.1")
PLANT = os.environ.get("PLANT", "x")
REDIS_PORT, KAFKA_PORT = 6379, 9092


class Redis(socketserver.BaseRequestHandler):
    def handle(self):
        # The client waits for each reply, so one recv is one command.
        while self.request.recv(65536):
            self.request.sendall(b"+OK\r\n")


class Kafka(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            head = self.request.recv(4, socket.MSG_WAITALL)
            if len(head) < 4:
                return
            (size,) = struct.unpack(">i", head)
            req = self.request.recv(size, socket.MSG_WAITALL)
            corr = req[4:8]
            body = corr + struct.pack(">hi", 0, 0)  # error_code, no api keys
            self.request.sendall(struct.pack(">i", len(body)) + body)


def resp(*args):
    out = f"*{len(args)}\r\n".encode()
    for a in args:
        a = a.encode()
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def main():
    if os.environ.get("MODE") == "server":
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        servers = [socketserver.ThreadingTCPServer((HOST, p), h)
                   for p, h in ((REDIS_PORT, Redis), (KAFKA_PORT, Kafka))]
        for s in servers[1:]:
            threading.Thread(target=s.serve_forever, daemon=True).start()
        servers[0].serve_forever()
        return

    n, out = int(sys.argv[1]), open(sys.argv[2], "w")
    r = socket.create_connection((HOST, REDIS_PORT))
    k = socket.create_connection((HOST, KAFKA_PORT))
    for i in range(n):
        pw = f"{PLANT}rpw{i}zz"
        auth = [("AUTH", pw), ("AUTH", "app", pw), ("HELLO", "3", "AUTH", "default", pw)][i % 3]
        for cmd in (auth, ("SET", f"k{i}", "v")):
            r.sendall(resp(*cmd))
            r.recv(64)
        client_id = f"{PLANT}k{i}@example.com".encode()
        req = struct.pack(">hhih", 18, 0, i, len(client_id)) + client_id
        k.sendall(struct.pack(">i", len(req)) + req)
        k.recv(64)
        out.write(json.dumps({"id": i, "secrets": [pw], "pii": [client_id.decode()],
                              "auth": auth[0]}) + "\n")
    r.close()
    k.close()
    out.close()


if __name__ == "__main__":
    main()
