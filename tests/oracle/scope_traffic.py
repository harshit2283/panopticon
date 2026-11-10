"""Marker traffic for the cgroup_skb scope lab tests (run_scope.sh).

HTTP/1.1, plain or TLS (the system python's ssl module, so the OpenSSL
uprobes see it). Every request carries the marker B2M-<TAG>-<seq> in its
path, an X-Mark header and its body; the server's response repeats it.

  scope_traffic.py server PORT             serve until killed
  scope_traffic.py client PORT TAG N OUT   N requests (N=0: until killed)
  scope_traffic.py send PORT UNIX          connect, pass the socket over the
                                           UNIX socket UNIX (SCM_RIGHTS), exit
  scope_traffic.py recv UNIX TAG N OUT     take one passed socket and run the
                                           client on it (one connection)
  scope_traffic.py reuse PID CMD...        fork until a child gets PID (via
                                           ns_last_pid), which execs CMD

Environment:
  HOST      bind / connect address (default 127.0.0.1)
  TLS=1     TLS (server: TLS_CERT, TLS_KEY; clients do not verify)
  TRANSPARENT=1  server: IP_TRANSPARENT on the listener (TPROXY)
  CGROUP    cgroup v2 path, relative to CG_ROOT (default /sys/fs/cgroup), to
            join before any socket is created
  GO        a path: wait until it exists before any socket is created
  EVERY     requests per connection (default 5)
  GAP       seconds between requests (default 0.05)

OUT gets one JSON line per completed request: marker, send time (epoch
seconds), local and remote address, pid. Runs on python 3.6+.
"""
import array
import json
import os
import socket
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

HOST = os.environ.get("HOST", "127.0.0.1")
TLS = os.environ.get("TLS") == "1"
EVERY = int(os.environ.get("EVERY", "5"))
GAP = float(os.environ.get("GAP", "0.05"))


def prepare():
    """Join CGROUP, then wait for GO: both before any socket exists."""
    cg = os.environ.get("CGROUP")
    if cg:
        root = os.environ.get("CG_ROOT", "/sys/fs/cgroup")
        with open(os.path.join(root, cg, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))
    go = os.environ.get("GO")
    while go and not os.path.exists(go):
        time.sleep(0.05)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        out = b"RESP " + body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def server(port):
    prepare()
    srv = Server((HOST, port), Handler, bind_and_activate=False)
    if os.environ.get("TRANSPARENT") == "1":  # TPROXY's listener
        srv.socket.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
    srv.server_bind()
    srv.server_activate()
    if TLS:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.environ["TLS_CERT"], os.environ["TLS_KEY"])
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def wrap(sock):
    if not TLS:
        return sock
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx.wrap_socket(sock)


def exchange(sock, rf, marker):
    body = ("mark=%s&contact=%s@example.com" % (marker, marker.lower())).encode()
    req = ("POST /%s HTTP/1.1\r\nHost: b2\r\nX-Mark: %s\r\nContent-Type: text/plain\r\n"
           "Content-Length: %d\r\n\r\n" % (marker, marker, len(body))).encode() + body
    sock.sendall(req)
    n = 0
    while True:
        line = rf.readline()
        if not line:
            raise ConnectionError("closed")
        if line in (b"\r\n", b"\n"):
            break
        if line.lower().startswith(b"content-length:"):
            n = int(line.split(b":")[1])
    if rf.read(n).find(marker.encode()) < 0:
        raise ConnectionError("bad response")


def run(tag, n, out, connect, one_connection=False):
    pid = os.getpid()
    with open(out, "a") as f:
        sock = rf = None
        i = 0
        while n == 0 or i < n:
            marker = "B2M-%s-%d" % (tag, i)
            t = time.time()
            try:
                if sock is None or (not one_connection and i % EVERY == 0):
                    if sock is not None:
                        sock.close()
                    sock = connect()
                    rf = sock.makefile("rb")
                exchange(sock, rf, marker)
            except (OSError, ConnectionError) as e:
                print("client %s: %s" % (tag, e), file=sys.stderr)
                if one_connection:
                    return
                sock = None
                time.sleep(GAP)
                continue
            la, ra = sock.getsockname(), sock.getpeername()
            f.write(json.dumps({"m": marker, "t": t, "laddr": la[0], "lport": la[1],
                                "raddr": ra[0], "rport": ra[1], "pid": pid}) + "\n")
            f.flush()
            i += 1
            time.sleep(GAP)


def client(port, tag, n, out):
    prepare()
    run(tag, n, out, lambda: wrap(socket.create_connection((HOST, port))))


def send(port, path):
    prepare()
    s = socket.create_connection((HOST, port))
    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    u.connect(path)
    u.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [s.fileno()]))])
    u.recv(1)  # the receiver holds it now


def recv(path, tag, n, out):
    prepare()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    lsn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    lsn.bind(path)
    lsn.listen(1)
    u, _ = lsn.accept()
    fds = array.array("i")
    _, anc, _, _ = u.recvmsg(1, socket.CMSG_LEN(fds.itemsize))
    fds.frombytes(anc[0][2][:fds.itemsize])
    s = socket.socket(fileno=fds[0])
    u.sendall(b"k")
    run(tag, n, out, lambda: wrap(s), one_connection=True)


def reuse(pid, cmd):
    for _ in range(200):
        with open("/proc/sys/kernel/ns_last_pid", "w") as f:
            f.write(str(pid - 1))
        child = os.fork()
        if child == 0:
            if os.getpid() == pid:
                os.execvp(cmd[0], cmd)
            os._exit(0)
        if child == pid:
            print(child)
            return
        os.waitpid(child, 0)
    sys.exit("could not get pid %d" % pid)


if __name__ == "__main__":
    a = sys.argv
    if a[1] == "server":
        server(int(a[2]))
    elif a[1] == "client":
        client(int(a[2]), a[3], int(a[4]), a[5])
    elif a[1] == "send":
        send(int(a[2]), a[3])
    elif a[1] == "recv":
        recv(a[2], a[3], int(a[4]), a[5])
    elif a[1] == "reuse":
        reuse(int(a[2]), a[3:])
    else:
        sys.exit(__doc__)
