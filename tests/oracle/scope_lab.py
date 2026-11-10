#!/usr/bin/env python3
"""End-to-end lab oracle for the cgroup_skb capture backend: the socket and
packet tests of the capture-scope design (DESIGN §10): T-1, T-3, T-4, T-7,
T-8, T-9, T-11, T-12, T-13, T-14, T-15, T-17, T-20 and T-22.

Each test runs its own agent(s) ([capture] backend = "cgroup_skb", privacy
mode full) with every sink on: the JSON export, the raw capture, the PII
audit log, --log-events at debug level and /metrics. It passes or fails on
what those sinks hold. Traffic carries unique markers and position-coded
byte streams (32-byte records "<tag>-<record number>|...."), so a check can
tell exactly which bytes left the node and from which stream position; the
leak checks search every sink file and every captured socket view (each
socket's payloads concatenated, so a marker split across packets is found).

Usage: sudo python3 tests/oracle/scope_lab.py TEST... | all
       (t1 t3 t4 t7 t8 t9 t11 t12 t13 t14 t15 t17 t20 t22)
Env:   AGENT        agent binary (default /tmp/b1/agent)
       OUT          results directory (default /tmp/b1/out)
       METRICS      metrics bind (default 127.0.0.1:29191)
       PORT_BASE    first TCP/UDP port (default 21000; up to +999 used)
       ORACLE_NET   netns subnets are 10.99.(ORACLE_NET + i).0/24 (default 201)
       NS_PREFIX    prefix for netns, veth, cgroup and chain names (default b1)
       HELPERS      directory with tcp_repair, tcp_repair32 (T-22, T-11) and
                    sk_storage_count.bpf.o (T-12) (default /tmp/b1); see
                    tcp_repair.c and sk_storage_count.bpf.c for how to build
       T1_CONNS     T-1 connections (default 20000)
       BIG_GIB      T-13 large stream size per direction (default 4.4)
Needs: root, python3 >= 3.6 (stdlib only), iproute2, tc (netem), iptables,
openssl, bpftool (T-12). Writes OUT/<test>/result.json per test.
"""
import array
import base64
import collections
import errno
import ctypes
import json
import math
import os
import random
import re
import select
import signal
import socket
import ssl  # loaded before any agent starts, so its TLS scan finds libssl
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.request

AGENT = os.environ.get("AGENT", "/tmp/b1/agent")
OUT = os.environ.get("OUT", "/tmp/b1/out")
METRICS = os.environ.get("METRICS", "127.0.0.1:29191")
PORT = int(os.environ.get("PORT_BASE", "21000"))
NET = int(os.environ.get("ORACLE_NET", "201"))
PFX = os.environ.get("NS_PREFIX", "b1")
HELPERS = os.environ.get("HELPERS", "/tmp/b1")
CG = "/sys/fs/cgroup"
# The cgroup selector needs the host's unified cgroup2 (DESIGN §3.2); RHEL 8
# has a v1 layout and the agent refuses it there.
UNIFIED = os.path.exists(CG + "/cgroup.controllers")
UNKNOWN = (1 << 64) - 1
RELEASE = tuple(int(x) for x in re.findall(r"\d+", os.uname().release)[:2])
LIBC = ctypes.CDLL(None, use_errno=True)
TCP_REPAIR, TCP_REPAIR_QUEUE, TCP_QUEUE_SEQ = 19, 20, 21
TCP_SEND_QUEUE = 2
TCP_FASTOPEN, TCP_INFO, TCP_ULP, SO_COOKIE = 23, 11, 31, 57
SOL_TLS, TLS_TX = 282, 1
MSG_FASTOPEN = 0x20000000
TCPI_OPT_SYN_DATA = 32

CLEAN = []  # undo actions of the running test, run last-in first-out


def sh(*cmd, check=True):
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    if check and r.returncode:
        raise RuntimeError("%s: %s" % (" ".join(cmd), r.stdout.strip()))
    return r.stdout


def until(f, timeout, step=0.1):
    end = time.time() + timeout
    while time.time() < end:
        v = f()
        if v:
            return v
        time.sleep(step)
    return f()


def sysctl(name, value):
    """Set a sysctl for this test; restored at its end."""
    path = "/proc/sys/" + name.replace(".", "/")
    old = open(path).read().strip()
    open(path, "w").write(str(value))
    CLEAN.append(lambda: open(path, "w").write(old))


class Test:
    def __init__(self, name):
        self.name, self.fail, self.notes, self.skip = name, [], [], None

    def check(self, ok, what):
        print("  %s %s" % ("ok  " if ok else "FAIL", what), flush=True)
        if not ok:
            self.fail.append(what)
        return ok

    def note(self, what):
        print("  note: " + what, flush=True)
        self.notes.append(what)


# ── position-coded streams ─────────────────────────────────────────────────

def block(tag, k):
    b = ("%s-%010d|" % (tag, k)).encode()
    return b + b"." * (32 - len(b))


def pattern(tag, start, length):
    """Bytes [start, start + length) of stream `tag`."""
    k0, k1 = start // 32, (start + length + 31) // 32
    buf = b"".join(block(tag, k) for k in range(k0, k1))
    return buf[start - k0 * 32:start - k0 * 32 + length]


ID_RE = re.compile(rb"([A-Za-z0-9]+)-(\d{10})\|")


def ids_past(hay, want_tag, n):
    """Record ids of tags accepted by `want_tag` whose identifier text ends
    past stream byte n, in any of the byte strings `hay`."""
    out = set()
    for data in hay:
        for m in ID_RE.finditer(data):
            tag = m.group(1).decode()
            if want_tag(tag) and int(m.group(2)) * 32 + len(m.group(0)) > n:
                out.add(m.group(0))
    return sorted(out)


def union_len(spans):
    total, end = 0, -1
    for a, b in sorted(spans):
        if b <= end:
            continue
        total += b - max(a, end)
        end = b
    return total


# ── the agent ──────────────────────────────────────────────────────────────

class Agent:
    """One agent run with every sink on; `stop()` loads what left it."""

    def __init__(self, t, run, scope):
        self.d = os.path.join(OUT, t.name, run)
        os.makedirs(self.d, exist_ok=True)
        self.cfg = self.path("agent.toml")
        self.write(scope)
        self.p = None
        self.events, self.sinks = [], {}

    def path(self, f):
        return os.path.join(self.d, f)

    def write(self, scope):
        with open(self.cfg, "w") as f:
            f.write(scope + '\n\n[capture]\nbackend = "cgroup_skb"\n\n[privacy]\nmode = "full"\n')

    def start(self):
        for f in ("agent.jsonl", "audit.jsonl", "raw.pncap"):
            if os.path.exists(self.path(f)):
                os.unlink(self.path(f))
        self.log = open(self.path("agent.log"), "wb")
        self.p = subprocess.Popen(
            [AGENT, "-v", "--config", self.cfg, "--log-events", "--metrics-bind", METRICS,
             "--json-export", self.path("agent.jsonl"), "--pii-audit-log",
             self.path("audit.jsonl"), "--capture-raw", self.path("raw.pncap")],
            stdout=self.log, stderr=subprocess.STDOUT)
        CLEAN.append(self.kill)

        def ready():
            if self.p.poll() is not None:
                raise RuntimeError("agent exited at start; see " + self.path("agent.log"))
            try:
                return urllib.request.urlopen("http://%s/readyz" % METRICS, timeout=2).getcode() == 200
            except OSError:
                return False
        if not until(ready, 90, 0.3):
            raise RuntimeError("agent not ready after 90 s")
        return self

    def kill(self):
        if self.p and self.p.poll() is None:
            self.p.send_signal(signal.SIGCONT)
            self.p.kill()
            self.p.wait()

    def log_text(self):
        return open(self.path("agent.log"), "rb").read()

    def scrape(self):
        body = urllib.request.urlopen("http://%s/metrics" % METRICS, timeout=10).read()
        with open(self.path("metrics.txt"), "wb") as f:
            f.write(body)
        m = {}
        for line in body.decode().splitlines():
            mm = re.match(r"^(\w+)(\{[^}]*\})?\s+(\S+)$", line)
            if mm:
                m[mm.group(1) + (mm.group(2) or "")] = float(mm.group(3))
        return m

    def drops(self):
        """SCOPE_DROPS by reason (synced into /metrics every second)."""
        time.sleep(1.5)
        return {k.split('"')[1]: int(v) for k, v in self.scrape().items()
                if k.startswith("panopticon_scope_dropped_events_total{")}

    def hup(self, scope, timeout=60):
        """Reload the config with SIGHUP; returns once the agent reports it applied."""
        def counts():
            text = self.log_text()
            return (text.count(b"Config reloaded via SIGHUP"),
                    text.count(b"Config reload rejected") + text.count(b"Config reload failed"))
        ok0, bad0 = counts()
        self.write(scope)
        self.p.send_signal(signal.SIGHUP)

        def done():
            ok, bad = counts()
            if bad > bad0:
                raise RuntimeError("config reload rejected; see " + self.path("agent.log"))
            return ok > ok0
        if not until(done, timeout):
            raise RuntimeError("config reload not applied in %d s" % timeout)

    def stop(self, settle=2.0):
        time.sleep(settle)
        self.metrics = self.scrape()
        self.p.send_signal(signal.SIGINT)
        try:
            self.p.wait(90)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.log.close()
        with open(self.path("raw.jsonl"), "wb") as f:
            subprocess.run([AGENT, "--privacy-mode", "full", "--decode-capture",
                            self.path("raw.pncap")], stdout=f, stderr=subprocess.DEVNULL,
                           check=True)
        self.events = []
        for line in open(self.path("raw.jsonl")):
            e = json.loads(line)
            e["payload"] = base64.b64decode(e.pop("payload_b64"))
            self.events.append(e)
        for name, f in (("export", "agent.jsonl"), ("raw", "raw.pncap"), ("audit", "audit.jsonl"),
                        ("log", "agent.log"), ("metrics", "metrics.txt")):
            self.sinks[name] = open(self.path(f), "rb").read() if os.path.exists(self.path(f)) else b""
        self.view = collections.defaultdict(bytearray)
        for e in self.events:
            self.view["%s:%s" % (e["connection_id"], e["direction"])] += e["payload"]
        lost = (int(self.metrics.get("panopticon_kernel_ringbuf_drops_total", 0)),
                int(self.metrics.get("panopticon_raw_capture_dropped_total", 0)))
        print("  [%s: %d raw events; ring drops %d, raw-capture drops %d]"
              % (os.path.basename(self.d), len(self.events), lost[0], lost[1]), flush=True)
        self.lost = sum(lost)
        return self

    def scope_drop(self, reason):
        k = 'panopticon_scope_dropped_events_total{reason="%s"}' % reason
        return int(self.metrics.get(k, 0))

    def hay(self):
        return list(self.sinks.values()) + [bytes(v) for v in self.view.values()]

    def found(self, markers):
        """marker -> where it is (sink names, or socket views)."""
        out = {}
        for m in markers:
            mb = m.encode() if isinstance(m, str) else m
            where = [k for k, v in self.sinks.items() if mb in v]
            where += ["view " + k for k, v in self.view.items() if mb in v]
            if where:
                out[m] = where[:4]
        return out

    def tcp(self, port):
        return [e for e in self.events
                if e["event_type"] == "TcPacket" and port in (e["src_port"], e["dst_port"])]


def check_absent(t, ag, markers, what):
    hit = ag.found(markers)
    t.check(not hit, "%s: none of %d markers in any sink (%d found: %s)"
            % (what, len(markers), len(hit), dict(list(hit.items())[:3])))


def check_present(t, ag, markers, what, min_recall=1.0):
    hit = ag.found(markers)
    missing = [m for m in markers if m not in hit]
    t.check(markers and len(hit) >= min_recall * len(markers),
            "%s: %d/%d markers captured (missing %s)" % (what, len(hit), len(markers), missing[:3]))


def head_check(t, ag, events, n, tag_of, what):
    """Every event lies inside the head [0, n) at its true stream position
    (its bytes are the stream's bytes there). Returns coverage per view."""
    bad, spans = [], collections.defaultdict(list)
    for e in events:
        off, data = e["stream_off"], e["payload"]
        tag = tag_of(e)
        if off == UNKNOWN or off + len(data) > n or (tag and data != pattern(tag, off, len(data))):
            bad.append((e["connection_id"], e["direction"], off, len(data), data[:24]))
        else:
            spans[(e["connection_id"], e["direction"])].append((off, off + len(data)))
    t.check(not bad, "%s: all %d events inside [0, %d) at their true positions (bad: %d %s)"
            % (what, len(events), n, len(bad), bad[:3]))
    return {k: union_len(v) for k, v in spans.items()}


# ── processes, cgroups, namespaces, sockets ────────────────────────────────

class Proc:
    """A forked child running fn(proc, *args), with a go pipe and a JSON report pipe."""

    def __init__(self, fn, *args, cgroup=None, netns=None):
        r1, w1 = os.pipe()
        r2, w2 = os.pipe()
        pid = os.fork()
        if pid == 0:
            code = 0
            try:
                os.close(w1)
                os.close(r2)
                self.go_r, self.rep_w = r1, w2
                if cgroup:
                    cg_enter(cgroup)
                if netns:
                    enter_netns(netns)
                fn(self, *args)
            except BaseException:
                traceback.print_exc()
                code = 1
            os._exit(code)
        os.close(r1)
        os.close(w2)
        self.pid, self.go_w, self.rep_r, self.buf = pid, w1, r2, b""
        CLEAN.append(self.kill)

    # child side
    def wait_go(self):
        return os.read(self.go_r, 64)

    def report(self, obj):
        os.write(self.rep_w, (json.dumps(obj) + "\n").encode())

    # parent side
    def go(self, msg=b"g"):
        os.write(self.go_w, msg)

    def get(self, timeout=120):
        end = time.time() + timeout
        while b"\n" not in self.buf:
            r, _, _ = select.select([self.rep_r], [], [], max(0, end - time.time()))
            chunk = os.read(self.rep_r, 65536) if r else None
            if not chunk:
                raise RuntimeError("no report from child %d" % self.pid)
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line.decode())

    def join(self, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            p, st = os.waitpid(self.pid, os.WNOHANG)
            if p:
                self.pid = None
                return os.WEXITSTATUS(st) if os.WIFEXITED(st) else -1
            time.sleep(0.05)
        self.kill()
        return -9

    def kill(self):
        if self.pid:
            try:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
            except OSError:
                pass
            self.pid = None


def cg_make(name):
    """A cgroup for this test; returns its cgroup_filter path."""
    path = os.path.join(CG, PFX + name)
    if not os.path.isdir(path):
        os.mkdir(path)
    CLEAN.append(lambda: os.path.isdir(path) and sh("rmdir", path, check=False))
    return PFX + name


def cg_enter(name):
    with open(os.path.join(CG, PFX + name, "cgroup.procs"), "w") as f:
        f.write(str(os.getpid()))


NSInfo = collections.namedtuple("NSInfo", "ns hif host_ip ns_ip")


def ns_up(i):
    """netns <PFX>n<i> joined by veth <PFX>v<i>: host 10.99.X.1, netns 10.99.X.2."""
    ns, hif, x = "%sn%d" % (PFX, i), "%sv%d" % (PFX, i), NET + i
    sh("ip", "link", "del", hif, check=False)
    sh("ip", "netns", "del", ns, check=False)
    sh("ip", "netns", "add", ns)
    CLEAN.append(lambda: sh("ip", "netns", "del", ns, check=False))
    sh("ip", "link", "add", hif, "type", "veth", "peer", "name", hif + "p")
    CLEAN.append(lambda: sh("ip", "link", "del", hif, check=False))
    sh("ip", "link", "set", hif + "p", "netns", ns)
    sh("ip", "addr", "add", "10.99.%d.1/24" % x, "dev", hif)
    sh("ip", "link", "set", hif, "up")
    sh("ip", "-n", ns, "addr", "add", "10.99.%d.2/24" % x, "dev", hif + "p")
    sh("ip", "-n", ns, "link", "set", hif + "p", "up")
    sh("ip", "-n", ns, "link", "set", "lo", "up")
    sh("ip", "-n", ns, "route", "add", "default", "via", "10.99.%d.1" % x)
    return NSInfo(ns, hif, "10.99.%d.1" % x, "10.99.%d.2" % x)


def enter_netns(ns):
    fd = os.open("/var/run/netns/" + ns, os.O_RDONLY)
    if LIBC.setns(fd, 0x40000000) != 0:
        raise OSError(ctypes.get_errno(), "setns " + ns)
    os.close(fd)


def listener(port, host="0.0.0.0", backlog=4096, fastopen=False):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fastopen:
        s.setsockopt(socket.IPPROTO_TCP, TCP_FASTOPEN, 64)
    s.bind((host, port))
    s.listen(backlog)
    return s


def recv_exact(s, n):
    buf = bytearray()
    while len(buf) < n:
        c = s.recv(min(n - len(buf), 1 << 20))
        if not c:
            break
        buf += c
    return bytes(buf)


def recv_line(s):
    buf = bytearray()
    while not buf.endswith(b"\n"):
        c = s.recv(4096)
        if not c:
            break
        buf += c
    return bytes(buf)


def drain(s):
    """Read until the peer closes or resets."""
    out = bytearray()
    try:
        while True:
            c = s.recv(1 << 16)
            if not c:
                break
            out += c
    except OSError:
        pass
    return bytes(out)


def serve(lsock, handler):
    """Accept on lsock in a daemon thread, one daemon thread per connection."""
    def conn(c):
        try:
            handler(c)
        except OSError:
            pass
        finally:
            c.close()

    def loop():
        while True:
            try:
                c, _ = lsock.accept()
            except OSError:
                return
            threading.Thread(target=conn, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


def unlisten(s):
    """Close a socket that a serve() thread may be blocked in accept() on:
    close() alone leaves the listener bound until that accept() returns."""
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    s.close()


def disconnect(s):
    """connect(AF_UNSPEC): tcp_disconnect, keeping the socket and its cookie."""
    sa = ctypes.create_string_buffer(struct.pack("H14x", socket.AF_UNSPEC), 16)
    if LIBC.connect(s.fileno(), sa, 16) != 0:
        raise OSError(ctypes.get_errno(), "connect(AF_UNSPEC)")


def send_fd(sock, fd):
    sock.sendmsg([b"f"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [fd]))])


def recv_fd(sock):
    _, anc, _, _ = sock.recvmsg(1, socket.CMSG_LEN(4))
    fd = struct.unpack("i", anc[0][2][:4])[0]
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0, fd)


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def forge(src, sport, dst, dport, seq, ack, flags, payload=b"", ttl=64):
    """An IPv4/TCP packet with valid checksums (the kernel drops bad ones
    before any socket filter)."""
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      5 << 4, flags, 65535, 0, 0) + payload
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), random.randrange(1, 65535), 0,
                     ttl, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return ip + tcp


def inject(pkts, dst):
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    for p in pkts:
        r.sendto(p, (dst, 0))
    r.close()


def inject_from(ns, pkts, dst):
    """Send raw packets from inside netns `ns`."""
    Proc(lambda p: inject(pkts, dst), netns=ns).join(30)


ACK, PSH, RST, SYN, FIN = 0x10, 0x08, 0x04, 0x02, 0x01


def queue_seq(s):
    """The send queue's next sequence number, through a brief TCP_REPAIR
    (the stream origin is this minus the bytes written)."""
    s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 1)
    try:
        s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
        return struct.unpack("I", s.getsockopt(socket.IPPROTO_TCP, TCP_QUEUE_SEQ, 4))[0]
    finally:
        s.setsockopt(socket.IPPROTO_TCP, TCP_REPAIR, 0)


def tcp_counter(name, ns=None):
    """A /proc/net/snmp Tcp or /proc/net/netstat TcpExt counter (in netns ns)."""
    pre = ("ip", "netns", "exec", ns) if ns else ()
    text = sh(*(pre + ("cat", "/proc/net/snmp", "/proc/net/netstat")))
    lines = text.splitlines()
    for a, b in zip(lines, lines[1:]):
        ka, kb = a.split(), b.split()
        if ka[0] == kb[0] and name in ka:
            return int(kb[ka.index(name)])
    return 0


def rps(on):
    """Receive packet steering on lo across every CPU (T-1, T-7)."""
    path = "/sys/class/net/lo/queues/rx-0/rps_cpus"
    old = open(path).read().strip()
    ncpu = os.cpu_count()
    open(path, "w").write("%x" % ((1 << ncpu) - 1))
    CLEAN.append(lambda: open(path, "w").write(old))


def churn_execs(n):
    for _ in range(n):
        pid = os.fork()
        if pid == 0:
            os.execv("/bin/true", ["/bin/true"])
        os.waitpid(pid, 0)


# ── T-1 publication race ───────────────────────────────────────────────────

def t1_server(p, port):
    p.wait_go()
    lsock = listener(port)

    def acceptor():
        while True:
            c, peer = lsock.accept()
            try:
                c.sendall(pattern("P%05d" % peer[1], 0, 1024))
                recv_exact(c, 1024)
            except OSError:
                pass
            c.close()
    for _ in range(16):
        threading.Thread(target=acceptor, daemon=True).start()
    p.report({"listening": True})
    p.wait_go()


def t1_client(p, port, count, threads):
    done, fail = [0], [0]
    lock = threading.Lock()

    def run(k):
        for i in range(k):
            s = socket.socket()
            try:
                s.connect(("127.0.0.%d" % (1 + i % 8), port))
                s.sendall(pattern("Q%05d" % s.getsockname()[1], 0, 1024))
                ok = len(recv_exact(s, 1024)) == 1024
            except OSError:
                ok = False
            s.close()
            with lock:
                done[0] += ok
                fail[0] += not ok
    ts = [threading.Thread(target=run, args=(count // threads,)) for _ in range(threads)]
    for x in ts:
        x.start()
    for x in ts:
        x.join()
    p.report({"done": done[0], "fail": fail[0]})


def t1(t):
    """T-1: accepts with data racing the initialisation callback, RPS on."""
    n, port, conns, procs = 256, PORT + 1, int(os.environ.get("T1_CONNS", "20000")), 4
    rps(True)
    srv = Proc(t1_server, port)
    spid = srv.pid
    ag = Agent(t, "pid_head", 'pid_filter = [%d]\nsampling_mode = "head_only"\n'
               'head_only_bytes = %d' % (spid, n)).start()
    srv.go()
    srv.get()
    t0 = time.time()
    cl = [Proc(t1_client, port, conns // procs, 8) for _ in range(procs)]
    stats = [c.get(timeout=1800) for c in cl]
    secs = time.time() - t0
    done = sum(s["done"] for s in stats)
    t.note("%d connections in %.0f s (%.0f/s) on %d CPUs (scaled down from 10^6), %d failed"
           % (done, secs, done / secs, os.cpu_count(), sum(s["fail"] for s in stats)))
    ag.stop()
    srv.kill()
    evs = ag.tcp(port)
    others = [e for e in evs if e["owner_tgid"] != spid]
    t.check(not others, "only the listed server's children exported (%d events of other "
            "sockets; client sockets are unlisted)" % len(others))

    def tag_of(e):
        return "Q%05d" % e["src_port"] if e["dst_port"] == port else "P%05d" % e["dst_port"]
    cover = head_check(t, ag, evs, n, tag_of, "children")
    full = sum(v == n for v in cover.values())
    # Missing a child is allowed (fails closed, counted uninit); exporting
    # one at a wrong position is not. Coverage only shows the race ran.
    t.note("%d child directions captured, %d of %d with the whole head; uninit drops %d"
           % (len(cover), full, 2 * done, ag.scope_drop("uninit")))
    t.check(done and full, "children captured (%d directions with the whole head)" % full)
    past = ids_past(ag.hay(), lambda g: len(g) == 6 and g[0] in "PQ", n)
    t.check(not past, "no stream record past %d bytes in any sink (%d: %s)" % (n, len(past), past[:3]))


# ── T-3 / T-15 shared listener and pre-fork servers ────────────────────────

def worker_loop(lsock, name, delay=0.2):
    """Accept on a listener shared with other workers; bytes the client sends
    right after connecting arrive before accept() returns (the delay)."""
    lsock.setblocking(False)
    while True:
        r, _, _ = select.select([lsock], [], [], 0.5)
        if not r:
            continue
        time.sleep(delay)
        try:
            c, _ = lsock.accept()
        except (BlockingIOError, InterruptedError):
            continue
        c.setblocking(True)
        try:
            cid = recv_line(c).split()[1].decode()
            c.sendall(("RESP1 %s B1P1x%s\n" % (name, cid)).encode())
            recv_line(c)
            c.sendall(("RESP2 %s B1P2x%s\n" % (name, cid)).encode())
            drain(c)
        except (OSError, IndexError):
            pass
        c.close()


def prefork_master(p, port, mode):
    """mode "scm": fork workers A and B; on go, create the listener and pass
    it to both by SCM_RIGHTS. "pre": create the listener, fork A and B now;
    they start accepting on go. "master": on go, create the listener and fork
    A and B, which inherit it. Reports the pids, then {"ready"}."""
    kids, pairs = {}, []
    lsock = listener(port) if mode == "pre" else None
    if mode in ("scm", "pre"):
        for name in ("A", "B"):
            ps, cs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            pid = os.fork()
            if pid == 0:
                try:
                    ps.close()
                    if mode == "scm":
                        ls = recv_fd(cs)
                    else:
                        cs.recv(1)
                        ls = lsock
                    worker_loop(ls, name)
                finally:
                    os._exit(0)
            cs.close()
            pairs.append(ps)
            kids[name] = pid
    p.report({"M": os.getpid(), "A": kids.get("A"), "B": kids.get("B")})
    p.wait_go()
    if mode == "scm":
        lsock = listener(port)
        for ps in pairs:
            send_fd(ps, lsock.fileno())
    elif mode == "pre":
        for ps in pairs:
            ps.send(b"g")
    else:
        lsock = listener(port)
        for name in ("A", "B"):
            pid = os.fork()
            if pid == 0:
                try:
                    worker_loop(lsock, name)
                finally:
                    os._exit(0)
            kids[name] = pid
    p.report({"ready": True, "A": kids["A"], "B": kids["B"]})
    p.wait_go()
    for pid in kids.values():
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def prefork_clients(port, run, count):
    """Sequential connections; each sends REQ1 at once (before accept), then
    REQ2 after RESP1. Returns [(cid, worker name)]."""
    out = []
    for i in range(count):
        cid = "%s%03d" % (run, i)
        s = socket.create_connection(("127.0.0.1", port), 10)
        s.sendall(("REQ1 %s B1Q1x%s\n" % (cid, cid)).encode())
        name = recv_line(s).split()[1].decode()
        s.sendall(("REQ2 B1Q2x%s\n" % cid).encode())
        recv_line(s)
        s.close()
        out.append((cid, name))
    return out


def pidfd_getfd_exists():
    """pidfd_getfd (5.6+, syscall 438 on x86-64): ENOSYS is the only error
    for an fd of -1 where it is missing."""
    LIBC.syscall(438, -1, -1, 0)
    return ctypes.get_errno() != errno.ENOSYS


def prefork_case(t, run, mode, listed, port):
    """One pre-fork run; `listed` is "M", "A" or "MAB" (every process).
    Checks per DESIGN §3.1."""
    m = Proc(prefork_master, port, mode)
    pids = m.get()
    sel = ", ".join(str(pids[k]) for k in listed)
    ag = Agent(t, run, "pid_filter = [%s]" % sel).start()
    m.go()
    pids.update(m.get())
    time.sleep(0.5)
    conns = prefork_clients(port, run, 40)
    ag.stop()
    m.go()
    m.join()
    by = collections.Counter(n for _, n in conns)
    t.note("%s: connections per worker %s" % (run, dict(by)))
    if not t.check(by["A"] and by["B"], "%s: both workers accepted connections" % run):
        return
    # Every holder listed: the pre-agent listener is initialised at arming
    # (DESIGN §3.1.2) where pidfd_getfd exists; else, as worker-listed,
    # every child from accept() on.
    init = listed != "MAB" or pidfd_getfd_exists()
    if not init:
        t.note("%s: no pidfd_getfd, listener not initialised" % run)
    m_in, m_out = [], []
    for cid, name in conns:
        marks = ["B1Q1x" + cid, "B1P1x" + cid, "B1Q2x" + cid, "B1P2x" + cid]
        if listed == "M" or (listed == "MAB" and init):
            m_in += marks
        elif listed == "MAB":
            m_out.append(marks[0])  # before accept() returned
            m_in += marks[1:]
        elif name == "A":
            m_out.append(marks[0])  # before accept() returned
            m_in += marks[1:]
        else:
            m_out += marks
    check_present(t, ag, m_in, "%s: in-scope bytes" % run)
    check_absent(t, ag, m_out, "%s: out-of-scope bytes" % run)
    evs = ag.tcp(port)
    if listed == "M":
        bad = [e for e in evs if e["owner_tgid"] != pids["M"]]
        what = "every event's owner is the listed master"
    elif listed == "MAB" and init:
        # A pre-agent listener initialised at arming: owner = its lowest holder.
        low = min(pids[k] for k in listed)
        bad = [e for e in evs if e["owner_tgid"] != low]
        what = "every event's owner is the listener's lowest holder"
    elif listed == "MAB":
        bad = [e for e in evs if e["acceptor_tgid"] not in (pids["A"], pids["B"])]
        what = "every event's acceptor is a listed worker"
    else:
        bad = [e for e in evs if e["acceptor_tgid"] != pids["A"]]
        what = "every event's acceptor is the listed worker A"
    t.check(evs and not bad, "%s: %s (%d of %d events not)" % (run, what, len(bad), len(evs)))
    return ag


def t3(t):
    """T-3: master (unlisted) creates the listener after the agent starts and
    passes it to workers A (listed) and B (unlisted) by SCM_RIGHTS."""
    ag = prefork_case(t, "scm_A", "scm", "A", PORT + 30)
    if ag:
        t.check(ag.scope_drop("out_of_scope") > 0, "pre-accept bytes counted out_of_scope")


def t15(t):
    """T-15: pre-fork server, master-listed (listener created under the
    agent) and worker-listed (listener and workers predate the agent). And
    every holder of the pre-agent listener listed: initialised at arming
    (DESIGN §3.1.2), so bytes before accept() are captured."""
    prefork_case(t, "master_M", "master", "M", PORT + 150)
    ag = prefork_case(t, "pre_A", "pre", "A", PORT + 151)
    if ag:
        t.check(ag.scope_drop("no_owner") > 0,
                "bytes before accept() on a pre-agent listener counted no_owner")
    # Bytes before accept() are among the in-scope marks checked there (other
    # node traffic may count no_owner, so the counter is only noted).
    ag = prefork_case(t, "pre_MAB", "pre", "MAB", PORT + 152)
    if ag:
        t.note("pre_MAB: no_owner %d" % ag.scope_drop("no_owner"))


# ── T-4 PID reuse ──────────────────────────────────────────────────────────

def t4_victim(p, port):
    p.wait_go()
    s = socket.create_connection(("127.0.0.1", port), 10)
    s.sendall(b"B1T4CTLx%d\n" % os.getpid())
    s.close()
    p.report({"sent": True})
    p.wait_go()  # then exit


def reuse_pid(pid, port, marker, tries=2000):
    """Fork until a child gets `pid` (ns_last_pid); it sends `marker`."""
    for _ in range(tries):
        with open("/proc/sys/kernel/ns_last_pid", "w") as f:
            f.write(str(pid - 1))
        child = os.fork()
        if child == 0:
            if os.getpid() != pid:
                os._exit(3)
            try:
                s = socket.create_connection(("127.0.0.1", port), 10)
                s.sendall(marker + b"\n")
                time.sleep(0.2)
                s.close()
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, st = os.waitpid(child, 0)
        if os.WIFEXITED(st) and os.WEXITSTATUS(st) == 0:
            return True
    return False


def t4(t):
    """T-4: a pid reused after exit (ns_last_pid) is not selected, also when
    the process ring is full at exit (exec churn with the agent stopped)."""
    for run, full in (("plain", False), ("ring_full", True)):
        port = PORT + 40 + full
        lsock = listener(port, "127.0.0.1")
        serve(lsock, drain)
        v = Proc(t4_victim, port)
        ag = Agent(t, run, "pid_filter = [%d]" % v.pid).start()
        v.go()
        v.get()
        victim = v.pid
        if full:
            os.kill(ag.p.pid, signal.SIGSTOP)
            churn_execs(4000)  # 8000 exec/exit records into a 64 KiB ring nobody reads
        v.go()
        t.check(v.join() == 0, "%s: listed process %d exited" % (run, victim))
        marker = b"B1T4REUSEx%s%d" % (run.encode(), victim)
        reused = reuse_pid(victim, port, marker)
        if full:
            os.kill(ag.p.pid, signal.SIGCONT)
        ag.stop(3)
        unlisten(lsock)
        if not t.check(reused, "%s: pid %d reused by a new process" % (run, victim)):
            continue
        check_present(t, ag, [b"B1T4CTLx%d" % victim], "%s: listed process before exit" % run)
        check_absent(t, ag, [marker], "%s: new process with the reused pid" % run)


# ── T-7 torn reads ─────────────────────────────────────────────────────────

FILL7 = (b"B1T7FILL" + b"." * 56) * 16384  # 1 MiB, past every head


def t7_sender(p, port, secs):
    s = socket.create_connection(("127.0.0.1", port), 10)
    tag = "T%05d" % s.getsockname()[1]
    s.sendall(pattern(tag, 0, 65536))
    sent, end = 65536, time.time() + secs
    while time.time() < end:
        s.sendall(FILL7)
        sent += len(FILL7)
    s.close()
    p.report({"sent": sent})


def t7(t):
    """T-7: head_only N=4096 under high-rate loopback, RPS on; zero bytes
    past N; head_incoherent reported (no test-only delay: that needs a
    kernel change)."""
    n, port, streams, secs = 4096, PORT + 70, 8, 20
    rps(True)
    ag = Agent(t, "head4096", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    lsock = listener(port, "127.0.0.1")

    def reader(c):
        while c.recv(1 << 16):
            pass
    serve(lsock, reader)
    t0 = time.time()
    snd = [Proc(t7_sender, port, secs) for _ in range(streams)]
    total = sum(x.get(secs + 60)["sent"] for x in snd)
    gbps = total * 8 / (time.time() - t0) / 1e9
    ag.stop()
    unlisten(lsock)
    t.note("%.1f GiB in %d streams, %.1f Gb/s" % (total / 2 ** 30, streams, gbps))
    evs = ag.tcp(port)
    cover = head_check(t, ag, evs, n, lambda e: "T%05d" % e["src_port"], "streams")
    t.note("views %d, whole head in %d; head_incoherent = %d"
           % (len(cover), sum(v == n for v in cover.values()), ag.scope_drop("head_incoherent")))
    check_absent(t, ag, [b"B1T7FILL"], "filler past the head")
    past = ids_past(ag.hay(), lambda g: g.startswith("T") and len(g) == 6, n)
    t.check(not past, "no stream record past %d bytes in any sink (%s)" % (n, past[:3]))


# ── T-8 TCP Fast Open ──────────────────────────────────────────────────────

def t8(t):
    """T-8: TFO client and server: SYN data not captured, the first byte after
    it exported at offset = TFO length, nothing past N."""
    n, port, L, more, conns = 1000, PORT + 80, 100, 2000, 20
    sysctl("net.ipv4.tcp_fastopen", 3)
    ag = Agent(t, "head1000", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    lsock = listener(port, "127.0.0.1", fastopen=True)

    def handler(c):
        recv_exact(c, L + more)
        c.sendall(pattern("G%05d" % c.getpeername()[1], 0, 2000))
        drain(c)
    serve(lsock, handler)
    a0, p0 = tcp_counter("TCPFastOpenActive"), tcp_counter("TCPFastOpenPassive")
    tfo = []
    for _ in range(conns + 1):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cport = s.getsockname()[1]
        tag = "F%05d" % cport
        s.sendto(pattern(tag, 0, L), MSG_FASTOPEN, ("127.0.0.1", port))
        s.sendall(pattern(tag, L, more))
        recv_exact(s, 2000)
        info = s.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 8)
        if info[5] & TCPI_OPT_SYN_DATA:
            tfo.append(cport)
        s.close()
    ag.stop()
    unlisten(lsock)
    t.note("TFO SYN data acked on %d of %d connections (TCPFastOpenActive +%d, Passive +%d)"
           % (len(tfo), conns + 1, tcp_counter("TCPFastOpenActive") - a0,
              tcp_counter("TCPFastOpenPassive") - p0))
    if not t.check(tfo, "TCP Fast Open exercised"):
        return
    evs = ag.tcp(port)

    def tag_of(e):
        return "F%05d" % e["src_port"] if e["dst_port"] == port else "G%05d" % e["dst_port"]
    head_check(t, ag, evs, n, tag_of, "all streams")
    for view, d in (("client egress", "Egress"), ("server ingress", "Ingress")):
        firsts = {}
        for e in evs:
            if e["dst_port"] == port and e["direction"] == d and e["src_port"] in tfo:
                firsts[e["src_port"]] = min(firsts.get(e["src_port"], UNKNOWN), e["stream_off"])
        wrong = {k: v for k, v in firsts.items() if v != L}
        t.check(len(firsts) == len(tfo) and not wrong,
                "%s: first captured byte at offset %d (the TFO length) on %d/%d TFO streams; "
                "wrong: %s" % (view, L, len(firsts), len(tfo), dict(list(wrong.items())[:3])))
    # Records wholly inside the SYN data: ids of records 0 .. L/32 - 1.
    syn = [block("F%05d" % c, k)[:18] for c in tfo for k in range(L // 32)]
    leaked = list(ag.found(syn))
    t.check(not leaked, "no SYN data (stream records 0..%d) in any sink (%s)"
            % (L // 32 - 1, leaked[:3]))


# ── T-9 UDP ────────────────────────────────────────────────────────────────

def dgram(i, j, size=64):
    b = b"U%02d-%04d|" % (i, j)
    return b + b"u" * (size - len(b))


def udp_sender(p, dst, prefix, rounds):
    """For each round: on go (the go message is the round's tag), send the
    round's datagrams from one socket (a fresh one when the round says so)."""
    s = None
    for count, fresh in rounds:
        tag = prefix + p.wait_go().decode()
        if s is None or fresh:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for j in range(count):
            s.sendto(b"%s-%04d|" % (tag.encode(), j) + b"." * 80, tuple(dst))
            time.sleep(0.002)
        p.report({"port": s.getsockname()[1]})


def udp_sink(p, port):
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.bind(("127.0.0.1", port))
    p.report({"ok": True})
    while True:
        r.recv(65536)


def t9(t):
    """T-9 UDP head_only: 64 threads on one socket; a pre-agent socket; a
    socket that sent 2N bytes out of scope, then its cgroup is added."""
    n = 4096
    port_rx, port_pre = PORT + 91, PORT + 92
    pre_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pre_rx.bind(("127.0.0.1", port_pre))
    pre_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pre_tx.sendto(b"warm", ("127.0.0.1", port_pre))
    ag = Agent(t, "head", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", port_rx))
    threading.Thread(target=lambda: [rx.recv(65536) for _ in iter(int, 1)], daemon=True).start()
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def burst(i):
        for j in range(50):
            tx.sendto(dgram(i, j), ("127.0.0.1", port_rx))
    ts = [threading.Thread(target=burst, args=(i,)) for i in range(64)]
    for x in ts:
        x.start()
    for x in ts:
        x.join()
    pre = [b"B1T9PREx%03d" % j for j in range(20)]
    for m in pre:
        pre_tx.sendto(m + b"." * 100, ("127.0.0.1", port_pre))
    ag.stop()
    sent = {dgram(i, j) for i in range(64) for j in range(50)}
    for view, sel in (("sender", lambda e: e["direction"] == "Egress"),
                      ("receiver", lambda e: e["direction"] == "Ingress")):
        evs = [e for e in ag.events if e["dst_port"] == port_rx and e["ip_proto"] == 17 and sel(e)]
        spans = sorted((e["stream_off"], e["stream_off"] + len(e["payload"])) for e in evs)
        overlap = sum(a < b_end for (_, b_end), (a, _) in zip(spans, spans[1:]))
        bad = [e for e in evs if e["stream_off"] >= n or e["stream_off"] + len(e["payload"]) > n
               or not any(d.startswith(e["payload"]) for d in sent)]
        total = sum(len(e["payload"]) for e in evs)
        t.check(evs and total <= n and not bad and not overlap,
                "64 threads, one socket, %s view: %d datagrams, %d bytes captured (<= %d), "
                "offsets inside the budget and disjoint (bad %d, overlaps %d)"
                % (view, len(evs), total, n, len(bad), overlap))
    check_absent(t, ag, pre, "pre-agent UDP socket")

    if not UNIFIED:
        t.note("2N-then-cgroup-added case not run: no unified cgroup2 (the selector is refused)")
        return
    a, b = cg_make("t9a"), cg_make("t9b")
    cg_make("t9c")  # the receiver's, never selected
    sink = Proc(udp_sink, PORT + 93, cgroup="t9c")
    sink.get()
    pre_count = 2 * n // 80 + 1  # 93-byte datagrams: more than 2N bytes
    x = Proc(udp_sender, ["127.0.0.1", PORT + 93], "B1T9",
             [(pre_count, False), (10, False), (5, True)], cgroup="t9b")
    base = 'sampling_mode = "head_only"\nhead_only_bytes = %d\n' % n
    ag = Agent(t, "cgroup_widen", base + 'cgroup_filter = ["%s"]' % a).start()
    x.go(b"PRE")
    x.get()
    ag.hup(base + 'cgroup_filter = ["%s", "%s"]' % (a, b))
    x.go(b"OUT")
    x.get()
    x.go(b"NEW")
    x.get()
    ag.stop()
    check_absent(t, ag, [b"B1T9PRE-%04d" % j for j in range(pre_count)],
                 "2N bytes sent out of scope")
    check_absent(t, ag, [b"B1T9OUT-%04d" % j for j in range(10)],
                 "after its cgroup was added, the socket that already sent 2N")
    check_present(t, ag, [b"B1T9NEW-%04d" % j for j in range(5)],
                  "control: a new socket in the added cgroup")


# ── T-11 every SCOPE_DROPS reason ──────────────────────────────────────────

def t11_actor(p, port_srv, helpers):
    """Listed process: each go runs one case on its own sockets."""
    while True:
        case = p.wait_go().decode()
        if case == "head_cut":
            ls = listener(0, "127.0.0.1")
            c = socket.create_connection(ls.getsockname(), 10)
            a, _ = ls.accept()
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for i in range(8):
                c.sendall(b"x" * 1024)
                time.sleep(0.01)
            recv_exact(a, 8192)
            c.close()
            a.close()
            ls.close()
        elif case == "ktls":
            ls = listener(0, "127.0.0.1")
            c = socket.create_connection(ls.getsockname(), 10)
            a, _ = ls.accept()
            # A kTLS key install (TLS_TX, AES-GCM-128) after the ULP: the
            # marker is set on entry to any SOL_TLS setsockopt, whatever the
            # result. A ULP without keys is not marked (DESIGN §3.5).
            try:
                c.setsockopt(socket.IPPROTO_TCP, TCP_ULP, b"tls")
            except OSError:
                pass
            try:
                c.setsockopt(SOL_TLS, TLS_TX, struct.pack(
                    "<HH8s16s4s8s", 0x0303, 51, b"\x01" * 8, b"\x02" * 16, b"\x03" * 4,
                    b"\x00" * 8))
            except OSError:
                pass
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for i in range(30):
                c.sendall(b"k" * 100)
                time.sleep(0.01)
            recv_exact(a, 3000)
            c.close()
            a.close()
        elif case == "burst":
            ls = listener(0, "127.0.0.1")
            c = socket.create_connection(ls.getsockname(), 10)
            a, _ = ls.accept()
            th = threading.Thread(target=lambda: [None for _ in iter(lambda: a.recv(1 << 16), b"")])
            th.start()
            end = time.time() + 3
            while time.time() < end:
                c.sendall(FILL7)
            c.close()
            th.join()
        elif case == "repair":
            os.execv(helpers + "/tcp_repair", [helpers + "/tcp_repair", "127.0.0.1",
                                               str(port_srv), "t11"])
        p.report({"done": case})


def repair_server(c):
    """Peer of tcp_repair: history, then the restored stream's bytes."""
    recv_exact(c, 3000)
    c.sendall(b"h" * 3000)
    recv_exact(c, 2000)
    c.sendall(b"r" * 2000)
    drain(c)


def tls_pair(port, certs, marker):
    """One TLS exchange on loopback (the uprobes see both ends)."""
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(certs + "/cert.pem", certs + "/key.pem")
    lsock = listener(port, "127.0.0.1")

    def server():
        c, _ = lsock.accept()
        with sctx.wrap_socket(c, server_side=True) as tc:
            tc.sendall(tc.recv(4096))
    th = threading.Thread(target=server)
    th.start()
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    with cctx.wrap_socket(socket.create_connection(("127.0.0.1", port), 10)) as tc:
        tc.sendall(marker)
        tc.recv(4096)
    th.join()
    unlisten(lsock)


def certs():
    d = os.path.join(OUT, "certs")
    if not os.path.exists(d + "/cert.pem"):
        os.makedirs(d, exist_ok=True)
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj",
           "/CN=b1", "-keyout", d + "/key.pem", "-out", d + "/cert.pem")
    return d


def t11(t):
    """T-11: each SCOPE_DROPS reason is incremented by its case (the delta
    over the case, at least the case's own packets)."""
    seen = {}

    def case(ag, reason, what, fn, at_least=1):
        before = ag.drops().get(reason, 0)
        fn()
        delta = ag.drops().get(reason, 0) - before
        seen[reason] = delta
        return t.check(delta >= at_least, "%s: +%d by %s (>= %d)" % (reason, delta, what, at_least))

    cert = certs()
    port = PORT + 110
    # Run A: pid_filter + head_only.
    pre_l = listener(port, "127.0.0.1")           # predates the agent: uninit
    pre_c = socket.create_connection(("127.0.0.1", port), 10)
    pre_a, _ = pre_l.accept()
    pre_c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # A listener that predates the agent, held by a listed process and by
    # this (unlisted) one: not every holder is listed, so arming gives it no
    # owner, and its children are selected only from accept() on (no_owner).
    # Held by the listed process alone, arming would own it.
    shared_l = listener(port + 1, "127.0.0.1")

    def owner_listener(p):                         # listed; inherits shared_l
        p.report({"ok": 1})
        p.wait_go()
        shared_l.close()
    s = Proc(owner_listener)
    s.get()
    lrep = listener(port + 2, "127.0.0.1")
    serve(lrep, repair_server)
    r = Proc(t11_actor, port + 2, HELPERS)
    ag = Agent(t, "pid_head", 'pid_filter = [%d, %d]\nsampling_mode = "head_only"\n'
               'head_only_bytes = 512' % (s.pid, r.pid)).start()

    def pre_traffic():
        for i in range(100):
            pre_c.sendall(b"p" * 50)
            time.sleep(0.005)
        recv_exact(pre_a, 5000)
    case(ag, "uninit", "100 segments on a pre-agent connection", pre_traffic, 100)

    held = []

    def unaccepted():
        c = socket.create_connection(("127.0.0.1", port + 1), 10)
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i in range(50):
            c.sendall(b"n" * 50)
            time.sleep(0.005)
        held.append(c)
    case(ag, "not_eligible", "a handshake with the listed process's listener",
         lambda: held.append(socket.create_connection(("127.0.0.1", port + 1), 10)))
    before = ag.drops()
    case(ag, "no_owner", "50 segments before accept() on a pre-agent listener", unaccepted, 50)
    seen["out_of_scope"] = ag.drops().get("out_of_scope", 0) - before.get("out_of_scope", 0)
    t.check(seen["out_of_scope"] >= 50,
            "out_of_scope: +%d by the unlisted client's 50 segments" % seen["out_of_scope"])

    def run_case(name):
        return lambda: (r.go(name.encode()), r.get())
    case(ag, "head_cut", "a listed process's 8 KiB stream (N = 512)", run_case("head_cut"))
    case(ag, "ktls_payload", "30 segments after a kTLS key install (TLS_TX)", run_case("ktls"),
         30)
    case(ag, "tls_mode", "a TLS exchange under head_only",
         lambda: tls_pair(port + 3, cert, b"B1T11TLSMODE"))
    before = ag.drops().get("head_incoherent", 0)
    r.go(b"burst")
    r.get()
    seen["head_incoherent"] = ag.drops().get("head_incoherent", 0) - before
    t.note("head_incoherent: +%d over a 3 s loopback burst (a torn read is a race; zero "
           "means none was caught, not a failure; T-7 has the long run)" % seen["head_incoherent"])
    case(ag, "no_baseline", "a TCP repair restore by a listed process (tcp_repair)",
         lambda: (r.go(b"repair"), time.sleep(3)), 1)
    ag.stop()
    s.go()
    for x in held + [pre_c, pre_a, pre_l, lrep, shared_l]:
        unlisten(x)
    check_absent(t, ag, [b"B1T11TLSMODE"], "TLS plaintext under head_only")

    # Run B: pid_filter, full: a TLS call by an unlisted process.
    q = Proc(lambda p: p.wait_go())
    ag = Agent(t, "pid_full", "pid_filter = [%d]" % q.pid).start()
    case(ag, "tls_out_of_scope", "a TLS exchange by an unlisted process",
         lambda: tls_pair(port + 4, cert, b"B1T11TLSOUT"))
    ag.stop()
    q.go()
    check_absent(t, ag, [b"B1T11TLSOUT"], "TLS plaintext of an unlisted process")

    # Run C: connection_sample at 0.
    ag = Agent(t, "sample0", 'sampling_mode = "connection_sample"\nsample_rate = 0.0').start()

    def sampled():
        ls = listener(port + 5, "127.0.0.1")
        c = socket.create_connection(("127.0.0.1", port + 5), 10)
        a, _ = ls.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i in range(20):
            c.sendall(b"s" * 50)
            time.sleep(0.005)
        recv_exact(a, 1000)
        for x in (c, a, ls):
            x.close()
    case(ag, "sampled_out", "20 segments at sample_rate 0", sampled, 20)
    ag.stop()

    # ring_full is the existing KERNEL_DROPS (DESIGN §5): unscoped full, the
    # agent stopped, 2 GiB of loopback traffic into rings nobody reads.
    ag = Agent(t, "ring_full", "").start()

    def kernel_drops():
        time.sleep(1.5)
        return int(ag.scrape().get("panopticon_kernel_ringbuf_drops_total", 0))
    before = kernel_drops()
    os.kill(ag.p.pid, signal.SIGSTOP)
    ls = listener(port + 6, "127.0.0.1")
    c = socket.create_connection(("127.0.0.1", port + 6), 10)
    a, _ = ls.accept()
    th = threading.Thread(target=lambda: [None for _ in iter(lambda: a.recv(1 << 20), b"")])
    th.start()
    for _ in range(2048):
        c.sendall(FILL7)
    c.close()
    th.join()
    a.close()
    ls.close()
    os.kill(ag.p.pid, signal.SIGCONT)
    seen["ring_full"] = kernel_drops() - before
    t.check(seen["ring_full"] > 0, "ring_full (panopticon_kernel_ringbuf_drops_total): +%d by "
            "2 GiB with the agent stopped" % seen["ring_full"])
    ag.stop()
    t.note("deltas: " + json.dumps(seen, sort_keys=True))


# ── T-12 sk_storage freed, close records ordered ───────────────────────────

def storage_count(ag):
    """Elements in the agent's SOCK_STATE map, by a map iterator."""
    obj = HELPERS + "/sk_storage_count.bpf.o"
    info = json.loads(sh("bpftool", "-j", "map", "show"))
    ids = [m["id"] for m in info if m.get("name") == "SOCK_STATE"]
    if not ids or not os.path.exists(obj):
        return None
    pin = "/sys/fs/bpf/%scnt" % PFX
    sh("rm", "-f", pin, check=False)
    try:
        sh("bpftool", "iter", "pin", obj, pin, "map", "id", str(ids[0]))
        return open(pin).read().count("e\n")
    except RuntimeError as e:
        print("  storage count: " + str(e).splitlines()[-1], flush=True)
        return None
    finally:
        sh("rm", "-f", pin, check=False)


def t12(t):
    """T-12: sk_storage elements are freed with their sockets; each socket's
    close record comes after its data.

    A close record reaches no sink (the worker consumes it to free the
    connection's parser state), so its order is observed through that
    state: a close processed before its socket's last data would leave the
    connection tracked again, and panopticon_active_connections would not
    return to where it started. Restricted mode (pid_filter = [this
    process]): unscoped full arms nothing, so it has no close records."""
    k, port = 200, PORT + 120
    ag = Agent(t, "pid_self", "pid_filter = [%d]" % os.getpid()).start()

    def active():
        time.sleep(1.5)
        return int(ag.scrape().get("panopticon_active_connections", -1))
    g0, c0 = active(), storage_count(ag)
    lsock = listener(port, "127.0.0.1")
    pairs = []
    for i in range(k):
        c = socket.create_connection(("127.0.0.1", port), 10)
        a, _ = lsock.accept()
        # HTTP, so the parser tracks each socket's connection (the gauge).
        c.sendall(b"GET /B1T12x%03d HTTP/1.1\r\nHost: b1\r\n\r\n" % i)
        recv_exact(a, 37)
        a.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        recv_exact(c, 38)
        pairs.append((c, a))
    udp = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(100)]
    for u in udp:
        u.sendto(b"B1T12U", ("127.0.0.1", port + 1))
    g1, c1 = active(), storage_count(ag)
    for c, a in pairs:
        c.close()
        a.close()
    for u in udp:
        u.close()
    time.sleep(3)  # RCU-deferred frees
    g2, c2 = active(), storage_count(ag)
    ag.stop()
    unlisten(lsock)
    if c0 is None or c1 is None or c2 is None:
        t.note("sk_storage count not run: no map iterator (bpftool iter pin failed or "
               "sk_storage_count.bpf.o missing)")
        t.skip = "partial"
    else:
        t.note("SOCK_STATE elements: %d before, %d with %d TCP pairs + %d UDP open, %d after close"
               % (c0, c1, k, len(udp), c2))
        t.check(c1 - c0 >= 2 * k + len(udp), "every new socket got state (+%d)" % (c1 - c0))
        t.check(c2 - c0 <= 10, "freed at close: back to %+d of the start" % (c2 - c0))
    data = {e["connection_id"] for e in ag.tcp(port)}
    t.check(len(data) == 2 * k, "data from all %d sockets (%d)" % (2 * k, len(data)))
    t.check(not [e for e in ag.events if e["event_type"] == "SockClose"],
            "no close record in any sink")
    t.note("active_connections: %d before, %d open, %d after close" % (g0, g1, g2))
    t.check(g1 >= 2 * k, "every socket tracked while open (%d)" % g1)
    t.check(g2 - g0 <= 2, "every close processed after its socket's data: tracking back to "
            "%+d of the start" % (g2 - g0))


# ── T-13 head ──────────────────────────────────────────────────────────────

def t13_client(p, host, port, count):
    out, ports = [], []
    for i in range(count):
        s = socket.create_connection((host, port), 10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ports.append(s.getsockname()[1])
        tag = "C%05d" % ports[-1]
        for a, b in ((0, 600), (600, 1200), (1200, 3200)):  # the second crosses N
            s.sendall(pattern(tag, a, b - a))
            time.sleep(0.05)
        ok = len(recv_exact(s, 3000)) == 3000
        s.close()
        out.append(ok)
    p.report({"ok": sum(out), "n": count, "ports": ports})


def t13_forged_client(p, host, port):
    s = socket.create_connection((host, port), 10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    cport = s.getsockname()[1]
    tag = "D%05d" % cport
    s.sendall(pattern(tag, 0, 3000))
    recv_exact(s, 3000)
    time.sleep(0.3)
    origin = (queue_seq(s) - 3000) & 0xFFFFFFFF
    p.report({"port": cport, "origin": origin})
    p.wait_go()  # forged segments injected meanwhile
    s.sendall(pattern(tag, 3000, 2000))
    got = len(recv_exact(s, 2000))
    s.close()
    p.report({"reply": got})


def t13(t):
    """T-13 head_only: exactly N per direction; a crossing segment; netem loss
    with retransmissions; forged RST/SYN/data; a stream past 4 GiB."""
    n = 1000
    net = ns_up(13)
    port = PORT + 130
    ag = Agent(t, "exact_netem", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    lsock = listener(port, net.host_ip)

    def handler(c):
        recv_exact(c, 3200)
        c.sendall(pattern("S%05d" % c.getpeername()[1], 0, 3000))
        drain(c)
    serve(lsock, handler)
    r0 = tcp_counter("RetransSegs") + tcp_counter("RetransSegs", net.ns)
    phase_of = {}
    for phase, netem in (("clean", False), ("netem", True)):
        if netem:
            sh("tc", "qdisc", "add", "dev", net.hif, "root", "netem", "loss", "10%", "delay", "2ms")
            sh("ip", "netns", "exec", net.ns, "tc", "qdisc", "add", "dev", net.hif + "p", "root",
               "netem", "loss", "10%", "delay", "2ms")
        c = Proc(t13_client, net.host_ip, port, 10, netns=net.ns)
        rep = c.get(600)
        t.check(rep["ok"] == rep["n"], "%s: %d/%d connections completed" % (phase, rep["ok"], rep["n"]))
        phase_of.update((cp, phase) for cp in rep["ports"])
    retrans = tcp_counter("RetransSegs") + tcp_counter("RetransSegs", net.ns) - r0
    ag.stop()
    unlisten(lsock)
    t.check(retrans > 0, "netem caused retransmissions (%d segments)" % retrans)
    evs = ag.tcp(port)

    def tag_of(e):
        return "C%05d" % e["src_port"] if e["dst_port"] == port else "S%05d" % e["dst_port"]
    cover = head_check(t, ag, evs, n, tag_of, "exact/crossing/netem")
    cport = {e["connection_id"]: e["src_port"] if e["dst_port"] == port else e["dst_port"]
             for e in evs}
    for phase in ("clean", "netem"):
        got = {k: v for k, v in cover.items() if phase_of.get(cport[k[0]]) == phase}
        short = {k: v for k, v in got.items() if v != n}
        what = ("%s: exactly the first %d bytes of each of 40 views (10 connections x 2 directions "
                "x 2 sockets): %d views, %d short %s" % (phase, n, len(got), len(short),
                                                         list(short.values())[:5]))
        if phase == "clean":
            t.check(len(got) == 40 and not short, what)
        else:
            # Under loss a view can miss head bytes and that is allowed (it errs
            # toward not capturing): a segment that completes the handshake
            # because the bare ACK was lost reaches the hook with the listener
            # (DESIGN §2.1), and it is never sent again.
            t.note(what)
    past = ids_past(ag.hay(), lambda g: g[0] in "CS" and len(g) == 6, n)
    t.check(not past, "no stream record past N, retransmissions included (%s)" % past[:3])

    # Forged segments.
    net2 = ns_up(14)
    port = PORT + 131
    ag = Agent(t, "forged", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    lsock = listener(port, net2.host_ip)

    def handler2(c):
        recv_exact(c, 3000)
        c.sendall(pattern("E%05d" % c.getpeername()[1], 0, 3000))
        recv_exact(c, 2000)
        c.sendall(pattern("E%05d" % c.getpeername()[1], 3000, 2000))
        drain(c)
    serve(lsock, handler2)
    cl = Proc(t13_forged_client, net2.host_ip, port, netns=net2.ns)
    info = cl.get()
    o, cp = info["origin"], info["port"]
    src, dst = net2.ns_ip, net2.host_ip
    pk = [forge(src, cp, dst, port, random.getrandbits(32), random.getrandbits(32), RST),
          forge(src, cp, dst, port, random.getrandbits(32), 0, SYN),
          forge(src, cp, dst, port, o + 100, 0, ACK | PSH, b"B1T13FORGEDLO"),
          forge(src, cp, dst, port, o + n + 500, 0, ACK | PSH, b"B1T13FORGEDHI"),
          forge(src, cp, dst, port, random.getrandbits(32), 0, ACK | PSH, b"B1T13FORGEDRND")]
    inject_from(net2.ns, pk, dst)
    time.sleep(0.5)
    cl.go()
    rep = cl.get()
    ag.stop()
    unlisten(lsock)
    t.check(rep["reply"] == 2000, "the connection survived the forged RST/SYN/data")
    past = ids_past(ag.hay(), lambda g: g[0] in "DE" and len(g) == 6, n)
    t.check(not past, "after the forged segments, no genuine record past N (%s)" % past[:3])
    check_absent(t, ag, [b"B1T13FORGEDHI"], "forged data at offset N + 500")
    t.note("forged data at offset 100 (below N) captured: %s (allowed: integrity, DESIGN §3.3)"
           % bool(ag.found([b"B1T13FORGEDLO"])))
    t.note("blind forged data at a random sequence captured: %s"
           % bool(ag.found([b"B1T13FORGEDRND"])))

    # A stream past 4 GiB, both directions.
    n, port = 4096, PORT + 132
    size = int(float(os.environ.get("BIG_GIB", "4.4")) * 2 ** 30)
    ag = Agent(t, "big", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    lsock = listener(port, "127.0.0.1")
    fill = {d: (b"B1WRAP" + d.encode() + b"." * 56) * 16384 for d in ("C", "S")}
    moved = {}

    def pump(s, d, tag):
        s.sendall(pattern(tag, 0, 65536))
        left = size - 65536
        while left > 0:
            chunk = fill[d] if left >= len(fill[d]) else fill[d][:left]
            s.sendall(chunk)
            left -= len(chunk)
        s.shutdown(socket.SHUT_WR)

    def sink(s, key):
        got = 0
        while True:
            c = s.recv(1 << 20)
            if not c:
                break
            got += len(c)
        moved[key] = got
    c = socket.create_connection(("127.0.0.1", port), 10)
    a, _ = lsock.accept()
    cport = c.getsockname()[1]
    t0 = time.time()
    ths = [threading.Thread(target=pump, args=(c, "C", "W%05d" % cport)),
           threading.Thread(target=pump, args=(a, "S", "V%05d" % cport)),
           threading.Thread(target=sink, args=(a, "c2s")),
           threading.Thread(target=sink, args=(c, "s2c"))]
    for x in ths:
        x.start()
    for x in ths:
        x.join()
    secs = time.time() - t0
    c.close()
    a.close()
    unlisten(lsock)
    ag.stop()
    t.note("large stream: %.2f GiB each way in %.0f s (BIG_GIB; >= 4 GiB tests the 32-bit wrap)"
           % (min(moved.values()) / 2 ** 30, secs))
    t.check(min(moved.values()) == size, "both directions moved %d bytes" % size)
    evs = ag.tcp(port)

    def tag_big(e):
        return ("W" if e["dst_port"] == port else "V") + "%05d" % cport
    cover = head_check(t, ag, evs, n, tag_big, "4 GiB+ stream")
    t.check(len(cover) == 4 and all(v == n for v in cover.values()),
            "exactly the first %d bytes of each of the 4 views (%s)" % (n, list(cover.values())))
    check_absent(t, ag, [b"B1WRAPC", b"B1WRAPS"], "bytes past the head, past 4 GiB included")


# ── T-14 sampling ──────────────────────────────────────────────────────────

def t14(t):
    """T-14 connection_sample over 1,000 connections (2,000 sockets) at 0,
    0.5 and 1; children of one listener drawn independently."""
    k = 1000
    for rate in ("0.0", "0.5", "1.0"):
        port = PORT + 140 + int(float(rate) * 2)
        r = float(rate)
        ag = Agent(t, "rate_" + rate, 'sampling_mode = "connection_sample"\nsample_rate = %s'
                   % rate).start()
        lsock = listener(port, "127.0.0.1")

        def handler(c):
            line = recv_line(c)
            c.sendall(line.replace(b"c", b"s", 1))
            drain(c)
        serve(lsock, handler)
        sem = threading.Semaphore(8)
        ports = []

        def one(i):
            with sem:
                s = socket.create_connection(("127.0.0.1", port), 10)
                ports.append(s.getsockname()[1])
                s.sendall(b"c%s-%04d|B1T14\n" % (rate.encode(), i))
                recv_line(s)
                s.close()
        ths = [threading.Thread(target=one, args=(i,)) for i in range(k)]
        for x in ths:
            x.start()
        for x in ths:
            x.join()
        ag.stop()
        unlisten(lsock)
        evs = [e for e in ag.events if port in (e["src_port"], e["dst_port"])]
        kept = {"client": collections.defaultdict(bytearray), "server": collections.defaultdict(bytearray)}
        for e in evs:
            if e["event_type"] != "TcPacket":
                continue
            cport = e["src_port"] if e["dst_port"] == port else e["dst_port"]
            # By tuple: at rate 1 (unscoped full, DESIGN §3.4) sockets carry no role.
            role = "client" if (e["direction"] == "Egress") == (e["dst_port"] == port) else "server"
            kept[role][cport] += e["payload"]
        partial = [(role, cp) for role in kept for cp, b in kept[role].items()
                   if not (b.count(b"c%s-" % rate.encode()) == 1 and b.count(b"s%s-" % rate.encode()) == 1)]
        t.check(not partial, "rate %s: every captured socket whole, request and reply (%d partial)"
                % (rate, len(partial)))
        nc, ns_ = len(kept["client"]), len(kept["server"])
        if r == 0:
            t.check(not evs, "rate 0: nothing from the 2,000 sockets (%d events: %s)"
                    % (len(evs), collections.Counter(e["event_type"] for e in evs)))
        elif r == 1:
            t.check(nc == k and ns_ == k, "rate 1: all sockets captured (%d client, %d server)" % (nc, ns_))
        else:
            sd = math.sqrt(k * r * (1 - r))
            zc, zs = (nc - k * r) / sd, (ns_ - k * r) / sd
            both = len(set(kept["client"]) & set(kept["server"]))
            # Independence of the two endpoint draws: both kept ~ k r^2.
            zb = (both - k * r * r) / math.sqrt(k * r * r * (1 - r * r))
            t.check(abs(zc) <= 3.5 and abs(zs) <= 3.5,
                    "rate 0.5: client sockets %d (z %+.2f), children of one listener %d (z %+.2f)"
                    % (nc, zc, ns_, zs))
            t.check(abs(zb) <= 3.5, "rate 0.5: client and server draws independent (both kept %d, "
                    "z %+.2f)" % (both, zb))
            t.check(ag.scope_drop("sampled_out") > 0, "sampled_out counted")


# ── T-17 policy drops ──────────────────────────────────────────────────────

def t17_client(p, host, port):
    s = socket.create_connection((host, port), 10)
    s.sendall(b"hello\n")
    p.report({"port": s.getsockname()[1]})
    p.wait_go()
    s.close()


def t17(t):
    """T-17: a forged segment dropped by rp_filter, by an INPUT DROP rule or
    by conntrack INVALID is not captured; the same segment is captured when
    the policy lets it through (control)."""
    port = PORT + 170
    a, b = ns_up(17), ns_up(18)
    chain = PFX.upper() + "CT"
    sysctl("net.ipv4.conf.all.rp_filter", 0)
    sysctl("net.ipv4.conf.%s.rp_filter" % b.hif, 0)
    sh("iptables", "-N", chain)
    CLEAN.append(lambda: sh("iptables", "-X", chain, check=False))
    rule_ct = ["INPUT", "-p", "tcp", "--dport", str(port), "-m", "conntrack", "--ctstate",
               "INVALID", "-j", chain]
    sh("iptables", "-I", *rule_ct)
    CLEAN.append(lambda: sh("iptables", "-D", *rule_ct, check=False))
    CLEAN.append(lambda: sh("iptables", "-F", chain, check=False))
    # Restricted mode: the server (this process) is listed.
    ag = Agent(t, "pid_self", "pid_filter = [%d]" % os.getpid()).start()
    lsock = listener(port, a.host_ip)
    serve(lsock, drain)
    cl = Proc(t17_client, a.host_ip, port, netns=a.ns)
    cport = cl.get()["port"]

    def send(ns, marker, ttl=64, flags=ACK | PSH):
        pkt = forge(a.ns_ip, cport, a.host_ip, port, random.getrandbits(32), 0, flags,
                    marker, ttl)
        inject_from(ns, [pkt], a.host_ip)
        time.sleep(0.5)

    def invalid_hits():
        """Packets the conntrack INVALID rule has matched."""
        out = sh("iptables", "-L", "INPUT", "-v", "-x", "-n")
        return sum(int(l.split()[0]) for l in out.splitlines() if chain in l.split())
    # Spoofed from the other veth: strict rp_filter first, then the control
    # (rp_filter 0). Order matters: once a segment from b's veth reaches the
    # socket, TCP caches that input route on it (sk_rx_dst), early demux then
    # reuses it for later segments from the same interface, and the route
    # lookup that applies rp_filter is skipped. Shown by RPLATE below.
    sysctl("net.ipv4.conf.%s.rp_filter" % b.hif, 1)
    rp0 = tcp_counter("IPReversePathFilter")
    send(b.ns, b"B1T17RPDROP")
    rp1 = tcp_counter("IPReversePathFilter")
    t.check(rp1 > rp0, "rp_filter dropped the spoofed segment (IPReversePathFilter +%d)" % (rp1 - rp0))
    sysctl("net.ipv4.conf.%s.rp_filter" % b.hif, 0)
    send(b.ns, b"B1T17RPCTL")
    sysctl("net.ipv4.conf.%s.rp_filter" % b.hif, 1)
    send(b.ns, b"B1T17RPLATE")
    rp_late = tcp_counter("IPReversePathFilter") - rp1
    send(a.ns, b"B1T17INCTL", 64)
    rule_in = ["INPUT", "-p", "tcp", "--dport", str(port), "-m", "ttl", "--ttl-eq", "77",
               "-j", "DROP"]
    sh("iptables", "-I", *rule_in)
    CLEAN.append(lambda: sh("iptables", "-D", *rule_in, check=False))
    send(a.ns, b"B1T17INDROP", 77)
    # conntrack INVALID: SYN|FIN is an invalid flag combination for every
    # conntrack version (an out-of-window segment is no longer INVALID on
    # newer kernels, which ignore it instead). Control: the chain is empty.
    bad_flags = SYN | FIN | ACK | PSH
    h0 = invalid_hits()
    send(a.ns, b"B1T17CTCTL", flags=bad_flags)
    h1 = invalid_hits()
    sh("iptables", "-A", chain, "-j", "DROP")
    send(a.ns, b"B1T17CTDROP", flags=bad_flags)
    t.check(h1 > h0 and invalid_hits() > h1,
            "conntrack marked both SYN|FIN segments INVALID (rule hits %d, %d, %d)"
            % (h0, h1, invalid_hits()))
    cl.go()
    ag.stop()
    unlisten(lsock)
    for policy, ctl, dropped in (("rp_filter", b"B1T17RPCTL", b"B1T17RPDROP"),
                                 ("INPUT DROP", b"B1T17INCTL", b"B1T17INDROP"),
                                 ("conntrack INVALID", b"B1T17CTCTL", b"B1T17CTDROP")):
        check_present(t, ag, [ctl], "%s control: the segment reaches the socket and is captured" % policy)
        check_absent(t, ag, [dropped], "%s: the dropped segment" % policy)
    t.note("strict rp_filter after one accepted segment from the same veth: IPReversePathFilter "
           "+%d, the spoofed segment captured: %s (early demux reuses the socket's cached input "
           "route, so rp_filter is not applied and the segment is not dropped)"
           % (rp_late, bool(ag.found([b"B1T17RPLATE"]))))


# ── T-20 reconnect ─────────────────────────────────────────────────────────

def t20_client(p, port1, port2, run):
    p.wait_go()
    s = socket.create_connection(("127.0.0.1", port1), 10)
    s.sendall(b"B1T20A1x%s\n" % run)
    recv_line(s)
    disconnect(s)
    time.sleep(0.3)
    s.connect(("127.0.0.1", port2))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"B1T20A2x%s\n" % run)
    recv_line(s)
    p.report({"port2": s.getsockname()[1]})
    s.close()


def t20(t):
    """T-20: connect(AF_UNSPEC) then a reconnect on one socket: nothing from
    the second connection's socket in any restricted mode; captured in
    unscoped full."""
    port1, port2 = PORT + 200, PORT + 201
    # sample_rate 1 is unscoped full (DESIGN §3.4); 0.9999 is the restricted
    # sampling mode, keeping a socket with probability 0.9999.
    runs = [("unscoped_full", ""), ("pid", None), ("sample", 'sampling_mode = "connection_sample"\n'
            'sample_rate = 0.9999'), ("head", 'sampling_mode = "head_only"\nhead_only_bytes = 4096')]
    if UNIFIED:
        runs.append(("cgroup", 'cgroup_filter = ["%s"]' % cg_make("t20")))
    else:
        t.note("cgroup_filter run not run: no unified cgroup2")
    for run, scope in runs:
        l1, l2 = listener(port1, "127.0.0.1"), listener(port2, "127.0.0.1")

        def reply(c):
            line = recv_line(c)
            c.sendall(line.replace(b"A", b"B", 1))
            drain(c)
        serve(l1, reply)
        serve(l2, reply)
        c = Proc(t20_client, port1, port2, run.encode(), cgroup="t20" if run == "cgroup" else None)
        if scope is None:
            scope = "pid_filter = [%d]" % c.pid
        ag = Agent(t, run, scope).start()
        c.go()
        cp2 = c.get()["port2"]
        c.join()
        ag.stop()
        unlisten(l1)
        unlisten(l2)
        a1, b1 = b"B1T20A1x" + run.encode(), b"B1T20B1x" + run.encode()
        a2, b2 = b"B1T20A2x" + run.encode(), b"B1T20B2x" + run.encode()
        client2 = [e for e in ag.events if e["event_type"] == "TcPacket" and (
            (e["direction"] == "Egress" and e["src_port"] == cp2 and e["dst_port"] == port2)
            or (e["direction"] == "Ingress" and e["dst_port"] == cp2 and e["src_port"] == port2))]
        mine = b"".join(e["payload"] for e in client2)
        check_present(t, ag, [a1, b1], "%s: first connection" % run)
        if run == "unscoped_full":
            t.check(a2 in mine and b2 in mine, "%s: second connection captured on the reused "
                    "socket (%d events)" % (run, len(client2)))
            continue
        t.check(not client2, "%s: nothing from the reused socket's second connection (%d events)"
                % (run, len(client2)))
        if run in ("pid", "cgroup"):
            check_absent(t, ag, [a2, b2], "%s: second connection (the server is out of scope)" % run)
        t.check(ag.scope_drop("uninit") > 0, "%s: reused socket's packets counted uninit" % run)


# ── T-22 TCP repair ────────────────────────────────────────────────────────

def t22(t):
    """T-22: a CRIU-style dump and restore of a stream already past N, through
    native and 32-bit setsockopt and io_uring: nothing after the restore is
    exported under head_only."""
    n, port = 1000, PORT + 220
    variants = [("native64", "tcp_repair", False), ("compat32", "tcp_repair32", False)]
    if RELEASE >= (6, 7):
        variants += [("uring64", "tcp_repair", True), ("uring32", "tcp_repair32", True)]
    else:
        t.note("io_uring setsockopt variants not run: SOCKET_URING_OP_SETSOCKOPT needs 6.7+")
    ag = Agent(t, "head1000", 'sampling_mode = "head_only"\nhead_only_bytes = %d' % n).start()
    lsock = listener(port, "127.0.0.1")
    tags = []

    def server(c):
        recv_exact(c, 3000)
        c.sendall(b"".join(b"B1T22HISTS-%06d|" % i + b"." * 15 for i in range(94))[:3000])
        got = recv_exact(c, 2000)
        tag = re.search(rb"B1T22OUTC(\w+?)-", got)
        tag = tag.group(1) if tag else b"?"
        c.sendall((b"B1T22OUTS" + tag + b"-" + b"." * 40) * 40)
        drain(c)
    serve(lsock, server)
    for name, binary, uring in variants:
        before = ag.drops().get("no_baseline", 0)
        r = subprocess.run([os.path.join(HELPERS, binary), "127.0.0.1", str(port), name]
                           + (["uring"] if uring else []), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, universal_newlines=True, timeout=60)
        delta = ag.drops().get("no_baseline", 0) - before
        if t.check(r.returncode == 0, "%s: restored (%s)" % (name, r.stdout.strip()[-120:])):
            tags.append(name)
            t.check(delta > 0, "%s: the restored socket's packets counted no_baseline (+%d)"
                    % (name, delta))
    ag.stop()
    unlisten(lsock)
    for name in tags:
        check_present(t, ag, [b"B1T22HISTC" + name.encode() + b"-000000|"],
                      "%s: the original stream's head (in scope before the dump)" % name)
        check_absent(t, ag, [b"B1T22OUTC" + name.encode(), b"B1T22OUTS" + name.encode()],
                     "%s: both directions after the restore" % name)


TESTS = collections.OrderedDict(
    (f.__name__, f) for f in (t1, t3, t4, t7, t8, t9, t11, t12, t13, t14, t15, t17, t20, t22))


def main():
    names = sys.argv[1:]
    if names == ["all"]:
        names = list(TESTS)
    if not names or any(n not in TESTS for n in names):
        sys.exit("usage: scope_lab.py TEST... | all (%s)" % " ".join(TESTS))
    status = 0
    for name in names:
        t = Test(name)
        print("==== %s (%s, kernel %s)" % (name, TESTS[name].__doc__.split("\n")[0],
                                         os.uname().release), flush=True)
        t0 = time.time()
        try:
            TESTS[name](t)
        except Exception as e:
            traceback.print_exc()
            t.fail.append("error: %r" % e)
        finally:
            while CLEAN:
                try:
                    CLEAN.pop()()
                except Exception:
                    pass
        result = "fail" if t.fail else (t.skip if t.skip else "pass")
        status |= bool(t.fail)
        os.makedirs(os.path.join(OUT, name), exist_ok=True)
        with open(os.path.join(OUT, name, "result.json"), "w") as f:
            json.dump({"test": name, "kernel": os.uname().release, "result": result,
                       "failures": t.fail, "notes": t.notes, "secs": round(time.time() - t0)},
                      f, indent=1)
        print("==== %s: %s (%d s)" % (name, result.upper(), time.time() - t0), flush=True)
    sys.exit(status)


if __name__ == "__main__":
    main()
