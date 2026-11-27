"""Ground-truth Kafka, AMQP (RabbitMQ) and DNS traffic for scoring the agent.

Runs a seeded mix of operations against a real server and writes one truth
record per operation it completed. Each record carries the unique token(s)
(`tok_<id>_`) the operation put on the wire, the expected operation name, the
expected topic / routing key / queue / query name, the expected status, and
the PII values it sent. Records a consumer received back (Kafka Fetch, AMQP
Basic.Deliver) are truth entries too. score_mq.py matches the agent's export
against it.

Record fields:
  id      token identifying the operation
  proto   kafka | amqp | dns
  kind    how score_mq.py scores it (see there)
  verb    expected `method` in the agent's record
  path    expected `path` (topic, exchange/routing-key, queue, qname)
  status  expected `status` (Kafka error code, AMQP reply code, DNS rcode)
  tokens  every token the operation carried (batched produce: one per record)
  pii     PII values the operation sent
  via     transport / variant, for the recall breakdown
  partition, offset   (Kafka fetch only) where the consumer read the record,
          so score_mq.py can place it in the Fetch response that carried it
  size    (Kafka fetch only) the record value's byte length: a Fetch
          response smaller than it cannot have carried the record

Kafka Fetch and the agent's body cap (max_body_bytes, 4096 by default): the
producer waits after each operation until the consumer has every record
produced so far, so a Fetch response carries one operation's records, all
in one partition, and stays below the cap. Records piled up in one fetch
would make its size, and whether and where the cap cuts it, depend on the
VM's timing, and a record of another partition past a cut cannot be told
from one the agent dropped (score_mq.py). Two held phases build the large
and multi-topic responses deliberately: the consumer is paused, a Fetch
parked before the pause is let expire, the records are produced and
acknowledged, then the consumer resumes, so the next Fetch request leaves
after every acknowledgement:
  cut     several 2000-byte records to one partition, one response larger
          than the cap: the records past its cut are in the cut record's
          partition, which score_mq.py proves (via "consume-cut")
  multi   one small record to each of several topics, one response of
          several topics below the cap (via "consume-multi")

Usage:
  python mq_oracle.py kafka HOST N OUT [SEED]
  python mq_oracle.py amqp HOST N OUT [SEED]
  python mq_oracle.py dns HOST N OUT [SEED]
  python mq_oracle.py dns-server HOST          # authoritative toy server, :53
Needs: confluent-kafka, kafka-python, pika, dnspython.
"""
import json
import random
import socket
import struct
import sys
import time

PROTO, HOST = sys.argv[1], sys.argv[2]
if PROTO != "dns-server":
    N, OUT = int(sys.argv[3]), sys.argv[4]
    SEED = int(sys.argv[5]) if len(sys.argv) > 5 else 1234
    rnd = random.Random(SEED)
truth = []


def record(tok, kind, verb, path, status=0, tokens=None, pii=None, via="", **extra):
    truth.append({"id": tok, "proto": PROTO, "kind": kind, "verb": verb, "path": path,
                  "status": status, "tokens": tokens or [tok], "pii": pii or [], "via": via,
                  **extra})


def body(tok, i, pad=0, with_pii=True):
    doc = {"id": tok, "seq": i}
    pii = []
    if with_pii:
        doc["email"] = f"user{i}@example.com"
        pii.append(doc["email"])
    if pad:
        doc["pad"] = "x" * pad
    return json.dumps(doc).encode(), pii


# ── Kafka ────────────────────────────────────────────────────────────────

KAFKA_TOPICS = ["orders", "user.events", "audit-log_v2", "payments.eu-west-1.settled"]
SMALL_TOPIC = "o3.small"  # max.message.bytes=1024: larger records are rejected
FETCH_WAIT_MS = 500  # the consumer's fetch.wait.max.ms


def raw_metadata(sock, version, topic, cid):
    """One Metadata request for `topic`; returns the topic's error code."""
    flex = version >= 9
    name = topic.encode()
    head = struct.pack(">hhih", 3, version, cid, 6) + b"oracle" + (b"\0" if flex else b"")
    if version >= 10:
        body = b"\x02" + b"\0" * 16 + bytes([len(name) + 1]) + name + b"\0" + b"\0\0\0"
    elif flex:
        body = b"\x02" + bytes([len(name) + 1]) + name + b"\0" + b"\0\0\0\0"
    else:
        body = struct.pack(">ih", 1, len(name)) + name + (b"\0" if version >= 4 else b"")
    msg = head + body
    sock.sendall(struct.pack(">i", len(msg)) + msg)
    size = struct.unpack(">i", recv_exact(sock, 4))[0]
    resp = recv_exact(sock, size)
    # The topic's error code is the i16 right before its name in the body.
    at = resp.rfind(name)
    if at < 0:
        return None
    pre = 2 if version < 9 else 1  # name length: i16, or a 1-byte varint
    return struct.unpack(">h", resp[at - pre - 2:at - pre])[0]


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("broker closed the connection")
        buf += chunk
    return buf


def run_kafka():
    import queue
    import threading

    from confluent_kafka import OFFSET_END, Consumer, KafkaException, Producer, TopicPartition
    from confluent_kafka.admin import AdminClient, NewTopic

    bootstrap = f"{HOST}:9092"
    admin = AdminClient({"bootstrap.servers": bootstrap})
    fs = admin.create_topics(
        [NewTopic(t, num_partitions=2, replication_factor=1) for t in KAFKA_TOPICS]
        + [NewTopic(SMALL_TOPIC, num_partitions=1, replication_factor=1,
                    config={"max.message.bytes": "1024"})])
    for f in fs.values():
        try:
            f.result()
        except KafkaException:
            pass  # already exists
    conf = {"bootstrap.servers": bootstrap, "allow.auto.create.topics": False}
    # linger.ms lets a burst of produce() calls to one partition share a
    # RecordBatch; flush() sends whatever is queued immediately. librdkafka
    # sends one ProduceRequest per partition.
    prod = Producer({**conf, "linger.ms": 50, "acks": "all", "retries": 0,
                     "compression.type": "none"})

    def delivered(errs):
        return lambda err, msg: errs.append(err)

    # Warm up: wait until every partition has a leader and accepts writes, so
    # the first operations do not hit NOT_LEADER retries.
    for t in KAFKA_TOPICS:
        for p in range(2):
            for _ in range(50):
                errs = []
                prod.produce(t, value=b"warmup", partition=p, on_delivery=delivered(errs))
                prod.flush(10)
                if errs and errs[0] is None:
                    break
                time.sleep(0.2)

    # Consume concurrently, from the end of each partition: Fetch responses
    # carry back the records produced below, a few at a time.
    # fetch.wait.max.ms is librdkafka's default, set so that the held
    # phases below wait out a parked Fetch for certain.
    cons = Consumer({**conf, "group.id": f"o3-{SEED}", "enable.auto.commit": False,
                     "fetch.wait.max.ms": FETCH_WAIT_MS})
    every = [TopicPartition(t, p) for t in KAFKA_TOPICS for p in range(2)]
    cons.assign([TopicPartition(t, p, OFFSET_END) for t in KAFKA_TOPICS for p in range(2)])
    consumed = {}  # token -> (partition, offset)
    got = threading.Condition()
    stop = threading.Event()
    # (Consumer method, done) for the consumer thread: pause() called from
    # another thread while poll() runs deadlocks, so the thread that polls
    # pauses and resumes.
    control = queue.Queue()

    def consume():
        while not stop.is_set():
            while not control.empty():
                call, done = control.get()
                call(every)
                done.set()
            msg = cons.poll(0.05)
            if msg is None or msg.error():
                continue
            try:
                tok = json.loads(msg.value())["id"]
            except (ValueError, KeyError, TypeError):
                continue
            with got:
                consumed[tok] = (msg.partition(), msg.offset())
                got.notify_all()

    consumer = threading.Thread(target=consume)
    consumer.start()
    time.sleep(2)  # assignment and first Fetch

    from kafka import KafkaProducer

    classic = KafkaProducer(bootstrap_servers=bootstrap, api_version=(2, 5), linger_ms=0,
                            acks="all")
    raw = socket.create_connection((HOST, 9092))
    produced = {}  # token -> (topic, pii, value size)
    fetch_via = {}  # token -> truth `via` of its Fetch record, if not "consume"

    def drain():
        """Wait until the consumer has every record produced so far."""
        with got:
            if not got.wait_for(lambda: produced.keys() <= consumed.keys(), timeout=10):
                print(f"mq_oracle: {len(produced.keys() - consumed.keys())} records not consumed "
                      f"after 10 s (op {i})", file=sys.stderr, flush=True)

    def on_consumer(call):
        done = threading.Event()
        control.put((call, done))
        if not done.wait(30):
            sys.exit(f"mq_oracle: consumer thread did not run {call.__name__}")

    def held(produce_all):
        """Run `produce_all` with the consumer paused: the next Fetch request
        leaves after its records are acknowledged (module docstring)."""
        drain()
        on_consumer(cons.pause)
        time.sleep(3 * FETCH_WAIT_MS / 1000)  # a Fetch parked before the pause expires
        produce_all()
        on_consumer(cons.resume)
        drain()

    def single(tok, i, topic, pad, with_pii, partition=None, via="single", headers=None):
        """Produce one record and wait for its acknowledgement."""
        value, pii = body(tok, i, pad=pad, with_pii=with_pii)
        errs = []
        kw = {} if partition is None else {"partition": partition}
        prod.produce(topic, key=f"k-{tok}".encode(), value=value, headers=headers,
                     on_delivery=delivered(errs), **kw)
        prod.flush(10)
        if errs and errs[0] is None:
            record(tok, "produce", "Produce", topic, pii=pii, via=via)
            produced[tok] = (topic, pii, len(value))
            return True
        return False

    i = 0
    while i < N:
        r = rnd.random()
        tok = f"tok_{i}_"
        if r < 0.45:
            topic = rnd.choice(KAFKA_TOPICS)
            pad = rnd.choice([0, 0, 200, 2000])
            with_pii = rnd.random() < 0.7
            headers = [("trace-id", f"t-{i}".encode())] if rnd.random() < 0.3 else None
            single(tok, i, topic, pad, with_pii, headers=headers,
                   via="single+headers" if headers else "single")
            drain()
            i += 1
        elif r < 0.65:
            # Batched: several records to one partition, one RecordBatch.
            k = min(rnd.randint(2, 6), N - i)
            topic = rnd.choice(KAFKA_TOPICS)
            part = rnd.randint(0, 1)
            toks, pii, errs, each = [], [], [], {}
            for j in range(i, i + k):
                t = f"tok_{j}_"
                value, p = body(t, j, with_pii=rnd.random() < 0.5)
                prod.produce(topic, key=f"k-{t}".encode(), value=value, partition=part,
                             on_delivery=delivered(errs))
                toks.append(t)
                pii += p
                each[t] = (topic, p, len(value))
            prod.flush(10)
            if all(e is None for e in errs):
                record(toks[0], "produce", "Produce", topic, tokens=toks, pii=pii, via="batch")
                produced.update(each)
            drain()
            i += k
        elif r < 0.75:
            # Rejected by the broker: MESSAGE_TOO_LARGE (10).
            value, _ = body(tok, i, pad=1500, with_pii=False)
            errs = []
            prod.produce(SMALL_TOPIC, key=f"k-{tok}".encode(), value=value,
                         on_delivery=delivered(errs))
            prod.flush(10)
            if errs and errs[0] is not None:
                record(tok, "produce", "Produce", SMALL_TOPIC, status=10, via="rejected")
            i += 1
        elif r < 0.85:
            # Classic (pre-flexible) encodings: kafka-python pinned to the
            # protocol of a 2.5 broker (Produce v8).
            topic = rnd.choice(KAFKA_TOPICS)
            value, pii = body(tok, i, with_pii=True)
            classic.send(topic, key=f"k-{tok}".encode(), value=value).get(timeout=10)
            record(tok, "produce", "Produce", topic, pii=pii, via="classic")
            produced[tok] = (topic, pii, len(value))
            drain()
            i += 1
        elif r < 0.88:
            # Held cut: 2000-byte records, each its own Produce (each below
            # the cap), to one partition; one Fetch response carries them all.
            k = min(rnd.randint(3, 4), N - i)
            topic, part = rnd.choice(KAFKA_TOPICS), rnd.randint(0, 1)

            def cut(i=i, k=k, topic=topic, part=part):
                for j in range(i, i + k):
                    if single(f"tok_{j}_", j, topic, 2000, rnd.random() < 0.7, partition=part):
                        fetch_via[f"tok_{j}_"] = "consume-cut"
            held(cut)
            i += k
        elif r < 0.91:
            # Held multi-topic: one small record to each of several topics.
            topics = rnd.sample(KAFKA_TOPICS, min(rnd.randint(2, 4), N - i))

            def multi(i=i, topics=topics):
                for j, topic in enumerate(topics, i):
                    if single(f"tok_{j}_", j, topic, 0, rnd.random() < 0.7,
                              partition=rnd.randint(0, 1)):
                        fetch_via[f"tok_{j}_"] = "consume-multi"
            held(multi)
            i += len(topics)
        else:
            # Metadata for a topic that does not exist: UNKNOWN_TOPIC_OR_PARTITION
            # (3), over a raw socket at a chosen version so that each operation
            # is exactly one exchange (librdkafka re-requests every topic it
            # was ever asked about).
            topic = f"missing.{tok}"
            version = rnd.choice([1, 4, 9, 12])
            if raw_metadata(raw, version, topic, i) == 3:
                record(tok, "metadata", "Metadata", topic, status=3, via=f"v{version}")
            i += 1

    classic.close()
    raw.close()
    deadline = time.time() + 20
    while not set(produced) <= consumed.keys() and time.time() < deadline:
        time.sleep(0.2)
    stop.set()
    consumer.join()
    cons.close()
    for tok, (topic, pii, size) in produced.items():
        if tok in consumed:
            part, offset = consumed[tok]
            record(f"fetch:{tok}", "fetch", "Fetch", topic, tokens=[tok], pii=pii,
                   via=fetch_via.get(tok, "consume"), partition=part, offset=offset, size=size)


# ── AMQP 0-9-1 ───────────────────────────────────────────────────────────


def run_amqp():
    import pika
    from pika.exceptions import ChannelClosedByBroker, UnroutableError

    params = pika.ConnectionParameters(host=HOST, port=5672,
                                       credentials=pika.PlainCredentials("oracle", "oracle"))
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.exchange_declare("o3.topic", "topic")
    ch.exchange_declare("o3.fanout", "fanout")
    ch.exchange_declare("o3.direct", "direct")
    for q in ("q.topic", "q.fanout", "q.direct", "q.default", "q.get"):
        ch.queue_declare(q)
        ch.queue_purge(q)
    ch.queue_bind("q.topic", "o3.topic", "orders.#")
    ch.queue_bind("q.fanout", "o3.fanout")
    ch.queue_bind("q.direct", "o3.direct", "invoices")
    confirm = conn.channel()
    confirm.confirm_delivery()  # publishes on it wait for the broker's Basic.Ack

    consumed = []  # (token, path, pii) of messages that a consumer should receive
    acks = 0  # Basic.Ack sent by the client
    i = 0
    while i < N:
        tok = f"tok_{i}_"
        r = rnd.random()
        props = None
        if rnd.random() < 0.3:
            props = pika.BasicProperties(content_type="application/json",
                                         headers={"x-trace": f"t-{i}"}, delivery_mode=2)
        pad = rnd.choice([0, 0, 0, 300, 6000])  # 6 KB: more than one 4 KB capture slot
        payload, pii = body(tok, i, pad=pad, with_pii=rnd.random() < 0.7)
        via = "large" if pad > 4000 else ""
        if r < 0.20:
            rk = f"orders.{tok}.created"
            ch.basic_publish("o3.topic", rk, payload, props)
            record(tok, "publish", "Basic.Publish", f"o3.topic/{rk}", pii=pii, via=via or "topic")
            consumed.append((tok, f"o3.topic/{rk}", pii))
        elif r < 0.32:
            rk = f"fan.{tok}"
            ch.basic_publish("o3.fanout", rk, payload, props)
            record(tok, "publish", "Basic.Publish", f"o3.fanout/{rk}", pii=pii, via=via or "fanout")
            consumed.append((tok, f"o3.fanout/{rk}", pii))
        elif r < 0.42:
            ch.basic_publish("o3.direct", "invoices", payload, props)
            record(tok, "publish", "Basic.Publish", "o3.direct/invoices", pii=pii,
                   via=via or "direct")
            consumed.append((tok, "o3.direct/invoices", pii))
        elif r < 0.52:
            # Default exchange, publisher confirms.
            confirm.basic_publish("", "q.default", payload, props)
            record(tok, "publish", "Basic.Publish", "q.default", pii=pii, via=via or "confirm")
            consumed.append((tok, "q.default", pii))
        elif r < 0.72:
            # Basic.Get: publish to q.get, then fetch it back synchronously.
            ch.basic_publish("", "q.get", payload, props)
            record(f"pub:{tok}", "publish", "Basic.Publish", "q.get", tokens=[tok], pii=pii,
                   via=via or "default")
            for _ in range(50):
                method, _, got = ch.basic_get("q.get", auto_ack=False)
                if method is not None:
                    break
                time.sleep(0.02)
            if method is not None and json.loads(got)["id"] == tok:
                ch.basic_ack(method.delivery_tag)
                acks += 1
                record(f"get:{tok}", "get", "Basic.Get", "q.get", tokens=[tok], pii=pii,
                       via=via or "get")
        elif r < 0.80:
            # Unroutable mandatory publish on a confirm channel: Basic.Return 312.
            rk = f"nowhere.{tok}"
            try:
                confirm.basic_publish("o3.direct", rk, payload, props, mandatory=True)
            except UnroutableError:
                pass
            record(f"pub:{tok}", "publish", "Basic.Publish", f"o3.direct/{rk}", tokens=[tok],
                   pii=pii, via="mandatory")
            record(tok, "return", "Basic.Return", f"o3.direct/{rk}", status=312, pii=pii,
                   via="unroutable")
        else:
            # Basic.Get on a queue that does not exist: Channel.Close 404.
            q = f"missing.{tok}"
            try:
                ch.basic_get(q)
            except ChannelClosedByBroker:
                ch = conn.channel()
                # pika 1.5 also queues the closure on the connection and
                # raises it again from the next process_data_events (here,
                # the consume loop below): take it now.
                try:
                    conn.process_data_events(time_limit=0)
                except ChannelClosedByBroker:
                    pass
            record(tok, "get", "Basic.Get", q, status=404, via="missing-queue")
        i += 1

    # Consume what was routed to queues, acking each delivery.
    want = {tok: (path, pii) for tok, path, pii in consumed}
    got = set()
    for q in ("q.topic", "q.fanout", "q.direct", "q.default"):
        for method, _, got_body in ch.consume(q, inactivity_timeout=2):
            if method is None:
                break
            tok = json.loads(got_body)["id"]
            ch.basic_ack(method.delivery_tag)
            acks += 1
            if tok in want and tok not in got:
                got.add(tok)
                record(f"deliver:{tok}", "deliver", "Basic.Deliver", want[tok][0], tokens=[tok],
                       pii=want[tok][1], via="consume")
        ch.cancel()
    conn.close()
    truth.append({"id": "acks", "proto": "amqp", "kind": "count", "verb": "Basic.Ack",
                  "count": acks, "tokens": [], "pii": []})


# ── DNS ──────────────────────────────────────────────────────────────────

ZONE = "oracle.test"


def run_dns():
    import dns.message
    import dns.query
    import dns.rcode
    import dns.rdatatype

    for i in range(N):
        tok = f"tok_{i}_"
        r = rnd.random()
        if r < 0.35:
            kind, qtype, rcode = "a", "A", 0
        elif r < 0.55:
            kind, qtype, rcode = "aaaa", "AAAA", 0
        elif r < 0.70:
            kind, qtype, rcode = "cname", "A", 0
        elif r < 0.85:
            kind, qtype, rcode = "nx", "A", 3
        elif r < 0.92:
            kind, qtype, rcode = "fail", "A", 2
        else:
            kind, qtype, rcode = "txt", "TXT", 0
        qname = f"{kind}-{tok}.{ZONE}"
        q = dns.message.make_query(qname, qtype)
        tcp = rnd.random() < 0.1
        resp = (dns.query.tcp if tcp else dns.query.udp)(q, HOST, timeout=5)
        assert resp.rcode() == rcode, (qname, resp.rcode())
        answers = [str(rd) for rrset in resp.answer for rd in rrset
                   if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME)]
        truth.append({"id": tok, "proto": "dns", "kind": "query", "verb": "QUERY",
                      "path": qname, "qtype": qtype, "status": rcode, "tokens": [tok],
                      "answers": [a.rstrip(".") for a in answers], "pii": [],
                      "via": "tcp" if tcp else "udp"})


def dns_answer(qname):
    """Deterministic answers derived from the token in the name."""
    label = qname.split(".")[0]
    kind, _, tok = label.partition("-")
    n = int(tok.split("_")[1]) if tok.startswith("tok_") else 0
    return kind, f"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}", f"fd00::{n:x}"


def dns_server():
    import socket
    import socketserver
    import threading

    import dns.message
    import dns.rcode
    import dns.rrset

    def answer(wire):
        q = dns.message.from_wire(wire)
        resp = dns.message.make_response(q)
        resp.flags |= 0x0400  # AA
        qname = q.question[0].name.to_text()
        kind, v4, v6 = dns_answer(qname)
        if kind == "nx":
            resp.set_rcode(dns.rcode.NXDOMAIN)
        elif kind == "fail":
            resp.set_rcode(dns.rcode.SERVFAIL)
        elif kind == "a":
            resp.answer.append(dns.rrset.from_text(qname, 60, "IN", "A", v4))
        elif kind == "aaaa":
            resp.answer.append(dns.rrset.from_text(qname, 60, "IN", "AAAA", v6))
        elif kind == "cname":
            target = "target-" + qname.split("-", 1)[1]
            resp.answer.append(dns.rrset.from_text(qname, 60, "IN", "CNAME", target))
            resp.answer.append(dns.rrset.from_text(target, 60, "IN", "A", v4))
        elif kind == "txt":
            resp.answer.append(dns.rrset.from_text(qname, 60, "IN", "TXT", '"v=oracle"'))
        return resp.to_wire()

    class Udp(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(answer(data), self.client_address)

    class Tcp(socketserver.BaseRequestHandler):
        def handle(self):
            f = self.request.makefile("rb")
            while True:
                hdr = f.read(2)
                if len(hdr) < 2:
                    return
                wire = answer(f.read(int.from_bytes(hdr, "big")))
                self.request.sendall(len(wire).to_bytes(2, "big") + wire)

    class UdpServer(socketserver.ThreadingUDPServer):
        allow_reuse_address = True

    class TcpServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        address_family = socket.AF_INET

    udp = UdpServer((HOST, 53), Udp)
    tcp = TcpServer((HOST, 53), Tcp)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print("dns server ready", flush=True)
    udp.serve_forever()


if PROTO == "dns-server":
    dns_server()
    sys.exit(0)
{"kafka": run_kafka, "amqp": run_amqp, "dns": run_dns}[PROTO]()
with open(OUT, "w") as f:
    for t in truth:
        f.write(json.dumps(t) + "\n")
print(f"{PROTO}: {len(truth)} operations", file=sys.stderr)
