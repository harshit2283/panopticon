"""Ground-truth gRPC traffic (HTTP/2, plaintext) for scoring the agent.

One process, two modes:
  server: python grpc_oracle.py server HOST:PORT
  client: python grpc_oracle.py client HOST:PORT N OUT [SEED]

Uses generic handlers with raw-bytes (de)serialisers, so no .proto files.
Methods:
  /oracle.Svc/Echo     unary; request carries JSON with an email -> reply
  /oracle.Svc/Fail     unary; server aborts with NOT_FOUND (trailers-only reply)
  /oracle.Svc/Stream   server-streaming; returns 3-8 messages
Every call sends its token (`tok_<id>_`) as `x-oracle-id` metadata and in the
request body; the truth records method path, expected grpc-status and PII.
"""
import json
import random
import sys
import time
from concurrent import futures

import grpc

MODE, ADDR = sys.argv[1], sys.argv[2]
IDENT = (lambda b: b, lambda b: b)


def echo(request, context):
    return b'{"ok":true,"echo":' + json.dumps(request.decode(errors="replace")).encode() + b"}"


def fail(request, context):
    context.abort(grpc.StatusCode.NOT_FOUND, "no such record")


def stream(request, context):
    for k in range(int(json.loads(request)["n"])):
        yield json.dumps({"row": k, "pad": "x" * 200}).encode()


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    handlers = {
        "Echo": grpc.unary_unary_rpc_method_handler(echo, *IDENT),
        "Fail": grpc.unary_unary_rpc_method_handler(fail, *IDENT),
        "Stream": grpc.unary_stream_rpc_method_handler(stream, *IDENT),
    }
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("oracle.Svc", handlers),))
    server.add_insecure_port(ADDR)
    server.start()
    server.wait_for_termination()


def client():
    n, out = int(sys.argv[3]), sys.argv[4]
    rnd = random.Random(int(sys.argv[5]) if len(sys.argv) > 5 else 1234)
    channel = grpc.insecure_channel(ADDR)
    grpc.channel_ready_future(channel).result(timeout=20)
    echo_rpc = channel.unary_unary("/oracle.Svc/Echo", *reversed(IDENT))
    fail_rpc = channel.unary_unary("/oracle.Svc/Fail", *reversed(IDENT))
    stream_rpc = channel.unary_stream("/oracle.Svc/Stream", *reversed(IDENT))
    truth = []
    for i in range(n):
        tok = f"tok_{i}_"
        md = (("x-oracle-id", tok),)
        r = rnd.random()
        if r < 0.6:
            email = f"user{i}@example.com"
            body = json.dumps({"id": tok, "email": email, "pad": "p" * rnd.choice([10, 500, 3000])})
            echo_rpc(body.encode(), metadata=md)
            truth.append({"id": tok, "path": "/oracle.Svc/Echo", "grpc_status": 0, "pii": [email]})
        elif r < 0.8:
            try:
                fail_rpc(json.dumps({"id": tok}).encode(), metadata=md)
            except grpc.RpcError:
                pass
            truth.append({"id": tok, "path": "/oracle.Svc/Fail", "grpc_status": 5, "pii": []})
        else:
            k = rnd.randint(3, 8)
            list(stream_rpc(json.dumps({"id": tok, "n": k}).encode(), metadata=md))
            truth.append({"id": tok, "path": "/oracle.Svc/Stream", "grpc_status": 0, "pii": []})
    with open(out, "w") as f:
        for t in truth:
            f.write(json.dumps({**t, "proto": "grpc"}) + "\n")
    print(f"grpc: {len(truth)} calls", file=sys.stderr)


serve() if MODE == "server" else client()
