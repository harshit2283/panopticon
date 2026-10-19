"""Ground-truth database traffic for scoring the agent: Redis, PostgreSQL, MySQL.

Runs a seeded mix of operations against a real server and writes one truth
record per operation it completed: protocol, expected command verb, whether
the server returned an error, the PII values it sent, and a unique token
(`tok_<id>_`) embedded in the key / SQL text / table name so score_db.py can
find the agent's record — including for errors, whose server message names
the table.

PostgreSQL alternates the simple query protocol and the extended protocol
(Parse/Bind/Execute, what drivers use for parameterised queries). In the
extended case the token is in the SQL text but the PII travels as a bind
parameter, which measures whether the agent sees parameter values.

Usage: python db_oracle.py {redis|postgres|mysql} HOST N OUT [SEED]
Needs: redis, psycopg[binary], pymysql.
"""
import json
import random
import sys

PROTO, HOST, N, OUT = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
SEED = int(sys.argv[5]) if len(sys.argv) > 5 else 1234
rnd = random.Random(SEED)
truth = []


def record(i, verb, error=False, pii=None, via=""):
    truth.append({"id": f"tok_{i}_", "proto": PROTO, "verb": verb, "error": error,
                  "pii": pii or [], "via": via})


def run_redis():
    import redis

    r = redis.Redis(host=HOST, port=6379)
    i = 0
    while i < N:
        if rnd.random() < 0.15:
            # Pipelined batch: several commands in one write, replies in one read.
            pipe = r.pipeline(transaction=False)
            batch = []
            for _ in range(rnd.randint(2, 6)):
                if i + len(batch) >= N:
                    break
                j = i + len(batch)
                pipe.set(f"o:tok_{j}_", f"v{j}")
                batch.append(j)
            pipe.execute()
            for j in batch:
                record(j, "SET", via="pipeline")
            i += len(batch)
            continue
        key = f"o:tok_{i}_"
        op = rnd.random()
        if op < 0.30:
            email = f"user{i}@example.com"
            r.set(key, json.dumps({"email": email, "plan": "pro"}))
            record(i, "SET", pii=[email])
        elif op < 0.50:
            r.get(key)
            record(i, "GET")
        elif op < 0.62:
            r.hset(key, mapping={"name": "Alice", "tier": "gold"})
            record(i, "HSET")
        elif op < 0.72:
            r.lpush(key, "a", "b")
            record(i, "LPUSH")
        elif op < 0.82:
            r.incr(key)
            record(i, "INCR")
        elif op < 0.92:
            r.delete(key)
            record(i, "DEL")
        else:
            try:
                r.execute_command("INCRBY", key, "notanumber")
            except redis.ResponseError:
                pass
            record(i, "INCRBY", error=True)
        i += 1


def run_sql(execute, simple):
    """`execute(sql, params)` uses the protocol under test for parameters;
    `simple(sql)` sends literal SQL only."""
    for i in range(N):
        tok = f"tok_{i}_"
        op = rnd.random()
        if op < 0.30:
            email = f"user{i}@example.com"
            via = execute(f"INSERT INTO users (id, email, note) VALUES (%s, %s, '{tok}')",
                          (i, email))
            record(i, "INSERT", pii=[email], via=via)
        elif op < 0.55:
            via = simple(f"SELECT id, email FROM users WHERE note = '{tok}'")
            record(i, "SELECT", via=via)
        elif op < 0.70:
            via = execute(f"UPDATE users SET email = %s WHERE note = '{tok}'",
                          (f"new{i}@example.com",))
            record(i, "UPDATE", pii=[f"new{i}@example.com"], via=via)
        elif op < 0.80:
            via = simple(f"DELETE FROM users WHERE note = '{tok}'")
            record(i, "DELETE", via=via)
        elif op < 0.92:
            # Large result: up to 500 rows back in one exchange.
            via = simple(f"SELECT id, email, note FROM users WHERE note <> '{tok}' LIMIT 500")
            record(i, "SELECT", via=via)
        else:
            try:
                simple(f"SELECT * FROM missing_{tok}")
            except Exception:
                pass
            record(i, "SELECT", error=True, via="simple")


def run_postgres():
    import psycopg

    conn = psycopg.connect(host=HOST, user="postgres", password="oracle", dbname="oracle",
                           autocommit=True)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id int, email text, note text)")

    def execute(sql, params):
        conn.execute(sql, params)  # parameters => extended protocol
        return "extended"

    def simple(sql):
        res = conn.pgconn.exec_(sql.encode())  # 'Q' message
        if res.error_message:
            raise RuntimeError(res.error_message)
        return "simple"

    run_sql(execute, simple)


def run_mysql():
    import pymysql

    # MySQL 8 clients negotiate TLS by default, which hides the protocol from
    # packet capture entirely; disable it to score the plaintext parser.
    conn = pymysql.connect(host=HOST, user="root", password="oracle", database="oracle",
                           autocommit=True, ssl_disabled=True)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute("CREATE TABLE users (id int, email varchar(200), note varchar(64))")

    def execute(sql, params):
        cur.execute(sql, params)  # pymysql interpolates client-side: COM_QUERY
        cur.fetchall()
        return "text"

    def simple(sql):
        cur.execute(sql)
        cur.fetchall()
        return "text"

    run_sql(execute, simple)


{"redis": run_redis, "postgres": run_postgres, "mysql": run_mysql}[PROTO]()
with open(OUT, "w") as f:
    for t in truth:
        f.write(json.dumps(t) + "\n")
print(f"{PROTO}: {len(truth)} operations", file=sys.stderr)
