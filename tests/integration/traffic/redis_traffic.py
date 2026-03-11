#!/usr/bin/env python3
"""Generate deterministic Redis traffic with PII."""

import json
import sys
import time

import redis


def run():
    print("[redis] Connecting to Redis...")
    for attempt in range(30):
        try:
            r = redis.Redis(
                host="redis", port=6379, decode_responses=True, socket_timeout=5
            )
            r.ping()
            break
        except Exception:
            time.sleep(1)
    else:
        print("[redis] Failed to connect after 30 attempts", file=sys.stderr)
        return

    # SET with PII JSON
    user_data = json.dumps(
        {
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789",
        }
    )
    r.set("user:123", user_data)
    print(f"[redis] SET user:123 ({len(user_data)} bytes)")

    # GET
    result = r.get("user:123")
    print(f"[redis] GET user:123 -> {result}")

    # SET with credit card PII
    payment_data = json.dumps(
        {
            "card_number": "4111111111111111",
            "expiry": "12/28",
            "holder": "Jane Smith",
        }
    )
    r.set("payment:789", payment_data)
    print(f"[redis] SET payment:789 ({len(payment_data)} bytes)")

    # GET payment data back
    result = r.get("payment:789")
    print(f"[redis] GET payment:789 -> {result}")

    # HSET with PII fields
    r.hset(
        "user:456",
        mapping={
            "name": "Jane Smith",
            "email": "jane.smith@company.org",
            "phone": "+1-555-987-6543",
            "ssn": "987-65-4321",
        },
    )
    print("[redis] HSET user:456")

    # HGETALL
    result = r.hgetall("user:456")
    print(f"[redis] HGETALL user:456 -> {result}")

    # SET with API key
    r.set("config:api", "api_key: sk_live_abcdefghij1234567890klmnop")
    print("[redis] SET config:api (API key)")

    # SET with JWT token
    jwt_token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "abc123_XYZ-def"
    )
    r.set("session:token", jwt_token)
    print("[redis] SET session:token (JWT)")

    # MGET multiple keys
    result = r.mget("user:123", "payment:789", "config:api")
    print(f"[redis] MGET 3 keys -> {len([x for x in result if x])} non-null")

    # Cleanup
    r.delete("user:123", "user:456", "payment:789", "config:api", "session:token")
    print("[redis] Redis traffic complete.")


if __name__ == "__main__":
    run()
