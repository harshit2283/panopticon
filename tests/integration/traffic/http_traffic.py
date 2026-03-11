#!/usr/bin/env python3
"""Generate deterministic HTTP traffic with PII in requests and responses."""

import json
import subprocess
import sys
import time

import requests

BASE_URL = "http://nginx"


def run():
    print("[http] Starting HTTP/1.1 traffic generation...")

    # GET with PII in response
    for i in range(3):
        try:
            r = requests.get(
                f"{BASE_URL}/api/users",
                headers={"X-Test-Id": f"http1-{i:03d}"},
            )
            print(f"[http] GET /api/users -> {r.status_code} ({len(r.content)} bytes)")
        except Exception as e:
            print(f"[http] Error: {e}", file=sys.stderr)
        time.sleep(0.1)

    # POST with PII in JSON body
    pii_payloads = [
        {
            "name": "Alice Johnson",
            "email": "alice.johnson@example.com",
            "ssn": "123-45-6789",
            "phone": "(555) 123-4567",
        },
        {
            "name": "Bob Smith",
            "email": "bob.smith@company.org",
            "credit_card": "4111111111111111",
            "ip_address": "192.168.1.100",
        },
        {
            "name": "Charlie Brown",
            "email": "charlie@secret.internal",
            "api_key": "api_key: sk_live_abcdefghij1234567890klmnop",
            "aadhaar": "1234 5678 9012",
        },
    ]

    for i, payload in enumerate(pii_payloads):
        try:
            r = requests.post(
                f"{BASE_URL}/api/users",
                json=payload,
                headers={
                    "X-Test-Id": f"http1-post-{i:03d}",
                    "Content-Type": "application/json",
                },
            )
            print(
                f"[http] POST /api/users (PII payload {i}) -> {r.status_code}"
            )
        except Exception as e:
            print(f"[http] Error: {e}", file=sys.stderr)
        time.sleep(0.1)

    # GET with PII in query params
    try:
        r = requests.get(
            f"{BASE_URL}/api/search",
            params={"email": "test@example.com", "ssn": "987-65-4321"},
            headers={"X-Test-Id": "http1-query-pii"},
        )
        print(f"[http] GET /api/search?email=...&ssn=... -> {r.status_code}")
    except Exception as e:
        print(f"[http] Error: {e}", file=sys.stderr)

    # Health check (no PII)
    try:
        r = requests.get(f"{BASE_URL}/api/health")
        print(f"[http] GET /api/health -> {r.status_code}")
    except Exception as e:
        print(f"[http] Error: {e}", file=sys.stderr)

    # 204 No Content
    try:
        r = requests.get(f"{BASE_URL}/api/empty")
        print(f"[http] GET /api/empty -> {r.status_code}")
    except Exception as e:
        print(f"[http] Error: {e}", file=sys.stderr)

    # HTTP/2 h2c (via curl subprocess)
    try:
        result = subprocess.run(
            [
                "curl",
                "-s",
                "--http2-prior-knowledge",
                "http://nginx:8080/api/users",
                "-H",
                "X-Test-Id: h2-001",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        print(f"[http] HTTP/2 GET /api/users -> {len(result.stdout)} bytes")
    except Exception as e:
        print(f"[http] HTTP/2 error (non-fatal): {e}", file=sys.stderr)

    print("[http] HTTP traffic complete.")


if __name__ == "__main__":
    run()
