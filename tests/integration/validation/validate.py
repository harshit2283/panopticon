#!/usr/bin/env python3
"""Validate agent JSONL output from integration tests.

Checks:
1. Protocol coverage (HTTP, MySQL, PostgreSQL, Redis, plus Kafka/DNS if present)
2. L7 message completeness (methods, paths, status codes)
3. PII detection (email, SSN, credit card)
4. Transport/context fields (addresses, ports, PID, TLS library)
5. Event count and latency measurements
"""

import json
import sys
from collections import Counter
from pathlib import Path


def load_events(path: str) -> list:
    events = []
    with open(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(
                        f"  WARN: Invalid JSON on line {line_num}: {e}",
                        file=sys.stderr,
                    )
    return events


def validate(events_path: str) -> bool:
    print(f"Loading events from {events_path}...")
    events = load_events(events_path)
    print(f"Loaded {len(events)} events")
    kafka_marker = Path(events_path).with_name("kafka_traffic_ran")
    kafka_required = kafka_marker.exists()
    print(f"Kafka traffic marker present: {kafka_required}")

    errors = []
    warnings = []

    # ── 1. Protocol detection ────────────────────────────────────────
    protocols = Counter()
    for e in events:
        proto = e.get("protocol", "unknown")
        # Normalize protocol names (handle both lowercase and mixed case)
        protocols[proto.lower()] += 1

    print(f"\nProtocol distribution: {dict(protocols)}")

    expected_protocols = ["http1", "mysql", "postgres", "redis"]
    if kafka_required:
        expected_protocols.append("kafka")
    for proto in expected_protocols:
        # Check case-insensitive
        count = protocols.get(proto, 0) + protocols.get(proto.upper(), 0)
        if count == 0:
            errors.append(f"FAIL: No {proto} events detected")
        else:
            print(f"  OK: {proto} -> {count} events")

    # Optional protocols (don't fail, just report)
    optional_protocols = ["dns", "amqp", "http2", "grpc"]
    if not kafka_required:
        optional_protocols.append("kafka")
    for proto in optional_protocols:
        count = protocols.get(proto, 0) + protocols.get(proto.upper(), 0)
        if count > 0:
            print(f"  OK: {proto} -> {count} events (optional)")

    # ── 2. L7 completeness ───────────────────────────────────────────
    print("\nL7 message completeness:")

    http_events = [e for e in events if e.get("protocol", "").lower() in ("http1", "http2")]
    http_with_method = [e for e in http_events if e.get("method")]
    http_with_path = [e for e in http_events if e.get("path")]
    http_with_status = [e for e in http_events if e.get("status")]

    print(f"  HTTP events: {len(http_events)} total, "
          f"{len(http_with_method)} with method, "
          f"{len(http_with_path)} with path, "
          f"{len(http_with_status)} with status")

    if http_events:
        missing_method = [e for e in http_events if not e.get("method")]
        if len(missing_method) > len(http_events) * 0.5:
            errors.append(
                f"FAIL: {len(missing_method)}/{len(http_events)} HTTP events missing method"
            )
        missing_path = [e for e in http_events if not e.get("path")]
        if len(missing_path) > len(http_events) * 0.5:
            errors.append(
                f"FAIL: {len(missing_path)}/{len(http_events)} HTTP events missing path"
            )

    mysql_events = [e for e in events if e.get("protocol", "").lower() == "mysql"]
    if mysql_events:
        has_query = any(
            e.get("method") or e.get("path") or e.get("payload_text")
            for e in mysql_events
        )
        if not has_query:
            errors.append("FAIL: No MySQL events have method/command or query text")
        else:
            print(f"  MySQL events: {len(mysql_events)} total, queries detected")

    pg_events = [e for e in events if e.get("protocol", "").lower() == "postgres"]
    if pg_events:
        has_query = any(e.get("method") or e.get("path") for e in pg_events)
        if not has_query:
            errors.append("FAIL: No PostgreSQL events have method/command or query text")
        else:
            print(f"  PostgreSQL events: {len(pg_events)} total, queries detected")

    redis_events = [e for e in events if e.get("protocol", "").lower() == "redis"]
    if redis_events:
        has_cmd = any(e.get("method") for e in redis_events)
        if not has_cmd:
            errors.append("FAIL: No Redis events have command (method)")
        else:
            print(f"  Redis events: {len(redis_events)} total, commands detected")

    # ── 3. PII detection ─────────────────────────────────────────────
    pii_events = [e for e in events if e.get("pii")]
    print(f"\nPII detection:")
    print(f"  Events with PII: {len(pii_events)}")

    if pii_events:
        pii_categories = Counter()
        for e in pii_events:
            pii_data = e["pii"]
            entities = []
            if isinstance(pii_data, dict):
                entities = pii_data.get("entities", [])
            elif isinstance(pii_data, list):
                entities = pii_data
            for entity in entities:
                cat = entity.get("category", "unknown")
                pii_categories[cat] += 1

        print(f"  PII categories: {dict(pii_categories)}")

        # We expect at least email and SSN from our test data
        email_found = any(
            k.lower() in ("email",) for k in pii_categories
        )
        ssn_found = any(
            k.lower() in ("ssn",) for k in pii_categories
        )

        if not email_found:
            warnings.append("WARN: No email PII detected in any payload")
        if not ssn_found:
            warnings.append("WARN: No SSN PII detected in any payload")
    else:
        warnings.append("WARN: No PII detected in any events")

    # ── 4. Transport/context fields ──────────────────────────────────
    print("\nTransport/context fields:")
    required_fields = ["src_addr", "dst_addr", "src_port", "dst_port"]
    for field in required_fields:
        events_with_field = [e for e in events if e.get(field) is not None]
        if events_with_field:
            print(f"  OK: {field} present in {len(events_with_field)} events")
        else:
            errors.append(f"FAIL: No events have '{field}' field")

    pid_events = [e for e in events if e.get("pid") is not None]
    if pid_events:
        print(f"  OK: pid present in {len(pid_events)} events")
    else:
        print("  INFO: pid absent in all events (expected for TC/plaintext capture)")

    tls_libraries = Counter(
        str(e.get("tls_library")).lower()
        for e in events
        if e.get("tls_library") is not None
    )
    if tls_libraries:
        print(f"  TLS libraries seen: {dict(tls_libraries)}")

    # ── 5. Event counts ──────────────────────────────────────────────
    print(f"\nEvent counts:")
    print(f"  Total events: {len(events)}")

    if len(events) < 5:
        errors.append(f"FAIL: Too few events ({len(events)}), expected >= 5")

    # ── 6. Latency ───────────────────────────────────────────────────
    latency_events = [
        e for e in events if e.get("latency_ns") and e["latency_ns"] > 0
    ]
    print(f"  Events with latency: {len(latency_events)}")
    if latency_events:
        latencies = [e["latency_ns"] for e in latency_events]
        print(f"    min: {min(latencies)} ns, max: {max(latencies)} ns")
    else:
        warnings.append("WARN: No events have non-zero latency_ns")

    # ── Report ───────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    for w in warnings:
        print(f"  {w}")
    for e in errors:
        print(f"  {e}")

    if errors:
        print(
            f"\nRESULT: FAIL ({len(errors)} errors, {len(warnings)} warnings)"
        )
        return False
    else:
        print(f"\nRESULT: PASS ({len(warnings)} warnings)")
        return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/output/events.jsonl"
    success = validate(path)
    sys.exit(0 if success else 1)
