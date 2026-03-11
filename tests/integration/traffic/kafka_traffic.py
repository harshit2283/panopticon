#!/usr/bin/env python3
"""Generate deterministic Kafka traffic."""

import json
import sys
import time
import uuid

from kafka.admin import KafkaAdminClient, NewTopic
from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import TopicAlreadyExistsError


BROKER = "kafka:9092"
TOPIC = "panopticon-integration"


def wait_for_kafka_ready(timeout_seconds: int = 60) -> bool:
    """Wait for broker availability and ensure topic exists with visible partitions."""
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None

    while time.time() < deadline:
        admin = None
        consumer = None
        try:
            admin = KafkaAdminClient(
                bootstrap_servers=[BROKER],
                api_version_auto_timeout_ms=3000,
                request_timeout_ms=3000,
            )
            try:
                admin.create_topics(
                    [NewTopic(name=TOPIC, num_partitions=1, replication_factor=1)],
                    timeout_ms=5000,
                )
            except TopicAlreadyExistsError:
                pass

            consumer = KafkaConsumer(
                bootstrap_servers=[BROKER],
                request_timeout_ms=3000,
                api_version_auto_timeout_ms=3000,
            )
            partitions = consumer.partitions_for_topic(TOPIC)
            if partitions:
                return True
        except Exception as exc:  # pragma: no cover - integration-only path
            last_error = exc
        finally:
            if consumer is not None:
                consumer.close()
            if admin is not None:
                admin.close()
        time.sleep(1)

    if last_error is not None:
        print(f"[kafka] ERROR: metadata readiness failed: {last_error}")
    else:
        print("[kafka] ERROR: metadata readiness timed out")
    return False


def main(wait_ready_only: bool = False) -> int:
    print("[kafka] Starting Kafka traffic generation...")
    if not wait_for_kafka_ready():
        return 1

    if wait_ready_only:
        print("[kafka] Kafka readiness check complete.")
        return 0

    run_id = str(uuid.uuid4())

    producer = KafkaProducer(
        bootstrap_servers=[BROKER],
        retries=3,
        acks="all",
        linger_ms=0,
        value_serializer=lambda v: json.dumps(v, sort_keys=True).encode("utf-8"),
    )

    messages = [
        {"run_id": run_id, "id": 1, "kind": "signup", "email": "alice@example.com"},
        {"run_id": run_id, "id": 2, "kind": "order", "amount": 42},
        {"run_id": run_id, "id": 3, "kind": "support", "ssn": "123-45-6789"},
    ]

    for msg in messages:
        producer.send(TOPIC, msg)
    producer.flush(timeout=10)
    producer.close()
    print(f"[kafka] Produced {len(messages)} messages to topic '{TOPIC}'")

    consumer = KafkaConsumer(
        TOPIC,
        bootstrap_servers=[BROKER],
        group_id=f"panopticon-integration-{int(time.time())}",
        auto_offset_reset="earliest",
        consumer_timeout_ms=3000,
        enable_auto_commit=False,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    expected_ids = {msg["id"] for msg in messages}
    seen_ids: set[int] = set()
    for record in consumer:
        payload = record.value
        if payload.get("run_id") != run_id:
            continue
        msg_id = payload.get("id")
        if isinstance(msg_id, int):
            seen_ids.add(msg_id)
        if seen_ids == expected_ids:
            break

    consumer.close()
    print(f"[kafka] Consumed {len(seen_ids)} messages from topic '{TOPIC}'")

    if seen_ids != expected_ids:
        print(
            f"[kafka] ERROR: expected ids {sorted(expected_ids)} from this run, got {sorted(seen_ids)}"
        )
        return 1

    print("[kafka] Kafka traffic complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main(wait_ready_only="--wait-ready-only" in sys.argv))
