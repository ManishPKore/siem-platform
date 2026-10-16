"""
Live integration test for writing 100 events to PostgreSQL
and Elasticsearch through the dual-sink writer.

Requirements:
    - PostgreSQL running
    - Elasticsearch running
    - Project dependencies installed
    - Project root added to PYTHONPATH

Run from the project root in Git Bash:

    PYTHONPATH=. SIEM_LOAD_DOTENV=true python -u scripts/test_dual_sink_batch.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import text

from api.services.dual_sink_writer import DualSinkWriter
from api.services.es_storage_service import ElasticsearchStorageService
from api.services.storage_service import EventStorageService
from consumers.schemas import LogEvent


BATCH_SIZE = 100


def make_event(number: int) -> LogEvent:
    """Create a valid event using the canonical LogEvent schema."""

    event_type = number % 4

    common = {
        "event_id": str(uuid4()),
        "timestamp": (
            datetime.now(timezone.utc) - timedelta(seconds=number)
        ).isoformat(),
        "source_ip": f"192.0.2.{(number % 200) + 1}",
        "severity": ["INFO", "MEDIUM", "HIGH", "CRITICAL"][number % 4],
        "raw_message": f"Dual-sink batch integration test event {number}",
    }

    if event_type == 0:
        payload = {
            **common,
            "event_type": "failed_login",
            "source": "ssh",
            "username": f"test_user_{number}",
            "auth_method": "password",
            "success": False,
        }

    elif event_type == 1:
        payload = {
            **common,
            "event_type": "web_request",
            "source": "web",
            "method": "GET",
            "path": f"/integration-test/{number}",
            "status_code": 200,
            "user_agent": "DualSinkIntegrationTest/1.0",
            "bytes_sent": 512,
        }

    elif event_type == 2:
        payload = {
            **common,
            "event_type": "firewall_drop",
            "source": "firewall",
            "action": "DROP",
            "dest_ip": "198.51.100.10",
            "dest_port": 443,
            "protocol": "TCP",
        }

    else:
        payload = {
            **common,
            "event_type": "successful_login",
            "source": "auth",
            "username": f"test_user_{number}",
            "auth_method": "password",
            "success": True,
        }

    return LogEvent.model_validate(payload)


def verify_postgres(event_ids: list[str]) -> int:
    """Count the specified test events stored in PostgreSQL."""

    from api.database import SessionLocal

    with SessionLocal() as session:
        result = session.execute(
            text(
                """
                SELECT COUNT(*)
                FROM events
                WHERE event_id = ANY(CAST(:event_ids AS uuid[]))
                """
            ),
            {"event_ids": event_ids},
        )

        return int(result.scalar_one())


def verify_elasticsearch(
    event_ids: list[str],
) -> tuple[int, list[str]]:
    """
    Verify that the specified event IDs are searchable in Elasticsearch.

    The siem-events alias may point to multiple backing indices.
    A search query works across those indices, whereas an individual
    document GET through a multi-index alias can fail.

    Returns:
        A tuple containing:
        - The number of matching documents.
        - A list of expected event IDs that were not found.
    """

    es = ElasticsearchStorageService()

    try:
        # Make recently indexed documents searchable before verification.
        es.client.indices.refresh(index=es.index_name)

        # Search across every index associated with the configured alias.
        response = es.client.search(
            index=es.index_name,
            query={
                "ids": {
                    "values": event_ids,
                }
            },
            size=len(event_ids),
            source=False,
        )

        hits = response["hits"]["hits"]

        found_ids = {
            str(hit["_id"])
            for hit in hits
        }

        found_count = len(found_ids)

        missing_ids = [
            event_id
            for event_id in event_ids
            if event_id not in found_ids
        ]

        return found_count, missing_ids

    finally:
        es.client.close()


def main() -> int:
    """Write and verify a batch of events in both storage systems."""

    print(f"Creating {BATCH_SIZE} test events...")

    events = [
        make_event(number)
        for number in range(BATCH_SIZE)
    ]

    event_ids = [
        str(event.event_id)
        for event in events
    ]

    postgres = EventStorageService()
    elasticsearch = ElasticsearchStorageService()

    writer = DualSinkWriter(
        postgres_write=postgres.save_events_bulk,
        es_service=elasticsearch,
    )

    try:
        print("Writing events to PostgreSQL and Elasticsearch...")

        result = writer.write(events)

        print()
        print("=== Dual-sink write result ===")

        print(f"Events received: {result.events_received}")
        print(f"PostgreSQL result: {result.postgres_result}")

        print(
            "Elasticsearch attempted: "
            f"{result.elasticsearch_result.attempted}"
        )

        print(
            "Elasticsearch indexed: "
            f"{result.elasticsearch_result.indexed}"
        )

        print(
            "Elasticsearch failed: "
            f"{result.elasticsearch_result.failed}"
        )

        print(f"Dead-letter file: {result.dead_letter_path}")

        print()
        print("Verifying PostgreSQL...")

        pg_count = verify_postgres(event_ids)

        print(f"PostgreSQL verified: {pg_count}/{BATCH_SIZE}")

        print()
        print("Verifying Elasticsearch...")

        es_count, missing_ids = verify_elasticsearch(event_ids)

        print(f"Elasticsearch verified: {es_count}/{BATCH_SIZE}")

        if missing_ids:
            print()
            print(
                "Missing Elasticsearch documents: "
                f"{len(missing_ids)}"
            )

            print("First 10 missing event IDs:")

            for event_id in missing_ids[:10]:
                print(f"  {event_id}")

        print()

        passed = (
            result.events_received == BATCH_SIZE
            and result.elasticsearch_result.attempted == BATCH_SIZE
            and result.elasticsearch_result.indexed == BATCH_SIZE
            and result.elasticsearch_result.failed == 0
            and pg_count == BATCH_SIZE
            and es_count == BATCH_SIZE
            and not missing_ids
        )

        if passed:
            print(
                "PASS: All 100 events were written "
                "to and verified in both sinks."
            )
            return 0

        print(
            "FAIL: The batch did not reach both sinks completely."
        )
        return 1

    except Exception as exc:
        print(f"TEST ERROR: {type(exc).__name__}: {exc}")
        return 1

    finally:
        writer.close()
        elasticsearch.client.close()


if __name__ == "__main__":
    sys.exit(main())