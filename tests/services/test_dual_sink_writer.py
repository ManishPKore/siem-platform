"""Live integration test for PostgreSQL + Elasticsearch dual-sink storage."""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import text

from api.database import SessionLocal
from api.services.dual_sink_writer import DualSinkWriter
from api.services.es_storage_service import ElasticsearchStorageService
from api.services.storage_service import EventStorageService
from consumers.schemas import LogEvent


def main() -> None:
    event_id = uuid4()

    event = LogEvent(
        event_id=event_id,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.0.2.10",
        event_type="failed_login",
        severity="MEDIUM",
        raw_message="Live dual-sink integration test: failed SSH login",
        source="ssh",
        username="test_user",
        auth_method="password",
        success=False,
    )

    es_service = ElasticsearchStorageService()
    writer = DualSinkWriter(
        postgres_write=EventStorageService().save_events_bulk,
        es_service=es_service,
    )

    try:
        result = writer.write([event])

        print(f"Test event ID: {event_id}")
        print(f"PostgreSQL inserted: {result.postgres_result}")
        print(f"Elasticsearch indexed: {result.elasticsearch_result.indexed}")
        print(f"Elasticsearch failed: {result.elasticsearch_result.failed}")
        print(f"Dead-letter file: {result.dead_letter_path}")

        with SessionLocal() as session:
            pg_count = session.execute(
                text(
                    "SELECT COUNT(*) FROM events WHERE event_id = :event_id"
                ),
                {"event_id": event_id},
            ).scalar_one()

        es_response = es_service.client.get(
            index=es_service.index_name,
            id=str(event_id),
        )

        es_event_id = es_response["_source"]["event_id"]

        print(f"PostgreSQL verification count: {pg_count}")
        print(f"Elasticsearch verification ID: {es_event_id}")

        if pg_count != 1:
            raise AssertionError(
                f"Expected one PostgreSQL event; found {pg_count}"
            )

        if es_event_id != str(event_id):
            raise AssertionError("Elasticsearch event ID mismatch")

        if result.elasticsearch_result.failed:
            raise AssertionError("Elasticsearch reported failed writes")

        print("\nPASS: Event successfully written to both sinks.")

    finally:
        writer.close()
        es_service.close()


if __name__ == "__main__":
    main()