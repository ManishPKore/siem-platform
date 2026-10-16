"""Spark foreachBatch adapter for PostgreSQL and Elasticsearch sinks."""

from __future__ import annotations

import logging
import os

from api.services.dual_sink_writer import DualSinkWriter
from api.services.es_storage_service import ElasticsearchStorageService
from api.services.storage_service import EventStorageService
from consumers.schemas import LogEvent

logger = logging.getLogger(__name__)


def build_dual_sink_writer() -> DualSinkWriter:
    postgres = EventStorageService()
    elasticsearch = ElasticsearchStorageService()

    return DualSinkWriter(
        postgres_write=postgres.save_events_bulk,
        es_service=elasticsearch,
        dead_letter_dir=os.getenv(
            "ES_DEAD_LETTER_DIR",
            "data/es_dead_letter",
        ),
    )


def write_valid_events_batch(writer: DualSinkWriter):
    """Return a foreachBatch callback for canonical LogEvent columns."""

    fields = list(LogEvent.model_fields.keys())

    def _write(batch_df, batch_id: int) -> None:
        available = [
            name
            for name in fields
            if name in batch_df.columns
        ]

        rows = batch_df.select(
            *available
        ).toLocalIterator()

        events = [
            LogEvent.model_validate(
                row.asDict(recursive=True)
            )
            for row in rows
        ]

        if not events:
            logger.info(
                "Spark batch %s has no valid events",
                batch_id,
            )
            return

        result = writer.write(events)

        logger.info(
            "Spark batch %s: events=%d PG=%s ES indexed=%d failed=%d",
            batch_id,
            result.events_received,
            result.postgres_result,
            result.elasticsearch_result.indexed,
            result.elasticsearch_result.failed,
        )

    return _write