"""Elasticsearch storage for canonical SIEM LogEvent records."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from uuid import UUID

from elasticsearch import Elasticsearch, helpers

logger = logging.getLogger(__name__)

DEFAULT_INDEX = "siem-events"
DEFAULT_CHUNK_SIZE = 100


def _json_value(value: Any) -> Any:
    if hasattr(value, "value"):
        value = value.value

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return (
            value.astimezone(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    if isinstance(value, Mapping):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]

    if hasattr(value, "model_dump"):
        return _json_value(
            value.model_dump(mode="python", exclude_none=True)
        )

    return value


def build_client_from_env() -> Elasticsearch:
    hosts = [
        host.strip()
        for host in os.getenv(
            "ES_HOSTS",
            "http://localhost:9200",
        ).split(",")
        if host.strip()
    ]

    kwargs: dict[str, Any] = {
        "hosts": hosts,
        "request_timeout": float(
            os.getenv("ES_REQUEST_TIMEOUT", "10")
        ),
        "max_retries": int(
            os.getenv("ES_MAX_RETRIES", "2")
        ),
        "retry_on_timeout": True,
    }

    if os.getenv("ES_API_KEY"):
        kwargs["api_key"] = os.environ["ES_API_KEY"]

    return Elasticsearch(**kwargs)


@dataclass
class BulkResult:
    attempted: int = 0
    indexed: int = 0
    failed: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0


class ElasticsearchStorageService:
    """Index normalized events using stable event IDs."""

    def __init__(
        self,
        client: Elasticsearch | None = None,
        index_name: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be >= 1")

        self.client = client or build_client_from_env()

        self.index_name = (
            index_name
            or os.getenv("ES_INDEX", DEFAULT_INDEX)
        )

        self.chunk_size = chunk_size

    @staticmethod
    def to_document(event: Any) -> dict[str, Any]:
        if hasattr(event, "model_dump"):
            payload = event.model_dump(
                mode="python",
                exclude_none=True,
            )
        elif isinstance(event, Mapping):
            payload = dict(event)
        else:
            payload = vars(event)

        document = {
            str(key): _json_value(value)
            for key, value in payload.items()
            if value is not None
        }

        if not document.get("event_id"):
            raise ValueError("event is missing event_id")

        if not document.get("timestamp"):
            raise ValueError("event is missing timestamp")

        if not document.get("event_type"):
            raise ValueError("event is missing event_type")

        # Optional GeoIP enrichment.
        if not document.get("location"):
            lat = document.pop("latitude", None)
            lon = document.pop("longitude", None)

            if lat is not None and lon is not None:
                document["location"] = {
                    "lat": float(lat),
                    "lon": float(lon),
                }

        return document

    def to_action(self, event: Any) -> dict[str, Any]:
        document = self.to_document(event)

        return {
            "_op_type": "index",
            "_index": self.index_name,
            "_id": str(document["event_id"]),
            "_source": document,
        }

    def index_event(self, event: Any) -> bool:
        try:
            action = self.to_action(event)

            self.client.index(
                index=action["_index"],
                id=action["_id"],
                document=action["_source"],
            )

            return True

        except Exception:
            logger.exception(
                "Elasticsearch index_event failed"
            )
            return False

    def bulk_index(
        self,
        events: Iterable[Any],
    ) -> BulkResult:
        batch = list(events)

        result = BulkResult(attempted=len(batch))
        actions = []

        for event in batch:
            try:
                actions.append(self.to_action(event))

            except Exception as exc:
                result.failed += 1
                result.errors.append(
                    {
                        "error": str(exc),
                        "event": repr(event),
                    }
                )

                logger.exception(
                    "Unable to serialize event for Elasticsearch"
                )

        if actions:
            indexed_result = self.bulk_actions(actions)

            result.indexed += indexed_result.indexed
            result.failed += indexed_result.failed
            result.errors.extend(indexed_result.errors)

        return result

    def bulk_actions(
        self,
        actions: Iterable[dict[str, Any]],
    ) -> BulkResult:
        actions = list(actions)

        result = BulkResult(attempted=len(actions))

        if not actions:
            return result

        try:
            success, errors = helpers.bulk(
                self.client,
                actions,
                chunk_size=self.chunk_size,
                raise_on_error=False,
                raise_on_exception=False,
                stats_only=False,
                max_retries=3,
                initial_backoff=1,
                max_backoff=10,
                retry_on_status=(429, 502, 503, 504),
            )

            result.indexed = int(success)
            result.errors = list(errors or [])

            result.failed = max(
                0,
                result.attempted - result.indexed,
            )

            if result.failed:
                logger.error(
                    "Elasticsearch bulk partially failed: "
                    "indexed=%d failed=%d",
                    result.indexed,
                    result.failed,
                )

        except Exception as exc:
            result.failed = result.attempted
            result.errors.append({"error": str(exc)})

            logger.exception(
                "Elasticsearch bulk request failed"
            )

        return result

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())

        except Exception:
            logger.exception("Elasticsearch ping failed")
            return False

    def close(self) -> None:
        try:
            self.client.close()

        except Exception:
            logger.exception(
                "Error closing Elasticsearch client"
            )