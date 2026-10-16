from datetime import datetime, timezone
from uuid import uuid4

import pytest

pytest.importorskip("elasticsearch")

from api.services.es_storage_service import (
    BulkResult,
    ElasticsearchStorageService,
)


class FakeClient:
    def __init__(self):
        self.index_calls = []

    def index(self, **kwargs):
        self.index_calls.append(kwargs)
        return {"result": "created"}

    def ping(self):
        return True

    def close(self):
        pass


def event(**overrides):
    item = {
        "event_id": str(uuid4()),
        "timestamp": datetime(
            2026, 10, 16, tzinfo=timezone.utc
        ),
        "source_ip": "192.0.2.1",
        "event_type": "failed_login",
        "severity": "HIGH",
        "source": "ssh",
        "raw_message": "Failed password",
        "username": "test",
        "success": False,
    }

    item.update(overrides)
    return item


def test_document_keeps_fields_and_serializes_timestamp():
    doc = ElasticsearchStorageService.to_document(event())

    assert doc["source"] == "ssh"
    assert doc["success"] is False
    assert doc["timestamp"].endswith("Z")


def test_action_id_is_event_id():
    item = event()

    action = ElasticsearchStorageService(
        client=FakeClient()
    ).to_action(item)

    assert action["_id"] == item["event_id"]
    assert action["_index"] == "siem-events"


def test_index_event_uses_stable_id():
    client = FakeClient()
    item = event()

    assert ElasticsearchStorageService(
        client=client
    ).index_event(item)

    assert client.index_calls[0]["id"] == item["event_id"]


def test_bad_event_is_counted_as_failure():
    result = ElasticsearchStorageService(
        client=FakeClient()
    ).bulk_index(
        [{"event_id": "no timestamp"}]
    )

    assert result.attempted == 1
    assert result.failed == 1
    assert not result.ok


def test_empty_batch_is_noop():
    result = ElasticsearchStorageService(
        client=FakeClient()
    ).bulk_index([])

    assert result == BulkResult()