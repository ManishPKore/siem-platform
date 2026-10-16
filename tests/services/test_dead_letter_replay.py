"""Unit tests for Elasticsearch dead-letter replay."""

import json
from pathlib import Path
from unittest.mock import MagicMock

from api.services.dual_sink_writer import DualSinkWriter
from api.services.es_storage_service import BulkResult


def make_writer(tmp_path: Path):
    """Create a writer with mocked sinks and a temporary dead-letter folder."""
    postgres_write = MagicMock()
    es_service = MagicMock()
    es_service.bulk_index.return_value = BulkResult(
        attempted=2,
        indexed=2,
        failed=0,
        errors=[],
    )

    writer = DualSinkWriter(
        postgres_write=postgres_write,
        es_service=es_service,
        dead_letter_dir=tmp_path,
    )

    return writer, postgres_write, es_service


def create_dead_letter_file(
    tmp_path: Path,
    events: list[dict],
) -> Path:
    """Write sample events to a JSONL dead-letter file."""
    path = tmp_path / "es-failed-test.jsonl"

    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    return path


def test_replay_success_deletes_dead_letter_file(tmp_path):
    events = [
        {"event_id": "event-1", "event_type": "failed_login"},
        {"event_id": "event-2", "event_type": "web_request"},
    ]

    path = create_dead_letter_file(tmp_path, events)
    writer, postgres_write, es_service = make_writer(tmp_path)

    try:
        result = writer.replay_dead_letters(path)

        assert result.ok
        assert result.attempted == 2
        assert result.indexed == 2
        assert not path.exists()

        es_service.bulk_index.assert_called_once_with(events)

        # Replay must not write to PostgreSQL again.
        postgres_write.assert_not_called()
    finally:
        writer.close()


def test_replay_failure_preserves_dead_letter_file(tmp_path):
    events = [
        {"event_id": "event-1", "event_type": "failed_login"},
        {"event_id": "event-2", "event_type": "web_request"},
    ]

    path = create_dead_letter_file(tmp_path, events)
    writer, postgres_write, es_service = make_writer(tmp_path)

    es_service.bulk_index.return_value = BulkResult(
        attempted=2,
        indexed=1,
        failed=1,
        errors=[{"error": "simulated Elasticsearch failure"}],
    )

    try:
        result = writer.replay_dead_letters(path)

        assert not result.ok
        assert result.indexed == 1
        assert result.failed == 1
        assert path.exists()

        # The original events should remain available for another replay.
        remaining_events = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
        ]
        assert remaining_events == events

        postgres_write.assert_not_called()
    finally:
        writer.close()


def test_replay_rejects_invalid_json_without_deleting_file(tmp_path):
    path = tmp_path / "es-failed-invalid.jsonl"
    path.write_text(
        '{"event_id": "event-1"}\n'
        '{"event_id": invalid-json}\n',
        encoding="utf-8",
    )

    writer, postgres_write, es_service = make_writer(tmp_path)

    try:
        try:
            writer.replay_dead_letters(path)
            raise AssertionError("Expected ValueError for invalid JSON")
        except ValueError as exc:
            assert "Invalid JSON" in str(exc)

        assert path.exists()
        es_service.bulk_index.assert_not_called()
        postgres_write.assert_not_called()
    finally:
        writer.close()