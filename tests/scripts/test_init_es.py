import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from elasticsearch import (
    ApiError,
    BadRequestError,
    ConnectionError as ESConnectionError,
)

_spec = importlib.util.spec_from_file_location(
    "init_es",
    Path(__file__).resolve().parents[2] / "scripts" / "init_es.py",
)

init_es = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(init_es)


def _mapping_response(props):
    return {
        init_es.INDEX_NAME: {
            "mappings": {
                "properties": props,
                "dynamic": "false",
            }
        }
    }


def _expected_props():
    return {
        key: {"type": value}
        for key, value in init_es.EXPECTED_TYPES.items()
    }


def test_mapping_has_required_fields_and_types():
    assert init_es.EXPECTED_TYPES == {
        "timestamp": "date",
        "source_ip": "keyword",
        "event_type": "keyword",
        "severity": "keyword",
        "country": "keyword",
        "raw_message": "text",
    }


def test_replicas_zero_for_single_node():
    assert (
        init_es.INDEX_BODY["settings"]["number_of_replicas"] == 0
    )


def test_creates_index_when_missing():
    client = MagicMock()
    client.indices.exists.return_value = False

    assert init_es.ensure_index(
        client,
        init_es.INDEX_NAME,
    ) is True

    client.indices.create.assert_called_once()


def test_noop_when_index_exists_with_correct_mapping():
    client = MagicMock()
    client.indices.exists.return_value = True
    client.indices.get_mapping.return_value = _mapping_response(
        _expected_props()
    )
    client.indices.get_settings.return_value = {
        init_es.INDEX_NAME: {
            "settings": {
                "index.number_of_shards": "1",
                "index.number_of_replicas": "0",
                "index.refresh_interval": "5s",
            }
        }
    }

    assert init_es.ensure_index(
        client,
        init_es.INDEX_NAME,
    ) is False

    client.indices.create.assert_not_called()


def test_raises_on_mapping_drift():
    props = _expected_props()
    props["source_ip"] = {"type": "text"}

    client = MagicMock()
    client.indices.exists.return_value = True
    client.indices.get_mapping.return_value = _mapping_response(props)

    with pytest.raises(RuntimeError, match="source_ip"):
        init_es.ensure_index(client, init_es.INDEX_NAME)


def test_recreate_deletes_then_creates():
    client = MagicMock()
    client.indices.exists.return_value = True

    assert init_es.ensure_index(
        client,
        init_es.INDEX_NAME,
        recreate=True,
    ) is True

    client.indices.delete.assert_called_once_with(
        index=init_es.INDEX_NAME
    )

    client.indices.create.assert_called_once()


def test_concurrent_creation_is_tolerated():
    client = MagicMock()
    client.indices.exists.return_value = False

    client.indices.create.side_effect = BadRequestError(
        message="exists",
        meta=MagicMock(status=400),
        body={
            "error": {
                "type": "resource_already_exists_exception"
            }
        },
    )

    client.indices.get_mapping.return_value = _mapping_response(
        _expected_props()
    )

    client.indices.get_settings.return_value = {
        init_es.INDEX_NAME: {
            "settings": {
                "index.number_of_shards": "1",
                "index.number_of_replicas": "0",
                "index.refresh_interval": "5s",
            }
        }
    }

    assert init_es.ensure_index(
        client,
        init_es.INDEX_NAME,
    ) is False


def test_wait_for_cluster_times_out():
    client = MagicMock()
    client.cluster.health.side_effect = ESConnectionError("down")

    with pytest.raises(TimeoutError):
        init_es.wait_for_cluster(client, timeout_s=1)


def test_wait_for_cluster_rejects_zero_timeout():
    client = MagicMock()

    with pytest.raises(ValueError, match="at least 1"):
        init_es.wait_for_cluster(client, timeout_s=0)

    client.cluster.health.assert_not_called()


def test_wait_for_cluster_accepts_yellow():
    client = MagicMock()
    client.options.return_value = client
    client.cluster.health.return_value = {"status": "yellow"}

    init_es.wait_for_cluster(client, timeout_s=5)

    client.cluster.health.assert_called_once()


def test_wait_for_cluster_accepts_green():
    client = MagicMock()
    client.options.return_value = client
    client.cluster.health.return_value = {"status": "green"}

    init_es.wait_for_cluster(client, timeout_s=5)

    client.cluster.health.assert_called_once()


def test_main_rejects_invalid_wait_timeout():
    assert init_es.main(["--wait-timeout", "0"]) == 2


def test_verify_mapping_detects_dynamic_setting_drift():
    client = MagicMock()
    client.indices.get_mapping.return_value = {
        init_es.INDEX_NAME: {
            "mappings": {
                "properties": _expected_props(),
                "dynamic": True,
            }
        }
    }

    problems = init_es.verify_mapping(
        client,
        init_es.INDEX_NAME,
    )

    assert any("dynamic" in problem for problem in problems)


def test_verify_mapping_detects_replica_setting_drift():
    client = MagicMock()
    client.indices.get_mapping.return_value = _mapping_response(
        _expected_props()
    )

    client.indices.get_settings.return_value = {
        init_es.INDEX_NAME: {
            "settings": {
                "index.number_of_shards": "1",
                "index.number_of_replicas": "1",
                "index.refresh_interval": "5s",
            }
        }
    }

    problems = init_es.verify_mapping(
        client,
        init_es.INDEX_NAME,
    )

    assert any("number_of_replicas" in problem for problem in problems)