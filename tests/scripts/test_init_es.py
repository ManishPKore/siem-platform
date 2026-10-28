import copy
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from elasticsearch import (
    BadRequestError,
    ConnectionError as ESConnectionError,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"

# Add the project root and scripts directory to Python's import path.
for path in (PROJECT_ROOT, SCRIPTS_DIR):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)

import es_mapping  # noqa: E402
_spec = importlib.util.spec_from_file_location(
    "init_es",
    SCRIPTS_DIR / "init_es.py",
)

init_es = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(init_es)

ALIAS = init_es.ALIAS
FIRST = init_es.FIRST_INDEX
POLICY = init_es.POLICY_NAME


def _expected_props():
    return copy.deepcopy(init_es.MAPPINGS["properties"])


def _mapping_response(props=None, dynamic="strict", index=FIRST):
    return {
        index: {
            "mappings": {
                "dynamic": dynamic,
                "properties": props if props is not None else _expected_props(),
            }
        }
    }


def _settings_response(replicas="0", policy=POLICY, index=FIRST):
    return {
        index: {
            "settings": {
                "index.number_of_replicas": replicas,
                "index.lifecycle.name": policy,
                "index.lifecycle.rollover_alias": ALIAS,
            }
        }
    }


def _alias_response(indices=(FIRST,), write=FIRST):
    return {
        name: {"aliases": {ALIAS: {"is_write_index": name == write}}}
        for name in indices
    }


def _client(alias_exists=True, concrete_exists=False):
    """MagicMock client in a healthy, fully provisioned state."""
    client = MagicMock()
    client.indices.exists_alias.return_value = alias_exists
    client.indices.exists.return_value = concrete_exists
    client.indices.get_alias.return_value = _alias_response()
    client.indices.get_mapping.return_value = _mapping_response()
    client.indices.get_settings.return_value = _settings_response()
    client.ilm.explain_lifecycle.return_value = {
        "indices": {FIRST: {"managed": True, "policy": POLICY, "phase": "hot"}}
    }
    return client


# --------------------------------------------------------------------------- #
# Definitions
# --------------------------------------------------------------------------- #

def test_mapping_has_required_fields_and_types():
    expected = init_es.EXPECTED_FIELD_TYPES

    keyword_fields = (
        "source_ip",
        "event_type",
        "severity",
        "country",
        "username",
        "auth_method",
        "method",
        "path",
        "user_agent",
        "action",
        "protocol",
    )

    for field in keyword_fields:
        assert expected[field] == "keyword", (
            f"{field} should be mapped as keyword"
        )

    assert expected["timestamp"] == "date"
    assert expected["raw_message"] == "text"
    assert expected["location"] == "geo_point"
    assert expected["success"] == "boolean"
    assert expected["status_code"] == "integer"
    assert expected["bytes_sent"] == "long"



def test_ilm_policy_deletes_after_seven_days():
    assert init_es.ILM_POLICY["phases"]["delete"]["min_age"] == "7d"


def test_replicas_zero_for_single_node_by_default():
    template = init_es.build_template()
    assert template["template"]["settings"]["index.number_of_replicas"] == 0


# --------------------------------------------------------------------------- #
# ILM policy / template
# --------------------------------------------------------------------------- #

def test_ensure_ilm_policy_puts_policy():
    client = MagicMock()

    init_es.ensure_ilm_policy(client)

    client.ilm.put_lifecycle.assert_called_once_with(
        name=POLICY, policy=init_es.ILM_POLICY
    )


def test_ensure_index_template_puts_template():
    client = MagicMock()

    init_es.ensure_index_template(client, replicas=1)

    kwargs = client.indices.put_index_template.call_args.kwargs
    assert kwargs["name"] == init_es.TEMPLATE_NAME
    assert kwargs["index_patterns"] == [es_mapping.INDEX_PATTERN]
    assert kwargs["template"]["settings"]["index.number_of_replicas"] == 1
    assert kwargs["template"]["mappings"]["dynamic"] == "strict"


# --------------------------------------------------------------------------- #
# ensure_index
# --------------------------------------------------------------------------- #

def test_creates_bootstrap_index_when_missing():
    client = _client(alias_exists=False)

    assert init_es.ensure_index(client) is True

    client.indices.create.assert_called_once_with(
        index=FIRST,
        aliases={ALIAS: {"is_write_index": True}},
    )
    client.indices.delete.assert_not_called()


def test_noop_when_alias_exists_with_correct_configuration():
    client = _client()

    assert init_es.ensure_index(client) is False

    client.indices.create.assert_not_called()
    client.indices.delete.assert_not_called()


def test_raises_on_mapping_type_drift():
    props = _expected_props()
    props["source_ip"] = {"type": "text"}

    client = _client()
    client.indices.get_mapping.return_value = _mapping_response(props)

    with pytest.raises(RuntimeError, match="source_ip"):
        init_es.ensure_index(client)


def test_raises_on_dynamic_drift():
    client = _client()
    client.indices.get_mapping.return_value = _mapping_response(dynamic="false")

    with pytest.raises(RuntimeError, match="dynamic"):
        init_es.ensure_index(client)


def test_raises_when_severity_keyword_subfield_missing():
    props = _expected_props()
    props["severity"] = {"type": "keyword"}

    client = _client()
    client.indices.get_mapping.return_value = _mapping_response(props)

    with pytest.raises(RuntimeError, match=r"severity\.keyword"):
        init_es.ensure_index(client)


def test_raises_on_timestamp_format_drift():
    props = _expected_props()
    props["timestamp"] = {"type": "date", "format": "epoch_millis"}

    client = _client()
    client.indices.get_mapping.return_value = _mapping_response(props)

    with pytest.raises(RuntimeError, match=r"timestamp\.format"):
        init_es.ensure_index(client)


def test_raises_on_replica_drift():
    client = _client()
    client.indices.get_settings.return_value = _settings_response(replicas="1")

    with pytest.raises(RuntimeError, match="number_of_replicas"):
        init_es.ensure_index(client, replicas=0)


def test_raises_when_ilm_policy_not_set_on_index():
    client = _client()
    client.indices.get_settings.return_value = _settings_response(policy="other")

    with pytest.raises(RuntimeError, match="lifecycle.name"):
        init_es.ensure_index(client)


def test_legacy_concrete_index_blocks_without_recreate():
    client = _client(alias_exists=False, concrete_exists=True)

    with pytest.raises(RuntimeError, match="legacy"):
        init_es.ensure_index(client)

    client.indices.delete.assert_not_called()
    client.indices.create.assert_not_called()


def test_recreate_deletes_legacy_index_then_creates():
    client = _client(alias_exists=False, concrete_exists=True)

    assert init_es.ensure_index(client, recreate=True) is True

    client.indices.delete.assert_called_once_with(index=ALIAS)
    client.indices.create.assert_called_once()


def test_recreate_deletes_alias_backing_indices_then_creates():
    client = _client(alias_exists=True, concrete_exists=False)
    client.indices.get_alias.return_value = _alias_response(
        indices=("siem-events-000001", "siem-events-000002"),
        write="siem-events-000002",
    )

    assert init_es.ensure_index(client, recreate=True) is True

    deleted = [c.kwargs["index"] for c in client.indices.delete.call_args_list]
    assert deleted == ["siem-events-000001", "siem-events-000002"]
    client.indices.create.assert_called_once()


def test_concurrent_creation_is_tolerated():
    client = _client(alias_exists=False)

    client.indices.create.side_effect = BadRequestError(
        message="exists",
        meta=MagicMock(status=400),
        body={"error": {"type": "resource_already_exists_exception"}},
    )

    assert init_es.ensure_index(client) is False


def test_concurrent_creation_with_bad_config_raises():
    props = _expected_props()
    props["source_ip"] = {"type": "text"}

    client = _client(alias_exists=False)
    client.indices.get_mapping.return_value = _mapping_response(props)
    client.indices.create.side_effect = BadRequestError(
        message="exists",
        meta=MagicMock(status=400),
        body={"error": {"type": "resource_already_exists_exception"}},
    )

    with pytest.raises(RuntimeError, match="Concurrent"):
        init_es.ensure_index(client)


def test_other_bad_requests_propagate():
    client = _client(alias_exists=False)
    client.indices.create.side_effect = BadRequestError(
        message="bad",
        meta=MagicMock(status=400),
        body={"error": {"type": "illegal_argument_exception"}},
    )

    with pytest.raises(BadRequestError):
        init_es.ensure_index(client)


# --------------------------------------------------------------------------- #
# write index / ILM verification
# --------------------------------------------------------------------------- #

def test_get_write_index_prefers_flagged_index():
    client = _client()
    client.indices.get_alias.return_value = _alias_response(
        indices=("siem-events-000001", "siem-events-000002"),
        write="siem-events-000002",
    )

    assert init_es.get_write_index(client) == "siem-events-000002"


def test_get_write_index_raises_when_ambiguous():
    client = _client()
    client.indices.get_alias.return_value = _alias_response(
        indices=("siem-events-000001", "siem-events-000002"),
        write="none",
    )

    with pytest.raises(RuntimeError, match="no write index"):
        init_es.get_write_index(client)


def test_verify_ilm_passes_when_managed():
    init_es.verify_ilm(_client())


def test_verify_ilm_raises_when_unmanaged():
    client = _client()
    client.ilm.explain_lifecycle.return_value = {"indices": {FIRST: {"managed": False}}}

    with pytest.raises(RuntimeError, match="not managing"):
        init_es.verify_ilm(client)


# --------------------------------------------------------------------------- #
# wait_for_cluster
# --------------------------------------------------------------------------- #

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


@pytest.mark.parametrize("status", ["yellow", "green"])
def test_wait_for_cluster_accepts_yellow_and_green(status):
    client = MagicMock()
    client.options.return_value = client
    client.cluster.health.return_value = {"status": status}

    init_es.wait_for_cluster(client, timeout_s=5)

    client.cluster.health.assert_called_once()


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def test_main_rejects_invalid_wait_timeout():
    assert init_es.main(["--wait-timeout", "0"]) == 2


def test_main_runs_all_steps_in_order(monkeypatch):
    calls = []
    monkeypatch.setattr(init_es, "Elasticsearch", MagicMock())
    monkeypatch.setattr(init_es, "wait_for_cluster", lambda *a, **k: calls.append("wait"))
    monkeypatch.setattr(init_es, "ensure_ilm_policy", lambda *a, **k: calls.append("ilm"))
    monkeypatch.setattr(init_es, "ensure_index_template", lambda *a, **k: calls.append("template"))
    monkeypatch.setattr(init_es, "ensure_index", lambda *a, **k: calls.append("index"))
    monkeypatch.setattr(init_es, "verify_ilm", lambda *a, **k: calls.append("verify"))

    assert init_es.main([]) == 0
    assert calls == ["wait", "ilm", "template", "index", "verify"]


def test_main_returns_1_on_timeout(monkeypatch):
    monkeypatch.setattr(init_es, "Elasticsearch", MagicMock())

    def boom(*args, **kwargs):
        raise TimeoutError("not ready")

    monkeypatch.setattr(init_es, "wait_for_cluster", boom)

    assert init_es.main([]) == 1


def test_main_returns_1_on_incompatible_configuration(monkeypatch):
    monkeypatch.setattr(init_es, "Elasticsearch", MagicMock())
    monkeypatch.setattr(init_es, "wait_for_cluster", lambda *a, **k: None)
    monkeypatch.setattr(init_es, "ensure_ilm_policy", lambda *a, **k: None)
    monkeypatch.setattr(init_es, "ensure_index_template", lambda *a, **k: None)

    def drift(*args, **kwargs):
        raise RuntimeError("incompatible")

    monkeypatch.setattr(init_es, "ensure_index", drift)

    assert init_es.main([]) == 1

# --------------------------------------------------------------------------- #
# Additive mapping update (new enrichment fields on a live index)
# --------------------------------------------------------------------------- #

NEW_FIELDS = {"asn_number": "long", "asn_org": "keyword", "reputation_score": "integer",
              "is_known_threat": "boolean", "threat_categories": "keyword"}


def test_enrichment_fields_are_declared_in_the_mapping():
    for field, expected in NEW_FIELDS.items():
        assert init_es.EXPECTED_FIELD_TYPES[field] == expected
    assert init_es.MAPPINGS["properties"]["location"]["type"] == "geo_point"
    assert len(init_es.MAPPINGS["properties"]) < 100  # index.mapping.total_fields.limit


def test_ensure_mapping_fields_adds_only_the_missing_fields_in_place():
    props = _expected_props()
    for field in NEW_FIELDS:
        props.pop(field)
    client = _client()
    client.indices.get_mapping.return_value = _mapping_response(props)

    added = init_es.ensure_mapping_fields(client)

    assert added == {FIRST: sorted(NEW_FIELDS)}
    call = client.indices.put_mapping.call_args
    assert call.kwargs["index"] == FIRST
    assert set(call.kwargs["properties"]) == set(NEW_FIELDS)  # nothing else is touched


def test_ensure_mapping_fields_is_a_no_op_when_nothing_is_missing():
    client = _client()
    assert init_es.ensure_mapping_fields(client) == {}
    client.indices.put_mapping.assert_not_called()


def test_ensure_index_upgrades_an_existing_index_instead_of_failing():
    old = _expected_props()
    for field in NEW_FIELDS:
        old.pop(field)
    client = _client()
    state = {"props": old}

    def put_mapping(index, properties):
        state["props"] = {**state["props"], **properties}

    client.indices.put_mapping.side_effect = put_mapping
    client.indices.get_mapping.side_effect = lambda index: _mapping_response(state["props"])

    assert init_es.ensure_index(client) is False  # upgraded, then verified compatible
    assert set(NEW_FIELDS) <= set(state["props"])