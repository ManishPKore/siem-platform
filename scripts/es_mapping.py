"""Single source of truth for the ``siem-events`` Elasticsearch setup.

Imported by:
  * scripts/init_es.py        - provisions ILM policy, index template, bootstrap index
  * scripts/test_es_write.py  - verifies the acceptance criteria against a live cluster
  * tests/infra/test_es_mapping.py - offline unit tests of the definitions

This module intentionally has no dependency on the ``elasticsearch`` client so it
can be imported anywhere (including unit tests without a running cluster).

Index layout
------------
Writers and readers always use the *alias* ``siem-events``. The alias points at
rolling backing indices (``siem-events-000001``, ``-000002`` ...). ILM rolls the
write index over daily and deletes rolled-over indices after ``RETENTION``.
"""
from __future__ import annotations

from typing import Any

ALIAS = "siem-events"
FIRST_INDEX = "siem-events-000001"
INDEX_PATTERN = "siem-events-*"
TEMPLATE_NAME = "siem-events-template"
POLICY_NAME = "siem-events-policy"
TEMPLATE_PRIORITY = 200

RETENTION = "7d"
ROLLOVER_MAX_AGE = "1d"
ROLLOVER_MAX_PRIMARY_SHARD_SIZE = "10gb"

# --------------------------------------------------------------------------- #
# ILM: hot (rollover) -> delete after RETENTION
# --------------------------------------------------------------------------- #
# NOTE: ILM's delete ``min_age`` is measured from the moment an index is rolled
# over, not from document timestamps. With a 1-day rollover, data lives roughly
# RETENTION + up to 1 day in total.
ILM_POLICY: dict[str, Any] = {
    "phases": {
        "hot": {
            "min_age": "0ms",
            "actions": {
                "rollover": {
                    "max_age": ROLLOVER_MAX_AGE,
                    "max_primary_shard_size": ROLLOVER_MAX_PRIMARY_SHARD_SIZE,
                },
            },
        },
        "delete": {
            "min_age": RETENTION,
            "actions": {"delete": {}},
        },
    }
}

# --------------------------------------------------------------------------- #
# Mappings
# --------------------------------------------------------------------------- #
# "dynamic": "strict" -> a document containing a field that is not declared here
# is REJECTED (HTTP 400 strict_dynamic_mapping_exception) instead of silently
# creating a new mapping. Adding a field is therefore an explicit, reviewed change.
#
# ``metadata`` (free-form JSONB-style data from PostgreSQL) is stored in _source
# but NOT indexed (``enabled: false``). Its sub-keys never become mapped fields,
# which is what prevents a mapping explosion. It is retrievable but not searchable.
MAPPINGS: dict[str, Any] = {
    "dynamic": "strict",
    "properties": {
        "event_id": {"type": "keyword"},
        "timestamp": {"type": "date", "format": "strict_date_optional_time"},
        "ingested_at": {"type": "date", "format": "strict_date_optional_time"},
        "source": {"type": "keyword"},
        "event_type": {"type": "keyword"},
        # `severity` is a keyword; the explicit `.keyword` sub-field exists so that
        # aggregations/queries written as `severity.keyword` (Kibana/Grafana
        # convention) also work. Both resolve to identical values.
        "severity": {
            "type": "keyword",
            "fields": {"keyword": {"type": "keyword"}},
        },
        "source_ip": {"type": "keyword"},
        "dest_ip": {"type": "keyword"},
        "dest_port": {"type": "integer"},
        "username": {"type": "keyword"},
        "outcome": {"type": "keyword"},
        "service": {"type": "keyword"},
        "country": {"type": "keyword"},
        "city": {"type": "keyword"},
        # GeoIP enrichment. Accepts {"lat": .., "lon": ..}, "lat,lon",
        # [lon, lat] and geohash. Required for Grafana's world map panel.
        "location": {"type": "geo_point"},
        # Full-text searchable; `.keyword` for exact match / aggregations.
        # ignore_above: values longer than 1024 chars stay searchable via the
        # text field but are not indexed in the keyword sub-field.
        "raw_message": {
            "type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}},
        },
        "metadata": {"type": "object", "enabled": False},
    },
}

# {field: type} for verification (top-level fields only).
EXPECTED_FIELD_TYPES: dict[str, str] = {
    name: spec["type"] for name, spec in MAPPINGS["properties"].items()
}


def build_index_settings(replicas: int = 0, shards: int = 1) -> dict[str, Any]:
    """Index settings applied through the template.

    ``replicas=0`` suits the single-node Docker stack (replicas can never be
    allocated on one node and would leave the index yellow). Use >=1 in a real
    multi-node cluster.
    """
    return {
        "index.number_of_shards": shards,
        "index.number_of_replicas": replicas,
        "index.refresh_interval": "5s",
        # Hard guard in addition to dynamic=strict.
        "index.mapping.total_fields.limit": 100,
        "index.lifecycle.name": POLICY_NAME,
        "index.lifecycle.rollover_alias": ALIAS,
    }


def build_template(replicas: int = 0, shards: int = 1) -> dict[str, Any]:
    """Kwargs for ``client.indices.put_index_template(name=TEMPLATE_NAME, **...)``."""
    return {
        "index_patterns": [INDEX_PATTERN],
        "priority": TEMPLATE_PRIORITY,
        "template": {
            "settings": build_index_settings(replicas=replicas, shards=shards),
            "mappings": MAPPINGS,
        },
        "_meta": {
            "description": "SIEM normalized events (strict mapping, ILM managed)",
        },
    }