"""Single source of truth for the ``siem-events`` Elasticsearch setup.

Imported by:
  * scripts/init_es.py
  * scripts/test_es_write.py
  * tests/infra/test_es_mapping.py

This module intentionally has no dependency on the ``elasticsearch`` client,
so it can be imported without a running cluster.

Index layout
------------
Writers and readers use the ``siem-events`` alias. The alias points to rolling
backing indices (``siem-events-000001``, ``-000002`` ...). ILM rolls the write
index over daily and deletes rolled-over indices after ``RETENTION``.
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
# NOTE: ILM's delete min_age is measured from the moment an index is rolled
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
# dynamic=strict rejects fields that are not explicitly declared.
#
# Source-specific event fields are declared explicitly so valid SSH, web,
# firewall, and authentication events can be indexed.
#
# metadata is stored in _source but not indexed. Its sub-keys do not become
# mapped fields, preventing mapping explosion.

MAPPINGS: dict[str, Any] = {
    "dynamic": "strict",
    "properties": {
        # Core event fields
        "event_id": {"type": "keyword"},
        "timestamp": {
            "type": "date",
            "format": "strict_date_optional_time",
        },
        "ingested_at": {
            "type": "date",
            "format": "strict_date_optional_time",
        },
        "source": {"type": "keyword"},
        "event_type": {"type": "keyword"},
        "severity": {
            "type": "keyword",
            "fields": {
                "keyword": {"type": "keyword"},
            },
        },
        "source_ip": {"type": "keyword"},
        "raw_message": {
            "type": "text",
            "fields": {
                "keyword": {
                    "type": "keyword",
                    "ignore_above": 1024,
                },
            },
        },

        # SSH and authentication events
        "username": {"type": "keyword"},
        "auth_method": {"type": "keyword"},
        "success": {"type": "boolean"},
        "outcome": {"type": "keyword"},

        # Web events
        "method": {"type": "keyword"},
        "path": {
            "type": "keyword",
            "ignore_above": 2048,
        },
        "status_code": {"type": "integer"},
        "user_agent": {
            "type": "keyword",
            "ignore_above": 2048,
        },
        "bytes_sent": {"type": "long"},
        "service": {"type": "keyword"},

        # Firewall events
        "action": {"type": "keyword"},
        "dest_ip": {"type": "keyword"},
        "dest_port": {"type": "integer"},
        "protocol": {"type": "keyword"},

        # GeoIP enrichment
        "country": {"type": "keyword"},
        "city": {"type": "keyword"},
        "location": {"type": "geo_point"},

        # Source-specific and enrichment metadata
        "metadata": {
            "type": "object",
            "enabled": False,
        },
    },
}


# {field: type} for verification (top-level fields only).
EXPECTED_FIELD_TYPES: dict[str, str] = {
    name: spec["type"]
    for name, spec in MAPPINGS["properties"].items()
}


def build_index_settings(
    replicas: int = 0,
    shards: int = 1,
) -> dict[str, Any]:
    """Return index settings applied through the index template.

    replicas=0 suits a single-node Docker stack. Use at least one replica
    in a multi-node cluster.
    """
    return {
        "index.number_of_shards": shards,
        "index.number_of_replicas": replicas,
        "index.refresh_interval": "5s",
        "index.mapping.total_fields.limit": 100,
        "index.lifecycle.name": POLICY_NAME,
        "index.lifecycle.rollover_alias": ALIAS,
    }


def build_template(
    replicas: int = 0,
    shards: int = 1,
) -> dict[str, Any]:
    """Build arguments for client.indices.put_index_template()."""
    return {
        "index_patterns": [INDEX_PATTERN],
        "priority": TEMPLATE_PRIORITY,
        "template": {
            "settings": build_index_settings(
                replicas=replicas,
                shards=shards,
            ),
            "mappings": MAPPINGS,
        },
        "_meta": {
            "description": (
                "SIEM normalized events "
                "(strict mapping, ILM managed)"
            ),
        },
    }