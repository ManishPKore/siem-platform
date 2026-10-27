# SIEM Platform Architecture

## Overview

The SIEM Platform is designed as a distributed security event processing
system that collects events from multiple sources, streams them through
Kafka, processes and normalizes the events, applies detection rules,
enriches security data, stores the results, and exposes analytics through
APIs and dashboards.

## High-Level Pipeline

```text
Log Sources
    ↓
Producers
    ↓
Kafka
    ↓
Normalization
    ↓
Enrichment (GeoIP + ASN + IP reputation)
    ↓
Detection Engine
    ↓
Storage
    ↓
API / Dashboards
```

## Enrichment

GeoIP enrichment (`enrichment/`) runs inside the Spark pipeline between
normalization and detection. `enrichment.spark_enrichment.add_geoip_columns()`
adds `geo_country`, `geo_city`, `geo_latitude`, `geo_longitude` and
`geo_is_private` to every valid event, looked up in a local MaxMind
GeoLite2-City database. Detection rules read the `geo_*` columns (impossible
travel needs the coordinates); the storage sinks persist them as `country`,
`city` and `location` (see `api/services/spark_dual_sink.py`).

ASN enrichment follows GeoIP in the same step: `add_asn_columns()` adds
`asn_number` and `asn_org` from a local GeoLite2-ASN database
(`data/GeoLite2-ASN.mmdb`, override with `ASN_DB_PATH`). For plain-Python
callers, `enrichment.enrich_event(event)` adds the geo and ASN fields in one
call. The ASN columns are stream-only for now: detection rules can read them,
but they are not yet persisted by the PostgreSQL / Elasticsearch sinks.

IP reputation follows ASN in the same step: `add_reputation_columns()` adds
`reputation_score`, `is_known_threat` and `threat_categories`. A local
blocklist (`data/known_bad_ips.txt`) is checked first and always wins; private
IPs are skipped; public IPs are looked up in AbuseIPDB through a one-hour
cache, with a local daily budget and rate-limit handling. If no API key is
configured or the API is unavailable, the step degrades to the blocklist
alone. Like the ASN columns, these are stream-only for now: detection rules
can read them, but the PostgreSQL / Elasticsearch sinks do not persist them
yet.