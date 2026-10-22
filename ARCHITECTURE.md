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
Enrichment (GeoIP)
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