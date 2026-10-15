# Elasticsearch Mapping: `siem-events`

Source of truth: [`scripts/es_mapping.py`](../scripts/es_mapping.py).
Provisioned by: [`scripts/init_es.py`](../scripts/init_es.py).
Verified by: [`scripts/test_es_write.py`](../scripts/test_es_write.py) (live) and `tests/infra/test_es_mapping.py` (offline).

## Index layout

| Object | Name | Purpose |
|---|---|---|
| Write/read alias | `siem-events` | The only name writers (Spark/consumers) and readers (API, Grafana) use |
| Backing indices | `siem-events-000001`, `-000002`, ... | Created by ILM rollover |
| Index template | `siem-events-template` | Applies settings + mapping to `siem-events-*` |
| ILM policy | `siem-events-policy` | Hot (daily rollover) -> delete after 7 days |

Always write to the **alias**, never to a backing index.

## Field reference

| Field | Type | Notes |
|---|---|---|
| `event_id` | `keyword` | Canonical event UUID; use as document `_id` for idempotent writes |
| `timestamp` | `date` | Format `strict_date_optional_time` (ISO-8601, e.g. `2026-10-15T10:30:00Z`). Epoch values are rejected |
| `ingested_at` | `date` | Same format; pipeline ingestion time |
| `source` | `keyword` | Log source (e.g. `firewall`, `auth`, `web`) |
| `event_type` | `keyword` | Canonical event type |
| `severity` | `keyword` + `.keyword` sub-field | `severity` and `severity.keyword` both aggregate identically |
| `source_ip` | `keyword` | |
| `dest_ip` | `keyword` | |
| `dest_port` | `integer` | |
| `username` | `keyword` | |
| `outcome` | `keyword` | |
| `service` | `keyword` | |
| `country` | `keyword` | From GeoIP enrichment |
| `city` | `keyword` | From GeoIP enrichment |
| `location` | `geo_point` | From GeoIP enrichment. Powers Grafana's world map |
| `raw_message` | `text` + `.keyword` | `text` for full-text search; `.keyword` (`ignore_above: 1024`) for exact match/aggregation |
| `metadata` | `object`, `enabled: false` | Free-form data kept in `_source` only; **not indexed or searchable** |

### `location` accepted formats

```json
{"lat": 19.07, "lon": 72.87}      // object (what the enrichment stage emits)
"19.07,72.87"                      // "lat,lon" string
[72.87, 19.07]                     // array: [lon, lat]  (note the order!)
```

## Design decisions

**`"dynamic": "strict"`**: a document with a field not listed above is rejected with
`strict_dynamic_mapping_exception` rather than silently auto-mapped. Typos and
schema drift fail loudly at write time.

**No mapping explosion from `metadata`**: the PostgreSQL JSONB `metadata` column is
mapped as an object with `enabled: false`. Its keys are never parsed into mapped
fields (verified by `test_es_write.py` with 300 arbitrary keys). Trade-off: you
cannot search or aggregate on `metadata.*`. Promote any key you need to query into
a first-class field in the mapping. `index.mapping.total_fields.limit` is also
capped at 100 as a second safeguard.

**`severity.keyword`**: `severity` is a `keyword` per the issue. The explicit
`.keyword` multi-field is added so dashboards written in the Kibana/Grafana
`field.keyword` convention work without modification. Cost: one extra copy of a
low-cardinality field.

**Alias + rollover instead of one fixed index**: ILM's delete phase deletes whole
indices. A single never-rolled-over index named `siem-events` would be deleted in
its entirety 7 days after creation. Rolling over daily means only data older than
the retention window is dropped.

**Replicas = 0** by default because the Docker stack is single-node (replicas could
never be allocated; the index would stay yellow). Use `--replicas 1` or more on a
multi-node cluster.

## ILM lifecycle

| Phase | Trigger | Action |
|---|---|---|
| hot | immediately | Roll over when the write index is 1 day old or its primary shard reaches 10 GB |
| delete | 7 days after rollover | Delete the index |

ILM `min_age` counts from **rollover**, not from document timestamps, so a document
lives about 7 to 8 days. ILM evaluates policies every 10 minutes by default.

## Setup and verification

```bash
docker compose up -d elasticsearch
pip install "elasticsearch==8.13.0"        # client major must match server (8.x)

python scripts/init_es.py                  # idempotent
python scripts/test_es_write.py            # live acceptance checks, exit 0 = pass
pytest tests/infra/test_es_mapping.py      # offline
```

If you previously created a concrete index called `siem-events` (earlier version of
`init_es.py`), it blocks the write alias. Run `python scripts/init_es.py --recreate`
once (deletes that index and any index behind the alias; dev only, data is lost).

### Acceptance criteria, manual checks

```bash
# 1. Mapping types
curl -s http://localhost:9200/siem-events/_mapping?pretty

# 2. Aggregation on severity.keyword
curl -s -H 'Content-Type: application/json' http://localhost:9200/siem-events/_search -d \
  '{"size":0,"aggs":{"by_severity":{"terms":{"field":"severity.keyword"}}}}'

# 3. location accepts {"lat","lon"}: covered by scripts/test_es_write.py
# 4. ILM applied
curl -s http://localhost:9200/siem-events-000001/_ilm/explain?pretty
curl -s http://localhost:9200/_ilm/policy/siem-events-policy?pretty
```

## Changing the mapping

Because mapping is strict, new fields need an explicit change:

1. Add the field to `MAPPINGS` in `scripts/es_mapping.py` (and the table above).
2. Run `python scripts/init_es.py`. This updates the template, which applies to
   **future** indices only.
3. Apply it to the current write index too, either by roll-over
   (`POST siem-events/_rollover`) or by adding the field in place:
   `PUT siem-events/_mapping {"properties": {"new_field": {"type": "keyword"}}}`.

Changing the type of an existing field requires a reindex.

## Grafana

Add an Elasticsearch data source pointing at `http://elasticsearch:9200`, index
`siem-events`, time field `timestamp`. For the world map panel use the `location`
geo_point field.