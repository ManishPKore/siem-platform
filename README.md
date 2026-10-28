# SIEM Platform

A Security Information and Event Management (SIEM) platform for collecting,
normalizing, processing, detecting, enriching, and visualizing security events.

## Overview

The platform is designed as a full-stack security monitoring pipeline that
processes events from multiple sources such as SSH, web servers, Linux
authentication logs, and firewalls.

The system will use Kafka for event streaming, PostgreSQL for structured data,
Elasticsearch for event search and storage, Spark for stream processing,
Grafana for visualization, and FastAPI for the API layer.

## Project Structure

```text
siem-platform/
├── producers/          # Event and log producers
├── consumers/          # Kafka consumers and stream processing
├── detection_engine/   # Security detection rules
├── enrichment/         # GeoIP, ASN, and threat intelligence enrichment
├── dashboards/         # Grafana dashboards and provisioning
├── api/                # FastAPI application
├── configs/            # Application configuration
├── docker/             # Docker-related files
├── tests/              # Unit and integration tests
├── docs/               # Project documentation
├── scripts/            # Utility and startup scripts
├── data/               # Local development data
│
├── docker-compose.yml
├── .env.example
├── .gitignore
├── requirements.txt
├── ARCHITECTURE.md
└── README.md
```

## GeoIP Database Setup

Events are enriched with country, city and coordinates from the free MaxMind
GeoLite2-City database (used by the attack heatmap and the impossible-travel
rule). The `.mmdb` file is licensed and **cannot be committed** -- it is
git-ignored (`*.mmdb`, `data/*`).

1. Create a free MaxMind account:
   https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
2. Generate a license key (Account -> Manage license keys).
3. Download GeoLite2 City (MMDB) into `data/`:

```bash
   curl -L -u "<ACCOUNT_ID>:<LICENSE_KEY>" -o GeoLite2-City.tar.gz \
     "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
   tar -xzf GeoLite2-City.tar.gz
   mv GeoLite2-City_*/GeoLite2-City.mmdb data/
   rm -rf GeoLite2-City_* GeoLite2-City.tar.gz
```

   (Alternatively download the archive from the MaxMind portal and copy
   `GeoLite2-City.mmdb` into `data/` by hand.)
4. Confirm `data/GeoLite2-City.mmdb` exists. To keep it elsewhere set
   `GEOIP_DB_PATH` in `.env`.

If the file is missing the pipeline still runs: private/reserved IPs are
flagged (`geo_is_private = true`), public IPs get null geo fields, and a
warning is logged when the Spark consumer starts.

Notes:

- Spark cluster: the Spark containers bind-mount the repo at
  `/opt/siem-platform`, so `data/GeoLite2-City.mmdb` is visible to the
  workers. Python workers also need `geoip2`, `pandas` and `pyarrow`
  installed (`pip install -r requirements.txt` in the image).
- MaxMind refreshes GeoLite2 twice a week; re-download it periodically and
  restart the Spark consumer to pick up the new file.
- Run the enrichment tests with `pytest tests/enrichment` (install
  `requirements-dev.txt` first; no MaxMind download is needed for tests).

  ## ASN Database Setup

Events are also enriched with the Autonomous System Number and organization
of the source IP (`asn_number`, `asn_org`) from the free MaxMind
GeoLite2-ASN database. This tells an analyst whether traffic comes from a
cloud provider (`DIGITALOCEAN`, `AMAZON`), an ISP or a hosting company. Like
the GeoIP file, the `.mmdb` is licensed and git-ignored.

1. Use the same MaxMind account and license key as for GeoIP.
2. Download GeoLite2 ASN (MMDB) into `data/`:

```bash
   curl -L -u "<ACCOUNT_ID>:<LICENSE_KEY>" -o GeoLite2-ASN.tar.gz \
     "https://download.maxmind.com/geoip/databases/GeoLite2-ASN/download?suffix=tar.gz"
   tar -xzf GeoLite2-ASN.tar.gz
   mv GeoLite2-ASN_*/GeoLite2-ASN.mmdb data/
   rm -rf GeoLite2-ASN_* GeoLite2-ASN.tar.gz
```
3. Confirm `data/GeoLite2-ASN.mmdb` exists. To keep it elsewhere set
   `ASN_DB_PATH` in `.env`.

If the file is missing the pipeline still runs: `asn_number` / `asn_org` are
null and a warning is logged when the Spark consumer starts. A file that is
not an ASN database (e.g. the City database) is rejected at startup.

Usage:

```python
from enrichment import ASNEnricher, enrich_event

ASNEnricher().enrich("8.8.8.8")   # {"asn_number": 15169, "asn_org": "GOOGLE"}
ASNEnricher().enrich("10.0.0.1")  # {"asn_number": None, "asn_org": None}

enrich_event({"source_ip": "8.8.8.8"})  # adds geo_* and asn_* fields in one call
```

Run the tests with `pytest tests/enrichment/test_asn.py` (no download needed;
one extra test runs against the real database when it is present).

## Threat Intelligence Setup

Every source IP is checked for a bad reputation. This adds three fields to
enriched events:

| Field | Meaning |
|---|---|
| `reputation_score` | 0-100 AbuseIPDB "abuse confidence". `null` = not assessed (private IP, no API key, API unavailable), which is different from `0` = assessed and clean. |
| `is_known_threat` | `true` for any local-blocklist hit, or a score at or above the threshold (default 50). |
| `threat_categories` | e.g. `["brute_force", "ssh"]`, most-reported first. `["local_blocklist"]` for blocklist hits. |

**Lookup order:** local blocklist, then private-IP skip (private IPs are never
sent to the API), then a 1-hour cache, then the AbuseIPDB API.

### AbuseIPDB API key

1. Register at https://www.abuseipdb.com/register and create a key (free tier:
   1000 checks/day).
2. Put it in `.env`:

```bash
ABUSEIPDB_API_KEY=<your key>
```

The enrichment code reads real environment variables and does not load `.env`
itself. Docker Compose reads `.env` automatically; for a local run, export it
first: `set -a; source .env; set +a`.

Without a key the pipeline still runs on the local blocklist only, and logs a
warning at startup. The key is sent in the `Key` header and is never logged.
If the API is down, rate limited (HTTP 429) or the daily budget is used up, the
enricher falls back to the blocklist and resumes automatically. Optional
settings: `ABUSEIPDB_THREAT_THRESHOLD` (default 50) and `ABUSEIPDB_DAILY_LIMIT`
(default 1000). With Docker, `docker-compose.yml` passes these through to the
Spark containers.

Note: the cache and daily budget are per Spark Python worker, so several
workers each spend from the same account quota. Keep that in mind on the free
tier; the server-side 429 handling is the backstop.

### Local blocklist

Add one IP or CIDR range per line to `data/known_bad_ips.txt` (`#` starts a
comment). Anything listed there **always** gets `is_known_threat=true`,
`reputation_score=100` and no API call, including private addresses. The file
is re-read automatically about every 30 seconds, so no restart is needed.
Override the location with `KNOWN_BAD_IPS_PATH`.

Usage:

```python
from enrichment import IPReputationEnricher, enrich_event

IPReputationEnricher().enrich("45.155.205.233")
# {"reputation_score": 100, "is_known_threat": True,
#  "threat_categories": ["brute_force", "ssh"]}

enrich_event({"source_ip": "8.8.8.8"})  # geo_*, asn_* and reputation fields
```

Run the tests with `pytest tests/enrichment/test_ip_reputation.py` (the
AbuseIPDB API is fully mocked; no key or network needed).

## Enrichment Pipeline (`logs-enriched`)

`spark_consumer.py` runs one enrichment stage after normalization:

```
logs-raw -> parse -> normalize -> validate -> enrichment stage -> Kafka logs-enriched
                                                              -> PostgreSQL + Elasticsearch
```

GeoIP, ASN and IP reputation run in a single UDF
(`enrichment/pipeline_enricher.py`). Each event is enriched exactly once and
the same batch is written to every sink. Events in `logs-enriched` carry every
normalized field plus `country`, `city`, `latitude`, `longitude`, `asn_number`,
`asn_org`, `reputation_score`, `is_known_threat`, `threat_categories`,
`is_private_ip` and `enriched_at`. Unknown values are explicit `null`s.
Elasticsearch stores `location` as a `geo_point`. A missing database, a missing
AbuseIPDB key or a failing enricher never stops the pipeline: the affected
fields are `null`.

**Upgrading an existing Elasticsearch cluster:** run `python scripts/init_es.py`
*before* starting the new consumer. It adds the new ASN / reputation fields to
the live index in place (additive only; no data loss, no rollover needed).

Downstream consumers (for example the rules engine) should read `logs-enriched`
and use `consumers.enriched_events.parse_enriched_events()`, which restores the
`geo_*` column names the detection rules expect.

### Benchmark and load test

```bash
python scripts/benchmark_enrichment.py micro            # per-event latency (<10 ms)
python scripts/benchmark_enrichment.py spark --cores 4  # throughput (>=500 events/s)
python scripts/benchmark_enrichment.py kafka            # end to end (<10 s), needs docker + spark_consumer
```