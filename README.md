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