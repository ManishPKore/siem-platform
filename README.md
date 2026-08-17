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