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
Detection Engine
    ↓
Enrichment
    ↓
Storage
    ↓
API / Dashboards