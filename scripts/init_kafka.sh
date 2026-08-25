#!/bin/bash

KAFKA_BROKER="${1:-kafka:29092}"

echo "Creating Kafka topics on ${KAFKA_BROKER}..."

kafka-topics --bootstrap-server "$KAFKA_BROKER" \
  --create --if-not-exists \
  --topic logs-raw \
  --partitions 1 \
  --replication-factor 1

kafka-topics --bootstrap-server "$KAFKA_BROKER" \
  --create --if-not-exists \
  --topic logs-enriched \
  --partitions 1 \
  --replication-factor 1

kafka-topics --bootstrap-server "$KAFKA_BROKER" \
  --create --if-not-exists \
  --topic alerts \
  --partitions 1 \
  --replication-factor 1

echo "Kafka topics created successfully."

kafka-topics --bootstrap-server "$KAFKA_BROKER" --list