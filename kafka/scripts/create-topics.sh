#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9093}"
CLIENT_CONFIG="${KAFKA_CLIENT_CONFIG:-/config/client.properties}"
TOPICS_LIST="${TOPICS:-}"
KAFKA_TOPICS_BIN="${KAFKA_TOPICS_BIN:-}"

if [[ -z "$KAFKA_TOPICS_BIN" ]]; then
  if command -v kafka-topics >/dev/null 2>&1; then
    KAFKA_TOPICS_BIN="kafka-topics"
  elif command -v kafka-topics.sh >/dev/null 2>&1; then
    KAFKA_TOPICS_BIN="kafka-topics.sh"
  elif [[ -x /usr/bin/kafka-topics ]]; then
    KAFKA_TOPICS_BIN="/usr/bin/kafka-topics"
  elif [[ -x /opt/kafka/bin/kafka-topics.sh ]]; then
    KAFKA_TOPICS_BIN="/opt/kafka/bin/kafka-topics.sh"
  else
    echo "kafka-topics CLI not found in PATH. Set KAFKA_TOPICS_BIN."
    exit 1
  fi
fi

if [[ -z "$TOPICS_LIST" ]]; then
  echo "No topics defined. Set TOPICS in conf/topics.env."
  exit 0
fi

IFS="," read -r -a TOPICS <<< "$TOPICS_LIST"

for ENTRY in "${TOPICS[@]}"; do
  NAME=$(echo "$ENTRY" | cut -d: -f1)
  PARTITIONS=$(echo "$ENTRY" | cut -d: -f2)
  RETENTION_MS=$(echo "$ENTRY" | cut -d: -f3)

  if [[ -z "$NAME" || -z "$PARTITIONS" || -z "$RETENTION_MS" ]]; then
    echo "Skipping invalid topic entry: $ENTRY"
    continue
  fi

  echo "Creating topic $NAME (partitions=$PARTITIONS, retention.ms=$RETENTION_MS)"
  "$KAFKA_TOPICS_BIN" --create --if-not-exists \
    --bootstrap-server "$BOOTSTRAP" \
    --command-config "$CLIENT_CONFIG" \
    --replication-factor 1 \
    --partitions "$PARTITIONS" \
    --topic "$NAME" \
    --config retention.ms="$RETENTION_MS"

done
