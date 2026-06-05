#!/usr/bin/env bash
set -euo pipefail

CLUSTER_ID_PATH="/etc/kafka/secrets/cluster_id"
WAIT_SECONDS="${KAFKA_CLUSTER_ID_WAIT_SECONDS:-30}"
WAIT_INTERVAL="${KAFKA_CLUSTER_ID_WAIT_INTERVAL:-1}"

elapsed=0
while [[ ! -f "$CLUSTER_ID_PATH" && "$elapsed" -lt "$WAIT_SECONDS" ]]; do
  echo "Waiting for cluster id at $CLUSTER_ID_PATH"
  sleep "$WAIT_INTERVAL"
  elapsed=$((elapsed + WAIT_INTERVAL))
done

if [[ ! -f "$CLUSTER_ID_PATH" ]]; then
  echo "Missing cluster id at $CLUSTER_ID_PATH"
  exit 1
fi

CLUSTER_ID="$(cat "$CLUSTER_ID_PATH")"
export CLUSTER_ID
export KAFKA_CLUSTER_ID="$CLUSTER_ID"

exec /etc/confluent/docker/run
