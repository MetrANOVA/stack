#!/usr/bin/env bash
set -euo pipefail

CLUSTER_ID_PATH="/etc/kafka/secrets/cluster_id"

if [[ ! -f "$CLUSTER_ID_PATH" ]]; then
  echo "Missing cluster id at $CLUSTER_ID_PATH"
  exit 1
fi

export KAFKA_CLUSTER_ID
KAFKA_CLUSTER_ID="$(cat "$CLUSTER_ID_PATH")"

exec /etc/confluent/docker/run
