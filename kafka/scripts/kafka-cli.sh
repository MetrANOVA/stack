#!/usr/bin/env bash
set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-kafka:9093}"
CLIENT_CONFIG="${KAFKA_CLIENT_CONFIG:-/config/client.properties}"

if [[ "$#" -lt 1 ]]; then
  echo "Usage: $0 <kafka-cli> [args...]"
  echo "Example: $0 kafka-topics --list"
  exit 1
fi

CMD="$1"
shift
ARGS=("$@")

has_arg() {
  local needle="$1"
  local item
  for item in "${ARGS[@]}"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

if ! has_arg "--bootstrap-server"; then
  ARGS+=("--bootstrap-server" "$BOOTSTRAP")
fi

CONFIG_FLAG="--command-config"
if [[ "$CMD" == "kafka-console-consumer" ]]; then
  CONFIG_FLAG="--consumer.config"
elif [[ "$CMD" == "kafka-console-producer" ]]; then
  CONFIG_FLAG="--producer.config"
fi

if ! has_arg "$CONFIG_FLAG"; then
  ARGS+=("$CONFIG_FLAG" "$CLIENT_CONFIG")
fi

docker compose -f docker-compose.yml exec \
  -e KAFKA_BOOTSTRAP_SERVERS="$BOOTSTRAP" \
  -e KAFKA_CLIENT_CONFIG="$CLIENT_CONFIG" \
  kafka "$CMD" "${ARGS[@]}"
