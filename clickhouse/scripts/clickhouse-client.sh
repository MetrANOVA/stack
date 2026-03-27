#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONF_DIR="$SCRIPT_DIR/../conf"
CONF_FILE="${CH_CONF_FILE:-$DEFAULT_CONF_DIR/clickhouse.env}"

get_value() {
  local key="$1"
  local line
  line=$(grep -E "^${key}=" "$CONF_FILE" 2>/dev/null || true)
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  echo "${line#*=}"
}

USER_VALUE="${CH_USER:-}"
PASS_VALUE="${CH_PASSWORD:-}"
PORT_VALUE="${CH_PORT:-}"
HOST_VALUE="${CH_HOST:-localhost}"

if [[ -z "$USER_VALUE" ]]; then
  USER_VALUE="$(get_value CH_DEFAULT_USER)"
  USER_VALUE="${USER_VALUE:-default}"
fi

if [[ -z "$PASS_VALUE" ]]; then
  PASS_VALUE="$(get_value CH_DEFAULT_PASSWORD)"
fi

if [[ -z "$PORT_VALUE" ]]; then
  PORT_VALUE="$(get_value CH_TCP_SECURE_PORT)"
  PORT_VALUE="${PORT_VALUE:-9440}"
fi

if [[ -z "$PASS_VALUE" ]]; then
  echo "Missing CH_DEFAULT_PASSWORD in $CONF_FILE."
  exit 1
fi

docker compose -f clickhouse/docker-compose.yml exec \
  clickhouse clickhouse-client \
  --host "$HOST_VALUE" \
  --secure \
  --port "$PORT_VALUE" \
  --user "$USER_VALUE" \
  --password "$PASS_VALUE" \
  --accept-invalid-certificate \
  "$@"
