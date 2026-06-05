#!/usr/bin/env bash
set -euo pipefail

MAX_SECONDS="${INITDB_WAIT_SECONDS:-120}"
SLEEP_SECONDS="${INITDB_WAIT_INTERVAL_SECONDS:-3}"

START_TIME="$(date +%s)"

HOST="${INITDB_HOST:-clickhouse}"
PORT="${CH_TCP_SECURE_PORT:-9440}"
USER="${CH_DEFAULT_USER:-default}"
DB_NAME="${CH_DATABASE:-metranova}"
USERS_FILE="${INITDB_USERS_FILE:-/etc/clickhouse-server/users.d/users.xml}"

extract_password() {
  local user="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    echo ""
    return
  fi
  awk -v u="$user" '
    $0 ~ "<" u ">" {in_user=1}
    in_user && $0 ~ "<password>" {
      gsub(/.*<password>|<\/password>.*/, "", $0)
      print $0
      exit
    }
    in_user && $0 ~ "</" u ">" {in_user=0}
  ' "$file"
}

PASS="$(extract_password "$USER" "$USERS_FILE")"
if [[ -z "$PASS" ]]; then
  PASS="${CH_DEFAULT_PASSWORD:-}"
  if [[ -z "$PASS" || "$PASS" == "default-secret" ]]; then
    echo "Could not find password for user '$USER' in $USERS_FILE and CH_DEFAULT_PASSWORD is not set or still default."
    exit 1
  fi
  echo "Falling back to CH_DEFAULT_PASSWORD."
fi

while true; do
  echo "Checking ClickHouse readiness: host=$HOST port=$PORT user=$USER"
  if OUTPUT=$(clickhouse-client --host "$HOST" --secure --port "$PORT" \
    --user "$USER" --password "$PASS" \
    --accept-invalid-certificate --query "SELECT 1" 2>&1); then
    echo "ClickHouse is ready. Creating database $DB_NAME."
    if CREATE_OUT=$(clickhouse-client --host "$HOST" --secure --port "$PORT" \
      --user "$USER" --password "$PASS" \
      --accept-invalid-certificate \
      --query "CREATE DATABASE IF NOT EXISTS $DB_NAME" 2>&1); then
      echo "Database check/create complete."
      exit 0
    else
      echo "Database create failed: $CREATE_OUT"
      exit 1
    fi
  else
    echo "Readiness check failed: $OUTPUT"
  fi

  NOW="$(date +%s)"
  if (( NOW - START_TIME >= MAX_SECONDS )); then
    echo "Timed out waiting for ClickHouse after ${MAX_SECONDS}s."
    exit 1
  fi

  echo "Sleeping for ${SLEEP_SECONDS}s before retry."
  sleep "$SLEEP_SECONDS"
done
