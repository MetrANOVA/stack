#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONF_DIR="$SCRIPT_DIR/../conf"
CONF_FILE="${KAFKA_CONF_FILE:-$DEFAULT_CONF_DIR/kafka.env}"

if [[ ! -f "$CONF_FILE" ]]; then
  echo "Missing $CONF_FILE. Run: cp -r kafka/conf.example/ kafka/conf/"
  exit 1
fi

random_password() {
  openssl rand -base64 24 | tr -d '\n'
}

get_value() {
  local key="$1"
  local line
  line=$(grep -E "^${key}=" "$CONF_FILE" || true)
  if [[ -z "$line" ]]; then
    echo ""
    return
  fi
  echo "${line#*=}"
}

set_value() {
  local key="$1"
  local value="$2"
  if grep -q -E "^${key}=" "$CONF_FILE"; then
    sed -i.bak "s#^${key}=.*#${key}=${value}#" "$CONF_FILE"
    rm -f "$CONF_FILE.bak"
  else
    printf '%s=%s\n' "$key" "$value" >> "$CONF_FILE"
  fi
}

ADMIN_USER="$(get_value KAFKA_CLIENT_USERNAME)"
ADMIN_PASS="$(get_value KAFKA_CLIENT_PASSWORD)"
PIPELINE_PASS="$(get_value KAFKA_PIPELINE_PASSWORD)"
COLLECTOR_PASS="$(get_value KAFKA_COLLECTOR_PASSWORD)"

if [[ -z "$ADMIN_USER" ]]; then
  ADMIN_USER="admin"
  set_value KAFKA_CLIENT_USERNAME "$ADMIN_USER"
fi

if [[ -z "$ADMIN_PASS" || "$ADMIN_PASS" == "admin-secret" ]]; then
  ADMIN_PASS="$(random_password)"
  set_value KAFKA_CLIENT_PASSWORD "$ADMIN_PASS"
fi

if [[ -z "$PIPELINE_PASS" || "$PIPELINE_PASS" == "pipeline-secret" ]]; then
  PIPELINE_PASS="$(random_password)"
  set_value KAFKA_PIPELINE_PASSWORD "$PIPELINE_PASS"
fi

if [[ -z "$COLLECTOR_PASS" || "$COLLECTOR_PASS" == "collector-secret" ]]; then
  COLLECTOR_PASS="$(random_password)"
  set_value KAFKA_COLLECTOR_PASSWORD "$COLLECTOR_PASS"
fi

INTERNAL_JAAS="org.apache.kafka.common.security.plain.PlainLoginModule required username=\"$ADMIN_USER\" password=\"$ADMIN_PASS\" user_${ADMIN_USER}=\"$ADMIN_PASS\" user_pipeline=\"$PIPELINE_PASS\" user_collector=\"$COLLECTOR_PASS\";"
EXTERNAL_JAAS="$INTERNAL_JAAS"
BROKER_JAAS="org.apache.kafka.common.security.plain.PlainLoginModule required username=\"$ADMIN_USER\" password=\"$ADMIN_PASS\";"

set_value KAFKA_LISTENER_NAME_INTERNAL_PLAIN_SASL_JAAS_CONFIG "$INTERNAL_JAAS"
set_value KAFKA_LISTENER_NAME_EXTERNAL_PLAIN_SASL_JAAS_CONFIG "$EXTERNAL_JAAS"
set_value KAFKA_SASL_JAAS_CONFIG "$BROKER_JAAS"
set_value KAFKA_SUPER_USERS "User:$ADMIN_USER"

echo "Updated $CONF_FILE"
