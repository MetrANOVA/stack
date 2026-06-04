#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONF_DIR="$SCRIPT_DIR/../conf"
CONF_FILE="${KAFKA_CONF_FILE:-$DEFAULT_CONF_DIR/kafka.env}"
CONF_DIR="$(cd "$(dirname "$CONF_FILE")" && pwd)"
EXPORT_DIR="$CONF_DIR/export"
EXPORT_ENV_FILE="$EXPORT_DIR/kafka.env"
CA_CERT_SRC="$CONF_DIR/ca.crt"
CA_CERT_DEST="$EXPORT_DIR/ca.crt"

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
KEYSTORE_PASS="$(get_value KAFKA_SSL_KEYSTORE_PASSWORD)"
TRUSTSTORE_PASS="$(get_value KAFKA_SSL_TRUSTSTORE_PASSWORD)"
KEY_PASS="$(get_value KAFKA_SSL_KEY_PASSWORD)"
SSL_DNS_NAME="$(get_value KAFKA_SSL_DNS_NAME)"
SSL_KEY_ALG="$(get_value KAFKA_SSL_KEY_ALG)"
SSL_KEY_SIZE="$(get_value KAFKA_SSL_KEY_SIZE)"

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

if [[ -z "$KEYSTORE_PASS" || "$KEYSTORE_PASS" == "changeit" ]]; then
  KEYSTORE_PASS="$(random_password)"
  set_value KAFKA_SSL_KEYSTORE_PASSWORD "$KEYSTORE_PASS"
fi

if [[ -z "$TRUSTSTORE_PASS" || "$TRUSTSTORE_PASS" == "changeit" ]]; then
  TRUSTSTORE_PASS="$(random_password)"
  set_value KAFKA_SSL_TRUSTSTORE_PASSWORD "$TRUSTSTORE_PASS"
fi

# For PKCS12, Kafka expects the key password to match the keystore password.
if [[ -z "$KEY_PASS" || "$KEY_PASS" == "changeit" || "$KEY_PASS" != "$KEYSTORE_PASS" ]]; then
  KEY_PASS="$KEYSTORE_PASS"
  set_value KAFKA_SSL_KEY_PASSWORD "$KEY_PASS"
fi

if [[ -z "$SSL_DNS_NAME" ]]; then
  SSL_DNS_NAME="kafka"
fi

if [[ -z "$SSL_KEY_ALG" ]]; then
  SSL_KEY_ALG="RSA"
fi

if [[ -z "$SSL_KEY_SIZE" ]]; then
  SSL_KEY_SIZE="2048"
fi

INTERNAL_JAAS="org.apache.kafka.common.security.plain.PlainLoginModule required username=\"$ADMIN_USER\" password=\"$ADMIN_PASS\" user_${ADMIN_USER}=\"$ADMIN_PASS\" user_pipeline=\"$PIPELINE_PASS\" user_collector=\"$COLLECTOR_PASS\";"
EXTERNAL_JAAS="$INTERNAL_JAAS"
BROKER_JAAS="org.apache.kafka.common.security.plain.PlainLoginModule required username=\"$ADMIN_USER\" password=\"$ADMIN_PASS\";"

set_value KAFKA_LISTENER_NAME_INTERNAL_PLAIN_SASL_JAAS_CONFIG "$INTERNAL_JAAS"
set_value KAFKA_LISTENER_NAME_EXTERNAL_PLAIN_SASL_JAAS_CONFIG "$EXTERNAL_JAAS"
set_value KAFKA_SASL_JAAS_CONFIG "$BROKER_JAAS"
set_value KAFKA_SUPER_USERS "User:$ADMIN_USER"

mkdir -p "$EXPORT_DIR"
cat > "$EXPORT_ENV_FILE" <<EOF
KAFKA_PIPELINE_PASSWORD=$PIPELINE_PASS
KAFKA_COLLECTOR_PASSWORD=$COLLECTOR_PASS
EOF

if [[ -f "$CA_CERT_SRC" ]]; then
  cp "$CA_CERT_SRC" "$CA_CERT_DEST"
  chmod 644 "$CA_CERT_DEST" 2>/dev/null || true
fi

export KAFKA_SSL_KEYSTORE_PASSWORD="$KEYSTORE_PASS"
export KAFKA_SSL_TRUSTSTORE_PASSWORD="$TRUSTSTORE_PASS"
export KAFKA_SSL_KEY_PASSWORD="$KEY_PASS"
export KAFKA_SSL_DNS_NAME="$SSL_DNS_NAME"
export KAFKA_SSL_KEY_ALG="$SSL_KEY_ALG"
export KAFKA_SSL_KEY_SIZE="$SSL_KEY_SIZE"
export KAFKA_CLIENT_USERNAME="$ADMIN_USER"
export KAFKA_CLIENT_PASSWORD="$ADMIN_PASS"

"$SCRIPT_DIR/generate-certs.sh"

KEYSTORE_PATH="${KAFKA_SSL_KEYSTORE_LOCATION:-/etc/kafka/secrets/kafka.keystore.jks}"
if [[ -f "$KEYSTORE_PATH" ]]; then
  if ! keytool -list -keystore "$KEYSTORE_PATH" -storepass "$KEYSTORE_PASS" >/dev/null 2>&1; then
    echo "Keystore password validation failed for $KEYSTORE_PATH"
    exit 1
  fi
fi

echo "Updated $CONF_FILE"
