#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONF_DIR="$SCRIPT_DIR/../conf"
CONF_FILE="${CH_CONF_FILE:-$DEFAULT_CONF_DIR/clickhouse.env}"

if [[ ! -f "$CONF_FILE" ]]; then
  echo "Missing $CONF_FILE. Run: cp -r clickhouse/conf.example/ clickhouse/conf/"
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

DB_NAME="$(get_value CH_DATABASE)"
DEFAULT_USER="$(get_value CH_DEFAULT_USER)"
DEFAULT_PASS="$(get_value CH_DEFAULT_PASSWORD)"
PIPELINE_USER="$(get_value CH_PIPELINE_USER)"
PIPELINE_PASS="$(get_value CH_PIPELINE_PASSWORD)"
GRAFANA_USER="$(get_value CH_GRAFANA_USER)"
GRAFANA_PASS="$(get_value CH_GRAFANA_PASSWORD)"

DB_NAME="${DB_NAME:-metranova}"
DEFAULT_USER="${DEFAULT_USER:-default}"
PIPELINE_USER="${PIPELINE_USER:-pipeline}"
GRAFANA_USER="${GRAFANA_USER:-grafana}"

if [[ -z "$DEFAULT_PASS" || "$DEFAULT_PASS" == "default-secret" ]]; then
  DEFAULT_PASS="$(random_password)"
  set_value CH_DEFAULT_PASSWORD "$DEFAULT_PASS"
fi

if [[ -z "$PIPELINE_PASS" || "$PIPELINE_PASS" == "pipeline-secret" ]]; then
  PIPELINE_PASS="$(random_password)"
  set_value CH_PIPELINE_PASSWORD "$PIPELINE_PASS"
fi

if [[ -z "$GRAFANA_PASS" || "$GRAFANA_PASS" == "grafana-secret" ]]; then
  GRAFANA_PASS="$(random_password)"
  set_value CH_GRAFANA_PASSWORD "$GRAFANA_PASS"
fi

CONFIG_DIR="$(dirname "$CONF_FILE")"
USERS_DIR="$CONFIG_DIR/users.d"
CONFIGD_DIR="$CONFIG_DIR/config.d"
EXPORT_DIR="$CONFIG_DIR/export"
EXPORT_ENV_FILE="$EXPORT_DIR/clickhouse.env"

mkdir -p "$USERS_DIR" "$CONFIGD_DIR"

cat > "$USERS_DIR/users.xml" <<EOF
<clickhouse>
  <users>
    <${DEFAULT_USER}>
      <password>${DEFAULT_PASS}</password>
      <networks>
        <ip>::/0</ip>
      </networks>
      <profile>default</profile>
      <quota>default</quota>
    </${DEFAULT_USER}>
    <${PIPELINE_USER}>
      <password>${PIPELINE_PASS}</password>
      <networks>
        <ip>::/0</ip>
      </networks>
      <profile>default</profile>
      <quota>default</quota>
      <readonly>0</readonly>
      <allow_databases>
        <database>${DB_NAME}</database>
      </allow_databases>
    </${PIPELINE_USER}>
    <${GRAFANA_USER}>
      <password>${GRAFANA_PASS}</password>
      <networks>
        <ip>::/0</ip>
      </networks>
      <profile>default</profile>
      <quota>default</quota>
      <readonly>1</readonly>
      <allow_databases>
        <database>${DB_NAME}</database>
      </allow_databases>
    </${GRAFANA_USER}>
  </users>
</clickhouse>
EOF

HTTP_PORT="${CH_HTTP_PORT:-}"
HTTPS_PORT="${CH_HTTPS_PORT:-8443}"
TCP_PORT="${CH_TCP_PORT:-}"
TCP_SECURE_PORT="${CH_TCP_SECURE_PORT:-9440}"
LISTEN_HOSTS_VALUE="${CH_LISTEN_HOSTS:-}"
if [[ -z "$LISTEN_HOSTS_VALUE" ]]; then
  LISTEN_HOSTS_VALUE="$(get_value CH_LISTEN_HOSTS)"
fi
LISTEN_HOSTS="${LISTEN_HOSTS_VALUE:-0.0.0.0}"

{
  echo "<clickhouse>"
  for host in ${LISTEN_HOSTS//,/ }; do
    echo "  <listen_host>$host</listen_host>"
  done
  if [[ -n "$HTTP_PORT" && "$HTTP_PORT" != "0" ]]; then
    echo "  <http_port>$HTTP_PORT</http_port>"
  fi
  echo "  <https_port>$HTTPS_PORT</https_port>"
  if [[ -n "$TCP_PORT" && "$TCP_PORT" != "0" ]]; then
    echo "  <tcp_port>$TCP_PORT</tcp_port>"
  fi
  echo "  <tcp_port_secure>$TCP_SECURE_PORT</tcp_port_secure>"
  echo "</clickhouse>"
} > "$CONFIGD_DIR/ports.xml"

cat > "$CONFIGD_DIR/tls.xml" <<EOF
<clickhouse>
  <openSSL>
    <server>
      <certificateFile>/var/lib/clickhouse/certs/server.crt</certificateFile>
      <privateKeyFile>/var/lib/clickhouse/certs/server.key</privateKeyFile>
    </server>
  </openSSL>
</clickhouse>
EOF

mkdir -p "$EXPORT_DIR"
cat > "$EXPORT_ENV_FILE" <<EOF
CH_PIPELINE_USER=$PIPELINE_USER
CH_PIPELINE_PASSWORD=$PIPELINE_PASS
CH_GRAFANA_USER=$GRAFANA_USER
CH_GRAFANA_PASSWORD=$GRAFANA_PASS
CH_DATABASE=$DB_NAME
CH_HTTPS_PORT=$HTTPS_PORT
CH_TCP_SECURE_PORT=$TCP_SECURE_PORT
EOF

echo "Updated $CONF_FILE and generated users/config files."
