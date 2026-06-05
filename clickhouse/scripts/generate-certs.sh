#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="/var/lib/clickhouse/certs"
CERT_PATH="$CERT_DIR/server.crt"
KEY_PATH="$CERT_DIR/server.key"
CA_CERT_PATH="$CERT_DIR/ca.crt"
CA_KEY_PATH="$CERT_DIR/ca.key"
CONF_CA_PATH="/config/ca.crt"
CONF_EXPORT_DIR="/config/export"
CONF_EXPORT_CA_PATH="$CONF_EXPORT_DIR/ca.crt"

DNS_NAME="${CH_TLS_DNS_NAME:-clickhouse}"
KEY_ALG="${CH_TLS_KEY_ALG:-RSA}"
KEY_SIZE="${CH_TLS_KEY_SIZE:-2048}"
TLS_UID="${CH_TLS_UID:-101}"
TLS_GID="${CH_TLS_GID:-101}"

mkdir -p "$CERT_DIR"

if [[ -f "$CERT_PATH" && -f "$KEY_PATH" && -f "$CA_CERT_PATH" ]]; then
  echo "TLS certificates already exist. Skipping generation."
  exit 0
fi

SAN_LIST="DNS:$DNS_NAME,IP:127.0.0.1"
WORKDIR="/tmp/ch-certs"
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"

cat > "$WORKDIR/openssl.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = $DNS_NAME

[v3_req]
subjectAltName = $SAN_LIST
EOF

if [[ ! -f "$CA_CERT_PATH" || ! -f "$CA_KEY_PATH" ]]; then
  openssl req -x509 -newkey rsa:"$KEY_SIZE" \
    -keyout "$CA_KEY_PATH" \
    -out "$CA_CERT_PATH" \
    -days 3650 \
    -nodes \
    -subj "/CN=ClickHouse-Local-CA"
fi

if [[ "$KEY_ALG" == "RSA" ]]; then
  openssl req -new -newkey rsa:"$KEY_SIZE" \
    -keyout "$KEY_PATH" \
    -out "$WORKDIR/server.csr" \
    -nodes \
    -config "$WORKDIR/openssl.cnf"
else
  openssl req -new -newkey "$KEY_ALG" \
    -keyout "$KEY_PATH" \
    -out "$WORKDIR/server.csr" \
    -nodes \
    -config "$WORKDIR/openssl.cnf"
fi

openssl x509 -req \
  -in "$WORKDIR/server.csr" \
  -CA "$CA_CERT_PATH" \
  -CAkey "$CA_KEY_PATH" \
  -CAcreateserial \
  -out "$CERT_PATH" \
  -days 3650 \
  -extensions v3_req \
  -extfile "$WORKDIR/openssl.cnf"

chmod 640 "$KEY_PATH" "$CA_KEY_PATH"
chmod 644 "$CERT_PATH" "$CA_CERT_PATH"
chown "$TLS_UID:$TLS_GID" "$KEY_PATH" "$CERT_PATH" "$CA_CERT_PATH" 2>/dev/null || true

if [[ -w "/config" ]]; then
  cp "$CA_CERT_PATH" "$CONF_CA_PATH"
  chmod 644 "$CONF_CA_PATH" 2>/dev/null || true

  if [[ -w "$CONF_EXPORT_DIR" || ! -e "$CONF_EXPORT_DIR" ]]; then
    mkdir -p "$CONF_EXPORT_DIR"
    cp "$CA_CERT_PATH" "$CONF_EXPORT_CA_PATH"
    chmod 644 "$CONF_EXPORT_CA_PATH" 2>/dev/null || true
  fi
fi

echo "TLS certificates created in $CERT_DIR"
