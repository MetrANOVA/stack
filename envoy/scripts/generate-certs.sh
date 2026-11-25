#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="/srv/envoy/certs"
CERT_PATH="$CERT_DIR/server.crt"
KEY_PATH="$CERT_DIR/server.key"
CA_CERT_PATH="$CERT_DIR/ca.crt"
CA_KEY_PATH="$CERT_DIR/ca.key"

CONF_FILE="${ENVOY_CONF_FILE:-/config/envoy.env}"
if [[ -f "$CONF_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$CONF_FILE"; set +a
fi

DNS_NAME="${ENVOY_TLS_DNS_NAME:-localhost}"
KEY_ALG="${ENVOY_TLS_KEY_ALG:-RSA}"
KEY_SIZE="${ENVOY_TLS_KEY_SIZE:-2048}"
TLS_UID="${ENVOY_TLS_UID:-0}"
TLS_GID="${ENVOY_TLS_GID:-0}"

mkdir -p "$CERT_DIR"

if [[ -s "$CERT_PATH" && -s "$KEY_PATH" && -s "$CA_CERT_PATH" ]]; then
  echo "TLS certificates already exist. Skipping generation."
  exit 0
fi

SAN_LIST="DNS:$DNS_NAME,IP:127.0.0.1"
WORKDIR="/tmp/envoy-certs"
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
    -subj "/CN=Envoy-Local-CA"
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
chown "$TLS_UID:$TLS_GID" "$KEY_PATH" "$CERT_PATH" "$CA_CERT_PATH" "$CA_KEY_PATH" 2>/dev/null || true

echo "TLS certificates created in $CERT_DIR"
