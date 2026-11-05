#!/usr/bin/env bash
# Copy Let's Encrypt certificates into the Envoy certs directory.
# Certbot writes live certs to /etc/letsencrypt/live/<hostname>/.
# We copy fullchain.pem -> server.crt and privkey.pem -> server.key so that
# generate-certs.sh (which runs after this) sees non-empty files and skips
# self-signed generation.
set -euo pipefail

CONF_FILE="${ENVOY_CONF_FILE:-/config/envoy.env}"
if [[ -f "$CONF_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$CONF_FILE"; set +a
fi

HOSTNAME="${ENVOY_LETSENCRYPT_HOSTNAME:-}"
TLS_UID="${ENVOY_TLS_UID:-101}"
TLS_GID="${ENVOY_TLS_GID:-101}"
CERT_DIR="/srv/envoy/certs"
LE_LIVE="/etc/letsencrypt/live/${HOSTNAME}"

if [[ -z "$HOSTNAME" ]]; then
  echo "ERROR: ENVOY_LETSENCRYPT_HOSTNAME is not set" >&2
  exit 1
fi

if [[ ! -f "${LE_LIVE}/fullchain.pem" || ! -f "${LE_LIVE}/privkey.pem" ]]; then
  echo "ERROR: Let's Encrypt certificates not found at ${LE_LIVE}" >&2
  exit 1
fi

mkdir -p "$CERT_DIR"

cp "${LE_LIVE}/fullchain.pem" "${CERT_DIR}/server.crt"
cp "${LE_LIVE}/privkey.pem"   "${CERT_DIR}/server.key"
# Use fullchain as CA so clients can validate the whole chain
cp "${LE_LIVE}/fullchain.pem" "${CERT_DIR}/ca.crt"

chmod 644 "${CERT_DIR}/server.crt" "${CERT_DIR}/ca.crt"
chmod 640 "${CERT_DIR}/server.key"
chown "${TLS_UID}:${TLS_GID}" "${CERT_DIR}/server.crt" "${CERT_DIR}/server.key" "${CERT_DIR}/ca.crt" 2>/dev/null || true

echo "Let's Encrypt certificates installed for ${HOSTNAME}"
