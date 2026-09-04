#!/usr/bin/env bash
set -euo pipefail

# Manage required secrets for the metranova umbrella chart without storing
# plaintext credentials in values.yaml.

NAMESPACE="${NAMESPACE:-metranova}"
MODE="${1:-check}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

secret_exists() {
  kubectl get secret "$1" -n "$NAMESPACE" >/dev/null 2>&1
}

secret_has_key() {
  local secret="$1"
  local key="$2"
  kubectl get secret "$secret" -n "$NAMESPACE" -o "jsonpath={.data.${key}}" 2>/dev/null | grep -q .
}

check_secret_and_keys() {
  local secret="$1"
  shift

  local ok=1
  if ! secret_exists "$secret"; then
    echo "MISSING secret: $secret"
    return 1
  fi

  for key in "$@"; do
    if ! secret_has_key "$secret" "$key"; then
      echo "MISSING key: $secret/$key"
      ok=0
    fi
  done

  if [[ "$ok" -eq 1 ]]; then
    echo "OK secret: $secret"
    return 0
  fi

  return 1
}

create_clickhouse_users_secret() {
  echo "Creating/updating secret clickhouse-users in namespace $NAMESPACE"

  read -r -s -p "ClickHouse admin-password: " CH_ADMIN_PASSWORD
  echo
  read -r -s -p "ClickHouse readonly-password: " CH_READONLY_PASSWORD
  echo
  read -r -s -p "ClickHouse backup-password: " CH_BACKUP_PASSWORD
  echo

  kubectl create secret generic clickhouse-users \
    -n "$NAMESPACE" \
    --from-literal=admin-password="$CH_ADMIN_PASSWORD" \
    --from-literal=readonly-password="$CH_READONLY_PASSWORD" \
    --from-literal=backup-password="$CH_BACKUP_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -

  unset CH_ADMIN_PASSWORD CH_READONLY_PASSWORD CH_BACKUP_PASSWORD
}

create_grafana_admin_secret() {
  echo "Creating/updating secret grafana-admin in namespace $NAMESPACE"

  read -r -p "Grafana admin-user: " GF_ADMIN_USER
  read -r -s -p "Grafana admin-password: " GF_ADMIN_PASSWORD
  echo

  kubectl create secret generic grafana-admin \
    -n "$NAMESPACE" \
    --from-literal=admin-user="$GF_ADMIN_USER" \
    --from-literal=admin-password="$GF_ADMIN_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f -

  unset GF_ADMIN_USER GF_ADMIN_PASSWORD
}

create_auth_secrets() {
  local release="${AUTH_RELEASE:-metranova-auth}"
  echo "Creating/updating auth secrets for release '$release' in namespace $NAMESPACE"

  # Keycloak admin password
  read -r -s -p "Keycloak admin password: " KC_ADMIN_PASSWORD
  echo

  # OpenLDAP passwords
  read -r -s -p "OpenLDAP admin password: " LDAP_ADMIN_PASSWORD
  echo
  read -r -s -p "OpenLDAP config password: " LDAP_CONFIG_PASSWORD
  echo

  # Envoy OIDC + HMAC secrets
  read -r -s -p "Envoy OIDC client secret (envoy-proxy Keycloak client): " ENVOY_OIDC_SECRET
  echo
  read -r -s -p "Envoy HMAC secret (leave blank to generate): " ENVOY_HMAC_SECRET
  echo
  if [[ -z "$ENVOY_HMAC_SECRET" ]]; then
    ENVOY_HMAC_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    echo "  → Generated HMAC secret."
  fi

  # Token store encryption key — must be valid Fernet key
  read -r -s -p "Token store encryption key (leave blank to generate): " TOKEN_ENC_KEY
  echo
  if [[ -z "$TOKEN_ENC_KEY" ]]; then
    TOKEN_ENC_KEY=$(python3 -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
    echo "  → Generated token store encryption key."
  fi

  # Grafana passwords
  read -r -s -p "Grafana admin password: " GF_ADMIN_PASSWORD
  echo
  read -r -s -p "Grafana ClickHouse password: " GF_CH_PASSWORD
  echo

  # Build Envoy SDS secret files inline
  local token_yaml
  token_yaml=$(cat <<EOF
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: token-secret
  generic_secret:
    secret:
      inline_string: ${ENVOY_OIDC_SECRET}
EOF
)
  local hmac_yaml
  hmac_yaml=$(cat <<EOF
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: hmac-secret
  generic_secret:
    secret:
      inline_string: ${ENVOY_HMAC_SECRET}
EOF
)

  kubectl create secret generic "${release}-secrets" \
    -n "$NAMESPACE" \
    --from-literal=KEYCLOAK_ADMIN=admin \
    --from-literal=KEYCLOAK_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD" \
    --from-literal=LDAP_ADMIN_PASSWORD="$LDAP_ADMIN_PASSWORD" \
    --from-literal=LDAP_CONFIG_PASSWORD="$LDAP_CONFIG_PASSWORD" \
    --from-literal=TOKEN_STORE_ENCRYPTION_KEY="$TOKEN_ENC_KEY" \
    --from-literal=GRAFANA_ADMIN_PASSWORD="$GF_ADMIN_PASSWORD" \
    --from-literal=GRAFANA_CLICKHOUSE_PASSWORD="$GF_CH_PASSWORD" \
    --from-literal=token.yaml="$token_yaml" \
    --from-literal=hmac.yaml="$hmac_yaml" \
    --dry-run=client -o yaml | kubectl apply -f -

  unset KC_ADMIN_PASSWORD LDAP_ADMIN_PASSWORD LDAP_CONFIG_PASSWORD \
        ENVOY_OIDC_SECRET ENVOY_HMAC_SECRET TOKEN_ENC_KEY \
        GF_ADMIN_PASSWORD GF_CH_PASSWORD

  # TLS — use existing secret, provided files, or generate self-signed
  local tls_cert="${AUTH_TLS_CERT:-}"
  local tls_key="${AUTH_TLS_KEY:-}"
  local existing_tls="${AUTH_TLS_SECRET:-}"

  if [[ -n "$existing_tls" ]]; then
    echo "  → Using existing TLS secret: $existing_tls (set auth.envoy.tls.existingTLSSecret=$existing_tls in values)"
  elif [[ -n "$tls_cert" && -n "$tls_key" ]]; then
    echo "  → Creating auth TLS secret from AUTH_TLS_CERT / AUTH_TLS_KEY"
    kubectl create secret generic "${release}-tls" \
      -n "$NAMESPACE" \
      --from-file=server.crt="$tls_cert" \
      --from-file=server.key="$tls_key" \
      --from-file=tls.crt="$tls_cert" \
      --from-file=tls.key="$tls_key" \
      --dry-run=client -o yaml | kubectl apply -f -
  else
    echo "  → No AUTH_TLS_CERT/AUTH_TLS_KEY set — generating self-signed cert for dev."
    local tmpdir
    tmpdir=$(mktemp -d)
    openssl req -x509 -newkey rsa:2048 \
      -keyout "$tmpdir/server.key" -out "$tmpdir/server.crt" \
      -days 365 -nodes \
      -subj "/CN=metranova-auth" \
      -addext "subjectAltName=DNS:metranova-auth,DNS:localhost" \
      2>/dev/null
    kubectl create secret generic "${release}-tls" \
      -n "$NAMESPACE" \
      --from-file=server.crt="$tmpdir/server.crt" \
      --from-file=server.key="$tmpdir/server.key" \
      --from-file=tls.crt="$tmpdir/server.crt" \
      --from-file=tls.key="$tmpdir/server.key" \
      --dry-run=client -o yaml | kubectl apply -f -
    rm -rf "$tmpdir"
    echo "  → Self-signed cert created. Replace with a real cert for production."
  fi
}

create_clickhouse_tls_secret() {
  local cert="${CLICKHOUSE_TLS_CERT:-}"
  local key="${CLICKHOUSE_TLS_KEY:-}"

  if [[ -z "$cert" || -z "$key" ]]; then
    echo "Skipping clickhouse-tls creation (set CLICKHOUSE_TLS_CERT and CLICKHOUSE_TLS_KEY to enable)."
    return 0
  fi

  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    echo "TLS files do not exist: cert=$cert key=$key" >&2
    return 1
  fi

  echo "Creating/updating TLS secret clickhouse-tls from files"
  kubectl create secret tls clickhouse-tls \
    -n "$NAMESPACE" \
    --cert="$cert" \
    --key="$key" \
    --dry-run=client -o yaml | kubectl apply -f -
}

check_all() {
  local failed=0
  local release="${AUTH_RELEASE:-metranova-auth}"

  echo "Checking required secrets in namespace: $NAMESPACE"
  check_secret_and_keys clickhouse-users admin-password readonly-password backup-password || failed=1
  check_secret_and_keys grafana-admin admin-user admin-password || failed=1

  if secret_exists clickhouse-tls; then
    echo "OK secret: clickhouse-tls"
  else
    echo "MISSING secret: clickhouse-tls"
    failed=1
  fi

  # These are usually created by Strimzi/Kafka processes and must exist for telegraf.
  if secret_exists pipeline-user; then
    echo "OK secret: pipeline-user"
  else
    echo "MISSING secret: pipeline-user"
    failed=1
  fi

  if secret_exists metranova-kafka-cluster-ca-cert; then
    echo "OK secret: metranova-kafka-cluster-ca-cert"
  else
    echo "MISSING secret: metranova-kafka-cluster-ca-cert"
    failed=1
  fi

  # Auth secrets (only checked when auth is enabled)
  if [[ "${CHECK_AUTH:-1}" == "1" ]]; then
    check_secret_and_keys "${release}-secrets" \
      KEYCLOAK_ADMIN_PASSWORD LDAP_ADMIN_PASSWORD LDAP_CONFIG_PASSWORD \
      TOKEN_STORE_ENCRYPTION_KEY GRAFANA_ADMIN_PASSWORD token.yaml hmac.yaml || failed=1
    if secret_exists "${release}-tls"; then
      echo "OK secret: ${release}-tls"
    else
      echo "MISSING secret: ${release}-tls (or set AUTH_TLS_SECRET to use existing)"
      failed=1
    fi
  fi

  if [[ "$failed" -ne 0 ]]; then
    echo ""
    echo "Some required secrets are missing."
    echo "Run: $0 bootstrap"
    return 1
  fi

  echo ""
  echo "All required secrets are present."
}

plan() {
  local release="${AUTH_RELEASE:-metranova-auth}"
  cat <<EOF

MetrANOVA Secret Bootstrap Plan
================================
Namespace : $NAMESPACE
Auth release: $release

Prepare the following values before running 'bootstrap':

── ClickHouse (secret: clickhouse-users) ──────────────────────────────
  admin-password      Password for the ClickHouse admin user
  readonly-password   Password for the ClickHouse readonly user
  backup-password     Password for the ClickHouse backup user

── Grafana (secret: grafana-admin) ────────────────────────────────────
  admin-user          Grafana admin username (e.g. admin)
  admin-password      Grafana admin password

── ClickHouse TLS (secret: clickhouse-tls) ────────────────────────────
  Set CLICKHOUSE_TLS_CERT and CLICKHOUSE_TLS_KEY env vars to paths of
  PEM files, or skip for now (required before deploying ClickHouse).

── Auth (secret: ${release}-secrets) ──────────────────────────────────
  Keycloak admin password
  OpenLDAP admin password
  OpenLDAP config password
  Envoy OIDC client secret  (the 'envoy-proxy' Keycloak client secret)
  Envoy HMAC secret         (leave blank to auto-generate)
  Token store encryption key (leave blank to auto-generate — Fernet key)
  Grafana admin password
  Grafana ClickHouse password

── Auth TLS (secret: ${release}-tls) ──────────────────────────────────
  Option A: Set AUTH_TLS_CERT and AUTH_TLS_KEY to PEM file paths
  Option B: Set AUTH_TLS_SECRET to name of an existing k8s secret
  Option C: Leave unset — a self-signed cert will be generated (dev only)

── Strimzi-managed (created by Kafka operator, not this script) ────────
  pipeline-user                   Kafka pipeline user cert/key
  metranova-kafka-cluster-ca-cert Kafka cluster CA cert

Run:
  NAMESPACE=$NAMESPACE bash $0 bootstrap

EOF
}

bootstrap() {
  create_clickhouse_users_secret
  create_grafana_admin_secret
  create_clickhouse_tls_secret
  create_auth_secrets
  echo
  echo "Bootstrap complete."
  echo "If missing, create Strimzi secrets separately: pipeline-user, metranova-kafka-cluster-ca-cert"
  check_all
}

main() {
  require_cmd kubectl

  case "$MODE" in
    plan)
      plan
      ;;
    check)
      check_all
      ;;
    bootstrap)
      bootstrap
      ;;
    *)
      echo "Usage: $0 [plan|check|bootstrap]" >&2
      exit 2
      ;;
  esac
}

main
