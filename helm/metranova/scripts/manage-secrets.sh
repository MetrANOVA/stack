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

  if [[ "$failed" -ne 0 ]]; then
    echo "\nSome required secrets are missing."
    echo "Run: $0 bootstrap"
    return 1
  fi

  echo "\nAll required secrets are present."
}

bootstrap() {
  create_clickhouse_users_secret
  create_grafana_admin_secret
  create_clickhouse_tls_secret
  echo
  echo "Bootstrap complete."
  echo "If missing, create Strimzi secrets separately: pipeline-user, metranova-kafka-cluster-ca-cert"
  check_all
}

main() {
  require_cmd kubectl

  case "$MODE" in
    check)
      check_all
      ;;
    bootstrap)
      bootstrap
      ;;
    *)
      echo "Usage: $0 [check|bootstrap]" >&2
      exit 2
      ;;
  esac
}

main
