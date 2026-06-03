#!/usr/bin/env bash
# Push secrets from auth/conf/*.env into a running Keycloak instance.
#
# Keycloak is the authoritative runtime store, but the source of truth for
# secret *values* is the local conf files. After standing up the stack or
# rotating a secret, run this script to reconcile them.
#
# What it syncs:
#   envoy.env   ENVOY_CLIENT_SECRET      → Keycloak client "envoy-proxy"
#   grafana.env GRAFANA_CLIENT_SECRET    → Keycloak client "grafana"
#   keycloak.env LDAP_BIND_PASSWORD      → Keycloak LDAP UserStorageProvider bindCredential
#
# Usage:
#   ./auth/scripts/sync-secrets.sh
#
# Environment (all optional — defaults match the dev stack):
#   KEYCLOAK_URL            Internal Keycloak base URL  (default: http://localhost:8180)
#   KEYCLOAK_ADMIN          Admin username              (default: admin)
#   KEYCLOAK_ADMIN_PASSWORD Admin password              (default: read from auth/conf/keycloak.env)
#   KEYCLOAK_REALM          Target realm                (default: metranova)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF_DIR="$REPO_ROOT/auth/conf"

# Source conf files for defaults
for f in keycloak.env envoy.env grafana.env; do
  if [[ -f "$CONF_DIR/$f" ]]; then
    set -a; source "$CONF_DIR/$f"; set +a
  fi
done

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:?KEYCLOAK_ADMIN_PASSWORD is required}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-metranova}"

echo "Syncing secrets to $KEYCLOAK_URL realm '$KEYCLOAK_REALM' ..."

TOKEN=$(curl -sf \
  -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$KEYCLOAK_ADMIN" \
  -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Fetch all clients once
CLIENTS=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients")

patch_client_secret() {
  local client_id="$1"
  local secret="$2"

  local uuid
  uuid=$(echo "$CLIENTS" | python3 -c "
import sys, json
clients = json.load(sys.stdin)
match = [c['id'] for c in clients if c.get('clientId') == '$client_id']
print(match[0] if match else '')
")

  if [[ -z "$uuid" ]]; then
    echo "  SKIP: client '$client_id' not found in realm"
    return
  fi

  local http_code
  http_code=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"secret\":\"$secret\"}" \
    "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients/$uuid")

  echo "  $client_id: HTTP $http_code"
}

patch_ldap_password() {
  local bind_password="$1"

  # Find the LDAP UserStorageProvider component
  local components
  components=$(curl -sf -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/components?type=org.keycloak.storage.UserStorageProvider")

  local uuid
  uuid=$(echo "$components" | python3 -c "
import sys, json
comps = json.load(sys.stdin)
ldap = [c['id'] for c in comps if c.get('providerId') == 'ldap']
print(ldap[0] if ldap else '')
")

  if [[ -z "$uuid" ]]; then
    echo "  SKIP: LDAP UserStorageProvider not found"
    return
  fi

  # Fetch full component, update bindCredential, PUT it back
  local component
  component=$(curl -sf -H "Authorization: Bearer $TOKEN" \
    "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/components/$uuid")

  local updated
  updated=$(echo "$component" | python3 -c "
import sys, json
c = json.load(sys.stdin)
c['config']['bindCredential'] = ['$bind_password']
print(json.dumps(c))
")

  local http_code
  http_code=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$updated" \
    "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/components/$uuid")

  echo "  ldap bindCredential: HTTP $http_code"
}

patch_client_secret "envoy-proxy" "${ENVOY_CLIENT_SECRET:?ENVOY_CLIENT_SECRET not set}"
patch_client_secret "grafana"     "${GRAFANA_CLIENT_SECRET:?GRAFANA_CLIENT_SECRET not set}"
patch_ldap_password               "${LDAP_BIND_PASSWORD:?LDAP_BIND_PASSWORD not set}"

echo "Done."
