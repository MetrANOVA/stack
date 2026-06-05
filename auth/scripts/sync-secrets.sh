#!/usr/bin/env bash
# Configure and sync auth secrets for a running MetrANOVA stack.
#
# Run this after every `docker compose up` or secret rotation. It:
#   1. Scans conf files for CHANGEME values and prompts for each one interactively
#   2. Waits for Keycloak to be ready
#   3. Pushes client secrets and LDAP bind password into Keycloak
#
# Usage:
#   ./auth/scripts/sync-secrets.sh
#
# Environment (all optional — defaults match the dev stack):
#   KEYCLOAK_URL         Internal Keycloak base URL  (default: http://localhost:8180)
#   KEYCLOAK_ADMIN       Admin username              (default: admin)
#   KEYCLOAK_REALM       Target realm                (default: metranova)
#   SYNC_WAIT_SECONDS    Max seconds to wait for Keycloak (default: 120)
#   NONINTERACTIVE       Set to 1 to skip prompts and fail on any CHANGEME (for CI)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF_DIR="$REPO_ROOT/auth/conf"
NONINTERACTIVE="${NONINTERACTIVE:-0}"

# ── Per-key context strings shown to the operator before prompting ────────────

declare -A KEY_CONTEXT
KEY_CONTEXT[KC_HOSTNAME]="The public HTTPS URL of this server as seen by browsers (e.g. https://myserver.example.com:8443 or https://localhost:8443). Used by Keycloak to build redirect URIs."
KEY_CONTEXT[LDAP_DOMAIN]="Your LDAP domain in dot notation (e.g. metranova.io). Used to construct the LDAP base DN (dc=metranova,dc=io)."
KEY_CONTEXT[LDAP_BASE_DN]="LDAP base DN (e.g. dc=metranova,dc=io). Derived from LDAP_DOMAIN if set."
KEY_CONTEXT[LDAP_BIND_DN]="LDAP admin bind DN (e.g. cn=admin,dc=metranova,dc=io). Derived from LDAP_DOMAIN if set."
KEY_CONTEXT[GLOBUS_CLIENT_ID]="Client ID from the Globus developer console (https://app.globus.org/settings/developers). Required for Globus OIDC federation."
KEY_CONTEXT[GLOBUS_CLIENT_SECRET]="Client secret from the Globus developer console. Required for Globus OIDC federation."

# ── Helper: prompt for a value with context ───────────────────────────────────

prompt_for_value() {
  local key="$1"
  local file="$2"
  local current="$3"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Missing required value: $key"
  echo "  File: ${file#$REPO_ROOT/}"
  if [[ -n "${KEY_CONTEXT[$key]:-}" ]]; then
    echo ""
    echo "  ${KEY_CONTEXT[$key]}"
  fi
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "  Enter value: "
  read -r value
  echo ""
  echo "$value"
}

# ── Helper: set a key=value in an env file ────────────────────────────────────

set_env_value() {
  local file="$1"
  local key="$2"
  local value="$3"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i.bak "s|^${key}=.*|${key}=${value}|" "$file" && rm -f "${file}.bak"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

# ── Scan for CHANGEMEs and prompt ────────────────────────────────────────────

CHANGEME_FOUND=0

scan_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0

  while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue

    if [[ "$line" == *"CHANGEME"* ]]; then
      local key="${line%%=*}"
      local current="${line#*=}"

      if [[ "$NONINTERACTIVE" == "1" ]]; then
        echo "ERROR: $key still set to CHANGEME in ${file#$REPO_ROOT/}" >&2
        CHANGEME_FOUND=1
        continue
      fi

      local new_value
      new_value=$(prompt_for_value "$key" "$file" "$current")
      set_env_value "$file" "$key" "$new_value"

      # Special case: LDAP_DOMAIN drives multiple derived values
      if [[ "$key" == "LDAP_DOMAIN" ]]; then
        local base_dn
        base_dn=$(echo "$new_value" | sed 's/\./,dc=/g; s/^/dc=/')
        for f in "$CONF_DIR"/keycloak_ldap_sync.env "$CONF_DIR"/portal.env \
                 "$CONF_DIR"/openldap.env "$CONF_DIR"/token_store.env \
                 "$CONF_DIR"/clickhouse_auth_proxy.env; do
          [[ -f "$f" ]] || continue
          set_env_value "$f" "LDAP_BASE_DN" "$base_dn"
          set_env_value "$f" "LDAP_BIND_DN" "cn=admin,$base_dn"
        done
        echo "  → Set LDAP_BASE_DN=$base_dn and LDAP_BIND_DN=cn=admin,$base_dn in all conf files."
      fi

      # Special case: KC_HOSTNAME must also update grafana.ini auth_url
      if [[ "$key" == "KC_HOSTNAME" ]]; then
        local grafana_ini="$CONF_DIR/grafana/grafana.ini"
        if [[ -f "$grafana_ini" ]]; then
          local domain="${new_value#https://}"
          sed -i.bak "s|^domain = .*|domain = $domain|" "$grafana_ini" && rm -f "${grafana_ini}.bak"
          sed -i.bak "s|^root_url = .*|root_url = ${new_value}/grafana/|" "$grafana_ini" && rm -f "${grafana_ini}.bak"
          sed -i.bak "s|^auth_url = .*|auth_url = ${new_value}/realms/metranova/protocol/openid-connect/auth|" "$grafana_ini" && rm -f "${grafana_ini}.bak"
          echo "  → Updated grafana.ini domain, root_url, and auth_url."
        fi
      fi
    fi
  done < "$file"
}

echo "Checking for unconfigured values in auth/conf/ ..."
echo ""

for f in \
  "$CONF_DIR/keycloak.env" \
  "$CONF_DIR/openldap.env" \
  "$CONF_DIR/envoy.env" \
  "$CONF_DIR/grafana.env" \
  "$CONF_DIR/grafana_ch_proxy.env" \
  "$CONF_DIR/portal.env" \
  "$CONF_DIR/keycloak_ldap_sync.env" \
  "$CONF_DIR/token_store.env" \
  "$CONF_DIR/clickhouse_auth_proxy.env"; do
  scan_file "$f"
done

if [[ "$CHANGEME_FOUND" == "1" ]]; then
  echo "" >&2
  echo "Fix the above CHANGEME values and re-run this script." >&2
  exit 1
fi

# Re-source updated conf files
for f in keycloak.env envoy.env grafana.env; do
  if [[ -f "$CONF_DIR/$f" ]]; then
    set -a; source "$CONF_DIR/$f"; set +a
  fi
done

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:?KEYCLOAK_ADMIN_PASSWORD is required}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-metranova}"
SYNC_WAIT_SECONDS="${SYNC_WAIT_SECONDS:-120}"

# ── Wait for Keycloak ─────────────────────────────────────────────────────────

echo "Waiting for Keycloak at $KEYCLOAK_URL ..."
START=$(date +%s)
until curl -sf "$KEYCLOAK_URL/health/ready" -o /dev/null 2>/dev/null; do
  if (( $(date +%s) - START >= SYNC_WAIT_SECONDS )); then
    echo "Timed out waiting for Keycloak after ${SYNC_WAIT_SECONDS}s." >&2
    exit 1
  fi
  sleep 3
done
echo "Keycloak is ready."

# ── Obtain admin token ────────────────────────────────────────────────────────

echo "Syncing secrets to $KEYCLOAK_URL realm '$KEYCLOAK_REALM' ..."

TOKEN=$(curl -sf \
  -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$KEYCLOAK_ADMIN" \
  -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

CLIENTS=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/clients")

# ── Patch client secrets ──────────────────────────────────────────────────────

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

# ── Patch LDAP bind password ──────────────────────────────────────────────────

patch_ldap_password() {
  local bind_password="$1"

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
