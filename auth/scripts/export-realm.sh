#!/usr/bin/env bash
# Export the Keycloak metranova realm to auth/conf/keycloak/metranova-realm.json.
#
# Uses the partial-export endpoint, which unlike GET /admin/realms/{realm}
# includes identity providers, IdP mappers, clients, groups, and roles —
# everything needed to fully reconstruct the realm on a fresh deployment.
#
# Usage:
#   ./auth/scripts/export-realm.sh
#
# Environment (all optional — defaults match the dev stack):
#   KEYCLOAK_URL            Internal Keycloak base URL  (default: http://localhost:8180)
#   KEYCLOAK_ADMIN          Admin username              (default: admin)
#   KEYCLOAK_ADMIN_PASSWORD Admin password              (default: read from auth/conf/keycloak.env)
#   KEYCLOAK_REALM          Realm to export             (default: metranova)
#   OUTPUT                  Destination file            (default: auth/conf/keycloak/metranova-realm.json)
#
# The output file contains IdP client secrets — keep it out of version control
# (auth/conf/ is gitignored). Commit a redacted copy to auth/conf.example/ instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONF_DIR="$REPO_ROOT/auth/conf"

# Load conf/keycloak.env for defaults if it exists
if [[ -f "$CONF_DIR/keycloak.env" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$CONF_DIR/keycloak.env"; set +a
fi

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
KEYCLOAK_ADMIN="${KEYCLOAK_ADMIN:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:?KEYCLOAK_ADMIN_PASSWORD is required}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-metranova}"
OUTPUT="${OUTPUT:-$CONF_DIR/keycloak/metranova-realm.json}"

echo "Exporting realm '$KEYCLOAK_REALM' from $KEYCLOAK_URL ..."

# Obtain admin token from the master realm
TOKEN=$(curl -sf \
  -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$KEYCLOAK_ADMIN" \
  -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# partial-export includes identity providers, IdP mappers, clients, groups, roles.
# This is the correct export format for re-import — unlike GET /admin/realms/{realm}
# which silently omits identity providers.
curl -sf \
  -X POST \
  "$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALM/partial-export?exportGroupsAndRoles=true&exportClients=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  | python3 -m json.tool --indent 2 \
  > "$OUTPUT"

echo "Exported to $OUTPUT"
echo ""
echo "NOTE: This file contains IdP client secrets. Do not commit it directly."
echo "Commit a redacted copy (replace secrets with CHANGEME) to auth/conf.example/keycloak/."
