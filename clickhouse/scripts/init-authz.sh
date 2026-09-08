#!/usr/bin/env bash
# Initialize the metranova_authz database and tables.
# Run after init-db.sh (requires ClickHouse to be ready and metranova DB to exist).
set -euo pipefail

HOST="${INITDB_HOST:-clickhouse}"
PORT="${CH_TCP_SECURE_PORT:-9440}"
USER="${CH_DEFAULT_USER:-default}"
USERS_FILE="${INITDB_USERS_FILE:-/etc/clickhouse-server/users.d/users.xml}"

extract_password() {
  local user="$1"
  local file="$2"
  [[ ! -f "$file" ]] && echo "" && return
  awk -v u="$user" '
    $0 ~ "<" u ">" {in_user=1}
    in_user && $0 ~ "<password>" {
      gsub(/.*<password>|<\/password>.*/, "", $0)
      print $0; exit
    }
    in_user && $0 ~ "</" u ">" {in_user=0}
  ' "$file"
}

PASS="$(extract_password "$USER" "$USERS_FILE")"
if [[ -z "$PASS" ]]; then
  PASS="${CH_DEFAULT_PASSWORD:-}"
  [[ -z "$PASS" ]] && echo "No password found for $USER" && exit 1
fi

CH="clickhouse-client --host $HOST --secure --port $PORT --user $USER --password $PASS --accept-invalid-certificate"

echo "Creating metranova_authz database..."
$CH --query "CREATE DATABASE IF NOT EXISTS metranova_authz"

echo "Creating authz tables..."
$CH --multiquery <<'SQL'

-- ── Organizations ──────────────────────────────────────────────────────────────
-- Each MetrANOVA installation has exactly one master organization.
CREATE TABLE IF NOT EXISTS metranova_authz.organizations
(
    id           UUID         DEFAULT generateUUIDv4(),
    name         String,
    slug         String,      -- lowercase identifier used in policy matching
    is_master    Bool         DEFAULT false,
    created_at   DateTime64(3) DEFAULT now64(),
    updated_at   DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

-- ── Classification rules ───────────────────────────────────────────────────────
-- Maps policy_originator + policy_scope patterns to an organization.
-- Rows matching no rule default to master org at tlp:red.
CREATE TABLE IF NOT EXISTS metranova_authz.rules
(
    id                        UUID         DEFAULT generateUUIDv4(),
    organization_id           UUID,
    policy_originator_pattern String,  -- glob/exact match on data_flow.policy_originator
    policy_scope_pattern      String,  -- glob/exact match on data_flow.policy_scope elements
    assigned_tlp              Nullable(String),  -- override TLP; null = use row's policy_level
    priority                  Int32    DEFAULT 0,
    description               String   DEFAULT '',
    created_at                DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (priority, id);

-- ── Access grants ──────────────────────────────────────────────────────────────
-- Read and write are independent grants.
-- A write grant does NOT imply a read grant.
CREATE TABLE IF NOT EXISTS metranova_authz.grants
(
    id              UUID     DEFAULT generateUUIDv4(),
    user_id         String,  -- Keycloak/LDAP username
    organization_id UUID,
    max_tlp_level   String,  -- 'tlp:clear' | 'tlp:green' | 'tlp:amber' | 'tlp:red'
    permission      String,  -- 'read' | 'write'
    granted_by      String,
    granted_at      DateTime64(3) DEFAULT now64(),
    revoked_at      Nullable(DateTime64(3))  -- null = active
)
ENGINE = ReplacingMergeTree(granted_at)
ORDER BY (user_id, organization_id, permission);

-- ── Audit log ──────────────────────────────────────────────────────────────────
-- Append-only. No mutations allowed by policy. HMAC checksum for tamper detection.
CREATE TABLE IF NOT EXISTS metranova_authz.audit_log
(
    timestamp    DateTime64(3) DEFAULT now64(),
    event_type   String,   -- grant_created | grant_revoked | rule_created | rule_modified |
                           --   org_created | policy_violation | access_denied | test_run | test_result
    actor        String,
    target_user  String    DEFAULT '',
    organization String    DEFAULT '',
    details      String    DEFAULT '',  -- JSON payload
    checksum     String    DEFAULT ''   -- HMAC-SHA256 of the row for tamper detection
)
ENGINE = MergeTree()
ORDER BY (timestamp, event_type, actor)
SETTINGS allow_nullable_key = 0;

SQL

echo "Creating authz roles..."
$CH --multiquery <<'SQL'

-- authz-admin: full read/write on authz tables (for metranova-authz CLI/daemon)
CREATE ROLE IF NOT EXISTS `authz-admin`;
GRANT SELECT, INSERT, ALTER, CREATE, DROP ON metranova_authz.* TO `authz-admin`;

-- authz-reader: SELECT only (for row policy dictionary refresh)
CREATE ROLE IF NOT EXISTS `authz-reader`;
GRANT SELECT ON metranova_authz.* TO `authz-reader`;

SQL

echo "metranova_authz schema initialized."
