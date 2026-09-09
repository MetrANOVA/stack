#!/usr/bin/env bash
# Initialize ClickHouse dictionaries and row policies for metranova_authz.
#
# Prerequisites:
#   - init-authz.sh has run (metranova_authz schema exists)
#   - metranova.data_flow table exists (init-db.sh + schema migrations)
#
# Run order: init-db.sh → init-authz.sh → (data_flow schema) → init-authz-policies.sh
set -euo pipefail

HOST="${INITDB_HOST:-clickhouse}"
PORT="${CH_TCP_SECURE_PORT:-9440}"
INTERNAL_PORT="${CH_TCP_PORT:-9000}"   # plain TCP for dictionary source (localhost-to-localhost)
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

# ── TLP numeric mapping function ───────────────────────────────────────────────

echo "Creating tlp_to_numeric function..."
$CH --query "
CREATE FUNCTION IF NOT EXISTS tlp_to_numeric AS (level) ->
    toInt8(transform(
        level,
        ['tlp:clear', 'tlp:green', 'tlp:amber', 'tlp:red'],
        [0, 1, 2, 3],
        -1
    ))
"

# ── Cumulative grant dictionaries ──────────────────────────────────────────────
#
# Key:   (user_id String, tlp_numeric Int8)  — the row's TLP level (exact match)
# Value: org_slugs Array(String)             — orgs the user can access AT that level
#
# "Cumulative" means: the key for tlp=2 (amber) includes orgs where max_tlp >= 2,
# i.e. orgs granted at amber OR red. This is pre-computed so the row policy can
# do a single exact dictGet() lookup using the row's TLP level as the key.
#
# Source query cross-joins a 4-row numbers table (levels 0-3) with grants so
# each user×level pair accumulates all orgs the user can access at that level.
#
# SQL single-quoting inside the heredoc: inner SQL single quotes are escaped as
# doubled single quotes per the ClickHouse SQL string literal convention.

DICT_SOURCE_READ="
SELECT
    g.group_name,
    CAST(n.tlp_numeric AS Int8) AS tlp_numeric,
    groupArray(o.slug) AS org_slugs
FROM (
    SELECT 0 AS tlp_numeric
    UNION ALL SELECT 1
    UNION ALL SELECT 2
    UNION ALL SELECT 3
) AS n
CROSS JOIN metranova_authz.grants AS g
JOIN metranova_authz.organizations AS o ON g.organization_id = o.id
WHERE g.permission = 'read'
  AND isNull(g.revoked_at)
  AND tlp_to_numeric(g.max_tlp_level) >= n.tlp_numeric
GROUP BY g.group_name, n.tlp_numeric
"

DICT_SOURCE_WRITE="
SELECT
    g.group_name,
    CAST(n.tlp_numeric AS Int8) AS tlp_numeric,
    groupArray(o.slug) AS org_slugs
FROM (
    SELECT 0 AS tlp_numeric
    UNION ALL SELECT 1
    UNION ALL SELECT 2
    UNION ALL SELECT 3
) AS n
CROSS JOIN metranova_authz.grants AS g
JOIN metranova_authz.organizations AS o ON g.organization_id = o.id
WHERE g.permission = 'write'
  AND isNull(g.revoked_at)
  AND tlp_to_numeric(g.max_tlp_level) >= n.tlp_numeric
GROUP BY g.group_name, n.tlp_numeric
"

echo "Creating authz_group_read_orgs dictionary..."
$CH --multiquery <<SQL
DROP DICTIONARY IF EXISTS metranova_authz.authz_group_read_orgs;
CREATE DICTIONARY metranova_authz.authz_group_read_orgs
(
    group_name  String,
    tlp_numeric Int8,
    org_slugs   Array(String)
)
PRIMARY KEY group_name, tlp_numeric
SOURCE(CLICKHOUSE(
    HOST 'localhost'
    PORT ${INTERNAL_PORT}
    USER '${USER}'
    PASSWORD '${PASS}'
    QUERY '$(echo "$DICT_SOURCE_READ" | tr -d '\n' | sed "s/'/''/g")'
))
LIFETIME(MIN 30 MAX 60)
LAYOUT(COMPLEX_KEY_HASHED());
SQL

echo "Creating authz_group_write_orgs dictionary..."
$CH --multiquery <<SQL
DROP DICTIONARY IF EXISTS metranova_authz.authz_group_write_orgs;
CREATE DICTIONARY metranova_authz.authz_group_write_orgs
(
    group_name  String,
    tlp_numeric Int8,
    org_slugs   Array(String)
)
PRIMARY KEY group_name, tlp_numeric
SOURCE(CLICKHOUSE(
    HOST 'localhost'
    PORT ${INTERNAL_PORT}
    USER '${USER}'
    PASSWORD '${PASS}'
    QUERY '$(echo "$DICT_SOURCE_WRITE" | tr -d '\n' | sed "s/'/''/g")'
))
LIFETIME(MIN 30 MAX 60)
LAYOUT(COMPLEX_KEY_HASHED());
SQL

# ── Row policies ───────────────────────────────────────────────────────────────
#
# TO ALL EXCEPT accepts both usernames and role names (including LDAP-mapped roles).
# A user who holds the clickhouse-admin role is exempt because that role is listed,
# not because their username is hardcoded. LDAP group → role mapping handles this
# automatically: any user in the clickhouse-admin LDAP group gets the role and the
# exemption.
#
# Rationale for exempting clickhouse-admin: a principal with DROP TABLE / DROP ROW
# POLICY privileges can bypass row policies through other means anyway — enforcing
# TLP on them provides false security, not real security. Trust is enforced at the
# role-grant level, not via row policy.
#
# Exempt identities (keep this list minimal — every addition is a security bypass):
#   clickhouse-admin role — DDL superusers; LDAP-mapped, no hardcoded usernames
#   default  (username)   — ClickHouse built-in superuser, needed for init scripts
#   pipeline (username)   — ingest writer; stamps policy_organizations itself
#
# External org service accounts must NOT be added here. They get grants in
# authz_grants and are subject to full TLP enforcement like any other user.
#
# authz_read_policy:         deny-by-default dict lookup for all non-exempt users
# authz_grafana_read_policy: grafana service account sees only tlp:clear rows
# authz_write_policy:        same dict-based check for INSERT

echo "Creating row policies..."
$CH --multiquery <<'SQL'

-- Remove old versions before recreating (policies are not IF NOT EXISTS-safe for changes)
DROP ROW POLICY IF EXISTS authz_read_policy ON metranova.data_flow;
DROP ROW POLICY IF EXISTS authz_grafana_read_policy ON metranova.data_flow;
DROP ROW POLICY IF EXISTS authz_write_policy ON metranova.data_flow;

-- SELECT: exempt clickhouse-admin role (DDL superusers) and init-only accounts;
--         grafana gets its own restricted policy below.
CREATE ROW POLICY authz_read_policy ON metranova.data_flow
FOR SELECT
USING hasAny(
    policy_organizations,
    arrayFlatten(arrayMap(
        r -> dictGetOrDefault(
                'metranova_authz.authz_group_read_orgs',
                'org_slugs',
                (r, tlp_to_numeric(policy_level)),
                cast([], 'Array(String)')
             ),
        currentRoles()
    ))
)
TO ALL EXCEPT `clickhouse-admin`, pipeline, default, grafana;

-- SELECT (grafana): public-only — grafana service account sees only tlp:clear rows.
--   When Grafana proxies a real user's identity, that user's own policy applies instead.
CREATE ROW POLICY authz_grafana_read_policy ON metranova.data_flow
FOR SELECT
USING (policy_level = 'tlp:clear')
TO grafana;

-- INSERT: grafana has no write grants so hasAny always returns false, but it is
--         still subject to the policy (not silently exempt).
CREATE ROW POLICY authz_write_policy ON metranova.data_flow
FOR INSERT
USING hasAny(
    policy_organizations,
    arrayFlatten(arrayMap(
        r -> dictGetOrDefault(
                'metranova_authz.authz_group_write_orgs',
                'org_slugs',
                (r, tlp_to_numeric(policy_level)),
                cast([], 'Array(String)')
             ),
        currentRoles()
    ))
)
TO ALL EXCEPT `clickhouse-admin`, pipeline, default;

SQL

echo "metranova_authz policies initialized."
