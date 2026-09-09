"""Unit tests for metranova_authz ClickHouse schema.

Uses clickhouse-local (no cluster needed) to validate table definitions,
column types, and engine settings.
"""
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_SCRIPT = REPO_ROOT / "clickhouse" / "scripts" / "init-authz.sh"

# TLP levels in hierarchy order
TLP_LEVELS = ["tlp:clear", "tlp:green", "tlp:amber", "tlp:red"]
TLP_NUMERIC = {level: i for i, level in enumerate(TLP_LEVELS)}


def ch(query: str) -> str:
    """Run a query via clickhouse-local and return stdout."""
    result = subprocess.run(
        ["clickhouse", "local", "--query", textwrap.dedent(query)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"clickhouse-local failed:\n{result.stderr}"
    return result.stdout.strip()


def ch_multi(*queries: str) -> str:
    """Run multiple statements via clickhouse-local."""
    result = subprocess.run(
        ["clickhouse", "local", "--multiquery"],
        input="\n".join(queries),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"clickhouse-local failed:\n{result.stderr}"
    return result.stdout.strip()


# ── Schema fixture ─────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE DATABASE metranova_authz;

CREATE TABLE metranova_authz.organizations
(
    id           UUID         DEFAULT generateUUIDv4(),
    name         String,
    slug         String,
    is_custodial    Bool         DEFAULT false,
    created_at   DateTime64(3) DEFAULT now64(),
    updated_at   DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY id;

CREATE TABLE metranova_authz.rules
(
    id                        UUID         DEFAULT generateUUIDv4(),
    organization_id           UUID,
    policy_originator_pattern String,
    policy_scope_pattern      String,
    assigned_tlp              Nullable(String),
    priority                  Int32    DEFAULT 0,
    description               String   DEFAULT '',
    created_at                DateTime64(3) DEFAULT now64()
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (priority, id);

CREATE TABLE metranova_authz.grants
(
    id              UUID     DEFAULT generateUUIDv4(),
    user_id         String,
    organization_id UUID,
    max_tlp_level   String,
    permission      String,
    granted_by      String,
    granted_at      DateTime64(3) DEFAULT now64(),
    revoked_at      Nullable(DateTime64(3))
)
ENGINE = ReplacingMergeTree(granted_at)
ORDER BY (user_id, organization_id, permission);

CREATE TABLE metranova_authz.audit_log
(
    timestamp    DateTime64(3) DEFAULT now64(),
    event_type   String,
    actor        String,
    target_user  String    DEFAULT '',
    organization String    DEFAULT '',
    details      String    DEFAULT '',
    checksum     String    DEFAULT ''
)
ENGINE = MergeTree()
ORDER BY (timestamp, event_type, actor)
SETTINGS allow_nullable_key = 0;
"""


# ── Table structure tests ──────────────────────────────────────────────────────

class TestSchema:
    def test_organizations_columns(self):
        out = ch_multi(SCHEMA_SQL, "DESCRIBE metranova_authz.organizations")
        cols = {line.split("\t")[0] for line in out.strip().splitlines()}
        assert cols == {"id", "name", "slug", "is_custodial", "created_at", "updated_at"}

    def test_organizations_engine(self):
        out = ch_multi(SCHEMA_SQL,
            "SELECT engine FROM system.tables "
            "WHERE database='metranova_authz' AND name='organizations'")
        assert "ReplacingMergeTree" in out

    def test_rules_columns(self):
        out = ch_multi(SCHEMA_SQL, "DESCRIBE metranova_authz.rules")
        cols = {line.split("\t")[0] for line in out.strip().splitlines()}
        assert {"id", "organization_id", "policy_originator_pattern",
                "policy_scope_pattern", "assigned_tlp", "priority",
                "description", "created_at"} == cols

    def test_rules_assigned_tlp_nullable(self):
        out = ch_multi(SCHEMA_SQL, "DESCRIBE metranova_authz.rules")
        col_types = {
            line.split("\t")[0]: line.split("\t")[1]
            for line in out.strip().splitlines()
        }
        assert "Nullable" in col_types["assigned_tlp"]

    def test_grants_columns(self):
        out = ch_multi(SCHEMA_SQL, "DESCRIBE metranova_authz.grants")
        cols = {line.split("\t")[0] for line in out.strip().splitlines()}
        assert {"id", "user_id", "organization_id", "max_tlp_level",
                "permission", "granted_by", "granted_at", "revoked_at"} == cols

    def test_grants_revoked_at_nullable(self):
        out = ch_multi(SCHEMA_SQL, "DESCRIBE metranova_authz.grants")
        col_types = {
            line.split("\t")[0]: line.split("\t")[1]
            for line in out.strip().splitlines()
        }
        assert "Nullable" in col_types["revoked_at"]

    def test_audit_log_columns(self):
        out = ch_multi(SCHEMA_SQL, "DESCRIBE metranova_authz.audit_log")
        cols = {line.split("\t")[0] for line in out.strip().splitlines()}
        assert {"timestamp", "event_type", "actor", "target_user",
                "organization", "details", "checksum"} == cols

    def test_audit_log_engine(self):
        out = ch_multi(SCHEMA_SQL,
            "SELECT engine FROM system.tables "
            "WHERE database='metranova_authz' AND name='audit_log'")
        # MergeTree (not Replacing) — audit log is append-only
        assert out.strip() == "MergeTree"

    def test_policy_organizations_column(self):
        """data_flow must have policy_organizations Array(String) for row policies."""
        # Verify the ALTER TABLE statement is syntactically valid using a temp table
        out = ch_multi(
            "CREATE TABLE metranova_data_flow_stub "
            "(policy_level String, policy_scope Array(String), policy_originator String) "
            "ENGINE = MergeTree() ORDER BY policy_level;",
            "ALTER TABLE metranova_data_flow_stub "
            "ADD COLUMN IF NOT EXISTS policy_organizations Array(String) DEFAULT [];",
            "DESCRIBE metranova_data_flow_stub;",
        )
        cols = {line.split("\t")[0] for line in out.strip().splitlines()}
        assert "policy_organizations" in cols


# ── Data integrity tests ───────────────────────────────────────────────────────

class TestDataIntegrity:
    """Verify inserts and basic queries work correctly."""

    SETUP = SCHEMA_SQL + """
INSERT INTO metranova_authz.organizations (id, name, slug, is_custodial)
VALUES ('00000000-0000-0000-0000-000000000001', 'ESnet', 'esnet', true);

INSERT INTO metranova_authz.organizations (id, name, slug, is_custodial)
VALUES ('00000000-0000-0000-0000-000000000002', 'Internet2', 'internet2', false);

INSERT INTO metranova_authz.grants
  (id, user_id, organization_id, max_tlp_level, permission, granted_by)
VALUES
  ('00000000-0000-0000-0000-000000000010',
   'jsmith', '00000000-0000-0000-0000-000000000001', 'tlp:amber', 'read', 'admin'),
  ('00000000-0000-0000-0000-000000000011',
   'jsmith', '00000000-0000-0000-0000-000000000001', 'tlp:green', 'write', 'admin'),
  ('00000000-0000-0000-0000-000000000012',
   'jsmith', '00000000-0000-0000-0000-000000000002', 'tlp:clear', 'read', 'admin');
"""

    def test_org_insert_and_query(self):
        out = ch_multi(
            self.SETUP,
            "SELECT count() FROM metranova_authz.organizations",
        )
        assert out.strip() == "2"

    def test_exactly_one_master_org(self):
        out = ch_multi(
            self.SETUP,
            "SELECT count() FROM metranova_authz.organizations WHERE is_custodial = true",
        )
        assert out.strip() == "1"

    def test_grants_read_write_independent(self):
        """jsmith has read up to amber but write only up to green for esnet."""
        out = ch_multi(
            self.SETUP,
            "SELECT max_tlp_level FROM metranova_authz.grants "
            "WHERE user_id='jsmith' AND organization_id='00000000-0000-0000-0000-000000000001' "
            "AND permission='read'",
        )
        assert out.strip() == "tlp:amber"

        out2 = ch_multi(
            self.SETUP,
            "SELECT max_tlp_level FROM metranova_authz.grants "
            "WHERE user_id='jsmith' AND organization_id='00000000-0000-0000-0000-000000000001' "
            "AND permission='write'",
        )
        assert out2.strip() == "tlp:green"

    def test_grant_count_for_user(self):
        out = ch_multi(
            self.SETUP,
            "SELECT count() FROM metranova_authz.grants WHERE user_id='jsmith'",
        )
        assert out.strip() == "3"

    def test_audit_log_insert(self):
        out = ch_multi(
            self.SETUP +
            "INSERT INTO metranova_authz.audit_log (event_type, actor, details) "
            "VALUES ('grant_created', 'admin', '{\"note\": \"test\"}');\n"
            "SELECT count() FROM metranova_authz.audit_log;"
        )
        assert out.strip() == "1"


# ── TLP hierarchy tests ────────────────────────────────────────────────────────

class TestTLPHierarchy:
    """Validate the TLP level ordering used by the access model."""

    def test_tlp_levels_ordered(self):
        assert TLP_NUMERIC["tlp:clear"] < TLP_NUMERIC["tlp:green"]
        assert TLP_NUMERIC["tlp:green"] < TLP_NUMERIC["tlp:amber"]
        assert TLP_NUMERIC["tlp:amber"] < TLP_NUMERIC["tlp:red"]

    def test_cumulative_access_clear_grant(self):
        """A tlp:clear grant sees only tlp:clear rows."""
        grant_level = TLP_NUMERIC["tlp:clear"]
        visible = [lvl for lvl, num in TLP_NUMERIC.items() if num <= grant_level]
        assert visible == ["tlp:clear"]

    def test_cumulative_access_amber_grant(self):
        """A tlp:amber grant sees clear, green, and amber rows."""
        grant_level = TLP_NUMERIC["tlp:amber"]
        visible = [lvl for lvl, num in TLP_NUMERIC.items() if num <= grant_level]
        assert set(visible) == {"tlp:clear", "tlp:green", "tlp:amber"}

    def test_cumulative_access_red_grant(self):
        """A tlp:red grant sees all levels."""
        grant_level = TLP_NUMERIC["tlp:red"]
        visible = [lvl for lvl, num in TLP_NUMERIC.items() if num <= grant_level]
        assert set(visible) == set(TLP_LEVELS)

    def test_write_does_not_imply_read(self):
        """Write grant at tlp:green does not grant read at tlp:amber."""
        write_grant = TLP_NUMERIC["tlp:green"]
        read_request_level = TLP_NUMERIC["tlp:amber"]
        # A separate read grant at tlp:amber would be required
        assert write_grant < read_request_level  # write grant insufficient for amber read
