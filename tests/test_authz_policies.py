"""Unit tests for metranova_authz row policies and dictionaries.

Tests the policy logic using clickhouse-local (no cluster, no real dictionary
server needed). Dictionary source queries are validated by running the SQL
directly against fixture data. Row policy expressions are validated inline.
"""
from __future__ import annotations

import subprocess
import textwrap

import pytest

TLP_LEVELS = ["tlp:clear", "tlp:green", "tlp:amber", "tlp:red"]
TLP_NUMERIC = {level: i for i, level in enumerate(TLP_LEVELS)}


def ch(query: str) -> str:
    result = subprocess.run(
        ["clickhouse", "local", "--query", textwrap.dedent(query)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"clickhouse-local failed:\n{result.stderr}"
    return result.stdout.strip()


def ch_multi(*queries: str) -> str:
    result = subprocess.run(
        ["clickhouse", "local", "--multiquery"],
        input="\n".join(queries),
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"clickhouse-local failed:\n{result.stderr}"
    return result.stdout.strip()


# ── Schema + fixture shared across policy tests ────────────────────────────────

AUTHZ_SCHEMA = """
CREATE DATABASE metranova_authz;

CREATE TABLE metranova_authz.organizations (
    id UUID DEFAULT generateUUIDv4(),
    name String, slug String, is_custodial Bool DEFAULT false,
    created_at DateTime64(3) DEFAULT now64(), updated_at DateTime64(3) DEFAULT now64()
) ENGINE = ReplacingMergeTree(updated_at) ORDER BY id;

CREATE TABLE metranova_authz.grants (
    id UUID DEFAULT generateUUIDv4(),
    group_name String, organization_id UUID,
    max_tlp_level String, permission String,
    granted_by String,
    granted_at DateTime64(3) DEFAULT now64(),
    revoked_at Nullable(DateTime64(3))
) ENGINE = ReplacingMergeTree(granted_at) ORDER BY (group_name, organization_id, permission);
"""

# Each grant row maps one Keycloak group to one org+TLP+permission.
# Groups are named by convention: authz-tlp-{org}-{level}-{read|write}
FIXTURE_DATA = """
INSERT INTO metranova_authz.organizations (id, name, slug, is_custodial) VALUES
    ('00000000-0000-0000-0000-000000000001', 'ESnet',     'esnet',     true),
    ('00000000-0000-0000-0000-000000000002', 'Internet2', 'internet2', false),
    ('00000000-0000-0000-0000-000000000003', 'GEANT',     'geant',     false);

-- esnet read grants at different TLP levels
INSERT INTO metranova_authz.grants (id, group_name, organization_id, max_tlp_level, permission, granted_by) VALUES
    ('10000000-0000-0000-0000-000000000001', 'authz-tlp-esnet-amber-read',  '00000000-0000-0000-0000-000000000001', 'tlp:amber', 'read',  'admin'),
    ('10000000-0000-0000-0000-000000000002', 'authz-tlp-esnet-red-read',    '00000000-0000-0000-0000-000000000001', 'tlp:red',   'read',  'admin'),
    ('10000000-0000-0000-0000-000000000003', 'authz-tlp-esnet-green-write', '00000000-0000-0000-0000-000000000001', 'tlp:green', 'write', 'admin');

-- internet2 read at clear only
INSERT INTO metranova_authz.grants (id, group_name, organization_id, max_tlp_level, permission, granted_by) VALUES
    ('10000000-0000-0000-0000-000000000004', 'authz-tlp-internet2-clear-read',   '00000000-0000-0000-0000-000000000002', 'tlp:clear', 'read',  'admin'),
    ('10000000-0000-0000-0000-000000000005', 'authz-tlp-internet2-green-write',  '00000000-0000-0000-0000-000000000002', 'tlp:green', 'write', 'admin');

-- revoked: this group's esnet read grant was revoked
INSERT INTO metranova_authz.grants (id, group_name, organization_id, max_tlp_level, permission, granted_by, revoked_at) VALUES
    ('10000000-0000-0000-0000-000000000006', 'authz-tlp-esnet-amber-read-revoked', '00000000-0000-0000-0000-000000000001', 'tlp:amber', 'read', 'admin', '2026-01-01 00:00:00');
"""

SETUP = AUTHZ_SCHEMA + FIXTURE_DATA

# The cumulative dict source query (same logic as init-authz-policies.sh)
DICT_SOURCE_QUERY = """
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
WHERE g.permission = '{permission}'
  AND isNull(g.revoked_at)
  AND toInt8(transform(
        g.max_tlp_level,
        ['tlp:clear','tlp:green','tlp:amber','tlp:red'],
        [0,1,2,3],
        -1
      )) >= n.tlp_numeric
GROUP BY g.group_name, n.tlp_numeric
ORDER BY g.group_name, n.tlp_numeric
"""


# ── tlp_to_numeric function ────────────────────────────────────────────────────

class TestTlpToNumeric:
    """Validate the tlp_to_numeric UDF logic inline (no persistent function needed)."""

    EXPR = """
    toInt8(transform(
        '{level}',
        ['tlp:clear','tlp:green','tlp:amber','tlp:red'],
        [0,1,2,3],
        -1
    ))
    """

    def _numeric(self, level: str) -> int:
        return int(ch(f"SELECT {self.EXPR.format(level=level)}"))

    def test_clear_is_zero(self):
        assert self._numeric("tlp:clear") == 0

    def test_green_is_one(self):
        assert self._numeric("tlp:green") == 1

    def test_amber_is_two(self):
        assert self._numeric("tlp:amber") == 2

    def test_red_is_three(self):
        assert self._numeric("tlp:red") == 3

    def test_unknown_is_minus_one(self):
        assert self._numeric("tlp:bogus") == -1

    def test_ordered(self):
        nums = [self._numeric(lvl) for lvl in TLP_LEVELS]
        assert nums == sorted(nums)


# ── Cumulative dictionary source query ─────────────────────────────────────────

class TestDictSourceQuery:
    """Validate the cumulative grant aggregation that feeds the dictionaries."""

    def _read_rows(self) -> dict[tuple, list[str]]:
        out = ch_multi(SETUP, DICT_SOURCE_QUERY.format(permission="read"))
        rows = {}
        for line in out.splitlines():
            parts = line.split("\t")
            group, tlp, slugs_raw = parts[0], int(parts[1]), parts[2]
            slugs = [s.strip("'") for s in slugs_raw.strip("[]").split(",") if s.strip("'")]
            rows[(group, tlp)] = slugs
        return rows

    def _write_rows(self) -> dict[tuple, list[str]]:
        out = ch_multi(SETUP, DICT_SOURCE_QUERY.format(permission="write"))
        rows = {}
        for line in out.splitlines():
            parts = line.split("\t")
            group, tlp, slugs_raw = parts[0], int(parts[1]), parts[2]
            slugs = [s.strip("'") for s in slugs_raw.strip("[]").split(",") if s.strip("'")]
            rows[(group, tlp)] = slugs
        return rows

    def test_esnet_amber_read_group_visible_at_clear(self):
        rows = self._read_rows()
        # amber:read group can read at tlp=0 (clear) — cumulative downward
        assert "esnet" in set(rows[("authz-tlp-esnet-amber-read", 0)])

    def test_esnet_amber_read_group_visible_at_amber(self):
        rows = self._read_rows()
        assert "esnet" in set(rows[("authz-tlp-esnet-amber-read", 2)])

    def test_esnet_amber_read_group_not_visible_at_red(self):
        rows = self._read_rows()
        # max_tlp is amber (2), so no entry at tlp=3 (red)
        assert ("authz-tlp-esnet-amber-read", 3) not in rows

    def test_esnet_red_read_group_visible_at_all_levels(self):
        rows = self._read_rows()
        for tlp in range(4):
            assert ("authz-tlp-esnet-red-read", tlp) in rows
            assert "esnet" in set(rows[("authz-tlp-esnet-red-read", tlp)])

    def test_internet2_clear_read_group_visible_at_clear_only(self):
        rows = self._read_rows()
        assert ("authz-tlp-internet2-clear-read", 0) in rows
        assert "internet2" in set(rows[("authz-tlp-internet2-clear-read", 0)])
        assert ("authz-tlp-internet2-clear-read", 1) not in rows

    def test_write_groups_absent_from_read_dict(self):
        rows = self._read_rows()
        # Write-only groups must not appear in the read dictionary
        assert not any(g.endswith("-write") for (g, _) in rows)

    def test_esnet_green_write_group_cumulative(self):
        rows = self._write_rows()
        # green write (level 1) covers clear (0) and green (1)
        assert ("authz-tlp-esnet-green-write", 0) in rows
        assert "esnet" in set(rows[("authz-tlp-esnet-green-write", 0)])
        assert ("authz-tlp-esnet-green-write", 1) in rows
        assert "esnet" in set(rows[("authz-tlp-esnet-green-write", 1)])
        assert ("authz-tlp-esnet-green-write", 2) not in rows  # above max

    def test_internet2_write_group(self):
        rows = self._write_rows()
        assert ("authz-tlp-internet2-green-write", 0) in rows
        assert "internet2" in set(rows[("authz-tlp-internet2-green-write", 0)])

    def test_read_groups_absent_from_write_dict(self):
        rows = self._write_rows()
        # Read-only groups must not appear in the write dictionary
        assert not any(g.endswith("-read") for (g, _) in rows)

    def test_revoked_grants_excluded(self):
        rows = self._read_rows()
        assert not any(g == "authz-tlp-esnet-amber-read-revoked" for (g, _) in rows)


# ── Row policy expressions ─────────────────────────────────────────────────────

class TestRowPolicyExpressions:
    """
    Validate the hasAny + arrayFlatten + arrayMap expression used in the row
    policy USING clause. We simulate dictGetOrDefault by substituting literal
    arrays per role, since clickhouse-local cannot create persistent dictionaries.
    """

    def _has_read_access(self, policy_organizations: list[str], roles_to_orgs: dict[str, list[str]], policy_level: str) -> bool:
        """
        Simulate the SELECT row policy:
          hasAny(policy_organizations,
                 arrayFlatten(arrayMap(r -> dictGetOrDefault(..., r, tlp), currentRoles())))

        roles_to_orgs: {role_name: [org_slugs_at_this_tlp]}
        """
        def arr(lst):
            return "[" + ",".join(f"'{s}'" for s in lst) + "]"

        # Build a flat union of all orgs from all roles (simulating arrayFlatten(arrayMap(...)))
        all_orgs = []
        for orgs in roles_to_orgs.values():
            all_orgs.extend(orgs)

        expr = f"SELECT hasAny({arr(policy_organizations)}, {arr(all_orgs)})"
        return ch(expr) == "1"

    def test_matching_group_grants_access(self):
        assert self._has_read_access(
            ["esnet"],
            {"authz-tlp-esnet-amber-read": ["esnet", "internet2"]},
            "tlp:clear",
        )

    def test_no_matching_group_denies_access(self):
        assert not self._has_read_access(
            ["geant"],
            {"authz-tlp-esnet-amber-read": ["esnet"]},
            "tlp:clear",
        )

    def test_user_with_multiple_roles_union(self):
        # User holds two groups; access is union of both groups' org sets
        assert self._has_read_access(
            ["geant"],
            {
                "authz-tlp-esnet-amber-read": ["esnet"],
                "authz-tlp-geant-amber-read": ["geant"],
            },
            "tlp:amber",
        )

    def test_empty_roles_denies(self):
        assert not self._has_read_access(["esnet"], {}, "tlp:clear")

    def test_empty_row_orgs_denies(self):
        assert not self._has_read_access([], {"authz-tlp-esnet-amber-read": ["esnet"]}, "tlp:clear")

    def test_multiple_row_orgs_any_match_grants(self):
        assert self._has_read_access(
            ["esnet", "internet2"],
            {"authz-tlp-internet2-clear-read": ["internet2"]},
            "tlp:clear",
        )

    def test_grafana_policy_clear_only(self):
        # grafana row policy: policy_level = 'tlp:clear'
        assert ch("SELECT policy_level = 'tlp:clear' FROM (SELECT 'tlp:clear' AS policy_level)") == "1"
        assert ch("SELECT policy_level = 'tlp:clear' FROM (SELECT 'tlp:green' AS policy_level)") == "0"
        assert ch("SELECT policy_level = 'tlp:clear' FROM (SELECT 'tlp:amber' AS policy_level)") == "0"
        assert ch("SELECT policy_level = 'tlp:clear' FROM (SELECT 'tlp:red'   AS policy_level)") == "0"

    def test_deny_by_default_empty_dict_result(self):
        # dictGetOrDefault returns [] when no key matches — hasAny(row_orgs, []) is false
        assert not self._has_read_access(["esnet"], {"some-unrelated-group": []}, "tlp:amber")

    def test_write_uses_separate_dict_from_read(self):
        # A group with read orgs=[esnet] but write orgs=[] cannot write
        row_orgs = ["esnet"]
        read_orgs = {"authz-tlp-esnet-amber-read": ["esnet"]}
        write_orgs: dict[str, list[str]] = {}
        assert self._has_read_access(row_orgs, read_orgs, "tlp:clear")
        assert not self._has_read_access(row_orgs, write_orgs, "tlp:clear")

    def test_arraymap_flatten_expression(self):
        """Validate the actual ClickHouse arrayFlatten(arrayMap(...)) syntax."""
        # Simulate: two roles each returning an array, flattened into one
        result = ch(
            "SELECT arrayFlatten(arrayMap("
            "    r -> if(r = 'role-a', ['esnet', 'internet2'], ['geant']),"
            "    ['role-a', 'role-b']"
            "))"
        )
        assert "esnet" in result
        assert "internet2" in result
        assert "geant" in result
