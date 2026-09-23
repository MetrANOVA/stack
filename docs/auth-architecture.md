# MetrANOVA Authorization Architecture

## Overview

MetrANOVA uses ClickHouse row-level security to enforce data access control.
Every row in `metranova.data_flow` carries a `policy_scope` array of scope elements
(e.g. `as:293`, `comm:lhcone`) and a `policy_level` TLP classification.  Access is
granted when a user's ClickHouse role can be mapped — through the authorization
dictionaries — to an organization that owns at least one of the row's scope elements.

## Data model

```
metranova_authz.organizations   — named orgs (esnet, lhcone-partners, …)
metranova_authz.rules           — scope pattern → org mapping rules
metranova_authz.grants          — Keycloak group → org + TLP + permission
metranova_authz.audit_log       — immutable append-only audit trail
```

## Dictionaries

Three ClickHouse dictionaries are deployed by `section_init_authz_policies` (wizard step 3).
All refresh every 30–60 seconds, so rule and grant changes propagate automatically.

### `authz_group_read_orgs`

**Key:** `(group_name String, tlp_numeric Int8)`  
**Value:** `org_slugs Array(String)`

Maps a Keycloak group + TLP level to the set of organization slugs that group
may read at that level.  The source query is cumulative: a grant at `tlp:amber`
(level 2) includes orgs readable at amber **and** red, so a single `dictGet` at
the row's own TLP level returns the full allowed set.

### `authz_group_write_orgs`

Same structure as `authz_group_read_orgs` but filtered to `permission='write'`.
Reserved for future INSERT row-policy enforcement (not yet supported in ClickHouse 25.x).

### `authz_scope_to_orgs` ← the key innovation

**Key:** `scope_el String`  
**Value:** `org_slugs Array(String)`

Maps each **scope element observed in `metranova.data_flow`** to the set of
organization slugs that own it, by expanding glob rules at dictionary load time:

```sql
SELECT scope_el, groupArray(DISTINCT slug) AS org_slugs
FROM (
    SELECT DISTINCT arrayJoin(policy_scope) AS scope_el
    FROM metranova.data_flow
) AS data_scopes
CROSS JOIN (
    SELECT policy_scope_pattern, slug
    FROM metranova_authz.rules FINAL
    JOIN metranova_authz.organizations
      ON organization_id = metranova_authz.organizations.id
) AS rule_orgs
WHERE policy_scope_pattern = '*'
   OR scope_el LIKE replace(policy_scope_pattern, '*', '%')
GROUP BY scope_el
```

Pattern matching at load time means row policies use only `dictGet` calls — no
correlated subqueries, which ClickHouse 25.x does not support in row policies
(Code: 48, NOT_IMPLEMENTED).

**Why this matters for historical data:** When new rules are added or changed, the
dictionary refreshes within 30–60 s and the new mapping applies to **all rows**,
including rows ingested before the rule existed.  No pipeline restart or re-stamping
is required.

## Row policies

Two active policies on `metranova.data_flow`:

### `authz_read_policy` (FOR SELECT)

Applied to all users **except** `clickhouse-admin`, `admin`, `pipeline`, `default`,
`grafana` (these roles bypass enforcement by design — they can drop row policies
anyway, so enforcing on them provides false security).

```sql
USING arrayExists(
    org -> arrayExists(
        s -> has(
            dictGetOrDefault('metranova_authz.authz_scope_to_orgs', 'org_slugs',
                             tuple(s), cast([], 'Array(String)')),
            org
        ),
        policy_scope
    ),
    arrayFlatten(arrayMap(
        r -> dictGetOrDefault('metranova_authz.authz_group_read_orgs', 'org_slugs',
                              (r, tlp_to_numeric(policy_level)), cast([], 'Array(String)')),
        currentRoles()
    ))
)
```

Logic: a row is visible if *any* of the user's readable orgs (from
`authz_group_read_orgs`) appears in the org set of *any* scope element on the row
(from `authz_scope_to_orgs`).

### `authz_grafana_read_policy` (FOR SELECT)

Applied only to the `grafana` service-account role.  Grafana sees only
`policy_level = 'tlp:clear'` rows — a hard limit regardless of grants, preventing
accidental dashboard exposure of amber/red data.

## Scope element conventions

The flow pipeline stamps `policy_scope` with:

- `as:<ASN>` — autonomous system number (e.g. `as:293` for ESnet)
- `comm:<name>` — BGP community tag (e.g. `comm:lhcone`)

Rule `policy_scope_pattern` supports:

| Pattern | Matches |
|---------|---------|
| `as:293` | exactly AS 293 |
| `as:*` | any AS scope element |
| `comm:lhcone` | exactly the lhcone community |
| `*` | every scope element (global catch-all) |

Patterns are expanded to SQL `LIKE` at dictionary load time:
`as:*` → `scope_el LIKE 'as:%'`.

## Access grant lifecycle

1. **Wizard step 5 (Rules):** add `policy_scope_pattern → organization` rules.
2. **Wizard step 6 (Grants):** create a grant linking a Keycloak group to an org + TLP.
   The wizard creates the matching ClickHouse role and grants it `SELECT` on
   `metranova.data_flow` plus `dictGet` on all three authz dictionaries.
3. **Keycloak:** add users to the group.  LDAP sync propagates membership to ClickHouse
   as role assignments.
4. **Dictionary refresh (≤60 s):** `authz_group_read_orgs` and `authz_scope_to_orgs`
   reload.  The new grant takes effect for all subsequent queries.

## TLP levels

| Level | Numeric | Audience |
|-------|---------|----------|
| `tlp:clear` | 0 | Public / Grafana service account |
| `tlp:green` | 1 | Community (need-to-know) |
| `tlp:amber` | 2 | Limited distribution |
| `tlp:red` | 3 | Custodial org only |

The `tlp_to_numeric` UDF maps level strings to integers for dictionary key lookups.

## ClickHouse version constraint

ClickHouse 25.7+ is required.  Versions ≤ 25.6 do not support
`COMPLEX_KEY_HASHED` dictionaries with `Array` value columns.

ClickHouse 25.9.7 (current) does **not** support correlated subqueries in row-policy
USING clauses (Code: 48, NOT_IMPLEMENTED).  The `authz_scope_to_orgs` dictionary
approach was designed specifically to avoid this limitation.

## Security properties

- All authorization decisions are derived from `metranova_authz` tables and evaluated
  by ClickHouse on every query — there is no client-side enforcement.
- Every grant and revocation is written to `metranova_authz.audit_log` with actor,
  timestamp, and a checksum for tamper detection.
- Exempt identities (`clickhouse-admin`, `admin`) can drop row policies and therefore
  cannot be meaningfully restricted by them — the exempt list is minimal and documented.
- Dictionary refresh (30–60 s) is the only window between a rule/grant change and its
  enforcement.  For immediate effect, run `SYSTEM RELOAD DICTIONARY` on the affected
  dictionary.
