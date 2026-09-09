# MetrANOVA Proof-of-Concept Authorization System — Design Specification

## Context

MetrANOVA has a working authentication system (Keycloak + OpenLDAP + Envoy + nonce-based ClickHouse access) but no authorization beyond three static roles (admin/operator/viewer). The system will be deployed at R&E ISPs carrying sensitive traffic, making row-level access control a hard requirement.

The data_flow table already has policy_level (e.g. tlp:amber), policy_scope (array), and policy_originator columns stamped at ingest time. A new policy_organizations Array(String) column will also be stamped at ingest to carry org tags. This spec designs an authorization layer that enforces row-level access using these columns, managed through organizations and TLP classification.

**Key invariant:** each row has exactly one TLP level and zero or more organization tags. A user can see a row if they have a grant matching at least one of the row's org tags at or above the row's TLP level.

All authorization decisions must be auditable, and the authorization system should be implemented with 100% test coverage.

------------------------------------------------------------------------

## 1. Data Model

### 1.1 TLP Levels (fixed hierarchy)<sup>[\[a\]](#cmnt1)</sup>

Standard Traffic Light Protocol levels, ordered by restrictiveness:

|           |         |                        |
|-----------|---------|------------------------|
| Level     | Numeric | Meaning                |
| tlp:clear | 0       | Public / unrestricted  |
| tlp:green | 1       | Community-wide sharing |
| tlp:amber | 2       | Limited sharing        |
| tlp:red   | 3       | Named recipients only  |

Access is cumulative downward: a user granted tlp:green:read for an org sees that org’s tlp:green AND tlp:clear rows. A user granted tlp:red:read sees all levels.<sup>[\[b\]](#cmnt2)[\[c\]](#cmnt3)[\[d\]](#cmnt4)</sup>

### 1.2 Organizations

An organization represents a deployment owner or data-sharing partner (e.g. “ESnet”, “Internet2”, “GEANT”). Each MetrANOVA installation has a custodial organization<sup>[\[e\]](#cmnt5)[\[f\]](#cmnt6)[\[g\]](#cmnt7)[\[h\]](#cmnt8)[\[i\]](#cmnt9)</sup> that owns all data not explicitly assigned elsewhere.

|            |          |                                        |
|------------|----------|----------------------------------------|
| Field      | Type     | Description                            |
| id         | UUID     | Primary key                            |
| name       | String   | Human-readable name                    |
| slug       | String   | Lowercase identifier, used in policies |
| is_custodial | Bool   | Exactly one per installation; "custodial" — institutions manage each other's data, not "master" |
| created_at | DateTime |                                        |
| updated_at | DateTime |                                        |

### 1.3 Authorization Rules

Rules are configuration stored in `metranova_authz.rules` and consumed by the pipeline’s ingest-time rules engine (in the `metranova/pipeline` repo). The pipeline already implements rule matching — this table is the source of truth that drives it.

Each rule matches rows using `policy_originator_pattern` and `policy_scope_pattern`. A single rule can have two independent effects:

1. **Org-tagging effect** (`organization_id` set): stamps the org’s slug into `policy_organizations` (additive — all matching rules fire, slugs deduplicated).
2. **TLP-override effect** (`assigned_tlp` set): overrides the row’s `policy_level`. When multiple rules set `assigned_tlp`, the highest-priority rule wins.

A rule can have one effect, the other, or both. Every row has exactly one TLP level and zero or more org tags. Rows matching no rules receive only the custodial org slug at their original `policy_level`.

`priority` only matters for TLP override conflict resolution — it has no effect on which orgs get stamped.

> **Pending pipeline team coordination (see `stack-4nm`):** confirm that the existing pipeline rules engine is compatible with this two-effect model and the `policy_organizations` Array(String) column.

|  |  |  |
|----|----|----|
| Field | Type | Description |
| id | UUID | Primary key |
| organization_id | UUID | FK to organization — if set, stamps this org’s slug into `policy_organizations` |
| policy_originator_pattern | String | Glob/exact match on `policy_originator` |
| policy_scope_pattern | String | Glob/exact match on `policy_scope` array elements |
| assigned_tlp | Nullable(String) | If set, overrides the row’s `policy_level`; highest-priority wins when multiple rules match |
| priority | Int | Conflict resolution for `assigned_tlp` overrides only |
| description | String | Human-readable explanation |
| created_at | DateTime |  |

Note: `policy_scope` carries BGP community labels (e.g. lhcone, lsst) — it is distinct from `policy_organizations`. Rules match on `policy_scope`/`policy_originator` and write to `policy_organizations`.

### 1.4 Grants (principal-based, not user-based)

Grants are attached to **Keycloak group names** (principals), not individual users. Keycloak evaluates its own group assignment rules at login time — the wizard never manages individual user accounts. Any user Keycloak places in a group automatically inherits that group's grants.

ClickHouse enforces grants by checking `currentRoles()` — the set of CH roles the logged-in user holds, mapped from Keycloak groups via LDAP.

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| group_name | String | Keycloak group name (e.g. `authz-tlp-esnet-amber-read`) |
| organization_id | UUID | FK to organization |
| max_tlp_level | String | Highest TLP level for this permission |
| permission | String | `read` or `write` |
| granted_by | String | Admin who created this grant |
| granted_at | DateTime64(3) | |
| revoked_at | Nullable(DateTime64(3)) | null = active |

Access rules:

- A user can read (SELECT) a row if: **any** of the row's org tags (`policy_organizations`) matches a grant with `permission=read` for any of the user's current roles, AND the row's TLP level <= `max_tlp_level` for that grant
- A user can write (INSERT/UPDATE) a row if: same check with `permission=write`
- `write` does NOT imply `read` — both must be explicitly granted
- Rows with no matching rules are tagged with only the custodial org at `tlp:red` — only principals with a custodial-org `tlp:red` grant can access them

Example grants:

```
group_name: authz-tlp-esnet-amber-read      -> org: esnet,              tlp:amber, read
group_name: authz-tlp-esnet-green-write     -> org: esnet,              tlp:green, write
group_name: authz-tlp-geant-amber-read      -> org: geant,              tlp:amber, read
group_name: authz-tlp-geant-eng-amber-write -> org: geant-engineering,  tlp:amber, write
```

Keycloak decides which groups a user belongs to via its own mappers (e.g. Globus organization attribute, IdP claims). The wizard creates the groups in Keycloak and the grants in ClickHouse — it never touches individual user accounts.

### 1.5 Audit Log

Every authorization decision and administrative change is recorded:

|  |  |  |
|----|----|----|
| Field | Type | Description |
| timestamp | DateTime64(3) | Event time |
| event_type | String | grant_created, grant_revoked, rule_created, rule_modified, org_created, policy_violation, access_denied, test_run, test_result |
| actor | String | User who performed the action |
| target_user | String | User affected (if applicable) |
| organization | String | Org slug |
| details | String (JSON) | Full event payload |
| checksum | String | HMAC of the row for tamper detection |

------------------------------------------------------------------------

## 2. Storage

All authorization metadata lives in ClickHouse in a dedicated metranova_authz database, separate from the metranova data database:

- `organizations` — org definitions (fully qualified: `metranova_authz.organizations`)
- `rules` — row classification rules (`metranova_authz.rules`)
- `grants` — principal (Keycloak group) ↔ org ↔ TLP ↔ permission mappings (`metranova_authz.grants`)
- `audit_log` — append-only audit trail (`metranova_authz.audit_log`, MergeTree with no mutations allowed by policy)

> **Table naming decision:** Tables are named without the `authz_` prefix because the `metranova_authz` database already provides the namespace. `metranova_authz.organizations` is clearer than `metranova_authz.authz_organizations`.

ClickHouse Dictionaries will cache the authz tables in memory for row policy evaluation performance (avoid per-row JOINs on the hot path).

------------------------------------------------------------------------

## 3. ClickHouse Row Policy Enforcement

### 3.1 Row Policies

ClickHouse native CREATE ROW POLICY applied to the data_flow table. Two separate policies — one for SELECT, one for INSERT:

```sql
-- SELECT: user must have a read grant for at least one of the row's org tags
-- at or above the row's TLP level
CREATE ROW POLICY authz_read_policy ON metranova.data_flow
FOR SELECT
USING (
  hasAny(
    policy_organizations,
    dictGet('authz_group_read_orgs', 'org_slugs',
            (currentUser(), tlp_numeric(policy_level)))
  )
)
TO ALL EXCEPT pipeline, default;

-- INSERT: same check for write grants
CREATE ROW POLICY authz_write_policy ON metranova.data_flow
FOR INSERT
USING (
  hasAny(
    policy_organizations,
    dictGet('authz_group_write_orgs', 'org_slugs',
            (currentUser(), tlp_numeric(policy_level)))
  )
)
TO ALL EXCEPT pipeline, default;
```

`tlp_numeric()` maps tlp:clear→0, tlp:green→1, tlp:amber→2, tlp:red→3. The dictionary returns the set of orgs a user can access at *at least* that TLP level (cumulative downward).

Key design decisions:

- **`TO ALL EXCEPT` accepts roles as well as usernames.** LDAP-mapped roles work here. A user whose LDAP groups map to `clickhouse-admin` is exempt because the *role* is listed — no hardcoded usernames needed.
- **`clickhouse-admin` role is exempt.** A principal with DROP TABLE / DROP ROW POLICY can bypass row policies through other means anyway — enforcing TLP on them provides false security, not real security. Trust is enforced at the role-grant level (who gets `clickhouse-admin` at all), not via row policy.
- **Exempt list (keep minimal — every addition is a security bypass):**
  - `clickhouse-admin` role — DDL superusers, LDAP-mapped
  - `pipeline` username — ingest writer, stamps `policy_organizations` itself
  - `default` username — ClickHouse built-in superuser, init scripts only
- **External org service accounts are NOT exempt.** They must have entries in `authz_grants` and are subject to full TLP enforcement.
- **Grafana fallthrough user (`grafana`):** limited to `tlp:clear` only via a separate policy (not globally exempt). When Grafana proxies a real user’s identity, that user’s own policy applies instead.
- Policies use ClickHouse dictionaries for sub-millisecond lookups
- Deny-by-default: if no grant matches, the row is invisible / write is rejected

### 3.2 Dictionary Design

`dictGet` returns `Array(String)` values (keys must remain scalar). The dictionaries store the full set of orgs accessible at a given TLP level for each principal, enabling `hasAny()` in the row policy.

Row policies use `currentRoles()` — the set of CH roles the logged-in user holds — and union across all roles to build the full set of accessible orgs.

```
authz_group_read_orgs (complex key dictionary):
  key:   (group_name String, tlp_numeric Int8)
  value: org_slugs Array(String)
  source: SELECT group_name, tlp_numeric, groupArray(org_slug)
          FROM authz_grants JOIN authz_organizations
          WHERE permission = 'read' AND revoked_at IS NULL
          -- cumulative: key for tlp=1 includes orgs granted at 0 and 1
          GROUP BY group_name, tlp_numeric
  refresh: 30 seconds

authz_group_write_orgs (complex key dictionary):
  key:   (group_name String, tlp_numeric Int8)
  value: org_slugs Array(String)
  source: same shape, WHERE permission = 'write'
  refresh: 30 seconds
```

Row policy expression (SELECT):
```sql
USING hasAny(
    policy_organizations,
    arrayFlatten(arrayMap(
        r -> dictGetOrDefault('metranova_authz.authz_group_read_orgs', 'org_slugs',
                     (r, tlp_to_numeric(policy_level)), cast([], 'Array(String)')),
        currentRoles()
    ))
)
```

The `arrayMap` runs one dict lookup per role the user holds; `arrayFlatten` unions the results into a single array. `hasAny` then checks whether any of the row's org tags appear in that union.

Org tags are written directly to `policy_organizations` at ingest by the rules engine — no runtime per-row lookup needed.

⚠️ A revoked grant may allow up to ~30s of continued access (dict refresh interval).


### 3.3 Materialized Views

⚠️ Deferred to post-POC. MV row policy enforcement has significant performance implications. For the POC, row policies apply only to data_flow. All user-facing queries must go through data_flow. MVs are for internal/pipeline/admin use only.

Future decision needed: enforce at MV level directly, or create authorized VIEWs on top of MVs that apply the row policy filter (MVs stay fast, views add security).

### 3.4 Cross-Instance Queries

MetrANOVA instances don’t re-ingest each other’s data — they query each other using federated identity credentials via the clickhouse-auth-proxy + token-store + cross-instance OIDC client. The remote instance’s own row policies enforce access, using the querying user’s identity. This system is explicitly designed to resolve cross-instance data access consideration.

------------------------------------------------------------------------

## 4. Keycloak / LDAP / ClickHouse Synchronization

**Keycloak is the source of truth for group membership. LDAP is a subordinate copy.**
Keycloak syncs group changes to LDAP automatically. The wizard writes directly to both
Keycloak (via Admin API) and ClickHouse — no sync daemon is required for initial setup
or incremental updates.

### 4.1 Sync Flow

```
auth_wizard.py (run from outside cluster, kubectl port-forward for access)
    |
    +-> Keycloak Admin API
    |     create group authz-tlp-{org}-{level}-{read|write}
    |     configure group mappers (Globus attribute -> group assignment)
    |     Keycloak auto-syncs groups to LDAP (subordinate copy)
    |
    +-> ClickHouse (via clickhouse-client port-forward)
    |     INSERT INTO metranova_authz.grants (principal, organization_id, ...)
    |     Dictionaries auto-refresh every 30s -> row policies enforce
    |
    (pipeline reads metranova_authz.rules async at next row ingest — no wizard action)
```

No long-running sync daemon is needed. The wizard is idempotent and can be re-run to
make incremental changes after initial setup.

### 4.2 Keycloak Group Structure

Keycloak groups created per org/TLP/permission combination:

```
authz-tlp-{org_slug}-clear-read
authz-tlp-{org_slug}-green-read
authz-tlp-{org_slug}-green-write
authz-tlp-{org_slug}-amber-read
authz-tlp-{org_slug}-amber-write
authz-tlp-{org_slug}-red-read
authz-tlp-{org_slug}-red-write
```

Keycloak group mappers (configured per IdP / realm) assign users to these groups based
on attributes from Globus or other IdPs (e.g. organization claim, role claim). The wizard
creates the groups and a default mapper template; administrators configure the specific
attribute matching rules in the Keycloak UI.

### 4.3 LDAP (subordinate copy)

Keycloak syncs groups to LDAP automatically. LDAP groups follow the same naming pattern:

```
cn=authz-tlp-esnet-clear-read,ou=groups,dc=metranova,dc=io
cn=authz-tlp-esnet-green-read,ou=groups,dc=metranova,dc=io
...
```

ClickHouse maps LDAP groups to CH roles via its LDAP user directory config (already in
place). New authz groups are automatically picked up — no ClickHouse config change needed
when a new grant is added.

------------------------------------------------------------------------

## 5. CLI Tool — metranova-authz

### 5.1 Overview

Python TUI application using python-dialog (the standard FreeBSD/Debian installer dialog interface). Lives in the metranova/auth repo. Can also be run non-interactively for scripted/CI use.

### 5.2 TUI Menu Structure

┌───────────────────────────┐

│ MetrANOVA Authorization Setup │

│ │

│ 1. Organizations │

│ 2. Classification Rules │

│ 3. User Access Grants │

│ 4. Audit & Reports │

│ 5. Test Battery │

│ 6. Export/Import Configuration │

│ 7. Exit │

└───────────────────────────┘

1. Organizations: - List / Create / Edit / Delete organizations - Set custodial organization - View members

2\. Classification Rules: - List / Create / Edit / Delete rules - Preview: “show me which rows this rule would match” (runs a COUNT query) - Validate: check for gaps (rows matching no rule → flagged)

3\. User Access Grants: - List users and their grants (showing read and write separately) - Grant / Revoke org+TLP+permission for a user - Bulk assign (e.g. “all users in LDAP group X get org Y at TLP Green read+write”)

4\. Audit & Reports: - View audit log (filterable by time, user, event type) - Generate compliance report (who has access to what) - Show policy violations / access denials

5\. Test Battery: - Run the full authorization test suite against the live system - Verify each user can see/write exactly what they should and nothing more - Results written to audit log

6\. Export/Import: - Export full authz config to YAML (for backup, migration, version control) - Import from YAML (for restore, replication to new instance)

### 5.3 Non-Interactive Mode

Every TUI operation has a CLI equivalent:

```bash
# Organizations
metranova-authz org create --name "ESnet" --slug esnet --custodial
metranova-authz org list

# Classification rules (pipeline reads async at next ingest)
metranova-authz rule create --org esnet \
  --originator-pattern "esnet-*" \
  --scope-pattern "*" \
  --priority 100

# Grants: principal is a Keycloak group name, not a username
metranova-authz grant create --group authz-tlp-esnet-amber-read \
  --org esnet --tlp-level amber --permission read
metranova-authz grant create --group authz-tlp-esnet-green-write \
  --org esnet --tlp-level green --permission write
metranova-authz grant list

# Audit
metranova-authz test run --verbose
metranova-authz audit report --from 2026-01-01 --to 2026-09-09
```

------------------------------------------------------------------------

## 6. Auditing System

### 6.1 Audit Coverage

Every operation is logged: - Admin actions: org CRUD, rule CRUD, grant CRUD, config import/export - Access decisions: policy violations, access denials (logged by ClickHouse query log + row policy evaluation) - Test results: every test battery run with pass/fail per assertion - System events: sync daemon start/stop, dictionary refresh, policy reload

### 6.2 Tamper Detection

Each audit log row includes an HMAC checksum computed over the row’s contents using a key stored outside ClickHouse (in the service’s environment). A verification query can detect any rows that have been modified:

metranova-authz audit verify --from 2026-01-01

\# Checks HMAC on every audit row, reports any mismatches

### 6.3 Compliance Reports

metranova-authz audit report --format html \> access-report.html

Generates: - Current state: all orgs, rules, grants (read and write shown separately) - Access matrix: user × org × TLP level × permission - Timeline: changes over the reporting period - Anomalies: access denials, policy violations, failed tests

------------------------------------------------------------------------

## 7. Testing Strategy

### 7.1 Unit Tests (in metranova/auth repo)

- Rule matching logic (pattern matching, priority resolution, default-to-master)
- TLP hierarchy (cumulative access, boundary conditions)
- Grant resolution (user × org × TLP × permission → visible/writable/denied)
- Read vs write independence (write grant without read → can insert but not select)
- Audit log HMAC computation and verification
- LDAP group name generation (including read/write suffix)
- CLI argument parsing

### 7.2 Integration Tests

- ClickHouse row policy enforcement for SELECT: create test users, insert test rows at various TLP levels and orgs, verify each user sees exactly their authorized rows
- ClickHouse row policy enforcement for INSERT: verify users can only insert rows at their authorized write TLP level
- Read/write independence: user with read-only grant cannot insert; user with write-only grant cannot select
- Dictionary refresh: modify a grant, verify the row policy reflects the change within 30s
- LDAP sync: create a grant, verify the corresponding LDAP group is created with the correct read/write suffix
- Keycloak sync: verify Keycloak groups mirror LDAP
- Grafana fallthrough: verify grafana user can only see tlp:clear rows
- Audit log integrity: perform operations, verify audit trail is complete and HMACs validate

### 7.3 Adversarial Tests

Given the threat model (possible nation-state actor intrusion), these are mandatory:

- Policy bypass attempts: Direct ClickHouse connections (bypassing Envoy) with various user types — verify row policies still enforce
- Privilege escalation: User with tlp:green:read attempts to query tlp:amber data via SQL injection in WHERE clauses, subqueries, UNION, CTEs
- Write escalation: User with tlp:green:write attempts to insert rows tagged tlp:amber
- Read-write confusion: User with write-only grant attempts SELECT; user with read-only grant attempts INSERT
- Dictionary cache poisoning: Verify dictionaries are read-only from the authz tables and cannot be manipulated via user queries
- Audit log tampering: Verify mutations on the audit table are blocked by ClickHouse settings, verify HMAC detects any out-of-band modification
- Service account abuse: Verify the pipeline user exemption cannot be exploited (pipeline user should only be reachable from internal network)
- Grafana fallthrough abuse: Verify the grafana user cannot see anything above tlp:clear
- TOCTOU: Verify that revoking a grant takes effect within the dictionary refresh window and cannot be raced

### 7.4 Test Battery (Runtime)

The metranova-authz test run command executes against the live system:

1.  Creates a temporary test organization and test users
2.  Inserts test rows at each TLP level
3.  Grants various read/write combinations to test users
4.  Verifies each test user can SELECT exactly their authorized rows
5.  Verifies each test user can INSERT only at their authorized write levels
6.  Attempts unauthorized read and write access, verifies denial
7.  Verifies audit log captured all access attempts
8.  Cleans up test data
9.  Results: pass/fail per assertion, written to audit log

------------------------------------------------------------------------

## 8. Implementation Plan (high-level phases)

### Phase 1: Core Data Model + Row Policies

- Create metranova_authz database and tables in ClickHouse
- Implement row classification rules engine
- Create ClickHouse dictionaries (separate read/write) and row policies (SELECT + INSERT)
- Grafana fallthrough user limited to tlp:clear
- Unit tests for rule matching, TLP hierarchy, read/write independence

### Phase 2: CLI Tool

- Python TUI with python-dialog
- Non-interactive CLI mode
- Org, rule, and grant CRUD (with read/write permission support)
- Export/import

### Phase 3: Sync Daemon

- New authz-sync service in metranova/auth
- ClickHouse → LDAP group sync (with read/write group suffixes)
- ClickHouse → Keycloak group sync
- Row policy and dictionary lifecycle management

### Phase 4: Auditing

- Audit log table with HMAC
- Compliance report generation (showing read/write grants separately)
- Audit verification tool

### Phase 5: Testing & Hardening

- Full unit test suite
- Integration test suite (read and write policies)
- Adversarial test suite (read/write escalation attacks)
- Runtime test battery
- Security review

### Phase 6: Integration

- Docker Compose entries for new services
- Helm chart updates
- sync-secrets.sh updates for new secrets
- Documentation

------------------------------------------------------------------------

## 9. Decision Log

| Decision | Resolution |
|----------|-----------|
| TLP hierarchy | Cumulative downward (Green = Green + Clear) |
| Storage backend | ClickHouse (dedicated `metranova_authz` database) |
| Code location | `metranova/auth` repo (alongside existing auth services) |
| CLI language | Python with `python-dialog` TUI |
| Audit storage | ClickHouse (dedicated audit table with HMAC tamper detection) |
| Row tagging | Single TLP level per row (`policy_level`); multiple org tags per row (`policy_organizations Array(String)`, stamped at ingest) |
| Multi-org access check | `hasAny(policy_organizations, union_of_orgs_from_currentRoles())` |
| Grants are group-based | Grants attach to Keycloak group names (`group_name`), not usernames. Keycloak decides group membership via mappers. |
| Identity authority | Keycloak is source of truth; LDAP is a subordinate copy. Keycloak auto-syncs to LDAP. |
| No sync daemon | `auth_wizard.py` writes directly to Keycloak Admin API + ClickHouse. No long-running daemon needed for setup or incremental updates. |
| Row policy enforcement | `currentRoles()` + `arrayMap` over `authz_group_read_orgs` / `authz_group_write_orgs` dictionaries |
| `clickhouse-admin` exemption | DDL superusers exempt from row policies by role name (not username). Enforcing TLP on them is false security — they can DROP ROW POLICY anyway. |
| Cross-instance | Not applicable — instances query each other via federated ID, remote policies enforce |
| Dictionary refresh | 30 seconds (acceptable for grant revocation latency) |
| Grafana access | User-identity passthrough; `grafana` service account limited to `tlp:clear` via separate policy |
| MV enforcement | Deferred post-POC |
| Read/write | Independent grants per TLP level: `tlp:X:read` and `tlp:X:write` are separate |
| Issue tracking | `bd` (beads) — Dolt-backed local issue tracker |

------------------------------------------------------------------------


## 10. Future Work (post-POC)

- Materialized view row policy enforcement (performance implications TBD)
- Row policy on metadata tables (meta_device, meta_interface, etc.) if needed
- Fine-grained policy_scope access (user can see lhcone scope but not fabric)
- API endpoint for programmatic authz management (REST/gRPC)
- Integration with external identity governance systems (if required by deployment sites)

[\[a\]](#cmnt_ref1)The most critical piece of feedback in reviewing this document: Any given datum will have exactly one TLP level. The datum can be tagged with any number of organization tags -- but the user must have \*at least one\* \[Org:TLP-level\] pair that meets or exceeds the tagged TLP level of the datum.

[\[b\]](#cmnt_ref2)is a user set to a tlp level? I thought they were granted access based on the content of rules and mapping those to user groups that the user was a part of?

[\[c\]](#cmnt_ref3)Good question. I don't think users would be assigned a TLP level (those are for data) they're assigned effective permissions for TLP level for a specific org:

\`ESnet::tlp:amber:read\` is a good example. it's an effective permission level for a specific org

[\[d\]](#cmnt_ref4)ah yes ok I think the correct way to state this is "a user grapnted tlp:red:read on a set of flow data sees all applicable data ie if a user is granted tlp:red for one specific flow tuple then given no other access its not that he or she can ever see anything else.

[\[e\]](#cmnt_ref5)imagine a case where ESnet wants to grant geant backbone engineers TLP:amber access to only flow data coming from LHC ports, otherwise TLP Green for all other ports and TLP:clear for snmp stats? but general geant engineers Id only want to grant TLP:clear?

[\[f\]](#cmnt_ref6)See my commentary above (Geant-Engineering organization as a separately authorization-granted organization)

[\[g\]](#cmnt_ref7)Worth pointing out that the "custodial organization" will differ per installation. At e.g. Geant's installation, Geant is the custodial organization; at I2's installation, I2 is the custodial organization etc... maybe this should be a different term "install organization," "owner organization," "operator organization," "custodial organization?"

[\[h\]](#cmnt_ref8)likely and I guess the key for me is permissions classes need to be based on some grouping that is smaller than org scoped often.

[\[i\]](#cmnt_ref9)That's really good feedback, after significant thought on this -- we should model the group-within-org as a separate organization, and grant access to users with the separate organization. For instance, Geant has an Engineering group. We can grant a specific permission level to users at Geant in the geant organization, and engineering-specific users in the geant-engineering organization.

[\[j\]](#cmnt_ref10)I'm maybe a bit confused here. I see the jsmith @ geant and @ esnet... is this just saying if jsmith logs in via the geant org he only sees tlp:clear with read but if he logged in with esnet he gets the amber read and green write?

I guess I originally interpreted this as an org got permissions and those were inherited to the user, but looking now it's not what my brain interpreted.

[\[k\]](#cmnt_ref11)Two issues:

\- the scenario as written didn't make a ton of sense. I rewrote it to be more realistic

more realistic scenario:

\- Let's imagine ESnet is the custodian for some data that we attribute to Geant that don't want ESnet folks in general to see.

\- ESnet stores the sensitive data we attribute to Geant as \`Geant::tlp:amber\`

\- John Smith is a user at ESnet who has access to both ESnet's tlp amber data, and for they sake of argument they're also a contractor at Geant, so they also have access to Geant's tlp amber data.

\- ESnet here grants permission \`Geant::tlp:amber:read\` to John Smith.

\- Now, John can see sensitive records (at tlp:amber level) for Geant, stored by ESnet.

Note that this is one user login, with access to two organizations' data inside of a single metranova installation.

[\[l\]](#cmnt_ref12)Above, I mention that the records are stored by ESnet. The entire scenario here is local to ESnet's cluster. This is important to disambiguate from the situation where Geant is holding records that John Smith should have access to. Geant would separately need to grant that permission on their totally separate metranova installation

[\[m\]](#cmnt_ref13)I added another example row that also begins to address Ed's commentary from above, I think that this is probably the simplest/most correct solution for the circumstance where we want to implement a group-with-an-org that has a different privilege level. I would suggest that keeping it simple with having a second virtual org for the group and being able to assign a different level of TLP access to that group is a better design than having group-level-specific permissions. If we go down the groups-level-specific permissions path, we've created irretrevable complexity that involves having to resolve nested "specificity levels" that compete with each other (does a group override an org? can a group exist outside of an org, etc) This keeps the model clear and simple: we have exactly two abstractions: orgs and tlp levels, orgs can represent a variety of "layers" of abstraction, and because we can multi-tag rows with Org/TLP pairs, we should be good to go here.
