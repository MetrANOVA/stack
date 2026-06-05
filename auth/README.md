# MetrANOVA Auth

OIDC-based authentication and authorization for the MetrANOVA stack.

**Components:**
- **Keycloak** — OIDC identity provider, realm `metranova`
- **Envoy** — trust boundary proxy; TLS termination, OAuth2 browser login, JWT validation
- **OpenLDAP** — group store for ClickHouse row-level access control
- **keycloak-ldap-sync** — mirrors Keycloak group membership into OpenLDAP
- **portal** — post-login landing page; surfaces user info and ClickHouse credentials

## Quick Start

```bash
# 1. Generate configs and secrets
make docker

# 2. Start the stack and sync secrets into Keycloak
#    (prompts for any required values not yet configured, then waits for
#    Keycloak to be ready and pushes client secrets and LDAP credentials)
make sync

# 3. Browse https://localhost:8443/ — you'll be redirected to Keycloak login
```

That's it. Re-run `make sync` any time you rotate a secret or restart the stack.

## Default Credentials

| User | Password | Role |
|---|---|---|
| admin1 | admin123 | admin |
| operator1 | operator123 | operator |
| viewer1 | viewer123 | viewer |

Keycloak admin UI: `http://localhost:8180` — admin / (see `auth/conf/keycloak.env` after `make docker`)

## Configuration

All runtime config lives in `auth/conf/` (gitignored, generated from `conf.example/`):

| File | Purpose |
|---|---|
| `auth.env` | Domain and realm name |
| `keycloak.env` | Keycloak admin credentials, LDAP connection for the nonce SPI |
| `envoy.env` | Envoy client/HMAC secrets (auto-generated) |
| `envoy/envoy.yaml` | Rendered Envoy config |
| `tls/server.{crt,key}` | Self-signed TLS cert (auto-generated) |
| `secrets/token.yaml` | Envoy SDS client secret |
| `secrets/hmac.yaml` | Envoy SDS HMAC secret |
| `keycloak/metranova-realm.json` | Full realm export (see below) |

## Envoy Routes

| Path | Destination | Auth |
|---|---|---|
| `/health` | direct 200 | none |
| `/grafana/` | grafana:3000 | OAuth2 passthrough (Grafana handles OIDC) |
| `/clickhouse` | clickhouse:8123 | OAuth2 + JWT; sets `X-ClickHouse-User` |
| `/token-store/api` | token-store:8000 | JWT |
| `/` | portal:8000 | OAuth2 |

## Realm Configuration

Keycloak realm config — clients, identity providers, group mappers, protocol mappers — is
managed as a **realm export artifact** rather than through manual UI clicks. This makes
deployments reproducible and reviewable.

### How it works

On startup, Keycloak imports `auth/conf/keycloak/metranova-realm.json` via `--import-realm`.
This file is a full realm export produced by `auth/scripts/export-realm.sh`, which uses
Keycloak's partial-export endpoint. Unlike the standard Admin API realm representation,
partial-export includes identity providers and IdP mappers — everything needed to fully
reconstruct the realm.

### Operator workflow

**First deployment:**
1. Start the stack — Keycloak imports the base realm from `conf.example/keycloak/metranova-realm.json`
2. Configure your identity provider(s) via the Keycloak admin UI (`http://localhost:8180`)
3. Export the configured realm:
   ```bash
   ./auth/scripts/export-realm.sh
   ```
4. Commit `auth/conf.example/keycloak/metranova-realm.json` with secrets redacted (replace real
   client secrets with `CHANGEME`). The live copy in `auth/conf/` is gitignored.

**Subsequent config changes:**
Make changes in the Keycloak UI, then re-run `export-realm.sh` and commit the updated export.

**Fresh deployment from the repo:**
1. `make docker` — copies `conf.example/` to `conf/` and generates all secrets
2. `make sync` — starts the stack, prompts for any remaining required values (hostname, LDAP domain, IdP credentials), waits for Keycloak, and pushes secrets in

Re-run `make sync` any time you rotate a secret or restart the stack.

### Dev vs. production persistence

| | Dev (default) | Production |
|---|---|---|
| Database | H2 (embedded, ephemeral) | PostgreSQL (external, persistent) |
| Persistence | Lost on container rebuild | Survives restarts and upgrades |
| Import behavior | Re-imports on every re-augmentation | Imports once on first boot; skips if realm exists |
| Recommendation | Accept reconfigure-after-rebuild; use export script frequently | Set `KC_DB=postgres` and point at your PostgreSQL instance |

In production, use Keycloak's `start` mode (not `start-dev`) with PostgreSQL. The realm export
still serves as the initial seed and as a backup/migration artifact — but day-to-day changes
persist in the database rather than requiring a re-export and redeploy.

### What's in the export

The partial-export includes:
- Clients and their protocol mappers (including the `ch_password` nonce mapper)
- Identity providers and their attribute mappers
- Groups and roles
- Authentication flows

It does **not** include users — those are managed via LDAP federation and created on first login.

## ClickHouse Credentials

ClickHouse authenticates users via LDAP. Each user's password is a per-session nonce generated
by the `keycloak-ch-nonce-mapper` Keycloak SPI at login time, written atomically to OpenLDAP,
and displayed on the portal homepage. The nonce is stable for the lifetime of the Keycloak
session and rotates on next login.

Users connect to ClickHouse using:
- **Username:** their Keycloak username (e.g. `jkafader@es.net`)
- **Password:** the `ch_password` shown on the portal homepage

## Reset

```bash
python docker/build.py --clean   # removes auth/conf/
make docker                       # re-bootstraps with fresh secrets
```
