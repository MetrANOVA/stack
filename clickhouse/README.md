# ClickHouse (Docker Compose)

This folder provides a single-node ClickHouse setup with TLS enabled. Configuration is driven by environment variables in `conf/clickhouse.env` and generated config files under `conf/`.

## Quick start

```bash
cp -r clickhouse/conf.example/ clickhouse/conf/
docker compose -f clickhouse/docker-compose.yml up -d
```

## Authentication

The init container generates random passwords for the default user plus `pipeline` and `grafana` users if they are unset or still placeholders.
Passwords are stored in [conf/clickhouse.env](conf/clickhouse.env).

View generated passwords:

```bash
grep '^CH_DEFAULT_PASSWORD=' clickhouse/conf/clickhouse.env
grep '^CH_PIPELINE_PASSWORD=' clickhouse/conf/clickhouse.env
grep '^CH_GRAFANA_PASSWORD=' clickhouse/conf/clickhouse.env
```

The `pipeline` user has read/write access and the `grafana` user has read-only access to the database in `CH_DATABASE` (defaults to `metranova`).

## TLS

Self-signed certificates are generated automatically and stored in a Docker volume. Non-TLS ports are disabled by default. TLS ports are enabled:

- HTTPS: 8443
- Native TLS: 9440

If you need different ports or want to enable non-TLS ports, update `CH_HTTPS_PORT`, `CH_TCP_SECURE_PORT`, `CH_HTTP_PORT`, or `CH_TCP_PORT` in [conf/clickhouse.env](conf/clickhouse.env).

If your Docker environment does not support IPv6 (common on macOS), set `CH_LISTEN_HOSTS=0.0.0.0` to avoid using `::`.
If your host is IPv6-only, set `CH_LISTEN_HOSTS=::` and connect using the container DNS name (for example, `CH_HOST=clickhouse`) or an IPv6 address.

## Connecting

Use the helper script to run `clickhouse-client` inside the container:

```bash
./clickhouse/scripts/clickhouse-client.sh
```

Example query:

```bash
./clickhouse/scripts/clickhouse-client.sh --query "SELECT 1"
```

Override the default connection values by setting:

```bash
CH_USER=default CH_PASSWORD=your_password CH_PORT=9440 CH_HOST=localhost \
  ./clickhouse/scripts/clickhouse-client.sh --query "SELECT version()"
```

## Notes

- The database in `CH_DATABASE` is created automatically at startup if missing.
- No table creation is performed by this setup.
- Data is persisted in a Docker volume.
