# Kafka (Docker Compose)

This folder provides a single-node Kafka setup (KRaft mode) with TLS and SASL/PLAIN authentication. The stack generates self-signed certificates on first run and bootstraps topics from a config file.

## Quick start

```bash
cp -r kafka/conf.example/ kafka/conf/

docker compose -f kafka/docker-compose.yml up -d
```

Kafka listens on:
- Internal: `kafka:9093` (SASL_SSL)
- External: `localhost:9094` (SASL_SSL)

## Authentication

Users are defined in [conf/kafka.env](conf/kafka.env).

Example:
```
KAFKA_LISTENER_NAME_INTERNAL_PLAIN_SASL_JAAS_CONFIG=org.apache.kafka.common.security.plain.PlainLoginModule required user_admin="admin-secret" user_app="app-secret";
KAFKA_LISTENER_NAME_EXTERNAL_PLAIN_SASL_JAAS_CONFIG=org.apache.kafka.common.security.plain.PlainLoginModule required user_admin="admin-secret" user_app="app-secret";
KAFKA_SUPER_USERS=User:admin
```

The client config is generated automatically from [conf/kafka.env](conf/kafka.env).

## TLS certificates

Self-signed certificates are generated automatically and stored in the `kafka-secrets` Docker volume.
The KRaft cluster id is also generated once and stored in the same volume.

To regenerate certificates:
```bash
docker compose -f kafka/docker-compose.yml down

docker volume rm metranova-stack_kafka-secrets

docker compose -f kafka/docker-compose.yml up -d
```

If the DNS name must change, set `KAFKA_SSL_DNS_NAME` before starting.

## Topics

Topics are defined in [conf/topics.env](conf/topics.env) as a comma-separated list:
```
TOPICS=example.events:3:604800000,example.metrics:1:86400000
```

Format: `name:partitions:retention_ms`

To apply topic changes:
```bash
docker compose -f kafka/docker-compose.yml up -d kafka-topics
```

## Example client

Use `kafka:9093` from within the Docker network or `localhost:9094` from your host.

```bash
kafka-topics.sh --list \
  --bootstrap-server localhost:9094 \
  --command-config kafka/conf/client.properties
```

## Notes

- Auto topic creation is disabled.
- Replication factor is set to 1 for single-node operation.
