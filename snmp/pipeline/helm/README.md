# MetrANOVA SNMP Pipeline Helm Chart

This Helm chart deploys the MetrANOVA SNMP Pipeline on a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PV provisioner support in the underlying infrastructure (if using persistent volumes)

## Components

This chart deploys three main components:

1. **data-snmp**: Processes SNMP data from Kafka and writes to ClickHouse
2. **metadata-caida-org-as**: Manages AS and Organization metadata from CAIDA
3. **metadata-file-export**: Exports metadata from configuration files to ClickHouse

## Installing the Chart

### Basic Installation

```bash
helm install metranova-snmp ./helm
```

### Installation with Custom Values

```bash
helm install metranova-snmp ./helm -f custom-values.yaml
```

### Installation with Inline Values

```bash
helm install metranova-snmp ./helm \
  --set config.clickhouse.password=mypassword \
  --set config.kafka.ssl.keyPassword=mykafkapassword
```

## Configuration

The following table lists the configurable parameters of the chart and their default values.

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/metranova/pipeline` |
| `image.tag` | Container image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `global.imagePullSecrets` | Image pull secrets | `[]` |

### Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `dataSnmp.enabled` | Enable data SNMP service | `true` |
| `dataSnmp.replicaCount` | Number of replicas for data SNMP | `1` |
| `metadataCaidaOrgAs.enabled` | Enable CAIDA metadata service | `true` |
| `metadataFileExport.enabled` | Enable file export metadata service | `true` |

### Base Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.debug` | Enable debug logging | `false` |
| `config.kafka.bootstrapServers` | Kafka bootstrap servers | `kafka:9092` |
| `config.kafka.consumerGroup` | Kafka consumer group | `metranova_pipeline` |
| `config.kafka.ssl.keyPassword` | Kafka SSL key password | `CHANGEME` |
| `config.clickhouse.host` | ClickHouse host | `clickhouse` |
| `config.clickhouse.port` | ClickHouse port | `9440` |
| `config.clickhouse.database` | ClickHouse database | `metranova` |
| `config.clickhouse.username` | ClickHouse username | `pipeline_user` |
| `config.clickhouse.password` | ClickHouse password | `CHANGEME` |
| `config.redis.host` | Redis host | `redis` |
| `config.redis.port` | Redis port | `6379` |

### Storage

| Parameter | Description | Default |
|-----------|-------------|---------|
| `caches.existingPvc` | Use existing PVC for caches | `""` |
| `caches.storageSize` | Storage size for caches PVC | `1Gi` |
| `caches.storageClassName` | Storage class for caches PVC | `""` |

### Certificates

| Parameter | Description | Default |
|-----------|-------------|---------|
| `certificates.existingSecret` | Use existing secret for certificates | `""` |
| `certificates.kafka.ca` | Kafka CA certificate (base64) | `""` |
| `certificates.kafka.cert` | Kafka client certificate (base64) | `""` |
| `certificates.kafka.key` | Kafka client key (base64) | `""` |

## Usage Examples

### Using Existing Secrets and ConfigMaps

```yaml
# values-production.yaml
certificates:
  existingSecret: my-kafka-certs

configFiles:
  existingConfigMap: my-pipeline-config

caches:
  existingPvc: my-cache-pvc

config:
  clickhouse:
    password: changeme_secure_password
  kafka:
    ssl:
      keyPassword: changeme_secure_kafka_password
```

```bash
helm install metranova-snmp ./helm -f values-production.yaml
```

### Providing Certificates Directly

```yaml
# values-with-certs.yaml
certificates:
  kafka:
    ca: |
      LS0tLS1CRUdJTi... (base64 encoded CA cert)
    cert: |
      LS0tLS1CRUdJTi... (base64 encoded client cert)
    key: |
      LS0tLS1CRUdJTi... (base64 encoded client key)
```

### Scaling Replicas

```bash
helm upgrade metranova-snmp ./helm \
  --set dataSnmp.replicaCount=3
```

### Setting Resource Limits

```yaml
# values-resources.yaml
dataSnmp:
  resources:
    limits:
      cpu: 2000m
      memory: 2Gi
    requests:
      cpu: 1000m
      memory: 1Gi
```

## Uninstalling the Chart

```bash
helm uninstall metranova-snmp
```

This removes all the Kubernetes components associated with the chart and deletes the release.

## Notes

- Make sure to update the `CHANGEME` passwords in production deployments
- The chart uses a ReadWriteMany PVC for caches to allow multiple pods to access the same cache data
- Certificate files should be provided either through an existing secret or inline in values
- Configuration files (meta_*.yml) should be provided through ConfigMap
