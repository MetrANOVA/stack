# MetrANOVA Flow Pipeline Helm Chart

This Helm chart deploys the MetrANOVA Flow Pipeline on a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PV provisioner support in the underlying infrastructure (if using persistent volumes)

## Components

This chart deploys six main components:

1. **data-flow**: Processes NetFlow/IPFIX data from Kafka and writes to ClickHouse
2. **metadata-caida-org-as**: Manages AS and Organization metadata from CAIDA
3. **metadata-file-export**: Exports metadata from configuration files to ClickHouse
4. **metadata-ip-geo**: Manages IP geolocation metadata from MaxMind GeoLite2
5. **metadata-scireg**: Manages Science Registry metadata from external sources
6. **cache-ip-trie**: Maintains IP prefix trie cache in Redis for fast lookups

## Installing the Chart

### Basic Installation

```bash
helm install metranova-flow ./helm
```

### Installation with Custom Values

```bash
helm install metranova-flow ./helm -f custom-values.yaml
```

### Installation with Inline Values

```bash
helm install metranova-flow ./helm \
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
| `dataFlow.enabled` | Enable data flow service | `true` |
| `dataFlow.replicaCount` | Number of replicas for data flow | `1` |
| `metadataCaidaOrgAs.enabled` | Enable CAIDA metadata service | `true` |
| `metadataFileExport.enabled` | Enable file export metadata service | `true` |
| `metadataIpGeo.enabled` | Enable IP geo metadata service | `true` |
| `metadataScireg.enabled` | Enable SciReg metadata service | `true` |
| `cacheIpTrie.enabled` | Enable IP trie cache service | `true` |

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
| `caches.storageSize` | Storage size for caches PVC | `5Gi` |
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
helm install metranova-flow ./helm -f values-production.yaml
```

### Scaling Replicas

```bash
helm upgrade metranova-flow ./helm \
  --set dataFlow.replicaCount=3
```

### Disabling Optional Services

```bash
helm install metranova-flow ./helm \
  --set metadataScireg.enabled=false \
  --set cacheIpTrie.enabled=false
```

## Uninstalling the Chart

```bash
helm uninstall metranova-flow
```

This removes all the Kubernetes components associated with the chart and deletes the release.

## Notes

- Make sure to update the `CHANGEME` passwords in production deployments
- The chart uses a ReadWriteMany PVC for caches to allow multiple pods to access the same cache data
- Certificate files should be provided either through an existing secret or inline in values
- Configuration files (meta_*.yml) should be provided through ConfigMap
- GeoLite2 CSV files must be present in the caches directory before deploying
- Redis is expected to be available (can use external Redis or deploy separately)
