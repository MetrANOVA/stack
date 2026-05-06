# MetraNova Umbrella Chart

This chart installs the MetraNova stack using one Helm release by including the
existing charts in this repository as dependencies:

- `clickhouse`
- `kafka`
- `telegraf`
- `metranova-snmp-pipeline`
- `metranova-flow-pipeline`
- `grafana`

## Layout

The chart is in `charts/metranova` and references local dependency charts:

- `file://../clickhouse`
- `file://../kafka`
- `file://../telegraf`
- `file://../snmp-pipeline`
- `file://../flow-pipeline`
- `https://grafana.github.io/helm-charts`

## Build Dependencies

From the repository root:

```bash
helm dependency build charts/metranova
```

This creates `charts/metranova/charts/*.tgz`.

## Operator Prerequisites

This umbrella chart assumes the following operators are already installed,
healthy, and configured to watch your target deployment namespace:

- Altinity ClickHouse Operator
- Strimzi Kafka Operator

If either operator is not installed or not watching the target namespace,
ClickHouse/Kafka custom resources may render in Argo but not reconcile
correctly.

## Install

```bash
helm install metranova charts/metranova -n metranova --create-namespace
```

## Upgrade

```bash
helm upgrade metranova charts/metranova -n metranova
```

## Configure Components

All component values are under top-level keys in
`charts/metranova/values.yaml`:

- `clickhouse.*`
- `kafka.*`
- `telegraf.*`
- `snmpPipeline.*`
- `flowPipeline.*`
- `grafana.*`

Each component can be toggled on/off with:

- `clickhouse.enabled`
- `kafka.enabled`
- `telegraf.enabled`
- `snmpPipeline.enabled`
- `flowPipeline.enabled`
- `grafana.enabled`

The umbrella chart now mirrors the full values trees for both pipeline
subcharts under:

- `snmpPipeline.*`
- `flowPipeline.*`

Examples:

- `snmpPipeline.config.clickhouse.batchSize`
- `snmpPipeline.config.clickhouse.batchTimeout`
- `flowPipeline.config.clickhouse.batchSize`
- `flowPipeline.config.clickhouse.batchTimeout`

## Global Storage Class

You can set one storage class for the entire stack and let component-specific
settings override it only when needed.

Set in `charts/metranova/values.yaml`:

```yaml
global:
	storageClassName: your-default-storage-class
```

Fallback behavior:

- component-specific storage class (if set)
- `global.storageClassName` (if set)
- cluster default storage class (if neither is set)

## Workload Scheduling And Resources

Deployments/stateful workloads can be tuned from `values.yaml`:

- `telegraf.resources`, `telegraf.tolerations`, `telegraf.affinity`
- `telegraf.topologySpreadConstraints`
- `snmpPipeline.dataSnmp.replicaCount`, `snmpPipeline.metadataCaidaOrgAs.replicaCount`, `snmpPipeline.metadataFileExport.replicaCount`
- `snmpPipeline.*.resources` (per component), `snmpPipeline.tolerations`, `snmpPipeline.affinity`, `snmpPipeline.topologySpreadConstraints`
- `flowPipeline.dataFlow.replicaCount`, `flowPipeline.metadataCaidaOrgAs.replicaCount`, `flowPipeline.metadataFileExport.replicaCount`, `flowPipeline.metadataIpGeo.replicaCount`, `flowPipeline.metadataScireg.replicaCount`, `flowPipeline.metadataCric.replicaCount`, `flowPipeline.cacheIpTrie.replicaCount`
- `flowPipeline.*.resources` (per component), `flowPipeline.tolerations`, `flowPipeline.affinity`, `flowPipeline.topologySpreadConstraints`
- `kafka.kafka.resources|tolerations|affinity|topologySpreadConstraints`
- `kafka.kraft.resources|tolerations|affinity|topologySpreadConstraints`
- `kafka.entityOperator.topicOperator.resources|tolerations|affinity|topologySpreadConstraints`
- `kafka.entityOperator.userOperator.resources|tolerations|affinity|topologySpreadConstraints`
- `clickhouse.config.ch.resources|tolerations|affinity|topologySpreadConstraints`
- `clickhouse.config.chk.resources|tolerations|affinity|topologySpreadConstraints`
- `grafana.resources`, `grafana.tolerations`, `grafana.affinity`, `grafana.topologySpreadConstraints`

## Grafana ClickHouse Plugin

Grafana is configured to install the ClickHouse datasource plugin by default:

- `grafana.plugins: [grafana-clickhouse-datasource]`

A default ClickHouse datasource definition is included under
`grafana.datasources.datasources.yaml` and points to `clickhouse-ch-cluster:8123`.

A default Grafana ingress is enabled and points to host
`grafana.metranova.test.example.org` using ingress class `traefik`.

## Secret Management

Required external secrets:

- `clickhouse-users` (keys: `admin-password`, `readonly-password`, `backup-password`)
- `clickhouse-tls`
- `pipeline-user`
- `metranova-kafka-cluster-ca-cert`

By default this chart now auto-creates `grafana-admin` using keys
`admin-user` and `admin-password` when `grafanaAdminSecret.create=true`.

To avoid plaintext credentials in `values.yaml`, use the helper script:

```bash
NAMESPACE=metranova bash charts/metranova/scripts/manage-secrets.sh check
NAMESPACE=metranova bash charts/metranova/scripts/manage-secrets.sh bootstrap
```

Notes:

- `bootstrap` securely prompts for passwords and creates/updates secrets in-cluster.
- `clickhouse-tls` can be created by setting `CLICKHOUSE_TLS_CERT` and `CLICKHOUSE_TLS_KEY` env vars before running `bootstrap`.
- `pipeline-user` and `metranova-kafka-cluster-ca-cert` are typically created by Strimzi/Kafka workflows and are checked by the script.

For production use, verify these secrets before install:

- Ensure `grafana-admin` exists (auto-created by default, or set
	`grafanaAdminSecret.create=false` and create it externally)
- Ensure `clickhouse-users` contains `readonly-password` (Grafana datasource uses this via secret reference)