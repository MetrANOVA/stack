# MetraNova Umbrella Chart

This chart installs the MetraNova stack as a single Helm release by composing
the component charts in this repository.

Included dependencies:

- `clickhouse`
- `kafka`
- `telegraf`
- `pmacct`
- `metranova-snmp-pipeline` (aliased as `snmpPipeline`)
- `metranova-flow-pipeline` (aliased as `flowPipeline`)
- `metranova-api` (aliased as `api`)
- `grafana`

## Install The Umbrella Chart

### 1) Prerequisites

- Kubernetes cluster + `kubectl` access
- Helm 3
- Altinity ClickHouse Operator installed and healthy
- Strimzi Kafka Operator installed and healthy

The operators must watch the namespace where you install this chart.

### 2) Build chart dependencies

From repository root:

```bash
helm dependency build helm/metranova
```

This populates `helm/metranova/charts/*.tgz`.

### 3) Prepare a values override file

Create a custom values file from the defaults:

```bash
cp helm/metranova/values.yaml helm/metranova/values.local.yaml
```

At minimum, review and set:

- `global.baseDomain` (or `global.ingressHost` for shared host/path routing)
- `global.storageClassName`
- component-level storage class overrides where needed
- replica counts and resources for your cluster size
- ingress settings (`grafanaIngress.*`, `apiIngress.*`, and chart-specific ingress settings)

### 4) Prepare required secrets

Required external secrets:

- `clickhouse-users` (keys: `admin-password`, `readonly-password`, `backup-password`)
- `clickhouse-tls`
- `pipeline-user`
- `metranova-kafka-cluster-ca-cert`

`grafana-admin` is auto-created by default when
`grafanaAdminSecret.create=true`.

Use the helper script to validate/bootstrap secrets:

```bash
NAMESPACE=metranova bash helm/metranova/scripts/manage-secrets.sh check
NAMESPACE=metranova bash helm/metranova/scripts/manage-secrets.sh bootstrap
```

Notes:

- `bootstrap` prompts securely and creates/updates in-cluster secrets.
- `clickhouse-tls` can be created by exporting `CLICKHOUSE_TLS_CERT` and
	`CLICKHOUSE_TLS_KEY` before `bootstrap`.

### 5) (Recommended) Dry-run render

```bash
helm upgrade --install metranova helm/metranova \
	--namespace metranova \
	--create-namespace \
	-f helm/metranova/values.local.yaml \
	--dry-run
```

### 6) Install

```bash
helm upgrade --install metranova helm/metranova \
	--namespace metranova \
	--create-namespace \
	-f helm/metranova/values.local.yaml
```

### 7) Verify rollout

```bash
kubectl -n metranova get pods
kubectl -n metranova get pvc
helm -n metranova status metranova
```

## Upgrade

```bash
helm dependency build helm/metranova
helm upgrade metranova helm/metranova \
	--namespace metranova \
	-f helm/metranova/values.local.yaml
```

## Uninstall

```bash
helm uninstall metranova -n metranova
```

## Configuration Reference

All top-level component values are in `helm/metranova/values.yaml`:

- `clickhouse.*`
- `kafka.*`
- `telegraf.*`
- `pmacct.*`
- `snmpPipeline.*`
- `flowPipeline.*`
- `api.*`
- `grafana.*`

Enable/disable components:

- `clickhouse.enabled`
- `kafka.enabled`
- `telegraf.enabled`
- `pmacct.enabled`
- `snmpPipeline.enabled`
- `flowPipeline.enabled`
- `api.enabled`
- `grafana.enabled`

Helpful global keys:

- `global.storageClassName`
- `global.baseDomain`
- `global.ingressHost`
- `global.clickhouseSubdomain`
- `global.grafanaSubdomain`
- `global.apiSubdomain`

Storage class fallback order:

- component-specific storage class
- `global.storageClassName`
- cluster default storage class