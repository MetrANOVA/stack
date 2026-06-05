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

Use one of these installation modes:

- Production: install from the published Helm repository.
- Development: clone this repository and install the chart from a local path.

### 1) Prerequisites

- Kubernetes cluster + `kubectl` access
- Helm 3
- Altinity ClickHouse Operator installed and healthy
- Strimzi Kafka Operator installed and healthy

The operators must watch the namespace where you install this chart.

### 2) Add the published Helm repository

Add the MetraNova Helm repository:

```bash
helm repo add metranova https://metranova.github.io/stack
helm repo update
```

Optional: inspect available versions.

```bash
helm search repo metranova/metranova --versions
helm search repo metranova --versions
```

Note: install commands in this README use the published chart reference
`metranova/metranova` from `https://metranova.github.io/stack`.

### Development install from a local checkout

Clone and check out the code you want to test (for example `main`, `0.1.0`,
or a feature branch):

```bash
git clone https://github.com/MetrANOVA/stack.git
cd stack
git checkout main
```

Build umbrella dependencies from local chart sources:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm dependency build helm/metranova
```

Export and customize local defaults:

```bash
helm show values ./helm/metranova > values.local.yaml
```

Install from the local chart directory:

```bash
helm upgrade --install metranova ./helm/metranova \
	--namespace metranova \
	--create-namespace \
	-f values.local.yaml
```

### 3) Prepare a values override file

Export default values and customize:

```bash
helm show values metranova/metranova > values.local.yaml
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

Note: the helper script is available in this repository checkout at
`helm/metranova/scripts/manage-secrets.sh`.

Notes:

- `bootstrap` prompts securely and creates/updates in-cluster secrets.
- `clickhouse-tls` can be created by exporting `CLICKHOUSE_TLS_CERT` and
	`CLICKHOUSE_TLS_KEY` before `bootstrap`.

### 5) (Recommended) Dry-run render

```bash
helm upgrade --install metranova metranova/metranova \
	--namespace metranova \
	--create-namespace \
	-f values.local.yaml \
	--dry-run
```

### 6) Install

```bash
helm upgrade --install metranova metranova/metranova \
	--namespace metranova \
	--create-namespace \
	-f values.local.yaml
```

### 7) Verify rollout

```bash
kubectl -n metranova get pods
kubectl -n metranova get pvc
helm -n metranova status metranova
```

## Upgrade

```bash
helm repo update
helm upgrade metranova metranova/metranova \
	--namespace metranova \
	-f values.local.yaml
```

## Uninstall

```bash
helm uninstall metranova -n metranova
```

## Configuration Reference

All top-level component values are available via:

```bash
helm show values metranova/metranova
```

Primary top-level keys:

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