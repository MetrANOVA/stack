# ClickHouse Cluster Installation Guide for MetrANOVA

This document describes how to install and configure the ClickHouse database cluster for the MetrANOVA network measurement and monitoring stack in the test Kubernetes environment.

## Overview

The ClickHouse cluster is deployed using the Altinity ClickHouse Operator and consists of:

- **ClickHouse Keeper**: 3-node cluster for coordination (similar to ZooKeeper)
- **ClickHouse Database**: 2 replicas for high availability
- **Storage**: CEPH storage via `csi-rbd-sc` storage class
- **Access**: Internal cluster access + external access via Traefik ingress

## Prerequisites

### Operator Prerequisites

This chart assumes the following operators are already installed and healthy in the cluster:

- ClickHouse Operator (Altinity)
- Kafka Operator (Strimzi)

Both operators must be configured to watch the same target namespace where this chart is deployed.

### Required Tools

- `kubectl` configured with access to the test Kubernetes cluster
- `helm` 3.x installed
- `openssl` for certificate generation

### Cluster Requirements

- Kubernetes cluster with CEPH storage configured
- Storage class `csi-rbd-sc` available
- Traefik ingress controller installed
- Namespace `metranova` created

### Resource Requirements

The cluster requires approximately:

- **ClickHouse Keeper**: 3 pods × (256M-4Gi RAM, 1-2 CPU, 10Gi storage each)
- **ClickHouse Database**: 2 pods × (8-16Gi RAM, 4-8 CPU, 100Gi data + 10Gi logs each)
- **Total**: ~16-32Gi RAM, 8-16 CPUs, ~240Gi storage

## Step 1: Install ClickHouse Operator

The ClickHouse Operator manages ClickHouse resources in Kubernetes.

### 1.1 Add Helm Repository

```bash
helm repo add clickhouse-operator https://docs.altinity.com/clickhouse-operator/
helm repo update
```

### 1.2 Install the Operator

```bash
helm install clickhouse-operator clickhouse-operator/altinity-clickhouse-operator \
  -n clickhouse-operator \
  --create-namespace \
  --set "watch.namespaces={TARGET_NAMESPACE}"
```

Replace `TARGET_NAMESPACE` with the namespace where you plan to deploy MetrANOVA (the same namespace you'll use for `helm install metranova`).

**Important**: The `watch.namespaces` parameter tells the operator which namespaces to monitor. The operator must watch the same namespace where you deploy the ClickHouse resources.

### 1.3 Verify Operator Installation

```bash
kubectl get pods -n clickhouse-operator
```

You should see the operator pod running:

```
NAME                                                              READY   STATUS    RESTARTS   AGE
clickhouse-operator-altinity-clickhouse-operator-xxxxxxxxx        2/2     Running   0          30s
```

### 1.4 Configure Operator to Watch Namespace (Critical Step)

**Known Issue**: The helm chart may not properly set the `watch.namespaces` parameter in the operator's ConfigMap. You must verify and manually fix if needed.

Check the operator configuration (replace with your actual target namespace):

```bash
kubectl get configmap clickhouse-operator-altinity-clickhouse-operator-files -n clickhouse-operator -o yaml | grep -A 2 "watch:"
```

If you see `namespaces: []` instead of your target namespace, you must manually edit the ConfigMap:

```bash
kubectl edit configmap clickhouse-operator-altinity-clickhouse-operator-files -n clickhouse-operator
```

Find this section:

```yaml
watch:
  namespaces: []
```

Change it to your target namespace (use spaces, NOT tabs):

```yaml
watch:
  namespaces:
    - your-namespace
```

Save and exit, then restart the operator:

```bash
kubectl rollout restart deployment clickhouse-operator-altinity-clickhouse-operator -n clickhouse-operator
```

**Verification**: Check the operator logs to confirm it's watching the namespace:

```bash
kubectl logs -n clickhouse-operator -l app.kubernetes.io/name=altinity-clickhouse-operator --tail=50 | grep "watchNamespaces"
```

You should see `watchNamespaces: [metranova]` or similar.

## Step 2: Create Required Secrets

### 2.1 Create Password Secret

Create secure passwords for ClickHouse users:

```bash
kubectl create secret generic clickhouse-users \
  --namespace=metranova \
  --from-literal=admin-password='<SECURE_PASSWORD_HERE>' \
  --from-literal=readonly-password='<SECURE_PASSWORD_HERE>' \
  --from-literal=backup-password='<SECURE_PASSWORD_HERE>'
```

**Note**: Replace `<SECURE_PASSWORD_HERE>` with actual secure passwords. Store these passwords securely in your team's password manager.

Verify:

```bash
kubectl get secret clickhouse-users -n metranova
```

### 2.2 Generate TLS Certificate

Generate a self-signed certificate for the test environment:

```bash
# Generate private key
openssl genrsa -out tls.key 2048

# Generate self-signed certificate (valid for 1 year)
openssl req -new -x509 -key tls.key -out tls.crt -days 365 \
  -subj "/CN=metranova.test.grnoc.iu.edu/O=MetrANOVA"

# Create Kubernetes TLS secret
kubectl create secret tls clickhouse-tls \
  --namespace=metranova \
  --cert=tls.crt \
  --key=tls.key
```

**Important for Production**: Replace this with proper certificates from your organization's certificate infrastructure. Consult with your team about:

- Internal CA certificates
- cert-manager integration
- Certificate rotation policies

Verify:

```bash
kubectl get secret clickhouse-tls -n metranova
```

## Step 3: Deploy ClickHouse Cluster

### 3.1 Clone Helm Charts Repository

```bash
git clone <your-helm-charts-repo>
cd <repo>/clickhouse
```

### 3.2 Review Configuration

The main configuration file is `values.yaml`. Key settings:

```yaml
namespace: metranova

config:
  tls:
    enabled: true
    cert_name: clickhouse-tls
  clickhouse_version: 25.9
  domains:
    - metranova.test.grnoc.iu.edu

  # Keeper configuration (coordination service)
  chk:
    name: "keeper-cluster"
    image:
      repository: clickhouse/clickhouse-keeper
      tag: "" # Optional override; defaults to config.clickhouse_version
    resources:
      disk_volume_size: 10Gi
      replicasCount: 3 # 3 nodes for HA quorum

  # ClickHouse configuration
  ch:
    image:
      repository: clickhouse/clickhouse-server
      tag: "" # Optional override; defaults to config.clickhouse_version
    resources:
      disk_volume_size: 100Gi
      log_volume_size: 10Gi
      shardCount: 1 # Single shard for test
      replicasCount: 2 # 2 replicas for HA
      requests:
        memory: 8Gi
        cpu: 4000m
      limits:
        memory: 16Gi
        cpu: 8000m
```

**Adjust these values** based on your expected data volume and available cluster resources.

### 3.3 Install the Helm Chart

```bash
helm install clickhouse . -n metranova
```

### 3.4 Monitor Deployment

Watch pods being created:

```bash
kubectl get pods -n metranova -w
```

You should see pods appear in this order:

1. **Keeper pods** (3 total): `chk-keeper-cluster-keeper-cluster-0-X-0`
2. **ClickHouse pods** (2 total): `chi-ch-cluster-ch-cluster-0-X-0`

Press Ctrl+C to stop watching once all pods show `Running` status.

**Expected deployment time**: 3-5 minutes

- Keeper pods: ~1-2 minutes
- ClickHouse pods: ~2-3 minutes (start after Keeper is healthy)

### 3.5 Verify Deployment

Check all resources:

```bash
kubectl get all -n metranova
```

Check installation status:

```bash
kubectl get clickhousekeeperinstallations -n metranova
kubectl get clickhouseinstallations -n metranova
```

Both should show `STATUS: Completed`.

Check ingress:

```bash
kubectl get ingress -n metranova
```

## Step 4: Test the Deployment

### 4.1 Test Internal Connectivity

Create a test pod and query ClickHouse:

```bash
# Get admin password
ADMIN_PASS=$(kubectl get secret clickhouse-users -n metranova -o jsonpath='{.data.admin-password}' | base64 -d)

# Create test pod
kubectl run clickhouse-test --image=curlimages/curl:latest -n metranova -- sleep 3600
kubectl wait --for=condition=ready pod/clickhouse-test -n metranova --timeout=30s

# Test query
kubectl exec -n metranova clickhouse-test -- \
  curl -s -k "https://clickhouse-ch-cluster.metranova.svc.cluster.local:8443/?user=admin&password=${ADMIN_PASS}&query=SELECT%201"

# Should return: 1

# Show databases
kubectl exec -n metranova clickhouse-test -- \
  curl -s -k "https://clickhouse-ch-cluster.metranova.svc.cluster.local:8443/?user=admin&password=${ADMIN_PASS}&query=SHOW%20DATABASES"

# Cleanup
kubectl delete pod clickhouse-test -n metranova
```

### 4.2 Test External Access

**Note**: External access currently has a known issue with TLS backend verification. This needs to be resolved with proper certificate infrastructure.

Get Traefik external IPs:

```bash
kubectl get svc traefik -n kube-system
```

Test with Host header (replace IP with one from above):

```bash
ADMIN_PASS=$(kubectl get secret clickhouse-users -n metranova -o jsonpath='{.data.admin-password}' | base64 -d)

curl -s -k -H "Host: metranova.test.grnoc.iu.edu" \
  "https://140.182.45.128/clickhouse/?user=admin&password=${ADMIN_PASS}&query=SELECT%201"
```

**Current Status**: This returns "Internal Server Error" due to TLS certificate verification issues between Traefik and ClickHouse backend. See "Known Issues" section below.

## Step 5: Configure DNS (Required for External Access)

Create a DNS CNAME record for `metranova.test.grnoc.iu.edu` pointing to the Kubernetes cluster A record:

```
metranova.test.grnoc.iu.edu  →  m.bldc.k8s.test.grnoc.iu.edu (CNAME)
```

This follows the standard pattern for services running on the test Kubernetes cluster.

**Existing cluster DNS** (already configured):

```
m.bldc.k8s.test.grnoc.iu.edu  →  140.182.45.129 (A record)
```

**Verification after DNS propagation:**

```bash
dig metranova.test.grnoc.iu.edu
```

**Note**: For production, consider having multiple A records for the cluster endpoint to provide high availability in case a single node fails.

## Accessing ClickHouse

### From Within Kubernetes

**Service Name**: `clickhouse-ch-cluster.metranova.svc.cluster.local`

**Ports**:

- `8123`: HTTP
- `8443`: HTTPS
- `9000`: Native TCP
- `9440`: Native TCP (secure)

**Example from Grafana** (running in same cluster):

```
Host: clickhouse-ch-cluster.metranova.svc.cluster.local
Port: 8443
Protocol: HTTPS
Database: default
Username: admin
Password: <from secret>
```

### From External

**URL**: `https://metranova.test.grnoc.iu.edu/clickhouse/`

**Note**: External access via ingress is currently blocked by TLS certificate issues (see Known Issues).

## Configuration Files

The helm chart consists of several template files:

### Chart.yaml

Defines the chart metadata and version.

### values.yaml

Main configuration file with all customizable parameters.

### templates/keeper.yml

Defines the ClickHouse Keeper (coordination) cluster.

### templates/ch.yml

Defines the ClickHouse database cluster.

### templates/ingress.yml

Defines the Traefik Ingress for external access.

### templates/extra-resources.yaml

Allows additional Kubernetes resources to be deployed alongside ClickHouse.

## Upgrading Configuration

To update the cluster configuration:

```bash
# Edit values.yaml or template files
cd <repo>/clickhouse

# Apply changes
helm upgrade clickhouse . -n metranova

# Monitor the upgrade
kubectl get pods -n metranova -w
```

## Troubleshooting

### Pods Not Starting

**Symptom**: No pods appear after helm install.

**Cause**: Operator is not watching the metranova namespace.

**Solution**: Follow Step 1.4 to manually configure the operator's ConfigMap.

### Storage Provisioning Issues

**Symptom**: Pods stuck in `Pending` state with PVC errors.

**Cause**: CEPH storage provisioner issues.

**Check**:

```bash
kubectl get pvc -n metranova
kubectl describe pvc <pvc-name> -n metranova
```

### ClickHouse Not Starting

**Symptom**: ClickHouse pods in CrashLoopBackOff.

**Check logs**:

```bash
kubectl logs -n metranova chi-ch-cluster-ch-cluster-0-0-0 -c clickhouse
```

### Keeper Issues

**Symptom**: ClickHouse pods waiting for Keeper.

**Verify Keeper health**:

```bash
kubectl logs -n metranova chk-keeper-cluster-keeper-cluster-0-0-0
```

All 3 Keeper pods must be healthy before ClickHouse can start.

### Ingress Not Working

**Check ingress configuration**:

```bash
kubectl describe ingress clickhouse-ingress -n metranova
```

**Check Traefik logs**:

```bash
kubectl logs -n kube-system -l app.kubernetes.io/name=traefik --tail=50
```

## Known Issues

### TLS Backend Verification

**Issue**: External access through ingress returns "Internal Server Error".

**Root Cause**: Traefik attempts to verify the ClickHouse backend TLS certificate, but the self-signed certificate only contains the hostname (`metranova.test.grnoc.iu.edu`), not the pod IP addresses. This causes the error:

```
tls: failed to verify certificate: x509: cannot validate certificate for 10.42.1.152 because it doesn't contain any IP SANs
```

**Temporary Workarounds**:

1. Use HTTP (port 8123) for backend instead of HTTPS (port 8443) - TLS terminates at ingress
2. Configure Traefik to skip backend certificate verification (not recommended for production)

**Proper Solution**:

- Implement proper certificate infrastructure with internal CA
- Use cert-manager to manage certificates
- Ensure certificates include pod IP SANs or use proper service DNS names
- Consult with team about existing certificate management practices

### Helm Chart watch.namespaces Bug

**Issue**: Setting `--set "watch.namespaces={metranova}"` during helm install doesn't properly update the operator's ConfigMap.

**Workaround**: Manually edit the ConfigMap as described in Step 1.4.

**Status**: This appears to be a bug in the helm chart that doesn't properly template the watch.namespaces value into the config.yaml.

## Next Steps

After successful deployment, the following integrations need to be configured:

1. **Certificate Management**: Implement proper certificate infrastructure
2. **SSO/Federated Login**: Integrate with organizational authentication
3. **Grafana Integration**: Configure ClickHouse as a Grafana datasource
4. **Telegraf Pipeline**: Configure telegraf to send SNMP data to ClickHouse
5. **pmacct Pipeline**: Configure pmacct to send netflow data to ClickHouse
6. **Database Schemas**: Create tables and schemas for network measurement data
7. **Backup Strategy**: Implement ClickHouse backup and restore procedures
8. **Monitoring**: Add ClickHouse metrics to monitoring stack

## Additional Resources

- [Altinity ClickHouse Operator Documentation](https://docs.altinity.com/clickhouse-operator/)
- [ClickHouse Documentation](https://clickhouse.com/docs/en/intro)
- [ClickHouse Keeper Documentation](https://clickhouse.com/docs/en/guides/sre/keeper/clickhouse-keeper)

## Support

For issues specific to this deployment, contact the MetrANOVA team.

For ClickHouse operator issues, see the [Altinity GitHub repository](https://github.com/Altinity/clickhouse-operator).
