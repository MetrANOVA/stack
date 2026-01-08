# MetrANOVA Stack - SNMP

This is the stack to collect and process data polled from SNMP. It uses Telegraf as the collector that does SNMP polling

## Collector
TBD

## Pipeline

### Installing with Helm (Recommended)

The recommended way to deploy the SNMP pipeline is using Helm:

#### Add the Helm Repository

```bash
helm repo add metranova https://metranova.github.io/stack
helm repo update
```

#### Install Latest Stable Release

```bash
helm install metranova-snmp metranova/snmp-pipeline
```

#### Install with Custom Values

```bash
helm install metranova-snmp metranova/snmp-pipeline -f custom-values.yaml
```

#### Install Pre-Release Version

To install a pre-release version (e.g., beta releases from version branches), use the `--devel` flag:

```bash
# Install latest pre-release version
helm install metranova-snmp metranova/snmp-pipeline --devel

# Install specific pre-release version
helm install metranova-snmp metranova/snmp-pipeline --version 0.1.0-beta --devel
```

For detailed configuration options, see the chart's README or use:

```bash
helm show readme metranova/snmp-pipeline
helm show values metranova/snmp-pipeline
```

### Pipeline Configuration (Docker Compose)
1. Change to the pipeline directory:
```bash
cd pipeline/
```
2. Copy conf.example to conf:
```bash
cp -r conf.example conf
```
3. Copy any certificates for Kafka and/or Clickhouse to `conf/certificates`. What you need here will depend on your Kafka and ClickHouse deploments. The filenames don't matter as you'll specify the path to these in next step.
4. Update `conf/envs/base.env` with Kafka and ClickHouse credentials
5. Bootstrap ClickHouse with the CAIDA metadata:
```bash
docker compose run --rm -e CAIDA_ORG_AS_CONSUMER_UPDATE_INTERVAL=-1 metadata_caida_org_as
```
6. Update `meta_device.yml` and `meta_interface.yml` with your site specific metadata. You can optionally also add circuit info to `meta_circuit.yml`, but this is not required.
7. Bootstrap ClickHouse with the metadata from the files:
```bash
docker compose run --rm -e FILE_CONSUMER_UPDATE_INTERVAL=-1 metadata_file_export
```
8. Start all the pipleines:
```bash
docker compose up -d
```