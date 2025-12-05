# MetrANOVA Stack - SNMP

This is the stack to collect and process data polled from SNMP. It uses Telgraf as the collector that does SNMP polling

## Collector
TBD

## Pipeline

### Pipeline Configurations 
1. Copy conf.example to conf:
```bash
cp -r conf.example conf
```
2. Copy any certificates for Kafka and/or Clickhouse to `conf/certificates`. What you need here will depend on your Kafka and ClickHouse deploments. The filenames don't matter as you'll specify the path to these in next step.
3. Update `conf/envs/base.env` with Kafka and ClickHouse credentials
4. Update `meta_device.yml` and `meta_interface.yml` with your site specific metadata. You can optionally also add circuit info to `meta_circuit.yml`, but this is not required.
5. Bootstrap the metadata pipelines by running those with `docker compose run`:
```bash
docker compose run -e CAIDA_ORG_AS_CONSUMER_UPDATE_INTERVAL=-1 metadata_caida_org_as
docker compose run -e FILE_CONSUMER_UPDATE_INTERVAL=-1 metadata_file_export
```
6. Start all the pipleines:
```bash
docker compose up -d
```