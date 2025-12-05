# MetrANOVA Stack - SNMP

This is the stack to collect and process data polled from SNMP. It uses Telgraf as the collector that does SNMP polling

## Collector
TBD

## Pipeline

### Pipeline Configurations 
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
5. Download the CAIDA AS and organization metadata:
```
curl -k "https://publicdata.caida.org/datasets/as-organizations/20251001.as-org2info.jsonl.gz" | gunzip --stdout > caches/caida_as_org2info.jsonl
curl -k -o caches/caida_peeringdb.json "https://publicdata.caida.org/datasets/peeringdb/2025/12/peeringdb_2_dump_2025_12_01.json"
```
6. Bootstrap ClickHouse with the CAIDA metadata:
```bash
docker compose run --rm -e CAIDA_ORG_AS_CONSUMER_UPDATE_INTERVAL=-1 metadata_caida_org_as
```
7. Update `meta_device.yml` and `meta_interface.yml` with your site specific metadata. You can optionally also add circuit info to `meta_circuit.yml`, but this is not required.
8. Bootstrap ClickHouse with the metadata from the files:
```bash
docker compose run --rm -e FILE_CONSUMER_UPDATE_INTERVAL=-1 metadata_file_export
```
9. Start all the pipleines:
```bash
docker compose up -d
```