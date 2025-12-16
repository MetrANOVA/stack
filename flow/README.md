# MetrANOVA Stack - Flow

This is the stack to collect and process network flow data. It uses pmacct as the collector and you can collector sFLow, Netflow and/or IPFIX.

## Collector
TBD

## Pipeline

### Pipeline Configuration
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

5. Update `conf/envs/metadata_ip_geo.env' with your MaxMind account id and license key. Go to https://www.maxmind.com/ to generate these.

6. Load MaxMind metadata into clickhouse
```bash
docker compose run --rm -e IP_GEO_CSV_CONSUMER_UPDATE_INTERVAL=-1 metadata_ip_geo
```

7. Bootstrap ClickHouse with Science Registry data:
```bash
docker compose run --rm -e SCIREG_HTTP_CONSUMER_UPDATE_INTERVAL=-1 metadata_scireg
```

8. Build local cache of IP references:
```bash
docker compose run --rm -e CLICKHOUSE_CONSUMER_UPDATE_INTERVAL=-1 cache_ip_trie
```

9. Update `meta_device.yml` and `meta_interface.yml` with your site specific metadata. You can optionally also add circuit info to `meta_circuit.yml`, but this is not required.

10. Bootstrap ClickHouse with the metadata from the files:
```bash
docker compose run --rm -e FILE_CONSUMER_UPDATE_INTERVAL=-1 metadata_file_export
```

11. Start all the pipleines:
```bash
docker compose up -d
```