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

5. Download the CAIDA AS and organization metadata:
```
curl -k "https://publicdata.caida.org/datasets/as-organizations/20251001.as-org2info.jsonl.gz" | gunzip --stdout > caches/caida_as_org2info.jsonl
curl -k -o caches/caida_peeringdb.json "https://publicdata.caida.org/datasets/peeringdb/2025/12/peeringdb_2_dump_2025_12_01.json"
```

6. Bootstrap ClickHouse with the CAIDA metadata:
```bash
docker compose run --rm -e CAIDA_ORG_AS_CONSUMER_UPDATE_INTERVAL=-1 metadata_caida_org_as
```

7. Download MaxMind metadata (replace YOUR_ACCOUNT_ID and YOUR_LICENSE_KEY with your MaxMind account and license key)
```
curl -o caches/GeoLite2-ASN-CSV.zip -L -u YOUR_ACCOUNT_ID:YOUR_LICENSE_KEY \
'https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download?suffix=zip'
unzip caches/GeoLite2-ASN-CSV.zip -d caches/GeoLite2-ASN-CSV
cp caches/GeoLite2-ASN-CSV/GeoLite2-ASN-CSV_*/GeoLite2-ASN-Blocks-IPv4.csv caches/GeoLite2-ASN-Blocks-IPv4.csv
cp caches/GeoLite2-ASN-CSV/GeoLite2-ASN-CSV_*/GeoLite2-ASN-Blocks-IPv6.csv caches/GeoLite2-ASN-Blocks-IPv6.csv
rm -rf caches/GeoLite2-ASN-CSV
curl -o caches/GeoLite2-City-CSV.zip -L -u YOUR_ACCOUNT_ID:YOUR_LICENSE_KEY \
'https://download.maxmind.com/geoip/databases/GeoLite2-City-CSV/download?suffix=zip'
unzip caches/GeoLite2-City-CSV.zip -d caches/GeoLite2-City-CSV
cp caches/GeoLite2-City-CSV/GeoLite2-City-CSV_*/GeoLite2-City-Blocks-IPv4.csv caches/GeoLite2-City-Blocks-IPv4.csv
cp caches/GeoLite2-City-CSV/GeoLite2-City-CSV_*/GeoLite2-City-Blocks-IPv6.csv caches/GeoLite2-City-Blocks-IPv6.csv
cp caches/GeoLite2-City-CSV/GeoLite2-City-CSV_*/GeoLite2-City-Locations-en.csv caches/GeoLite2-City-Locations-en.csv
rm -rf caches/GeoLite2-City-CSV
```

8. Load MaxMind metadata into clickhouse
```bash
docker compose run --rm -e IP_GEO_CSV_CONSUMER_UPDATE_INTERVAL=-1 metadata_ip_geo
```

9. Bootstrap ClickHouse with Science Registry data:
```bash
docker compose run --rm -e SCIREG_HTTP_CONSUMER_UPDATE_INTERVAL=-1 metadata_scireg
```

10. Build local cache of IP references:
```bash
docker compose run --rm -e CLICKHOUSE_CONSUMER_UPDATE_INTERVAL=-1 cache_ip_trie
```

11. Update `meta_device.yml` and `meta_interface.yml` with your site specific metadata. You can optionally also add circuit info to `meta_circuit.yml`, but this is not required.

12. Bootstrap ClickHouse with the metadata from the files:
```bash
docker compose run --rm -e FILE_CONSUMER_UPDATE_INTERVAL=-1 metadata_file_export
```

13. Start all the pipleines:
```bash
docker compose up -d
```