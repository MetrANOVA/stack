# MetrANOVA BMP Stack - Docker Deployment Guide

This guide walks you through setting up the MetrANOVA BMP Stack for collecting BGP routing state from your network devices using BMP (BGP Monitoring Protocol) on a single host using Docker Compose.

## 1. Goals

This document will help you deploy a standalone instance of the MetrANOVA BMP Stack using Docker. By the end of this guide, you will have a fully functional system capable of:

- **Collecting** BGP routing table state and updates via BMP
- **Processing** BMP messages with enrichment and normalization
- **Storing** BGP routing data in ClickHouse
- **Visualizing** routing topology and prefix data in Grafana dashboards

**Target Use Case:** This deployment is designed for environments monitoring BGP routing state from one or more routers. For larger scale deployments requiring horizontal scaling, we recommend using our Kubernetes Helm charts.

## 2. Prerequisites

Before beginning, ensure the following software is installed on your system:

- **Python 3.9+** - Required for build scripts
- **Git** - For cloning the repository
- **Make** - For automating the build process
- **Docker** and **Docker Compose** - For containerized deployment

Any Unix-like system (Linux, macOS) with these tools installed should work.

You can verify your installations with:

```bash
python3 --version
git --version
make --version
docker --version
docker compose version
```

## 3. Quickstart

For experienced users who want to get up and running immediately:

```bash
git clone https://github.com/MetrANOVA/stack
cd stack
cp docker/config.bmp.yml docker/config.yml
make
docker compose up -d
```

Then configure your routers to send BMP data to TCP port **1790**.

Access Grafana at `http://localhost:3000` (login credentials in `grafana/conf/grafana_auth.env`).

## 4. Component Overview

The MetrANOVA BMP Stack consists of several integrated components:

### BMP Collector
- **pmbmpd** - Receives BMP sessions from routers and forwards messages to Kafka. Built on [pmacct](http://www.pmacct.net/).

### Message Bus
- **Kafka** - Provides reliable message queuing between the collector and processing pipeline

### Processing Pipeline
- **MetrANOVA BMP Pipeline** - Processes raw BMP messages with:
  - BGP update parsing and normalization
  - IP geolocation enrichment (via MaxMind GeoLite2)
  - ASN and organization mapping (via CAIDA datasets)
  - Route state tracking and materialized views for current RIB snapshots

### Shared Metadata Services
- **cache_ip_trie** - Maintains an IP prefix trie in shared memory for fast lookups
- **metadata_ip_geo** - Downloads and processes MaxMind GeoIP data for IP geolocation
- **metadata_caida_org_as** - Fetches CAIDA ASN and organization data

### Data Storage
- **ClickHouse** - High-performance columnar database optimized for analytical queries on routing data

### Visualization
- **Grafana** - Web-based dashboards for visualizing BGP routing state and prefix data

## 5. Choosing Hardware

Hardware requirements depend on the number of BMP sessions and routing table sizes being monitored.

### Recommended Specifications
- **Memory:** 32 GB RAM (64 GB recommended for large routing tables)
- **CPU:** 8 cores
- **Storage:** 200 GB minimum (see capacity planning notes below)

### Storage Considerations

Storage requirements depend primarily on the number of routes monitored and how long update history is retained. Full Internet routing tables (~900k prefixes per peer) will consume significantly more storage than partial table peers. A typical deployment with a small number of full-table peers and 30-day retention requires approximately **50-100 GB**.

## 6. Download the Software

Clone the MetrANOVA Stack repository from GitHub:

```bash
git clone https://github.com/MetrANOVA/stack
cd stack
```

## 7. Configure the Stack

The BMP stack uses `docker/config.yml` to control which components are enabled. A pre-built starting configuration is provided for BMP deployments:

```bash
cp docker/config.bmp.yml docker/config.yml
```

The default `config.bmp.yml` enables:
- The `pmbmpd` BMP collector
- The BMP processing pipeline with shared metadata services (IP trie, IP geo, CAIDA ASN)
- Kafka message bus
- ClickHouse datastore
- Grafana dashboard

You can open `docker/config.yml` to review or adjust these settings before building.

## 8. Build the Software

The repository uses `make` to generate your Docker Compose configuration and set up the environment. This process:

- Generates SSL/TLS certificates for secure communication
- Creates randomized credentials for each service
- Renders configuration files from templates
- Prepares the Docker Compose stack

Run the build process:

```bash
make
```

The build typically takes 1-2 minutes. If you encounter issues, you can clean up and retry:

```bash
make clean
make
```

## 9. Optional: Setup MaxMind GeoLocation

MetrANOVA can automatically enrich routing data with geographic information using MaxMind's free GeoLite2 databases.

### Create a MaxMind Account

1. **Sign up for a free account:** [Create MaxMind Account](https://support.maxmind.com/knowledge-base/articles/create-a-maxmind-account)
2. **Generate a license key:** [Generate License Key](https://support.maxmind.com/knowledge-base/articles/generate-a-maxmind-license-key)

**Note:** You do **not** need a paid account - the free GeoLite2 databases are sufficient.

### Configure Credentials

Edit `shared/pipeline/conf/envs/metadata_ip_geo.env` and add your credentials:

```bash
IP_GEO_CSV_CONSUMER_MAXMIND_ACCOUNT_ID=123456
IP_GEO_CSV_CONSUMER_MAXMIND_LICENSE_KEY=abcdefghijklmnop
```

Once configured, the pipeline will automatically download and refresh GeoLite2 databases on a scheduled basis.

## 10. Start the Services

Once configuration is complete, start all services:

```bash
docker compose up -d
```

The `-d` flag runs containers in detached mode (background).

### Verify Services

Check that all containers are running:

```bash
docker compose ps
```

You should see services including:
- `kafka`
- `clickhouse`
- `pmbmpd` - BMP collector listening on TCP port 1790
- `data_bmp` - Main pipeline processing BMP messages
- `cache_ip_trie` - IP prefix trie cache
- `metadata_ip_geo` - MaxMind GeoIP metadata
- `metadata_caida_org_as` - CAIDA ASN/organization metadata
- `grafana`

### View Logs

Monitor logs for any issues:

```bash
# View all logs
docker compose logs

# Follow logs in real-time
docker compose logs -f

# View logs for a specific service
docker compose logs -f pmbmpd
docker compose logs -f data_bmp
```

### Service Startup Time

Initial startup may take 2-5 minutes as services initialize databases, create Kafka topics, and establish connections.


## 11. Access Grafana

Once services are running and routers are sending BMP data, you can visualize the routing state in Grafana.

### Login to Grafana

1. Open your browser and navigate to: `http://localhost:3000`
2. Login credentials:
   - **Username:** `admin`
   - **Password:** Located in `grafana/conf/grafana_auth.env`

**Retrieve the password:**
```bash
cat grafana/conf/grafana_auth.env
```

**Important:** Change the default password after your first login via the Grafana UI (User menu → Preferences → Change Password).

### Explore Your Data

You can explore BMP data using Grafana's **Explore** feature:

1. Click the **Explore** icon (compass) in the left sidebar
2. Select the **MetrANOVA ClickHouse** datasource
3. Use the SQL editor to query routing data

**Example Query — current BGP routing table:**
```sql
SELECT *
FROM data_bmp_route_latest
ORDER BY prefix
LIMIT 100
```

### Security Considerations

For production deployments:
- Place Grafana behind a reverse proxy (nginx, Apache)
- Enable HTTPS/TLS encryption
- Configure authentication (LDAP, OAuth, etc.)
- Restrict network access with firewall rules

## 12. Optional: ROOTBEER BGP Export

The BMP stack includes optional support for exporting a snapshot of the current BGP routing table as a JSON file compatible with Internet2's **ROOTBEER** (Routing Observatory for Operationally Testing BGP Enrichment and Reporting) BGP analysis system.

When enabled, the `cache_rootbeer` service periodically queries the current RIB from ClickHouse and writes a JSON file to the shared caches directory.

### Enable ROOTBEER Export

Start the stack with the `rootbeer` profile:

```bash
docker compose --profile rootbeer up -d
```

This brings up all standard services **plus** the `cache_rootbeer` exporter. If the stack is already running:

```bash
docker compose --profile rootbeer up -d cache_rootbeer
```

### Configure the Export

Edit `bmp/pipeline/conf/envs/cache_rootbeer.env` to adjust the export settings:

```bash
# Source table (AggregatingMergeTree materialized view)
ROOTBEER_SOURCE_TABLE=data_bmp_route_latest

# How often to regenerate the report in seconds; -1 = run once and exit
ROOTBEER_UPDATE_INTERVAL=86400

# Where to write the JSON report
JSON_FILE_DIRECTORY=/app/caches

# Pretty-print indent (set to 0 for compact output)
JSON_FILE_INDENT=0
```

The exported JSON file will be written to the `bmp/pipeline/caches/` directory on the host. Configure your ROOTBEER integration to read from that path or mount it as appropriate.

## 14. Next Steps

Congratulations! You now have a working MetrANOVA BMP Stack deployment.

### What's Next?

- **Monitor Data Ingestion:** Check that BMP sessions are established and route data is being received
- **Create Custom Dashboards:** Build visualizations tailored to your network's routing topology
- **Set Up Alerting:** Configure alerts for routing changes or session drops
- **Tune Retention:** Adjust data retention policies based on storage capacity
- **Scale Up:** Migrate to Kubernetes with Helm charts for larger deployments

### Getting Help

If you encounter issues or have questions:

- **GitHub Issues:** [https://github.com/MetrANOVA/stack/issues](https://github.com/MetrANOVA/stack/issues)
- **Community Support:** Reach out to MetrANOVA developers and community

Thank you for using MetrANOVA!
