# MetrANOVA Flow Stack - Docker Deployment Guide

This guide walks you through setting up the MetrANOVA Flow Stack for collecting network flow data (Netflow, IPFIX and/or sFlow) on a single host using Docker Compose.

## 1. Goals

This document will help you deploy a standalone instance of the MetrANOVA Flow Stack using Docker. By the end of this guide, you will have a fully functional system capable of:

- **Collecting** network flow data (IPFIX/NetFlow and sFlow)
- **Processing** flow records with enrichment and aggregation
- **Storing** raw and aggregated flow data in ClickHouse
- **Visualizing** network traffic in Grafana dashboards

**Target Use Case:** This deployment is designed for smaller to medium-sized environments handling **< 10,000 flows per second** with moderate retention periods. For larger scale deployments requiring horizontal scaling, we recommend using our Kubernetes Helm charts.

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
make
docker compose up -d
```

Once running, configure your network devices to send flow data to:
- **IPFIX/NetFlow:** UDP port **9996**
- **sFlow:** UDP port **9997**

Access Grafana at `http://localhost:3000` (login credentials in `grafana/conf/grafana_auth.env`).

## 4. Component Overview

The MetrANOVA Flow Stack consists of several integrated components:

### Flow Collectors
- **nfacctd** - Collects NetFlow v5/v9 and IPFIX data
- **sfacctd** - Collects sFlow data

Both collectors receive flow records from network devices and forward them to Kafka for processing.

### Message Bus
- **Kafka** - Provides reliable message queuing between collectors and processing pipelines

### Processing Pipeline
- **MetrANOVA Flow Pipeline** - Processes raw flow records with:
  - Data normalization and validation
  - IP geolocation enrichment (via MaxMind GeoLite)
  - ASN and organization mapping (via CAIDA datasets)
  - Device, interface, and circuit metadata enrichment
  - Aggregation for efficient storage

### Data Storage
- **ClickHouse** - High-performance columnar database optimized for analytical queries on time-series flow data

### Visualization
- **Grafana** - Web-based dashboards for visualizing network traffic patterns and trends

## 5. Choosing Hardware

Hardware requirements depend on your traffic volume and retention needs. For deployments running all of these components on one host and handling up to 10,000 flows per second:

### Recommended Specifications
- **Memory:** 64 GB RAM
- **CPU:** 8 cores (16 threads)
- **Storage:** 500 GB minimum (see capacity planning table below for retention-based requirements)

### Storage Capacity Planning

Raw flow records consume approximately **20 bytes per record** (including indexes and overhead). Aggregated records are approximately **10 bytes per record** with significantly fewer total records.

**Estimated disk space for raw flow data at 10,000 flows/sec:**

| Retention Period | Total Records | Disk Space Required |
|-----------------|---------------|---------------------|
| 1 day           | 864 million   | ~17 GB             |
| 7 days          | 6.0 billion   | ~121 GB            |
| 30 days         | 25.9 billion  | ~518 GB            |
| 180 days        | 155.5 billion | ~3.1 TB            |
| 1 year          | 315.4 billion | ~6.3 TB            |

**Note:** Aggregated data reduces storage requirements by 10-20x depending on traffic patterns. A typical deployment with 7-day raw retention and 1-year aggregate retention requires approximately **150-200 GB** of storage.

### Storage Recommendations
- **Small deployments (< 1,000 fps):** 100 GB minimum
- **Medium deployments (1,000-5,000 fps):** 200-300 GB recommended
- **Large deployments (5,000-10,000 fps):** 500 GB or more

## 6. Download the Software

Clone the MetrANOVA Stack repository from GitHub:

```bash
git clone https://github.com/MetrANOVA/stack
cd stack
```

This will download all necessary configuration files, build scripts, and Docker Compose definitions.

## 7. Build the Software

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

## 8. Optional: Choose Collectors

By default, both flow collectors (nfacctd and sfacctd) are enabled. If you only need one protocol, you can disable the unused collector.

Edit `docker/config.yml` and locate the collectors section:

```yaml
collectors:
  nfacctd:
    enabled: true  # Set to false to disable NetFlow/IPFIX collection
  sfacctd:
    enabled: true  # Set to false to disable sFlow collection
```

**Example: IPFIX-only deployment**

```yaml
collectors:
  nfacctd:
    enabled: true
  sfacctd:
    enabled: false  # Disable sFlow collector
```

After making changes, rebuild the configuration:

```bash
make clean
make
```

## 9. Optional: Define Device, Interface, and Circuit Metadata

Metadata enrichment makes flow data more meaningful by mapping interface indices to human-readable names and associating flows with specific circuits or devices.

### Metadata Files

You can statically define metadata by editing these YAML files:

- `flow/pipeline/conf/meta_device.yml` - Device metadata (routers, switches)
- `flow/pipeline/conf/meta_interface.yml` - Interface metadata (names, descriptions)
- `flow/pipeline/conf/meta_circuit.yml` - Circuit metadata (carrier, bandwidth)

### Example: Device Metadata

```yaml
devices:
  - router_id: "192.168.1.1"
    hostname: "core-router-01"
    site: "DataCenter-01"
    vendor: "Cisco"
    model: "ASR1001-X"
```

### Example: Interface Metadata

```yaml
interfaces:
  - router_id: "192.168.1.1"
    ifindex: 10
    name: "GigabitEthernet0/0/1"
    description: "Uplink to ISP-A"
    speed: 10000000000  # 10 Gbps in bps
```

### Example: Circuit Metadata

```yaml
circuits:
  - circuit_id: "CKT-12345"
    description: "Primary Internet Circuit"
    provider: "ISP-A"
    bandwidth_mbps: 10000
    type: "internet"
```

### Notes
- Metadata is **optional** but highly recommended for operational visibility
- Metadata can be defined before or after starting the stack
- The `metadata_file_exporter` pipeline automatically detects changes and updates ClickHouse
- Future releases will include APIs for custom integrations and plugins for common inventory management systems

## 10. Optional: Setup MaxMind GeoLocation

MetrANOVA can automatically enrich flow data with geographic information using MaxMind's free GeoLite2 databases.

### Create a MaxMind Account

1. **Sign up for a free account:** [Create MaxMind Account](https://support.maxmind.com/knowledge-base/articles/create-a-maxmind-account)
2. **Generate a license key:** [Generate License Key](https://support.maxmind.com/knowledge-base/articles/generate-a-maxmind-license-key)

**Note:** You do **not** need a paid account - the free GeoLite2 databases are sufficient.

### Configure Credentials

Edit `flow/pipeline/conf/envs/metadata_ip_geo.env` and add your credentials:

```bash
IP_GEO_CSV_CONSUMER_MAXMIND_ACCOUNT_ID=123456
IP_GEO_CSV_CONSUMER_MAXMIND_LICENSE_KEY=abcdefghijklmnop
```

Once configured, the pipeline will automatically download and refresh GeoLite2 databases on a scheduled basis.

## 11. Start the Services

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
- kafka
- clickhouse
- nfacctd (if enabled)
- sfacctd (if enabled)
- flow-pipeline (multiple containers for different pipeline stages):
  - **data_flow** - Main pipeline processing flow data records (scalable with replicas). Each worker handles roughly 8k flows per second.
  - **metadata_caida_org_as** - Fetches and processes CAIDA ASN and organization data
  - **metadata_file_export** - Exports device/interface/circuit metadata from YAML files to ClickHouse
  - **metadata_ip_geo** - Downloads and processes MaxMind GeoIP data for IP geolocation
  - **metadata_scireg** - Fetches Science Registry metadata for research networks
  - **metadata_cric** - Fetches CRIC metadata for LHC computing infrastructure (optional, LHC profile only)
  - **cache_ip_trie** - Maintains IP prefix trie cache for fast lookups
- grafana

### View Logs

Monitor logs for any issues:

```bash
# View all logs
docker compose logs

# Follow logs in real-time
docker compose logs -f

# View logs for a specific service
docker compose logs -f nfacctd
```

### Service Startup Time

Initial startup may take 2-5 minutes as services initialize databases, create topics, and establish connections.

## 12. Configure Network Devices

Configure your routers, switches, and other network devices to export flow data to the MetrANOVA collector host.

### Port Assignments

- **NetFlow/IPFIX:** UDP port **9996**
- **sFlow:** UDP port **9997**

### Generic Configuration Guidelines

**IPFIX/NetFlow Example (Cisco IOS):**
```
flow exporter METRANOVA
 destination <collector-ip>
 transport udp 9996
 template data timeout 60
```

**sFlow Example (Linux/sFlowTrend):**
```
sflow {
  collector {
    ip = <collector-ip>
    udpport = 9997
  }
}
```

**Important:** Replace `<collector-ip>` with the IP address of your MetrANOVA server.

### Platform-Specific Documentation

Consult your device vendor's documentation for detailed flow export configuration.

## 13. Access Grafana

Once services are running and devices are sending flow data, you can visualize the data in Grafana.

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

Pre-built dashboards are under development. In the meantime, you can explore flow data using Grafana's **Explore** feature:

1. Click the **Explore** icon (compass) in the left sidebar
2. Select the **MetrANOVA ClickHouse** datasource
3. Use the SQL editor to query flow data

**Example Query:**
```sql
SELECT
    *
FROM data_flow
ORDER BY start_time DESC
LIMIT 100
```

### Security Considerations

For production deployments:
- Place Grafana behind a reverse proxy (nginx, Apache)
- Enable HTTPS/TLS encryption
- Configure authentication (LDAP, OAuth, etc.)
- Restrict network access with firewall rules

## 14. Next Steps

Congratulations! You now have a working MetrANOVA Flow Stack deployment.

### What's Next?

- **Monitor Data Ingestion:** Check that flow records are being received and processed
- **Create Custom Dashboards:** Build visualizations tailored to your network
- **Set Up Alerting:** Configure alerts for traffic anomalies or threshold violations
- **Tune Retention:** Adjust data retention policies based on storage capacity
- **Scale Up:** Migrate to Kubernetes with Helm charts for larger deployments

### Getting Help

If you encounter issues or have questions:

- **GitHub Issues:** [https://github.com/MetrANOVA/stack/issues](https://github.com/MetrANOVA/stack/issues)
- **Community Support:** Reach out to MetrANOVA developers and community

### Roadmap

Upcoming features include:
- Pre-built Grafana dashboards for common use cases
- Enhanced authentication and authorization features
- REST APIs for metadata management
- Integration with network inventory systems
- Enhanced anomaly detection and alerting
- Support for additional flow protocols

Thank you for using MetrANOVA!
