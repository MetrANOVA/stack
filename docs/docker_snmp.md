# MetrANOVA SNMP Stack - Docker Deployment Guide

This guide walks you through setting up the MetrANOVA SNMP Stack for collecting network device metrics via SNMP on a single host using Docker Compose.

## 1. Goals

This document will help you deploy a standalone instance of the MetrANOVA SNMP Stack using Docker. By the end of this guide, you will have a fully functional system capable of:

- **Collecting** SNMP metrics (interface counters, device statistics) from network devices
- **Processing** SNMP data with enrichment and aggregation
- **Storing** SNMP metrics in ClickHouse
- **Visualizing** device metrics and performance in Grafana dashboards

**Target Use Case:** This deployment is designed for environments monitoring network device metrics via SNMP from one or more devices. For larger scale deployments requiring horizontal scaling, we recommend using our Kubernetes Helm charts.

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
cp docker/config.snmp.yml docker/config.yml
make
docker compose up -d
```

Then configure your network devices to respond to SNMP polls on the collector host.

Access Grafana at `https://localhost/` (login credentials in `grafana/conf/grafana_auth.env`).

## 4. Component Overview

The MetrANOVA SNMP Stack consists of several integrated components:

### SNMP Collector
- **Telegraf** - Polls SNMP metrics from network devices and forwards data to Kafka. Telegraf is configured to poll interface metrics and device statistics at regular intervals.

### Message Bus
- **Kafka** - Provides reliable message queuing between the collector and processing pipeline

### Processing Pipeline
- **MetrANOVA SNMP Pipeline** - Processes raw SNMP metrics with:
  - Data normalization and validation
  - Device metadata enrichment
  - Basic mapping of interface and device information

### Shared Metadata Services
- **metadata_file_export** - Exports device and interface metadata from YAML files to ClickHouse

### Data Storage
- **ClickHouse** - High-performance columnar database optimized for analytical queries on time-series metric data

### Visualization
- **Grafana** - Web-based dashboards for visualizing device metrics and performance trends

### Reverse Proxy
- **Envoy** - Terminates external HTTPS connections and routes traffic to Grafana (at `/`) and ClickHouse (at `/clickhouse`). All external access to these services goes through Envoy; direct ports are not exposed by default.

## 5. Choosing Hardware

Hardware requirements depend on the number of SNMP devices being monitored and the polling frequency.

### Recommended Specifications
- **Memory:** 16 GB RAM
- **CPU:** 4-8 cores
- **Storage:** 100 GB minimum (see capacity planning notes below)

### Storage Considerations

Storage requirements depend primarily on the number of devices monitored and their interface counts. SNMP metrics are typically collected every 60 seconds. A typical deployment monitoring 50 devices with an average of 20 interfaces per device and 30-day retention requires approximately **50-100 GB**.

## 6. Download the Software

Clone the MetrANOVA Stack repository from GitHub:

```bash
git clone https://github.com/MetrANOVA/stack
cd stack
```

## 7. Configure the Stack

The SNMP stack uses `docker/config.yml` to control which components are enabled. A pre-built starting configuration is provided for SNMP deployments:

```bash
cp docker/config.snmp.yml docker/config.yml
```

The default `config.snmp.yml` enables:
- The Telegraf SNMP collector
- The SNMP processing pipeline with shared metadata services
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

## 9. Configure SNMP Collectors

Before starting the services, you must configure Telegraf to poll your SNMP devices. Telegraf uses individual configuration files for each device to allow independent polling goroutines.

### Understanding Telegraf Configuration

The SNMP collector is configured using Telegraf's SNMP input plugin. Configuration files are stored in `snmp/collector/telegraf/conf/telegraf.d/`.

An example configuration template is provided at:
```
snmp/collector/telegraf/conf.example/10_input_snmp_HOSTNAME.conf.example
```

### Create Configuration Files for Your Devices

For each network device you want to monitor, you must:

1. **Copy the example configuration** to a new file in `snmp/collector/telegraf/conf.d/`
2. **Replace placeholders** with your device's information
3. **Customize MIB selections** if needed

#### Step 1: Copy the Example Configuration

```bash
cp snmp/collector/telegraf/conf.example/10_input_snmp_HOSTNAME.conf.example \
   snmp/collector/telegraf/conf/telegraf.d/10_input_snmp_router01.conf
```

#### Step 2: Edit the Configuration File

Open the new file and replace the following placeholders:

- **`HOSTNAME`** - Replace with your device's hostname or IP address
- **`COMMUNITY_STRING`** - Replace with your SNMP community string (usually `public` for read-only access)

**Example configuration for a device named `router01`:**

```toml
[[inputs.snmp]]
agents = [
  "udp://192.168.1.1:161"
]

community = "public"
agent_host_tag = "source"
interval = "60s"
timeout = "10s"
version = 2
retries = 2
max_repetitions = 20

[inputs.snmp.tags]
type = "snmp"
interval = "60"
device_name = "router01"
device_site = "DataCenter-01"
```

#### Step 3: Customize MIB Selections (Optional)

The example configuration includes standard IF-MIB (interface) metrics:
- Interface names, aliases, and speeds
- Interface admin and operational status
- In/out octets, packets, errors, and discards
- Broadcast and multicast packet counts

If you need additional MIBs or different metrics, refer to the example file for syntax and add additional `[[inputs.snmp.table]]` sections for each MIB table you want to poll.

#### Step 4: Repeat for Each Device

Create a separate configuration file for each device:

```bash
cp snmp/collector/telegraf/conf.example/10_input_snmp_HOSTNAME.conf.example \
   snmp/collector/telegraf/conf/telegraf.d/10_input_snmp_switch01.conf

cp snmp/collector/telegraf/conf.example/10_input_snmp_HOSTNAME.conf.example \
   snmp/collector/telegraf/conf/telegraf.d/10_input_snmp_switch02.conf

# Edit each file with your device's IP and community string
```

### SNMP Best Practices

- **Use SNMPv2c or SNMPv3:** SNMPv2c provides basic security via community strings. SNMPv3 offers authentication and encryption for sensitive environments.
- **Set appropriate polling intervals:** Shorter intervals (10-30 seconds) provide more granular data but consume more resources. Longer intervals (5-10 minutes) reduce overhead.
- **Validate SNMP access:** Test SNMP connectivity before deploying:
  ```bash
  snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0
  ```
- **Customize for your environment:** Remove MIBs you don't need and add metrics specific to your devices

## 10. Optional: Define Device and Interface Metadata

Metadata enrichment makes SNMP data more meaningful by associating device IPs with friendly names and site information.

### Metadata Files

You can statically define metadata by editing these YAML files:

- `snmp/pipeline/conf/meta_device.yml` - Device metadata (routers, switches)
- `snmp/pipeline/conf/meta_interface.yml` - Interface metadata (names, descriptions)

### Example: Device Metadata

```yaml
devices:
  - device_ip: "192.168.1.1"
    device_name: "core-router-01"
    site: "DataCenter-01"
    vendor: "Cisco"
    model: "ASR1001-X"
```

### Example: Interface Metadata

```yaml
interfaces:
  - device_ip: "192.168.1.1"
    ifindex: 10
    name: "GigabitEthernet0/0/1"
    description: "Uplink to ISP-A"
    speed: 10000000000  # 10 Gbps in bps
```

### Notes
- Metadata is **optional** but highly recommended for operational visibility
- Metadata can be defined before or after starting the stack
- The `metadata_file_exporter` pipeline automatically detects changes and updates ClickHouse

### Pipeline Capabilities

The current SNMP pipeline provides basic mapping and enrichment. Future versions will offer greater flexibility in how SNMP metrics are mapped and enriched in ClickHouse. If you require custom field mappings or additional transformations, please consult the project's issue tracker or community forums for guidance on extending the pipeline.

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
- `kafka`
- `clickhouse`
- `telegraf` - SNMP collector polling your configured devices
- `data_snmp` - Main pipeline processing SNMP metrics
- `metadata_file_export` - Exports device/interface metadata from YAML files to ClickHouse
- `grafana`

### View Logs

Monitor logs for any issues:

```bash
# View all logs
docker compose logs

# Follow logs in real-time
docker compose logs -f

# View logs for a specific service
docker compose logs -f telegraf
docker compose logs -f data_snmp
```

### Service Startup Time

Initial startup may take 2-5 minutes as services initialize databases, create Kafka topics, and establish connections.

### Verify SNMP Collection

Once running, check that Telegraf is successfully collecting SNMP metrics:

```bash
# View Telegraf logs
docker compose logs -f telegraf

# Check for successful SNMP queries - look for messages like:
# "Executed SNMP queries" or "Collected X metrics"
```

If you see SNMP timeout errors, verify:
- Device IP addresses are correct
- SNMP community strings are correct
- Devices are reachable from the collector host
- SNMP port 161 (UDP) is not blocked by firewalls

## 12. Access Grafana

Once services are running and SNMP metrics are being collected, you can visualize the data in Grafana.

### Login to Grafana

1. Open your browser and navigate to: `https://localhost/`
2. Login credentials:
   - **Username:** `admin`
   - **Password:** Located in `grafana/conf/grafana_auth.env`

**Retrieve the password:**
```bash
cat grafana/conf/grafana_auth.env
```

**Note:** The Envoy proxy uses a self-signed certificate by default. Your browser will show a certificate warning — accept it to proceed, or replace the certificates in `envoy/conf/` with ones signed by a trusted CA.

**Important:** Change the default password after your first login via the Grafana UI (User menu → Preferences → Change Password).

### Access ClickHouse (HTTP API)

The ClickHouse HTTP API is accessible via the proxy at `https://localhost/clickhouse`. The native TCP protocol (used by `clickhouse-client` and drivers) remains directly accessible on port **9440**.

### Explore Your Data

You can explore SNMP metrics using Grafana's **Explore** feature:

1. Click the **Explore** icon (compass) in the left sidebar
2. Select the **MetrANOVA ClickHouse** datasource
3. Use the SQL editor to query metric data

**Example Query — latest interface metrics:**
```sql
SELECT
    timestamp,
    source as device,
    snmp_if_name as interface,
    snmp_if_highspeed as speed,
    snmp_if_operStatus as status,
    snmp_if_hcinoctets as bytes_in,
    snmp_if_hcoutoctets as bytes_out
FROM data_snmp
ORDER BY timestamp DESC
LIMIT 100
```

### Security Considerations

The MetrANOVA stack includes an **Envoy reverse proxy** that terminates HTTPS and routes external traffic. By default:

- **Grafana** is accessible at `https://<host>/` via the proxy; port 3000 is not directly exposed.
- **ClickHouse HTTP API** is accessible at `https://<host>/clickhouse` via the proxy; port 8443 is not directly exposed.
- **ClickHouse native port** (9440) is exposed directly since it uses a binary protocol that cannot go through an HTTP proxy.
- A self-signed TLS certificate is generated automatically during `make`. Replace it with a CA-signed certificate for production use.

You can customize proxy behaviour in `docker/config.yml`:

```yaml
datastore:
  use_proxy: false   # Removes ClickHouse from the proxy; port 8443 becomes unreachable externally
  expose_port: true  # Forwards port 8443 directly (useful when proxy is disabled)

dashboard:
  use_proxy: false   # Removes Grafana from the proxy; port 3000 becomes unreachable externally
  expose_port: true  # Forwards port 3000 directly (useful when proxy is disabled)

proxy:
  enabled: false     # Disables Envoy entirely; set expose_port: true on each service to restore access
```

For production deployments, also consider:
- Replacing the self-signed certificate with one from a trusted CA (Let's Encrypt, your organization's PKI)
- Configuring Grafana authentication (LDAP, OAuth, etc.)
- Restricting network access with firewall rules
- Using SNMPv3 with authentication and encryption for sensitive environments
- Storing SNMP community strings in secure vaults rather than configuration files

## 13. Next Steps

Congratulations! You now have a working MetrANOVA SNMP Stack deployment.

### What's Next?

- **Monitor Data Ingestion:** Check that SNMP metrics are being collected from all configured devices
- **Create Custom Dashboards:** Build visualizations tailored to your network devices and metrics
- **Set Up Alerting:** Configure alerts for high utilization, interface errors, or device failures
- **Tune Polling Intervals:** Adjust collection frequency based on your monitoring needs and resource constraints
- **Expand Device Coverage:** Add additional devices by creating more Telegraf configuration files
- **Scale Up:** Migrate to Kubernetes with Helm charts for larger deployments

### Getting Help

If you encounter issues or have questions:

- **GitHub Issues:** [https://github.com/MetrANOVA/stack/issues](https://github.com/MetrANOVA/stack/issues)
- **Community Support:** Reach out to MetrANOVA developers and community

Thank you for using MetrANOVA!
