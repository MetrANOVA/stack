#!/usr/bin/env python3
"""Send IPFIX test records to nfacctd via UDP.

Supports normal UDP mode and raw socket mode with IP spoofing to simulate
different router/exporter IPs. Raw socket mode requires root privileges.

When using config mode (--config), templates are sent with every record to ensure
nfacctd receives them before processing data records, especially important with
fast intervals (--interval 0). This is safe and expected behavior in IPFIX.

Usage:
    # Normal mode (UDP source IP is the exporter)
    python3 send_ipfix.py --host localhost --port 9996 --count 100
    
    # Config mode with YAML file (templates sent with every record)
    python3 send_ipfix.py --config flows.yaml --host localhost --port 9996 \\
        --count 100000 --interval 0
    
    # Raw socket mode with IP spoofing (requires root)
    sudo python3 send_ipfix.py --host localhost --port 9996 \\
        --exporter-ip 203.0.113.10 --count 100
"""

import argparse
import os
import random
import socket
import struct
import time
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:
    yaml = None

IPFIX_VERSION = 10
TEMPLATE_SET_ID = 2
DEFAULT_TEMPLATE_ID_V4 = 256
DEFAULT_TEMPLATE_ID_V6 = 257

# IPv4 template fields
FIELDS_V4 = [
    # (field_id, length)
    (8, 4),    # sourceIPv4Address
    (12, 4),   # destinationIPv4Address
    (7, 2),    # sourceTransportPort
    (11, 2),   # destinationTransportPort
    (4, 1),    # protocolIdentifier
    (10, 4),   # ingressInterface
    (14, 4),   # egressInterface
    (2, 8),    # packetDeltaCount
    (1, 8),    # octetDeltaCount
    (152, 8),  # flowStartMilliseconds
    (153, 8),  # flowEndMilliseconds
    (34, 4),   # samplingInterval (1 = unsampled; required for nfacctd_renormalize)
]

# IPv6 template fields
FIELDS_V6 = [
    # (field_id, length)
    (27, 16),  # sourceIPv6Address
    (28, 16),  # destinationIPv6Address
    (7, 2),    # sourceTransportPort
    (11, 2),   # destinationTransportPort
    (4, 1),    # protocolIdentifier
    (10, 4),   # ingressInterface
    (14, 4),   # egressInterface
    (2, 8),    # packetDeltaCount
    (1, 8),    # octetDeltaCount
    (152, 8),  # flowStartMilliseconds
    (153, 8),  # flowEndMilliseconds
    (34, 4),   # samplingInterval (1 = unsampled; required for nfacctd_renormalize)
]

PROTOCOL_MAP = {
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
    "icmpv6": 58,
}


def _pack_template(template_id: int, fields: list) -> bytes:
    field_count = len(fields)
    record = struct.pack("!HH", template_id, field_count)
    for field_id, length in fields:
        record += struct.pack("!HH", field_id, length)
    set_length = 4 + len(record)
    return struct.pack("!HH", TEMPLATE_SET_ID, set_length) + record


def parse_speed(speed_str: str) -> float:
    """Parse speed string like '1Mbps', '100Gbps' to bytes per second."""
    speed_str = speed_str.strip().lower()
    
    # Extract number and unit
    import re
    match = re.match(r"([\d.]+)\s*([kmgt]?)b(?:ps)?", speed_str)
    if not match:
        raise ValueError(f"Invalid speed format: {speed_str}")
    
    value = float(match.group(1))
    unit = match.group(2)
    
    multipliers = {
        "": 1,
        "k": 1_000,
        "m": 1_000_000,
        "g": 1_000_000_000,
        "t": 1_000_000_000_000,
    }
    
    # Convert bits per second to bytes per second
    return value * multipliers[unit] / 8


def random_ip_from_subnet(subnet_str: str) -> str:
    """Generate a random IP address from a subnet."""
    net = ip_network(subnet_str, strict=False)
    # Get a random host from the network
    num_addresses = net.num_addresses
    if num_addresses == 1:
        return str(net.network_address)
    # Skip network and broadcast for IPv4
    if net.version == 4 and num_addresses > 2:
        random_offset = random.randint(1, num_addresses - 2)
    else:
        random_offset = random.randint(0, num_addresses - 1)
    return str(net.network_address + random_offset)


def parse_protocol(proto: Any) -> int:
    """Parse protocol (string or int) to protocol number."""
    if isinstance(proto, int):
        return proto
    proto_str = str(proto).lower()
    if proto_str in PROTOCOL_MAP:
        return PROTOCOL_MAP[proto_str]
    # Try to parse as integer
    try:
        return int(proto_str)
    except ValueError:
        raise ValueError(f"Unknown protocol: {proto}")


def generate_flow_from_spec(spec: dict) -> dict:
    """Generate a random flow based on specification.
    
    Returns a dict with flow data including optional exporter_ip if defined in spec.
    """
    # Select random source IP from subnets
    src_subnet = random.choice(spec["source_ip"])
    src_ip = random_ip_from_subnet(src_subnet)
    
    # Select random destination IP from subnets
    dst_subnet = random.choice(spec["destination_ip"])
    dst_ip = random_ip_from_subnet(dst_subnet)
    
    # Select random ports
    src_port_spec = spec["source_port"][0]
    src_port = random.randint(src_port_spec["min"], src_port_spec["max"])
    
    dst_port_spec = spec["destination_port"][0]
    dst_port = random.randint(dst_port_spec["min"], dst_port_spec["max"])
    
    # Select random protocol
    proto = parse_protocol(random.choice(spec["protocol"]))
    
    # Get interface indices
    in_interface = spec.get("in_interface_index", 0)
    out_interface = spec.get("out_interface_index", 0)
    
    # Generate traffic parameters
    traffic = spec["traffic"]
    
    # Random speed within range
    min_speed = parse_speed(traffic["speed"]["min"])
    max_speed = parse_speed(traffic["speed"]["max"])
    speed_bps = random.uniform(min_speed, max_speed)
    
    # Random packet size
    packet_size = random.randint(
        traffic["packet_size"]["min"],
        traffic["packet_size"]["max"]
    )
    
    # Random duration
    duration = random.uniform(
        traffic["duration"]["min"],
        traffic["duration"]["max"]
    )
    
    # Calculate total bytes and packets
    total_bytes = int(speed_bps * duration)
    packet_count = max(1, total_bytes // packet_size)
    # Adjust total bytes to match packet count
    total_bytes = packet_count * packet_size
    
    # Ensure values fit in uint64 (max value: 2^64 - 1)
    MAX_UINT64 = 2**64 - 1
    if total_bytes > MAX_UINT64:
        total_bytes = MAX_UINT64
        packet_count = max(1, total_bytes // packet_size)
    if packet_count > MAX_UINT64:
        packet_count = MAX_UINT64
    
    flow = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "in_interface": in_interface,
        "out_interface": out_interface,
        "packet_count": packet_count,
        "octet_count": total_bytes,
        "duration_ms": int(duration * 1000),
    }
    
    # Include exporter_ip if defined in spec
    if "exporter_ip" in spec:
        flow["exporter_ip"] = spec["exporter_ip"]
    
    return flow


def _pack_data_record(flow: dict, fields: list) -> bytes:
    """Pack flow data based on template fields."""
    now_ms = int(time.time() * 1000)
    end_ms = now_ms + flow.get("duration_ms", 1000)
    
    src_ip_obj = ip_address(flow["src_ip"])
    dst_ip_obj = ip_address(flow["dst_ip"])
    
    data = b""
    
    for field_id, length in fields:
        if field_id == 8:  # sourceIPv4Address
            data += src_ip_obj.packed
        elif field_id == 12:  # destinationIPv4Address
            data += dst_ip_obj.packed
        elif field_id == 27:  # sourceIPv6Address
            data += src_ip_obj.packed
        elif field_id == 28:  # destinationIPv6Address
            data += dst_ip_obj.packed
        elif field_id == 7:  # sourceTransportPort
            data += struct.pack("!H", flow["src_port"])
        elif field_id == 11:  # destinationTransportPort
            data += struct.pack("!H", flow["dst_port"])
        elif field_id == 4:  # protocolIdentifier
            data += struct.pack("!B", flow["proto"])
        elif field_id == 10:  # ingressInterface
            data += struct.pack("!I", flow.get("in_interface", 0))
        elif field_id == 14:  # egressInterface
            data += struct.pack("!I", flow.get("out_interface", 0))
        elif field_id == 2:  # packetDeltaCount
            data += struct.pack("!Q", flow["packet_count"])
        elif field_id == 1:  # octetDeltaCount
            data += struct.pack("!Q", flow["octet_count"])
        elif field_id == 152:  # flowStartMilliseconds
            data += struct.pack("!Q", now_ms)
        elif field_id == 153:  # flowEndMilliseconds
            data += struct.pack("!Q", end_ms)
        elif field_id == 34:   # samplingInterval: 1 = every packet (unsampled)
            data += struct.pack("!I", flow.get("sampling_interval", 1))
    
    # Pad to 4-byte boundary
    pad_len = (-len(data)) % 4
    if pad_len:
        data += b"\x00" * pad_len
    return data


def _pack_data_set(template_id: int, record: bytes) -> bytes:
    set_length = 4 + len(record)
    return struct.pack("!HH", template_id, set_length) + record


def _pack_message(sets: bytes, seq: int, obs_domain_id: int) -> bytes:
    export_time = int(time.time())
    length = 16 + len(sets)
    header = struct.pack("!HHIII", IPFIX_VERSION, length, export_time, seq, obs_domain_id)
    return header + sets


def _compute_ip_checksum(header: bytes) -> int:
    """Compute IP header checksum."""
    checksum = 0
    for i in range(0, len(header), 2):
        checksum += int.from_bytes(header[i:i+2], 'big')
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def _build_raw_ipv4_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    """Build a raw IPv4 UDP packet with spoofed source IP."""
    # IP header
    version_ihl = (4 << 4) | 5  # IPv4, header length 5 (20 bytes)
    dscp_ecn = 0
    total_length = 20 + 8 + len(payload)  # IP header + UDP header + payload
    identification = random.randint(0, 0xFFFF)
    flags_fragment_offset = 0  # No fragmentation
    ttl = 64
    protocol = 17  # UDP
    
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    
    # Build IP header without checksum first
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        0,  # Checksum (will be filled)
        src_ip_bytes,
        dst_ip_bytes
    )
    
    # Calculate IP checksum
    ip_checksum = _compute_ip_checksum(ip_header)
    
    # Rebuild IP header with checksum
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        ip_checksum,
        src_ip_bytes,
        dst_ip_bytes
    )
    
    # UDP header — checksum=0 means "disabled" (valid per RFC 768 for IPv4 UDP)
    udp_length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)

    return ip_header + udp_header + payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Send IPFIX test data to nfacctd.")
    parser.add_argument("--config", type=str, help="YAML config file defining flow patterns")
    parser.add_argument("--host", default="localhost", help="Collector host (default: localhost)")
    parser.add_argument("--port", type=int, default=9996, help="Collector UDP port (default: 9996)")
    parser.add_argument("--count", type=int, default=-1, help="Number of records to send, -1 for continuous (default: -1)")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between records (default: 0.5)")
    parser.add_argument("--template-id-v4", type=int, default=DEFAULT_TEMPLATE_ID_V4, help="Template ID for IPv4 (default: 256)")
    parser.add_argument("--template-id-v6", type=int, default=DEFAULT_TEMPLATE_ID_V6, help="Template ID for IPv6 (default: 257)")
    parser.add_argument("--template-every", type=int, default=20, help="Send template every N records (default: 20)")
    parser.add_argument("--src-ip", default="192.0.2.10", help="Source IP (default: 192.0.2.10)")
    parser.add_argument("--dst-ip", default="198.51.100.20", help="Destination IP (default: 198.51.100.20)")
    parser.add_argument("--src-port", type=int, default=12345, help="Source port (default: 12345)")
    parser.add_argument("--dst-port", type=int, default=443, help="Destination port (default: 443)")
    parser.add_argument("--proto", type=int, default=6, help="IP protocol number (default: 6 for TCP)")
    parser.add_argument("--obs-domain-id", type=int, default=0, help="Observation domain ID (default: 0)")
    parser.add_argument("--exporter-ip", type=str, default=None, help="Spoof exporter/router IP via raw sockets (requires root). Can also be specified per-flow in YAML config. If not set, uses actual sender IP.")

    args = parser.parse_args()

    # Load config file if provided
    flow_specs = None
    if args.config:
        if yaml is None:
            print("Error: PyYAML is required for config file support. Install with: pip install pyyaml")
            return
        
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {args.config}")
            return
        
        with open(config_path) as f:
            config = yaml.safe_load(f)
            flow_specs = config.get("flows", [])
            if not flow_specs:
                print("Error: No flows defined in config file")
                return
        
        print(f"Loaded {len(flow_specs)} flow specifications from {args.config}")

    # Resolve hostname to IP address for use in both normal and raw socket modes
    try:
        resolved_host_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{args.host}'")
        return
    
    # Determine whether raw socket mode is needed — either CLI flag or any YAML flow spec
    yaml_has_exporter_ip = flow_specs and any("exporter_ip" in s for s in flow_specs)
    use_raw_socket = args.exporter_ip is not None or yaml_has_exporter_ip
    
    if use_raw_socket:
        # Check if destination is localhost/loopback and warn user FIRST
        # (before checking privileges, since this is a logic error not privilege error)
        # Validate all exporter IPs are IPv4 — the raw socket outer packet is always IPv4
        all_exporter_ips = []
        if args.exporter_ip:
            all_exporter_ips.append(args.exporter_ip)
        if flow_specs:
            all_exporter_ips.extend(s["exporter_ip"] for s in flow_specs if "exporter_ip" in s)
        for eip in all_exporter_ips:
            if ip_address(eip).version == 6:
                print(f"Error: exporter_ip must be an IPv4 address (got {eip})")
                print(f"       The raw socket transport is IPv4-only. The flows it carries")
                print(f"       can report IPv6 addresses as field values.")
                return

        is_loopback = resolved_host_ip.startswith("127.") or resolved_host_ip == "::1"
        if is_loopback:
            print(f"Error: --exporter-ip does not work with localhost/loopback ({resolved_host_ip})")
            print(f"       Raw socket mode with spoofed IPs does not work reliably with loopback.")
            print(f"       The Linux kernel filters these packets at the routing level.")
            print(f"\nSuggested fixes:")
            print(f"1. Remove exporter_ip from your YAML / --exporter-ip from CLI")
            print(f"2. Use the actual container/service IP instead of localhost")
            print(f"3. Create a virtual interface with your desired IP and use that")
            return
        
        if os.geteuid() != 0:
            print("Error: exporter_ip (via --exporter-ip or YAML) requires root privileges")
            return
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    seq = 0

    # Determine which template to use (IPv4 or IPv6)
    # For manual mode, check the provided IPs
    if flow_specs is None:
        src_ip_obj = ip_address(args.src_ip)
        ip_version = src_ip_obj.version
        fields = FIELDS_V6 if ip_version == 6 else FIELDS_V4
        template_id = args.template_id_v6 if ip_version == 6 else args.template_id_v4
        template_set = _pack_template(template_id, fields)
    else:
        ip_version = None
        fields = None
        template_id = None
        template_set = None

    continuous_mode = args.count < 0
    i = 0
    last_sent_template_version = None
    
    try:
        while continuous_mode or i < args.count:
            if flow_specs:
                # Generate random flow from one of the specs
                spec = random.choice(flow_specs)
                flow = generate_flow_from_spec(spec)
                
                # Determine IP version and use appropriate template
                src_ip_obj = ip_address(flow["src_ip"])
                ip_version = src_ip_obj.version
                fields = FIELDS_V6 if ip_version == 6 else FIELDS_V4
                template_id = args.template_id_v6 if ip_version == 6 else args.template_id_v4
                template_set = _pack_template(template_id, fields)
                
                record = _pack_data_record(flow, fields)
            else:
                # Manual mode - use command line args
                flow = {
                    "src_ip": args.src_ip,
                    "dst_ip": args.dst_ip,
                    "src_port": args.src_port,
                    "dst_port": args.dst_port,
                    "proto": args.proto,
                    "in_interface": 0,
                    "out_interface": 0,
                    "packet_count": 1,
                    "octet_count": 128,
                    "duration_ms": 1000,
                }
                record = _pack_data_record(flow, fields)
            
            data_set = _pack_data_set(template_id, record)

            # Determine if we should send template with this record
            if flow_specs:
                # Config mode: always send template with every record to ensure nfacctd
                # receives it before processing data, especially critical with --interval 0
                # Templates are small and IPFIX collectors expect frequent resets
                send_template = True
            else:
                # Manual mode: send template on first record and periodically
                send_template = (i == 0 or 
                                 (args.template_every > 0 and i % args.template_every == 0))
            
            if send_template:
                sets = template_set + data_set
                last_sent_template_version = ip_version
            else:
                sets = data_set

            msg = _pack_message(sets, seq, args.obs_domain_id)
            
            # Determine which exporter IP to use (precedence: CLI > per-flow > default None)
            exporter_ip = args.exporter_ip or flow.get("exporter_ip")
            
            if exporter_ip:
                # Send via raw socket with spoofed source IP.
                # The outer IPv4 packet carries any IPFIX message regardless of whether
                # the observed flows inside are IPv4 or IPv6.
                raw_packet = _build_raw_ipv4_packet(
                    src_ip=exporter_ip,
                    dst_ip=resolved_host_ip,
                    src_port=random.randint(49152, 65535),  # Random ephemeral port
                    dst_port=args.port,
                    payload=msg
                )
                sock.sendto(raw_packet, (resolved_host_ip, 0))  # 0 for protocol field when using raw socket
            else:
                # Send via standard UDP socket
                sock.sendto(msg, (args.host, args.port))
            
            seq += 1
            i += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nSent {i} records before interruption")

    sock.close()


if __name__ == "__main__":
    main()
