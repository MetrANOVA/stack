#!/usr/bin/env python3
"""Send basic IPFIX test records to nfacctd via UDP."""

import argparse
import random
import socket
import struct
import time
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

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
    """Generate a random flow based on specification."""
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
    
    return {
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

            # Send template on first record, periodically, or when IP version changes
            send_template = (
                i == 0 or 
                (args.template_every > 0 and i % args.template_every == 0) or
                (flow_specs and last_sent_template_version != ip_version)
            )
            
            if send_template:
                sets = template_set + data_set
                last_sent_template_version = ip_version
            else:
                sets = data_set

            msg = _pack_message(sets, seq, args.obs_domain_id)
            sock.sendto(msg, (args.host, args.port))
            seq += 1
            i += 1
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nSent {i} records before interruption")

    sock.close()


if __name__ == "__main__":
    main()
