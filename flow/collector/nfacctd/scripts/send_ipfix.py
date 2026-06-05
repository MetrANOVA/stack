#!/usr/bin/env python3
"""Send basic IPFIX test records to nfacctd via UDP."""

import argparse
import socket
import struct
import time
from ipaddress import ip_address

IPFIX_VERSION = 10
TEMPLATE_SET_ID = 2
DEFAULT_TEMPLATE_ID = 256

FIELDS = [
    # (field_id, length)
    (8, 4),    # sourceIPv4Address
    (12, 4),   # destinationIPv4Address
    (7, 2),    # sourceTransportPort
    (11, 2),   # destinationTransportPort
    (4, 1),    # protocolIdentifier
    (2, 8),    # packetDeltaCount
    (1, 8),    # octetDeltaCount
    (152, 8),  # flowStartMilliseconds
    (153, 8),  # flowEndMilliseconds
]


def _pack_template(template_id: int) -> bytes:
    field_count = len(FIELDS)
    record = struct.pack("!HH", template_id, field_count)
    for field_id, length in FIELDS:
        record += struct.pack("!HH", field_id, length)
    set_length = 4 + len(record)
    return struct.pack("!HH", TEMPLATE_SET_ID, set_length) + record


def _pack_data_record(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> bytes:
    now_ms = int(time.time() * 1000)
    end_ms = now_ms + 1000
    packet_count = 1
    octet_count = 128

    data = (
        ip_address(src_ip).packed
        + ip_address(dst_ip).packed
        + struct.pack("!H", src_port)
        + struct.pack("!H", dst_port)
        + struct.pack("!B", proto)
        + struct.pack("!Q", packet_count)
        + struct.pack("!Q", octet_count)
        + struct.pack("!Q", now_ms)
        + struct.pack("!Q", end_ms)
    )

    # Pad to 4-byte boundary.
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
    parser.add_argument("--host", default="localhost", help="Collector host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9996, help="Collector UDP port (default: 9996)")
    parser.add_argument("--count", type=int, default=10, help="Number of records to send (default: 10)")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between records (default: 0.5)")
    parser.add_argument("--template-id", type=int, default=DEFAULT_TEMPLATE_ID, help="Template ID (default: 256)")
    parser.add_argument("--template-every", type=int, default=20, help="Send template every N records (default: 20)")
    parser.add_argument("--src-ip", default="192.0.2.10", help="Source IP (default: 192.0.2.10)")
    parser.add_argument("--dst-ip", default="198.51.100.20", help="Destination IP (default: 198.51.100.20)")
    parser.add_argument("--src-port", type=int, default=12345, help="Source port (default: 12345)")
    parser.add_argument("--dst-port", type=int, default=443, help="Destination port (default: 443)")
    parser.add_argument("--proto", type=int, default=6, help="IP protocol number (default: 6 for TCP)")
    parser.add_argument("--obs-domain-id", type=int, default=0, help="Observation domain ID (default: 0)")

    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0

    template_set = _pack_template(args.template_id)

    for i in range(args.count):
        record = _pack_data_record(args.src_ip, args.dst_ip, args.src_port, args.dst_port, args.proto)
        data_set = _pack_data_set(args.template_id, record)

        sets = data_set
        if i == 0 or (args.template_every > 0 and i % args.template_every == 0):
            sets = template_set + data_set

        msg = _pack_message(sets, seq, args.obs_domain_id)
        sock.sendto(msg, (args.host, args.port))
        seq += 1
        time.sleep(args.interval)

    sock.close()


if __name__ == "__main__":
    main()
