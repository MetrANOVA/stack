#!/usr/bin/env python3
"""Send basic sFlow v5 sample datagrams to sfacctd via UDP."""

import argparse
import socket
import struct
import time
from ipaddress import ip_address

SFLOW_VERSION = 5
SAMPLE_TYPE_FLOW = 1
SAMPLE_FORMAT_FLOW = 1
RECORD_TYPE_RAW = 1


def _pack_header(agent_ip: str, seq: int, uptime_ms: int, samples: bytes) -> bytes:
    agent_addr = ip_address(agent_ip).packed
    return struct.pack(
        "!II4sIIII",
        SFLOW_VERSION,
        1,  # IPv4
        agent_addr,
        0,  # sub-agent id
        seq,
        uptime_ms,
        1,  # sample count
    ) + samples


def _pack_raw_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> tuple[bytes, int]:
    # Minimal Ethernet + IPv4 + UDP header (no payload).
    eth_header = b"\x00" * 12 + b"\x08\x00"
    total_len = 20 + 8
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        0,
        0,
        64,
        proto,
        0,
        ip_address(src_ip).packed,
        ip_address(dst_ip).packed,
    )
    l4_header = struct.pack("!HHHH", src_port, dst_port, 8, 0)
    packet = eth_header + ip_header + l4_header
    raw_len = len(packet)
    pad_len = (-raw_len) % 4
    if pad_len:
        packet += b"\x00" * pad_len
    return packet, raw_len


def _pack_flow_record(raw_packet: bytes, raw_len: int) -> bytes:
    # raw packet record: header_protocol(1=ETHERNET), frame_length, stripped, header_length, header_bytes
    payload = struct.pack("!IIII", 1, raw_len, 0, raw_len) + raw_packet
    record_header = struct.pack("!II", RECORD_TYPE_RAW, len(payload))
    return record_header + payload


def _pack_flow_sample(seq: int, sampling_rate: int, sample_pool: int, drops: int, record: bytes) -> bytes:
    # Flow sample has 8 uint32 fields before the records (32 bytes).
    sample_header = struct.pack("!II", SAMPLE_TYPE_FLOW, 32 + len(record))
    # sequence, source_id, sampling_rate, sample_pool, drops, input, output, record_count
    payload = struct.pack("!IIIIIIII", seq, 0, sampling_rate, sample_pool, drops, 0, 0, 1)
    return sample_header + payload + record


def main() -> None:
    parser = argparse.ArgumentParser(description="Send sFlow test data to sfacctd.")
    parser.add_argument("--host", default="localhost", help="Collector host (default: localhost)")
    parser.add_argument("--port", type=int, default=9997, help="Collector UDP port (default: 9997)")
    parser.add_argument("--count", type=int, default=10, help="Number of samples to send (default: 10)")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between samples (default: 0.5)")
    parser.add_argument("--agent-ip", default="192.0.2.1", help="Agent IP address (default: 192.0.2.1)")
    parser.add_argument("--src-ip", default="192.0.2.10", help="Source IP (default: 192.0.2.10)")
    parser.add_argument("--dst-ip", default="198.51.100.20", help="Destination IP (default: 198.51.100.20)")
    parser.add_argument("--src-port", type=int, default=12345, help="Source port (default: 12345)")
    parser.add_argument("--dst-port", type=int, default=443, help="Destination port (default: 443)")
    parser.add_argument("--proto", type=int, default=17, help="IP protocol number (default: 17 for UDP)")
    parser.add_argument("--sampling-rate", type=int, default=1, help="Sampling rate (default: 1)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start = time.time()

    for i in range(args.count):
        raw_packet, raw_len = _pack_raw_packet(
            args.src_ip,
            args.dst_ip,
            args.src_port,
            args.dst_port,
            args.proto,
        )
        record = _pack_flow_record(raw_packet, raw_len)
        sample = _pack_flow_sample(i + 1, args.sampling_rate, i + 1, 0, record)
        uptime_ms = int((time.time() - start) * 1000)
        msg = _pack_header(args.agent_ip, i + 1, uptime_ms, sample)
        sock.sendto(msg, (args.host, args.port))
        time.sleep(args.interval)

    sock.close()


if __name__ == "__main__":
    main()
