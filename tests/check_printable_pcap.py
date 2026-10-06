#!/usr/bin/env python3
"""Summarize actual first TCP payloads in a tcpdump pcap (IPv4).

Requires a captured SYN before accepting a flow's first payload. Never treats
application writes or socket recv boundaries as TCP packet boundaries.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import socket
import struct


def initial_payloads(path, ports, require_sequence=False):
    with Path(path).open('rb') as stream:
        header = stream.read(24)
        formats = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\xa1\xb2\xc3\xd4': ('>', 1e6),
                   b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
        endian, scale = formats[header[:4]]
        link = struct.unpack(endian + 'I', header[20:24])[0]
        offset = {0: 4, 1: 14, 113: 16, 276: 20}[link]
        flows = {}
        while raw := stream.read(16):
            sec, frac, length, _ = struct.unpack(endian + 'IIII', raw)
            packet = stream.read(length)
            ip = packet[offset:]
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
                continue
            ihl = (ip[0] & 15) * 4
            total_length = int.from_bytes(ip[2:4], 'big')
            tcp = ip[ihl:total_length]
            if len(tcp) < 20:
                continue
            src, dst, seq = struct.unpack('!HHI', tcp[:8])
            if dst not in ports:
                continue
            flow = (socket.inet_ntoa(ip[12:16]), src, socket.inet_ntoa(ip[16:20]), dst)
            flags = tcp[13]
            if flags & 2 and not flags & 16:
                flows.setdefault(flow, (seq + 1) & 0xffffffff)
            payload = tcp[(tcp[12] >> 4) * 4:]
            if payload and flow in flows:
                expected = flows[flow]
                if require_sequence and seq != expected:
                    continue
                flows.pop(flow)
                # Require sequence correspondence: dropped first data cannot pass.
                yield dict(time=sec + frac / scale, source=flow[0], port=dst,
                           sequence_ok=seq == expected, prefix=payload[:6].hex(),
                           payload_hex=payload.hex(),
                           payload_complete=len(ip) >= total_length,
                           printable=len(payload) >= 6 and all(0x20 <= b <= 0x7e for b in payload[:6]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pcap')
    parser.add_argument('--ports', nargs='+', type=int, required=True)
    parser.add_argument('--events', help='crossover JSONL to attribute port/mode by phase')
    args = parser.parse_args()
    events = [json.loads(line) for line in Path(args.events).read_text().splitlines()] if args.events else []
    boundary = None
    ports = args.ports
    if events:
        from datetime import datetime
        boundary = next((datetime.fromisoformat(e['utc'].replace('Z', '+00:00')).timestamp()
                         for e in events if e['event'] == 'phase_complete' and e['phase'] == 1), None)
    counts = Counter()
    for flow in initial_payloads(args.pcap, ports):
        if flow['source'].startswith('127.'):
            continue
        phase = 2 if boundary is not None and flow['time'] >= boundary else 1
        mode = 'modified' if flow['port'] == ports[1 if phase == 1 else 0] else 'stock'
        counts[f"phase{phase}/{mode}/total"] += 1
        counts[f"phase{phase}/{mode}/printable"] += flow['printable']
        counts[f"phase{phase}/{mode}/sequence_ok"] += flow['sequence_ok']
    print(json.dumps(dict(counts), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
