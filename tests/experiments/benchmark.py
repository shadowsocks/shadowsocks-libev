#!/usr/bin/env python3
"""Synthetic uniform-ciphertext screening; not a live censorship measurement."""
import argparse
from collections import Counter
import json
import math
import os
import statistics
import time

from transport import BLOCK, decode, encode


def exemptions(data):
    printable = [0x20 <= value <= 0x7e for value in data]
    popcount = sum(value.bit_count() for value in data) / len(data)
    longest = run = 0
    for value in printable:
        run = run + 1 if value else 0
        longest = max(run, longest)
    return dict(popcount=popcount <= 3.4 or popcount >= 4.6,
                prefix=len(data) >= 6 and all(printable[:6]),
                half=sum(printable) > len(data) / 2, run=longest > 20)


def statistics_for(data):
    counts = Counter(data)
    total = len(data)
    return dict(byte_entropy=-sum(n / total * math.log2(n / total) for n in counts.values()),
                alphabet_size=len(counts), printable_fraction=sum(0x20 <= b <= 0x7e for b in data) / total,
                ones_per_byte=sum(b.bit_count() for b in data) / total)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    payload = os.urandom(1024 * 1024)
    results = []
    for mode in ('raw', 'printable_variable', 'base85', 'lowpop85'):
        def transform(data):
            if mode == 'printable_variable':
                import secrets
                length = 6 + secrets.randbelow(7)
                return bytes(32 + secrets.randbelow(95) for _ in range(length)) + data[length:]
            return encode(mode, data)
        timings = []
        for _ in range(5):
            start = time.perf_counter()
            if mode == 'printable_variable':
                wire = transform(payload)
            else:
                frames = [transform(payload[i:i + BLOCK]) for i in range(0, len(payload), BLOCK)]
                wire = b''.join(frames)
                if mode != 'raw':
                    recovered = b''.join(decode(mode, frame[:-1]) for frame in frames)
                    assert recovered == payload
            timings.append(time.perf_counter() - start)
        passes = Counter()
        for _ in range(2000):
            sample = transform(os.urandom(100))
            rules = exemptions(sample)
            passes.update({key: int(value) for key, value in rules.items()})
            passes['any'] += any(rules.values())
        results.append(dict(mode=mode, synthetic=True, source_bytes=len(payload), wire_bytes=len(wire),
                            overhead_fraction=len(wire) / len(payload) - 1,
                            codec_roundtrip_mib_s=1 / statistics.median(timings) if mode not in ('raw', 'printable_variable') else None,
                            historical_exemption_samples=2000, historical_exemption_passes=dict(passes),
                            **statistics_for(wire)))
    with open(args.output, 'w') as output:
        json.dump(results, output, indent=2)
        output.write('\n')
    for row in results:
        print(row['mode'], 'overhead', round(row['overhead_fraction'] * 100, 2),
              'entropy', round(row['byte_entropy'], 3), 'ones/byte', round(row['ones_per_byte'], 3),
              'historical exemptions', row['historical_exemption_passes']['any'], '/ 2000')


if __name__ == '__main__':
    main()
