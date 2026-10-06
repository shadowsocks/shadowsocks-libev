#!/usr/bin/env python3
"""Summarize transport screening and captured first TCP payloads."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime
import json
import hashlib
from pathlib import Path
import statistics
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_printable_pcap import initial_payloads  # noqa: E402
from benchmark import exemptions  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    args = parser.parse_args()
    root = Path(args.directory)
    protocol = json.loads((root / 'protocol.json').read_text())
    events = [json.loads(line) for line in (root / 'events.jsonl').read_text().splitlines()]
    phases = [(datetime.fromisoformat(e['utc'].replace('Z', '+00:00')).timestamp(), e)
              for e in events if e['event'] == 'phase_start']
    summary = dict(protocol=protocol, complete=any(e['event'] == 'complete' for e in events),
                   aborts=[e for e in events if e['event'] == 'aborted'],
                   completed_phases=sum(e['event'] == 'phase_complete' for e in events),
                   outcome_logging_limit='Runs before the durable-outcome fix can omit in-flight outcomes at abort.',
                   health_checks=sum(e['event'] in ('health', 'phase_start') for e in events),
                   health_failures=sum(e.get('healthy') is False for e in events), modes={})
    for mode in protocol['modes']:
        records = [e for e in events if e.get('mode') == mode and e['event'] == 'transfer']
        small = [e['seconds'] * 1000 for e in records if e['size'] == 1024 and e['success']]
        large = [e['mbps'] for e in records if e['size'] > 1024 and e['success']]
        summary['modes'][mode] = dict(recorded_outcomes=len(records), success=sum(e['success'] for e in records),
            errors=[e for e in records if not e['success']],
            small_median_ms=statistics.median(small) if small else None,
            small_p95_ms=sorted(small)[min(len(small) - 1, int(len(small) * .95))] if small else None,
            large_median_mbps=statistics.median(large) if large else None)
    expected_source = next((e.get('client_address') for e in events if e['event'] == 'start'), None)
    for filename in ('client.pcap', 'remote-server.pcap'):
        counts = defaultdict(Counter)
        flows = list(initial_payloads(root / filename, protocol['ports']))
        external = [f for f in flows if not f['source'].startswith('127.')]
        source = expected_source if filename.startswith('remote-') else None
        if source is None and external:
            source = Counter(f['source'] for f in external).most_common(1)[0][0]
        unexpected = [f for f in external if f['source'] != source]
        replays = []
        for probe in unexpected:
            matches = [f for f in external if f['source'] == source and f['time'] < probe['time']
                       and f['port'] == probe['port'] and f['payload_hex'] == probe['payload_hex']
                       and f['payload_complete'] and probe['payload_complete']]
            if matches:
                original_phase = [event for stamp, event in phases if stamp <= matches[-1]['time']][-1]
                replay_mode = original_phase['port_modes'][protocol['ports'].index(probe['port'])]
                replays.append(dict(mode=replay_mode, phase=original_phase['phase'], port=probe['port'], delay_seconds=probe['time'] - matches[-1]['time'],
                    payload_bytes=len(bytes.fromhex(probe['payload_hex'])),
                    payload_sha256=hashlib.sha256(bytes.fromhex(probe['payload_hex'])).hexdigest()))
        summary[filename + '/unsolicited'] = dict(connections=len(unexpected), exact_replays=replays)
        for flow in flows:
            if flow['source'] != source:
                continue
            previous = [event for stamp, event in phases if stamp <= flow['time']]
            if not previous:
                continue
            phase = previous[-1]
            mode = phase['port_modes'][protocol['ports'].index(flow['port'])]
            values = counts[mode]
            values['connections'] += 1
            values['sequence_ok'] += flow['sequence_ok']
            values['complete_first_payload'] += flow['payload_complete']
            payload = bytes.fromhex(flow['payload_hex'])
            rules = exemptions(payload)
            rules['tls_header'] = len(payload) >= 3 and payload[0] in (22, 23) and payload[1] == 3 and payload[2] <= 9
            if flow['payload_complete']:
                values['historical_exemption'] += any(rules.values())
                for rule, passed in rules.items():
                    values[rule] += passed
        summary[filename] = {mode: dict(values) for mode, values in counts.items()}
        stream_counts = defaultdict(Counter)
        for flow in initial_payloads(root / filename, protocol['ports'], require_sequence=True):
            if flow['source'] != source:
                continue
            previous = [event for stamp, event in phases if stamp <= flow['time']]
            if not previous:
                continue
            mode = previous[-1]['port_modes'][protocol['ports'].index(flow['port'])]
            payload = bytes.fromhex(flow['payload_hex'])
            rules = exemptions(payload)
            tls = len(payload) >= 3 and payload[0] in (22, 23) and payload[1] == 3 and payload[2] <= 9
            stream_counts[mode]['connections'] += 1
            stream_counts[mode]['complete_first_payload'] += flow['payload_complete']
            if flow['payload_complete']:
                stream_counts[mode]['historical_exemption'] += any(rules.values()) or tls
        summary[filename + '/stream_start'] = {mode: dict(values) for mode, values in stream_counts.items()}
    (root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
