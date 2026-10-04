#!/usr/bin/env python3
"""Index live app evidence; keep base acceptance separate from extension success."""
import argparse
import collections
import csv
import gzip
import hashlib
import json
from pathlib import Path
import struct


def timestamp(data, offset, ptp):
    seconds, fraction = struct.unpack_from('!II', data, offset)
    return seconds - (0 if ptp else 2208988800) + fraction / (1e9 if ptp else 2**32)


def audit(case):
    notes = []
    replies = [r for r in case['wire'] if r['direction'] == 'reply']
    requests = [r for r in case['wire'] if r['direction'] == 'request']
    auth = case.get('sender_auth', False)
    prior = None
    for reply in replies:
        data = bytes.fromhex(reply['hex'])
        seq = 48 if auth else 24
        source = next((r for r in requests if bytes.fromhex(r['hex'])[:4] == data[seq:seq+4]), None)
        if source is None or len(data) < (112 if auth else 44):
            continue
        request = bytes.fromhex(source['hex'])
        t1, t2, t3, error = (16, 32, 16, 24) if auth else (4, 16, 4, 12)
        echo_time = 64 if auth else 28
        if data[echo_time:echo_time + 10] != request[t1:t1 + 10]:
            continue  # Wrong packet layout; do not interpret its clock fields.
        sender_error = 24 if auth else 12
        a = timestamp(request, t1, bool(request[sender_error] & 0x40))
        b = timestamp(data, t2, bool(data[error] & 0x40))
        if abs(a - b) > 10:
            notes.append('same-host timestamp epoch/format discrepancy exceeds 10 seconds')
        integrity = any(f['flags'] & 0x20 for f in reply.get('tlvs', []))
        for field in reply.get('tlvs', []):
            if integrity or field['flags'] & 0xe0 or field['truncated']:
                continue
            value = bytes.fromhex(field['value'])
            if field['type'] == 4 and len(value) == 4:
                received_tos = (((value[0] & 3) << 4) | (value[1] >> 4)) * 4 + ((value[1] >> 2) & 3)
                if received_tos != source['tos']:
                    notes.append('CoS received DSCP/ECN report differs from request IP metadata')
                if 'cos_dscp' in case and case.get('group') == 'cos-values':
                    requested = case['cos_dscp'] * 4 + case['cos_ecn']
                    if reply['tos'] != requested:
                        notes.append('reply IP DSCP/ECN differs from requested value')
            if field['type'] == 7 and len(value) == 16 and prior is not None and any(value[:12]):
                if value[:12] != prior[:4] + prior[t3:t3+8]:
                    notes.append('Follow-Up sequence/timestamp does not describe previous captured reply')
        prior = data
    return sorted(set(notes))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    rows = []
    index = {'reports': [], 'totals': {}, 'semantic_audit': {}}
    paths = sorted(list(args.directory.glob('*.json')) + list(args.directory.glob('*.json.gz')))
    for path in paths:
        payload = gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes()
        report = json.loads(payload)
        if not isinstance(report, dict) or 'cases' not in report:
            continue
        if 'expected' not in report:
            continue  # Existing independent fixture runner has a different schema.
        assert len(report['cases']) == report['expected'], f'incomplete report: {path}'
        assert [c['id'] for c in report['cases']] == list(range(report['expected'])), path
        counts = collections.Counter(c['outcome'] for c in report['cases'])
        entry = {'file': path.name, 'uncompressed_sha256': hashlib.sha256(payload).hexdigest(),
                 'file_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                 'expected': report['expected'], 'completed': len(report['cases']),
                 'outcomes': dict(counts), 'runner_sha256': report['runner_sha256'],
                 'started_utc': report['started_utc'], 'completed_utc': report.get('completed_utc')}
        index['reports'].append(entry)
        for case in report['cases']:
            flags = {letter: sorted({f['type'] for r in case['wire'] if r['direction'] == 'reply'
                                     for f in r.get('tlvs', []) if f['flags'] & mask})
                     for letter, mask in [('U', 128), ('M', 64), ('I', 32), ('C', 16)]}
            notes = audit(case)
            if notes:
                stem = path.name.removesuffix('.gz').removesuffix('.json')
                index['semantic_audit'][f'{stem}:{case["id"]}'] = notes
            rows.append({'report': path.name, 'id': case['id'], 'group': case['group'],
                         'sender': case['sender'], 'reflector': case['reflector'],
                         'ip': case.get('ip', '127.0.0.1'),
                         'sender_auth': case.get('sender_auth', False),
                         'reflector_auth': case.get('reflector_auth', 'peer-specific'),
                         'stateful': case.get('stateful', True),
                         'direct': case.get('direct', False),
                         'extensions': '+'.join(case.get('extensions', [])),
                         'outcome': case['outcome'], 'requests_captured': case['requests'],
                         'replies_captured': case['replies'], 'accepted_by_sender': case.get('accepted'),
                         'U_types': ','.join(map(str, flags['U'])),
                         'M_types': ','.join(map(str, flags['M'])),
                         'I_types': ','.join(map(str, flags['I'])),
                         'C_types': ','.join(map(str, flags['C'])),
                         'wire_issues': '; '.join(case['wire_issues']),
                         'semantic_issues': '; '.join(notes),
                         'setup_error': case.get('harness_error', ''),
                         'provision_gap': case.get('provision_gap', ''),
                         'tamper': case.get('tamper', ''),
                         'cos_dscp': case.get('cos_dscp', ''), 'cos_ecn': case.get('cos_ecn', '')})
    index['totals'] = {'attempted_cases': len(rows),
                       'direct_cases': sum(r['direct'] for r in rows),
                       'requests_captured': sum(r['requests_captured'] for r in rows),
                       'replies_captured': sum(r['replies_captured'] for r in rows),
                       'setup_errors': sum(bool(r['setup_error']) for r in rows),
                       'outcomes': dict(collections.Counter(r['outcome'] for r in rows)),
                       'cases_with_integrity_flags': sum(bool(r['I_types']) for r in rows),
                       'cases_with_semantic_audit_findings': len(index['semantic_audit'])}
    with (args.directory / 'results.csv').open('w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (args.directory / 'index.json').write_text(json.dumps(index, indent=2) + '\n')
    print(json.dumps(index['totals'], indent=2))


if __name__ == '__main__':
    main()
