#!/usr/bin/env python3
"""Check clause rows against matrix summaries and the README rollup.

This checks evidence bookkeeping, not whether a clause's score is justified.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

STATUSES = ('Compliant', 'Partial', 'Gap', 'N-A', 'Excluded')
MATRICES = ('rfc8762', 'rfc8972', 'rfc9503', 'rfc9534', 'rfc8545',
            'draft-asymmetrical-pkts', 'draft-stamp-cos-ecn',
            'draft-stamp-ext-hdr', 'draft-stamp-ber')


def cells(line):
    return [c.strip() for c in re.split(r'(?<!\\)\|', line)[1:-1]]


def check(root):
    directory = Path(root) / 'doc/conformance'
    problems, counts = [], {}
    for name in MATRICES:
        path = directory / (name + '.md')
        if not path.is_file():
            problems.append(f'{path.name}: missing matrix')
            continue
        counter, ids, status_index = Counter(), set(), None
        lines = path.read_text().splitlines()
        for number, line in enumerate(lines, 1):
            row = cells(line)
            if 'Status' in row and row[0].startswith(('ID', 'Clause')):
                status_index = row.index('Status')
                continue
            if not row or not re.match(r'(?:RFC\d+|\d{4}|asym|cos-ecn|ext-hdr|ber)-', row[0]):
                continue
            if row[0] in ids:
                problems.append(f'{path.name}:{number}: duplicate clause {row[0]}')
            ids.add(row[0])
            if status_index is None or len(row) <= status_index:
                problems.append(f'{path.name}:{number}: missing Status column')
                continue
            status = row[status_index].split(' (')[0].replace('N/A', 'N-A')
            if status not in STATUSES:
                problems.append(f'{path.name}:{number}: unknown status {status!r}')
            else:
                counter[status] += 1
        actual = [sum(counter.values())] + [counter[s] for s in STATUSES]
        counts[path.name] = actual
        if not ids:
            problems.append(f'{path.name}: no clause rows')
        summaries = [line for line in lines if line.startswith('Summary:')]
        if len(summaries) != 1:
            problems.append(f'{path.name}: expected one Summary line')
        for line in summaries + [line for line in lines if line.startswith('Counts:')]:
            total = re.search(r'(\d+) clauses', line)
            declared = Counter()
            for count, status in re.findall(r'(\d+) (Compliant|Partial|Gap|N-A|Excluded)', line):
                declared[status] += int(count)
            expected = ([int(total[1])] if total else [-1]) + [declared[s] for s in STATUSES]
            if expected != actual:
                problems.append(f'{path.name}: {line.split(":")[0]} {expected} != rows {actual}')
    rollup = directory / 'README.md'
    if not rollup.is_file():
        problems.append('README.md: missing rollup')
    else:
        seen = set()
        total_seen = 0
        for line in rollup.read_text().splitlines():
            row = cells(line)
            if not row:
                continue
            link = re.search(r'\]\(([^)]+\.md)\)', row[0])
            is_total = row[0] == '**Total**'
            if not is_total and (not link or link[1] not in counts):
                continue
            if is_total:
                total_seen += 1
                actual = [sum(v[i] for v in counts.values()) for i in range(6)]
            else:
                if link[1] in seen:
                    problems.append(f'README.md: duplicate row {link[1]}')
                seen.add(link[1])
                actual = counts[link[1]]
            try:
                declared = [int(cell.strip('*')) for cell in row[2:]]
            except ValueError:
                declared = []
            if actual != declared:
                problems.append(f'README.md: {row[0]} {declared} != rows {actual}')
        if total_seen != 1:
            problems.append('README.md: expected one Total row')
        for missing in counts.keys() - seen:
            problems.append(f'README.md: missing row {missing}')
    return {'matrices': counts, 'problems': problems}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    result = check(args.root)
    print(json.dumps(result, indent=2) if args.json else '\n'.join(result['problems']) or 'Conformance counts match clause rows.')
    return bool(result['problems'])


if __name__ == '__main__':
    raise SystemExit(main())
