#!/usr/bin/env python3
"""Run exactly one Cargo test artifact, rejecting empty or wrong-backend suites.

Usage: run_privileged_test.py ARTIFACTS.json TARGET EXPECTED_COUNT [COMMAND_PREFIX ...]
The prefix can be `sudo -n env ...`. Builds happen separately without sudo.
"""
import json
from pathlib import Path
import subprocess
import sys


def select_artifact(path, target):
    matches = set()
    for line in Path(path).read_text().splitlines():
        event = json.loads(line)
        if (event.get('reason') == 'compiler-artifact'
                and event.get('target', {}).get('name') == target
                and event.get('profile', {}).get('test')
                and event.get('executable')):
            matches.add(event['executable'])
    if len(matches) != 1:
        raise ValueError(f'{target}: expected one test executable, found {len(matches)}')
    return matches.pop()


def main():
    artifact, target, count, *prefix = sys.argv[1:]
    executable = select_artifact(artifact, target)
    listing = subprocess.check_output([executable, '--list', '--ignored'], text=True)
    actual = sum(line.endswith(': test') for line in listing.splitlines())
    if actual != int(count) or actual == 0:
        raise ValueError(f'{target}: expected {count} ignored tests, found {actual}; check features')
    # Required mode turns all known prerequisite skips into failures.
    # Put the assignment after sudo/unshare so a prefix that sanitizes its
    # environment cannot silently turn this back into an optional probe.
    return subprocess.call(prefix + ['env', 'STAMP_REQUIRE_PRIVILEGED=1', executable,
                                     '--ignored', '--nocapture', '--test-threads=1'])


if __name__ == '__main__':
    raise SystemExit(main())
