#!/usr/bin/env python3
"""Run Cargo tests on the requested native OS and retain revision-bound evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = re.compile(
    r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; '
    r'(\d+) measured; (\d+) filtered out;', re.MULTILINE)


def summarize(log, exit_code):
    rows = SUMMARY.findall(log)
    counts = {name: sum(int(row[i]) for row in rows)
              for i, name in enumerate(('passed', 'failed', 'ignored',
                                        'measured', 'filtered_out'), 1)}
    # Exit success alone (or a build with no executed tests) is not runtime proof.
    passed = (exit_code == 0 and bool(rows) and counts['passed'] > 0
              and counts['failed'] == 0 and counts['filtered_out'] == 0
              and all(row[0] == 'ok' for row in rows))
    return {'suite_summaries': len(rows), **counts, 'passed_gate': passed}


def capture(command):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                            check=True)
    return result.stdout.strip()


def run(expected_platform, profile, report_path):
    report_path = Path(report_path).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path = report_path.with_suffix('.log')
    report = {'schema_version': 1, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'expected_platform': expected_platform, 'actual_platform': sys.platform,
              'platform': platform.platform(), 'machine': platform.machine(),
              'profile': profile, 'completed': False, 'passed': False,
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'ci': {key: os.environ.get(key) for key in
                     ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB', 'GITHUB_SHA')}}
    exit_code = 2
    # Truncate evidence from a previous invocation even if a preflight fails.
    log_path.write_text('', encoding='utf-8')
    try:
        if sys.platform != expected_platform:
            raise ValueError(f'native platform mismatch: expected {expected_platform}, '
                             f'got {sys.platform}')
        report['commit'] = capture(['git', 'rev-parse', 'HEAD'])
        report['tracked_changes'] = capture(['git', 'status', '--porcelain',
                                             '--untracked-files=no'])
        report['tracked_patch_sha256'] = hashlib.sha256(
            capture(['git', 'diff', 'HEAD', '--binary']).encode('utf-8')).hexdigest()
        report['rustc'] = capture(['rustc', '-Vv'])
        report['cargo'] = capture(['cargo', '-V'])
        report['cargo_build_target'] = os.environ.get('CARGO_BUILD_TARGET')
        if sys.platform == 'darwin':
            report['macos'] = capture(['sw_vers'])
        command = ['cargo', 'test', '--locked', '--no-fail-fast', '--color', 'never']
        if profile == 'all-features':
            command.append('--all-features')
        report['command'] = command
        env = os.environ.copy()
        env['CARGO_TERM_COLOR'] = 'never'
        # Cargo reads no flags or test filters from this runner's CLI.
        with log_path.open('w', encoding='utf-8') as log:
            process = subprocess.Popen(command, cwd=ROOT, env=env, text=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            with process.stdout:
                for line in process.stdout:
                    log.write(line)
                    print(line, end='', flush=True)
            report['exit_code'] = process.wait()
        report['summary'] = summarize(log_path.read_text(encoding='utf-8'),
                                      report['exit_code'])
        report['completed'] = True
        report['passed'] = report['summary']['passed_gate']
        exit_code = 0 if report['passed'] else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(error, file=sys.stderr)
    finally:
        report['log_file'] = log_path.name
        report['log_sha256'] = hashlib.sha256(log_path.read_bytes()).hexdigest()
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        report_path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-platform', choices=('darwin', 'linux', 'win32'), required=True)
    parser.add_argument('--profile', choices=('default', 'all-features'), required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    return run(args.expected_platform, args.profile, args.report)


if __name__ == '__main__':
    sys.exit(main())
