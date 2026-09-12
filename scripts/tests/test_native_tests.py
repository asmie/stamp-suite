"""Native evidence must not convert build/partial/foreign runs into a pass."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'run_native_tests.py'
spec = importlib.util.spec_from_file_location('native_tests', SCRIPT)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)

OK = 'test result: ok. 4 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'
BAD = 'test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n'


class NativeEvidenceTests(unittest.TestCase):
    def test_counts_keep_ignored_separate(self):
        result = native.summarize(OK + OK, 0)
        self.assertTrue(result['passed_gate'])
        self.assertEqual(result['passed'], 8)
        self.assertEqual(result['ignored'], 4)
        self.assertEqual(result['suite_summaries'], 2)

    def test_no_runtime_or_incomplete_run_cannot_pass(self):
        for log, code in [('Finished test profile', 0), (OK, 101),
                          (OK + BAD, 0), (OK.replace('4 passed', '0 passed'), 0),
                          (OK.replace('0 filtered out', '1 filtered out'), 0)]:
            with self.subTest(log=log, code=code):
                self.assertFalse(native.summarize(log, code)['passed_gate'])

    def test_wrong_platform_does_not_launch_cargo(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            with mock.patch.object(native.sys, 'platform', 'linux'), \
                    mock.patch.object(native.subprocess, 'Popen') as popen:
                self.assertEqual(native.run('darwin', 'default', path), 2)
            popen.assert_not_called()
            report = json.loads(path.read_text())
            self.assertFalse(report['completed'])
            self.assertFalse(report['passed'])
            self.assertIn('platform mismatch', report['error'])

    def test_failed_command_retains_partial_counts_and_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            child = mock.Mock(stdout=io.StringIO(OK + BAD))
            child.wait.return_value = 101
            with mock.patch.object(native.sys, 'platform', 'linux'), \
                    mock.patch.object(native, 'capture', return_value='fixture'), \
                    mock.patch.object(native.subprocess, 'Popen', return_value=child) as popen:
                self.assertEqual(native.run('linux', 'all-features', path), 1)
            report = json.loads(path.read_text())
            self.assertTrue(report['completed'])
            self.assertFalse(report['passed'])
            self.assertEqual(report['exit_code'], 101)
            self.assertEqual(report['summary']['failed'], 1)
            self.assertEqual(path.with_suffix('.log').read_text(), OK + BAD)
            command = popen.call_args.args[0]
            self.assertIn('--no-fail-fast', command)
            self.assertIn('--all-features', command)
            self.assertEqual(report['command'], command)

    def test_preflight_error_still_writes_failure_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.with_suffix('.log').write_text(OK)
            with mock.patch.object(native.sys, 'platform', 'linux'), \
                    mock.patch.object(native, 'capture', side_effect=OSError('missing tool')):
                self.assertEqual(native.run('linux', 'default', path), 2)
            report = json.loads(path.read_text())
            self.assertFalse(report['completed'])
            self.assertFalse(report['passed'])
            self.assertEqual(path.with_suffix('.log').read_text(), '')


if __name__ == '__main__':
    unittest.main()
