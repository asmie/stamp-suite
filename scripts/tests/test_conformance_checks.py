"""Regression cases for evidence drift and privileged artifact selection."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


counts = load('check_conformance_counts')
runner = load('run_privileged_test')


class EvidenceChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.docs = self.root / 'doc/conformance'
        self.docs.mkdir(parents=True)

    def matrices(self):
        for name in counts.MATRICES:
            (self.docs / (name + '.md')).write_text(
                'Summary: 1 clauses — 1 Compliant / 0 Partial / 0 Gap / 0 N-A / 0 Excluded\n'
                '| ID | Requirement | Status | Evidence |\n'
                '| ber-1 | a \\| b | Compliant (provisioned mode) | evidence |\n')
        (self.docs / 'README.md').write_text(''.join(
            f'| [{name}]({name}.md) | frozen | 1 | 1 | 0 | 0 | 0 | 0 |\n'
            for name in counts.MATRICES) + '| **Total** | | **9** | **9** | **0** | **0** | **0** | **0** |\n')

    def test_counts_accept_notes_escaped_pipes_and_rollup(self):
        self.matrices()
        self.assertEqual(counts.check(self.root)['problems'], [])

    def test_counts_reject_summary_footer_duplicate_and_rollup_drift(self):
        for alteration in ['summary', 'footer', 'duplicate', 'rollup', 'missing', 'status']:
            with self.subTest(alteration=alteration):
                self.matrices()
                p = self.docs / 'rfc8762.md'
                if alteration == 'summary':
                    p.write_text(p.read_text().replace('1 Compliant', '0 Compliant'))
                elif alteration == 'footer':
                    p.write_text(p.read_text() + 'Counts: 0 Compliant, 1 Gap — 1 clauses total.\n')
                elif alteration == 'duplicate':
                    p.write_text(p.read_text() + '| ber-1 | duplicated | Compliant | evidence |\n')
                elif alteration == 'missing':
                    p.unlink()
                elif alteration == 'status':
                    p.write_text(p.read_text().replace('Compliant (provisioned mode)', 'Unknown'))
                else:
                    p = self.docs / 'README.md'
                    p.write_text(p.read_text().replace('**9**', '**8**'))
                self.assertTrue(counts.check(self.root)['problems'])

    def citation(self, reference):
        source = self.root / 'src'
        source.mkdir(exist_ok=True)
        (source / 'example.rs').write_text('fn example_test() {\n  work();\n}\n\n// other\n')
        (self.docs / 'fixture.md').write_text(f'`example_test` (`{reference}`)\n')
        result = subprocess.run([sys.executable, str(SCRIPTS / 'check_conformance_citations.py'),
                                 '--root', str(self.root), '--json', '--details'],
                                capture_output=True, text=True)
        return result.returncode, json.loads(result.stdout)

    def test_citations_accept_body_extent_and_report_inventory(self):
        code, report = self.citation('src/example.rs:2-3')
        self.assertEqual(code, 0)
        self.assertEqual(report['counts'], {'ok': 1})
        self.assertEqual(len(report['citations']), 1)

    def test_citations_reject_both_range_bounds_missing_file_and_stale_anchor(self):
        for citation in ['src/example.rs:0', 'src/example.rs:2-99', 'src/example.rs:3-2',
                         'src/missing.rs:1', 'src/example.rs:5']:
            with self.subTest(citation=citation):
                code, report = self.citation(citation)
                self.assertNotEqual(code, 0)
                self.assertEqual(len(report['problems']), 1)

    def test_artifact_selection_rejects_missing_or_ambiguous_test(self):
        path = self.root / 'artifacts.json'
        event = {'reason': 'compiler-artifact', 'target': {'name': 'wire'},
                 'profile': {'test': True}, 'executable': '/tmp/one'}
        path.write_text(json.dumps(event) + '\n')
        self.assertEqual(runner.select_artifact(path, 'wire'), '/tmp/one')
        with self.assertRaises(ValueError):
            runner.select_artifact(path, 'absent')
        path.write_text(path.read_text() + json.dumps(dict(event, executable='/tmp/two')) + '\n')
        with self.assertRaises(ValueError):
            runner.select_artifact(path, 'wire')

    def test_runner_rejects_zero_tests_before_privileged_execution(self):
        executable = self.root / 'empty-test'
        executable.write_text('#!/bin/sh\nprintf "0 tests, 0 benchmarks\\n"\n')
        executable.chmod(0o755)
        path = self.root / 'artifacts.json'
        path.write_text(json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'wire'},
                                    'profile': {'test': True}, 'executable': str(executable)}) + '\n')
        result = subprocess.run([sys.executable, str(SCRIPTS / 'run_privileged_test.py'),
                                 str(path), 'wire', '3', 'must-not-execute'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('expected 3 ignored tests, found 0', result.stderr)

    def test_required_mode_survives_a_prefix_that_clears_the_environment(self):
        executable = self.root / 'required-test'
        executable.write_text('#!/bin/sh\nif [ "$1" = "--list" ]; then\n'
                              '  printf "wire: test\\n"\nelse\n'
                              '  test "$STAMP_REQUIRE_PRIVILEGED" = "1"\nfi\n')
        executable.chmod(0o755)
        path = self.root / 'artifacts.json'
        path.write_text(json.dumps({'reason': 'compiler-artifact', 'target': {'name': 'wire'},
                                    'profile': {'test': True}, 'executable': str(executable)}) + '\n')
        result = subprocess.run([sys.executable, str(SCRIPTS / 'run_privileged_test.py'),
                                 str(path), 'wire', '1', 'env', '-i'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
