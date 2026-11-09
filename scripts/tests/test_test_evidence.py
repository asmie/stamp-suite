"""Test source-reference detection, advisory rollout and strict failure semantics."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('conformance_test_evidence', SCRIPTS / 'conformance_test_evidence.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class TestEvidencePolicy(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'doc/conformance').mkdir(parents=True)
        self.write('src/lib.rs', 'pub fn production() {}\n#[cfg(test)] mod tests;\n')
        self.write('src/lib/tests.rs', '#[test]\nfn checks_real_path() {}\n')

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')

    def report(self, clauses, strict=False):
        self.write('doc/conformance/fixture.md',
                   '| ID | Clause | Level | Role | Status | Evidence |\n|---|---|---|---|---|---|\n' + clauses)
        args = [sys.executable, str(SCRIPTS / 'check_conformance_citations.py'),
                '--root', str(self.root), '--json', '--details']
        if strict:
            args.append('--require-test-evidence')
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertTrue(result.stdout, result.stderr)
        return result.returncode, json.loads(result.stdout)

    def row(self, evidence, identifier='RFC1-1', level='MUST', status='Compliant'):
        return f'| {identifier} | a \\| b | {level} | Both | {status} | {evidence} |\n'

    def test_normative_and_compliant_filters_include_structural_requirements(self):
        rows = ''.join(self.row('`src/lib.rs::production`', f'RFC1-{i}', level, status)
                       for i, (level, status) in enumerate([
                           ('MUST', 'Compliant'), ('MUST NOT', 'Compliant (profile)'),
                           ('SHALL', 'Compliant'), ('SHALL NOT', 'Compliant'),
                           ('REQUIRED', 'Compliant'), ('MUST (implied, structural)', 'Compliant'),
                           ('SHOULD', 'Compliant'), ('MAY', 'Compliant'),
                           ('MUST', 'Partial'), ('MUST', 'Gap'), ('MUST', 'N-A')]))
        code, report = self.report(rows)
        self.assertEqual(code, 0)  # advisory backlog does not turn source validity into a pass claim
        self.assertEqual(report['test_evidence']['counts'],
                         dict(normative_compliant=6, with_test_reference=0, missing_test_reference=6))

    def test_actual_test_attributes_and_test_modules_qualify(self):
        code, report = self.report(self.row('Test: `src/lib.rs::checks_real_path`')
                                   + self.row('Test module: `src/lib.rs::tests`', 'RFC1-2'))
        self.assertEqual(code, 0, report)
        self.assertEqual(report['test_evidence']['counts']['with_test_reference'], 2)
        self.assertFalse(report['test_evidence']['execution_checked'])

    def test_production_functions_and_bare_production_files_are_not_tests(self):
        code, report = self.report(self.row('Test: `src/lib.rs::production`; `src/lib.rs`'))
        self.assertEqual(code, 0)
        self.assertEqual(report['test_evidence']['counts']['missing_test_reference'], 1)

    def test_inner_cfg_attributes_macros_and_ignored_tests_are_source_presence_only(self):
        self.write('tests/wire.rs', '''#![cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn wire_path() {}
proptest! {
  #[test]
  fn property(value in any::<u8>()) {}
}
#[ignore = "requires a namespace"]
#[test]
fn privileged() {}
fn not_a_test_helper() {}
''')
        code, report = self.report(self.row('`tests/wire.rs`'))
        self.assertEqual(code, 0, report)
        reference = report['test_evidence']['clauses'][0]['references'][0]
        self.assertEqual(reference['test_count'], 3)
        self.assertEqual(reference['ignored_test_count'], 1)
        self.assertFalse(report['test_evidence']['execution_checked'])

    def test_comments_strings_lifetimes_and_test_like_helper_names_do_not_fake_tests(self):
        source = '''// #[test] fn line_comment() {}
/* outer /* nested */ #[test] fn block_comment() {} */
const TEXT: &str = r###"#[test] fn raw_string() {}"###;
const BYTES: &[u8] = br#"#[test] fn raw_bytes() {}"#;
const QUOTED: &str = "#[test] fn quoted() {}";
fn test_named_helper<'a>(text: &'a str) {}
#[test] pub(crate) fn real() {}
'''
        functions = policy.rust_functions(source)
        self.assertEqual([f['item'] for f in functions if f['is_test']], ['real'])
        self.assertIn('test_named_helper', [f['item'] for f in functions])

    def test_bare_unique_test_names_work_but_ambiguous_ones_need_a_file(self):
        code, report = self.report(self.row('Test: `checks_real_path`'))
        self.assertEqual(code, 0)
        self.assertEqual(report['test_evidence']['counts']['with_test_reference'], 1)
        self.write('tests/duplicate.rs', '#[test] fn checks_real_path() {}\n')
        code, report = self.report(self.row('Test: `checks_real_path`'))
        self.assertEqual(report['test_evidence']['counts']['missing_test_reference'], 1)
        code, report = self.report(self.row('Test: `tests/duplicate.rs::checks_real_path`'))
        self.assertEqual(report['test_evidence']['counts']['with_test_reference'], 1)

    def test_helpers_cannot_borrow_same_named_child_tests(self):
        self.write('src/lib.rs', 'fn same_name() {}\nmod tests;\n')
        self.write('src/lib/tests.rs', '#[test] fn same_name() {}\n')
        _, report = self.report(self.row('`src/lib.rs::same_name`'))
        self.assertEqual(report['test_evidence']['counts']['missing_test_reference'], 1)
        _, report = self.report(self.row('`same_name` (`src/lib.rs`)'))
        self.assertEqual(report['test_evidence']['counts']['missing_test_reference'], 1)
        _, report = self.report(self.row('`src/lib.rs::tests::same_name`'))
        self.assertEqual(report['test_evidence']['counts']['with_test_reference'], 1)

    def test_data_files_common_helpers_and_word_test_are_not_test_evidence(self):
        self.write('tests/common/helper.rs', 'fn test_helper() {}\n')
        self.write('tests/fixtures/packet.json', '{"hex": "00"}\n')
        _, report = self.report(self.row('Tests were run; `tests/common/helper.rs`; `tests/fixtures/packet.json`'))
        self.assertEqual(report['test_evidence']['counts']['missing_test_reference'], 1)

    def test_python_wire_functions_require_explicit_role_and_missing_items_fail(self):
        self.write('scripts/wire.py', 'def peer_case():\n    pass\ndef other_case():\n    pass\n')
        code, report = self.report(self.row('`scripts/wire.py::peer_case`'))
        self.assertEqual(code, 0)
        self.assertEqual(report['test_evidence']['counts']['missing_test_reference'], 1)
        code, report = self.report(self.row('Wire test: `scripts/wire.py::peer_case`'))
        self.assertEqual(code, 0)
        self.assertEqual(report['test_evidence']['clauses'][0]['references'][0]['kind'], 'wire-test')
        code, report = self.report(self.row('Wire tests: `scripts/wire.py::peer_case`, `scripts/wire.py::other_case`'))
        self.assertEqual(code, 0)
        self.assertEqual(len(report['test_evidence']['clauses'][0]['references']), 2)
        code, report = self.report(self.row('Wire test: `scripts/wire.py::absent`'))
        self.assertEqual(code, 1)
        self.assertEqual(report['problems'][0]['status'], 'invalid-test-reference')

    def test_python_unittest_function_and_suite_references(self):
        self.write('scripts/tests/test_wire.py', 'import unittest\nclass Wire(unittest.TestCase):\n    def test_reply(self):\n        pass\n')
        code, report = self.report(self.row('Test: `scripts/tests/test_wire.py::Wire::test_reply`')
                                   + self.row('Tests: `scripts/tests/test_wire.py`', 'RFC1-2'))
        self.assertEqual(code, 0, report)
        self.assertEqual(report['test_evidence']['counts']['with_test_reference'], 2)
        code, report = self.report(self.row('Tests: `test_wire.py`'))
        self.assertEqual(code, 0, report)
        self.assertEqual(report['test_evidence']['clauses'][0]['references'][0]['path'], 'scripts/tests/test_wire.py')

    def test_stale_python_reference_fails_even_outside_a_compliant_row(self):
        self.write('scripts/wire.py', 'def peer_case():\n    pass\n')
        code, report = self.report(self.row('Wire test: `scripts/wire.py::absent`', status='Partial'))
        self.assertEqual(code, 1)
        self.assertEqual(report['test_evidence']['counts']['normative_compliant'], 0)
        self.assertEqual(report['problems'][0]['status'], 'invalid-test-reference')

    def test_strict_mode_fails_backlog_and_default_citation_errors_still_fail(self):
        code, report = self.report(self.row('`src/lib.rs::production`'), strict=True)
        self.assertEqual(code, 1)
        self.assertTrue(report['test_evidence']['required'])
        self.assertEqual(report['problems'][0]['status'], 'missing-test-evidence')
        code, report = self.report(self.row('`src/lib.rs::checks_real_path`'), strict=True)
        self.assertEqual(code, 0, report)
        code, report = self.report(self.row('`src/lib.rs::does_not_exist`'))
        self.assertEqual(code, 1)
        self.assertEqual(report['problems'][0]['status'], 'missing-item')


if __name__ == '__main__':
    unittest.main()
