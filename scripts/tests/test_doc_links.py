"""Offline documentation checks must catch missing evidence without networking."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('check_doc_links', SCRIPTS / 'check_doc_links.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class DocumentationLinks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / 'doc').mkdir()
        (self.root / 'doc/target.md').write_text(
            '# Title\n## Repeated\n## Repeated\n## Repeated-1\n## Repeated\n'
            '## Café and `packet_id`\n## Hello _world_\n'
            'Setext title\n============\n<a id="explicit"></a>\n'
            '```md\n## Hidden\n```\n', encoding='utf-8')
        (self.root / 'asset (1).svg').write_text('<svg/>')
        (self.root / 'source.rs').write_text('fn source() {}\n')

    def check(self, markdown):
        (self.root / 'README.md').write_text(markdown, encoding='utf-8')
        return checker.check(self.root, ['README.md'])

    def test_inline_images_nested_labels_titles_spaces_and_balanced_parentheses(self):
        report = self.check('[**target**](doc/target.md "title")\n'
                            '[![image](<asset (1).svg>)](doc/target.md)\n'
                            '![other](asset%20(1).svg)\n'
                            '[root](/doc/target.md?raw=1)\n')
        self.assertEqual(report['problems'], [])
        self.assertEqual(report['counts']['local'], 5)

    def test_reference_links_and_html_attributes(self):
        report = self.check('[label][MY target]\n[my target][]\n[my target]\n'
                            '[My   target]: doc/target.md "reference"\n'
                            '<a href="doc/target.md#explicit">target</a>\n'
                            '<img src="asset%20(1).svg" />\n')
        self.assertEqual(report['problems'], [])
        self.assertEqual(report['counts']['local'], 6)

    def test_fragments_unicode_duplicates_setext_and_explicit_ids(self):
        fragments = ['title', 'repeated', 'repeated-1', 'repeated-1-1', 'repeated-2',
                     'caf%C3%A9-and-packet_id', 'hello-world', 'setext-title', 'explicit']
        report = self.check('\n'.join(f'[target](doc/target.md#{f})' for f in fragments))
        self.assertEqual(report['problems'], [])
        self.assertEqual(len(checker.anchors((self.root / 'doc/target.md').read_text())), 9)

    def test_stale_anchor_and_missing_evidence_fail_with_line_and_target(self):
        report = self.check('# Start\n[evidence](doc/missing.json)\n'
                            '[stale](doc/target.md#gone)\n[code heading](doc/target.md#hidden)\n')
        self.assertEqual([p['line'] for p in report['problems']], [2, 3, 4])
        self.assertEqual([p['reason'] for p in report['problems']],
                         ['missing local target', 'missing Markdown anchor', 'missing Markdown anchor'])
        self.assertEqual(report['problems'][0]['target'], 'doc/missing.json')

    def test_code_and_comments_do_not_create_links(self):
        report = self.check('`[inline](gone)`\n``[nested `code`](gone)``\n'
                            '```markdown\n[example](gone)\n```\n'
                            '~~~\n[example](gone)\n~~~\n'
                            '    [indented code](gone)\n'
                            '<!-- [comment](gone) -->\n'
                            '<pre>[example](gone)</pre><code>[example](gone)</code>\n'
                            '[valid](doc/target.md)\n<!-- [unclosed comment](gone)')
        self.assertEqual(report['problems'], [])
        self.assertEqual(report['counts']['links'], 1)

    def test_external_release_artifacts_are_not_local_exemptions(self):
        report = self.check('[release](https://github.com/org/repo/releases/download/v1/archive.tar.gz)\n'
                            '[other](//example.test/asset)\n[mail](mailto:owner@example.test)\n'
                            '[generated](archive.tar.gz)\n')
        self.assertEqual(report['counts']['external'], 3)
        self.assertEqual([p['target'] for p in report['problems']], ['archive.tar.gz'])

    def test_repository_escape_and_bad_schemes_or_urls_fail(self):
        report = self.check('[escape](../outside.md)\n[encoded](%2e%2e/outside.md)\n'
                            '[file](file://host/etc/passwd)\n[bad](https:missing-host)\n')
        self.assertEqual(len(report['problems']), 4)
        self.assertEqual([p['reason'] for p in report['problems'][:2]],
                         ['target escapes repository'] * 2)
        self.assertEqual(report['problems'][2]['reason'], 'unsupported URL scheme')

    def test_same_document_directory_and_non_markdown_fragments(self):
        (self.root / 'doc/README.md').write_text('# Directory\n')
        report = self.check('# Local\n[self](#local)\n[directory](doc/#directory)\n'
                            '[source](source.rs#L1)\n')
        self.assertEqual(report['problems'], [])
        self.assertEqual(report['counts']['unverified_fragments'], 1)

    def test_missing_or_outside_document_is_not_a_success(self):
        report = checker.check(self.root, ['missing.md', '../outside.md'])
        self.assertEqual(len(report['problems']), 2)

    def test_cli_reports_failure_as_json_and_success_without_network(self):
        for target, expected in [('gone', 1), ('doc/target.md', 0)]:
            with self.subTest(target=target):
                (self.root / 'README.md').write_text(f'[target]({target})\n')
                result = subprocess.run([sys.executable, str(SCRIPTS / 'check_doc_links.py'),
                                         '--root', str(self.root), '--json', 'README.md'],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(bool(json.loads(result.stdout)['problems']), bool(expected))

    def test_git_discovery_includes_new_docs_and_excludes_ignored_outputs(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / '.gitignore').write_text('target/\n')
        (self.root / 'target').mkdir()
        (self.root / 'target/generated.md').write_text('[ignored](gone)\n')
        (self.root / 'README.md').write_text('[new](doc/new.md)\n')
        (self.root / 'doc/new.md').write_text('[broken](missing.json)\n')
        result = subprocess.run([sys.executable, str(SCRIPTS / 'check_doc_links.py'),
                                 '--root', str(self.root), '--json'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual([p['document'] for p in report['problems']], ['doc/new.md'])
        self.assertEqual(report['counts']['documents'], 3)


if __name__ == '__main__':
    unittest.main()
