"""Standards drift, malformed sources and unavailable evidence must stay visible."""
import importlib.util
import json
from datetime import date
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("standards", Path(__file__).resolve().parents[1] / "check_standards.py")
standards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(standards)


class StandardsChecks(unittest.TestCase):
    def setUp(self):
        self.entry = {"kind": "draft", "name": "draft-ietf-example", "revision": "01"}
        self.observed = {"name": self.entry["name"], "rev": "01", "rfc_number": None,
                         "expires": "2026-10-01T00:00:00Z"}
        self.today = date(2026, 9, 11)

    def test_current_and_approaching_expiry(self):
        self.assertEqual(standards.compare(self.entry, self.observed, self.today), ([], []))
        problems, warnings = standards.compare(self.entry, self.observed, date(2026, 9, 25))
        self.assertEqual(problems, [])
        self.assertEqual(len(warnings), 1)

    def test_new_revision_publication_and_expiry_need_review(self):
        for field, value in (("rev", "02"), ("rfc_number", 9999), ("expires", "2026-09-01T00:00:00Z")):
            with self.subTest(field=field):
                observed = {**self.observed, field: value}
                self.assertEqual(len(standards.compare(self.entry, observed, self.today)[0]), 1)

    def test_invalid_metadata_does_not_mean_current(self):
        for field, value in (("name", "wrong-document"), ("rev", None), ("expires", 42),
                             ("expires", "not-a-date"), ("expires", None)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                standards.compare(self.entry, {**self.observed, field: value}, self.today)

    def test_rfc_update_obsolescence_and_status_changes(self):
        entry = {"kind": "rfc", "name": "rfc9999", "expected": {
            "status": "PROPOSED STANDARD", "updated_by": [], "obsoleted_by": []}}
        observed = {"doc_id": "RFC9999", **entry["expected"]}
        self.assertEqual(standards.compare(entry, observed, self.today), ([], []))
        for field, value in (("status", "HISTORIC"), ("updated_by", ["RFC10000"]),
                             ("obsoleted_by", ["RFC10000"])):
            with self.subTest(field=field):
                self.assertEqual(len(standards.compare(entry, {**observed, field: value}, self.today)[0]), 1)
        with self.assertRaises(ValueError):
            standards.compare(entry, {"doc_id": "RFC9999"}, self.today)

    def test_missing_offline_file_and_malformed_json_are_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.assertEqual(standards.check(self.entry, self.today, offline=directory)["status"], "error")
            path = directory / (self.entry["name"] + ".json")
            for content in ("<html>upstream error</html>", "[]", '{"name": 1}'):
                path.write_text(content)
                self.assertEqual(standards.check(self.entry, self.today, offline=directory)["status"], "error")
            path.write_text(json.dumps(self.observed))
            self.assertEqual(standards.check(self.entry, self.today, offline=directory)["status"], "current")

    def test_manifest_requires_matching_matrix_and_unique_documents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix = root / "doc/conformance/example.md"
            matrix.parent.mkdir(parents=True)
            matrix.write_text("Revision frozen: draft-ietf-example-**01**")
            entry = {**self.entry, "matrix": "doc/conformance/example.md"}
            manifest = {"schema_version": 1, "documents": [entry]}
            standards.validate_manifest(manifest, root)
            matrix.write_text("Revision frozen: draft-ietf-example-00\n\nHistory: draft-ietf-example-01")
            with self.assertRaisesRegex(ValueError, "matrix/frozen"):
                standards.validate_manifest(manifest, root)
            matrix.write_text("Revision frozen: draft-ietf-example-01")
            manifest["documents"].append(entry)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                standards.validate_manifest(manifest, root)

    def test_repository_manifest(self):
        standards.validate_manifest(json.loads(standards.MANIFEST.read_text()))


if __name__ == "__main__":
    unittest.main()
