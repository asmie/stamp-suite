"""Standards drift, malformed sources and unavailable evidence must stay visible."""
import importlib.util
import contextlib
import hashlib
import io
import json
from datetime import date
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("standards", Path(__file__).resolve().parents[1] / "check_standards.py")
standards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(standards)
FIXTURES = Path(__file__).parent / "fixtures/standards/ber-replacement"


class StandardsChecks(unittest.TestCase):
    def setUp(self):
        self.entry = {"kind": "draft", "name": "draft-ietf-example", "revision": "01"}
        self.observed = {"name": self.entry["name"], "rev": "01", "state": "Active",
                         "expires": "2026-10-01T00:00:00Z"}
        self.today = date(2026, 9, 11)

    def test_current_and_approaching_expiry(self):
        self.assertEqual(standards.compare(self.entry, self.observed, self.today), ([], []))
        problems, warnings = standards.compare(self.entry, self.observed, date(2026, 9, 25))
        self.assertEqual(problems, [])
        self.assertEqual(len(warnings), 1)

    def test_new_revision_publication_and_expiry_need_review(self):
        for field, value in (("rev", "02"), ("state", "RFC"), ("expires", "2026-09-01T00:00:00Z")):
            with self.subTest(field=field):
                observed = {**self.observed, field: value}
                self.assertEqual(len(standards.compare(self.entry, observed, self.today)[0]), 1)

    def test_invalid_metadata_does_not_mean_current(self):
        for field, value in (("name", "wrong-document"), ("rev", None), ("expires", 42),
                             ("expires", "not-a-date"), ("expires", None), ("state", None),
                             ("state", []), ("state", ""), ("rfc_number", True), ("rfc_number", -1)):
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

    def write_document(self, directory, name, state="Active", revision="01"):
        observed = {**self.observed, "name": name, "rev": revision, "state": state}
        (directory / (name + ".json")).write_text(json.dumps(observed))
        return observed

    def relations(self, name, successors):
        return {"meta": {"next": None, "total_count": len(successors)}, "objects": [
            {"target": f"/api/v1/doc/document/{name}/",
             "source": f"/api/v1/doc/document/{successor}/",
             "relationship": "/api/v1/name/docrelationshipname/replaces/"}
            for successor in successors]}

    def write_relations(self, directory, name, successors):
        (directory / (name + "-replacements.json")).write_text(json.dumps(self.relations(name, successors)))

    def test_resolved_document_endpoint_and_rfc_publication(self):
        self.assertEqual(standards.source_url(self.entry),
                         "https://datatracker.ietf.org/doc/draft-ietf-example/doc.json")
        for expires in (None, "2020-01-01 00:00:00"):
            observed = {**self.observed, "state": "RFC", "expires": expires}
            self.assertEqual(standards.compare(self.entry, observed, self.today), (["published as RFC"], []))

    def test_replaced_document_with_future_expiry_requires_review(self):
        # Keep the legacy publication field to isolate the former state blind spot.
        observed = {**self.observed, "state": "Replaced", "rfc_number": None}
        problems, _ = standards.compare(self.entry, observed, self.today)
        self.assertEqual(problems, ["document state changed: Active -> Replaced"])
        for state in ["Expired", "Withdrawn", "Unknown future state"]:
            self.assertTrue(standards.compare(self.entry, {**self.observed, "state": state}, self.today)[0])

    def test_ber_two_hop_replacement_chain_and_hashes(self):
        entry = {"kind": "draft", "name": "draft-gandhi-ippm-stamp-ber", "revision": "07"}
        with patch.object(standards.urllib.request, "urlopen", side_effect=AssertionError("offline must not connect")):
            result = standards.check(entry, date(2026, 11, 8), offline=FIXTURES)
        self.assertEqual(result["status"], "review")
        self.assertEqual(result["replacement_paths"], [[entry["name"], "draft-ietf-ippm-stamp-ber", "draft-ietf-bpm-stamp-ber"]])
        self.assertEqual([item["observed"]["state"] for item in result["successors"]], ["Replaced", "Active"])
        self.assertEqual(len(result["sources"]), 5)
        for source in result["sources"]:
            self.assertEqual(source["sha256"], hashlib.sha256((FIXTURES / source["file"]).read_bytes()).hexdigest())

    def test_live_cache_replays_without_network(self):
        entry = {"kind": "draft", "name": "draft-gandhi-ippm-stamp-ber", "revision": "07"}
        requested = []

        def fetch(request, timeout):
            requested.append(request.full_url)
            if "target__name=" in request.full_url:
                filename = request.full_url.split("target__name=")[1] + "-replacements.json"
            else:
                filename = request.full_url.split("/doc/")[1].split("/")[0] + ".json"
            return io.BytesIO((FIXTURES / filename).read_bytes())

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            with patch.object(standards.urllib.request, "urlopen", side_effect=fetch):
                live = standards.check(entry, date(2026, 11, 8), cache=cache)
            with patch.object(standards.urllib.request, "urlopen", side_effect=AssertionError("offline must not connect")):
                replay = standards.check(entry, date(2026, 11, 8), offline=cache)
            self.assertEqual(live, replay)
            self.assertEqual(len(requested), 5)
            self.assertEqual(len(set(requested)), 5)
            (cache / "draft-ietf-ippm-stamp-ber-replacements.json").unlink()
            self.assertEqual(standards.check(entry, date(2026, 11, 8), offline=cache)["status"], "error")

    def test_cycles_and_traversal_bounds_are_incomplete(self):
        for limit, value in [("MAX_REPLACEMENT_HOPS", 1), ("MAX_DRAFT_DOCUMENTS", 2),
                             ("MAX_REPLACEMENT_VISITS", 2)]:
            with self.subTest(limit=limit), patch.object(standards, limit, value):
                entry = {"kind": "draft", "name": "draft-gandhi-ippm-stamp-ber", "revision": "07"}
                self.assertEqual(standards.check(entry, date(2026, 11, 8), offline=FIXTURES)["status"], "error")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first, second = self.entry["name"], "draft-ietf-successor"
            for name, successor in [(first, second), (second, first)]:
                self.write_document(directory, name, "Replaced")
                self.write_relations(directory, name, [successor])
            result = standards.check(self.entry, self.today, offline=directory)
            self.assertEqual(result["status"], "error")
            self.assertIn("replacement cycle", result["error"])

    def test_replacement_branches_report_every_path_without_refetching(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, first, final = self.entry["name"], "draft-ietf-first", "draft-ietf-final"
            self.write_document(directory, root, "Replaced")
            self.write_document(directory, first, "Replaced")
            self.write_document(directory, final)
            self.write_relations(directory, root, [first, final])
            self.write_relations(directory, first, [final])
            result = standards.check(self.entry, self.today, offline=directory)
            self.assertEqual(result["status"], "review")
            self.assertCountEqual(result["replacement_paths"], [[root, first, final], [root, final]])
            self.assertEqual(len(result["sources"]), 5)

    def test_missing_and_invalid_replacement_evidence_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            name = self.entry["name"]
            self.write_document(directory, name, "Replaced")
            self.assertEqual(standards.check(self.entry, self.today, offline=directory)["status"], "error")
            valid = self.relations(name, ["draft-ietf-successor"])
            invalid = [{}, {"meta": {}, "objects": []}, self.relations(name, []),
                       {**valid, "meta": {"next": "/next-page", "total_count": 1}},
                       {**valid, "meta": {"next": None, "total_count": 2}},
                       self.relations(name, ["draft-ietf-successor", "draft-ietf-successor"])]
            for field, value in [("source", "/api/v1/doc/document/../../secret/"),
                                 ("source", 42), ("target", "/api/v1/doc/document/wrong/"),
                                 ("relationship", "/api/v1/name/docrelationshipname/refers/")]:
                invalid.append({**valid, "objects": [{**valid["objects"][0], field: value}]})
            for relations in invalid:
                with self.subTest(relations=relations):
                    (directory / (name + "-replacements.json")).write_text(json.dumps(relations))
                    self.assertEqual(standards.check(self.entry, self.today, offline=directory)["status"], "error")
            self.write_relations(directory, name, ["draft-ietf-successor"])
            for observed in [{}, {**self.observed, "name": "wrong"},
                             {**self.observed, "name": "draft-ietf-successor", "state": None}]:
                (directory / "draft-ietf-successor.json").write_text(json.dumps(observed))
                self.assertEqual(standards.check(self.entry, self.today, offline=directory)["status"], "error")

    def test_network_failure_and_oversized_sources_are_incomplete(self):
        with patch.object(standards.urllib.request, "urlopen", side_effect=OSError("unavailable")):
            self.assertEqual(standards.check(self.entry, self.today)["status"], "error")
        with patch.object(standards.urllib.request, "urlopen", return_value=io.BytesIO(b"x" * (standards.MAX_SOURCE_BYTES + 1))):
            self.assertEqual(standards.check(self.entry, self.today)["status"], "error")

    def test_watch_only_changes_are_advisory_but_missing_evidence_is_incomplete(self):
        entry = {**self.entry, "watch_only": True, "expected_state": "Expired"}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            self.write_document(directory, entry["name"], "Active", "02")
            result = standards.check(entry, self.today, offline=directory)
            self.assertEqual(result["status"], "review")
            self.assertIn("document state changed: Expired -> Active", result["problems"])
            self.assertEqual(standards.exit_code({"completed": True, "documents": [result]}), 0)
            self.assertEqual(standards.exit_code({"completed": True, "documents": [{**result, "watch_only": False}]}), 1)
            (directory / (entry["name"] + ".json")).unlink()
            result = standards.check(entry, self.today, offline=directory)
            self.assertEqual(result["status"], "error")
            self.assertEqual(standards.exit_code({"completed": False, "documents": [result]}), 2)

    def test_watch_manifest_requires_explicit_state_but_not_a_matrix(self):
        entry = {**self.entry, "watch_only": True, "expected_state": "Expired"}
        standards.validate_manifest({"schema_version": 1, "documents": [entry]})
        for changes in [{"expected_state": None}, {"watch_only": "true"}, {"watch_only": False}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                standards.validate_manifest({"schema_version": 1, "documents": [{**entry, **changes}]})

    def test_cli_writes_incomplete_and_watch_only_reports_with_correct_exit_codes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = directory / "manifest.json"
            entry = {**self.entry, "watch_only": True, "expected_state": "Expired"}
            manifest.write_text(json.dumps({"schema_version": 1, "documents": [entry]}))
            self.write_document(directory, entry["name"])
            report_path = directory / "report.json"
            args = ["check_standards.py", "--offline", str(directory), "--report", str(report_path),
                    "--as-of", self.today.isoformat()]
            with patch.object(standards, "MANIFEST", manifest), patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(standards.main(), 0)
                report = json.loads(report_path.read_text())
                self.assertTrue(report["completed"])
                self.assertEqual(report["schema_version"], 2)
                (directory / (entry["name"] + ".json")).unlink()
                self.assertEqual(standards.main(), 2)
                self.assertFalse(json.loads(report_path.read_text())["completed"])


if __name__ == "__main__":
    unittest.main()
