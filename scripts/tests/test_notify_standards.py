"""Exercise issue notifications without writing to GitHub."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("notify_standards", Path(__file__).resolve().parents[1] / "notify_standards.py")
notifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notifier)


class StandardsNotifications(unittest.TestCase):
    def report(self, directory):
        path = directory / "report.json"
        path.write_text(json.dumps({"completed": True, "documents": [
            {"name": "draft-old", "status": "review", "problems": ["document state changed: Active -> Replaced"],
             "replacement_paths": [["draft-old", "draft-new"]]},
            {"name": "draft-watch", "status": "review", "watch_only": True, "problems": ["revision changed"]},
            {"name": "rfc9999", "status": "current"},
        ]}))
        return path

    def test_issue_contains_review_replacement_and_watch_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            body = notifier.issue_body(self.report(Path(temporary)), "https://github.com/example/repo/actions/runs/123")
        self.assertIn(notifier.MARKER, body)
        self.assertIn("Active -> Replaced", body)
        self.assertIn("draft-old -> draft-new", body)
        self.assertIn("draft-watch: review (watch-only)", body)
        self.assertNotIn("rfc9999", body)
        self.assertIn("actions/runs/123", body)

    def test_incomplete_and_missing_reports_still_produce_notifications(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            self.assertIn("readable report", notifier.issue_body(path, "run-url"))
            for data in ["<html>", "[]", '{}']:
                path.write_text(data)
                self.assertIn("readable report", notifier.issue_body(path, "run-url"))
            path.write_text(json.dumps({"completed": False, "error": "manifest invalid", "documents": [
                {"name": "draft-old", "status": "error", "error": "network unavailable"}]}))
            body = notifier.issue_body(path, "run-url")
            self.assertIn("check is incomplete", body)
            self.assertIn("manifest invalid", body)
            self.assertIn("network unavailable", body)

    def test_creates_or_updates_one_marked_issue_using_a_body_file(self):
        for number in [None, 42]:
            with self.subTest(number=number), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                path = self.report(directory)
                # An unrelated issue with the same title must remain untouched.
                listing = [{"number": 1, "title": notifier.TITLE, "body": "manual unrelated report"}]
                if number:
                    listing.append({"number": number, "title": notifier.TITLE, "body": notifier.MARKER})
                calls = []

                def run(command, **kwargs):
                    calls.append(command)
                    self.assertTrue(kwargs["check"])
                    if command[2] == "list":
                        return SimpleNamespace(stdout=json.dumps(listing))
                    body_path = Path(command[command.index("--body-file") + 1])
                    self.assertIn("draft-old -> draft-new", body_path.read_text())
                    self.assertEqual(command[command.index("--repo") + 1], "example/repo")
                    if number:
                        self.assertEqual(command[2:4], ["edit", "42"])
                    else:
                        self.assertEqual(command[2], "create")
                        self.assertEqual(command[command.index("--title") + 1], notifier.TITLE)
                    return SimpleNamespace(returncode=0)

                with patch.object(notifier.subprocess, "run", side_effect=run):
                    notifier.notify("example/repo", path, "run-url")
                self.assertEqual(len(calls), 2)

    def test_duplicate_issues_or_failed_lookup_never_create_another_issue(self):
        duplicates = [{"number": number, "title": notifier.TITLE, "body": notifier.MARKER}
                      for number in [1, 2]]
        with patch.object(notifier.subprocess, "run", return_value=SimpleNamespace(stdout=json.dumps(duplicates))) as run:
            with self.assertRaisesRegex(ValueError, "multiple open"):
                notifier.notify("example/repo", Path("unused.json"), "run-url")
            self.assertEqual(run.call_count, 1)
        with patch.object(notifier.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["gh"])) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                notifier.notify("example/repo", Path("unused.json"), "run-url")
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
