#!/usr/bin/env python3
"""Create or update the monitor's open issue after a failed check; requires gh."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

TITLE = "Standards revision monitor needs review"
MARKER = "<!-- stamp-suite-standards-monitor -->"


def issue_body(report_path, run_url):
    lines = [MARKER, "The standards revision monitor needs attention.", "",
             f"Workflow run: {run_url}", ""]
    try:
        report = json.loads(report_path.read_text())
        if not isinstance(report, dict) or not isinstance(report.get("documents"), list):
            raise ValueError("invalid report structure")
        if not report.get("completed"):
            lines.append("The check is incomplete; unavailable metadata does not establish that standards are current.")
        if report.get("error"):
            lines.append("Report error: " + str(report["error"]))
        for document in report["documents"]:
            if document["status"] == "current":
                continue
            suffix = " (watch-only)" if document.get("watch_only") else ""
            lines.extend(["", f"- {document['name']}: {document['status']}{suffix}"])
            for problem in document.get("problems", []):
                lines.append("  - " + problem)
            for path in document.get("replacement_paths", []):
                lines.append("  - Replacement: " + " -> ".join(path))
            if document.get("error"):
                lines.append("  - " + document["error"])
    except (OSError, ValueError, TypeError, KeyError) as error:
        lines.append("The checker did not produce a readable report: " + str(error))
    lines.extend(["", "Review the uploaded standards-revisions artifact. Update implementation, "
                  "conformance evidence and frozen pins together after reviewing the specification.",
                  "This issue is updated by failed checks and is closed manually after reconciliation."])
    return "\n".join(lines) + "\n"


def notify(repository, report_path, run_url):
    listing = subprocess.run(
        ["gh", "issue", "list", "--repo", repository, "--state", "open", "--limit", "100",
         "--search", f'in:title "{TITLE}"', "--json", "number,title,body"],
        check=True, capture_output=True, text=True,
    )
    issues = [issue for issue in json.loads(listing.stdout)
              if issue["title"] == TITLE and MARKER in (issue.get("body") or "")]
    if len(issues) > 1:
        raise ValueError("multiple open standards-monitor issues; reconcile duplicates first")
    with tempfile.TemporaryDirectory(prefix="stamp-standards-issue-") as temporary:
        body = Path(temporary) / "body.md"
        body.write_text(issue_body(report_path, run_url))
        if issues:
            command = ["gh", "issue", "edit", str(issues[0]["number"]), "--repo", repository]
        else:
            command = ["gh", "issue", "create", "--repo", repository, "--title", TITLE]
        subprocess.run(command + ["--body-file", str(body)], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()
    notify(args.repo, args.report, args.run_url)


if __name__ == "__main__":
    main()
