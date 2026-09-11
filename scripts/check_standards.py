#!/usr/bin/env python3
"""Compare frozen protocol revisions with public IETF/RFC Editor metadata.

Exit 0: current (expiry warnings are advisory); 1: review needed; 2: incomplete
check. Network errors never mean 'unchanged'. See doc/release-evidence.md.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "doc/conformance/standards.json"


def validate_manifest(manifest, root=ROOT):
    if manifest.get("schema_version") != 1 or not manifest.get("documents"):
        raise ValueError("missing/unsupported standards manifest")
    seen = set()
    for entry in manifest["documents"]:
        name = entry["name"]
        if name in seen:
            raise ValueError("duplicate document: " + name)
        seen.add(name)
        if entry["kind"] == "draft":
            if not re.fullmatch(r"draft-[a-z0-9-]+", name) or not re.fullmatch(r"\d{2}", entry["revision"]):
                raise ValueError("invalid draft identity/revision")
            matrix = (root / entry["matrix"]).resolve()
            if not matrix.is_relative_to((root / "doc/conformance").resolve()):
                raise ValueError("matrix must be inside doc/conformance")
            frozen = re.search(r"Revision frozen:\s*(.*?)(?:\n\s*\n|$)",
                               matrix.read_text().replace("*", ""), re.DOTALL)
            marker = frozen.group(1) if frozen else ""
            full_revision = name + "-" + entry["revision"]
            short_revision = re.match(r"-(\d{2})(?:\D|$)", marker)
            if full_revision not in marker and not (
                    short_revision and short_revision.group(1) == entry["revision"]):
                raise ValueError("matrix/frozen revision mismatch: " + name)
        elif entry["kind"] == "rfc":
            if not re.fullmatch(r"rfc\d+", name):
                raise ValueError("invalid RFC identity")
            expected = entry["expected"]
            if set(expected) != {"status", "updated_by", "obsoleted_by"}:
                raise ValueError("incomplete frozen RFC metadata")
        else:
            raise ValueError("unknown document kind")


def source_url(entry):
    if entry["kind"] == "draft":
        return "https://datatracker.ietf.org/api/v1/doc/document/" + entry["name"] + "/"
    return "https://www.rfc-editor.org/rfc/" + entry["name"] + ".json"


def compare(entry, observed, today):
    problems, warnings = [], []
    if entry["kind"] == "draft":
        if observed.get("name") != entry["name"] or not re.fullmatch(r"\d{2}", str(observed.get("rev", ""))):
            raise ValueError("invalid/mismatched Datatracker document")
        if "rfc_number" not in observed or "expires" not in observed:
            raise ValueError("incomplete Datatracker metadata")
        if observed["rev"] != entry["revision"]:
            problems.append(f"revision changed: {entry['revision']} -> {observed['rev']}")
        if observed["rfc_number"] is not None:
            problems.append(f"published as RFC {observed['rfc_number']}")
        if observed["expires"] is not None:
            if not isinstance(observed["expires"], str):
                raise ValueError("invalid draft expiry metadata")
            expiry = datetime.fromisoformat(observed["expires"].replace("Z", "+00:00")).date()
            remaining = (expiry - today).days
            if remaining < 0:
                problems.append(f"draft metadata expired on {expiry}")
            elif remaining <= 14:
                warnings.append(f"draft metadata expires on {expiry} ({remaining} days)")
        elif observed["rfc_number"] is None:
            raise ValueError("unpublished draft has no expiry metadata")
    else:
        if observed.get("doc_id") != entry["name"].upper():
            raise ValueError("invalid/mismatched RFC Editor document")
        for field, expected in entry["expected"].items():
            if field not in observed or not isinstance(observed[field], type(expected)):
                raise ValueError("missing/invalid RFC metadata: " + field)
            actual = observed[field]
            if (sorted(actual) if isinstance(actual, list) else actual) != expected:
                problems.append(f"{field} changed: {expected!r} -> {actual!r}")
    return problems, warnings


def check(entry, today, offline=None, cache=None):
    result = {"name": entry["name"], "source": source_url(entry)}
    try:
        if offline is not None:
            raw = (offline / (entry["name"] + ".json")).read_bytes()
        else:
            request = urllib.request.Request(result["source"], headers={"User-Agent": "stamp-suite-standards-check/1"})
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise ValueError("metadata response exceeds size bound")
            if cache is not None:
                (cache / (entry["name"] + ".json")).write_bytes(raw)
        result["sha256"] = hashlib.sha256(raw).hexdigest()
        observed = json.loads(raw)
        if not isinstance(observed, dict):
            raise ValueError("metadata must be a JSON object")
        problems, warnings = compare(entry, observed, today)
        result.update(status="review" if problems else "current", problems=problems,
                      warnings=warnings, observed=observed)
    except (OSError, ValueError, TypeError, KeyError) as error:
        result.update(status="error", error=str(error))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--offline", type=Path, help="recheck saved metadata without networking")
    parser.add_argument("--cache", type=Path, help="save downloaded source JSON")
    parser.add_argument("--as-of", type=date.fromisoformat, help="date for reproducible expiry checks (YYYY-MM-DD)")
    args = parser.parse_args()
    today = args.as_of or datetime.now(timezone.utc).date()
    report = {"schema_version": 1, "as_of": str(today), "completed": False,
              "mode": "offline" if args.offline else "live",
              "checker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "documents": []}
    try:
        manifest = json.loads(MANIFEST.read_text())
        validate_manifest(manifest)
        if args.cache:
            args.cache.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = executor.map(lambda entry: check(entry, today, args.offline, args.cache), manifest["documents"])
            for result in results:
                report["documents"].append(result)
                print(result["name"], result["status"], flush=True)
        report["completed"] = all(r["status"] != "error" for r in report["documents"])
        report["manifest_sha256"] = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    except (OSError, ValueError, TypeError, KeyError) as error:
        report["error"] = str(error)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    if not report["completed"]:
        return 2
    return int(any(r["status"] == "review" for r in report["documents"]))


if __name__ == "__main__":
    sys.exit(main())
