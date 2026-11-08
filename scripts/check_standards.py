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
MAX_REPLACEMENT_HOPS = 8
MAX_DRAFT_DOCUMENTS = 16
MAX_REPLACEMENT_VISITS = 64
MAX_SOURCE_BYTES = 2_000_000
DRAFT_NAME = r"draft-[a-z0-9-]+"


def validate_manifest(manifest, root=ROOT):
    if manifest.get("schema_version") != 1 or not manifest.get("documents"):
        raise ValueError("missing/unsupported standards manifest")
    seen = set()
    for entry in manifest["documents"]:
        name = entry["name"]
        if name in seen:
            raise ValueError("duplicate document: " + name)
        seen.add(name)
        if type(entry.get("watch_only", False)) is not bool:
            raise ValueError("watch_only must be a boolean")
        if entry["kind"] == "draft":
            if not re.fullmatch(DRAFT_NAME, name) or not re.fullmatch(r"\d{2}", entry["revision"]):
                raise ValueError("invalid draft identity/revision")
            if "expected_state" in entry and not entry.get("watch_only"):
                raise ValueError("expected_state is only for watch-only drafts")
            if entry.get("watch_only"):
                if not isinstance(entry.get("expected_state"), str) or not entry["expected_state"].strip():
                    raise ValueError("watch-only drafts require an expected_state")
                if "matrix" not in entry:
                    continue
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
        return "https://datatracker.ietf.org/doc/" + entry["name"] + "/doc.json"
    return "https://www.rfc-editor.org/rfc/" + entry["name"] + ".json"


def compare(entry, observed, today):
    problems, warnings = [], []
    if entry["kind"] == "draft":
        if observed.get("name") != entry["name"] or not re.fullmatch(r"\d{2}", str(observed.get("rev", ""))):
            raise ValueError("invalid/mismatched Datatracker document")
        state = observed.get("state")
        if not isinstance(state, str) or not state.strip() or "expires" not in observed:
            raise ValueError("incomplete Datatracker metadata")
        number = observed.get("rfc_number")
        if number is not None and (type(number) is not int or number <= 0):
            raise ValueError("invalid RFC publication number")
        if observed["rev"] != entry["revision"]:
            problems.append(f"revision changed: {entry['revision']} -> {observed['rev']}")
        if state == "RFC" or number is not None:
            problems.append("published as RFC" + (f" {number}" if number is not None else ""))
        elif state != entry.get("expected_state", "Active"):
            problems.append(f"document state changed: {entry.get('expected_state', 'Active')} -> {state}")
        if observed["expires"] is not None:
            if not isinstance(observed["expires"], str):
                raise ValueError("invalid draft expiry metadata")
            expiry = datetime.fromisoformat(observed["expires"].replace("Z", "+00:00")).date()
            remaining = (expiry - today).days
            if remaining < 0 and state != "RFC":
                problems.append(f"draft metadata expired on {expiry}")
            elif 0 <= remaining <= 14 and state != "RFC":
                warnings.append(f"draft metadata expires on {expiry} ({remaining} days)")
        elif state != "RFC" and number is None:
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


def read_source(url, filename, sources, offline=None, cache=None):
    if offline is not None:
        with (offline / filename).open("rb") as source:
            raw = source.read(MAX_SOURCE_BYTES + 1)
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "stamp-suite-standards-check/2"})
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("metadata response exceeds size bound")
    if cache is not None:
        (cache / filename).write_bytes(raw)
    sources.append({"source": url, "file": filename, "sha256": hashlib.sha256(raw).hexdigest()})
    observed = json.loads(raw)
    if not isinstance(observed, dict):
        raise ValueError("metadata must be a JSON object")
    return observed


def replacement_names(name, observed):
    """Reject missing pages or unrelated relationships instead of guessing a successor."""
    objects, meta = observed.get("objects"), observed.get("meta")
    if not isinstance(objects, list) or not isinstance(meta, dict):
        raise ValueError("invalid replacement metadata")
    if ("next" not in meta or meta["next"] is not None
            or type(meta.get("total_count")) is not int
            or meta["total_count"] != len(objects) or len(objects) > MAX_DRAFT_DOCUMENTS):
        raise ValueError("incomplete or excessive replacement relationships")
    names = []
    for relation in objects:
        if not isinstance(relation, dict):
            raise ValueError("invalid replacement relationship")
        if (relation.get("target") != f"/api/v1/doc/document/{name}/"
                or relation.get("relationship") != "/api/v1/name/docrelationshipname/replaces/"):
            raise ValueError("mismatched replacement relationship")
        source = relation.get("source")
        match = re.fullmatch(r"/api/v1/doc/document/(" + DRAFT_NAME + r")/", source or "")
        if not match:
            raise ValueError("invalid replacement document")
        names.append(match.group(1))
    if not names or len(names) != len(set(names)):
        raise ValueError("missing or duplicate replacement relationships")
    return sorted(names)


def follow_replacements(entry, observed, result, today, offline, cache):
    documents = {entry["name"]: observed}
    edges = {}
    visits = 0
    result["successors"] = []
    result["replacement_paths"] = []

    def visit(name, path):
        nonlocal visits
        visits += 1
        if visits > MAX_REPLACEMENT_VISITS:
            raise ValueError("replacement traversal limit exceeded")
        if name in path:
            raise ValueError("replacement cycle: " + " -> ".join(path + [name]))
        if len(path) > MAX_REPLACEMENT_HOPS:
            raise ValueError("replacement hop limit exceeded")
        if name not in documents:
            if len(documents) >= MAX_DRAFT_DOCUMENTS:
                raise ValueError("replacement document limit exceeded")
            url = source_url({"kind": "draft", "name": name})
            data = read_source(url, name + ".json", result["sources"], offline, cache)
            # Validate successor metadata without applying the root's revision pin.
            compare({"kind": "draft", "name": name, "revision": data.get("rev")}, data, today)
            documents[name] = data
            result["successors"].append({"name": name, "observed": data})
        if documents[name]["state"] != "Replaced":
            if path:
                result["replacement_paths"].append(path + [name])
            return
        if name not in edges:
            url = ("https://datatracker.ietf.org/api/v1/doc/relateddocument/"
                   "?relationship=replaces&target__name=" + name)
            relations = read_source(url, name + "-replacements.json", result["sources"], offline, cache)
            edges[name] = replacement_names(name, relations)
        for successor in edges[name]:
            visit(successor, path + [name])

    visit(entry["name"], [])


def check(entry, today, offline=None, cache=None):
    result = {"name": entry["name"], "source": source_url(entry),
              "watch_only": entry.get("watch_only", False), "sources": []}
    try:
        observed = read_source(result["source"], entry["name"] + ".json",
                               result["sources"], offline, cache)
        result["sha256"] = result["sources"][0]["sha256"]
        problems, warnings = compare(entry, observed, today)
        result.update(status="review" if problems else "current", problems=problems,
                      warnings=warnings, observed=observed)
        if entry["kind"] == "draft":
            follow_replacements(entry, observed, result, today, offline, cache)
    except (OSError, ValueError, TypeError, KeyError) as error:
        result.update(status="error", error=str(error))
    return result


def exit_code(report):
    if not report["completed"]:
        return 2
    return int(any(r["status"] == "review" and not r.get("watch_only") for r in report["documents"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--offline", type=Path, help="recheck saved metadata without networking")
    parser.add_argument("--cache", type=Path, help="save downloaded source JSON")
    parser.add_argument("--as-of", type=date.fromisoformat, help="date for reproducible expiry checks (YYYY-MM-DD)")
    args = parser.parse_args()
    today = args.as_of or datetime.now(timezone.utc).date()
    report = {"schema_version": 2, "as_of": str(today), "completed": False,
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
                suffix = " (watch-only)" if result["watch_only"] else ""
                print(f"{result['name']} {result['status']}{suffix}", flush=True)
                for problem in result.get("problems", []):
                    print("  review:", problem, flush=True)
                for warning in result.get("warnings", []):
                    print("  warning:", warning, flush=True)
                for path in result.get("replacement_paths", []):
                    print("  replacement:", " -> ".join(path), flush=True)
                if result.get("error"):
                    print("  error:", result["error"], flush=True)
        report["completed"] = all(r["status"] != "error" for r in report["documents"])
        report["manifest_sha256"] = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    except (OSError, ValueError, TypeError, KeyError) as error:
        report["error"] = str(error)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    return exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
