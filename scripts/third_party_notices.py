#!/usr/bin/env python3
"""Generate license notices for one target and feature set at packaging time."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
RELEASE_PROFILES = (
    ("x86_64-unknown-linux-gnu", "all"),
    ("aarch64-unknown-linux-gnu", "all"),
    ("aarch64-apple-darwin", "ttl-nix,snmp,hwtstamp,control,metrics"),
    ("x86_64-apple-darwin", "ttl-nix,snmp,hwtstamp,control,metrics"),
    ("x86_64-pc-windows-msvc", "ttl-pnet,metrics,control"),
)
LEGAL_NAME = re.compile(r"^(licen[sc]e|copying|notice|copyright)([._-]|$)", re.I)
PREFERENCE = {"MIT": 0, "ISC": 1, "Apache-2.0": 2, "BSD-2-Clause": 3,
              "BSD-3-Clause": 4, "Zlib": 5, "Unicode-3.0": 6}
MARKERS = {"MIT": "Permission is hereby granted", "ISC": "Permission to use, copy",
           "BSD-2-Clause": "Redistribution and use", "BSD-3-Clause": "Redistribution and use",
           "Zlib": "This software is provided", "Apache-2.0": "Apache License",
           "Unicode-3.0": "UNICODE LICENSE"}
SPECIAL_PACKAGES = {"atomic-waker", "matchit", "metrics-exporter-prometheus", "regex-syntax",
                    "ring", "rustls-webpki", "tracing-core"}


def cargo(root, args, offline):
    command = ["cargo", *args, "--locked"]
    if offline:
        command.append("--offline")
    return subprocess.run(command, cwd=root, check=True, stdout=subprocess.PIPE,
                          text=True, encoding="utf-8").stdout


def runtime_packages(metadata):
    """Follow target-filtered normal edges, excluding host proc-macro subgraphs."""
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root_id = metadata["resolve"]["root"]
    if root_id is None:
        raise ValueError("metadata must describe a package, not a virtual workspace")
    selected = {}

    def visit(package_id):
        if package_id in selected:
            return
        package = packages[package_id]
        if any("proc-macro" in target["kind"] for target in package["targets"]):
            return
        selected[package_id] = {**package, "enabled_features": nodes[package_id]["features"]}
        for dependency in nodes[package_id]["deps"]:
            if any(kind["kind"] is None for kind in dependency["dep_kinds"]):
                visit(dependency["pkg"])

    visit(root_id)
    selected.pop(root_id)
    return selected.values()


def selected_licenses(expression):
    """Choose a supported OR branch while preserving every AND requirement."""
    expression = re.sub(r"\s*/\s*", " OR ", expression or "")
    tokens = re.findall(r"\(|\)|[A-Za-z0-9.+-]+", expression)
    if re.sub(r"\s+", "", expression) != "".join(tokens):
        raise ValueError(f"unsupported license expression: {expression!r}")
    offset = 0

    def atom():
        nonlocal offset
        if offset >= len(tokens):
            raise ValueError(f"incomplete license expression: {expression}")
        token = tokens[offset]
        offset += 1
        if token == "(":
            result = either()
            if offset >= len(tokens) or tokens[offset] != ")":
                raise ValueError(f"unbalanced license expression: {expression}")
            offset += 1
            return result
        if token in {"AND", "OR", "WITH", ")"}:
            raise ValueError(f"invalid license expression: {expression}")
        if offset < len(tokens) and tokens[offset] == "WITH":
            if offset + 1 >= len(tokens):
                raise ValueError(f"incomplete license exception: {expression}")
            offset += 2
            return None  # Review an exception if there is no supported alternative.
        return {token} if token in PREFERENCE else None

    def both():
        nonlocal offset
        result = atom()
        while offset < len(tokens) and tokens[offset] == "AND":
            offset += 1
            other = atom()
            result = result | other if result is not None and other is not None else None
        return result

    def either():
        nonlocal offset
        choices = [both()]
        while offset < len(tokens) and tokens[offset] == "OR":
            offset += 1
            choices.append(both())
        supported = [choice for choice in choices if choice is not None]
        return min(supported, key=lambda choice: (sum(PREFERENCE[x] for x in choice),
                                                  len(choice), sorted(choice))) if supported else None

    chosen = either()
    if offset != len(tokens) or chosen is None:
        raise ValueError(f"license requires review: {expression}")
    return chosen


def uncomment(text):
    lines = []
    for line in text.strip().splitlines():
        line = re.sub(r"\s*\*/\s*$", "", line)
        line = re.sub(r"^\s*(?://|\#|/\*|\*)(?: ?)", "", line)
        lines.append(line.rstrip())
    return "\n".join(lines).strip()


def split_terms(text):
    """Separate attribution from complete terms so identical terms print once."""
    text = uncomment(text)
    matches = [re.search(r"\s+".join(re.escape(word) for word in marker.split()), text, re.I)
               for marker in MARKERS.values()]
    starts = [match.start() for match in matches if match]
    if not starts:
        return text, ""
    start = min(starts)
    attribution, body = text[:start].strip(), text[start:].strip()
    if body.startswith("Apache License"):
        canonical = (ROOT / "scripts/licenses/Apache-2.0.txt").read_text().strip()
        separator = "END OF TERMS AND CONDITIONS"
        original_terms, _, appendix = body.partition(separator)
        canonical_terms, _, canonical_appendix = canonical.partition(separator)
        normalize = lambda value: re.sub(r"\s+", " ", value).strip()
        # Share the standard Apache text only when the actual terms match.
        # Keep any real copyright substituted into the optional application example.
        copyright = re.search(r"Copyright\s+\[([0-9][^]]*)\]\s+\[([^]]+)\]", appendix)
        normalized_appendix = appendix
        if copyright:
            normalized_appendix = appendix.replace(copyright.group(), "Copyright [yyyy] [name of copyright owner]")
        if normalize(original_terms) == normalize(canonical_terms) and (
                not appendix.strip() or normalize(normalized_appendix) == normalize(canonical_appendix)):
            if copyright:
                attribution = "\n".join(filter(None, [attribution, copyright.group()]))
            body = canonical
    return attribution, body


def leading_notice(path):
    source = path.read_text(encoding="utf-8")
    source = re.sub(r"\A#![^\n]*\n", "", source).lstrip()
    match = re.match(r"/\*.*?\*/|(?:(?://|\#)[^\n]*(?:\n|$))+", source, re.S)
    if match and re.search(r"copyright", match.group(), re.I):
        return uncomment(match.group())
    return ""


def reviewed_policy(package, policy):
    rule = policy.get(package["name"])
    if rule is None:
        if package["name"] in SPECIAL_PACKAGES:
            raise ValueError(f"{package['name']}: missing reviewed notice policy")
        return
    if package["version"] != rule["version"]:
        raise ValueError(f"{package['name']} {package['version']}: update reviewed notice policy")
    directory = Path(package["manifest_path"]).parent
    for filename, expected in rule["sha256"].items():
        if hashlib.sha256((directory / filename).read_bytes()).hexdigest() != expected:
            raise ValueError(f"{package['name']}/{filename}: reviewed notice input changed")


def ring_notices(directory, target):
    """Select native inputs by ring's reviewed RING_SRCS architecture table."""
    architecture = target.split("-")[0]
    architecture = {"i686": "x86", "armv7": "arm"}.get(architecture, architecture)
    build = (directory / "build.rs").read_text()
    constants = dict(re.findall(r'const (\w+): &str = "([^"]+)";', build))
    table = build.split("const RING_SRCS:", 1)[1].split("\n];", 1)[0]
    paths = []
    for arches, expression in re.findall(r'\(&\[([^]]*)\],\s*("[^"]+"|\w+)\)', table):
        if not arches.strip() or architecture.upper() in {arch.strip() for arch in arches.split(",")}:
            paths.append(expression.strip('"') if expression.startswith('"') else constants[expression])
    if architecture not in {"x86", "x86_64", "aarch64", "arm"}:
        raise ValueError(f"ring architecture requires review: {architecture}")
    for name in paths:
        text = leading_notice(directory / name)
        if text:
            yield text
    for path in sorted((directory / "src").rglob("*.rs")):
        if any("test" in part for part in path.relative_to(directory).parts):
            continue
        text = leading_notice(path)
        if text:
            yield text
    yield (directory / "src/polyfill/once_cell/LICENSE-MIT").read_text()
    yield (directory / "third_party/fiat/LICENSE").read_text()


def legal_texts(package, target, policy):
    directory = Path(package["manifest_path"]).parent
    reviewed_policy(package, policy)
    if package["name"] not in policy:
        for path in directory.rglob("*"):
            if path.is_file() and LEGAL_NAME.match(path.name) and path.parent != directory:
                relative = path.relative_to(directory)
                if not any(part in {"tests", "test", "examples", "benches", "fuzz"} for part in relative.parts):
                    raise ValueError(f"{package['name']}/{relative}: nested legal files require review")
    features = set(package["enabled_features"])
    expression = package.get("license")
    # Apache covers the protobuf schema, absent when protobuf is disabled.
    if package["name"] == "metrics-exporter-prometheus" and "protobuf" not in features:
        expression = "MIT"
    chosen = selected_licenses(expression)
    texts = []
    root_files = sorted(p for p in directory.iterdir() if p.is_file() and LEGAL_NAME.match(p.name))
    if package["name"] not in policy:
        for path in root_files:
            if path.name.lower().startswith(("license", "licence")) and not re.fullmatch(
                    r"licen[sc]e(?:[._-](?:mit|apache(?:-2\.0)?|isc|bsd(?:-[23]-clause)?|boost|zlib))?(?:\.(?:txt|md))?",
                    path.name, re.I):
                raise ValueError(f"{package['name']}/{path.name}: additional legal file requires review")
    for license_id in sorted(chosen):
        if package["name"] == "ring" and license_id == "Apache-2.0":
            # LICENSE-BoringSSL also includes test/CI licenses explicitly excluded
            # from linked binaries. Only the complete Apache terms apply here.
            texts.append((ROOT / "scripts/licenses/Apache-2.0.txt").read_text())
            continue
        candidates = [p for p in root_files if re.search(
            r"(?:license|licence)[._-]" + re.escape(license_id.split("-")[0]) + r"(?:[._-]|$)", p.name, re.I)]
        if not candidates:
            marker = MARKERS[license_id].lower()
            candidates = [p for p in root_files if marker in re.sub(
                r"\s+", " ", p.read_text(encoding="utf-8").lower())]
        if not candidates:
            if package["name"] == "metrics-exporter-prometheus" and license_id == "Apache-2.0":
                texts.extend([(ROOT / "scripts/licenses/Apache-2.0.txt").read_text(),
                              leading_notice(directory / "proto/metrics.proto")])
                continue
            raise ValueError(f"{package['name']}: missing full {license_id} terms; review required")
        texts.extend(p.read_text(encoding="utf-8") for p in candidates)
    texts.extend(p.read_text(encoding="utf-8") for p in root_files
                 if p.name.lower().startswith(("copyright", "notice")))
    name = package["name"]
    if name == "atomic-waker":
        # The same code/authors are offered under Apache OR MIT; retain MIT.
        text = (directory / "LICENSE-THIRD-PARTY").read_text()
        texts.append(text.rsplit("=" * 79, 1)[-1])
    elif name == "ring":
        texts.extend(ring_notices(directory, target))
    elif name == "rustls-webpki":
        for path in sorted((directory / "src").rglob("*.rs")):
            if not any("test" in part for part in path.relative_to(directory).parts):
                text = leading_notice(path)
                if text:
                    texts.append(text)
    elif name == "regex-syntax" and any(feature.startswith("unicode") for feature in features):
        texts.append((directory / "src/unicode_tables/LICENSE-UNICODE").read_text())
    elif name == "tracing-core" and "std" not in features:
        texts.append((directory / "src/spin/LICENSE").read_text())
    return chosen, texts


def render(packages, target, features, lock_digest, policy):
    entries = []
    shared = {}
    for package in sorted(packages, key=lambda p: (p["name"], p["version"])):
        chosen, texts = legal_texts(package, target, policy)
        attributions = set()
        terms = set()
        for text in texts:
            attribution, body = split_terms(text)
            if attribution:
                attributions.add(attribution)
            if body:
                key = re.sub(r"\s+", " ", body).strip()
                shared.setdefault(key, body)
                terms.add(key)
        if not terms:
            raise ValueError(f"{package['name']}: empty legal terms")
        entries.append((package, chosen, attributions, terms))
    labels = {key: f"License text {i}" for i, key in enumerate(sorted(shared), 1)}
    lines = ["stamp-suite third-party license notices", "",
             f"Target: {target}; features: {features or '(default)'}",
             f"Cargo.lock SHA-256: {lock_digest}",
             "Generated at packaging time by scripts/third_party_notices.py.",
             "Scope: normal target dependencies; build/dev tools and proc macros excluded.",
             "One offered license is selected for OR alternatives; AND requirements retained.",
             "Copyright and additional attribution are listed per crate; full terms follow.",
             "stamp-suite's own MIT license is in LICENSE.", "", f"Crates: {len(entries)}", ""]
    for package, chosen, attributions, terms in entries:
        lines.extend([f"{package['name']} {package['version']} - {' AND '.join(sorted(chosen))}",
                      f"Repository: {package.get('repository') or '(not declared)'}"])
        lines.extend(sorted(attributions))
        lines.append("Terms: " + ", ".join(sorted(labels[key] for key in terms)))
        lines.append("")
    for key in sorted(shared):
        lines.extend(["=" * 72, labels[key], "", shared[key], ""])
    return "\n".join(lines).encode("utf-8")


def generate(root, target, features="", offline=False, no_default_features=False):
    args = ["metadata", "--format-version", "1", "--filter-platform", target]
    args += ["--all-features"] if features == "all" else ["--features", features]
    if no_default_features:
        args.append("--no-default-features")
    metadata = json.loads(cargo(root, args, offline))
    policy = json.loads((ROOT / "scripts/licenses/notice-policy.json").read_text())
    digest = hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest()
    return render(runtime_packages(metadata), target, features, digest, policy)


def check_current(path, expected):
    if not path.is_file() or path.read_bytes() != expected:
        raise ValueError(f"{path}: missing or stale; regenerate for the same target and features")


def host_target():
    if os.environ.get("CARGO_BUILD_TARGET"):
        return os.environ["CARGO_BUILD_TARGET"]
    version = subprocess.run(["rustc", "-vV"], check=True, stdout=subprocess.PIPE, text=True).stdout
    return next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "THIRD_PARTY_NOTICES.txt")
    parser.add_argument("--check", action="store_true", help="compare an existing generated bundle")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--target", help="build target; defaults to Cargo's target or rustc's host")
    parser.add_argument("--features", help="exact comma-separated build features; 'all' selects all features")
    parser.add_argument("--no-default-features", action="store_true", help="match a build with default features disabled")
    parser.add_argument("--validate-release-profiles", action="store_true",
                        help="validate all release graphs and legal inputs without writing a bundle")
    args = parser.parse_args()
    try:
        if args.validate_release_profiles:
            if args.check or args.target or args.features is not None or args.no_default_features:
                raise ValueError("--validate-release-profiles cannot be combined with target/features/check")
            for target, features in RELEASE_PROFILES:
                expected = generate(ROOT, target, features, args.offline, no_default_features=features != "all")
                print(f"Validated notices: {target}, {len(expected):,} bytes")
        else:
            target = args.target or host_target()
            features = args.features
            if features is None:
                features = dict(RELEASE_PROFILES).get(target, "")
            release_defaults = args.features is None and features != "all" and target in dict(RELEASE_PROFILES)
            no_default = args.no_default_features or release_defaults
            expected = generate(ROOT, target, features, args.offline, no_default_features=no_default)
            if args.check:
                check_current(args.output, expected)
                print(f"Third-party notices are current: {args.output}")
            else:
                args.output.write_bytes(expected)
                print(f"Wrote {len(expected):,} bytes: {args.output}")
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Third-party notice check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
