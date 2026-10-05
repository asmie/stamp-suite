"""Exercise provenance collection and reject incomplete binary distributions."""

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


notices = load("notices", "third_party_notices.py")
packaged = load("packaged", "check_packaged_notices.py")


def package(directory, name="dependency", version="1.0.0", license="MIT"):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "Cargo.toml").touch()
    return {"name": name, "version": version, "id": f"registry#{name}@{version}",
            "manifest_path": str(directory / "Cargo.toml"), "license": license,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "targets": [{"kind": ["lib"]}], "enabled_features": []}


class NoticeGenerationTests(unittest.TestCase):
    terms = "Permission is hereby granted, free of charge.\nTHE SOFTWARE IS PROVIDED AS IS."

    def test_runtime_graph_excludes_host_tools_but_keeps_shared_runtime_dependencies(self):
        packages = [{"id": name, "name": name, "targets": [{"kind": [kind]}]}
                    for name, kind in [("app", "bin"), ("runtime", "lib"), ("macro", "proc-macro"),
                                       ("host-only", "lib"), ("shared", "lib"), ("dev", "lib"), ("build", "lib")]]
        edge = lambda name, kind=None: {"pkg": name, "dep_kinds": [{"kind": kind}]}
        nodes = [{"id": name, "features": [], "deps": []} for name in [p["id"] for p in packages]]
        nodes[0]["deps"] = [edge("runtime"), edge("macro"), edge("dev", "dev"), edge("build", "build")]
        nodes[1]["deps"] = [edge("shared")]
        nodes[2]["deps"] = [edge("host-only"), edge("shared")]
        metadata = {"packages": packages, "resolve": {"root": "app", "nodes": nodes}}
        self.assertEqual({p["name"] for p in notices.runtime_packages(metadata)}, {"runtime", "shared"})

    def test_generation_filters_target_features_and_tracks_lockfile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = package(root, "app")
            dependency = package(root / "dep")
            Path(dependency["manifest_path"]).with_name("LICENSE").write_text("Copyright Owner\n" + self.terms)
            (root / "Cargo.lock").write_bytes(b"locked dependencies")
            metadata = {"packages": [app, dependency], "resolve": {"root": app["id"], "nodes": [
                {"id": app["id"], "features": [], "deps": [{"pkg": dependency["id"], "dep_kinds": [{"kind": None}]}]},
                {"id": dependency["id"], "features": [], "deps": []}]}}
            with patch.object(notices, "cargo", return_value=json.dumps(metadata)) as command:
                result = notices.generate(root, "aarch64-apple-darwin", "metrics", offline=True)
            args = command.call_args.args[1]
            self.assertEqual(args[args.index("--filter-platform") + 1], "aarch64-apple-darwin")
            self.assertEqual(args[args.index("--features") + 1], "metrics")
            self.assertNotIn("--all-features", args)
            self.assertNotIn("--no-default-features", args)
            self.assertIn(b"Crates: 1", result)
            self.assertIn(hashlib.sha256(b"locked dependencies").hexdigest().encode(), result)
            with patch.object(notices, "cargo", return_value=json.dumps(metadata)) as command:
                notices.generate(root, "target", "metrics", offline=True, no_default_features=True)
            self.assertIn("--no-default-features", command.call_args.args[1])

    def test_license_alternatives_and_mandatory_combinations(self):
        for expression in ["MIT OR Apache-2.0", "MIT/Apache-2.0", "Apache-2.0 / MIT",
                           "Apache-2.0 WITH LLVM-exception OR MIT", "Unlicense OR MIT"]:
            self.assertEqual(notices.selected_licenses(expression), {"MIT"})
        self.assertEqual(notices.selected_licenses("(MIT OR Apache-2.0) AND Unicode-3.0"), {"MIT", "Unicode-3.0"})
        self.assertEqual(notices.selected_licenses("MIT AND BSD-3-Clause"), {"MIT", "BSD-3-Clause"})
        for expression in ["GPL-3.0-only", "MIT AND Unknown", "MIT AND", "MIT OR", "(MIT", "MIT) OR Apache-2.0",
                           "MIT OR OR Apache-2.0", "MIT WITH", "MIT & Apache-2.0"]:
            with self.assertRaises(ValueError, msg=expression):
                notices.selected_licenses(expression)

    def test_only_selected_terms_and_required_attribution_are_collected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependency = package(root, license="MIT OR Apache-2.0")
            (root / "LICENSE-MIT").write_text("Copyright MIT Owner\n" + self.terms)
            (root / "LICENSE-APACHE").write_text("Apache alternative should be excluded")
            (root / "NOTICE").write_text("Additional required attribution")
            (root / "examples").mkdir()
            (root / "examples/LICENSE").write_text("Unrelated example license")
            (root / "source.rs").write_text("// Copyright unrelated source variant\nfn code() {}")
            chosen, texts = notices.legal_texts(dependency, "target", {})
            self.assertEqual(chosen, {"MIT"})
            self.assertEqual(set(texts), {"Copyright MIT Owner\n" + self.terms, "Additional required attribution"})
            (root / "third_party").mkdir()
            (root / "third_party/LICENSE").write_text("Unreviewed nested license")
            with self.assertRaisesRegex(ValueError, "nested legal files require review"):
                notices.legal_texts(dependency, "target", {})
            (root / "third_party/LICENSE").unlink()
            (root / "LICENSE-vendor").write_text("Required vendor BSD notice")
            with self.assertRaisesRegex(ValueError, "additional legal file requires review"):
                notices.legal_texts(dependency, "target", {})

    def test_missing_terms_or_changed_reviewed_inputs_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependency = package(root)
            with self.assertRaisesRegex(ValueError, "missing full MIT terms"):
                notices.legal_texts(dependency, "target", {})
            (root / "LICENSE").write_text("Copyright Owner\n" + self.terms)
            digest = hashlib.sha256((root / "LICENSE").read_bytes()).hexdigest()
            policy = {"dependency": {"version": "1.0.0", "sha256": {"LICENSE": digest}}}
            notices.reviewed_policy(dependency, policy)
            (root / "LICENSE").write_text("altered terms")
            with self.assertRaisesRegex(ValueError, "input changed"):
                notices.reviewed_policy(dependency, policy)
            dependency["version"] = "2.0.0"
            with self.assertRaisesRegex(ValueError, "update reviewed notice policy"):
                notices.reviewed_policy(dependency, policy)

    def test_prometheus_schema_notice_only_when_protobuf_is_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dependency = package(root, "metrics-exporter-prometheus", license="MIT AND Apache-2.0")
            (root / "LICENSE").write_text("Copyright Metrics Owner\n" + self.terms)
            (root / "proto").mkdir()
            (root / "proto/metrics.proto").write_text("// Copyright Prometheus Team\n// Licensed under Apache License\nsyntax = \"proto2\";")
            policy = {dependency["name"]: {"version": "1.0.0", "sha256": {}}}
            chosen, texts = notices.legal_texts(dependency, "target", policy)
            self.assertEqual(chosen, {"MIT"})
            self.assertNotIn("Prometheus Team", "\n".join(texts))
            dependency["enabled_features"] = ["protobuf"]
            chosen, texts = notices.legal_texts(dependency, "target", policy)
            self.assertEqual(chosen, {"MIT", "Apache-2.0"})
            self.assertIn("Prometheus Team", "\n".join(texts))
            self.assertIn("END OF TERMS AND CONDITIONS", "\n".join(texts))

    def test_ring_native_notices_are_selected_by_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build.rs").write_text('const RING_SRCS: &[(&[&str], &str)] = &[\n'
                                          '(&[], "common.c"),\n(&[X86_64], "intel.pl"),\n'
                                          '(&[AARCH64], "arm.pl"),\n];')
            for filename, owner in [("common.c", "Common"), ("intel.pl", "Intel"), ("arm.pl", "ARM")]:
                (root / filename).write_text("// Copyright " + owner + "\n// Terms\n\ncode")
            for filename in ["src/polyfill/once_cell/LICENSE-MIT", "third_party/fiat/LICENSE"]:
                path = root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("Copyright Nested Owner")
            intel = "\n".join(notices.ring_notices(root, "x86_64-unknown-linux-gnu"))
            arm = "\n".join(notices.ring_notices(root, "aarch64-apple-darwin"))
            self.assertIn("Copyright Intel", intel)
            self.assertNotIn("Copyright ARM", intel)
            self.assertIn("Copyright ARM", arm)
            self.assertNotIn("Copyright Intel", arm)

    def test_shared_terms_preserve_each_owner_and_output_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = package(root / "a", "a"), package(root / "b", "b")
            (root / "a/LICENSE").write_text("Copyright A\n" + self.terms)
            (root / "b/LICENSE").write_text("Copyright B\n" + self.terms.replace(" ", "  "))
            result = notices.render([first, second], "target", "features", "digest", {})
            self.assertEqual(result, notices.render([second, first], "target", "features", "digest", {}))
            self.assertEqual(result.count(self.terms.encode()), 1)
            self.assertIn(b"Copyright A", result)
            self.assertIn(b"Copyright B", result)

    def test_apache_terms_share_one_copy_and_retain_substituted_copyright(self):
        canonical = (ROOT / "scripts/licenses/Apache-2.0.txt").read_text().strip()
        custom = canonical.replace("Copyright [yyyy] [name of copyright owner]", "Copyright [2019] [Mike Heffner]")
        attribution, body = notices.split_terms(custom)
        self.assertIn("Copyright [2019] [Mike Heffner]", attribution)
        self.assertEqual(body, canonical)
        altered = custom.replace("perpetual", "temporary")
        self.assertNotEqual(notices.split_terms(altered)[1], canonical)

    def test_comment_removal_does_not_leave_c_comment_terminators(self):
        self.assertEqual(notices.uncomment("/* Copyright Owner\n * Terms\n */"), "Copyright Owner\nTerms")

    def test_stale_check_does_not_modify_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notices.txt"
            with self.assertRaisesRegex(ValueError, "missing or stale"):
                notices.check_current(path, b"current")
            path.write_bytes(b"stale")
            with self.assertRaisesRegex(ValueError, "missing or stale"):
                notices.check_current(path, b"current")
            self.assertEqual(path.read_bytes(), b"stale")
            notices.check_current(path, b"stale")


class PackagedNoticeTests(unittest.TestCase):
    expected = b"Copyright Owner\nComplete terms\n"

    def write_archive(self, path, members):
        if path.suffix == ".zip":
            with zipfile.ZipFile(path, "w") as archive:
                for name, content in members:
                    archive.writestr(name, content)
        else:
            with tarfile.open(path, "w:gz" if path.suffix == ".gz" else "w") as archive:
                for name, content in members:
                    member = tarfile.TarInfo(name)
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))

    def test_tar_and_zip_reject_missing_stale_and_conflicting_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            for extension in ("tar.gz", "zip"):
                path = Path(directory) / f"package.{extension}"
                name = f"package/{packaged.NOTICE}"
                self.write_archive(path, [(name, self.expected)])
                self.assertEqual(packaged.check_archive(path, self.expected), 1)
                self.write_archive(path, [("package/stamp-suite", b"binary")])
                with self.assertRaisesRegex(ValueError, "missing"):
                    packaged.check_archive(path, self.expected)
                self.write_archive(path, [(name, b"stale")])
                with self.assertRaisesRegex(ValueError, "stale or altered"):
                    packaged.check_archive(path, self.expected)
                self.write_archive(path, [(name, self.expected), ("another/" + name, b"stale")])
                with self.assertRaisesRegex(ValueError, "stale or altered"):
                    packaged.check_archive(path, self.expected)

    def test_gzipped_doc_file_is_compared_after_decompression(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "package.tar.gz"
            self.write_archive(path, [("usr/share/doc/stamp-suite/" + packaged.NOTICE + ".gz",
                                       gzip.compress(self.expected))])
            self.assertEqual(packaged.check_archive(path, self.expected), 1)

    def test_deb_payload_is_inspected_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "payload.tar.gz"
            self.write_archive(payload, [("./usr/share/doc/stamp-suite/" + packaged.NOTICE, self.expected)])
            result = subprocess.CompletedProcess([], 0, stdout=payload.read_bytes())
            with patch.object(packaged.subprocess, "run", return_value=result) as command:
                self.assertEqual(packaged.check_archive(Path("package.deb"), self.expected), 1)
            self.assertEqual(command.call_args.args[0], ["dpkg-deb", "--fsys-tarfile", "package.deb"])

    def test_rpm_tar_payload_rejects_missing_stale_and_conflicting_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rpm = root / "package.rpm"
            rpm.write_bytes(b"RPM input")
            payload = root / "payload.tar"
            name = "./usr/share/doc/stamp-suite/" + packaged.NOTICE
            cases = [
                ([(name, self.expected)], None),
                ([(name + ".gz", gzip.compress(self.expected))], None),
                ([("./usr/bin/stamp-suite", b"binary")], "missing"),
                ([(name, b"stale")], "stale or altered"),
                ([(name, self.expected), ("another/" + name, b"stale")], "stale or altered"),
            ]
            for members, error in cases:
                with self.subTest(members=[name for name, _ in members]):
                    self.write_archive(payload, members)
                    result = subprocess.CompletedProcess([], 0, stdout=payload.read_bytes())

                    def convert(args, *, stdin, check, stdout):
                        self.assertEqual(args, ["rpm2archive", "-n", "-"])
                        self.assertEqual(stdin.read(), rpm.read_bytes())
                        self.assertTrue(check)
                        self.assertEqual(stdout, subprocess.PIPE)
                        return result

                    with patch.object(packaged.subprocess, "run", side_effect=convert):
                        if error:
                            with self.assertRaisesRegex(ValueError, error):
                                packaged.check_archive(rpm, self.expected)
                        else:
                            self.assertEqual(packaged.check_archive(rpm, self.expected), 1)

    def test_rpm_conversion_failure_and_invalid_tar_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            rpm = Path(directory) / "package.rpm"
            rpm.touch()
            with patch.object(packaged.subprocess, "run",
                              side_effect=subprocess.CalledProcessError(1, ["rpm2archive"])):
                with self.assertRaises(subprocess.CalledProcessError):
                    packaged.check_archive(rpm, self.expected)
            result = subprocess.CompletedProcess([], 0, stdout=b"invalid tar")
            with patch.object(packaged.subprocess, "run", return_value=result):
                with self.assertRaises(tarfile.TarError):
                    packaged.check_archive(rpm, self.expected)

    def test_unmatched_archive_pattern_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / packaged.NOTICE
            path.write_bytes(self.expected)
            with patch("sys.argv", ["check_packaged_notices", "--notices", str(path), str(root / "*.zip")]):
                self.assertEqual(packaged.main(), 1)


if __name__ == "__main__":
    unittest.main()
