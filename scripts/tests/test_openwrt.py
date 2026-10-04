import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from render_openwrt import render


class OpenWrtRecipeTests(unittest.TestCase):
    def test_digest_pins_exact_archive_and_preserves_template_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            template = (Path(__file__).resolve().parents[2] / "dist/openwrt/Makefile").read_text()
            version = next(line.split(":=", 1)[1] for line in template.splitlines() if line.startswith("PKG_VERSION:="))
            archive = Path(directory) / f"stamp-suite-{version}.tar.gz"
            archive.write_bytes(b"release archive bytes")
            result = render(template, archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertIn(f"PKG_HASH:={digest}\n", result)
            self.assertNotIn("PKG_HASH:=skip", result)
            self.assertIn("ifeq ($(PKG_HASH),@SOURCE_SHA256@)", result)
            archive.write_bytes(b"changed release archive bytes")
            self.assertNotEqual(result, render(template, archive))

    def test_version_mismatch_and_missing_placeholder_are_errors(self):
        with self.assertRaises(ValueError):
            render("PKG_VERSION:=1.0.0\nPKG_HASH:=@SOURCE_SHA256@", Path("wrong.tar.gz"))
        with self.assertRaises(ValueError):
            render("PKG_VERSION:=1.0.0\nPKG_HASH:=skip", Path("stamp-suite-1.0.0.tar.gz"))
