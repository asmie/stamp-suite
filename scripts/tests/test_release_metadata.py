"""Reject version, crate-list and Windows stack drift before publishing."""
import importlib.util
from pathlib import Path
import shutil
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_metadata', ROOT / 'scripts/check_release_metadata.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseMetadataTests(unittest.TestCase):
    def test_versions_and_crate_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ['Cargo.toml', 'Cargo.lock', 'fuzz/Cargo.toml', 'CHANGELOG.md', 'dist/debian/changelog',
                         'dist/openwrt/Makefile', 'dist/man/stamp-suite.1',
                         'dist/gentoo/net-analyzer/stamp-suite/stamp-suite-1.0.0.ebuild']:
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, dest)
            self.assertEqual(release.check_metadata(root, '1.0.0'), '1.0.0')
            with self.assertRaises(ValueError):
                release.check_metadata(root, '1.0.1')
            ebuild = root / 'dist/gentoo/net-analyzer/stamp-suite/stamp-suite-1.0.0.ebuild'
            ebuild.write_text(ebuild.read_text().replace('CRATES="', 'CRATES="\n\tobsolete@0.1.0'))
            with self.assertRaisesRegex(ValueError, 'CRATES'):
                release.check_metadata(root)

    def test_windows_stack_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'stamp-suite.exe'
            data = bytearray(256)
            data[:2] = b'MZ'
            struct.pack_into('<I', data, 0x3c, 64)
            data[64:68] = b'PE\0\0'
            struct.pack_into('<H', data, 68, 0x8664)
            struct.pack_into('<H', data, 88, 0x20b)
            for size, passes in [(1024 * 1024, False), (4 * 1024 * 1024, True)]:
                struct.pack_into('<Q', data, 160, size)
                path.write_bytes(data)
                if passes:
                    self.assertEqual(release.check_windows_binary(path), size)
                else:
                    with self.assertRaisesRegex(ValueError, 'stack reserve'):
                        release.check_windows_binary(path)
            struct.pack_into('<H', data, 68, 0xaa64)
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'x64'):
                release.check_windows_binary(path)
