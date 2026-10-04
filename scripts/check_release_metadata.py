#!/usr/bin/env python3
"""Check release versions, Gentoo crates and the Windows executable stack."""
import argparse
from pathlib import Path
import re
import struct
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def check_metadata(root, expected=None):
    manifest = tomllib.loads((root / 'Cargo.toml').read_text())
    version = manifest['package']['version']
    if expected is not None and version != expected:
        raise ValueError(f'Cargo.toml: {version}, expected {expected}')
    sources = {
        'CHANGELOG.md': r'^## \[([0-9]+\.[0-9]+\.[0-9]+)\]',
        'dist/debian/changelog': r'^stamp-suite \(([0-9]+\.[0-9]+\.[0-9]+)-',
        'dist/openwrt/Makefile': r'^PKG_VERSION:=(.+)$',
        'dist/man/stamp-suite.1': r'^\.TH stamp-suite 1 +"stamp-suite ([0-9.]+)"',
    }
    for path, pattern in sources.items():
        match = re.search(pattern, (root / path).read_text(), re.MULTILINE)
        if match is None or match[1] != version:
            raise ValueError(f'{path}: expected version {version}')
    ebuild = root / f'dist/gentoo/net-analyzer/stamp-suite/stamp-suite-{version}.ebuild'
    text = ebuild.read_text()
    minimum = re.search(r'^RUST_MIN_VER="([^"]+)"', text, re.MULTILINE)
    if minimum is None or minimum[1] != manifest['package']['rust-version']:
        raise ValueError('Gentoo RUST_MIN_VER differs from Cargo.toml')
    crates = re.search(r'^CRATES="(.*?)"', text, re.MULTILINE | re.DOTALL)
    lock = tomllib.loads((root / 'Cargo.lock').read_text())
    expected_crates = {f"{p['name']}@{p['version']}" for p in lock['package']
                       if p.get('source', '').startswith('registry+')}
    if crates is None or set(crates[1].split()) != expected_crates:
        raise ValueError('Gentoo CRATES differs from Cargo.lock')
    fuzz = tomllib.loads((root / "fuzz/Cargo.toml").read_text())
    if fuzz["dependencies"]["stamp-suite"]["version"] != version:
        raise ValueError("Fuzz path dependency version differs from Cargo.toml")
    package = next(p for p in lock['package'] if p['name'] == 'stamp-suite')
    if package['version'] != version:
        raise ValueError('Cargo.lock version differs from Cargo.toml')
    return version


def check_windows_binary(path):
    data = path.read_bytes()
    if data[:2] != b'MZ':
        raise ValueError('Expected a PE executable')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', data, pe + 4)[0] != 0x8664:
        raise ValueError('Expected a Windows x64 executable')
    optional = pe + 24
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('Expected a PE32+ optional header')
    stack = struct.unpack_from('<Q', data, optional + 72)[0]
    if stack < 4 * 1024 * 1024:
        raise ValueError(f'Windows stack reserve is {stack}; need at least 4 MiB')
    return stack


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', help='Expected release version, without v')
    parser.add_argument('--windows-binary', type=Path)
    args = parser.parse_args()
    try:
        version = check_metadata(ROOT, args.version)
        if args.windows_binary:
            print(f'Windows stack reserve: {check_windows_binary(args.windows_binary)} bytes')
    except (OSError, ValueError, StopIteration, struct.error) as error:
        parser.exit(1, f'{error}\n')
    print(f'Release metadata agrees: {version}')


if __name__ == '__main__':
    main()
