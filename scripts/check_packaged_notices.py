#!/usr/bin/env python3
"""Verify binary archives contain the exact generated third-party notice bundle."""

import argparse
import glob
import gzip
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
NOTICE = "THIRD_PARTY_NOTICES.txt"


def cpio_files(data):
    """Read the newc format emitted by rpm2cpio without extracting files."""
    offset = 0
    while offset < len(data):
        header = data[offset:offset + 110]
        if len(header) != 110 or header[:6] not in (b"070701", b"070702"):
            raise ValueError("invalid RPM cpio header")
        size = int(header[54:62], 16)
        name_size = int(header[94:102], 16)
        start = offset + 110
        end = start + name_size
        if not name_size or end > len(data) or data[end - 1] != 0:
            raise ValueError("invalid RPM cpio filename")
        name = data[start:end - 1].decode("utf-8")
        start = (end + 3) & ~3
        end = start + size
        if end > len(data):
            raise ValueError("truncated RPM cpio member")
        if name == "TRAILER!!!":
            return
        yield name, data[start:end]
        offset = (end + 3) & ~3
    raise ValueError("missing RPM cpio trailer")


def tar_notices(fileobj):
    with tarfile.open(fileobj=fileobj, mode="r:*") as archive:
        for member in archive.getmembers():
            if member.isfile() and Path(member.name).name in (NOTICE, NOTICE + ".gz"):
                yield member.name, archive.extractfile(member).read()


def packaged_notices(path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if Path(member.filename).name in (NOTICE, NOTICE + ".gz"):
                    yield member.filename, archive.read(member)
    elif path.suffix == ".deb":
        data = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(path)], check=True,
                              stdout=subprocess.PIPE).stdout
        yield from tar_notices(io.BytesIO(data))
    elif path.suffix == ".rpm":
        data = subprocess.run(["rpm2cpio", str(path)], check=True, stdout=subprocess.PIPE).stdout
        yield from ((name, content) for name, content in cpio_files(data)
                    if Path(name).name in (NOTICE, NOTICE + ".gz"))
    else:
        with path.open("rb") as stream:
            yield from tar_notices(stream)


def check_archive(path, expected):
    found = list(packaged_notices(path))
    if not found:
        raise ValueError(f"{path}: missing {NOTICE}")
    for name, content in found:
        if name.endswith(".gz"):
            content = gzip.decompress(content)
        if content != expected:
            raise ValueError(f"{path}: stale or altered notice bundle at {name}")
    return len(found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--notices", type=Path, default=ROOT / NOTICE)
    parser.add_argument("archives", nargs="+", help="archive paths or glob patterns (each must match)")
    args = parser.parse_args()
    try:
        expected = args.notices.read_bytes()
        if not expected:
            raise ValueError("expected notice bundle is empty")
        paths = set()
        for pattern in args.archives:
            matches = glob.glob(pattern)
            if not matches:
                raise ValueError(f"no archives match {pattern!r}")
            paths.update(Path(path) for path in matches)
        for path in sorted(paths):
            count = check_archive(path, expected)
            print(f"Verified {count} notice bundle(s): {path}")
    except (ValueError, OSError, EOFError, subprocess.CalledProcessError, tarfile.TarError,
            zipfile.BadZipFile) as error:
        print(f"Packaged notice check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
