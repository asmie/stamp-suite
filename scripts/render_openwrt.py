#!/usr/bin/env python3
"""Pin the OpenWrt recipe to the source archive produced by a release build."""

import argparse
import hashlib
from pathlib import Path
import re


def render(template: str, archive: Path) -> str:
    version = re.search(r"^PKG_VERSION:=(.+)$", template, re.MULTILINE)
    if version is None or archive.name != f"stamp-suite-{version[1]}.tar.gz":
        raise ValueError("source archive name must match the recipe version")
    marker = "PKG_HASH:=@SOURCE_SHA256@"
    if template.count(marker) != 1:
        raise ValueError("recipe must contain exactly one source hash placeholder")
    hasher = hashlib.sha256()
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    return template.replace(marker, f"PKG_HASH:={digest}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--template", type=Path,
                        default=Path(__file__).resolve().parents[1] / "dist/openwrt/Makefile")
    args = parser.parse_args()
    args.output.write_text(render(args.template.read_text(), args.archive))


if __name__ == "__main__":
    main()
