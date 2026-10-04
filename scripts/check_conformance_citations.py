#!/usr/bin/env python3
"""Check the source citations in doc/conformance/*.md against the tree.

Run from the repository root:

    python3 scripts/check_conformance_citations.py          # report + exit code
    python3 scripts/check_conformance_citations.py --json    # machine-readable

Exit nonzero for stale citations. Checks:
- `path.rs::item`: item defined in that file or its child modules. Derived
  methods such as Type::default check the type.
- `ident` (`path.rs`): definition, or a qualified name used in that file.
- Bare file paths: must exist; filenames must resolve uniquely.
- `path.rs:N[-M]`: range must overlap a preceding named item's extent.
  No overlap is stale; no matching definition is unverifiable.
"""
import argparse
import glob
import json
import os
import re
import sys
from collections import Counter

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--root", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
parser.add_argument("--json", action="store_true")
parser.add_argument("--details", action="store_true", help="include all citations, including unverified evidence")
args = parser.parse_args()
ROOT = os.path.abspath(args.root)
CITE = re.compile(r'([A-Za-z0-9_./-]+\.rs):(\d+)(?:-(\d+))?')
BACKTICK = re.compile(r'`([^`]+)`')
GOOD = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*$')

paths = []
for base in ("src", "tests", "benches", "fuzz", "examples"):
    for dp, _d, fs in os.walk(os.path.join(ROOT, base)):
        if "target" in dp:
            continue
        paths += [os.path.relpath(os.path.join(dp, f), ROOT) for f in fs if f.endswith(".rs")]

cache = {}


def lines_of(p):
    if p not in cache:
        cache[p] = open(os.path.join(ROOT, p), encoding="utf-8").read().splitlines()
    return cache[p]


def resolve(c):
    if os.path.exists(os.path.join(ROOT, c)):
        return c
    m = [p for p in paths if p.endswith("/" + c)]
    return m[0] if len(m) == 1 else None


def scope(p):
    """The file plus its child-module files."""
    if p.endswith("/mod.rs"):
        prefix = p[: -len("mod.rs")]
    elif os.path.isdir(os.path.join(ROOT, p[:-3])):
        prefix = p[:-3] + "/"
    else:
        return [p]
    return [p] + [q for q in paths if q.startswith(prefix) and q != p]


DERIVED = {"default", "clone", "fmt", "eq", "ne", "cmp", "partial_cmp", "hash", "from_str", "to_string"}


def target_name(ident):
    """The name to look up: the last segment, or the type for a derived method."""
    parts = ident.split("::")
    if len(parts) > 1 and parts[-1] in DERIVED:
        return parts[-2]
    return parts[-1]


def defined_in(ident, files):
    return any(defs(f, target_name(ident)) for f in files)


def is_item(n):
    if not GOOD.match(n):
        return False
    t = n.split("::")[-1]
    return "::" in n or "_" in t or t[:1].isupper()


DEFPATS = [
    r'\bfn\s+{0}\s*[(<]',
    r'\b(?:struct|enum|trait|union)\s+{0}\b',
    r'\b(?:const|static)\s+{0}\s*:',
    r'\btype\s+{0}\s*=',
    r'^\s*(?:pub(?:\([^)]*\))?\s+)?{0}\s*:\s',
    r'\bmod\s+{0}\b',
    r'macro_rules!\s*{0}\b',
    r'^\s*{0}\s*(?:=|,|\(|\{{|$)',
]


def defs(path, ident):
    """All definition lines for ident in path (a name may be defined once, but
    macros/impl blocks can repeat it)."""
    t = re.escape(ident.split("::")[-1])
    found = []
    for raw in DEFPATS:
        pat = re.compile(raw.format(t))
        for i, line in enumerate(lines_of(path), 1):
            if pat.search(line):
                found.append(i)
        if found:
            break
    return found


def extent(path, start):
    src = lines_of(path)
    depth, seen = 0, False
    for i in range(start - 1, min(len(src), start + 400)):
        for ch in src[i]:
            if ch == '{':
                depth += 1
                seen = True
            elif ch == '}':
                depth -= 1
        if seen and depth <= 0:
            return start, i + 1
    return start, start


PATH_ITEM = re.compile(r'`([A-Za-z0-9_./-]+\.rs)::([A-Za-z_][A-Za-z0-9_:]*)`')
PLAIN = re.compile(r'`([A-Za-z0-9_./-]+\.rs)`')
# `a`, `b` and `c` (`x.rs`, `y.rs`)
ATTRIBUTED = re.compile(
    r'((?:`[^`]+`(?:\s*,\s*|\s+and\s+|\s+or\s+|\s*/\s*)?)+)\s*'
    r'\(((?:`[A-Za-z0-9_./-]+\.rs`(?:\s*,\s*|\s+and\s+)?)+)\)')

rows = []


def check_named_citations(md, lineno, row):
    base = {"md": os.path.relpath(md, ROOT), "md_line": lineno}
    for m in PATH_ITEM.finditer(row):
        path = resolve(m.group(1))
        rec = dict(base, cite=m.group(0).strip("`"), path=path)
        if path is None:
            rec["status"] = "unresolved"
        elif defined_in(m.group(2), scope(path)):
            rec["status"] = "ok"
        else:
            rec["status"] = "missing-item"
        rows.append(rec)
    for m in PLAIN.finditer(row):
        rows.append(dict(base, cite=m.group(1), path=resolve(m.group(1)),
                         status="ok" if resolve(m.group(1)) else "unresolved"))
    for m in ATTRIBUTED.finditer(row):
        cited = [resolve(f) for f in BACKTICK.findall(m.group(2))]
        files = [f for p in cited if p for f in scope(p)]
        if not files:
            continue  # the unresolved path is already reported above
        for ident in BACKTICK.findall(m.group(1)):
            if not is_item(ident):
                continue
            used = "::" in ident and any(ident in "\n".join(lines_of(f)) for f in files)
            ok = used or defined_in(ident, files)
            rec = dict(base, cite=f"{ident} ({', '.join(p for p in cited if p)})",
                       status="ok" if ok else "misattributed")
            if not ok:
                rec["defined_in"] = [p for p in paths if defs(p, target_name(ident))][:3]
            rows.append(rec)


for md in sorted(glob.glob(os.path.join(ROOT, "doc/conformance/*.md"))):
    for lineno, row in enumerate(open(md, encoding="utf-8").read().splitlines(), 1):
        check_named_citations(md, lineno, row)
        cites = list(CITE.finditer(row))
        if not cites:
            continue
        # window for each citation = text since previous citation
        prev = 0
        wins = []
        for m in cites:
            wins.append(row[prev:m.start()])
            prev = m.end()
        for m, win in zip(cites, wins):
            path = resolve(m.group(1))
            lo = int(m.group(2))
            hi = int(m.group(3)) if m.group(3) else lo
            rec = {"md": os.path.relpath(md, ROOT), "md_line": lineno,
                   "cite": m.group(0), "path": path, "start": lo, "end": hi}
            if path is None:
                rec["status"] = "unresolved"
                rows.append(rec)
                continue
            src = lines_of(path)
            if lo < 1 or hi < lo or hi > len(src):
                rec["status"] = "OUT-OF-RANGE"
                rec["file_len"] = len(src)
                rows.append(rec)
                continue
            idents = [s for s in BACKTICK.findall(win) if is_item(s)]
            # de-dup, keep order nearest-last
            seen_i = set()
            idents = [i for i in idents if not (i in seen_i or seen_i.add(i))]
            anchors = []
            for ident in idents[-4:]:
                for d in defs(path, ident):
                    anchors.append((ident, d, extent(path, d)))
            if not anchors:
                rec["status"] = "unverifiable"
                rec["idents"] = idents[-4:]
                rows.append(rec)
                continue
            hit = [a for a in anchors if not (a[2][1] < lo or a[2][0] > hi)]
            if hit:
                rec["status"] = "ok"
                rec["anchor"] = hit[0][0]
            else:
                # nearest anchor wins as the suggestion
                ident, d, ex = anchors[-1]
                rec["status"] = "STALE"
                rec["anchor"] = ident
                rec["anchor_def"] = d
                rec["anchor_extent"] = ex
                rec["all_anchors"] = [[a[0], a[1]] for a in anchors]
                rec["suggest"] = list(ex) if hi != lo else [d, d]
            rows.append(rec)

c = Counter(r["status"] for r in rows)
FAILING = ("STALE", "OUT-OF-RANGE", "unresolved", "missing-item", "misattributed")
stale = [r for r in rows if r["status"] in FAILING]

if args.json:
    report = {"counts": dict(c), "problems": stale}
    if args.details:
        report["citations"] = rows
    print(json.dumps(report, indent=1))
else:
    print(f"citations examined: {len(rows)}")
    for k in ("ok", "unverifiable") + FAILING:
        if c.get(k):
            print(f"  {c[k]:4d}  {k}")
    for r in stale:
        detail = f" (anchor `{r['anchor']}` is at {r.get('anchor_def')})" if r.get("anchor") else ""
        if r.get("defined_in") is not None:
            detail = f" (defined in {', '.join(r['defined_in']) or 'no source file'})"
        print(f"\n{r['status'].upper()} {r['md']}:{r['md_line']}  {r['cite']}{detail}")
        if r.get("suggest"):
            print(f"        suggested: {r['cite'].split(':')[0]}:"
                  f"{r['suggest'][0]}-{r['suggest'][1]}")

sys.exit(1 if stale else 0)
