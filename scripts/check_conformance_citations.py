#!/usr/bin/env python3
"""Check the file:line citations in doc/conformance/*.md against the tree.

Run from the repository root:

    python3 scripts/check_conformance_citations.py          # report + exit code
    python3 scripts/check_conformance_citations.py --json    # machine-readable

Exits non-zero when a citation has drifted, so this can gate CI. Citation drift
was a recurring finding in the 1.0 audit — the matrices are the compliance
evidence, and a citation pointing at the wrong construct quietly devalues it.

Verdict rule: a citation is OK when the cited line range intersects the *extent*
(definition line .. closing brace) of any identifier named beside it in the same
row. That tolerates a citation pointing into a function body rather than at its
signature, and rows whose several named items share a citation group.

"unverifiable" is not a failure: many citations follow prose that names no
backticked identifier, or name an item defined in a different file (a call site).
Those are reported for transparency but cannot be machine-checked. Where a
citation could not be pinned during the 2026-08-05 refresh, its line number was
deliberately removed and only the path kept — a coarse citation that is correct
beats a precise one that is confidently wrong.


Verdict rule: a citation is OK when the cited line range intersects the *extent*
(definition line .. closing brace) of ANY plausible identifier named next to it.
That tolerates citations pointing at a body line rather than the signature, and
citations shared by a row that names several items.

STALE requires: at least one adjacent identifier is defined in the cited file,
and NONE of the adjacent identifiers' extents intersect the cited range.
"""
import glob
import json
import os
import re
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CITE = re.compile(r'([A-Za-z0-9_./-]+\.rs):(\d+)(?:-(\d+))?')
BACKTICK = re.compile(r'`([^`]+)`')
GOOD = re.compile(r'^(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*$')

paths = []
for base in ("src", "tests", "benches", "fuzz"):
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
    r'^\s*(?:pub\s+)?{0}\s*:\s',
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


rows = []
for md in sorted(glob.glob(os.path.join(ROOT, "doc/conformance/*.md"))):
    for lineno, row in enumerate(open(md, encoding="utf-8").read().splitlines(), 1):
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
            if lo > len(src):
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
stale = [r for r in rows if r["status"] in ("STALE", "OUT-OF-RANGE", "unresolved")]

if "--json" in sys.argv:
    print(json.dumps({"counts": dict(c), "problems": stale}, indent=1))
else:
    print(f"citations examined: {len(rows)}")
    for k in ("ok", "unverifiable", "STALE", "OUT-OF-RANGE", "unresolved"):
        if c.get(k):
            print(f"  {c[k]:4d}  {k}")
    for r in stale:
        detail = f" (anchor `{r['anchor']}` is at {r.get('anchor_def')})" if r.get("anchor") else ""
        print(f"\nDRIFTED {r['md']}:{r['md_line']}  {r['cite']}{detail}")
        if r.get("suggest"):
            print(f"        suggested: {r['cite'].split(':')[0]}:"
                  f"{r['suggest'][0]}-{r['suggest'][1]}")

sys.exit(1 if stale else 0)
