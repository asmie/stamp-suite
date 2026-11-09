# Successor BER migration evidence — 9 November 2026

T5c validates the active `draft-ietf-bpm-stamp-ber-01` profile after T5b
(`3783462`), fixes a stateful error-reply signing defect found by the independent
peer, and moves the standards pin. This report describes local execution with
the uncommitted T5c changes. Remote CI has not run this change; no release,
commit, push or external author message was performed.

## Outcome

| Check | Result |
|---|---|
| Independent BER wire peer, default features | 60/60 cases passed, complete report |
| Independent BER wire peer, all features | 60/60 cases passed, complete report |
| Existing independent protocol combinations | 16/16 cases passed for each build |
| Full Rust suites: default / all / pnet | 1,308 / 1,409 / 1,264 passed; 12 / 12 / 13 privileged tests ignored |
| Required isolated route-MTU test | One test passed, all eight combinations; no prerequisite skip |
| Python evidence tests | 81 passed, including 11 new BER oracle tests |
| Clippy | Default, all-features and pnet all-targets passed with warnings denied |
| Rust 1.87 | Locked all-features/all-targets check passed |
| Rustdoc / rustfmt / matrix counts / citations | Passed; 1,019 source citations resolve |
| Standards metadata, live and offline replay | Exit 0; all implemented revisions current; expired YANG watch remains advisory |

All-features selects the Linux nix backend. The pnet result above is the Cargo
suite, not the independent live BER profile. Ordinary ignored tests are not
runtime passes; the MTU test was separately executed with required prerequisites.
Native Windows/macOS runtime, physical LAG/NIC tests and a new fuzz campaign
were not performed for this chunk. Codec/reflector fuzz results from T5a/T5b
remain historical evidence in the [migration guide](../../ber-migration.md).

## Independent wire evidence

[`scripts/interop_ber.py`](../../../scripts/interop_ber.py) is a Python standard-library
wire implementation, independent of the Rust serializer, BER helper, sender and
reflector. Sources are the [BPM -01 draft](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-ber-01.txt),
[RFC 8762](https://www.rfc-editor.org/rfc/rfc8762.html) and
[RFC 8972](https://www.rfc-editor.org/rfc/rfc8972.html).
Only agreed experimental outer Type 243 and nested Type 241 are used;
TBA1/TBA2 remain unassigned in this profile.

Each build ran 12 reflector and 48 sender configurations across IPv4/IPv6,
unkeyed open, keyed open and authenticated base modes. Reflector configurations
also cover stateful/stateless sequencing. Sender configurations combine
default/explicit five-byte patterns with baseline, sample-gating and parent/child
U behavior. Each successful run records 216 probes to the reflector, 212 replies
and four expected invalid-base timeouts. The independent reflector receives
252 sender probes and sends 288 replies, including deliberate duplicates.
Readiness traffic is separate and excluded from these counts.

The [17 frozen logical request vectors](../../../tests/fixtures/residual-ber/requests.json)
exercise counters, four/five-byte patterns, corrected padding, unknown nested
values, missing/duplicate fields, semantic/framing M boundaries, C, opaque
remainders and retired legacy types. Independent expected values include a
four-bit burst crossing byte/pattern boundaries. Sender tests check emitted
zero counters and padding, sign crafted responses and validate directional
counts, denominators, burst statistics, rates and computation intervals.
Unusable signed metadata adds no BER sample. A nonzero count with burst zero
retains the count without adding a burst sample. U disables later BER requests
while three delay/loss replies remain counted.

The [frozen observations](../../../tests/fixtures/residual-ber/replies.json)
contain every default-build reflector reply and sender request/summary record,
plus provenance hashes. They are application regression inputs, not independent
certification. Oracle tests replay them, deliberately alter signed semantic
fields, HMACs, copied failure values, padding and summaries, and verify complete
failure-report bookkeeping. The HMAC primitive has an RFC 4231 known-answer
test; the BER reference uses an XOR bit string rather than the Rust algorithm.

The live run first exposed a defect: after the session selected its actual
sequence, the final signer failed to find the generated HMAC behind a
well-framed M-marked BER value with nonzero padding. It retained an assembly-time
sequence-zero digest. The regression failed before the fix and passes now.
The signer traverses complete frames past semantic M for an owned/generated
HMAC. Incoming failed HMACs remain unchanged in I-marked copies, as required
by RFC 8972 §4.8; they must not be regenerated as successful digests.

[`runs.json`](runs.json) preserves all 120 case outcomes and run provenance.
The default run began at 10:00:16 UTC, all-features at 10:02:09 UTC on
Linux 6.18.54.1 WSL2 x86_64, Python 3.14.4, Rust 1.99.1.

| Input/artifact | SHA-256 |
|---|---|
| Default binary | `8b99358bfc5f718f9fed592e36590e06ee2ad25935ab2efa84718ef47a2030d6` |
| All-features binary | `2d524e0c01b348d4d791a47e3564cdf517d9b557aa0ce1454a9afee8689fdb55` |
| BER runner | `93e9af2841f41d1ebebc6cbecfbccad10f10919fee71023d65d9478a582acfd0` |
| Request vectors | `a2721f69b0baf9e9b86ef23cc543c041be5523733cbc07ae19021148d537dc01` |

Full reports from this execution are local temporary artifacts:
`/tmp/stamp-t5c-ber-default.json`, `/tmp/stamp-t5c-ber-all.json`,
`/tmp/stamp-t5c-wire-default.json` and `/tmp/stamp-t5c-wire-all.json`.
Their full BER report hashes are in `runs.json`; frozen UDP observations are
tracked separately. Temporary artifacts are not a durable CI archive.
`conformance.yml` now requires both BER build profiles and uploads their full
wire reports alongside the existing suite, including when a case fails.

## MTU and standards evidence

The required route-MTU test ran inside isolated user/network namespaces:

```sh
cargo test --locked --all-features --test route_mtu_test --no-run --message-format=json > /tmp/t5c-mtu-artifacts.json
python3 scripts/run_privileged_test.py /tmp/t5c-mtu-artifacts.json route_mtu_test 1 unshare -Urn env STAMP_MTU_NETNS_TESTS=1 TOKIO_WORKER_THREADS=2
```

It passed IPv4/IPv6 × open/authenticated × wildcard/bound source combinations,
checking route MTU decreases/increases, route metrics, alternate destinations,
single-reply limits, whole-pattern BER trimming, optional header trimming and
final signatures. It does not establish end-to-end PMTU discovery.

The [rebuilt matrix](../../conformance/draft-stamp-ber.md) has 54 clauses:
48 Compliant, four Partial, one Gap and one N-A. Partial rows cover validation
when UDP checksums are zero, MTU across platforms, physical LAG and automatic
link-MTU filling. Specific BER conformance-error logs/counters remain a SHOULD
Gap. The overall rollup is 471 clauses: 395 Compliant, 23 Partial, two Gap,
48 N-A and three Excluded. Revision tracking being current does not close
these implementation/evidence limitations.

The manifest now pins `draft-ietf-bpm-stamp-ber-01`. Live authoritative metadata
and its offline replay both passed; [standards.json](standards.json) records
the results and source identities. The sole advisory is expired watch-only
`draft-ietf-ippm-stamp-yang-12`. Local full metadata/report artifacts are
`/tmp/stamp-t5c-standards-source` and `/tmp/stamp-t5c-standards.json`.

## Independent application compatibility

No GPL implementation, tests or comments were copied or used to derive the
oracle. Only build inputs, command help and emitted UDP data were inspected
for the black-box compatibility checks.

The draft-listed Teaparty `592558a` emits separate Types 9/10, which conflict
with assigned RFC 9503 types. Current origin/main fetched on 9 November,
`7fb2bdea48d42875e3237b97718f3c2149995b40`, was built separately and captured on
both families. It emits separate outer count Type 241 (four bytes) and pattern
Type 240, with padding Type 1. The [current captures and hashes](../../../tests/fixtures/residual-ber/teaparty-7fb2bde.json)
and [draft-listed captures](../../../tests/fixtures/residual-ber/teaparty-592558a.json)
establish incompatible layouts. Neither proves a successor exchange.
No Cisco IOS XR device was available. Successor BER interoperability with a
separately maintained application remains unverified.

## Reproduction

Run each build and its live suites sequentially so Cargo cannot replace a
binary while a test uses it:

```sh
cargo build --locked
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report /tmp/ber-default.json
python3 scripts/interop_stamp.py --binary target/debug/stamp-suite --report /tmp/wire-default.json
cargo build --locked --all-features
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report /tmp/ber-all.json
python3 scripts/interop_stamp.py --binary target/debug/stamp-suite --report /tmp/wire-all.json
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check_conformance_counts.py
python3 scripts/check_conformance_citations.py
python3 scripts/check_standards.py --cache /tmp/ber-standards-source --report /tmp/ber-standards.json
python3 scripts/check_standards.py --offline /tmp/ber-standards-source --report /tmp/ber-standards-offline.json
```

These loopback checks transform delivered payloads with valid checksums;
they do not demonstrate raw physical-link error delivery. Explicit peer
agreement is required for experimental codepoints. Native platform runtime,
zero-checksum behavior, physical LAG/FEC and hardware timestamps require
separate evidence before expanding the conformance claims.
