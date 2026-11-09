# Standards conformance

These matrices link STAMP requirements to implementation and test evidence.

Results apply to the frozen revisions and tested profiles. They do not
certify untested behavior.

## Matrices

| Document | Revision frozen | Clauses | Compliant | Partial | Gap | N-A | Excluded |
|---|---|---:|---:|---:|---:|---:|---:|
| [RFC 8762](rfc8762.md): STAMP base protocol | RFC 8762, March 2020 | 62 | 52 | 0 | 0 | 9 | 1 |
| [RFC 8972](rfc8972.md): STAMP optional extensions | RFC 8972, January 2021 | 151 | 144 | 0 | 0 | 7 | 0 |
| [RFC 9503](rfc9503.md): Destination Node Address and Return Path | RFC 9503, November 2023 | 26 | 22 | 0 | 0 | 3 | 1 |
| [RFC 9534](rfc9534.md): Micro-session ID (LAG) | RFC 9534, February 2024 | 18 | 7 | 8 | 1 | 2 | 0 |
| [RFC 8545](rfc8545.md): OWAMP/TWAMP port allocation | RFC 8545, March 2019 | 8 | 1 | 0 | 0 | 7 | 0 |
| [RFC 10052](draft-asymmetrical-pkts.md): Reflected Test Packet Control (Type 12) | RFC 10052, September 2026 | 47 | 36 | 3 | 0 | 7 | 1 |
| [draft-ietf-ippm-stamp-cos-ecn](draft-stamp-cos-ecn.md): CoS and ECN signaling | -02, 2 November 2026 | 30 | 17 | 4 | 0 | 9 | 0 |
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md): reflected headers (Types 246, 247) | -26, 27 October 2026 | 75 | 64 | 8 | 0 | 3 | 0 |
| [draft-ietf-bpm-stamp-ber](draft-stamp-ber.md): Residual BER | -01, 2 November 2026 | 54 | 48 | 4 | 1 | 1 | 0 |
| **Total** | | **471** | **391** | **27** | **2** | **48** | **3** |

[`standards.json`](standards.json) pins the revision of each document; see
[Checks](#checks).

## How to read a matrix

Each matrix starts with the frozen revision, a `Summary:` line with the counts,
and a scope section for limits that apply to many rows. The clause table
follows, then notes that hold evidence shared by several rows.

Every matrix uses the same columns:

| Column | Content |
|---|---|
| ID | Stable clause ID, for example `RFC8762-4-1` or `ext-hdr-4.1-C`. Other documents and scripts refer to it. |
| Clause | The normative text, quoted and trimmed, or paraphrased where the matrix says so. |
| Level | The BCP 14 keyword (MUST, SHOULD, MAY and so on). `MUST (implied)` marks a requirement the text states without an uppercase keyword, with a qualifier such as `structural` (a field format) where useful. `Descriptive` marks text with no keyword that still describes required behavior. `N-A` marks non-normative text. |
| Role | Which endpoint the clause binds: Sender, Reflector, Both or N-A. |
| Status | One of the statuses below. |
| Evidence | Code citations, then tests, then a short qualification. |

### Statuses

| Status | Meaning |
|---|---|
| Compliant | Implemented, with cited evidence, within the profile the matrix states (for example, provisioned session admission or a supported platform). |
| Partial | Implemented for some cases; a platform, backend or part of the behavior is missing. The row says what. |
| Gap | A requirement that applies but is not implemented. |
| N-A | Does not apply to stamp-suite, for example a TWAMP-Control message or an optional mode that is not implemented. |
| Excluded | Applies, but is outside the project's scope by decision. The row states the boundary and what the implementation does instead. |

A status may carry a qualifier in parentheses, such as `Compliant
(provisioned mode)`.

### Evidence citations

- `` `<file>.rs::<item>` `` names a function, type, constant or test in a
  file or its child modules.
- `` `<item>` (`<file>.rs`) `` attributes one or more identifiers to a file.
- `` `tests/<file>.rs::<test>` `` names an integration test.
- A bare `` `<file>.rs` `` names a file.

### Quoted text

The Clause column quotes RFCs and Internet-Drafts. That text is Copyright (c)
IETF Trust and the persons identified as the document authors, and is
reproduced under BCP 78 and the IETF Trust's Legal Provisions Relating to IETF
Documents. Each matrix links the source document it quotes.

## Known limits

This table is the shared profile reference for the README, architecture, test
inventory, interoperability guide and release checks. A Compliant row applies
only within its stated profile; an ignored test or successful compilation is
not runtime evidence. Historical reports remain tied to their recorded commit.

| Area | Supported profile and boundary | Evidence/details |
|---|---|---|
| Session admission | The default is permissive. RFC 8972 admission/provisioning rows are Compliant only with `--session-admission provisioned`; installing a key does not provision a session. | [RFC 8972 scope](rfc8972.md#scope), [provisioning](../usage.md#session-provisioning) |
| Reply correlation | The sender requires a complete echoed sequence and wire T1, even with lenient trailing-field parsing. Identical sequence/T1 pairs cannot prove freshness. Kernel TX corrections keep wire identity separate from OWD timing. | [Reply accounting and limits](../measurements.md#probes-reply-copies-and-duplicates) |
| Micro-sessions and LAG | Numeric IDs are encoded, checked and learned. Physical member association, egress steering and ingress-member validation are absent. Sender port-pair sharing is not demonstrated by reflector demultiplexing. Eight rows remain Partial and one Gap. | [RFC 9534](rfc9534.md), [sender reply validation](rfc9534.md#sender-reply-validation) |
| Header reflection | Both header types require explicit sender-IP disclosure permission. Linux nix can reflect Type 246 ancillary headers; fixed/nested headers (Type 247) need pnet. macOS nix and reverse-path header attachment return C. All-features selects nix. Revision 26's conflicting repeated-selector examples remain Partial. | [Backend support](draft-stamp-ext-hdr.md#backend-support), [revision interpretation](draft-stamp-ext-hdr.md#revision-26-interpretation) |
| MTU | Linux sender/reflector sizing uses a kernel route lookup, not end-to-end PMTU probing. Other platforms have fixed sender budgets; size-controlled/header replies needing a route budget are dropped. Sender dispatch now has Linux IPv4/IPv6 trim/restore and refusal tests, including actual Hop-by-Hop attachment. BER platform sizing remains Partial. | [RFC 10052 sizing](draft-asymmetrical-pkts.md#reply-size-and-route-mtu), [BER matrix](draft-stamp-ber.md), [test-evidence review](test-evidence.md) |
| Type 12 | Exact wire intervals and conservative first-request selection remain Partial. Identity protection is scored only for the authenticated profile with extension-HMAC verification. An optional HMAC in permissive open mode may be absent. | [RFC 10052 limits and profiles](draft-asymmetrical-pkts.md#identity-protection) |
| Return paths | IP/SRv6 support has explicit backend/route constraints. SR-MPLS is Excluded and receives U. A fallback reply is not evidence of successful SRH transit. | [RFC 9503 scope](rfc9503.md#scope), [privileged tests](../testing-netns.md) |
| Management | AgentX is a read-only subagent and is not scored in these protocol matrices; SET is unsupported. A separate master is required. YANG management is not implemented and its expired draft is watch-only. | [Observability](../usage.md#observability), [AgentX](../architecture.md#snmp-agentx-sub-agent) |
| BER | Four Partial rows cover zero-checksum validation, platform MTU, physical LAG and link-MTU filling; specific conformance-error logs/counters remain a SHOULD Gap. Wire tests use delivered software-loopback data with valid checksums, not raw-link/FEC error capture. A compatible maintained application peer remains unverified. | [BER matrix](draft-stamp-ber.md), [migration evidence](../interop/2026-11-09-ber/REPORT.md) |
| CoS/ECN | Revision 02 is reconciled within the scored profile; RFC 3168/9330 controller consistency and capability/bleaching diagnostics remain Partial. Reverse feedback is supported on Linux/macOS; Windows marking returns C. | [CoS/ECN scope](draft-stamp-cos-ecn.md#scope) |
| Platforms and hardware | Physical LAG/NIC timestamp evidence is absent. macOS has software receive timestamps; Windows driver-free checks do not establish driver-backed capture. A cross-build is not a native runtime test. | [Release verification](../release-evidence.md), [hardware timestamps](../testing-hardware-timestamps.md) |

## Experimental codepoints

These local allocations are defined in `src/tlv/experimental.rs`. Peers must
agree on their meaning; they are not IANA assignments.

| Codepoint | Registry | Constant | Specification | Needs |
|---|---|---|---|---|
| Type 243 | STAMP TLV Types (Experimental, 240-251) | `RESIDUAL_BER_TLV_TYPE` | draft-ietf-bpm-stamp-ber-01 §4 | IANA allocation of TBA1; explicit peer agreement |
| Sub-TLV Type 241 (of Type 243) | STAMP Sub-TLV Types (Experimental, 240-251) | `RESIDUAL_BER_PATTERN_SUBTLV_TYPE` | draft-ietf-bpm-stamp-ber-01 §4.1 | IANA allocation of TBA2; explicit peer agreement |
| Type 246 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_IPV6_EXT_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-26 §4.1, §4.2 | IANA allocation of TBA1 |
| Type 247 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_FIXED_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-26 §6.1, §6.2 | IANA allocation of TBA2 |
| Sub-TLV Type 240 (of Type 12) | STAMP Sub-TLV Types (Experimental, 240-251) | `REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` | draft-ietf-ippm-stamp-ext-hdr-26 §5.1 | IANA allocation of TBA3 |

Legacy outer Types 240–242 are retired and return U. Type 242 previously
collided with another implementation's Heartbeat TLV. The successor always
carries the burst field, so `--ber-omit-burst` is now a migration error. The
successor matrix and standards pin now track BPM revision 01. The
[migration report](../interop/2026-11-09-ber/REPORT.md) records independent
wire evidence and the incompatible layouts observed from Teaparty.

When a final allocation changes a wire identifier, update its constant,
record the change in `CHANGELOG.md`, and bump the minor version under the
project's draft-feature policy. There is no runtime codepoint override.

## Checks

Local checks keep the matrices consistent with themselves and with the
code and verify documentation targets. The `Conformance evidence` workflow
(`.github/workflows/conformance.yml`) runs these checks and the script unit
tests in `scripts/tests/` on
pushes and pull requests to `master` and `1.0-line`.

```sh
python3 scripts/check_conformance_counts.py
python3 scripts/check_conformance_citations.py
python3 scripts/check_doc_links.py
```

`check_conformance_counts.py` checks clause-ID uniqueness, the five statuses,
each matrix's `Summary:` counts and this page's totals. Status changes require
updates to the summary and [Matrices](#matrices) table.

`check_conformance_citations.py` resolves every citation in
`doc/conformance/*.md` against the source tree:

- `` `<file>.rs::<item>` `` must name an item defined in that file or its child
  modules.
- In `` `<item>` (`<file>.rs`) ``, each identifier must be defined in that file,
  or a path-qualified name must appear in it.
- Every `` `<file>.rs` `` must exist; a bare file name must match exactly one
  file.
- A line citation `<file>.rs:N-M` must overlap an identifier named before it.

Use `--json` for machine-readable output. Neither script checks protocol
semantics: a citation that resolves can still describe the code wrongly, so
rows need review when the code changes.

The same checker inventories explicit test references on normative Compliant
rows. Missing references are advisory during backlog review; invalid citations
still fail. Recognizing a test declaration, including an ignored or gated test,
does not establish runtime or semantic coverage. See the
[policy, reviewed paths and remaining backlog](test-evidence.md).

`check_doc_links.py` checks repository Markdown paths and heading/HTML anchors
offline. External release URLs are classified separately; a missing local
artifact is an error. Non-Markdown fragments are unverified. It checks neither
external availability nor the evidence's meaning. See [documentation checks](../../CONTRIBUTING.md#tests).

`scripts/check_standards.py` compares [`standards.json`](standards.json)
with the IETF Datatracker and RFC Editor metadata to detect new revisions,
inactive states and replacement chains. For each implemented draft it also
checks that the matrix's `Revision frozen:` line names the pinned revision.
Watch-only entries, such as the expired STAMP YANG draft, report changes without
an implementation claim or blocking on drift; missing evidence still fails the
check. The scheduled workflow creates or updates a review issue on failure.
See [Standards revision
monitor](../release-evidence.md#standards-revision-monitor).

## Other evidence

- Cargo test suites run separately for the default features, all features,
  and pnet only (`--no-default-features --features ttl-pnet`). With all
  features the reflector uses the nix backend. See the [test
  inventory](../../tests/README.md).
- The [independent UDP fixtures](../testing-interop.md) use frozen bytes and
  encoders and verifiers separate from the crate. Their SRv6 case checks the
  U fallback.
- The [privileged namespace tests](../testing-netns.md) check wire behavior,
  SRv6 transit, extension-header reflection on both backends, and route MTU
  changes. CI sets `STAMP_REQUIRE_PRIVILEGED=1`, which fails the job when
  prerequisites are missing or no test runs; a skipped test is not evidence.
- Property tests run with Cargo. The fuzz workflow builds and runs nine
  targets; building a target is not fuzzing it.
- [Release verification](../release-evidence.md) covers authenticated HTTP and
  HTTPS control, a Net-SNMP master, platform runtime gates and the standards
  revision monitor.
