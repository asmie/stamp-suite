# Standards conformance

These matrices map each STAMP requirement to the code that implements it and
the tests that show it works.

A result holds only for the frozen revision and the profile that was tested.
It says nothing about behavior that was not tested.

## Matrices

| Document | Revision frozen | Clauses | Compliant | Partial | Gap | N-A | Excluded |
|---|---|---:|---:|---:|---:|---:|---:|
| [RFC 8762](rfc8762.md): STAMP base protocol | RFC 8762, March 2020 | 62 | 52 | 0 | 0 | 9 | 1 |
| [RFC 8972](rfc8972.md): STAMP optional extensions | RFC 8972, January 2021 | 151 | 140 | 4 | 0 | 7 | 0 |
| [RFC 9503](rfc9503.md): Destination Node Address and Return Path | RFC 9503, October 2023 | 27 | 22 | 1 | 0 | 3 | 1 |
| [RFC 9534](rfc9534.md): Micro-session ID (LAG) | RFC 9534, February 2024 | 18 | 7 | 8 | 1 | 2 | 0 |
| [RFC 8545](rfc8545.md): OWAMP/TWAMP port allocation | RFC 8545, March 2019 | 8 | 1 | 0 | 0 | 7 | 0 |
| [RFC 10052](draft-asymmetrical-pkts.md): Reflected Test Packet Control (Type 12) | RFC 10052, September 2026 | 47 | 36 | 3 | 0 | 7 | 1 |
| [draft-ietf-bpm-stamp-cos-ecn](draft-stamp-cos-ecn.md): CoS and ECN signaling | -00, 16 November 2026 | 31 | 19 | 3 | 0 | 9 | 0 |
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md): reflected headers (Types 246, 247) | -26, 27 October 2026 | 75 | 63 | 9 | 0 | 3 | 0 |
| [draft-ietf-bpm-stamp-ber](draft-stamp-ber.md): Residual BER | -01, 2 November 2026 | 54 | 49 | 4 | 0 | 1 | 0 |
| **Total** | | **473** | **389** | **32** | **1** | **48** | **3** |

[`standards.json`](standards.json) pins the revision of each document; see
[Checks](#checks).

## How to read a matrix

Each matrix opens with the frozen revision, a `Summary:` line with the counts,
and a scope section for limits that affect many rows. The clause table comes
next, followed by notes that hold evidence shared by several rows.

All matrices use the same columns:

| Column | Content |
|---|---|
| ID | Stable clause ID, for example `RFC8762-4-1` or `ext-hdr-4.1-C`. Other documents and the scripts refer to rows by this ID. |
| Clause | The normative text, quoted and trimmed, or paraphrased where the matrix says so. |
| Level | The BCP 14 keyword (MUST, SHOULD, MAY and so on). `MUST (implied)` marks a requirement that the text states without an uppercase keyword, sometimes with a note such as `structural` (a field format). `Descriptive` marks text with no keyword that still describes required behavior. `N-A` marks non-normative text. |
| Role | The endpoint the clause applies to: Sender, Reflector, Both or N-A. |
| Status | One of the statuses below. |
| Evidence | Code citations, then tests, then a short note on any limits. |

### Statuses

| Status | Meaning |
|---|---|
| Compliant | Implemented and backed by cited evidence, within the profile the matrix states (for example, provisioned session admission or a supported platform). |
| Partial | Implemented for some cases only. A platform, a backend or part of the behavior is missing, and the row says which. |
| Gap | The requirement applies, but is not implemented. |
| N-A | Does not apply to stamp-suite, for example a TWAMP-Control message or an optional mode that is not implemented. |
| Excluded | The requirement applies, but the project has decided to leave it out of scope. The row states where the line is drawn and what stamp-suite does instead. |

A status can have a note in parentheses, such as `Compliant
(provisioned mode)`.

### Evidence citations

- `` `<file>.rs::<item>` `` names a function, type, constant or test in a
  file or one of its child modules.
- `` `<item>` (`<file>.rs`) `` says that one or more identifiers are in a
  file.
- `` `tests/<file>.rs::<test>` `` names an integration test.
- A bare `` `<file>.rs` `` names a file.

### Quoted text

The Clause column quotes RFCs and Internet-Drafts. That text is Copyright (c)
IETF Trust and the persons identified as the document authors, and is
reproduced under BCP 78 and the IETF Trust's Legal Provisions Relating to IETF
Documents. Each matrix links the source document it quotes.

## Known limits

The README, the architecture guide, the test inventory, the interoperability
guide and the release guide link here for the supported profiles. A Compliant
row holds only within the profile it states. An ignored test, or code that
compiles, is not evidence of runtime behavior.

| Area | Supported profile and boundary | Evidence/details |
|---|---|---|
| Session admission | Admission is permissive by default. The RFC 8972 admission and provisioning rows are Compliant only with `--session-admission provisioned`. Installing a key does not provision a session. | [RFC 8972 scope](rfc8972.md#scope), [provisioning](../usage.md#session-provisioning) |
| Deployment provisioning | A sender cannot bind to a local endpoint the reflector already holds, but a sender on a different local IP can use the same port number as the reflector. Receive caps are configurable, but stamp-suite does not check that the total receive and transmit rates fit together. Both rows are Partial. | [Port and policing limits](draft-stamp-ext-hdr.md#port-and-policing-limits) |
| Reply correlation | The sender accepts a reply only if it echoes the complete sequence number and the T1 that went out on the wire, even when trailing fields are parsed leniently. A repeated sequence number and T1 pair cannot prove that a reply is fresh. When a kernel TX timestamp corrects T1, matching still uses the T1 from the wire, and only the OWD calculation uses the corrected value. | [Reply accounting and limits](../measurements.md#probes-reply-copies-and-duplicates) |
| Micro-sessions and LAG | Numeric IDs are encoded, checked and learned. stamp-suite does not tie IDs to physical LAG members, steer traffic out of a given member, or check which member a packet came in on. Reflector demultiplexing does not show that senders can share a port pair. Eight rows are Partial and one is a Gap. | [RFC 9534](rfc9534.md), [sender reply validation](rfc9534.md#sender-reply-validation) |
| Header reflection | Both header types are reflected only to sender IPs that the operator has allowed. On Linux, the nix backend can reflect Type 246 headers from ancillary data; fixed and nested headers (Type 247) need pnet. On the macOS nix backend, header requests get C. Requests to attach headers on the reverse path get C on every backend. An all-features build uses nix. Revision 26 has contradictory examples for repeated selectors, so those rows are Partial. | [Backend support](draft-stamp-ext-hdr.md#backend-support), [revision interpretation](draft-stamp-ext-hdr.md#revision-26-interpretation) |
| MTU | The sender and reflector size packets from a kernel route lookup on Linux and Windows, and for native unicast IPv6 on macOS. They do not probe the end-to-end PMTU. Where no lookup is available (IPv4 or pinned interfaces on macOS, other platforms), the sender refuses header requests at startup and sizes BER padding for a fixed 1500-byte (IPv4) or 1280-byte (IPv6) MTU. The reflector drops Type 12 and header replies that need a route budget there. Sender dispatch has Linux IPv4 and IPv6 tests for trimming, restoring and refusing packets, including with a real Hop-by-Hop header attached. BER sizing per platform is Partial. | [RFC 10052 sizing](draft-asymmetrical-pkts.md#reply-size-and-route-mtu), [BER matrix](draft-stamp-ber.md), [test-evidence review](test-evidence.md) |
| Type 12 | Three rows are Partial: exact intervals on the wire, the conservative choice of the first request, and filling a clamped reply to exactly the MTU. Requests are checked against count, size, interval, rate, volume and duration caps. Identity protection is scored only for authenticated mode with extension HMAC verification. In permissive open mode the HMAC is optional, so a request may carry none. | [RFC 10052 limits](draft-asymmetrical-pkts.md#type-12-limits), [route MTU](draft-asymmetrical-pkts.md#reply-size-and-route-mtu), [identity protection](draft-asymmetrical-pkts.md#identity-protection) |
| Return paths | IP and SRv6 return paths work only with certain backends and routes. SR-MPLS is Excluded and gets U. Tests check the flags on processed children and that processing stops at malformed data. Copies that are protected or skipped can keep the child flags they arrived with, so the inherited requirement is Partial. A fallback reply does not prove SRH transit. | [RFC 9503 scope](rfc9503.md#scope), [nested flags](rfc9503.md#nested-flags), [privileged tests](../testing-netns.md) |
| Management | The AgentX sub-agent is read-only (SET is not supported) and is not scored in these protocol matrices. It needs a separate master agent. YANG management is not implemented, and its expired draft is only watched. | [Observability](../usage.md#observability), [AgentX](../architecture.md#snmp-agentx-sub-agent) |
| BER | Four rows are Partial: zero-checksum validation, platform MTU, physical LAG, and filling up to the link MTU. With TLV processing on, diagnostics report local causes of C and C flags kept from the peer in the defined child layouts. Arbitrary values, and the tails copied in legacy TLV-ignore mode, are not interpreted. The independent BER peer uses ordinary UDP checksums. Separate raw fixtures cover IPv4 packets that arrive with a zero checksum and authenticated sending. None of this shows that errors are captured at the raw link or FEC level. No maintained, compatible application has been tested as a peer. | [BER matrix](draft-stamp-ber.md), [BER migration](../ber-migration.md) |
| CoS/ECN | ECN capability reporting from BPM revision 00 is implemented. RPE=01 says that marking is unavailable, including on Windows, and sender diagnostics recognize it. The DSCP fallback uses the received value only if policy admits it, and otherwise picks a third value that policy permits. An empty policy answers on DSCP 0 with RPD=01 and C. If the backend cannot enforce a restricted policy, the reflector sends no reply to the CoS request. For this profile, the frozen RFC 8972 text's unconditional fallback to DSCP2 is Partial. Consistency with RFC 3168 and RFC 9330 controllers is also Partial. Reverse feedback works on Linux and macOS. | [Successor changes](draft-stamp-cos-ecn.md#bpm-00-successor-changes), [empty policy](draft-stamp-cos-ecn.md#empty-policy) |
| Platforms and hardware | There is no evidence yet from physical LAGs or NIC timestamps. macOS has software receive timestamps. The Windows checks run without a capture driver, so they show nothing about capture through one. A cross-build is not a native runtime test. | [Release procedures](../releasing.md), [hardware timestamps](../testing-hardware-timestamps.md) |

## Experimental codepoints

These codepoints are local allocations, defined in
`src/tlv/experimental.rs`. IANA has not assigned them, so both peers must
agree on what they mean.

| Codepoint | Registry | Constant | Specification | Needs |
|---|---|---|---|---|
| Type 243 | STAMP TLV Types (Experimental, 240-251) | `RESIDUAL_BER_TLV_TYPE` | draft-ietf-bpm-stamp-ber-01 §4 | IANA allocation of TBA1; agreement with the peer |
| Sub-TLV Type 241 (of Type 243) | STAMP Sub-TLV Types (Experimental, 240-251) | `RESIDUAL_BER_PATTERN_SUBTLV_TYPE` | draft-ietf-bpm-stamp-ber-01 §4.1 | IANA allocation of TBA2; agreement with the peer |
| Type 246 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_IPV6_EXT_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-26 §4.1, §4.2 | IANA allocation of TBA1 |
| Type 247 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_FIXED_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-26 §6.1, §6.2 | IANA allocation of TBA2 |
| Sub-TLV Type 240 (of Type 12) | STAMP Sub-TLV Types (Experimental, 240-251) | `REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` | draft-ietf-ippm-stamp-ext-hdr-26 §5.1 | IANA allocation of TBA3 |

The old outer Types 240–242 are retired, and requests that use them get U.
Type 242 collided with another implementation's Heartbeat TLV. The successor
TLV always carries the burst field, so `--ber-omit-burst` is a startup error.
The BER matrix and the standards pin follow BPM revision 01. Teaparty's BER
layouts are incompatible with this profile; see
[BER migration](../ber-migration.md#interoperability).

When a final allocation changes a codepoint on the wire, update its constant,
note the change in `CHANGELOG.md`, and bump the minor version, as the
project's policy for draft features requires. Codepoints cannot be overridden
at runtime.

## Checks

Three scripts check that the matrices agree with themselves and with the
code, and that documentation links resolve. The `Conformance evidence`
workflow (`.github/workflows/conformance.yml`) runs them, along with the
script unit tests in `scripts/tests/`, on pushes and pull requests to
`master` and `1.0-line`.

```sh
python3 scripts/check_conformance_counts.py
python3 scripts/check_conformance_citations.py --require-test-evidence
python3 scripts/check_doc_links.py
```

`check_conformance_counts.py` checks that clause IDs are unique, that every
row uses one of the five statuses, and that each matrix's `Summary:` counts
and this page's totals match the rows. When you change a status, update the
matrix's summary and the [Matrices](#matrices) table.

`check_conformance_citations.py` resolves every citation in
`doc/conformance/*.md` against the source tree:

- `` `<file>.rs::<item>` `` must name an item defined in that file or in one
  of its child modules.
- In `` `<item>` (`<file>.rs`) ``, each identifier must be defined in that
  file, or, for a path-qualified name, appear in it.
- Every `` `<file>.rs` `` must exist, and a bare file name must match exactly
  one file.
- A line citation `<file>.rs:N-M` must overlap an identifier named before it.

`--json` gives machine-readable output. Neither script understands the
protocol. A citation can resolve and still describe the code wrongly, so
review the affected rows when the code changes.

The citation checker also lists which normative Compliant rows name a test.
CI requires every such row to name one, and saves the full list in
`citations.json`, even when the check fails. Locally, without
`--require-test-evidence`, a missing test reference is only reported, but an
invalid citation still fails. The checker only sees that a test is declared.
An ignored or gated test still counts, and a declared test does not show that
the behavior runs or is tested correctly. See the
[policy, reviewed paths and execution limits](test-evidence.md).

`check_doc_links.py` checks offline that links to repository files, and to
Markdown headings and HTML anchors, resolve. Links to external release URLs
are classified separately, and a missing local artifact is an error.
Fragments in links to non-Markdown files are not checked. The script does not
check whether external sites are reachable, or whether the linked evidence
says what the text claims. See
[documentation checks](../../CONTRIBUTING.md#tests).

`scripts/check_standards.py` compares [`standards.json`](standards.json) with
metadata from the IETF Datatracker and the RFC Editor. It reports new
revisions, drafts that are no longer active, and chains of replacement drafts.
For each implemented draft, it also checks that the `Revision frozen:` line in
the matrix names the pinned revision. Watch-only entries, such as the expired
STAMP YANG draft, report changes without claiming an implementation, and a
change does not fail the check. Missing evidence does fail it. When
the scheduled workflow fails, it opens or updates an issue asking for review.
See [Standards revision monitor](../releasing.md#standards-revision-monitor).

## Other evidence

- The Cargo test suites run separately with the default features, with all
  features, and with pnet only (`--no-default-features --features ttl-pnet`).
  With all features, the reflector uses the nix backend. See the
  [test inventory](../../tests/README.md).
- The [independent UDP fixtures](../testing-interop.md) use frozen bytes, and
  encoders and verifiers that are separate from the crate. Their SRv6 case
  checks the U fallback.
- The [privileged namespace tests](../testing-netns.md) check wire behavior,
  SRv6 transit, extension-header reflection on both backends, and changes to
  the route MTU. CI sets `STAMP_REQUIRE_PRIVILEGED=1`, so the job fails if a
  prerequisite is missing or no test runs. A skipped test is not evidence.
- The [independent BER peer](../testing-interop.md#independent-successor-ber-profile)
  runs 60 cases in both roles against the default and all-features builds.
- Property tests run as part of the Cargo tests. The fuzz workflow builds and
  runs ten targets. Building a fuzz target is not the same as fuzzing it.
- [Releasing](../releasing.md) covers authenticated HTTP and HTTPS control, a
  Net-SNMP master, the platform runtime gates and the standards revision
  monitor.
