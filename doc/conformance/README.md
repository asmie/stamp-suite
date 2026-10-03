# Standards conformance

These matrices map every normative clause of the standards stamp-suite
implements to the code and tests that implement it. They are for reviewers,
packagers and contributors who need to know what is supported, what is
partial and what is out of scope.

The matrices record evidence against frozen revisions of each document. They
are not a certification. A code citation or a passing test supports only the
behavior it checks.

## Matrices

| Document | Revision frozen | Clauses | Compliant | Partial | Gap | N-A | Excluded |
|---|---|---:|---:|---:|---:|---:|---:|
| [RFC 8762](rfc8762.md): STAMP base protocol | RFC 8762, March 2020 | 62 | 52 | 0 | 0 | 9 | 1 |
| [RFC 8972](rfc8972.md): STAMP optional extensions | RFC 8972, January 2021 | 151 | 141 | 0 | 0 | 10 | 0 |
| [RFC 9503](rfc9503.md): Destination Node Address and Return Path | RFC 9503, October 2023 | 26 | 22 | 0 | 0 | 3 | 1 |
| [RFC 9534](rfc9534.md): Micro-session ID (LAG) | RFC 9534, January 2024 | 18 | 9 | 6 | 1 | 2 | 0 |
| [RFC 8545](rfc8545.md): OWAMP/TWAMP port allocation | RFC 8545, March 2019 | 8 | 1 | 0 | 0 | 7 | 0 |
| [RFC 10052](draft-asymmetrical-pkts.md): Reflected Test Packet Control (Type 12) | RFC 10052, September 2026 | 47 | 38 | 1 | 0 | 7 | 1 |
| [draft-ietf-ippm-stamp-cos-ecn](draft-stamp-cos-ecn.md): CoS and ECN signaling | -01, 20 July 2026 | 16 | 16 | 0 | 0 | 0 | 0 |
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md): reflected headers (Types 246, 247) | -15, 30 September 2026 | 63 | 54 | 2 | 0 | 7 | 0 |
| [draft-gandhi-ippm-stamp-ber](draft-stamp-ber.md): residual BER (Types 240 to 242) | -07, 30 June 2026 | 30 | 27 | 2 | 0 | 1 | 0 |
| **Total** | | **421** | **360** | **11** | **1** | **46** | **3** |

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

## Known limits

- RFC 8972 session-admission rows are Compliant only with
  `--session-admission provisioned`. The permissive default does not enforce
  the provisioning and discard requirements.
- RFC 9534 has six Partial rows and one Gap. Numeric Micro-session IDs work,
  but the tool does not associate them with physical LAG members, steer
  packets onto a member link, or verify the ingress member.
- Type 12 reply sizing and BER padding fit use the route MTU on Linux. This
  is a route lookup, not path-MTU probing. On other platforms the sender uses
  a fixed budget, and the reflector cannot size replies to an accepted Type 12
  request and drops them; see [RFC 10052](draft-asymmetrical-pkts.md).
- Extension-header reflection depends on the backend: the nix backend on
  Linux reflects Type 246 from ancillary data; Type 247 needs the pnet
  backend. See [backend support](draft-stamp-ext-hdr.md#backend-support).
- SR-MPLS return paths are Excluded; the reflector answers them with U. YANG
  management is not implemented.
- AgentX (SNMP subagent) support is read-only and is not scored in these
  matrices.
- NIC timestamping and physical LAG behavior have no physical-testbed
  evidence. macOS has software receive timestamps only. Windows capture and
  hardware limits are covered in [release verification](../release-evidence.md).

## Experimental codepoints

These local allocations are defined in `src/tlv/experimental.rs`. Peers must
agree on their meaning; they are not IANA assignments.

| Codepoint | Registry | Constant | Specification | Needs |
|---|---|---|---|---|
| Type 240 | STAMP TLV Types (Experimental, 240-251) | `BER_PATTERN_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.1 | Type allocation in the draft |
| Type 241 | STAMP TLV Types (Experimental, 240-251) | `BER_COUNT_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.2 | Type allocation in the draft |
| Type 242 | STAMP TLV Types (Experimental, 240-251) | `BER_MAX_BURST_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.3 | Type allocation in the draft; **known collision**, see below |
| Type 246 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_IPV6_EXT_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-15 §4.1, §4.2 | IANA allocation of TBA1 |
| Type 247 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_FIXED_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-15 §6.1, §6.2 | IANA allocation of TBA2 |
| Sub-TLV Type 240 (of Type 12) | STAMP Sub-TLV Types (Experimental, 240-251) | `REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` | draft-ietf-ippm-stamp-ext-hdr-15 §5.1 | IANA allocation of TBA3 |

Type 242 conflicts with another implementation's experimental Heartbeat TLV,
and the formats are incompatible. `--ber-omit-burst` leaves Type 242 out of
BER probes. Types 240 and 241 follow the experimental values reported in the
BER draft; 242 is this project's choice.

When a final allocation changes a wire identifier, update its constant,
record the change in `CHANGELOG.md`, and bump the minor version under the
project's draft-feature policy. There is no runtime codepoint override.

## Checks

Three scripts keep the matrices consistent with themselves and with the
code. The `Conformance evidence` workflow (`.github/workflows/conformance.yml`)
runs the first two, and the script unit tests in `scripts/tests/`, on
pushes and pull requests to `master` and `1.0-line`.

```sh
python3 scripts/check_conformance_counts.py
python3 scripts/check_conformance_citations.py
```

`check_conformance_counts.py` reads every clause row (a row whose first cell
is a clause ID) in the nine matrices. It checks that IDs are unique, that each
status is one of the five statuses, that the single `Summary:` line in each
matrix matches the row counts, and that the [Matrices](#matrices) table here
matches every matrix and the total. Change a status, and the summary line and
this table must change with it.

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

`scripts/check_standards.py` compares [`standards.json`](standards.json)
with the IETF Datatracker and RFC Editor metadata to detect new revisions and
status changes. For each draft it also checks that the matrix's
`Revision frozen:` line names the pinned revision. See [Standards revision
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
