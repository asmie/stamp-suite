# Conformance inventory

These nine matrices record implementation evidence against frozen RFC/draft
revisions. Scores were maintained through September 2026; they are not an
independent certification or a fresh audit of every Compliant row. A code
citation or passing fixture supports only the behavior it checks.

## Per-document summary

| Document | Revision frozen | Clauses | Compliant | Partial | Gap | N/A | Excluded |
|---|---|---:|---:|---:|---:|---:|---:|
| [RFC 8762](rfc8762.md) — STAMP base protocol | RFC 8762, March 2020 | 62 | 52 | 0 | 0 | 9 | 1 |
| [RFC 8972](rfc8972.md) — STAMP Optional Extensions | RFC 8972, January 2021 | 151 | 141 | 0 | 0 | 10 | 0 |
| [RFC 9503](rfc9503.md) — Destination Node Address / Return Path | RFC 9503, October 2023 | 26 | 22 | 0 | 0 | 3 | 1 |
| [RFC 9534](rfc9534.md) — Micro-session ID (LAG) | RFC 9534, January 2024 | 18 | 9 | 6 | 1 | 2 | 0 |
| [RFC 8545](rfc8545.md) — TWAMP port allocation | RFC 8545, March 2019 | 8 | 1 | 0 | 0 | 7 | 0 |
| [draft-ietf-ippm-asymmetrical-pkts](draft-asymmetrical-pkts.md) — Reflected Test Packet Control (Type 12) | -14, 16 March 2026 | 47 | 38 | 1 | 0 | 7 | 1 |
| [draft-ietf-ippm-stamp-cos-ecn](draft-stamp-cos-ecn.md) — CoS/ECN congestion signaling | -01, 20 July 2026 | 16 | 16 | 0 | 0 | 0 | 0 |
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md) — Reflected header data (Types 246/247) | -13, 9 September 2026 | 60 | 54 | 0 | 0 | 6 | 0 |
| [draft-gandhi-ippm-stamp-ber](draft-stamp-ber.md) — Residual BER (Types 240–242) | -07, 30 June 2026 | 30 | 27 | 2 | 0 | 1 | 0 |
| **Total** | | **418** | **360** | **9** | **1** | **45** | **3** |

Compliant means supported within the row's stated profile. Partial means some
behavior or platform support is missing; Gap means an unmet requirement. N/A
means inapplicable. Excluded marks an explicit scope boundary.

## Scope and remaining gaps

- RFC 8972 session-admission scores require `--session-admission provisioned`.
  The permissive default does not enforce its provisioning/discard requirements.
- RFC 9534 has six Partial rows and one Gap: numeric IDs work, but physical LAG
  association, steering, and ingress-member verification are unsupported.
- Type-12 exact sizing and BER route enforcement retain platform limits.
  Linux uses route/interface MTU lookup; this is not active path-MTU probing.
- SR-MPLS return forwarding is excluded and replies with U. YANG management
  is unsupported. AgentX is read-only; its [review](agentx-review.md) is separate
  from STAMP clause totals.
- NIC timestamp discipline and physical LAG behavior have no physical-testbed
  evidence here. macOS has software RX timestamps only. Windows capture and
  hardware limits are covered in [release verification](../release-evidence.md).

## Experimental codepoints

These local allocations are defined in `src/tlv/experimental.rs`. Peers must
agree on their meaning; they are not final IANA assignments.

| Codepoint | Registry | Const | Draft | What it needs |
|---|---|---|---|---|
| Type 240 | STAMP TLV Types (Experimental, 240-251) | `BER_PATTERN_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.1 | Draft-side Type allocation |
| Type 241 | STAMP TLV Types (Experimental, 240-251) | `BER_COUNT_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.2 | Draft-side Type allocation |
| Type 242 | STAMP TLV Types (Experimental, 240-251) | `BER_MAX_BURST_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.3 | Draft-side Type allocation; **known collision**, see below |
| Type 246 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_IPV6_EXT_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-13 §§3.2/5.1 | IANA allocation of TBA1 |
| Type 247 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_FIXED_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-13 §§3.3/5.2 | IANA allocation of TBA2 |
| Sub-TLV Type 240 (of Type 12) | STAMP Sub-TLV Types (Experimental, 240-251) | `REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` | draft-ietf-ippm-stamp-ext-hdr-13 §5.3 | IANA allocation of TBA3 |

Type 242 conflicts with another implementation's experimental Heartbeat TLV.
The formats are incompatible. Types 240/241 follow the BER draft's reported
experimental use; 242 is this project's choice.

When a final allocation changes a wire identifier, update its constant, record
the change in `CHANGELOG.md`, and bump the minor version under the project's
draft-feature policy. There is no runtime codepoint override.

## Verification

```sh
python3 scripts/check_conformance_counts.py --json
python3 scripts/check_conformance_citations.py --json --details
```

The count checker compares unique clause IDs, statuses, matrix summaries, and
this rollup. The citation checker checks file/range resolution and heuristic
identifier overlap. Neither verifies protocol semantics; unresolved citations
still need manual review when code changes.

- Run default, all-feature, and pnet-only Cargo suites separately. All-features
  selects nix. See the [test inventory](../../tests/README.md).
- The [independent UDP fixtures](../testing-interop.md) use frozen bytes and
  separate encoders/verifiers. Their SRv6 case checks U fallback.
- [Privileged namespace tests](../testing-netns.md) check wire behavior,
  successful SRv6 transit, and route MTU changes. CI requires prerequisites and
  nonempty test execution with `STAMP_REQUIRE_PRIVILEGED=1`; skips are not evidence.
- Property tests run through Cargo. The separate fuzz workflow builds and runs
  eight targets; compilation alone is not fuzz execution.
- [Release fixtures](../release-evidence.md) cover live authenticated HTTP/HTTPS,
  a Net-SNMP master, platform tests, and standards revision checks.
- The [revision-13 review](ext-hdr-13-review.md) describes its incompatible
  Type-246 selector change and supported header-reflection profile.
