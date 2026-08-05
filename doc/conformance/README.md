# stamp-suite conformance — compliance statement

Status date: **2026-08-05**. Branch: **1.0-line**.

This document rolls up the eight clause-level conformance matrices in this
directory into a single compliance statement for the stamp-suite 1.0 line.
Every count below is read verbatim from each matrix's own `Summary:` line.
Where this document goes further than the matrices is in stating, as a
maintainer decision, which of the residual non-Compliant rows are accepted
design trade-offs (**Documented exclusions**), and in disclosing the
experimental/pending-IANA codepoints this implementation stands in for.

**Bottom line:** as of the status date there are **no Partial rows and no open
Gap rows left**. The fifteen rows that were Partial or open Gap on 2026-07-23
were closed by the post-review pass (see "Closed since the 1.0 audit" below);
the only non-Compliant rows remaining are the three SSID-admission Gaps kept
deliberately under "Documented exclusions" and three Excluded rows, each with a
named rationale. Nothing was silently dropped or silently re-scored: every
closed row keeps its original finding in the matrix, with the closure appended
beneath it.

## Per-document summary

| Document | Revision frozen | Clauses | Compliant | Partial | Gap | N/A | Excluded |
|---|---|---:|---:|---:|---:|---:|---:|
| [RFC 8762](rfc8762.md) — STAMP base protocol | RFC 8762, March 2020 | 62 | 52 | 0 | 0 | 9 | 1 |
| [RFC 8972](rfc8972.md) — STAMP Optional Extensions | RFC 8972, January 2021 | 151 | 138 | 0 | 3 | 10 | 0 |
| [RFC 9503](rfc9503.md) — Destination Node Address / Return Path | RFC 9503, October 2023 | 26 | 22 | 0 | 0 | 3 | 1 |
| [RFC 9534](rfc9534.md) — Micro-session ID (LAG) | RFC 9534, January 2024 | 18 | 15 | 0 | 0 | 3 | 0 |
| [RFC 8545](rfc8545.md) — TWAMP port allocation | RFC 8545, March 2019 | 8 | 1 | 0 | 0 | 7 | 0 |
| [draft-ietf-ippm-asymmetrical-pkts](draft-asymmetrical-pkts.md) — Reflected Test Packet Control (Type 12) | -14, 16 March 2026 (RFC Editor queue) | 47 | 38 | 0 | 0 | 8 | 1 |
| [draft-ietf-ippm-stamp-cos-ecn](draft-stamp-cos-ecn.md) — CoS/ECN congestion signaling | -01, 20 July 2026 | 16 | 16 | 0 | 0 | 0 | 0 |
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md) — Reflected header data (Types 246/247) | -11, 4 July 2026 | 40 | 38 | 0 | 0 | 2 | 0 |
| **Total** | | **368** | **320** | **0** | **3** | **42** | **3** |

Each matrix was independently re-verified against a freshly fetched copy of
its source text on 2026-07-22 (see each file's own "Revision frozen" line and
adversarial re-verification log). No clause was re-read against its source text
in the 2026-08-05 pass: that pass changed *implementation*, and each row it
touched was re-scored against the same frozen clause text, with the code and
test evidence for the closure appended to the row. The matrices remain the
source of truth; the table above is read from their `Summary:` lines.

## Documented exclusions

These are non-Compliant rows (or feature-scope boundaries the matrices don't
score at all) that this project has deliberately decided **not** to close,
with a stated rationale. These are not "still open" — they are closed as
accepted design, and as of the status date they are the *only* non-Compliant
rows left in any matrix.

| Exclusion | Rationale | Pointer |
|---|---|---|
| **SR-MPLS return-path forwarding** | A userspace UDP-socket reflector cannot push an MPLS label stack onto its own IP reply. By design, any Return Path TLV carrying an SR-MPLS segment list is echoed with the U-flag (`ReturnPathAction::UnsupportedSr`) rather than attempted. | `9503-4.1.3.1-1` (Excluded in the matrix); `src/tlv/list/processing.rs` `has_sr_mpls()` / `process_return_path` |
| **SNMP SET** | The AgentX sub-agent is a read-only monitoring surface by design (GET/GETNEXT/GETBULK only). A TestSet is answered `notWritable` (Commit/UndoSet get the matching failure code; CleanupSet is a no-op) rather than the PDU being silently dropped, so a manager gets a clean, immediate failure instead of a timeout — that response *is* the compliant behavior for a sub-agent that has chosen not to expose writable OIDs, not a gap in one. | `src/snmp/`; `doc/control-plane.md` ("SNMP SET parity — tracked elsewhere"); `doc/architecture.md` ("`--snmp` requires a Unix platform") |
| **STAMP YANG** | No implementation gap is scored because no adopted standard exists to implement against: the STAMP YANG individual draft this project tracked has expired, and RFC 9534 §3.2's own text places YANG augmentation for micro-session mapping explicitly out of scope ("The detailed augmentation is not in the scope of this document"). | `rfc9534.md` note under §3.2; project standards-tracking notes |
| **Windows backend limits** | Windows uses the `pnet`/libpcap-Npcap datalink-capture backend as a fallback tier, not the primary `nix` backend Linux/macOS get. This is a documented platform tier, not an unnoticed gap: Windows CI runs the test suite best-effort (non-gating — a Windows test failure does not block the pipeline), and features requiring raw-socket control-message access (kernel timestamping, some CoS/ECN paths) are honestly reported as unsupported at runtime rather than silently degraded. | `doc/architecture.md` ("Windows ❌"); CI `rust.yml` best-effort Windows job |
| **macOS TX timestamping** | The kernel/hardware timestamping feature has a real, tested RX path on macOS (`SO_TIMESTAMP`/`SCM_TIMESTAMP`, software-tier, µs resolution) but no TX path and no NIC-hardware path — Darwin exposes no equivalent of Linux's `MSG_ERRQUEUE`/`SIOCSHWTSTAMP`. This is a platform capability boundary, disclosed in code and docs, not an oversight. | `src/hwtstamp.rs` (module doc + macOS branch); `doc/architecture.md` hwtstamp section |
| **NIC-hardware timestamp paths** | The `SIOCSHWTSTAMP` hardware-timestamp tier (Linux, `--hwtstamp on`, needs `CAP_NET_ADMIN` and a NIC that actually supports it) is code-cited and unit-tested for its request/fallback logic, but the live hardware path itself cannot be exercised in ordinary CI (no privileged, hardware-timestamp-capable NIC available there). Verification for this tier is the code citation plus a manual procedure an operator with the right hardware can run; `startup_action()`'s graceful fallback means the binary never *requires* the hardware to start. | `src/hwtstamp.rs`; `doc/architecture.md` ("NIC hardware tier") |
| **SSID-based session admission** | RFC 8972 §3 MUSTs require a Session-Reflector to be pre-provisioned with session identity (SSID + 4-tuple) and to discard non-matching traffic (`RFC8972-3-6`/`-3-7`/`-3-8`, scored Gap in the matrix). stamp-suite's reflector deliberately accepts any syntactically valid STAMP packet on the bound port — a general-purpose measurement tool, not a provisioned network element — and the RFC's own §3 text places "the means of provisioning" explicitly out of its own scope. The actual admission controls this project ships instead are: the per-source/per-SSID rate limiter, HMAC integrity in authenticated mode, and per-client stateful sequencing when `--stateful-reflector` is set. **Maintainer decision, 2026-07-22:** keep the accept-any design; these three rows remain Gap in `rfc8972.md` for traceability but are treated as closed here, not as outstanding work. | `RFC8972-3-6`, `RFC8972-3-7`, `RFC8972-3-8` in `rfc8972.md`; `src/session.rs` `SessionManager`; `src/receiver/mod.rs` rate limiter wiring |

## Closed since the 1.0 audit

The 2026-07-23 statement listed eleven open items covering fifteen matrix rows —
ten scored Partial and five scored Gap. **All fifteen were closed in the
post-review pass of 2026-08-04/05.** They are recorded here rather than deleted,
so the statement remains readable against its predecessor: each matrix row keeps
its original finding with the closure appended beneath it, naming the code and
the tests.

| Item (as listed on 2026-07-23) | Was | Rows | Closed by |
|---|---|---|---|
| Control-plane transport security trade-off | Partial | `RFC8762-7-1` | TLS for the control plane: `--control-tls-cert`/`--control-tls-key` (rustls, explicit `ring` provider), both flags required together, and TLS additionally requires a bearer token. Verified with a real handshake asserting 200 with the token and 401 without. |
| Reply source-address pinning (SHOULD) | Partial | `9503-3-1` | The matched Destination Node Address now reaches the send path (`StampResponse::reply_source`) and both backends pin it via an `IP_PKTINFO`/`IPV6_PKTINFO` ancillary message. Verified by asserting the *receiver* observes the pinned source. |
| DSCP/ECN admission-policy layer | Partial | `RFC8972-4.4-8`, `RFC8972-6-3`, `cos-ecn-3.2-3`, `cos-ecn-3.2-6` | `src/cos_policy.rs` separates *permitted* from *capable*: `--allowed-dscp`, `--allowed-ecn`, and destination-scoped `--allowed-dscp-for`. A refused DSCP1 reports RPD=0b01; a refused EC1 forces Not-ECT and reports RPE=0b10. |
| Extra-Padding-after-HMAC leniency | Partial | `RFC8972-4.8-2` | Both parsers now accept trailing Extra Padding. Required fixing HMAC coverage first: the covered prefix had been derived from the sum of non-HMAC TLV sizes, which is only the true prefix while the HMAC TLV is last. |
| Live egress-MTU query (reflector side) | Partial | `asym-3-08` | `ioctl(SIOCGIFMTU)` on the egress interface, enforced alongside `--reflected-control-max-size`. The stand-in had been wrong at the default, permitting a 1528-byte datagram on a 1500-byte link. |
| Reflector ingress clock telemetry | Partial | `RFC8972-4.3-5`, `RFC8972-4.3-6` | All four Timestamp Info octets are now filled from the reflector's own clocks, with the ingress (T2) and egress (T3) methods reported separately. |
| Replay detection (SHOULD) | Gap | `asym-5-07` | `Session::check_replay` with a 31-entry per-session window in a single `AtomicU64`; counters on `/v1/status`; opt-in `--drop-replayed` for the action. |
| Send-delay / reflected-burst cross-check | Gap | `asym-5-09` | `reflected_burst_pacing_warning()` warns at startup when `--send-delay` is shorter than the requested burst, naming the minimum. |
| Zeroed-SSID reply control (sender) | Gap | `RFC8972-3-11` | `--on-zero-ssid continue\|stop`, checking both reflected SSID fields and inert without a configured `--ssid`. |
| Location field-disclosure policy | Gap | `RFC8972-4.2.2-2` | `--location-disclose`; a withheld field is answered as zeroes, and a withheld IP request keeps its generic sub-TLV type so the address family is not disclosed either. |
| Misplaced-HMAC severity | Gap | `RFC8972-4.8-3` | A misplaced HMAC now runs the §4.8 verification-failure procedure (I flag on every TLV), not only the parser's M flag. |

Two further defects were fixed in the same pass that no matrix row had scored,
because both sat inside behaviour the matrices recorded as Compliant:

- A Type-12 `length` request from a peer that sends no HMAC TLV produced a reply
  exactly 20 octets over the requested length, because the keyed reflector
  appends its own HMAC TLV after the length-padding decision. The pre-existing
  test asserted the reply was *at least* the requested length, so the overshoot
  passed; it now asserts equality.
- With the AIMD congestion response active, an Access Report wait-phase
  retransmission carried no Reflected Test Packet Control TLV at all, because
  that path rebuilt its TLV set from the static list the main loop deliberately
  omits it from.

## Citation verification

The `file:line` citations in the matrices are the link between a clause and its
evidence, and they drift whenever the code moves. `scripts/check_conformance_citations.py`
checks them and exits non-zero on drift, so this can gate CI rather than being
rediscovered by the next audit.

As of the status date: **540 line-bearing citations, 0 drifted.** Of those, 108
are positively machine-verified — the cited range intersects the extent of an
identifier the row names beside it — and 432 cannot be machine-checked, because
the citation follows prose that names no identifier, or names one defined in a
different file (a call site rather than a definition). Every citation resolves to
an existing file and an in-range line.

Fourteen citations that the tool could not pin to a single construct had their
line numbers **deliberately removed** during the 2026-08-05 refresh, keeping the
file path and the identifier the prose already names. A coarse citation that is
correct is worth more than a precise one that is confidently wrong, and those
rows are now out of the drift surface for good.

## Experimental-codepoint disclosure

This implementation stands in for six codepoints across three drafts that
have not (yet) received a final IANA allocation. All six are now collected
in one place in the source tree — `src/tlv/experimental.rs` — which each
const's doc comment cites as its own single edit point.

| Codepoint | Registry | Const | Draft | What it needs |
|---|---|---|---|---|
| Type 240 | STAMP TLV Types (Experimental, 240-251) | `BER_PATTERN_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-05 §3.2 | Draft-side Type allocation |
| Type 241 | STAMP TLV Types (Experimental, 240-251) | `BER_COUNT_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-05 §3.3 | Draft-side Type allocation |
| Type 242 | STAMP TLV Types (Experimental, 240-251) | `BER_MAX_BURST_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-05 §3.4 | Draft-side Type allocation; **known collision**, see below |
| Type 246 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_IPV6_EXT_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-11 §§3.1/5.1 | IANA allocation of TBA1 |
| Type 247 | STAMP TLV Types (Experimental, 240-251) | `REFLECTED_FIXED_HDR_TLV_TYPE` | draft-ietf-ippm-stamp-ext-hdr-11 §§3.2/5.2 | IANA allocation of TBA2 |
| Sub-TLV Type 240 (of Type 12) | STAMP Sub-TLV Types (Experimental, 240-251) | `REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` | draft-ietf-ippm-stamp-ext-hdr-11 §5.3 | IANA allocation of TBA3 |

Of the three `draft-gandhi-ippm-stamp-ber` TLVs, only Types 240/241 (Bit
Pattern, Bit Error Count) are cited by the draft's own Implementation Status
section as having a known implementation at those numbers; Type 242 (Max Bit
Error Burst Size) is this project's own extension into the shared
Experimental range, not a number the draft itself reports as already taken.

**Known collision (disclosed, not a bug).** Type 242 is also used,
independently, by another STAMP implementation for an unrelated,
incompatible experimental "Heartbeat" TLV. Both uses are legitimate under
RFC 8972 §5.1 — the Experimental range exists precisely so implementations
don't need to coordinate before picking a number — but the two TLVs are
wire-format-incompatible with each other. A stamp-suite reflector talking to
that other implementation's Heartbeat sender (or vice versa) at Type 242
will misparse the value. See `doc/architecture.md` for the original note.

**Renumbering policy.** When any of these drafts receives a real IANA
allocation, the fix is: update the single named constant in
`src/tlv/experimental.rs`, bump the crate's **minor** version (these are
on-wire-visible identifiers, but they are pre-standard stand-ins by
definition — a minor bump is this project's chosen severity for that), and
call it out under `CHANGELOG.md`'s `[Unreleased]` → next release, consistent
with the Semantic Versioning policy stated at the top of that file. There is
deliberately no runtime or config-file override for these values (YAGNI —
see the module doc comment in `src/tlv/experimental.rs`).

## Verification tiers

- **Unit tests** — 933 tests under `cargo test --lib` (`cargo test
  --all-features`), covering packet/TLV parsing and serialization, flag
  derivation, session state, HMAC, congestion control, SNMP encoding, and
  every semantic TLV-processing path exercised without a socket.
- **Integration / loopback tests** — real `tokio`/`std` UDP sockets on
  `127.0.0.1`/`::1` across `tests/loopback_test.rs`,
  `tests/loopback_ipv6_test.rs`, `tests/tlv_flag_semantics.rs`,
  `tests/multi_key_hmac_test.rs`, `tests/malformed_input_test.rs`,
  `tests/ber_regression_test.rs`, `tests/ptp_e2e_test.rs`, and
  `tests/control_api_test.rs` (the REST API, via `tower`'s `oneshot` —
  no sockets there specifically, but exercised end to end otherwise).
- **Property tests** — `proptest` invariants in `tests/proptest_tlv.rs`
  (TLV round-trip/parsing fuzz-style properties) and inline in
  `src/rate_control.rs` (AIMD congestion-controller invariants: interval
  never exceeds the configured cap, monotonic growth on repeated CE, etc.).
- **Fuzzing** — 8 targets under `fuzz/fuzz_targets/` (`raw_tlv_parse`,
  `tlv_list_parse`, `tlv_list_parse_lenient`, `packet_unauth_parse`,
  `packet_auth_parse`, `process_stamp_packet`, `agentx_decode_header`,
  `agentx_decode_oid`), run on demand and on a weekly CI schedule
  (`.github/workflows/fuzz.yml`, Sundays 03:30 UTC).
- **Privileged network-namespace tier** — `tests/netns_conformance.rs`
  (9 scenarios, all `#[ignore]`-gated and additionally opt-in via
  `STAMP_NETNS_TESTS=1` plus a root/`CAP_NET_ADMIN` check), exercising
  real on-wire IP TOS/ECN/TTL marking, IPv6 extension headers, Address
  Group filtering, and Type-12 multi-reply pacing over Linux `veth` pairs.
  Full prerequisites and running instructions: `doc/testing-netns.md`. The
  SRv6 return-path scenario (`scenario_3_srv6_return_path`) is additionally
  gated on kernel `seg6` support and is this line's first live exercise of
  the SRH-send path; live-send verification elsewhere in this codebase is
  otherwise construction-only (unit-tested SRH building) plus a manual
  procedure, not automated CI.
- **Cross-implementation testing (local, informational)** — ad hoc
  interoperability runs against another, unnamed STAMP implementation on
  the local network, used to sanity-check wire-format assumptions (e.g. the
  CoS TLV layout fix, the Type-242 collision noted above) during
  development. Informational only: not part of the automated gate, and not
  reproducible in CI, so it carries no weight in the counts above.

## Sign-off

Every Gap identified during the audit was either fixed in the 1.0 line's
commits, closed in the post-review pass recorded above, or moved into
"Documented exclusions" with a maintainer rationale and date. Nothing found was
left unaddressed and undocumented, and no row was re-scored without its
supporting code and tests named in the matrix.

As of the status date the residual is: **three Gap rows** (the SSID-admission
trio, kept deliberately) and **three Excluded rows**, all six under "Documented
exclusions"; **no Partial rows**. This statement reflects the matrices as they
stand on the date above, on branch `1.0-line`; it is not re-issued automatically
and should be revisited whenever a matrix's own `Summary:` line changes.
