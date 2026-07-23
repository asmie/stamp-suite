# stamp-suite conformance — compliance statement

Status date: **2026-07-23**. Branch: **1.0-line**.

This document rolls up the eight clause-level conformance matrices in this
directory into a single compliance statement for the stamp-suite 1.0 line.
It does not re-score any clause — every count below is read verbatim from
each matrix's own `Summary:` line, and none of the eight matrix files were
edited to produce this rollup. Where this document goes further than the
matrices is in stating, as a maintainer decision, which of the residual
non-Compliant rows are accepted design trade-offs (**Documented exclusions**)
versus genuinely open work (**Remaining Partials**), and in disclosing the
experimental/pending-IANA codepoints this implementation stands in for.

**Bottom line:** every Gap the audit found was either fixed in this 1.0 line
or moved into one of the two sections below, with a named rationale and a
maintainer sign-off date. Nothing was silently dropped.

## Per-document summary

| Document | Revision frozen | Clauses | Compliant | Partial | Gap | N/A | Excluded |
|---|---|---:|---:|---:|---:|---:|---:|
| [RFC 8762](rfc8762.md) — STAMP base protocol | RFC 8762, March 2020 | 62 | 51 | 1 | 0 | 9 | 1 |
| [RFC 8972](rfc8972.md) — STAMP Optional Extensions | RFC 8972, January 2021 | 151 | 130 | 5 | 6 | 10 | 0 |
| [RFC 9503](rfc9503.md) — Destination Node Address / Return Path | RFC 9503, October 2023 | 26 | 21 | 1 | 0 | 3 | 1 |
| [RFC 9534](rfc9534.md) — Micro-session ID (LAG) | RFC 9534, January 2024 | 18 | 15 | 0 | 0 | 3 | 0 |
| [RFC 8545](rfc8545.md) — TWAMP port allocation | RFC 8545, March 2019 | 8 | 1 | 0 | 0 | 7 | 0 |
| [draft-ietf-ippm-asymmetrical-pkts](draft-asymmetrical-pkts.md) — Reflected Test Packet Control (Type 12) | -14, 16 March 2026 (RFC Editor queue) | 47 | 35 | 1 | 2 | 8 | 1 |
| [draft-ietf-ippm-stamp-cos-ecn](draft-stamp-cos-ecn.md) — CoS/ECN congestion signaling | -01, 20 July 2026 | 16 | 14 | 2 | 0 | 0 | 0 |
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md) — Reflected header data (Types 246/247) | -11, 4 July 2026 | 40 | 38 | 0 | 0 | 2 | 0 |
| **Total** | | **368** | **305** | **10** | **8** | **42** | **3** |

Each matrix was independently re-verified against a freshly fetched copy of
its source text on 2026-07-22 (see each file's own "Revision frozen" line and
adversarial re-verification log). Only the `Summary:` line of each file was
read to build the table above; the matrices themselves are the source of
truth and are not reproduced or altered here.

## Documented exclusions

These are non-Compliant rows (or feature-scope boundaries the matrices don't
score at all) that this project has deliberately decided **not** to close,
with a stated rationale. Unlike the Partials below, these are not "still
open" — they are closed as accepted design.

| Exclusion | Rationale | Pointer |
|---|---|---|
| **SR-MPLS return-path forwarding** | A userspace UDP-socket reflector cannot push an MPLS label stack onto its own IP reply. By design, any Return Path TLV carrying an SR-MPLS segment list is echoed with the U-flag (`ReturnPathAction::UnsupportedSr`) rather than attempted. | `9503-4.1.3.1-1` (Excluded in the matrix); `src/tlv/list/processing.rs` `has_sr_mpls()` / `process_return_path` |
| **SNMP SET** | The AgentX sub-agent is a read-only monitoring surface by design (GET/GETNEXT/GETBULK only). A TestSet is answered `notWritable` (Commit/UndoSet get the matching failure code; CleanupSet is a no-op) rather than the PDU being silently dropped, so a manager gets a clean, immediate failure instead of a timeout — that response *is* the compliant behavior for a sub-agent that has chosen not to expose writable OIDs, not a gap in one. | `src/snmp/`; `doc/control-plane.md` ("SNMP SET parity — tracked elsewhere"); `doc/architecture.md` ("`--snmp` requires a Unix platform") |
| **STAMP YANG** | No implementation gap is scored because no adopted standard exists to implement against: the STAMP YANG individual draft this project tracked has expired, and RFC 9534 §3.2's own text places YANG augmentation for micro-session mapping explicitly out of scope ("The detailed augmentation is not in the scope of this document"). | `rfc9534.md` note under §3.2; project standards-tracking notes |
| **Windows backend limits** | Windows uses the `pnet`/libpcap-Npcap datalink-capture backend as a fallback tier, not the primary `nix` backend Linux/macOS get. This is a documented platform tier, not an unnoticed gap: Windows CI runs the test suite best-effort (non-gating — a Windows test failure does not block the pipeline), and features requiring raw-socket control-message access (kernel timestamping, some CoS/ECN paths) are honestly reported as unsupported at runtime rather than silently degraded. | `doc/architecture.md` ("Windows ❌"); CI `rust.yml` best-effort Windows job |
| **macOS TX timestamping** | The kernel/hardware timestamping feature has a real, tested RX path on macOS (`SO_TIMESTAMP`/`SCM_TIMESTAMP`, software-tier, µs resolution) but no TX path and no NIC-hardware path — Darwin exposes no equivalent of Linux's `MSG_ERRQUEUE`/`SIOCSHWTSTAMP`. This is a platform capability boundary, disclosed in code and docs, not an oversight. | `src/hwtstamp.rs` (module doc + macOS branch); `doc/architecture.md` hwtstamp section |
| **NIC-hardware timestamp paths** | The `SIOCSHWTSTAMP` hardware-timestamp tier (Linux, `--hwtstamp on`, needs `CAP_NET_ADMIN` and a NIC that actually supports it) is code-cited and unit-tested for its request/fallback logic, but the live hardware path itself cannot be exercised in ordinary CI (no privileged, hardware-timestamp-capable NIC available there). Verification for this tier is the code citation plus a manual procedure an operator with the right hardware can run; `startup_action()`'s graceful fallback means the binary never *requires* the hardware to start. | `src/hwtstamp.rs`; `doc/architecture.md` ("NIC hardware tier") |
| **SSID-based session admission** | RFC 8972 §3 MUSTs require a Session-Reflector to be pre-provisioned with session identity (SSID + 4-tuple) and to discard non-matching traffic (`RFC8972-3-6`/`-3-7`/`-3-8`, scored Gap in the matrix). stamp-suite's reflector deliberately accepts any syntactically valid STAMP packet on the bound port — a general-purpose measurement tool, not a provisioned network element — and the RFC's own §3 text places "the means of provisioning" explicitly out of its own scope. The actual admission controls this project ships instead are: the per-source/per-SSID rate limiter, HMAC integrity in authenticated mode, and per-client stateful sequencing when `--stateful-reflector` is set. **Maintainer decision, 2026-07-22:** keep the accept-any design; these three rows remain Gap in `rfc8972.md` for traceability but are treated as closed here, not as outstanding work. | `RFC8972-3-6`, `RFC8972-3-7`, `RFC8972-3-8` in `rfc8972.md`; `src/session.rs` `SessionManager`; `src/receiver/mod.rs` rate limiter wiring |

## Remaining Partials

These rows are genuinely open — real, disclosed limitations, not accepted
design. Each is tagged with its actual matrix status (some rows below are
scored **Partial**, others **Gap** in their matrices; they are listed
together because together with the three Gap rows retired under
"Documented exclusions" above, this table accounts for **every**
non-Compliant, non-N/A row across all eight matrices — the complete honest
residual of the audit).

| Item | Status | Rationale | Pointer |
|---|---|---|---|
| **Control-plane transport security trade-off** | Partial | The runtime control-plane REST API binds loopback-only by default, warns loudly on a non-loopback bind, and supports an opt-in constant-time-compared bearer token — but there is no TLS in v1 and the token is not enforced. Remote management is expected to go over an SSH tunnel or reverse proxy. | `RFC8762-7-1`; `doc/control-plane.md` |
| **Reply source-address pinning (SHOULD)** | Partial | RFC 9503 §3 says a matched Destination Node Address SHOULD become the reply's IP source address; neither backend pins it — source selection is left to OS routing on both `nix` and `pnet`. Correct on a single-address bind by coincidence; not forced on a multi-homed/wildcard bind, which is exactly the tunnel-decap case the RFC motivates. | `9503-3-1` |
| **DSCP/ECN admission-policy layer** | Partial | RFC 8972 §4.4/§6 and draft-stamp-cos-ecn §3.2 call for a local policy that can independently confirm a DSCP/ECN value is *permitted* before applying it. This implementation conflates "permitted" with "capable": it always attempts the `IP_TOS`/`IPV6_TCLASS` setsockopt and only refuses on syscall failure. No `--allowed-dscp`-style destination-scoped policy exists. | `RFC8972-4.4-8`, `RFC8972-6-3`, `cos-ecn-3.2-3`, `cos-ecn-3.2-6` |
| **Extra-Padding-after-HMAC leniency** | Partial | RFC 8972 §4.8's coherent reading permits an Extra Padding TLV after the HMAC TLV (pure filler, not HMAC-covered content); the receive-side parser has no such exemption and marks any post-HMAC TLV malformed regardless of type. The sender is unaffected (it never emits this ordering). Receive-side leniency gap toward an otherwise-conformant peer. | `RFC8972-4.8-2` |
| **Live egress-MTU query (reflector side)** | Partial | draft-ietf-ippm-asymmetrical-pkts §3's MTU-exceeded C-flag/single-reply behavior is implemented, but `--reflected-control-max-size` is an operator-configured constant standing in for the real egress-interface MTU, not a live `SIOCGIFMTU`/`IP_MTU` query. Correct only insofar as the operator keeps the flag in sync with the real path MTU. (The sender side of the same MUST, by contrast, does query the live route MTU — see `ext-hdr-3.1-9`/`-3.2-8` in `draft-stamp-ext-hdr.md`, which are Compliant.) | `asym-3-08` |
| **Replay detection (SHOULD)** | Gap | The draft's Security Considerations recommend tracking the Sequence Number of received test packets to detect replay/reordering; no such tracking exists (the reflector's own `curr_seq` is an outgoing generator, not a record of received sequence numbers). Blast radius is bounded by the rate limiter and by Type-12 amplification being off by default, but the SHOULD itself is unmet. | `asym-5-07` |
| **Send-delay / reflected-burst cross-check** | Gap | The sender's own `--send-delay` pacing is not validated against the expected completion time of a requested Type-12 reflected burst (`count`/`interval`), so an operator can configure a `--send-delay` shorter than the burst the reflector will still be transmitting. Self-inflicted, advisory-level (SHOULD NOT), and opt-in only (Type-12 defaults to count 1 / disabled). | `asym-5-09` |
| **Zeroed-SSID reply control (sender)** | Gap | RFC 8972 §3 expects the Session-Sender to support a control governing how to proceed when a reflector returns a zeroed SSID (continue vs. stop the session); the sender logs the reflected SSID but exposes no such knob and never changes behavior on a zeroed SSID. Advisory impact for a CLI probe — measurement continues either way and no reflected value is trusted because of it. | `RFC8972-3-11` |
| **Location field-disclosure policy (stateful reflector)** | Gap | §4.2.2 calls for reflector-side policy control over which Location TLV fields are disclosed; no such knob exists. Exposure is bounded in practice: this implementation only ever fills source/destination IP and port answers (MAC/EUI sub-TLVs are answered zeroed on UDP-socket backends by platform necessity), so the data a policy layer would suppress is already minimal. | `RFC8972-4.2.2-2` |
| **Misplaced-HMAC severity** | Gap | §4.8 treats a TLV placed after the HMAC TLV as an integrity condition; the parser marks such packets malformed (M-flag) and stops processing rather than additionally running the full HMAC-verification-failure procedure (I-flag on all TLVs). Only reachable from a malformed or adversarial peer, and the affected packet's TLVs are never trusted either way — the deviation is in which flag signals the problem, not in any value being consumed. | `RFC8972-4.8-3` |
| **Reflector ingress clock telemetry (Timestamp Info "In" fields)** | Partial | §4.3's Sync Src In / Timestamp In field definitions describe the reflector's ingress (T2) clock characteristics; the reflector fills its egress-side fields but reports no distinct ingress-side source/method. The field definitions are descriptive rather than an explicit reflector-fill MUST (which is why these rows are Partial, not Gap). | `RFC8972-4.3-5`, `RFC8972-4.3-6` |

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

- **Unit tests** — 848 tests under `cargo test --lib` (`cargo test
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

Every Gap identified during this audit was either fixed in the 1.0 line's
commits, moved into "Documented exclusions" above with a maintainer
rationale and date, or listed under "Remaining Partials" as open,
disclosed work. Nothing found was left unaddressed and undocumented.
This statement reflects the matrices as they stand on the date above, on
branch `1.0-line`; it is not re-issued automatically and should be revisited
whenever a matrix's own `Summary:` line changes.
