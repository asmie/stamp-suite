# stamp-suite conformance — compliance statement

Evidence refresh: **2026-09-10**. Historical audit: **2026-08-05**. Branch: **1.0-line**.

**September remediation:** the status and clause scores below are
historical, not a current conformance sign-off. The [September review](../reviews/2026-09-08/review.md)
identified 16 findings, including behavior previously scored Compliant.
The [repair tracker](../reviews/2026-09-08/progress.md) records fixes and their
verification one item at a time. Finding 02 updates the three session-admission rows for provisioned mode only.
Finding 07 narrows RFC 9534 support to numeric ID handling and reopens physical-member requirements as Partial/Gap. Finding 09 repairs the Type-12 ordering response and reclassifies its stale N-A row as Compliant. Finding 11 implements Linux route-aware sizing and reopens three MTU rows as Partial across the broader platform/route scope. Finding 12 separates synchronization-source declarations from encoding, corrects source code points and records actual TX provenance. Finding 13 adds the BER-07 matrix, repair and directional interval reporting. Other clause scores remain historical; citation maintenance alone does not
establish semantic compliance. Finding 14 repairs AgentX request ordering/framing and Close acknowledgments; its [targeted record](agentx-review.md) is separate from the STAMP clause totals. Finding 15 separates machine-readable output; finding 16 checks evidence consistency and requires privileged CI scenarios to execute. Clippy and the optimization checkpoints remain pending.

This document rolls up the nine clause-level conformance matrices in this
directory into an evidence inventory for the stamp-suite 1.0 line.
Counts below include findings 02 (RFC 8972), 07 (RFC 9534), 09 (Type-12 ordering), 11 (route MTU scope), and 13 (BER-07); they are not a new
full-project audit.
Where this document goes further than the matrices is in stating, as a
maintainer decision, which of the residual non-Compliant rows are accepted
design trade-offs (**Documented exclusions**), and in disclosing the
experimental/pending-IANA codepoints this implementation stands in for.

The August audit treated three SSID-admission Gaps as an accepted design
exclusion. Finding 02 replaces that decision with explicit provisioned
admission. The legacy default remains permissive and does not enforce the
RFC 8972 §3 provisioning/discard MUSTs. Remaining September findings are
tracked independently of these historical clause totals.

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
| [draft-ietf-ippm-stamp-ext-hdr](draft-stamp-ext-hdr.md) — Reflected header data (Types 246/247) | -11, 4 July 2026 | 40 | 36 | 2 | 0 | 2 | 0 |
| [draft-gandhi-ippm-stamp-ber](draft-stamp-ber.md) — Residual BER (Types 240–242) | -07, 30 June 2026 | 30 | 27 | 2 | 0 | 1 | 0 |
| **Total** | | **398** | **342** | **11** | **1** | **41** | **3** |

The eight pre-existing matrices were independently re-verified against a freshly fetched copy of
its source text on 2026-07-22 (see each file's own "Revision frozen" line and
adversarial re-verification log). No clause was re-read against its source text
in the 2026-08-05 pass: that pass changed *implementation*, and each row it
touched was re-scored against the same frozen clause text, with the code and
test evidence for the closure appended to the row. The matrices remain the
source of truth; the table above and their `Summary:` lines are checked against individual clause rows by `scripts/check_conformance_counts.py`. The BER matrix was added and verified on 2026-09-09.

## Documented exclusions

These are accepted scope boundaries, distinct from the open Partial/Gap rows.
Physical LAG association and steering remain incomplete (six Partial and one
Gap in RFC 9534). Route-MTU coverage remains platform-limited (five Partial
rows across Type 12, reflected headers and BER). Those twelve rows have not
been closed by the exclusions below.

| Exclusion | Rationale | Pointer |
|---|---|---|
| **SR-MPLS return-path forwarding** | A userspace UDP-socket reflector cannot push an MPLS label stack onto its own IP reply. By design, any Return Path TLV carrying an SR-MPLS segment list is echoed with the U-flag (`ReturnPathAction::UnsupportedSr`) rather than attempted. | `9503-4.1.3.1-1` (Excluded in the matrix); `src/tlv/list/processing.rs` `has_sr_mpls()` / `process_return_path` |
| **SNMP SET** | The AgentX sub-agent is a read-only monitoring surface by design (GET/GETNEXT/GETBULK only). A TestSet is answered `notWritable` (Commit/UndoSet get the matching failure code; CleanupSet is a no-op) rather than the PDU being silently dropped, so a manager gets a clean, immediate failure instead of a timeout — that response *is* the compliant behavior for a sub-agent that has chosen not to expose writable OIDs, not a gap in one. | `src/snmp/`; `doc/control-plane.md` ("SNMP SET parity — tracked elsewhere"); `doc/architecture.md` ("`--snmp` requires a Unix platform") |
| **STAMP YANG** | No implementation gap is scored because no adopted standard exists to implement against: the STAMP YANG individual draft this project tracked has expired, and RFC 9534 §3.2's own text places YANG augmentation for micro-session mapping explicitly out of scope ("The detailed augmentation is not in the scope of this document"). | `rfc9534.md` note under §3.2; project standards-tracking notes |
| **Windows backend limits** | Windows uses the `pnet`/libpcap-Npcap datalink-capture backend as a fallback tier, not the primary `nix` backend Linux/macOS get. This is a documented platform tier, not an unnoticed gap: Windows CI runs the test suite best-effort (non-gating — a Windows test failure does not block the pipeline), and features requiring raw-socket control-message access (kernel timestamping, some CoS/ECN paths) are honestly reported as unsupported at runtime rather than silently degraded. | `doc/architecture.md` ("Windows ❌"); CI `rust.yml` best-effort Windows job |
| **macOS TX timestamping** | The kernel/hardware timestamping feature has a real, tested RX path on macOS (`SO_TIMESTAMP`/`SCM_TIMESTAMP`, software-tier, µs resolution) but no TX path and no NIC-hardware path — Darwin exposes no equivalent of Linux's `MSG_ERRQUEUE`/`SIOCSHWTSTAMP`. This is a platform capability boundary, disclosed in code and docs, not an oversight. | `src/hwtstamp.rs` (module doc + macOS branch); `doc/architecture.md` hwtstamp section |
| **NIC-hardware timestamp paths** | The `SIOCSHWTSTAMP` hardware-timestamp tier (Linux, `--hwtstamp on`, needs `CAP_NET_ADMIN` and a NIC that actually supports it) is code-cited and unit-tested for its request/fallback logic, but the live hardware path itself cannot be exercised in ordinary CI (no privileged, hardware-timestamp-capable NIC available there). Verification for this tier is the code citation plus a manual procedure an operator with the right hardware can run; `startup_action()`'s graceful fallback means the binary never *requires* the hardware to start. | `src/hwtstamp.rs`; `doc/architecture.md` ("NIC hardware tier") |
| **Legacy permissive session admission** | `--session-admission permissive` remains the compatibility default and does not enforce RFC 8972 §3 provisioning/discard. Select `provisioned` and configure exact `--reflector-session` entries for those requirements. The three formerly excluded Gaps were repaired under finding 02 on 2026-09-08; sequence/counter/replay/Follow-Up state uses full identity in both modes. | `RFC8972-3-6`, `RFC8972-3-7`, `RFC8972-3-8`; [configuration](../usage.md#session-provisioning); `tests/session_identity_test.rs` |

## Closed since the 1.0 audit

The 2026-07-23 statement listed eleven open items covering fifteen matrix rows —
ten scored Partial and five scored Gap. **The August pass recorded all fifteen as closed. September checks reopened
some scope claims; the current row scores and rollup take precedence.** They are recorded here rather than deleted,
so the statement remains readable against its predecessor: each matrix row keeps
its original finding with the closure appended beneath it, naming the code and
the tests.

| Item (as listed on 2026-07-23) | Was | Rows | Closed by |
|---|---|---|---|
| Control-plane transport security trade-off | Partial | `RFC8762-7-1` | TLS for the control plane: `--control-tls-cert`/`--control-tls-key` (rustls, explicit `ring` provider), both flags required together, and TLS additionally requires a bearer token. Verified with a real handshake asserting 200 with the token and 401 without. |
| Reply source-address pinning (SHOULD) | Partial | `9503-3-1` | The matched Destination Node Address now reaches the send path (`StampResponse::reply_source`) and both backends pin it via an `IP_PKTINFO`/`IPV6_PKTINFO` ancillary message. Verified by asserting the *receiver* observes the pinned source. |
| DSCP/ECN admission-policy layer | Partial | `RFC8972-4.4-8`, `RFC8972-6-3`, `cos-ecn-3.2-3`, `cos-ecn-3.2-6` | `src/cos_policy.rs` separates *permitted* from *capable*: `--allowed-dscp`, `--allowed-ecn`, and destination-scoped `--allowed-dscp-for`. A refused DSCP1 reports RPD=0b01; a refused EC1 forces Not-ECT and reports RPE=0b10. |
| Extra-Padding-after-HMAC leniency | Partial | `RFC8972-4.8-2` | Both parsers now accept trailing Extra Padding. Required fixing HMAC coverage first: the covered prefix had been derived from the sum of non-HMAC TLV sizes, which is only the true prefix while the HMAC TLV is last. |
| Live egress-MTU query (reflector side) | Partial | `asym-3-08`, `ext-hdr-3.1-9`, `ext-hdr-3.2-8` | Finding 11 replaces the startup interface stand-in with Linux per-route sizing, bounded notification-invalidated caching and fragmentation prevention. Live veth tests cover both IP families, wildcard/bound sources, link/route changes and alternate targets. Unknown budgets fail closed; exact-size and platform limits are explicit in the current rows. |
| Reflector clock metadata | Partial | `RFC8972-4.3-5`–`RFC8972-4.3-8`, `RFC8972-5.4-1` | Finding 12 replaces format/capability inference with explicit system/PHC discipline, correct registry values and actual timestamp methods. Sources remain operator declarations; physical clock synchronization is not verified. The current packet's software T3 and the previous reply's corrected Follow-Up timestamp are distinguished. |
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

The current checker reports **381 numeric citations: 88 matched to a named
source construct, 293 mechanically unverifiable, 0 detected stale references**.
This is a bookkeeping result, not a semantic sign-off. An anchor overlap does
not prove a requirement is met; unverifiable and path-only references still
need human review when their associated behavior changes. Earlier totals
(540/542) describe historical revisions and are superseded here.

```bash
python3 scripts/check_conformance_citations.py --json --details
python3 scripts/check_conformance_counts.py --json
```

The first command checks both range endpoints, file resolution and heuristic
identifier overlap, and includes the full unverified inventory with `--details`.
The second compares clause statuses, unique IDs, matrix summaries/Counts footers
and the rollup, failing on missing matrices or mismatches. Both run in
`.github/workflows/conformance.yml`; regression fixtures prove drift is rejected.
Neither checker rereads RFCs or upgrades historical clause scores automatically.

## Experimental-codepoint disclosure

This implementation stands in for six codepoints across three drafts that
have not (yet) received a final IANA allocation. All six are now collected
in one place in the source tree — `src/tlv/experimental.rs` — which each
const's doc comment cites as its own single edit point.

| Codepoint | Registry | Const | Draft | What it needs |
|---|---|---|---|---|
| Type 240 | STAMP TLV Types (Experimental, 240-251) | `BER_PATTERN_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.1 | Draft-side Type allocation |
| Type 241 | STAMP TLV Types (Experimental, 240-251) | `BER_COUNT_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.2 | Draft-side Type allocation |
| Type 242 | STAMP TLV Types (Experimental, 240-251) | `BER_MAX_BURST_TLV_TYPE` | draft-gandhi-ippm-stamp-ber-07 §5.3 | Draft-side Type allocation; **known collision**, see below |
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

- **Unit and ordinary integration suites:** run separately for default,
  all-features and pnet-only builds. All-features selects nix and cannot verify
  pnet execution. Results are recorded by checkpoint rather than keeping a
  timeless unit-test count here. See [test inventory](../../tests/README.md).
- **Independent protocol combinations:** the Python standard-library peer runs
  against default and all-feature binaries in conformance CI, recording exact
  UDP bytes, traffic class and source metadata. Frozen requests and corrupted
  reply checks keep its encoder/verifier independent of production codecs.
  The SRv6 profile verifies U-flag fallback, not successful SRH transmission;
  see [fixture contract and coverage map](../testing-interop.md).
- **Properties and fuzzing:** deterministic/property suites run through Cargo;
  eight fuzz targets are compiled from the separate locked fuzz manifest and
  exercised by the scheduled fuzz workflow. Compilation is not fuzz execution.
- **Privileged wire tests:** three raw pnet tests, nine namespace scenarios and
  one reply-route MTU regression. The conformance workflow builds without root,
  selects exact Cargo artifacts, verifies nonempty expected test counts and runs
  with `STAMP_REQUIRE_PRIVILEGED=1`. A missing privilege/tool, unsupported kernel
  prerequisite or internal skip fails that job. Local exploratory runs may omit
  strict mode, but an internal skip is not wire evidence. See
  [namespace procedures](../testing-netns.md).
- **Platform and hardware limits:** local September results are Linux evidence.
  macOS CI and best-effort Windows CI retain their separate scopes. No physical
  NIC timestamp or LAG-member test is claimed. Earlier informal interoperability
  runs are not reproducible certification; AgentX has its separate targeted record.

## Current residual and evidence limits

The clause inventory is **398 rows: 342 Compliant, 11 Partial, 1 Gap,
41 N/A and 3 Excluded**. The three session-admission rows are Compliant only
under their documented provisioned-mode conditions. The remaining LAG and
platform-MTU rows are open scope limits, not accepted exclusions or finished
optimizations. The historical Compliant rows have not all received a fresh
semantic audit in this evidence checkpoint.

The [repair tracker](../reviews/2026-09-08/progress.md) records findings and
remaining optimization work. Finding 16's [test results](../reviews/2026-09-08/logs/finding-16/results.json)
state what actually ran, including expected negative checks and environment
limits. Clippy repair remains the user's final checkpoint; this statement does
not claim a green remote CI run or release sign-off.
