# Conformance test references

Three checks are easy to confuse: whether a cited source exists, whether a row
names a test, and whether the behavior is verified. This policy adds the second
check. A test reference on its own does not prove the third.

## Policy

For a Compliant row whose Level includes MUST, MUST NOT, SHALL, SHALL NOT or
REQUIRED, including structural/implied requirements, the Evidence column must
identify a test of the claimed behavior. A parenthetical profile qualifier does
not waive this requirement. Other statuses and SHOULD/MAY/descriptive rows are
outside this inventory; their source references still need to be valid.

The checker recognizes:

- A real Rust test function with a built-in or namespaced test attribute, such
  as an ordinary test, Tokio test or annotated property test. Prefer a qualified
  reference such as `src/receiver/transmit/tests.rs::single_header_reply_checks_mtu_trims_and_resigns`.
  An unqualified name is accepted only if it identifies one test and no helper
  has the same name.
- A dedicated test file containing annotated tests, such as
  `tests/session_identity_test.rs`, or a declared test module such as
  `src/tlv/list/mod.rs::tests`. File and child-module lookup follows the
  citation checker's source convention, not compiler name resolution. A whole
  suite reference needs a manual review of the relevant assertions, so named
  cases are better.
- A Python unittest method or suite that contains actual TestCase methods,
  such as `scripts/tests/test_interop_ber.py::BerOracleChecks::test_hmac_rfc4231_and_bit_reference`.
  Tests of an oracle alone do not establish application conformance.
- A named wire-driver function. For example, Wire tests:
  `scripts/interop_ber.py::reflector_case`, `scripts/interop_ber.py::sender_case`.
  Each function must exist. A reviewer must confirm that the driver runs the
  application and checks the relevant bytes or behavior. The surrounding
  evidence should name the scenario or vector.

Comments, string literals, helper names containing "test", ordinary production
files and fixture data do not count on their own. For example,
`src/receiver/transmit/shape.rs::fit_reply` identifies implementation, not a test of
its caller. Qualified Python references are also checked for stale files and
functions, including outside normative Compliant rows.

The scanner understands the repository's built-in, Tokio and property-test
attributes and Python unittest. It is not a general Rust macro expander or
Python test runner. An unrecognized or ambiguous reference needs a clearer
citation or a reviewer's attention. It does not mean the behavior is untested.

## Semantic and execution review

Before approving a row, trace the trigger through the claimed production path
to the assertion. Check role, authentication mode, IP family, backend and
failure/fallback conditions. A codec test can establish field encoding without
establishing dispatch. A mocked transport can establish finalization logic but
does not prove OS routing or physical behavior. Shared implementation is not
runtime evidence for every backend.

Test presence is not a pass. Ignored tests, platform/feature-gated declarations
and source-only wire drivers need execution evidence for the claimed profile.
The JSON report sets `execution_checked` to false and lists directly ignored
Rust tests and suite counts. Counts describe source declarations, not runnable
cases in a particular build. The checker does not infer execution from Cargo
builds, earlier runs or the presence of fixtures. A few representative
assertions also do not certify every statement in a broad requirement.

When evidence is insufficient, add a regression through the correct entry
point, narrow the profile and say why, or lower the status. Do not rename a
helper, add a generic suite or change the normative Level just to clear the
inventory. Links to shared notes do not replace a direct test reference on
the row.

## Inventory and CI guard

```sh
python3 scripts/check_conformance_citations.py --require-test-evidence --json --details > citations.json
python3 scripts/check_conformance_citations.py --json --details > advisory-citations.json
```

The first command keeps stale citation failures and adds `test_evidence` with
the policy version, applicable clause counts, missing rows and, with `--details`,
all clause and reference records. Counts separate rows that have a test
reference from rows that lack one. They are not coverage percentages. Citation
counts describe Rust source references. Qualified Python test references are
recorded in the test inventory, and invalid ones also fail source checking.

The CI citation step uses `--require-test-evidence`. Any normative Compliant
row without a test reference makes it return nonzero and adds a
`missing-test-evidence` problem. `citations.json` keeps the detailed inventory,
including after a failed check. Without that flag the command only reports
missing references, but invalid citations fail in either mode. The guard checks
that references exist. It does not check semantic coverage, successful
execution or certification.

The first inventory, on 9 November 2026 at `d6a4f8a`, found 325 applicable
rows: 159 with test references and 166 without. The reviews below added a test
reference to every remaining row and narrowed several claims to Partial. After
the last review (`8d388e5`), all 318 applicable rows had a reference, and
commit `cce43a9` made the CI step strict. These figures are history. Run the
checker for current counts.

## Review records

Each section below covers one review: what it examined, which tests now back
which rows, and why some rows became Partial. When a review found a defect, the
same commit fixed it; the commit is named in each section. The evidence is from
Linux runs unless a section says otherwise. Broader semantic review of rows
that already had references, and native, hardware and deployment-profile
testing, are outside these reviews.

## First reviewed batch

Commit `a70328d` added the inventory and resolved the first 40 missing
references. It lowered three Both-role MTU claims to Partial.

| Area | Evidence and what it establishes | Limits / remaining work |
|---|---|---|
| 39 normative Compliant BER rows | Role-specific wire drivers now appear on every applicable BER row. Seventeen reflector vectors and sender baseline/gating/U scenarios check counters, flags, repaired padding, unknown/malformed children, configuration and directional statistics. | Linux nix software-loopback profile using agreed experimental types; no zero-checksum, physical-link or maintained-peer certification. Existing Partial/Gap rows remain. |
| RFC 8972 HMAC rows 4.8-1, 6, 7, 8, 11, 13, 14 | A new production Rust signer/verifier known-answer test uses RFC 4231 case 1, truncated to 128 bits. Separate wire roles check the actual HMAC type, length and coverage; a malformed-length parser test checks M. Failed extension-HMAC echoes keep all copied values and the failed digest, with I set. | Primitive/equivalence tests supplement the wire driver; they do not replace send-path checks. The copied failure digest is not regenerated into a successful one. |
| RFC 8972 admission rows 3-6 to 3-8 | Named IPv4 open/authenticated and IPv6 identity tests run the nix receiver with exact provisioned endpoints, SSIDs and micro IDs. Authentication tests verify that invalid bases cannot allocate or refresh state. | Provisioned profile only. Shared-core tests are not pnet capture runtime or physical ingress validation. |
| Reflected-header MTU rows 7.2-1, 3, 5 | The single-reply tests run actual transmission finalization, checking trimming, final signatures, unavailable budgets and EMSGSIZE refresh. The required namespace tests also exercise sender route budgets, trimming/restoration and refusal. | Lowered to Partial in `a70328d`; restored to Compliant in `a825b6b` after the sender regression and fixes described below. Linux kernel-route evidence, not end-to-end PMTU discovery. |
| Type 12 C signaling | Packet-processing and separate wire tests exercise exact/fractional rate ceilings, volume, count-zero suppression, sender C clearing, ignoring incoming C, and protected admission. | Exact timing and conservative first-request selection are Partial. Identity protection holds only for the authenticated protected profile. See the Type 12 review below. |

The required route-MTU namespace test ran all eight family/auth/binding
combinations with no prerequisite skip. Run builds and wire suites one after
another so Cargo cannot replace a binary that a test is using:

```sh
cargo test --locked --all-features --lib hmac
cargo test --locked --all-features --lib single_
cargo test --locked --all-features --test session_identity_test --test session_auth_admission_test --test tlv_flag_semantics
cargo build --locked --all-features
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report ber-wire.json
cargo test --locked --all-features --test route_mtu_test --no-run --message-format=json > mtu-artifacts.json
python3 scripts/run_privileged_test.py mtu-artifacts.json route_mtu_test 2 unshare -Urn env STAMP_MTU_NETNS_TESTS=1 TOKIO_WORKER_THREADS=2
```

## Sender MTU dispatch review

Fixed in commit `a825b6b`. The review found three sender defects. An
unreadable route budget kept the previous request set. Oversized mandatory
packets reached the kernel's send/retry path. Startup trimming could choose a
base-only send mode that never restored header requests. Per-probe AIMD control
and diagnostic trailers also needed space reserved before optional headers were
trimmed.

The sender never sends a header-reflection probe with an unknown budget.
Before sending, it checks the built packet, including IP/UDP and attached IPv6
header bytes, against the current route MTU. At startup an unknown or too
small budget is an error. During a run, since `b8c2879`, the probe is skipped
and counts as a send failure; eight consecutive failures end the run. Trimming reserves room for every possible
per-probe field. The TLV send mode survives an initially empty request set, so
requests can return after the MTU grows. These changes apply to
header-reflection probes; other packet-size policies keep their own scope.

`tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes`
runs the public sender loop and checks the received bytes and HMACs
separately. Eight IPv4/IPv6 and key-mode combinations go through 1280 → 1500 →
partial-header budget → 1280 → 1500. They check that mandatory non-header TLVs
stay, dynamic Direct Measurement/Type 12 fields, ordered removal/restoration
and final signatures. The modes are open, keyed open with TLV-HMAC origination
on or off, and authenticated. IPv6 attaches the default eight-byte Hop-by-Hop
header; the test does not establish exact-boundary delivery for every
Destination Options layout. Four more IPv4 cases check restoration after
startup removed every request. Each of the eight combinations also checks a
mandatory packet one octet too large, both at startup and after a successful
send and MTU drop. An observer changes only the isolated namespace's loopback
MTU after each successful send, before the next one, so the ordering does not
depend on timers.

`src/sender/run/mtu_tests.rs::unreadable_route_mtu_is_refreshed_before_the_probe_is_sent`
disconnects real IPv4/IPv6 open/authenticated UDP sockets, so the kernel has no
cached route, and checks that the sender reconnects and reads the MTU before
sending. `src/sender/run/mtu_tests.rs::refused_probes_share_the_send_failure_budget_without_pending_state`
checks that a probe refused for its route budget is not sent, leaves no pending
state, and ends the run after eight consecutive failures. These sender
regressions are separate from reflector backend capture evidence.

Both required namespace tests pass with no skip: the eight reflector
combinations and the sender cases above. The three MTU rows return to Compliant
within their Linux sender scope. Restoring them did not clear any
missing-reference row. CI requires two ignored tests in the MTU artifact.

## Sender echoed-identity review

Fixed in commit `a40f264`. A correctly signed delayed reply could consume a
newer pending probe with the same sequence, because the sender did not check
the echoed T1. A regression reproduced this through actual sends and the
sender's receive path before the fix. Another regression reproduced the
session-state monitor expiring a newer probe at the old deadline of the retired
sequence.

The sender now matches the full echoed sequence and all eight original wire
T1 bytes before deduplication, SSID policy, measurement acceptance and semantic
control/ID updates. Unknown or mismatched replies leave pending state intact.
`measurements.mismatched_replies` counts a known sequence with a missing or
different echo; `unknown_replies` still counts replies with no history. TLV
diagnostic evaluations run before this check and can still count rejected
input. Reply identities now include wire T1, so a legitimate newer generation
is accepted when the peer reuses its own sequence/T3. Kernel corrections keep
wire identity unchanged and require the original local send context. The
failure monitor replaces the retired sequence's deadline when a new generation
is sent.

Direct production-path evidence:

- `src/sender/run/admission_tests.rs::reused_sequence_rejects_old_signed_echo_before_measurement_or_control_state`
  forces sequence reuse across real probes in both families, NTP/PTP,
  authenticated/keyed-open modes and bounded/unlimited retention. A signed
  old echo cannot consume pending state, learn an ID, acknowledge Access Report,
  apply CE or change delay/DM/session-state samples. A correct echo succeeds;
  a later legitimate generation with the same reflector sequence/T3 also succeeds.
- `tests/sender_measurement_test.rs::sender_matches_every_echoed_timestamp_octet_before_consuming_a_probe`
  runs a separately written peer against the binary in 16 family/auth/parser/clock
  combinations. It changes each echoed T1 octet and sends an unknown sequence
  with zero SSID before the valid reply, showing that neither can trigger the
  SSID stop policy or complete the probe.
- `src/sender/run/admission_tests.rs::retained_late_and_additional_copies_require_the_original_echo`
  checks valid late copies, duplicates and additional replies after expiry.
  `src/sender/run/admission_tests.rs::short_replies_need_full_echo_but_may_omit_trailing_fields`
  rejects missing or partial identity and accepts complete echoes in 36- and
  41-byte unauthenticated replies. Reflector short-request handling did not
  change.
- `src/sender/tests.rs::delayed_tx_reports_do_not_correct_a_reused_sequence`
  rejects older send metadata, including tied monotonic times with different
  wire T1. The mixed-clock tests now exercise both original and corrected
  OWD T1 while echoing the original wire value through all four parsers.
- `src/sender/session_state.rs::tests::reused_sequence_replaces_the_old_deadline_and_clears_on_current_reply`
  checks the current deadline, cleanup after success and exactly one genuine
  timeout after reuse.

The fuzz adapter seeds matching echo context so the fuzz targets can still
reach measurement and control logic; the regressions above test stale identity.
These checks do not establish physical TX timestamp behavior or cryptographic
replay protection. Repeated sequence/T1 pairs cannot prove freshness. Required
micro-session late-reply restrictions keep their existing policy. See
[sender identity and compatibility](rfc8762.md#sender-reply-identity).

Three missing RFC 8762 references are resolved: eight-byte timestamp encoding
(4.2.1-2), HMAC algorithm/truncation (4.4-1) and 96-byte base coverage (4.4-2).
The last two cite the separate BER wire drivers for both application roles,
supplemented by the production known-answer test. No clause status is raised.

```sh
cargo test --locked --all-features --lib sender::
cargo test --locked --all-features --test sender_measurement_test --test pending_probe_limit_test
cargo check --locked --manifest-path fuzz/Cargo.toml
```

## Type 12 policy and admission review

Fixed in commit `8052e40`. The review reproduced two defects through production
packet processing. The integer rate quotient admitted fractional excess, and a
later matching Address Group could overwrite an earlier mismatch. Rate
admission now compares wide integer products, including the maximum u64 rate
ceiling without overflow. L2/L3 group decisions keep every valid mismatch.

`tests/tlv_flag_semantics.rs::reflected_control_rate_boundary_does_not_round_down_excess_traffic`
checks just below, exactly at and just above a 5,000 B/s ceiling in open,
keyed-open and authenticated packet processing. At 500 bytes, 100,000,000 ns
is admitted, while 99,999,999 ns gets C and no extra copy. The regression
failed before the change. The maximum-u64 cases check wide multiplication.
`tests/tlv_flag_semantics.rs::repeated_address_groups_cannot_overwrite_an_earlier_mismatch`
also failed before the fix. It checks L2/L3 mismatches in both orders and
all-matching groups. Malformed L3 lengths and continuing to later valid groups
are covered by
`tests/tlv_flag_semantics.rs::reflected_control_malformed_l3_lengths_do_not_filter_or_hide_later_groups`.

Four UDP tests run the actual Linux nix sender and reflector binaries against
separately written peers:

- `tests/type12_policy_test.rs::exact_rate_volume_and_zero_count_decisions_reach_the_wire`
  covers both families and open/keyed-open/authenticated modes. It checks C
  clearing/setting, ignoring received C, exact rate/volume admission, fractional
  rate/volume rejection as one correctly sized signed reply, count-zero
  suppression and a bound node-local reply source.
- `tests/type12_policy_test.rs::every_l3_group_must_match_before_wire_reflection`
  checks repeated IPv4/IPv6 groups in both orders, with valid HMACs when keyed.
  All-matching groups get a reply; a mismatch in either order gets no datagram.
- `tests/type12_policy_test.rs::protected_type12_profile_rejects_unverified_amplification`
  checks authenticated mode plus extension-HMAC verification. An invalid base
  HMAC is dropped. A missing or bad extension HMAC gets one I failure echo
  without burst shaping, and a valid request gets its admitted burst. It also
  confirms that an optional-HMAC open profile still accepts a missing HMAC.
- `tests/type12_policy_test.rs::sender_control_defaults_and_static_or_scaled_requests_clear_c`
  captures real requests in both families and authentication modes, including
  the AIMD-scaled path. Sender C stays clear. Defaults omit Type 12, and a burst
  that is configured starts immediately with its count and interval.

Five missing references are resolved. Exact nanosecond wire timing
(asym-3-11) and conservative selection of a first request (asym-5-05) are now
Partial: software pacing and omitting Type 12 by default do not establish those
general claims. Identity protection (asym-5-01) is Compliant only for the
tested authenticated protected profile. Enabling optional verification with a
key in open mode does not by itself require signed requests. After this review
no normative Compliant Type 12 row lacked a reference.

These results are software-loopback and packet-processing evidence. They do
not cover exact wire timing, a multicast topology, native platforms or pnet
capture.

```sh
cargo test --locked --all-features --test tlv_flag_semantics --test type12_policy_test
```

## Core extension review

Fixed in commit `d804d3b`. The review reproduced two sender defects with
separately written binary peers. A reply with extensions after a base-only
probe skipped TLV validation. An unused known type with an invalid length but
no peer M flag could leave later measurement values usable. The sender now
detects extensions from the received length and derives malformed markers for
every known outer type it keeps before it uses any values. Authentication still
verifies the original wire bytes, and base RTT acceptance does not depend on
unusable extension data.

`tests/sender_measurement_test.rs::base_only_sender_validates_returned_extensions`
checks actual 44/112-byte requests followed by extended replies in both IP
families and authentication modes.
`tests/sender_measurement_test.rs::sender_validates_unused_tlv_lengths_before_later_measurements`
checks invalid-length CoS without wire M and valid-length CoS with wire M,
before Direct Measurement, after base-only and extended requests. It verifies
that later values are ignored while the signed original bytes still
authenticate. Both regressions failed before the fix.
`tests/sender_measurement_test.rs::sender_origins_rfc8972_tlvs_with_u_set_and_m_i_clear`
captures all eight RFC 8972 outer types, U/M/I flags, big-endian multi-byte
lengths/counters and signatures in open, keyed-open and authenticated modes.

The three tests in `tests/tlv_extension_wire_test.rs` exercise real reflectors
in both families and all three key profiles. They check ordered padding and
unknown opaque values, ignored incoming flag bits, copied values after the
first malformed known TLV, and that integrity-failure values and digests are
kept. Separate HMAC calculations check the resulting original and final wire
bytes. Opaque unknown data contains a count-zero Type 12 request that must not
run. These malformed-length cases use complete frames, so they do not change
the opaque-trailer compatibility policy. Processing the prefix before the
first malformed TLV is permitted, and the matrix now says so.

Fourteen missing RFC 8972 references are resolved. Clause statuses did not
change. These are Linux nix software-loopback and shared-parser checks. The
pnet frame decoder regression ran separately as a unit test. Nothing here
covers pnet capture runtime, physical clocks or native platforms.

```sh
cargo test --locked --all-features --test sender_measurement_test --test tlv_extension_wire_test
```

## Location nested validation review

Fixed in commit `59c3d94`. The review reproduced sender and reflector failures:
incomplete Location child headers were silently ignored, and invalid nested
lengths did not stop later outer values from being used. A received child M
with a valid length also needed to stop the sender's outer processing.

The nested validator, which does not allocate, now checks the port prefix,
child frames and known-type lengths before semantic processing. It sets M on
the whole Location TLV, which stops later values. After integrity verification
succeeds, an identifiable malformed child's header also gets M when the whole
list allows processing. Failed-integrity and structurally malformed signed
echoes keep the original nested bytes. Signatures verify the original input
and are regenerated over the final outgoing bytes when appropriate.

`tests/sender_measurement_test.rs::sender_stops_at_malformed_location_children_but_ignores_child_i`
checks incomplete headers, known wrong lengths, child M and ignored child I in
both families and authentication modes. The origination capture test also
asserts the exact zeroed Location value and nested U/M/I headers.
`tests/tlv_extension_wire_test.rs::location_requests_preserve_lengths_and_report_observed_endpoints`
checks real stateful all/none disclosure policies, observed ports and
addresses, unknown/specific child echoes, ignoring I, MBZ zeroing and the nix
missing-MAC fallback in both families and three key profiles. IPv4 uses
distinct endpoints; IPv6 loopback is supplemented by distinct-address unit
fixtures.
`tests/tlv_extension_wire_test.rs::malformed_location_children_stop_later_outer_tlvs_on_the_wire`
checks all nine known child length errors, short outer values, partial child
headers and truncated bodies, outer/child M, later outer U and final signatures.
The integrity-failure wire test now includes a malformed child with incoming I
and checks that those bytes also come back unchanged. Both new failure
regressions failed before the production fix.
`tests/tlv_extension_wire_test.rs::malformed_signed_list_keeps_nested_location_bytes_and_original_digest`
caught a regression in marker editing during review. It now checks that values
stay unchanged in a malformed signed list whose covered prefix verifies.
The combined wire targets contain 15 tests.

Sixteen missing Location references are resolved with tests. One more row,
RFC8972-4.2.1-3, becomes Partial. Copied malformed, skipped and
integrity-failure values can keep child I, although originated and processed
children clear it. Which of the flag rule and the copy rule takes precedence is
still undecided; see
[Location nested validation](rfc8972.md#location-nested-validation). These
checks establish Linux software-loopback and shared-parser behavior, not
physical addressing, NAT traversal or native/pnet capture runtime conformance.

During this review one full all-features run failed at the launcher's
`retained_socket_excludes_other_binders_and_is_released_on_teardown` assertion,
with AddrInUse (OS 98) on an immediate rebind. A full rerun passed, and 50
isolated IPv4/IPv6 rounds of that test also passed. The failed run was not
counted as a pass. A new ephemeral allocation racing the rebind was possible,
but no competing owner was captured, so the cause was left open for the
[teardown review](../testing-startup.md#teardown-ownership-follow-up-10-november-2026)
in commit `a7630af`. A controlled case there shows that the original socket can
be closed while another socket holds the endpoint. Stress testing also exposed
a second reserve/drop/rebind gap in the launcher's contention control. The
tests now inspect the original Linux socket's ownership and keep the contention
endpoint held throughout. That fix changed test lifecycle only, not the
conformance inventory.

```sh
cargo test --locked --all-features --test sender_measurement_test --test tlv_extension_wire_test
```

## Measurement telemetry review

Fixed in commit `64465ea`. The review reproduced nonzero reserved fields in
valid Access Report and stateless Follow-Up replies with separately written
binary peers. Processable valid Access Reports now keep ID and Return Code and
zero the Resv nibble and Reserved tail. Valid Follow-Up replies zero their
Reserved bytes in both reflector modes. Invalid IDs, skipped values and
integrity-failure copies still keep their bytes unchanged.

Two more length failures were reproduced. Incomplete Timestamp Information
optional children were accepted, and a truncated Follow-Up that the parser had
marked could report previous state just because sixteen value bytes remained.
A shared Timestamp Information check, which does not allocate, now validates
the complete optional child framing in the typed decoder and in both roles'
length validation. Unknown complete children stay opaque. Follow-Up handling
now respects parser M and zeroes the available sequence and timestamp fields
when processing is allowed.

The expanded signed-list copy regression also found a send-path gap. Assembly
kept an opaque signed list unchanged, but the send-time telemetry refresh still
changed its usable prefix. Transmission now refreshes signed telemetry only
when the reflector generated the outer HMAC. Copied HMAC and value bytes stay
unchanged. Normal unsigned replies and generated signatures still get per-send
updates.

Direct evidence includes:

- `tests/sender_measurement_test.rs::sender_direct_measurement_counts_actual_probes_and_zeroes_peer_fields`
  captures three actual probes per family/key mode, checking S_TxC = 1, 2, 3,
  zero reflector counters, zero request metadata and original signatures.
  The all-type origination capture now checks exact Type 3/5/6/7 values.
- `tests/tlv_extension_wire_test.rs::timestamp_and_direct_measurement_fields_are_finalized_per_probe`
  checks observed receive/transmit counts, sentinel S_TxC kept as sent, declared
  software clock metadata, complete opaque Timestamp Information children and
  previous-reflection Follow-Up values over repeated actual requests.
- `tests/tlv_extension_wire_test.rs::access_reports_preserve_identity_and_code_but_zero_reserved_fields`
  checks valid IDs and invalid-ID U echoes, dirty reserved input and the exact
  Return Code in both families, three key profiles and both reflector modes.
  `telemetry_known_lengths_mark_m_and_stop_later_values` checks valid framing
  boundaries, M, later U, malformed Follow-Up zeroing and final signatures.
- `tests/tlv_extension_wire_test.rs::truncated_follow_up_cannot_report_previous_state_as_a_valid_timestamp`
  sets up real previous state before sending an unsigned truncated Follow-Up.
  It verifies parser M and zeroed available fields in both families. The guard
  for malformed signed lists has its own unchanged-value coverage, including
  Access Report, Follow-Up and Direct Measurement prefixes.
- Skipped and integrity-failed telemetry keeps all original values. Shared unit
  tests cover normalization and optional framing, including pnet builds. The
  stateless Follow-Up unit test used to leave sender U set and never populated
  the prior state it was meant to check. It now clears flags and confirms the
  state is nonzero before checking zeroing. The typed Follow-Up regression also
  checks that received Reserved bytes are ignored.

Twenty-one missing references are resolved. The invalid Follow-Up zeroing claim
(RFC8972-4.7-6) is now Partial: the guard for malformed signed lists can keep
an invalid Length-17 value unchanged even when a covered prefix verifies.
Promoting it needs a separate decision on whether copying or normalization
takes precedence. Evidence is Linux software-loopback and shared-parser
behavior, not physical synchronization, native-platform or pnet capture runtime
certification.

```sh
cargo test --locked --all-features --test sender_measurement_test --test tlv_extension_wire_test
```

## CoS/ECN wire review

Commit `06c4848` adds Linux packet and marking evidence for the
draft-02 profile. BPM -00 later replaced draft-02 with the same wire layout; see
[successor changes](draft-stamp-cos-ecn.md#bpm-00-successor-changes).

The new reflector test runs seven policy cases in both
families and open/keyed-open/authenticated modes: 42 profile combinations,
each with three burst replies and an interleaved ordinary reply, for 168
replies in all. It sets ingress IP TOS/Traffic Class separately from the CoS
value fields. It then checks observed DSCP2/EC2, actual reply markings,
global/scoped DSCP admission, ECN refusal on its own, RPD/RPE, Reserved bits
and final signatures on every copy. Distinct IPv4 endpoints exercise
destination-scoped policy. The ordinary reply keeps its own marking, with no
burst CoS leaking into it.

`tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy`
includes all ECN codepoints and a legacy CoS request with a zero Reserved field.
`tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`
covers 30 combinations. It checks the actual Type/Length/RPD/RPE/Reserved
origination and that the automatic congestion controller is present for CoS
ECT0/ECT1, plus a backoff on a correctly signed forward CE report.
Default/no-CoS and non-ECT CoS inputs are negative controls. This shows that
the response can be enabled and works. The Partial claims for controller
consistency, unsupported reverse metadata and capability diagnostics stay
Partial. Injected socket failures are not the same as actual Linux wire marking
and admission rejection.

Seven missing references gain tests. One more missing-reference row,
RFC8972-4.4-5, is now Partial: draft-02 allocates EC1/RPE inside four of the
original sixteen Reserved bits, and the selected profile can send nonzero
values there. The other twelve Reserved bits are zeroed. The draft is work in
progress and says it updates RFC 8972 only if approved, so the frozen RFC's
literal sixteen-bit rule is scored separately. This review changed no
encoding, runtime default, controller or other production behavior. After it,
no normative Compliant row in the RFC 8972 or CoS/ECN matrices lacked a test
reference. These are software-loopback and shared-sender checks, not
native-platform, hardware, downstream remarking or pnet capture runtime
certification.

```sh
cargo test --locked --all-features --test cos_ecn_wire_test --test sender_measurement_test
```

The [CI follow-up](../testing-startup.md#ci-follow-up-10-november-2026)
corrected native-platform test assumptions and an admission snapshot race
seen on `64465ea`. Commit `ef3f78d` passed Windows and Linux CI but exposed a
shared-fixture startup race in the native macOS jobs. The
[metadata startup follow-up](../testing-startup.md#macos-metadata-startup-follow-up-10-november-2026)
waits for socket setup before fixture traffic. Commit `ea4f037` passed both
native macOS profiles; only a Windows startup test failed, after selecting the
same released port twice. The
[port reuse follow-up](../testing-startup.md#windows-startup-test-port-reuse-follow-up-10-november-2026)
keeps peers bound and uses automatic sender ports. Commit `f9c8bb8` then
passed [CI (23/23 jobs)](https://github.com/asmie/stamp-suite/actions/runs/42808905339),
[conformance evidence](https://github.com/asmie/stamp-suite/actions/runs/42808905202)
and [CodeQL](https://github.com/asmie/stamp-suite/actions/runs/42808904888).
These repairs did not change the evidence inventory.

## Base packet review

Commit `ff1ebd7` covers the remaining RFC 8762 references.
`tests/base_protocol_wire_test.rs` uses raw offsets and its own HMAC coverage
selection instead of the application's packet builders and parsers:

- `sender_base_sequence_clock_layout_and_reserved_receipt` runs the public
  sender loop against a UDP peer that stays silent until it replies, in 16
  family/authentication/clock/strictness combinations. Each fresh session sends
  sequences 0, 1, 2. The peer checks the 44/112-byte layout, all transmitted
  reserved bytes, SSID zero, NTP/PTP timestamp recency and Z, dynamic
  source-port separation and authenticated bytes 96..112 over coverage 0..96.
  The peer replies with nonzero reserved bytes and valid signatures, and all
  three replies must be accepted. NTP is tested without a clock flag.
- `reflector_base_mbz_symmetry_clocks_and_stateless_sequences` starts the real
  nix reflector in 32 family/authentication/clock/strictness/state combinations.
  Ninety-six replies check stateless echo against stateful 0/1/2 sequences,
  copied sequence/T1/Error Estimate, real ingress TTL/Hop Limit 37, zeroed
  reply reserved bytes, T2/T3 format and ordering within the exchange window,
  final base signatures and symmetric sizes. Cases include bare bases,
  three nonzero opaque trailer bytes and 32 zero padding bytes. Authenticated
  requests carry nonzero MBZ signed over all 96 bytes. If a covered MBZ octet
  changes after signing, the request must get no response and no stateful
  sequence advance.

The public configuration-loading test
`src/configuration/tests.rs::base_protocol_default_ports_and_user_dynamic_ranges_reach_endpoints`
checks the default sender destination and reflector bind port 862 and NTP, and
CLI/TOML overrides at 1024, 49151, 49152 and 65535 through the actual endpoint
accessors. The wire cases exercise real bound dynamic peers. The port boundary
and default checks establish configuration and endpoint selection. They do not
show live binds on every registered port or default-port access on every host.

All 21 remaining RFC 8762 missing-reference rows now cite these tests. Nine
rows that already had references gain the more direct wire evidence for base
widths, MBZ origination/receipt, echoed fields, TTL and authenticated layout.
Statuses did not change. RFC 8762 has no normative Compliant row left without a
test reference. That is source presence plus the execution scope below, not
certification of every normative clause or configuration.

The sender test is portable and is part of the required Windows runtime job.
It also passes locally under the `ttl-pnet,metrics,control` feature set. Small
macOS and Windows target harnesses compile the same test source against the
real default libraries; these are compile checks, not native runtime evidence.

These are software-clock loopback checks with `--hwtstamp off` and SSID zero
for the base profile. RFC 8972's SSID occupies two original reserved bytes;
other SSID and extension profiles have their own evidence. PTP checks the
documented UTC software encoding, not TAI alignment. The bounds enclose
application receive and send timestamps; they do not establish NIC timestamp
accuracy or an exact hardware arrival instant. No pnet reflector capture,
privileged, hardware, BER or fuzz testing was part of this review, and no
application default or packet encoding changed.

## Return Path review

Commit `5481841` resolves the five remaining RFC 9503 test-reference gaps and
adds a previously missing inherited flag requirement as Partial.

`tests/return_path_wire_test.rs::sender_emits_one_return_path_with_unique_network_order_children`
runs the public sender against retained UDP peers in 42 combinations: both
families, unkeyed open/keyed open/authenticated modes, and seven Return Path
profiles (two Control Codes, address alone, each segment-list kind, and each
list combined with an address). Raw expected bytes check one outer Type 10,
unique child kinds, that Control Code is never combined with address or list
children, positive list lengths, two nontrivial MPLS label stack entries in
network order and two full SRv6 SID byte strings. Separate coverage checks
verify the base and extension signatures where present. The peer cancels the
run after it sees one packet, so these cases establish origination, not reply
consumption or successful SR forwarding.

`tests/return_path_wire_test.rs::reflector_first_return_path_owns_routing_even_when_unusable`
uses the real nix reflector in six family/key combinations. Twenty-four
replies verify that the first Return Path wins when a later TLV requests
suppression and the first one requests same-link, carries an empty SRv6/SR-MPLS
list, or has a malformed outer value. In the reversed case, first suppress then
same-link, there is no reply, and one live same-link request follows without a
retry. Thirty replies and six suppressions check the original sequence, copied
values, the first outer U/M result and final signatures. The equality
assertions on processed values leave out child flag bytes on purpose: their
correctness is the separate Partial finding below and should not be frozen as
intended behavior.

`src/tlv/list/processing/tests.rs::return_path_first_segment_owner_includes_empty_and_unsupported_lists`
tests empty-first and valid-first lists directly through route processing.
An empty first SRv6 list is unusable even when a valid list follows; an
unsupported first MPLS list cannot fall through to SRv6. A valid first SRv6
list keeps its action when an empty second list follows. This is shared-core
selection evidence, not an SRH forwarding test.
`src/configuration/tests.rs::empty_return_segment_lists_from_a_file_are_rejected`
now also checks actual TOML loading and empty CLI values before sender startup.

The original matrix left out the sub-TLV flag procedures that RFC 9503
Section 4.1 inherits. A separate Linux wire control saw a recognized, used
Control Code child keep U=1 while the successful parent had U=0, so the
control failed. The new `9503-4.1-flags` row is Partial. Known and unknown
child flags, framing, failed-integrity copying and Control Code ignore
precedence needed a repair before a broader claim; see the next section and
[the concrete request/reply](rfc9503.md#nested-flags). The RFC publication
month is also corrected to October 2023 from the source document.

This adds a missing requirement. It does not demote a working top-level
routing clause to hide the nested issue. RFC 9503 has no missing normative
Compliant test references, but that is separate from its Partial flag row.

The portable sender case is part of the required Windows runtime gate and
passes with that feature set locally. Small macOS and Windows target harnesses
compile the same test source with the real default libraries. Reflector wire
evidence is nix software loopback. It does not cover pnet capture, physical
interfaces or SR transit, and the SR-MPLS forwarding exclusion still applies.
Protocol and runtime behavior did not change in this review.

## Return Path child validation and flag repair

Fixed in commit `ea4d97b`. This change repairs the used-child U failure found
in the Return Path review and checks nested framing through the real reflector
and sender.

`src/tlv/list/processing/tests.rs::processed_return_path_children_rederive_flags_and_ignore_other_parameters`
failed before the repair: received `ff` headers stayed unchanged instead of
becoming `00` for the selected child and `80` for ignored ones. It now passes
through the shared processing entry point.
`src/tlv/typed/return_path.rs::tests::return_path_framing_and_selected_lengths_are_bounded`
checks complete framing, selected lengths and Control Code ignore precedence.
`src/tlv/list/processing/tests.rs::malformed_return_path_stops_later_values_before_early_child_mutation`
shows that a valid early child is not changed before a malformed later child
is found.
`src/tlv/list/processing/tests.rs::return_path_integrity_and_skipped_copies_keep_all_child_bytes`
checks failed-extension-integrity and already-skipped copies, including a
truncated container that the parser marked after an earlier malformed
extension.

`tests/return_path_wire_test.rs::reflector_normalizes_return_path_children_and_preserves_failure_values`
runs the nix reflector in 12 family/key/strictness combinations: IPv4/IPv6,
unkeyed open/keyed open/authenticated, permissive/strict. It checks 112 replies
and 12 suppressions: selected, ignored and unknown flags, reserved Control Code
bits, a valid early Control Code with later truncation, a partial child header,
a wrong selected address length, empty segment lists, and well-framed ignored
parameters. A later Access Report is processed after a valid Return Path and
copied after a malformed one. Separate byte and HMAC checks cover successful
replies. Failed extension signatures keep the values and the failed digest,
including a no-reply request that must be echoed instead. A fresh positive
reply follows each suppression. The origination and first-owner suites also
pass with the new malformed M/U behavior.

`tests/sender_measurement_test.rs::sender_validates_return_path_children_before_consuming_extension_values`
uses 56 separately built mock replies across IPv4/IPv6 and open/authenticated
modes. Direct Measurement appears before and after the Return Path to verify
that child M stops later values and child I blocks all extension values. It
also checks partial framing, wrong selected lengths, late child M, an
unrecognized parent whose child I is skipped, and a well-framed empty list
ignored under a Control Code. Base RTT stays usable on its own. These tests run
in all three Linux feature profiles and the Windows CI feature set.

The required `tests/netns_conformance.rs::scenario_3_srv6_return_path` passes
in private user/mount/network namespaces with no prerequisite skip. Its 24
captured open/authenticated replies cover a transit SID and a final SID, SRH
Segments Left 1 to 0, Hop Limit 255 to 254, CoS, separately computed HMACs and
isolation of ordinary replies. The test unpacks its capture packages into a
temporary directory and needs no system installation or host sysctl change.
This is Linux virtual-network evidence, not physical-interface or pnet capture
evidence.

A packet-processing ASan/libFuzzer run completed 100,000 executions from 48
Return Path seeds, with 965 new units, 330 MiB peak RSS and no crash. That
short run is a regression check, not exhaustive input coverage. Small macOS
and Windows harnesses compile the same test source with the real default
libraries; they do not replace native runtime or full platform dependency
builds.

The inherited child-flag row stays Partial: integrity-failed copies,
malformed signed outer lists and already-skipped copies keep child flags and
reserved value bits as received. The test-reference inventory did not change.

## Sender header-request evidence

Commit `c89936d` adds 16 sender references in the ext-hdr-26 matrix. It does
not change protocol behavior, selector syntax, platform support or any status.

`tests/header_request_wire_test.rs::sender_control_request_is_unique_zero_length_and_opt_in`
runs the public sender and a separately written peer in 18 combinations:
IPv4/IPv6, unkeyed open/keyed open/authenticated, and plain, control-only or
shaped control. Plain probes have no header or control requests. Control-only
probes carry one Type 12 with count 1, length 0, interval 0 and exactly one
zero-length control child (experimental Type 240). Configured count, length and
interval shaping is carried separately. Raw expected bytes also check
U/M/I/reserved flags and base/extension HMAC coverage computed by the test.
This portable case is in Windows' required runtime test list.

`tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`
checks 12 Linux combinations: both families, all three key modes, and zero or
nonzero Requested fields. Exactly one Type 247 has the family's 20/40-octet
length, its four-octet selector and a zero-filled Received tail. Whole-extension
equality rules out stray Type 246 and control TLVs. The test goes through
sender startup, route budgeting, packet building and signing, and actual UDP
transmission.

`tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`
runs 21 probes per Linux profile in private user/network namespaces and fails
if prerequisites are missing. The peer reads the actual Hop-by-Hop and
Destination Options ancillary headers and compares the STAMP bytes against its
own expected values. Seven attachment/request profiles in three key modes cover
automatic and configured full requests, different and same lengths, both
same-length subsets, a length-selected subset, mutable-option masking, and
fixed headers ordered before extension headers even when the CLI flags are
reversed. Headers, request counts and lengths, selector bytes, zero Received
tails and signatures are checked. Default, all-features and pnet runs pass
separately, 63 probes in total. This is sender origination evidence with kernel
receive metadata. It does not establish reflector matching, successful
reflected measurements or raw pnet capture. The namespace case is in the
required nix and pnet CI gates with an exact nonzero test count. It is an
ignored test that is run on its own, not counted as an ordinary-suite pass.

`src/configuration/tests.rs::revision26_sender_subset_rules_apply_to_cli_and_toml`
checks 14 profiles through both real CLI loading and TOML merge/validation:
wrong request count, length and order, ambiguous and unique subsets and
full-group wildcards. Selector arguments must contain a nonzero byte, so an
all-zero argument is rejected before matching. A bare length generates the
supported all-zero wire field. An early investigation took this syntax rule
for a matching defect. Source review and the existing rejection test show it
is intended, so production code did not change.

Small macOS and Windows harnesses cross-compile the same portable test source
with the real default libraries. The Windows CI feature set passes locally on
Linux. These checks do not establish native runtime or the full platform
dependency graph.

## Reflector header disclosure, matching and control

Commit `3574d6e` adds ten reflector and header-policy references. Production
behavior and status/profile limits did not change.

`tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`
runs 200 exchanges per Linux profile: five source/header policies, three key
modes and two strictness settings. Default deny, unmatched source, fixed-only,
extension-only and both-kind permission are crossed with absent, single or
duplicate reverse-header control and normal or reversed Type 247/246 order.
There are 180 normal replies and 20 failed-extension-integrity replies. Exact
expected bytes check policy refusal, successful capture, every control-child C
flag, parent flags, unchanged data on global order refusal, the echoed sender
sequence and base/extension HMACs computed by the test. Failed integrity keeps
the request values and the failed digest and exposes no captures. Reply
ancillary metadata contains no matching Hop-by-Hop or Destination Options
header, with or without control. This proves the fallback when the reflector
cannot attach headers, not bidirectional attachment.

Default and all-features runs exercise nix capture of an actual Destination
Options header; fixed headers are unavailable there and get C. The pnet-only
run injects complete IPv6/UDP wire checksums through a raw socket, because the
application rejects loopback's incomplete TX checksums by design. Its replies
verify actual fixed and extension capture, separate permissions for both
kinds and the same control behavior. All three namespace runs pass without
prerequisite skips, 600 replies in total. This is Linux software-loopback
evidence; it does not establish physical interfaces or nested tunnels. CI
requires exactly one ignored case per backend and rejects empty or gated
suites.

`tests/tlv_flag_semantics.rs::fixed_header_reflection_fills_requested_and_copies_received_in_capture_order`
checks supplied 20/40-octet fixed-header formats through `process_stamp_packet`:
filling zero Requested fields, consuming captures in order, unique selectors
that keep their wildcards, exact Received copying and exhaustion without data.
Together with
`tests/tlv_flag_semantics.rs::global_header_order_refusal_preserves_all_requests_before_copying`,
these add 36 raw request/reply cases per feature profile across three key modes
and both strictness settings, with separately computed signatures. The
ordering case uses marked Received tails to show that nothing is copied before
the refusal. Supplied capture records establish matching, not nested raw
extraction; the final reflected-header review below covers that. The full
60-test flag suite is in Windows' required driver-free runtime gate.

`src/receiver/ingest.rs::tests::header_reflection_policy_is_per_source_and_header_kind`
now passes captured data through real processing after building policy from
configuration and each received source. Six source mappings, including
IPv4-mapped canonicalization, check both policy decisions and the exact
allowed or refused fixed/extension response values. The shared ancillary
capture helper moved to `tests/common/ipv6_headers.rs`; the sender namespace
case passes again in all-features and pnet builds (42 probes).

The pnet probe first failed on `--local-port 0`: `run_receiver` reported the
configured zero port, bound family sockets separately and installed capture
filter port zero. That was an endpoint defect, not a header-policy failure,
and commit `8d7afaa` fixed it (next section). For this review the pnet
reflector bound port 19862 inside its fresh private namespace before the peer
bound, so there was no released-port reservation or host port contention.

No draft ambiguity, platform limitation or Partial row is promoted. The
namespace executions above are separate from the ignored-test counts of
ordinary runs. Small macOS and Windows harnesses cross-compile the same test
source with warnings denied using the real default libraries. They do not
establish native runtime or the full platform dependency graph.

## Pnet assigned-port endpoint repair

Fixed in commit `8d7afaa`. In the previous review, the first pnet attempt at
port zero exposed an endpoint defect: the family sockets received ports, but
readiness, capture filtering and received metadata kept the configured zero.
The new endpoint fixture fails before the repair for both configured families,
with a readiness report showing an unassigned port. All three cases pass after
the repair. No failed wire exchange is counted as a passing baseline.

`src/receiver/pnet.rs::bind_reply_sockets` binds the configured-family socket
first, reads its actual endpoint and binds the other family to that port when
it is available. The primary socket is required; an unavailable counterpart
does not block it. IPv6 reply sockets are IPv6-only, so IPv4 and IPv6 wildcard
owners can coexist. A configured-family bind failure now stops startup before
capture, including IPv6 failures that an optional IPv6 bind used to hide.
Explicit ports stay exact. An IPv6 primary no longer depends on an unrelated
IPv4 bind succeeding. The capture filter, received Location ports and
readiness use the selected port, and the send worker handles either
counterpart being unavailable.

`tests/pnet_endpoint_test.rs::pnet_assigned_ipv4_ports_reach_capture_metadata_and_both_reply_families`
and
`tests/pnet_endpoint_test.rs::pnet_assigned_ipv6_ports_reach_capture_metadata_and_both_reply_families`
exercise four concrete/wildcard binds, three key modes and assigned/explicit
ports. Raw IPv4/IPv6 probes with complete checksums check reply source ports,
the echoed sequence, Location destination/source ports and base/extension
HMACs. A second startup fails while the original reflector keeps its exact
endpoint; no released-port reservation or readiness probe is used. Separate
live owners of the counterpart family show the optional-family fallback
without changing the configured port. These tests require both reply families
when available inside their private namespace, including IPv6 wildcard binds.

`tests/pnet_endpoint_test.rs::pnet_ipv4_works_with_ipv6_disabled_and_ipv6_startup_fails`
checks IPv4 replies and early IPv6 bind failure after disabling IPv6 addresses
only inside the verified private namespace. A guard restores the sysctl. The
three endpoint cases run one at a time even under a parallel test runner,
require the recorded parent namespace to differ and reject missing
prerequisites. Together they produce 63 replies, 27 expected startup
failures and 39 graceful SIGTERM shutdowns, each limited to four seconds. CI
requires all three ignored cases with the actual pnet backend, so a zero-test
or gated suite cannot pass.

`src/receiver/pnet.rs::tests::reply_socket_binding_retains_primary_endpoint_and_one_port`
checks real unprivileged socket binding for all four concrete/wildcard profiles,
available family ports, IPv6-only operation and conflicts with the primary
endpoint. `tests/startup_failure_test.rs::reflector_reports_bind_failure` now
checks both families through receiver startup before capture discovery. These
run without capture privileges and are part of the native Windows unit and
startup gates.

The 200-exchange pnet header-policy test now uses its advertised assigned
port, so the fixed-port workaround is gone. All three earlier raw loopback
tests pass, including bad-checksum rejection. The scoped link-local IPv6
fixture first failed on incomplete TX checksums. It now disables offload on its
own private veth ends and passes open/authenticated bursts, alternate-address
signatures and sender zones. Application checksum validation did not change.

Small macOS and Windows harnesses cross-compile the same pnet library and
startup test source with warnings denied. They do not establish native capture
or runtime, or the full platform dependency graph. This is Linux software
capture evidence, not physical NIC or driver evidence. Statuses and the
test-reference inventory did not change.

## Final reflected-header reference review

Commit `8d388e5` reviews the last four header rows through real packet paths
and narrows two unconditional claims. Production behavior did not change.
After this review every applicable row had a test reference and strict
checking passed. Complete references are not whole-matrix certification or
execution evidence for every platform.

`tests/pnet_nested_headers_test.rs::actual_nested_capture_reflects_outer_to_inner_and_rejects_bad_checksums_and_depth`
injects envelopes with complete checksums into the actual Linux pnet capture
path. Six IPv4/IPv6 two- and three-layer chains are crossed with unkeyed
open/keyed open/authenticated modes and both parsing strictness settings.
Thirty-six main replies and six fresh follow-ups verify exact outer-to-inner
Type 247 values, separately computed base/extension HMACs, innermost reply
endpoints and received hop count 37. Outer addresses and hop counts differ, so
using the outer session metadata would fail the check. Thirty-six bad inner UDP
checksums and six 32-layer envelopes get no reply; valid follow-ups show that
the receiver is still live. The run passes 42 replies and 42 negative probes
with no prerequisite skip. CI requires the single ignored case on the actual
pnet backend. This is software-loopback capture, not a claim about a physical
tunnel, NIC or Windows capture driver.

`tests/ext_hdr_revision13_test.rs::sender_hops_and_held_local_endpoint_separation_cover_both_families_and_keys`
checks actual sender UDP metadata across both families and three key modes.
Six binds to a local reflector endpoint that is held open fail without sending.
Then six automatic binds send with hops 255 and distinct peer and local ports.
The held UDP owner establishes same-endpoint exclusion. It does not model an
inventory of reflector ports on different addresses. Authenticated sender
base bytes are checked separately.
`tests/ext_hdr_revision13_test.rs::reflector_transmits_255_and_accepts_lower_received_hops`
now waits for readiness without a released-port handoff or startup traffic.
Six nix cases reflect requests that arrive with hops 37 and send with hops 255,
including separately checked authenticated base signatures. The pnet endpoint
suite now reads actual ancillary hop metadata on all 63 replies.
`tests/common/hops.rs` shares that receive check across the tests. The pnet
endpoint cases pass separately; the nix and sender cases pass in default and
all-features builds, and the sender cases also pass in pnet builds.

A separate live control runs a pnet reflector on `127.0.0.1:56620` while the
public sender sends from `127.0.0.2:56620` to a retained peer on another port.
The peer sees the same numeric port and the reflector keeps running. So the
same-endpoint argument did not cover the whole local-role-port requirement.
The row stays MUST NOT but becomes Partial: operators must provision
separate numeric role ports across addresses. This is a failed conformance
control, not a passing test that freezes the limit. Its observed values and
scope are recorded here and in the matrix.

`src/configuration/tests.rs::receive_policing_defaults_and_provisioned_cli_toml_values_reach_runtime`
checks default unlimited policing with 1,024 immediate accepts per address
family, real TOML loading, CLI precedence and the resulting runtime rate and
burst values. This verifies the reflector's configuration path. It cannot show
that deployed limits accommodate aggregate offered traffic, other sessions,
bursts and changing capacity, so that MUST NOT row also becomes Partial.
Operator provisioning and resource-protection drops remain documented. There
is no aggregate-capacity validator or local role-port inventory. Either could
be a future provisioning feature, but it would need session and capacity input
from the operator rather than guarantees inferred from the default limiter.

Both normative levels stay as they were. Two rows gain executed evidence and
two overbroad claims are narrowed. Profile, hardware, native-platform and
draft-ambiguity limits still apply. The new configuration test passes locally
on Linux under the Windows CI features. Small macOS and Windows harnesses
cross-check the pnet library and the relevant startup and hop test source with
warnings denied. This does not establish native runtime or the full platform
dependency graph.

## Required CI test-reference guard

Commit `cce43a9` makes the conformance workflow pass
`--require-test-evidence --json --details` to the citation checker. A missing
normative Compliant test reference now fails the evidence job, alongside stale
citations. The detailed `citations.json` artifact is still produced when a
reference is missing, because the upload step keeps its `if: always()`
condition. Calls without the strict flag still only report. Checker defaults
and Rust and protocol behavior did not change.

The configured CI command passed on the tree with 318 applicable, 318
referenced and zero missing rows. On a temporary copy of the source and
matrices, the
ext-hdr-6.2-5 test citation was then replaced with only the (valid) production
implementation. Strict mode returned exit 1, with 317 referenced, one
missing and exactly one `missing-test-evidence` diagnostic for that clause.
The failure output was valid detailed JSON with `required: true` and
`execution_checked: false`. The same copy without the strict flag returned
exit 0 and reported the same missing reference. Restoring the row returned
strict mode to exit 0 and 318/318 references. The repository matrix and
status counts were not touched.

This guard checks source references. It does not certify execution or
semantics. Ignored and platform-gated declarations still need the runtime
evidence described in this policy. Broader review of rows that already had
references, and native, hardware and deployment-profile reviews, are separate
work.
