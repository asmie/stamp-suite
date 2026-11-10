# Conformance test references

Source validity, test-reference presence and verified behavior are different
checks. This policy adds the second without treating it as the third.

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
  An unqualified name is accepted only if it identifies one test without a
  conflicting helper name.
- A dedicated test file containing annotated tests, such as
  `tests/session_identity_test.rs`, or an explicitly declared test module such
  as `src/tlv/list/mod.rs::tests`. File/child-module lookup follows the existing
  citation checker's source convention, not compiler name resolution. A broad
  suite reference needs manual review of the relevant assertions; named cases
  are preferable.
- A Python unittest method or suite that contains actual TestCase methods,
  such as `scripts/tests/test_interop_ber.py::BerOracleChecks::test_hmac_rfc4231_and_bit_reference`.
  Tests of an oracle alone do not establish application conformance.
- An explicitly identified wire-driver function. For example, Wire tests:
  `scripts/interop_ber.py::reflector_case`, `scripts/interop_ber.py::sender_case`.
  Each function must exist. Review must establish that the driver invokes the
  application and validates the relevant bytes/behavior. Identify the scenario
  or vector in the surrounding evidence.

Comments, string literals, helper names containing "test", ordinary production
files and fixture data alone do not qualify. For example,
`src/receiver/transmit.rs::fit_reply` identifies implementation, not a test of
its caller. Explicitly qualified Python references are also checked for stale
files/functions, including outside normative Compliant rows.

The scanner supports the repository's built-in/Tokio/property-test and unittest
conventions; it is not a general Rust macro expander or Python test runner.
Unrecognized or ambiguous references need a clearer citation or reviewer work,
not a claim that the behavior is necessarily untested.

## Semantic and execution review

Before approving a row, trace the trigger through the claimed production path
to the assertion. Check role, authentication mode, IP family, backend and
failure/fallback conditions. A codec test can establish field encoding without
establishing dispatch. A mocked transport can establish finalization logic but
does not prove OS routing or physical behavior. Shared implementation is not
runtime evidence for every backend.

Test presence is not a pass. Ignored tests, platform/feature-gated declarations
and source-only wire drivers require execution evidence for the claimed profile.
The JSON report sets `execution_checked` to false and identifies directly ignored
Rust tests/suite counts. Counts describe source declarations, not runnable cases
in a particular build. It does not infer execution from Cargo builds, prior runs
or the existence of fixtures. A few representative assertions also do not
certify every statement in a broad requirement.

When evidence is insufficient, add a regression through the correct entry
point, narrow the profile with an explanation, or lower the status. Do not
rename a helper, add a generic suite or change the normative Level simply to
clear the inventory. Links to shared notes do not replace a direct test
reference on the row.

## Inventory and rollout

```sh
python3 scripts/check_conformance_citations.py --json --details > citations.json
python3 scripts/check_conformance_citations.py --require-test-evidence --json > strict-citations.json
```

The first command keeps stale citation failures and adds `test_evidence` with
the policy version, applicable clause counts, missing rows and, with `--details`,
all clause/reference records. Counts distinguish rows with a test reference
from rows missing one; they are not coverage percentages. Existing citation
counts describe Rust source references; qualified Python test references are
recorded under the test inventory, and invalid ones also fail source checking.

Missing test references are advisory by default. `--require-test-evidence`
returns nonzero and adds `missing-test-evidence` problems while any remain.
The existing CI citation step retains this inventory in its `citations.json`
artifact. Whole-backlog enforcement will be enabled only after review and
resolution; an advisory success is not a claim that all rows are tested.

The initial source inventory on 9 November 2026 (parent `d6a4f8a`) found
325 applicable rows: 159 with explicit test references and 166 missing them.
This first review resolves 40 missing references and lowers three existing
Both-role MTU claims to Partial. The resulting inventory is **322 applicable,
196 with references, 126 missing**. The rollup is **471 clauses: 390 Compliant,
28 Partial, two Gap, 48 N-A and three Excluded**. These are review snapshots;
rerun the checker after edits rather than treating the numbers as certification.

## First reviewed batch

| Area | Evidence and what it establishes | Limits / remaining work |
|---|---|---|
| 39 normative Compliant BER rows | Explicit role-specific wire drivers now appear on every applicable BER row. Seventeen reflector vectors and sender baseline/gating/U scenarios check counters, flags, repaired padding, unknown/malformed children, configuration and directional statistics. | Linux nix software-loopback profile using agreed experimental types; no zero-checksum, physical-link or maintained-peer certification. Existing Partial/Gap rows remain. |
| RFC 8972 HMAC rows 4.8-1, 6, 7, 8, 11, 13, 14 | A new production Rust signer/verifier known-answer test uses RFC 4231 case 1, truncated to 128 bits. Independent wire roles check actual HMAC type/length/coverage; a malformed-length parser test checks M. Failed extension-HMAC echoes preserve all copied values and the failed digest with I. | Primitive/equivalence tests supplement the wire driver; they do not replace send-path checks. The copied failure digest is not regenerated into a successful one. |
| RFC 8972 admission rows 3-6 to 3-8 | Named IPv4 open/authenticated and IPv6 identity tests run the nix receiver with exact provisioned endpoints, SSIDs and micro IDs. Authentication tests verify invalid bases cannot allocate or refresh state. | Provisioned profile only. Shared-core tests are distinct from pnet capture runtime or physical ingress validation. |
| Reflected-header MTU rows 7.2-1, 3, 5 | The single-reply tests invoke actual transmission finalization, checking trimming, final signatures, unavailable budgets and EMSGSIZE refresh. The required namespace tests now also exercise sender route budgets, trimming/restoration and refusal. | Initially downgraded in T22a; restored after the T22b1 sender regression and fixes described below. Linux kernel-route evidence, not end-to-end PMTU discovery. |
| Type 12 C signaling | Packet-processing and independent wire tests now exercise exact/fractional rate ceilings, volume, count-zero suppression, sender C clearing, incoming C ignoring and protected admission. | Exact timing and conservative first-request selection are Partial. Identity protection is qualified by the authenticated protected profile. See T22b3 below. |

After the reviews below, 56 missing references remain across three
matrices. Prioritize the remaining authentication, C-flag and admission claims,
then work through the rest. The full test-evidence goal and strict CI gate
remain unfinished.

## Sender MTU dispatch review (T22b1)

The review against parent `a70328d` found that an unreadable route budget kept
the previous request set, oversized mandatory packets reached the kernel's
send/retry path, and startup trimming could choose a base-only send mode that
never restored header requests. Per-probe AIMD control and diagnostic trailers
also needed a reserve before optional-header trimming.

The sender now refuses an unknown budget and checks the actual built packet,
including IP/UDP and attached IPv6 header bytes, against the current route MTU
before sending. Trimming reserves all possible per-probe fields. The TLV send
mode survives an initially empty request set, allowing requests to return after
MTU growth. Changes apply to header-reflection probes; other packet-size
policies keep their existing scope.

`tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes`
runs the public sender loop with independent received-byte/HMAC assertions.
Eight IPv4/IPv6 and key-mode combinations exercise 1280 → 1500 → partial-header
budget → 1280 → 1500, mandatory non-header preservation, dynamic Direct
Measurement/Type 12 fields, ordered removal/restoration and final signatures.
The modes are open, keyed open with TLV-HMAC origination on or off, and
authenticated. IPv6 attaches the default eight-byte Hop-by-Hop header; this
test does not establish exact-boundary delivery for every Destination Options
layout. Four additional IPv4 cases check restoration after startup removed
every request. Each of the eight combinations also checks a mandatory packet
one octet too large, both at startup and after a successful send and MTU drop.
An observer changes only the isolated namespace's loopback MTU after each
successful send, before the next, avoiding timer-dependent ordering.

`src/sender/run/mtu_tests.rs::missing_route_budget_refuses_send_without_mutating_pending_state`
disconnects real IPv4/IPv6 open/authenticated UDP sockets, making the kernel
route lookup fail. It verifies a configuration error before the send/retry path,
without pending-state changes or a received probe. The shared sender regression
is distinct from reflector backend capture evidence.

Both required namespace tests pass with no skip: the existing eight reflector
combinations and the sender cases above. The three MTU rows return to Compliant
within their Linux sender scope. The inventory is now **325 applicable, 199
with references, 126 missing**; the rollup is **471 clauses: 393 Compliant,
25 Partial, two Gap, 48 N-A and three Excluded**. No missing-reference row was
cleared merely by restoring these three reviewed claims. CI now requires two
ignored tests in the MTU artifact, while whole-backlog strict checking remains
advisory.

Local T22b1 verification passes full default/all-features/pnet Rust suites
(1,330/1,431/1,279 tests; 13 privileged tests ignored in each ordinary run).
Both required MTU tests were executed separately and passed without a skip.
The final all-features BER wire run passes 60/60 cases. Clippy passes all three
profiles; all 104 Python tests, rustfmt, 1,047 source citations, matrix counts
and 431 documentation links pass. The shared failed-budget regression runs in
each Rust profile; pnet-feature success here is shared sender evidence, not
pnet reflector capture evidence. Logs and reports are under `/tmp/t22b-*`;
no remote CI or physical/native-platform result is claimed.

## Sender echoed-identity review (T22b2)

Review against parent `a825b6b` found that a correctly signed delayed reply
could consume a newer pending probe with the same sequence, because echoed T1
was not checked. A regression reproduced this through actual sends and the
sender's receive path before the fix. Another regression reproduced the
session-state monitor expiring a newer probe at the retired sequence's old
deadline.

The sender now matches the full echoed sequence and all eight original wire
T1 bytes before deduplication, SSID policy, measurement acceptance and semantic
control/ID updates. Unknown/mismatched replies leave pending state intact.
`measurements.mismatched_replies` reports a known sequence with a missing or
different echo; `unknown_replies` retains the no-history distinction. TLV
diagnostic evaluations precede this check and can still count rejected input.
Reply identities now include wire T1, allowing a legitimate newer generation
when the peer reuses its own sequence/T3. Kernel corrections keep wire identity
immutable and require the original local send context. The failure monitor
replaces the retired sequence's deadline when a new generation is sent.

Direct production-path evidence:

- `src/sender/run/admission_tests.rs::reused_sequence_rejects_old_signed_echo_before_measurement_or_control_state`
  forces sequence reuse across real probes in both families, NTP/PTP,
  authenticated/keyed-open modes and bounded/unlimited retention. A signed
  old echo cannot consume pending state, learn an ID, acknowledge Access Report,
  apply CE or change delay/DM/session-state samples. A correct echo succeeds;
  a later legitimate generation with the same reflector sequence/T3 also succeeds.
- `tests/sender_measurement_test.rs::sender_matches_every_echoed_timestamp_octet_before_consuming_a_probe`
  uses a separately encoded peer against the binary in 16 family/auth/parser/clock
  combinations. It changes each echoed T1 octet and sends an unknown sequence
  with zero SSID before the valid reply, proving these cannot trigger SSID stop
  policy or complete the probe.
- `src/sender/run/admission_tests.rs::retained_late_and_additional_copies_require_the_original_echo`
  checks valid late copies, duplicates and additional replies after expiry.
  `src/sender/run/admission_tests.rs::short_replies_need_full_echo_but_may_omit_trailing_fields`
  rejects missing/partial identity while accepting complete echoes in 36- and
  41-byte unauthenticated replies. Reflector short-request handling is unchanged.
- `src/sender/tests.rs::delayed_tx_reports_do_not_correct_a_reused_sequence`
  rejects older send metadata, including tied monotonic times with different
  wire T1. Existing mixed-clock tests now exercise both original and corrected
  OWD T1 while echoing the original wire value through all four parsers.
- `src/sender/session_state.rs::tests::reused_sequence_replaces_the_old_deadline_and_clears_on_current_reply`
  checks the current deadline, successful cleanup and exactly one genuine
  timeout after reuse.

The fuzz adapter seeds matching echo context so existing fuzz targets can still
reach measurement/control logic; the separate regressions test stale identity.
These checks do not establish physical TX timestamp behavior or cryptographic
replay protection. Repeated sequence/T1 pairs cannot themselves prove freshness.
Required micro-session late-reply restrictions retain their existing policy.
See [sender identity and compatibility](rfc8762.md#sender-reply-identity).

Three previously missing RFC 8762 references are resolved: eight-byte timestamp
encoding (4.2.1-2), HMAC algorithm/truncation (4.4-1) and 96-byte base coverage
(4.4-2). The latter two cite the independent BER wire drivers for both application
roles, supplemented by the production known-answer test. No clause status is
raised: the rollup remains **471 clauses: 393 Compliant, 25 Partial, two Gap,
48 N-A and three Excluded**. The inventory is **325 applicable, 202 with
references, 123 missing**. Strict CI enforcement remains pending.

Final local checks pass full default/all-features/pnet suites with
**1,335/1,437/1,284** passed tests, respectively (13 privileged ignored in each
ordinary run). The two required MTU tests ran separately without a skip, and
the final all-features BER wire run passes all 60 cases. All three Clippy
profiles, the fuzz manifest build check, all 104 Python tests, rustfmt, matrix
counts and source/link checks pass. This is a fuzz build check, not a new fuzz
campaign. Reproduction includes:

```sh
cargo test --locked --all-features --lib sender::
cargo test --locked --all-features --test sender_measurement_test --test pending_probe_limit_test
cargo check --locked --manifest-path fuzz/Cargo.toml
```

The BER/MTU commands below also apply to the final all-features binary. Strict
test-evidence checking fails only on the expected 123 remaining missing rows;
the default/CI report remains advisory. Logs/reports are under `/tmp/t22b2-*`.
No remote CI, new native-platform or physical timestamp pass is claimed.

## Type 12 policy and admission review (T22b3)

Review against parent `a40f264` reproduced two defects through production
packet processing: the integer rate quotient admitted fractional excess, and a
later matching Address Group could overwrite an earlier mismatch. Rate
admission now compares wide integer products, including the maximum u64 rate
ceiling without overflow. L2/L3 group decisions retain every valid mismatch.

`tests/tlv_flag_semantics.rs::reflected_control_rate_boundary_does_not_round_down_excess_traffic`
checks just below, exactly at and just above a 5,000 B/s ceiling in open,
keyed-open and authenticated packet processing. At 500 bytes, 100,000,000 ns
is admitted while 99,999,999 ns receives C and no extra copy. The regression
failed before the change. The maximum-u64 cases check wide multiplication.
`tests/tlv_flag_semantics.rs::repeated_address_groups_cannot_overwrite_an_earlier_mismatch`
also failed before the fix and now checks L2/L3 mismatches in both orders and
all-matching groups. Malformed L3 lengths and continuation to later valid
groups are covered by
`tests/tlv_flag_semantics.rs::reflected_control_malformed_l3_lengths_do_not_filter_or_hide_later_groups`.

Four independent UDP tests run the actual Linux nix sender/reflector binaries:

- `tests/type12_policy_test.rs::exact_rate_volume_and_zero_count_decisions_reach_the_wire`
  covers both families and open/keyed-open/authenticated modes. It checks C
  clearing/setting, received-C ignoring, exact rate/volume admission, fractional
  rate/volume rejection as one correctly sized signed reply, count-zero
  suppression and a bound node-local reply source.
- `tests/type12_policy_test.rs::every_l3_group_must_match_before_wire_reflection`
  checks repeated IPv4/IPv6 groups in both orders, with valid HMACs when keyed.
  All-matching groups reply; either mismatch order emits no datagram.
- `tests/type12_policy_test.rs::protected_type12_profile_rejects_unverified_amplification`
  checks authenticated mode plus extension-HMAC verification: invalid base HMAC
  drops, missing/bad extension HMAC produces one I failure echo without burst
  shaping, and a valid request produces its admitted burst. It also confirms
  that an optional-HMAC open profile still accepts a missing HMAC.
- `tests/type12_policy_test.rs::sender_control_defaults_and_static_or_scaled_requests_clear_c`
  captures real requests in both families/authentication modes, including the
  AIMD-scaled path. Sender C stays clear; defaults omit Type 12, and an explicit
  burst starts immediately with its configured count/interval.

Five missing references are resolved. Exact nanosecond wire timing
(asym-3-11) and conservative selection of an explicit first request
(asym-5-05) are now Partial: software pacing/default omission do not establish
those general claims. Identity protection (asym-5-01) is Compliant only for
the tested authenticated protected profile; enabling optional verification
with a key in open mode alone does not require signed requests. The Type 12
matrix is **47 clauses: 36 Compliant, three Partial, seven N-A, one Excluded**.
The full rollup is **471 clauses: 391 Compliant, 27 Partial, two Gap, 48 N-A,
three Excluded**. The inventory is **323 applicable, 207 with references,
116 missing**; no normative Compliant Type 12 row remains without a reference.

These results are software-loopback/packet-processing evidence, not exact wire
timing, a multicast topology, native-platform or pnet capture certification.
The conservative-first-request and timing work remain explicit follow-ups;
the strict whole-backlog CI gate is still pending.

Final local verification passes full default/all-features/pnet suites with
**1,342/1,444/1,287** tests, respectively (13 privileged ignored in each
ordinary run). The new wire target contains four passing tests; pnet builds
exercise the shared packet-processing regressions without claiming capture
runtime. Both required MTU tests pass separately without a skip, and all 60
BER wire cases pass against the final all-features binary. All three Clippy
profiles, the fuzz manifest build check, 104 Python tests, rustfmt, matrix
counts, 1,083 source citations and 438 documentation links pass. Opt-in strict
checking fails only on the expected 116 missing-reference rows. Temporary
logs/reports use `/tmp/t22b3-*`; no remote CI or new fuzz campaign is claimed.

```sh
cargo test --locked --all-features --test tlv_flag_semantics --test type12_policy_test
```

## Core extension review (T22b4)

Review against parent `8052e40` reproduced two sender defects through independent
binary peers. A reply with extensions after a base-only probe bypassed TLV
validation. An unused known type with an invalid length but no peer M flag
could leave later measurement values usable. The sender now detects extensions
from received length and derives malformed markers for every retained known
outer type before semantic consumption. Authentication still verifies original
wire bytes; base RTT acceptance remains independent of unusable extension data.

`tests/sender_measurement_test.rs::base_only_sender_validates_returned_extensions`
checks actual 44/112-byte requests followed by extended replies in both IP
families and authentication modes.
`tests/sender_measurement_test.rs::sender_validates_unused_tlv_lengths_before_later_measurements`
checks invalid-length CoS without wire M and valid-length CoS with wire M,
before Direct Measurement, after base-only and extended requests. It verifies
that later values are ignored while signed original bytes still authenticate.
Both regressions failed before the fix.
`tests/sender_measurement_test.rs::sender_origins_rfc8972_tlvs_with_u_set_and_m_i_clear`
captures all eight RFC 8972 outer types, U/M/I flags, big-endian multi-byte
lengths/counters and signatures in open, keyed-open and authenticated modes.

The three tests in `tests/tlv_extension_wire_test.rs` exercise real reflectors
in both families and all three key profiles. They check ordered padding and
unknown opaque values, ignored incoming flag bits, copied values after the
first malformed known TLV, and integrity-failure value/digest preservation.
Independent HMAC calculations check the resulting original/final wire bytes.
Opaque unknown data contains a count-zero Type 12 request that must not execute.
These semantic malformed-length cases retain complete frames; they do not
change the existing opaque-trailer compatibility policy. Prefix processing
before the first malformed TLV is permitted and now described accurately.

Fourteen previously missing RFC 8972 references are resolved; that matrix has
43 remaining. The inventory is **323 applicable, 221 with references,
102 missing**. Clause statuses are unchanged: **471 clauses: 391 Compliant,
27 Partial, two Gap, 48 N-A and three Excluded**. Nested Location and other
field-specific evidence reviews remain pending, as does strict CI enforcement.
These are Linux nix software-loopback and shared-parser checks. The pnet frame
decoder regression ran separately as a unit test; no pnet capture runtime,
physical clock or native-platform conformance is inferred.

Final local verification passes full default/all-features/pnet suites with
**1,348/1,450/1,290** tests, respectively (13 privileged ignored in each
ordinary run). The targeted wire suites pass all eight sender and three
reflector tests. Both required MTU tests pass separately without a skip, and
the final all-features BER wire run passes all 60 cases. All three Clippy
profiles, the fuzz manifest build check, 104 Python tests, root/fuzz rustfmt,
matrix counts, 1,117 source citations and 438 documentation links pass. Opt-in
strict checking fails only on the expected 102 missing-reference rows. Logs
and reports use `/tmp/t22b4-*`; no remote CI or new fuzz campaign is claimed.

```sh
cargo test --locked --all-features --test sender_measurement_test --test tlv_extension_wire_test
```

## Location nested validation review (T22b5)

Review against parent `d804d3b` reproduced independent sender and reflector
failures: incomplete Location child headers were silently ignored, and invalid
nested lengths did not prevent later outer values from being used. A received
child M with valid length also needed to stop the sender's outer processing.
The allocation-free nested validator now checks the port prefix, child frames
and known-type lengths before semantic processing. It marks the whole Location
M, stopping later values. After successful integrity verification, an
identifiable malformed child's header also receives M when the whole list
permits processing. Failed-integrity and structurally malformed signed echoes
preserve original nested bytes; signatures verify the original input and are
regenerated over the final outgoing bytes when appropriate.

`tests/sender_measurement_test.rs::sender_stops_at_malformed_location_children_but_ignores_child_i`
checks incomplete headers, known wrong lengths, explicit child M and ignored
child I in both families/authentication modes. The existing origination capture
now asserts the exact zeroed Location value and nested U/M/I headers.
`tests/tlv_extension_wire_test.rs::location_requests_preserve_lengths_and_report_observed_endpoints`
checks real stateful all/none disclosure policies, observed ports and addresses,
unknown/specific child echoes, I ignoring, MBZ zeroing and the nix missing-MAC
fallback in both families and three key profiles. IPv4 uses distinct endpoints;
IPv6 loopback is supplemented by distinct-address unit fixtures.
`tests/tlv_extension_wire_test.rs::malformed_location_children_stop_later_outer_tlvs_on_the_wire`
checks all nine known child length errors, short outer values, partial child
headers and truncated bodies, outer/child M, later outer U and final signatures.
The integrity-failure wire test now includes a malformed child with incoming I,
checking that even those bytes survive unchanged. Both new failure regressions
failed before the production fix.
`tests/tlv_extension_wire_test.rs::malformed_signed_list_keeps_nested_location_bytes_and_original_digest`
also reproduced a marker-edit regression during review and now checks the
unchanged-value guard for a malformed signed list whose covered prefix verifies.
The combined wire targets contain 15 tests.

Sixteen missing Location references are resolved with tests. One additional
row, RFC8972-4.2.1-3, becomes Partial: copied malformed/skipped/integrity-failure
values can retain child I despite clearing it in originated and processed
children. A flag/copy-rule precedence decision remains explicit follow-up;
see [Location nested validation](rfc8972.md#location-nested-validation).
The RFC 8972 matrix is **151 clauses: 143 Compliant, one Partial, seven N-A**,
with 26 missing references left. The full rollup is **471 clauses: 390
Compliant, 28 Partial, two Gap, 48 N-A and three Excluded**. The inventory is
**322 applicable, 237 with references, 85 missing**. Strict CI stays advisory.
These checks establish Linux software-loopback/shared-parser behavior, not
physical addressing, NAT traversal or native/pnet capture runtime conformance.

The first full all-features run failed once at the launcher's
`retained_socket_excludes_other_binders_and_is_released_on_teardown` assertion,
with AddrInUse (OS 98) on immediate rebind. A full rerun passed, and 50 isolated
IPv4/IPv6 rounds of that test also passed. A new ephemeral allocation racing
the rebind was possible, but no competing owner was captured; that left the
cause unconfirmed and prompted the separate T6b investigation below. The failed
run is retained as `/tmp/t22b5-all-features.log`; it is not counted as a pass.

Final local verification passes full default/all-features/pnet suites with
**1,352/1,454/1,291** tests, respectively (13 privileged ignored in each
ordinary run). All 15 sender/reflector wire tests pass in the nix profiles;
the pnet profile runs the shared sender path. Both required MTU tests pass
separately without a skip, and all 60 independent BER cases pass against the
final guarded all-features binary. All three Clippy profiles, the fuzz manifest
build check, 104 Python tests, root/fuzz rustfmt, matrix counts, 1,144 source
citations and 441 documentation links pass. Opt-in strict checking fails only
on the expected 85 missing-reference rows; CI stays advisory. Reports/logs use
`/tmp/t22b5-*`; no remote CI or new fuzz campaign is claimed.

```sh
cargo test --locked --all-features --test sender_measurement_test --test tlv_extension_wire_test
```

The later [T6b teardown review](../testing-startup.md#teardown-ownership-follow-up-10-november-2026)
addresses the launcher failure recorded under T22b5. A controlled case proves
that the original socket can be closed while another socket holds the endpoint;
stress testing also exposed a second reserve/drop/rebind gap in the launcher's
contention control. The tests now inspect original Linux socket ownership and
keep the contention endpoint held throughout. This changes test lifecycle
evidence, not the normative inventory or the historical T22b5 run record.

## Measurement telemetry review (T22b6)

Review against parent `a7630af` reproduced nonzero reserved fields in valid
Access Report and stateless Follow-Up replies through independent binary
peers. Processable valid Access Reports now preserve ID/Return Code while
zeroing the Resv nibble and Reserved tail. Valid Follow-Up replies zero their
Reserved bytes in both reflector modes. Invalid IDs, skipped values and
integrity-failure copies retain their existing byte-preservation policy.

Two additional length failures were reproduced: incomplete Timestamp Information
optional children were accepted, and a parser-marked truncated Follow-Up could
report previous state merely because sixteen value bytes remained. A shared,
allocation-free Timestamp Information check now validates the complete optional
child framing in the typed decoder and both roles' length validation. Unknown
complete children remain opaque. Follow-Up handling now respects parser M,
zeroing available sequence/timestamp fields when processing is allowed.

The expanded signed-list copy regression also found a send-path gap: assembly
preserved an opaque signed list, but send-time telemetry refresh still changed
its usable prefix. Transmission now refreshes signed telemetry only when the
reflector generated the outer HMAC. Copied HMAC/value bytes remain unchanged;
normal unsigned replies and generated signatures retain per-send updates.

Direct evidence includes:

- `tests/sender_measurement_test.rs::sender_direct_measurement_counts_actual_probes_and_zeroes_peer_fields`
  captures three actual probes per family/key mode, checking S_TxC = 1, 2, 3,
  zero reflector counters, zero request metadata and original signatures.
  The existing all-type origination capture now checks exact Type 3/5/6/7 values.
- `tests/tlv_extension_wire_test.rs::timestamp_and_direct_measurement_fields_are_finalized_per_probe`
  checks observed receive/transmit counts, sentinel S_TxC preservation, declared
  software clock metadata, complete opaque Timestamp Information children and
  previous-reflection Follow-Up values over repeated actual requests.
- `tests/tlv_extension_wire_test.rs::access_reports_preserve_identity_and_code_but_zero_reserved_fields`
  checks both valid IDs and invalid-ID U echoes, dirty reserved input and exact
  preserved Return Code in both families, three key profiles and both reflector
  modes. `telemetry_known_lengths_mark_m_and_stop_later_values` checks valid
  framing boundaries, M, later U, malformed Follow-Up zeroing and final signatures.
- `tests/tlv_extension_wire_test.rs::truncated_follow_up_cannot_report_previous_state_as_a_valid_timestamp`
  establishes real previous state before sending an unsigned truncated Follow-Up.
  It verifies parser M and zero available fields in both families. The signed
  malformed-list guard has separate unchanged-value coverage, including Access
  Report, Follow-Up and Direct Measurement prefixes.
- Skipped/integrity-failed telemetry retains all original values. Shared unit
  tests cover normalization and optional framing, including pnet builds.
  The stateless Follow-Up unit test previously left sender U set and never
  populated its supposed prior state; it now clears flags and proves nonzero
  state before checking zeroing. The typed Follow-Up regression also checks
  that received Reserved bytes are ignored.

Twenty-one missing references are resolved. The invalid Follow-Up zeroing claim
(RFC8972-4.7-6) is now Partial: the malformed signed-list guard can retain an
invalid Length-17 value unchanged despite a verified covered prefix. That
copy/normalization precedence needs separate review before promotion. The
inventory is **321 applicable, 257 with references, 64 missing**; five missing
RFC 8972 references remain, all in CoS. The rollup is **471 clauses: 389
Compliant, 29 Partial, two Gap, 48 N-A and three Excluded**. Strict CI remains advisory. Evidence is
Linux software-loopback/shared-parser behavior, not physical synchronization,
native-platform or pnet capture runtime certification. Reproduced failures are
retained under `/tmp/t22b6-*` separately from passing runs.

Final verification passes full default/all-features/pnet suites with
**1,362/1,464/1,294** tests, respectively (13 privileged ignored in each ordinary
run). The final wire targets pass 10 sender and 11 reflector tests; the signed
copy cases also pass in the default profile. Both required MTU tests pass
separately without a skip, and all 60 independent BER cases pass against the
final all-features binary. All three Clippy profiles, fuzz manifest build check,
104 Python tests, root/fuzz rustfmt, matrix counts, 1,176 source citations and
441 documentation links pass. Strict checking fails only on the expected 64
missing-reference rows; the CI inventory remains advisory. No remote CI,
native/hardware pass or new fuzz campaign is claimed.

```sh
cargo test --locked --all-features --test sender_measurement_test --test tlv_extension_wire_test
```

## CoS/ECN wire review (T22b7)

Review against parent `64465ea` adds independent Linux packet/marking evidence
for the selected draft-02 profile. The new reflector test runs seven policy
cases in both families and open/keyed-open/authenticated modes: 42 profile
combinations, each with three burst replies and an interleaved ordinary reply.
It sets ingress IP TOS/Traffic Class independently of CoS value fields, then
checks observed DSCP2/EC2, actual reply markings, global/scoped DSCP admission,
independent ECN refusal, RPD/RPE, Reserved bits and final signatures on every
copy. Distinct IPv4 endpoints exercise destination-scoped policy. The ordinary
reply keeps its own marking, with no burst CoS leakage.

`tests/cos_ecn_wire_test.rs::reflector_cos_bytes_and_wire_markings_follow_ingress_and_admission_policy`
includes all ECN codepoints and a genuine legacy zero-reserved CoS request.
`tests/sender_measurement_test.rs::sender_cos_fields_and_automatic_ect_response_reach_the_wire`
checks actual Type/Length/RPD/RPE/Reserved origination and automatic congestion
controller presence for CoS ECT0/ECT1, plus a backoff on a correctly signed
forward CE report. Default/no-CoS and non-ECT CoS inputs are negative controls.
This demonstrates enablement/response capability. The existing controller
consistency, unsupported reverse-metadata and capability-diagnostic Partial
claims remain; injected socket failures are distinct from actual Linux wire
marking and admission rejection.

Seven missing references gain tests. One further missing-reference row,
RFC8972-4.4-5, is now Partial: draft-02 allocates EC1/RPE inside four of the
original sixteen Reserved bits, and the selected profile can emit nonzero
values there. Its twelve remaining Reserved bits are zeroed. The draft is
work in progress and identifies RFC 8972 as an update only if approved; the
frozen RFC's literal sixteen-bit rule is scored separately. No encoding,
runtime default, controller or other production behavior changes in this chunk.

The inventory is **320 applicable, 264 with references, 56 missing**. No
normative Compliant row in the RFC 8972 or CoS/ECN matrices now lacks a test
reference. The remaining missing rows are RFC 8762 (21), RFC 9503 (five), and
the reflected-header draft (30). The RFC 8972 matrix is **141 Compliant,
three Partial, seven N-A**; the full rollup is **471 clauses: 388 Compliant,
30 Partial, two Gap, 48 N-A and three Excluded**. Strict CI stays advisory.
These are software-loopback/shared-sender checks, not native-platform,
hardware, downstream remarking or pnet capture runtime certification.

Final local verification passes full default/all-features/pnet suites with
**1,364/1,466/1,295** tests, respectively (13 privileged ignored in each ordinary
run). The final focused run passes the CoS wire test and all 11 sender tests;
the wire test covers 42 policy/family/key combinations and 168 replies, and
the new sender case covers 30 combinations. All three Clippy profiles,
104 Python tests, rustfmt, matrix counts, 1,201 source citations and 442
documentation links pass. Strict checking fails only on the expected 56
missing-reference rows; CI stays advisory. Logs use `/tmp/t22b7-*`. Remote CI
and native/hardware behavior remain unclaimed. Runtime and protocol bytes did
not change, so verification targets the new evidence rather than rerunning
unchanged privileged/wire-oracle/fuzz campaigns.

```sh
cargo test --locked --all-features --test cos_ecn_wire_test --test sender_measurement_test
```

The subsequent [CI follow-up](../testing-startup.md#ci-follow-up-10-november-2026)
corrects native-platform test assumptions and an admission snapshot race
observed on `64465ea`. Commit `ef3f78d` passes Windows and Linux CI, but exposes
a shared-fixture startup race in the native macOS jobs. The
[metadata startup follow-up](../testing-startup.md#macos-metadata-startup-follow-up-10-november-2026)
waits for socket setup before fixture traffic. Commit `ea4f037` passes both
native macOS profiles; only a Windows startup test fails after selecting the
same released port twice. The
[port reuse follow-up](../testing-startup.md#windows-startup-test-port-reuse-follow-up-10-november-2026)
retains peers and uses automatic sender ports. These repairs do not change
this evidence inventory; native Windows verification of the latest correction
is still pending.

## Local validation for T22a

The all-features focused runs exercise 90 HMAC tests (including the new known
answer), 12 tests selected by the single-reply filter, one tracked-admission
unit test and the identity/authentication/flag-semantics integration suites.
The identity/authentication/flag suites passed 62 tests. The independent
all-features BER profile passed all 60 cases. The required route-MTU namespace
test passed its eight family/auth/binding combinations, with no prerequisite
skip. The new known answer also passed in default and pnet builds; the shared
admission-core regression passed in pnet without requiring a capture driver.
All 104 Python tests, all-features Clippy, rustfmt, matrix counts and source/link
checks pass. Results apply only to these local profiles; they do not establish
remote CI or unexecuted native platform behavior. Temporary logs and reports
use `/tmp/t22-*`; durable source tests and CI reproduction remain in the repository.

Run builds and wire suites sequentially so Cargo cannot replace a live binary:

```sh
cargo test --locked --all-features --lib hmac
cargo test --locked --all-features --lib single_
cargo test --locked --all-features --test session_identity_test --test session_auth_admission_test --test tlv_flag_semantics
cargo build --locked --all-features
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report /tmp/t22-ber-wire.json
cargo test --locked --all-features --test route_mtu_test --no-run --message-format=json > /tmp/t22-mtu-artifacts.json
python3 scripts/run_privileged_test.py /tmp/t22-mtu-artifacts.json route_mtu_test 2 unshare -Urn env STAMP_MTU_NETNS_TESTS=1 TOKIO_WORKER_THREADS=2
```
