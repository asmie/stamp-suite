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

After the reviews below, 30 missing references remain in the reflected-header
matrix. Prioritize the remaining authentication, C-flag and admission claims,
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

## Base packet review (T22b8)

The parent `f9c8bb8` has green
[CI (23/23 jobs)](https://github.com/asmie/stamp-suite/actions/runs/42808905339),
[conformance evidence](https://github.com/asmie/stamp-suite/actions/runs/42808905202)
and [CodeQL](https://github.com/asmie/stamp-suite/actions/runs/42808904888).
The CI repairs are committed; this review resumes the remaining RFC 8762
reference backlog. It does not claim remote execution of the new tests.

`tests/base_protocol_wire_test.rs` uses raw offsets and an independent
coverage selection for HMAC, rather than application packet builders/parsers:

- `sender_base_sequence_clock_layout_and_reserved_receipt` runs the public
  sender loop against a silent-until-reply UDP peer in 16 family/authentication/
  clock/strictness combinations. Each fresh session sends sequences 0, 1, 2;
  the peer checks the 44/112-byte layout, all transmitted reserved bytes, SSID
  zero, NTP/PTP timestamp recency and Z, dynamic source-port separation and
  authenticated bytes 96..112 over coverage 0..96. The peer replies with
  deliberately nonzero reserved bytes and valid signatures; all three replies
  must be accepted. NTP is tested without an explicit clock flag.
- `reflector_base_mbz_symmetry_clocks_and_stateless_sequences` starts the real
  nix reflector in 32 family/authentication/clock/strictness/state combinations.
  Ninety-six replies check stateless echo versus stateful 0/1/2 controls,
  copied sequence/T1/Error Estimate, real ingress TTL/Hop Limit 37, zeroed
  reply reserved bytes, T2/T3 format and ordering within the exchange window,
  final base signatures and symmetric sizes. Cases include bare bases,
  three nonzero opaque trailer bytes and 32 zero padding bytes. Authenticated
  requests carry nonzero MBZ signed over all 96 bytes; changing a covered MBZ
  octet after signing must get no response or stateful sequence advance.

The public configuration-loading test
`src/configuration/tests.rs::base_protocol_default_ports_and_user_dynamic_ranges_reach_endpoints`
checks default sender destination/reflector bind port 862 and NTP, and CLI/TOML
overrides at 1024, 49151, 49152 and 65535 through actual endpoint accessors.
The wire cases exercise real bound dynamic peers. The port-boundary/default
checks establish configuration and endpoint selection; they do not claim
live binds on every registered port or default-port access on every host.

All 21 remaining RFC 8762 missing-reference rows now cite these tests. Nine
already referenced rows gain the more direct wire evidence for base widths,
MBZ origination/receipt, echoed fields, TTL and authenticated layout. Status
counts remain **471 clauses: 388 Compliant, 30 Partial, two Gap, 48 N-A and
three Excluded**. The inventory is **320 applicable, 285 with references,
35 missing**: RFC 9503 (five) and the reflected-header draft (30). RFC 8762
has no remaining normative Compliant row without an explicit test reference.
This is source presence plus the execution scope below, not certification
of every normative clause or configuration.

The sender test is portable and added to the existing required Windows
runtime job. Local execution also passes under its `ttl-pnet,metrics,control`
feature set. Isolated macOS/Windows target harnesses compile the exact source
against the real default libraries, omitting unrelated optional/dev C graphs;
these are compile checks, not native runtime evidence for this chunk.

Final default/all-features/pnet Linux suites pass **1,368/1,470/1,297** tests,
respectively, with 13 privileged tests ignored in each ordinary run. The
sender and port-configuration tests pass in all three profiles; the reflector
wire case passes in both nix profiles. All three Clippy profiles, rustfmt,
104 Python tests, release metadata, matrix counts, 1,236 source citations and
456 documentation links pass (379 local checked, 77 external classified).
Strict checking fails only on the expected 35 missing references. Native
runtime and remote CI for this new chunk follow the manual commit.

These are software-clock loopback checks with `--hwtstamp off` and SSID zero
for the base profile. RFC 8972's SSID occupies two original reserved bytes;
other SSID/extension profiles retain their separate evidence. PTP checks the
documented UTC software encoding, not TAI alignment. The bounds enclose
application receive/send timestamps; they do not establish NIC timestamp
accuracy or an exact hardware arrival instant. No pnet reflector capture,
privileged, hardware, new BER or fuzz campaign is claimed. Logs use
`/tmp/t22b8-*`; strict CI enforcement stays pending until the other 35 rows
are reviewed. No application/runtime default or packet encoding changed.

## Return Path review (T22b9)

Parent `ff1ebd7` contains the RFC 8762 chunk. Its native CI result has not yet
been observed; the most recent observed green CI remains `f9c8bb8`. This
review resolves the five remaining RFC 9503 test-reference gaps while adding
a previously omitted inherited flag requirement as Partial.

`tests/return_path_wire_test.rs::sender_emits_one_return_path_with_unique_network_order_children`
runs the public sender against retained UDP peers in 42 combinations: both
families, unkeyed open/keyed open/authenticated modes, and seven Return Path
profiles (two Control Codes, address alone, each segment-list kind, and each
list combined with an address). Raw expected bytes check one outer Type 10,
unique child kinds, exclusion of Control Code with address/list children,
positive list lengths, two nontrivial MPLS label stack entries in network
order and two full SRv6 SID byte strings. Independent coverage checks verify
the base and extension signatures where present. The peer cancels the run
after observing one packet; these cases establish origination, not reply
consumption or successful SR forwarding.

`tests/return_path_wire_test.rs::reflector_first_return_path_owns_routing_even_when_unusable`
uses the real nix reflector in six family/key combinations. Twenty-four
replies verify first-owner precedence when a later TLV requests suppression:
the first requests same-link, carries an empty SRv6/SR-MPLS list, or has a
malformed outer value. A reversed first-suppress/later-same-link case gets no
reply, followed by one live same-link request without a retry. Thirty replies
and six suppressions check original sequence, copied values, the first outer
U/M result and final signatures. Child flag bytes are deliberately excluded
from equality assertions on processed values: their correctness is the
separate Partial finding below, not frozen as intended behavior.

`src/tlv/list/processing/tests.rs::return_path_first_segment_owner_includes_empty_and_unsupported_lists`
tests empty-first and valid-first lists directly through route processing.
An empty first SRv6 list is unusable even when a valid list follows; an
unsupported first MPLS list cannot fall through to SRv6. A valid first SRv6
list keeps its action when an empty second list follows. This is shared-core
selection evidence, not an SRH forwarding test. The existing
`src/configuration/tests.rs::empty_return_segment_lists_from_a_file_are_rejected`
now also checks actual TOML loading and empty CLI values before sender startup.

The original matrix omitted RFC 9503 Section 4.1's inherited sub-TLV flag
procedures. A separate Linux wire control observes a recognized, used Control
Code child retaining U=1 while the successful parent has U=0. It exits with a
failed conformance result (`/tmp/t22b9-child-flags-before.json`), independently
of the passing routing tests. The new `9503-4.1-flags` row is **Partial**;
known/unknown child flags, framing, failed-integrity copying and Control Code
ignore precedence need a separate repair before a broader claim is justified.
See [the concrete request/reply](rfc9503.md#nested-flags). The RFC publication
month is also corrected to October 2023 from the source document.

The RFC 9503 matrix now has **27 clauses: 22 Compliant, one Partial, three
N-A, one Excluded**. The rollup is **472 clauses: 388 Compliant, 31 Partial,
two Gap, 48 N-A and three Excluded**. This adds an omitted requirement; it
does not demote a working top-level routing clause to hide the nested issue.
The inventory is **320 applicable, 290 with references, 30 missing**, all in
the reflected-header draft. There are no missing normative Compliant test
references in RFC 9503, but that is distinct from its new Partial flag row.

The portable sender case joins Windows' required runtime gate and passes its
feature set locally. Exact-source macOS/Windows target checks use minimal
harnesses with the real default libraries; native runtime remains pending for
this chunk. Reflector wire evidence is nix software loopback; pnet capture,
physical interfaces and SR transit are not established here. The SR-MPLS
forwarding exclusion remains. Protocol/runtime behavior is unchanged. Logs
use `/tmp/t22b9-*`; repair the nested flags next, then review the remaining
header rows before strict CI enforcement.

Final default/all-features/pnet Linux suites pass **1,371/1,473/1,299** tests,
respectively (13 privileged tests ignored in each ordinary run). The portable
sender and shared-core/configuration cases pass in all three profiles; both
nix profiles pass the reflector wire case. All three Clippy profiles,
rustfmt, 104 Python tests, release metadata, matrix counts, 1,249 source
citations and 460 documentation links pass (383 local checked, 77 external
classified). Strict mode fails only on the expected 30 header references.
These checks do not turn the separate nested-flag conformance failure into a
pass. Native execution and remote CI of this chunk remain pending.

## Return Path child validation and flag repair (T22b10)

Parent `5481841` contains the T22b9 origination/ownership review. This chunk
repairs its concrete used-child U failure and reviews nested framing through
the real reflector and sender. It does not enable strict evidence enforcement.

`src/tlv/list/processing/tests.rs::processed_return_path_children_rederive_flags_and_ignore_other_parameters`
failed before the repair: received `ff` headers remained unchanged instead of
selected `00` and ignored `80`. It now passes through the shared processing
entry point. `src/tlv/typed/return_path.rs::tests::return_path_framing_and_selected_lengths_are_bounded`
checks complete framing, selected lengths and Control Code ignore precedence.
`src/tlv/list/processing/tests.rs::malformed_return_path_stops_later_values_before_early_child_mutation`
establishes that a valid early child is not changed before a malformed later
child is discovered.
`src/tlv/list/processing/tests.rs::return_path_integrity_and_skipped_copies_keep_all_child_bytes`
checks failed-extension-integrity and already-skipped copies, including a
parser-marked truncated container after an earlier malformed extension.

`tests/return_path_wire_test.rs::reflector_normalizes_return_path_children_and_preserves_failure_values`
runs the nix reflector in 12 family/key/strictness combinations: IPv4/IPv6,
unkeyed open/keyed open/authenticated, permissive/strict. It checks 112 replies
and 12 suppressions: selected/ignored/unknown flags, reserved Control Code
bits, a valid early Control Code with later truncation, a partial child header,
wrong selected address length, empty segment lists, and well-framed ignored
parameters. A later Access Report is processed after a valid Return Path and
copied after a malformed one. Independent byte/HMAC checks cover successful
replies; failed extension signatures retain values and the failed digest,
including a no-reply request that must instead be echoed. A fresh positive
reply follows each suppression. The existing origination and first-owner
suites also pass with the new malformed M/U behavior.

`tests/sender_measurement_test.rs::sender_validates_return_path_children_before_consuming_extension_values`
uses 56 independent mock replies across IPv4/IPv6 and open/authenticated modes.
Direct Measurement occurs before and after the Return Path to verify that
child M stops later values and child I blocks all extension values. It also
checks partial framing, wrong selected lengths, late child M, an unrecognized
parent whose child I is skipped, and a well-framed empty list ignored under a
Control Code. Base RTT remains independently usable. These tests run in all
three Linux feature profiles and the Windows CI feature set.

The required `tests/netns_conformance.rs::scenario_3_srv6_return_path` passes
in private user/mount/network namespaces with no prerequisite skip: 24 captured
open/authenticated replies cover a transit SID and explicit final SID,
SRH Segments Left 1 to 0, Hop Limit 255 to 254, CoS, independent HMACs and
ordinary-reply isolation. Capture packages are extracted under `/tmp`; no
system installation or host sysctl change is needed. This is Linux virtual
network evidence, not physical-interface or pnet capture evidence.

The final packet-processing ASan/libFuzzer run completes 100,000 executions
from 48 Return Path seeds, with 965 new units, 330 MiB peak RSS and no crash.
Its bounded run is a regression check, not exhaustive input coverage. Exact
macOS/Windows test-source cross-checks pass in minimal harnesses using the
real default libraries; they do not replace native runtime or full platform
dependency builds. Native CI for this uncommitted chunk remains pending.

The inherited child-flag row remains **Partial**: integrity-failed, malformed
signed outer-list and already-skipped copies preserve child flags and reserved
value bits. The RFC 9503 and rollup counts remain **27: 22 Compliant, one
Partial, three N-A, one Excluded**, and **472: 388 Compliant, 31 Partial, two
Gap, 48 N-A, three Excluded**. The test-reference inventory remains **320
applicable, 290 referenced, 30 missing**, all in the reflected-header draft.

Final default/all-features/pnet suites pass **1,377/1,479/1,304** tests,
respectively, with 13 privileged tests ignored in each ordinary run. All three
Clippy profiles with warnings denied, rustfmt, Rust 1.87 all-features/all-targets
checking, warnings-denied rustdoc, 104 Python tests and release metadata pass.
Matrix counts, 1,259 source citations and 461 documentation links pass
(384 local checked, 77 external classified). Strict citation mode fails only
for the expected 30 header references; it remains advisory in CI.

Temporary validation logs use `/tmp/t22b10-*`; source regressions and this
scope record are durable. Resume the 30 header rows in the next chunk.

## Sender header-request evidence (T22b11)

Parent `ea4d97b` contains the Return Path repair. This chunk resolves 16 sender
references in the frozen ext-hdr-26 matrix without changing protocol behavior,
selector syntax, platform support or status counts. It leaves 14 header rows
for endpoint/hop policy, reflector matching/control, disclosure and policing.
Strict evidence enforcement remains pending until that review is complete.

`tests/header_request_wire_test.rs::sender_control_request_is_unique_zero_length_and_opt_in`
uses the public sender and a retained independent peer in 18 combinations:
IPv4/IPv6, unkeyed open/keyed open/authenticated, and plain/control-only/
explicitly shaped control. Plain probes have no header or control requests.
Control-only probes carry one Type 12 with count 1, length 0, interval 0 and
exactly one zero-length control child (experimental Type 240). Explicit count,
length and interval shaping survives separately. Raw expected bytes also
check U/M/I/reserved flags and independent base/extension HMAC coverage. This
portable case is included in Windows' required runtime test list.

`tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`
checks 12 Linux combinations: both families, all three key modes, and zero or
nonzero Requested fields. Exactly one Type 247 has the family's 20/40-octet
length, its four-octet selector and zero-filled Received tail. Whole-extension
equality excludes stray Type 246 and control TLVs. This calls sender startup,
route budgeting, packet building/signing and actual UDP transmission.

`tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`
runs 21 probes per Linux profile in private user/network namespaces, with
missing prerequisites failing. The independent peer reads actual Hop-by-Hop
and Destination Options ancillary headers alongside independently expected
STAMP bytes. Seven attachment/request profiles in three key modes cover
automatic and explicit full requests, different/same lengths, both same-length
subsets, a length-selected subset, mutable-option masking and fixed-before-
extension ordering even when CLI flags are reversed. Headers and request
counts/lengths, selector bytes, zero Received tails and signatures are checked.
Default, all-features and pnet runs pass separately. This is sender origination
evidence with kernel receive metadata; it does not establish reflector matching,
successful reflected measurements or raw pnet capture. The new namespace case
joins the required nix and pnet CI gates with an exact nonzero test count.

`src/configuration/tests.rs::revision26_sender_subset_rules_apply_to_cli_and_toml`
now checks 14 profiles through both real CLI loading and TOML merge/validation:
wrong request count, length and order, ambiguous/unique subsets and full-group
wildcards. Selector arguments intentionally require a nonzero byte; explicit
all-zero arguments remain rejected before matching. A bare length generates
the supported all-zero wire field. An initial investigation treated this
syntax rule as a matching defect; source review and the existing rejection
test establish it as deliberate, so no production change is made.

The exact portable test source cross-compiles for macOS and Windows in minimal
harnesses with the real default libraries. The Windows CI feature set passes
locally on Linux; these checks do not establish native runtime or the full
platform dependency graph. An exact-parent CI query finds no run for
`ea4d97b`; the latest observed CI, conformance and CodeQL success remains
`f9c8bb8`. Remote CI for this uncommitted chunk is pending.

The inventory is **320 applicable, 306 referenced, 14 missing**. All status
counts are unchanged: **472 clauses: 388 Compliant, 31 Partial, two Gap, 48
N-A and three Excluded**. Presence and execution are separate: the ignored
namespace case is executed explicitly, not counted as an ordinary-suite pass.

Final default/all-features/pnet suites pass **1,379/1,481/1,306** tests,
respectively (14 privileged tests ignored in each ordinary run). All three
Clippy profiles with warnings denied, rustfmt, Rust 1.87 all-targets/all-features
checking, warnings-denied rustdoc, 104 Python tests, release metadata and
matrix counts pass. Both edited workflows parse as YAML. Source validation
passes 1,288 citations;
461 documentation links pass (384 local checked, 77 external classified).
Strict mode fails only on the expected 14 header references. The new ignored
case passed separately in default/all-features/pnet, totaling 63 probes.

Temporary logs use `/tmp/t22b11-*`; the source tests and this scope record are
durable. Stop for a manual commit before reviewing the remaining 14 rows.

## Reflector header disclosure, matching and control (T22b12)

Parent `c89936d` contains the sender-header review. This chunk resolves ten
reflector/header-policy references while preserving production behavior and
all status/profile limits. Four rows remain: source-port separation, outgoing
TTL/Hop Limit, nested fixed-header capture order and receive policing. Strict
test-reference CI remains pending until their separate review is complete.

`tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`
runs 200 exchanges per Linux profile: five source/header policies, three key
modes and two strictness settings. Default deny, unmatched source, fixed-only,
extension-only and both-kind permission are crossed with absent/single/duplicate
reverse-header control and normal/reversed Type 247/246 order. There are 180
normal replies and 20 failed-extension-integrity replies. Exact independent
bytes check policy refusal, successful capture, every control-child C flag,
parent flags, preserved data on global order refusal, echoed sender sequence
and independent base/extension HMACs. Failed integrity retains request values
and the failed digest without exposing captures. Reply ancillary metadata
contains no matching Hop-by-Hop or Destination Options header, with or without
control. This proves the cannot-add fallback, not bidirectional attachment.

Default and all-features runs exercise nix capture of an actual Destination
Options header; fixed headers remain unavailable and get C. The separate
pnet-only run injects complete IPv6/UDP wire checksums through a raw socket,
because loopback's incomplete TX checksums are deliberately rejected by the
application. Its reply verifies actual fixed and extension capture, independent
permissions for both kinds and the same control behavior. All three namespace
runs pass without prerequisite skips: 600 replies total. This is Linux software
loopback evidence; it does not establish physical interfaces or nested tunnels.
CI requires exactly one ignored case per backend, rejecting empty/gated suites.

`tests/tlv_flag_semantics.rs::fixed_header_reflection_fills_requested_and_copies_received_in_capture_order`
checks supplied 20/40-octet fixed-header formats through `process_stamp_packet`:
zero Requested filling, ordered consumption, unique selectors preserving
wildcards, exact Received copying and exhaustion without data. Together with
`tests/tlv_flag_semantics.rs::global_header_order_refusal_preserves_all_requests_before_copying`,
these add 36 raw request/reply cases per feature profile across three key modes
and both strictness settings, with independent signatures. The ordering case
uses marked Received tails to prove preservation before any copy. Supplied
capture records establish matching, not nested raw extraction (still pending).
The full 60-test flag suite joins Windows' required driver-free runtime gate.

`src/receiver/ingest.rs::tests::header_reflection_policy_is_per_source_and_header_kind`
now passes captured data through real processing after constructing policy
from configuration and each received source. Six source mappings, including
IPv4-mapped canonicalization, check both policy decisions and exact allowed/
refused fixed/extension response values. The shared ancillary capture helper
moves to `tests/common/ipv6_headers.rs`; the prior sender namespace case passes
again in all-features and pnet builds (42 probes).

The pnet probe initially failed on `--local-port 0`: `run_receiver` reports the
configured zero port, binds family sockets independently and installs capture
filter port zero. That is a newly exposed endpoint defect, not a header-policy
failure. This chunk's pnet reflector binds port 19862 inside its fresh private
namespace before the peer binds; there is no released-port reservation or host
port contention. Repair pnet port-zero binding/filter/advertisement in the next
endpoint chunk, then review the four remaining rows. Do not infer port-zero
support from this fixed-port capture pass.

The inventory is **320 applicable, 316 referenced, four missing**. The rollup
stays **472 clauses: 388 Compliant, 31 Partial, two Gap, 48 N-A and three
Excluded**. No draft ambiguity, platform limitation or Partial row is promoted.

Final default/all-features/pnet suites pass **1,381/1,483/1,308** tests,
respectively (15 privileged tests ignored in each ordinary run). The namespace
executions above are separate from those ignored counts. All three Clippy
profiles, rustfmt, Rust 1.87 all-targets/all-features checking, warnings-denied
rustdoc, 104 Python tests, release metadata and matrix counts pass. Source
validation passes 1,312 citations; 461 documentation links pass (384 local,
77 external classified). Strict mode fails only on the expected four rows.
Both edited workflows parse as YAML. The Windows CI feature set passes all
60 flag tests locally on Linux; exact-source minimal macOS/Windows harnesses
cross-compile with warnings denied using the real default libraries. These
source checks do not establish native runtime or the full platform dependency
graph. An exact-parent query finds no CI run for `c89936d`; remote CI for this
uncommitted chunk remains pending.

Temporary logs use `/tmp/t22b12-*`; these source regressions and this scope
record are durable. Stop for a manual commit before the endpoint repair.

## Pnet assigned-port endpoint repair (T22b13)

Parent `3574d6e` contains the reflector header review. Its first pnet attempt
at port zero exposed an endpoint defect: family sockets independently received
ports, but readiness, capture filtering and received metadata kept configured
zero. The new endpoint fixture fails before the repair for both configured
families with an unassigned-port readiness report. All three cases pass after
the repair; no failed wire exchange is counted as a successful baseline.

`src/receiver/pnet.rs::bind_reply_sockets` retains the configured-family socket
first, reads its actual endpoint and binds the other family to that port when
available. The primary is required; an unavailable counterpart does not block
it. IPv6 reply sockets are IPv6-only, allowing IPv4/IPv6 wildcard owners to
coexist. A configured-family bind failure now stops startup before capture,
including IPv6 failures previously masked by an optional IPv6 bind. Explicit
ports remain exact. An IPv6 primary no longer depends on an unrelated IPv4
bind succeeding. Capture filter, received Location ports and readiness use
the selected port, and the send worker handles either unavailable counterpart.

`tests/pnet_endpoint_test.rs::pnet_assigned_ipv4_ports_reach_capture_metadata_and_both_reply_families`
and
`tests/pnet_endpoint_test.rs::pnet_assigned_ipv6_ports_reach_capture_metadata_and_both_reply_families`
exercise four concrete/wildcard binds, three key modes and assigned/explicit
ports. Independent complete-checksum raw IPv4/IPv6 probes validate reply source
ports, echoed sequence, Location destination/source ports and base/extension
HMACs. A second startup fails while the original reflector retains its exact
endpoint; no released-port reservation or readiness probe is used. Separate
live counterpart owners establish optional-family fallback without changing
the configured port. These tests require both reply families when available
inside their private namespace, including IPv6 wildcard binds.

`tests/pnet_endpoint_test.rs::pnet_ipv4_works_with_ipv6_disabled_and_ipv6_startup_fails`
checks IPv4 replies and early IPv6 bind failure after disabling IPv6 addresses
only inside the verified private namespace. A guard restores the sysctl. The
three endpoint cases serialize even under a parallel test runner, require the
recorded parent namespace to differ and reject missing prerequisites. Together
they pass **63 replies, 27 expected startup failures and 39 graceful SIGTERM
shutdowns** (each bounded to four seconds). CI requires all three ignored cases
with the actual pnet backend; zero/gated suites cannot pass.

`src/receiver/pnet.rs::tests::reply_socket_binding_retains_primary_endpoint_and_one_port`
checks real unprivileged socket binding for all four concrete/wildcard profiles,
available family ports, IPv6-only operation and retained primary conflicts.
`tests/startup_failure_test.rs::reflector_reports_bind_failure` now checks both
families through receiver startup before capture discovery. These run without
capture privileges and join the existing native Windows unit/startup gates.

The 200-exchange pnet header-policy test now uses its advertised assigned port,
removing the fixed-port workaround. All three pre-existing raw loopback tests
pass, including bad-checksum rejection. The scoped link-local IPv6 fixture
initially failed on incomplete TX checksums; it now disables offload on its
own private veth ends and passes open/authenticated bursts, alternate-address
signatures and sender zones. Application checksum validation is unchanged.

Exact pnet-library/startup-test source cross-checks pass for macOS and Windows
with warnings denied using minimal harnesses. They do not establish native
capture/runtime or the full platform dependency graph. Fresh remote CI for
this uncommitted chunk remains pending. This is Linux software capture evidence,
not physical NIC/driver evidence.

The inventory stays **320 applicable, 316 referenced, four missing**; all
status counts remain **472 clauses: 388 Compliant, 31 Partial, two Gap, 48
N-A and three Excluded**. The remaining four rows and strict CI enforcement
are T22b14/T22c.

Final default/all-features/pnet suites pass **1,381/1,483/1,309** tests,
respectively, with **15/15/18** privileged cases ignored in the ordinary runs.
The explicit namespace executions above are separate evidence. All three
Clippy profiles, rustfmt, Rust 1.87 all-targets checking in all-features and
pnet-only profiles, warnings-denied rustdoc, 104 Python tests, release metadata
and matrix counts pass. The Windows CI feature set passes the new binding
unit and all 12 startup tests locally on Linux. Source checks pass 1,318
citations; 461 documentation links pass (384 local, 77 external classified).
Strict mode fails only on the four expected missing references. The edited
workflow parses as YAML. An exact-parent query observes no CI run for
`3574d6e`; remote CI remains pending for this uncommitted chunk.

Temporary logs use `/tmp/t22b13-*`; durable regression source
and this report retain the scope. Stop for a manual commit before T22b14.

## Final reflected-header reference review (T22b14)

Parent `8d7afaa` contains the pnet assigned-port repair. This chunk reviews
the four remaining header rows through real packet paths and narrows two
unconditional claims. Production behavior is unchanged. Strict reference
checking now passes locally; enabling that CI guard remains the separate T22c
chunk after the manual commit. Reference completeness is not whole-matrix
certification or execution evidence for every platform.

`tests/pnet_nested_headers_test.rs::actual_nested_capture_reflects_outer_to_inner_and_rejects_bad_checksums_and_depth`
injects complete-checksum envelopes into the actual Linux pnet capture path.
Six IPv4/IPv6 two/three-layer chains cross unkeyed open/keyed open/authenticated
modes and both parsing strictness settings. Thirty-six main replies and six
fresh follow-ups verify exact outer-to-inner Type 247 values, independent
base/extension HMACs, innermost reply endpoints and received hop count 37.
Outer addresses/hops differ, so selecting outer session metadata fails the
oracle. Thirty-six bad inner UDP checksums and six 32-layer envelopes get no
reply; valid follow-ups prove the receiver remains live. The final run passes
42 replies and 42 negative probes, with no prerequisite skip. CI requires the
single ignored case on the actual pnet backend. This is software-loopback
capture, not a physical tunnel, NIC or Windows capture-driver claim.

`tests/ext_hdr_revision13_test.rs::sender_hops_and_held_local_endpoint_separation_cover_both_families_and_keys`
checks actual sender UDP metadata across both families and three key modes:
six explicit binds to a retained local reflector endpoint fail without sending,
then six automatic binds send with hops 255 and distinct peer/local ports.
The retained UDP owner establishes same-endpoint exclusion; it does not model
an inventory of reflector ports on different addresses. Authenticated sender
base bytes are checked independently.
`tests/ext_hdr_revision13_test.rs::reflector_transmits_255_and_accepts_lower_received_hops`
now uses readiness without a released-port handoff or startup traffic. Six
nix cases reflect requests arriving with hops 37 and send with hops 255,
including independent authenticated base signatures. The existing pnet
endpoint suite now reads actual ancillary hop metadata on all 63 replies.
`tests/common/hops.rs` shares that independent receive oracle across the tests.
Pnet endpoint cases pass separately; the nix/sender cases pass in default/
all-features and the sender cases also pass in pnet builds.

A separate live control runs a pnet reflector on `127.0.0.1:56620` while the
public sender sends from `127.0.0.2:56620` to a retained peer on another port.
The peer observes the same numeric port and the reflector remains running.
The original same-endpoint argument therefore did not establish the whole
local-role-port requirement. The row stays MUST NOT but becomes **Partial**;
operators must provision separate numeric role ports across addresses. This
is a failed conformance control, not a passing test that freezes that limit.
The control JSON is `/tmp/t22b14-local-port-control.json`; its observed values
and scope are retained here and in the matrix.

`src/configuration/tests.rs::receive_policing_defaults_and_provisioned_cli_toml_values_reach_runtime`
checks default unlimited policing with 1,024 immediate accepts per address
family, real TOML loading, CLI precedence and resulting runtime rate/burst
values. This verifies the reflector's configuration path. It cannot establish
that deployed limits accommodate aggregate offered traffic, other sessions,
bursts and changing capacity. That MUST NOT row also becomes **Partial**.
Operator provisioning and resource-protection drops remain documented; no
aggregate-capacity validator or local role-port inventory is implemented.
Those are possible future provisioning features, requiring explicit session/
capacity input rather than inferred guarantees from the default limiter.

Both normative levels are retained. Two rows gain executed evidence and two
overbroad claims are narrowed. The header matrix is now **75: 62 Compliant,
10 Partial, three N-A**. Overall counts are **472: 386 Compliant, 33 Partial,
two Gap, 48 N-A, three Excluded**. The explicit-reference inventory is
**318 applicable, 318 referenced, zero missing**, and strict mode succeeds.
Existing profile, hardware, native-platform and draft-ambiguity limits remain.

Final default/all-features/pnet suites pass **1,383/1,485/1,311** tests,
respectively (15/15/19 privileged cases ignored in ordinary runs). The nested
and endpoint executions above are separate evidence. All three Clippy
profiles, rustfmt, Rust 1.87 all-targets checks for all-features/pnet-only,
warnings-denied rustdoc, 104 Python tests, release metadata and matrix counts
pass. Strict source checking passes 1,330 citations with no missing test
references; 463 documentation links pass (386 local, 77 external classified).
The edited workflow parses as YAML. The new configuration test passes locally
on Linux under Windows CI features. Exact-source minimal macOS/Windows
harnesses cross-check the pnet library and relevant startup/hop test source
with warnings denied. This does not establish native runtime or the full
platform dependency graph. No CI run is observed for exact parent `8d7afaa`;
remote CI for this uncommitted chunk remains pending.

Temporary logs use `/tmp/t22b14-*`; source tests and this report are durable.
Stop for a manual commit before T22c enforcement.

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
