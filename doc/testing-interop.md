# Independent protocol-combination fixtures

[`scripts/interop_apps.py`](../scripts/interop_apps.py) can compare separately
built applications in compatible roles and modes. The previously cited October
report is unavailable, so this page makes no claim about that run's case totals
or results. Record peer revisions, profiles and wire reports for a new run.

Independent wire fixtures for testing a reflector and reusing STAMP payloads.
See the [profile limits](conformance/README.md#known-limits) before interpreting
an exchange as evidence for another backend, platform or physical link.

[`scripts/interop_stamp.py`](../scripts/interop_stamp.py) drives a real reflector
with a separate Python standard-library implementation of the wire layout,
HMAC coverage, reply checks and UDP metadata collection. It does not import the
Rust crate or call its sender. Linux and Python 3.10+ are required; the profile
uses the nix backend, loopback IPv4/IPv6, and software timestamps. A missing
socket capability or failed check is a failure, with no internal skip.

```sh
cargo build --locked
python3 scripts/interop_stamp.py --binary target/debug/stamp-suite --report /tmp/interop-default.json
cargo build --locked --all-features
python3 scripts/interop_stamp.py --binary target/debug/stamp-suite --report /tmp/interop-all-features.json
python3 -m unittest discover -s scripts/tests -v
```

Run builds and live suites sequentially: Cargo can replace the executable while
another suite is using it. `conformance.yml` gates both build variants and uploads
the JSON wire records. The script launches and reaps its own reflectors, uses
ephemeral ports, and creates temporary key directories with mode-0600 key files.
It only sends to loopback. It never changes interface addresses or kernel policy.

## Fixture contract and scope

The `loopback-burst-fallback-v1` profile runs 16 configurations: IPv4/IPv6,
open/authenticated base, NTP/PTP reflector format and stateful/stateless sequencing.
Each configuration uses a sender timestamp format different from the reflector's.
Each then exercises SSIDs 42 and 43 with distinct directory keys, and SSID 99
with the default key: **48 exchanges and 192 validated replies** in a complete
successful run. Both base modes include a keyed HMAC TLV. The authenticated
configurations additionally send **24 bases signed with the wrong directory
entry's key**, expect silence, and verify that the subsequent valid request still
starts its session sequence/counters at their initial values.

Each exchange sends a three-copy burst request containing Type 12, CoS, Direct
Measurement, Follow-Up, Destination Node Address, SRv6 Return Path and HMAC TLVs.
After receiving the first copy, it interleaves an ordinary request. Every reply
is checked for sequence and echoed fields, source endpoint, actual IP traffic
class, TLV order/flags/values, and HMAC coverage. Later copies must retain T2,
advance T3, retain the requested CoS/source, and report the intervening send in
the DM/Follow-Up fields. An extra reply during the final 150 ms guard fails.

SRv6 forwarding is disabled: Type 10 must return U=1 with a valid final HMAC.
Source matching uses loopback, so this fixture cannot establish multihomed source
override. The 120 ms burst gap allows interleaving; it is not a timing benchmark.
Physical LAG, NIC timestamps, and successful SRH transit need separate tests.

## Reusable bytes and oracle checks

[`requests.json`](../tests/fixtures/interop/requests.json) contains 24 named
parameter sets, each with `burst_hex` and `ordinary_hex`: **48 fixed UDP
payloads**, with no IP/UDP header or host-dependent field. Timestamps are fixed
valid wire values so repeated requests are byte-identical. Keys are public test
values: `ab` repeated 16 times for SSID 42, `cd` for 43, `ef` for the default.
These payloads can also be consumed by another implementation's test harness;
its session, key, CoS and burst policies must match this profile. The launcher
itself expects stamp-suite's CLI.

The generator refuses a mismatch between checked-in bytes and its encoding.
Changing a fixture requires explicit regeneration and review:

```sh
python3 scripts/interop_stamp.py --write-vectors
git diff -- tests/fixtures/interop/requests.json
python3 -m unittest discover -s scripts/tests -v
```

[`replies.json`](../tests/fixtures/interop/replies.json) holds four observed
exchanges from the recorded baseline binary, with its SHA-256 and platform provenance.
These are frozen regression inputs for the checker, not normative timestamp
values or independent certification. Unit tests replay them and then deliberately
corrupt sequences, timestamps, clocks, counters, flags, CoS, endpoints and
digests. Behavioral mutations are re-signed so their rejection checks semantics
as well as integrity. The SHA-256 primitive also has the truncated
[RFC 4231 §4.2 test vector](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2).

The live report records binary, runner and request-fixture SHA-256, platform,
Python version, UTC start, all measured transmitted/received UDP bytes and
receive metadata, expected silence, command arguments and reflector stderr.
Startup readiness exchanges use a separate retained socket and are excluded
from measurement records. `expected_cases`, `completed`, `passed` and `failed`
distinguish partial reports from complete runs; exit status is nonzero if any
case fails. A missing binary, fixture mismatch or unsupported platform fails
preflight before a case report is created. Reports are rewritten after every
case. Temporary key paths and UDP ports are recorded for diagnosis, not replayed
verbatim.

## Independent successor BER profile

[`scripts/interop_ber.py`](../scripts/interop_ber.py) is a separate Python
standard-library sender and reflector for `draft-ietf-bpm-stamp-ber-01`.
It uses agreed experimental outer Type 243 and pattern sub-TLV Type 241;
neither value is an IANA assignment. It imports no Rust code or other peer
implementation. Run it after each build, sequentially with other live suites:

```sh
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report /tmp/ber-interop.json
```

The `successor-ber-v1` profile requires **60 cases**: both families × three
integrity profiles (open, keyed open, authenticated) × ten configurations.
Each group includes stateful/stateless reflector tests and eight sender tests
(default/explicit five-byte patterns × baseline, invalid observations, parent U
and child U). Missing capabilities fail rather than skip. Both default and
all-features builds run this profile in `conformance.yml` and upload reports
even when a case fails. All-features still selects nix.

The [17 request/expected-field vectors](../tests/fixtures/residual-ber/requests.json)
cover clean/default errors, explicit four/five-byte patterns, unknown children,
missing/duplicate padding, duplicate BER/pattern, misalignment, short outer and
nested values, truncated nested headers, acknowledged prefixes, opaque remainders
and retired legacy outer types. The reference bit counter constructs an XOR bit
string; deliberate four-bit runs cross byte and pattern boundaries. Keyed cases
verify HMAC over the actual reflected sequence and metadata prefix, leaving
padding outside coverage. Invalid extension HMACs must be copied with I and
their failed digest unchanged (RFC 8972 §4.8); invalid authenticated bases must
receive no reply.

Sender cases independently decode emitted requests and return crafted replies.
Baseline sends same-sequence duplicates. The gates scenario returns signed
M/C/I, duplicate fields, incorrect patterns, impossible counts and resized padding,
plus a failed digest in keyed modes. These must add no BER samples. A nonzero
count with burst zero remains a count sample without a burst sample. Reverse
errors are introduced independently. Summary checks cover directional counts,
denominators, error totals, burst maximum/average, rates and interval sums.
After parent or child U, subsequent requests omit BER and delay/loss continues.

[`replies.json`](../tests/fixtures/residual-ber/replies.json) freezes all 12
reflector observations and 48 sender request/summary records from the documented
default build. Provenance includes binary, runner and vector hashes. These are
application regression observations, not independent certification. The
[`oracle tests`](../scripts/tests/test_interop_ber.py) replay them, alter signed
semantics/digests/echoes/padding and summaries, and check failure-report bookkeeping.
The HMAC primitive has an RFC 4231 known-answer test. Regeneration of requests
is explicit (`--write-vectors`) and live preflight rejects unexpected changes.

Reports contain commands, process outcomes, stdout/stderr, UDP bytes/endpoints,
expected silence, platform/tool versions, UTC time and hashes. A retained warmup
socket is separate from measurements; reflectors bind a kernel-selected port
and expose readiness in their startup log. Every case is attempted, reports are
rewritten after each, and any failure produces a nonzero exit. A report with
`completed=false` is incomplete evidence. Keys are public fixture values only.

These are software-loopback tests with valid UDP checksums. They do not prove
physical error capture or PMTU discovery. The [9 November report](interop/2026-11-09-ber/REPORT.md)
also records route-MTU tests and incompatible Teaparty black-box captures; no
successor exchange with another maintained application has been demonstrated.

## Protocol sources and complementary coverage

The encoder/checker uses the following frozen sources, not generated Rust
layouts. Draft rows apply to the pinned revision.

| Source | Fields used by the independent profile |
| --- | --- |
| [RFC 8762 §§4.2–4.4](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.2) | 44/112-byte bases, sequence/echo, timestamp Z bit, truncated base HMAC over the first 96 authenticated bytes |
| [RFC 8972 §§4.4–4.8](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.4) | CoS, DM, Follow-Up and HMAC TLV; digest covers the reflected sequence followed by preceding TLVs |
| [RFC 9503 §§3–4](https://www.rfc-editor.org/rfc/rfc9503.html#section-3) | Destination Node Address (Type 9), Return Path (Type 10), SRv6 segment-list sub-TLV (Type 4), fallback flag |
| [RFC 10052 §§3, 4.3](https://www.rfc-editor.org/rfc/rfc10052.html#section-3) | Type 12 count, interval, minimum size and composition |

The wire suites below assemble bytes manually and use
[`common/wire_hmac.rs`](../tests/common/wire_hmac.rs), which calls `hmac`/`sha2`
directly. Tests may still invoke the production receiver as the system under test.

| Combination | Reproducible coverage and limits |
| --- | --- |
| Key directory + fallback + queued rotation/revocation | `cargo test --locked --test keyset_fallback_test`; IPv4/IPv6, open/auth, per-SSID/default keys; independent wire signing/verification |
| Bursts + CoS + software/kernel Follow-Up | `cargo test --locked --all-features --test burst_transmission_test`; independent HMAC checks, actual IP traffic class and interleaved ordinary packets |
| Sessions + cap + authentication/replay/rotation | `cargo test --locked --test session_auth_admission_test --test session_capacity_test`; the former uses the independent HMAC helper; checks rejection before admission/refresh and overload behavior |
| Required micro-session + absent/U/I TLV | `cargo test --locked --test required_micro_session_test`; real sender vs raw peer, independent signing; [RFC 9534 §3.2](https://www.rfc-editor.org/rfc/rfc9534.html#section-3.2), logical identifiers only |
| Mixed clocks and advertised clock quality | `cargo test --locked --test mixed_clock_test`; independently encoded/signed peer with explicit time offset and synchronization metadata |
| Source/SRH fallback failures | `cargo test --locked --lib receiver::transmit`; shared finalizer tests inject combined transport failures and verify final signatures; syscall source tests are Linux-specific |
| Scoped IPv6, real routing/MTU and SRH | `scoped_ipv6_test`, `route_mtu_test`, `netns_conformance`; separate ignored tiers, see [tests that need privileges](../tests/README.md#tests-that-need-privileges-or-namespaces) and the [namespace guide](testing-netns.md). Inspect SRH capture versus reported fallback; neither a skip nor fallback is successful SRH evidence. These suites still use some production packet/TLV helpers. |

Malformed-input properties, fuzzing, telemetry, and session-identity tests
cover additional cases; this fixture does not cover every combination.
