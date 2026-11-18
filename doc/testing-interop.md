# Independent protocol-combination fixtures

[`scripts/interop_apps.py`](../scripts/interop_apps.py) runs stamp-suite
against separately built peers (Teaparty, and the TWAMP-Light tools twampy and
cujo) in the roles and modes they share, through a loopback relay that records
payloads and traffic class. `--suite` selects `smoke`, `core`, `subsets`,
`pairs`, `other` or `full`. The exit status reports that the run completed, not
that the peers interoperate. No report from it is checked in; for a new run,
record the peer revisions, the suite and the wire reports.

The fixtures below are written separately from the Rust code. They test a
reflector and provide STAMP payloads that other tools can reuse. Read the
[profile limits](conformance/README.md#known-limits) before you treat an
exchange as evidence about another backend, platform or physical link.

[`scripts/interop_stamp.py`](../scripts/interop_stamp.py) drives a real
reflector. It has its own implementation of the wire layout, HMAC coverage,
reply checks and UDP metadata collection, written with only the Python standard
library. It does not import the Rust crate or call its sender. It needs Linux
and Python 3.10 or later. The profile uses the nix backend, IPv4 and IPv6
loopback, and software timestamps. A missing socket capability or a failed
check counts as a failure. The script never skips a check internally.

```sh
cargo build --locked
python3 scripts/interop_stamp.py --binary target/debug/stamp-suite --report /tmp/interop-default.json
cargo build --locked --all-features
python3 scripts/interop_stamp.py --binary target/debug/stamp-suite --report /tmp/interop-all-features.json
python3 -m unittest discover -s scripts/tests -v
```

Run the builds and the live suites one after another. Cargo can replace the
executable while another suite is still using it. `conformance.yml` runs both
build variants as gates and uploads the JSON wire records. The script starts
and reaps its own reflectors, uses ephemeral ports, and creates temporary key
directories with mode-0600 key files. It sends only to loopback and never
changes interface addresses or kernel policy.

## Fixture contract and scope

The `loopback-burst-fallback-v1` profile runs 16 configurations, one for each
combination of IPv4/IPv6, open/authenticated base packets, NTP/PTP reflector
timestamp format, and stateful/stateless sequencing. In every configuration the
sender uses a different timestamp format from the reflector. Each configuration
then exercises SSIDs 42 and 43, each with its own key from the key directory,
and SSID 99 with the default key. A complete successful run makes
48 exchanges and 192 validated replies. Both base modes include a keyed HMAC
TLV. The authenticated configurations also send 24 bases signed with the wrong
directory entry's key and expect no reply to them. They then
check that the next valid request still starts its session's sequence number
and counters at their initial values.

Each exchange sends a request for a burst of three copies. The request carries
Type 12, CoS, Direct Measurement, Follow-Up, Destination Node Address, SRv6
Return Path and HMAC TLVs. After the first copy arrives, the script sends an
ordinary request in between. Every reply is checked for its sequence number and
echoed fields, its source endpoint, the actual IP traffic class, TLV order,
flags and values, and HMAC coverage. Later copies must carry the same T2 and a
later T3, keep the requested CoS and source, and report the ordinary send in
between in their DM and Follow-Up fields. Any extra reply during the final
150 ms guard period fails the run.

SRv6 forwarding is disabled, so Type 10 must come back with U=1 and a valid
final HMAC. Its understood Type 4 child has U, M, I and the reserved header
bits cleared, but keeps the child type, length and segment bytes. The outer
fallback U flag does not allow the reflector to copy the sender's child flags
(RFC 9503 §4.1, RFC 8972 flags). Source matching runs over loopback, so
this fixture cannot show that source override works on a multihomed host. The
120 ms gap between burst copies leaves room for the interleaved request. It is
not a timing benchmark. Physical LAG, NIC timestamps and successful SRH
transit need their own tests.

## Reusable bytes and oracle checks

[`requests.json`](../tests/fixtures/interop/requests.json) holds 24 named
parameter sets, each with `burst_hex` and `ordinary_hex`. That gives
48 fixed UDP payloads, with no IP or UDP header and no host-dependent
field. Timestamps are fixed, valid wire values, so repeated requests are
identical byte for byte. The keys are public test values: `ab` repeated 16
times for SSID 42, `cd` for 43 and `ef` for the default key. Another
implementation's test harness can use these payloads as well, as long as its
session, key, CoS and burst policies match this profile. The launcher itself
expects stamp-suite's CLI.

The generator refuses to run if the checked-in bytes differ from what it
encodes. To change a fixture, regenerate it and review the diff:

```sh
python3 scripts/interop_stamp.py --write-vectors
git diff -- tests/fixtures/interop/requests.json
python3 -m unittest discover -s scripts/tests -v
```

[`replies-normalized.json`](../tests/fixtures/interop/replies-normalized.json)
holds four observed exchanges with the Return Path child flags normalized. It
also stores the binary, runner and request hashes and the platform the
exchanges came from. These are frozen regression inputs for the checker. They
are not normative timestamp values and not independent certification. The unit
tests replay them, then corrupt sequences, timestamps, clocks, counters, outer
and child flags, child framing and segments, CoS, endpoints and digests.
Mutations that change behavior are re-signed, so the checker has to reject them
for what they mean and not only for a broken digest. The SHA-256 primitive is
also checked against the truncated
[RFC 4231 §4.2 test vector](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2).
The historical [`replies.json`](../tests/fixtures/interop/replies.json) is kept
as it was. Its child U flags were copied from the request, so it must now fail
the oracle. Signed child mutations check that a valid HMAC cannot hide wrong
nested fields.

The live report records the SHA-256 of the binary, the runner and the request
fixture, the platform, the Python version and the UTC start time. It also
records every transmitted and received UDP byte it measured with the receive
metadata, the expected silences, the command arguments and the reflector's
stderr. Startup readiness exchanges go through a separate socket that stays
open, and they are left out of the measurement records. `expected_cases`,
`completed`, `passed` and `failed` tell a partial report apart from a complete
run. The exit status is nonzero if any case fails. A missing binary, a fixture
mismatch or an unsupported platform fails the preflight before any case report
is written. The report is rewritten after every case. Temporary key paths and
UDP ports are recorded to help with diagnosis. A replay does not reuse them.

## Independent successor BER profile

[`scripts/interop_ber.py`](../scripts/interop_ber.py) is a separate sender and
reflector for `draft-ietf-bpm-stamp-ber-01`, written with only the Python
standard library. It uses the agreed experimental outer Type 243 and pattern
sub-TLV Type 241. Neither value is an IANA assignment. It imports no Rust code
and no other peer implementation. Run it after each build, one at a time with
the other live suites:

```sh
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report /tmp/ber-interop.json
```

The `successor-ber-v1` profile requires 60 cases: both address families ×
three integrity profiles (open, keyed open, authenticated) × ten
configurations. Each group of ten has the stateful and stateless reflector
tests and eight sender tests (default or explicit five-byte pattern × baseline,
invalid observations, parent U and child U). A missing capability fails the
case instead of skipping it. `conformance.yml` runs this profile on both the
default and the all-features build, and uploads the reports even when a case
fails. The all-features build still selects nix.

The [17 request/expected-field vectors](../tests/fixtures/residual-ber/requests.json)
cover the default pattern clean and with errors, explicit four- and five-byte patterns,
unknown children, missing and duplicate padding, duplicate BER and pattern
TLVs, misalignment, short outer and nested values, truncated nested headers,
acknowledged prefixes, opaque remainders and the retired legacy outer types.
The reference bit counter builds an XOR bit string, and the four-bit error runs
are placed so they cross byte and pattern boundaries. Keyed cases verify the
HMAC over the actual reflected sequence number and metadata prefix. The padding
stays outside the HMAC coverage. An invalid extension HMAC must be copied back
with I set and the failed digest unchanged (RFC 8972 §4.8). An invalid
authenticated base packet must get no reply.

The sender cases decode the emitted requests with their own code and send back
crafted replies. The baseline case sends duplicates with the same sequence
number. The gates case returns signed replies with M, C or I set, duplicate
fields, wrong patterns, impossible counts and resized padding, plus a failed
digest in the keyed modes. None of these may add a BER sample. A nonzero error
count with a burst of zero still counts as an error-count sample, but not as a
burst sample. Errors in the reverse direction are injected separately. The
summary checks cover per-direction counts, denominators, error totals, burst
maximum and average, rates and interval sums. After a parent or child U flag,
later requests leave out BER, and delay and loss measurement carries on.

[`replies.json`](../tests/fixtures/residual-ber/replies.json) freezes all 12
reflector observations and 48 sender request/summary records from the default
build described here. Their provenance includes the binary, runner and vector
hashes. These are regression observations of this application, not independent
certification. The [`oracle tests`](../scripts/tests/test_interop_ber.py)
replay them, alter the signed meaning, digests, echoes, padding and summaries,
and check how failures are recorded in the report. The HMAC primitive has an
RFC 4231 known-answer test. Requests are regenerated only when you pass
`--write-vectors`, and the live preflight rejects unexpected changes.

Reports contain the commands, process outcomes, stdout and stderr, UDP bytes
and endpoints, expected silences, platform and tool versions, UTC time and
hashes. The warmup socket stays open for the run but is kept separate from the
measurements. Reflectors bind a port chosen by the kernel and announce
readiness in their startup log. Every case is attempted, the report is
rewritten after each one, and any failure gives a nonzero exit. A report with
`completed=false` is incomplete evidence. The only keys are public fixture
values.

These tests run over software loopback with valid UDP checksums. They do not
prove that bit errors on a physical link are captured, or that PMTU discovery
works. Black-box captures against Teaparty showed BER layouts incompatible
with the successor profile, and no successor-profile exchange with another
maintained application has been shown yet.

## Protocol sources and complementary coverage

The encoder and checker are built from the frozen sources below, not from
layouts generated from the Rust code. Draft rows refer to the pinned revision.

| Source | Fields used by the independent profile |
| --- | --- |
| [RFC 8762 §§4.2–4.4](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.2) | 44/112-byte bases, sequence/echo, timestamp Z bit, truncated base HMAC over the first 96 authenticated bytes |
| [RFC 8972 §§4.4–4.8](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.4) | CoS, DM, Follow-Up and HMAC TLV; digest covers the reflected sequence followed by preceding TLVs |
| [RFC 9503 §§3–4](https://www.rfc-editor.org/rfc/rfc9503.html#section-3) | Destination Node Address (Type 9), Return Path (Type 10), SRv6 segment-list sub-TLV (Type 4), fallback flag |
| [RFC 10052 §§3, 4.3](https://www.rfc-editor.org/rfc/rfc10052.html#section-3) | Type 12 count, interval, minimum size and composition |

The wire suites below build their bytes by hand and use
[`common/wire_hmac.rs`](../tests/common/wire_hmac.rs), which calls `hmac` and
`sha2` directly. A test can still run the production receiver as the system
under test. [`common/wire_mode.rs`](../tests/common/wire_mode.rs) holds the
open, keyed and authenticated layouts, with offsets written out from the RFCs
rather than taken from the crate. Matrix loops create a
[`common/case.rs`](../tests/common/case.rs) guard, so a failed assertion
prints the combination it failed in.

| Combination | Reproducible coverage and limits |
| --- | --- |
| Key directory + fallback + queued rotation/revocation | `cargo test --locked --test keyset_fallback_test`; IPv4/IPv6, open/auth, per-SSID and default keys; wire signing and verification done outside the crate |
| Bursts + CoS + software/kernel Follow-Up | `cargo test --locked --all-features --test burst_transmission_test`; HMACs checked outside the crate, actual IP traffic class and interleaved ordinary packets |
| Sessions + cap + authentication/replay/rotation | `cargo test --locked --test session_auth_admission_test --test session_capacity_test`; the first uses the independent HMAC helper; checks that rejection happens before admission or refresh, and checks overload behavior |
| Required micro-session + absent/U/I TLV | `cargo test --locked --test required_micro_session_test`; real sender against a raw peer that signs on its own; [RFC 9534 §3.2](https://www.rfc-editor.org/rfc/rfc9534.html#section-3.2), logical identifiers only |
| Mixed clocks and advertised clock quality | `cargo test --locked --test mixed_clock_test`; a peer that encodes and signs on its own, with a set time offset and synchronization metadata |
| Source/SRH fallback failures | `cargo test --locked --lib receiver::transmit`; shared finalizer tests inject combined transport failures and verify the final signatures; the syscall source tests are Linux-specific |
| Scoped IPv6, real routing/MTU and SRH | `scoped_ipv6_test`, `route_mtu_test`, `netns_conformance`; separate ignored tiers, see [tests that need privileges](../tests/README.md#tests-that-need-privileges-or-namespaces) and the [namespace guide](testing-netns.md). Compare the SRH capture with the reported fallback. Neither a skip nor a fallback counts as successful SRH evidence. These suites still use some production packet and TLV helpers. |

Malformed-input properties, fuzzing, telemetry and session-identity tests cover
combinations that these fixtures do not.
