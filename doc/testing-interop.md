# Independent protocol-combination fixtures

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

SRv6 forwarding is **disabled deliberately**. Type 10 must return U=1, with a
valid HMAC after that final mutation. This tests composition with the fallback;
it does not prove that an SRH was transmitted. Destination Node Address matches
the loopback interface on a wildcard bind. Its accepted flag and actual source
are checked, but that address also matches the kernel's usual route choice, so
this profile alone cannot prove source overriding on a multihomed host. Existing
source syscall tests, scoped-IPv6 fixtures and namespace scenarios provide the
separate coverage described below. No physical LAG, hardware timestamp, external
vendor certification, accurate OWD or exact nanosecond scheduling claim is made.
The 120 ms requested gap permits interleaving under ordinary test-host load;
this is a correctness regression, not a throughput benchmark.

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
exchanges from the pre-O10 binary, with its SHA-256 and platform provenance.
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

## Protocol sources and complementary coverage

The encoder/checker uses the following frozen sources, not generated Rust
layouts. Draft support remains explicitly work in progress.

| Source | Fields used by the independent profile |
| --- | --- |
| [RFC 8762 §§4.2–4.4](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.2) | 44/112-byte bases, sequence/echo, timestamp Z bit, truncated base HMAC over the first 96 authenticated bytes |
| [RFC 8972 §§4.4–4.8](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.4) | CoS, DM, Follow-Up and HMAC TLV; digest covers the reflected sequence followed by preceding TLVs |
| [RFC 9503 §§3–4](https://www.rfc-editor.org/rfc/rfc9503.html#section-3) | Destination Node Address (Type 9), Return Path (Type 10), SRv6 segment-list sub-TLV (Type 4), fallback flag |
| [asymmetrical-pkts-14 §§3, 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-ippm-asymmetrical-pkts-14#section-3) | Type-12 project code point, count/interval/minimum size and composition; no claim of a final IANA allocation |

O10 also removes production HMAC helpers from the five existing wire suites
below. They assemble base/TLV bytes manually and now pass their independently
selected coverage bytes to [`common/wire_hmac.rs`](../tests/common/wire_hmac.rs),
which uses `hmac`/`sha2` directly. Key/admission tests still invoke the receiver
and mutate its state in process; that is the system under test, not their codec.

| Combination | Reproducible coverage and limits |
| --- | --- |
| Key directory + fallback + queued rotation/revocation | `cargo test --locked --test keyset_fallback_test`; IPv4/IPv6, open/auth, per-SSID/default keys; independent wire signing/verification |
| Bursts + CoS + software/kernel Follow-Up | `cargo test --locked --all-features --test burst_transmission_test`; independent HMAC checks, actual IP traffic class and interleaved ordinary packets |
| Sessions + cap + authentication/replay/rotation | `cargo test --locked --test session_auth_admission_test --test session_capacity_test`; the former uses the independent HMAC helper; checks rejection before admission/refresh and overload behavior |
| Required micro-session + absent/U/I TLV | `cargo test --locked --test required_micro_session_test`; real sender vs raw peer, independent signing; [RFC 9534 §3.2](https://www.rfc-editor.org/rfc/rfc9534.html#section-3.2), logical identifiers only |
| Mixed clocks and advertised clock quality | `cargo test --locked --test mixed_clock_test`; independently encoded/signed peer with explicit time offset and synchronization metadata |
| Source/SRH fallback failures | `cargo test --locked --lib receiver::transmit`; shared finalizer tests inject combined transport failures and verify final signatures; syscall source tests are Linux-specific |
| Scoped IPv6, real routing/MTU and SRH | `scoped_ipv6_test`, `route_mtu_test`, `netns_conformance`; separate ignored privileged tiers, see [test inventory](../tests/README.md) and [namespace guide](testing-netns.md). Inspect SRH capture versus reported fallback; neither a skip nor fallback is successful SRH evidence. These suites still use some production packet/TLV helpers. |

This is a bounded combination suite, not the Cartesian product of every TLV,
policy, platform and packet shape. Existing malformed-input properties, fuzzing,
sender telemetry and session-identity tests retain their separate scope.
