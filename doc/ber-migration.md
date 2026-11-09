# BER successor migration

T5 migrates from `draft-gandhi-ippm-stamp-ber-07` to
[draft-ietf-bpm-stamp-ber-01](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-ber-01.txt)
(2 November 2026). The successor identity and revision were checked against
[Datatracker](https://datatracker.ietf.org/doc/draft-ietf-bpm-stamp-ber/)
on 9 November 2026. This is an incompatible draft-feature change for the next
minor release, planned as 1.1.0; it must not enter a 1.0.x compatibility patch.

## Delivery boundaries

1. **T5a, codec and design:** add a bounded successor value codec, independent
   vectors, property tests, malformed nested inputs and a fuzz target. Keep
   endpoint dispatch, CLI behavior, legacy allocations and the standards pin
   on the existing profile. That preparatory chunk was committed as `04de534`.
2. **T5b, endpoint integration:** switch both roles, observation validation,
   HMAC signing, padding correction, MTU fitting and configuration together.
   Retire the legacy wire profile explicitly and test the migration boundary.
3. **T5c, evidence:** complete independent live wire checks for IPv4/IPv6,
   open/keyed/authenticated modes and malformed nested TLVs. Rebuild the
   conformance matrix and change the standards identity/pin only once the
   endpoints implement the successor. Record independent-peer limitations.

## Format comparison and codec contract

| Revision | BER fields and pattern |
|---|---|
| gandhi -07 and ippm -00 | Separate top-level pattern, count and optional maximum-burst TLVs; two-byte default pattern. |
| ippm -01 | One TLV with a four-byte count; optional pattern and maximum-burst sub-TLVs. Explicit patterns have a length divisible by four. |
| bpm -01 | One TLV with two fixed four-byte fields: count, then maximum burst. Optional pattern sub-TLV; its value needs at least four bytes. Default pattern is `FF00FF00`. |

The successor's minimum value length is eight. It can carry zero or more
framed sub-TLVs, with at most one known pattern sub-TLV. A five-byte pattern
is valid; padding must still contain whole repetitions. A burst value of
zero can mean that the reflector cannot calculate it, even when the count
is nonzero; it must not cause the sender to invent a clean burst sample or
discard an otherwise usable count.

`ResidualBerValue` encodes/decodes values without registering any type in
the endpoint dispatcher. It checks the 16-bit outer length and every nested
header/value bound. Encoding checks lengths before appending output. Unknown
sub-TLVs and complete flag octets survive decoding unchanged. A separate
pattern accessor checks duplicates and the minimum pattern length; absence
remains distinct from an explicit empty pattern. The codec imposes no count
versus padding relationship because it has no packet/session context.

Successful decoding is not revision detection or negotiation. Callers must
agree on a wire revision and codepoints, apply flag and integrity checks,
and validate counts against the admitted padding size before using metadata.
The codec preserves malformed semantic inputs for later flagging; it does
not itself acknowledge unknown sub-TLVs, compute BER or alter packet flags.

## Activation and legacy compatibility

T5b makes the successor the sole active BER wire profile.
Do not infer a legacy format from lengths or reuse top-level Types 240–242
for a different layout. Retired legacy types must receive U rather than be
silently interpreted as successor BER. A peer that does not support the
chosen successor type should return U, disabling BER while delay/loss
measurements continue. Endpoint tests verify that legacy types get U and an unsupported successor
response disables BER without losing delay/loss measurements.

The outer TLV uses experimental Type 243; its optional pattern sub-TLV uses
experimental Type 241 until IANA assigns TBA1/TBA2. Their registries are
separate.
Avoid the legacy Type 242/Heartbeat collision and the assigned RFC 9503
Types 9/10. These are local allocations requiring explicit peer agreement,
not IANA assignments. They are recorded in `src/tlv/experimental.rs` and the
conformance inventory. Legacy Rust helper types remain serialization utilities
for historical fixtures; byte dispatch returns U for their retired types.

CLI/TOML validation now enforces the successor format:
explicit patterns shorter than four bytes return a migration error,
and the successor always carries the fixed maximum-burst field. The legacy
`--ber-omit-burst` workaround cannot remove it. The obsolete flag/TOML value
is rejected with an actionable error, even if BER is disabled. The default pattern is four bytes; empty or unaligned padding
is rejected. For example, replace `--ber-pattern aa55` with
`--ber-pattern aa55aa55` and use a padding size divisible by four. Five-byte
patterns are allowed with padding sizes divisible by five. Omission uses
`FF00FF00` without sending an explicit pattern sub-TLV.

Reflector integration must distinguish framing errors (M on a short outer
value or malformed known sub-TLV) from conformance errors (C for missing or
duplicate padding, duplicate BER or pattern TLVs, and pattern misalignment).
The draft requires both M and C when the outer length is below eight.
Unknown sub-TLVs receive U and retain their values. Stop processing at a
malformed boundary and preserve the opaque remainder; do not convert it to
the default pattern. Verify HMAC/session admission before counting or repairing
padding. Apply the same checks to sender observations, including nested U,
M and I. Re-sign metadata after all edits and mark resized denominators unusable.

## Independent peer finding

The draft lists Teaparty commit
[`592558a38dbcf9b273acb2a2fe8ab0d8f16d0709`](https://github.com/cerfcast/teaparty/commit/592558a38dbcf9b273acb2a2fe8ab0d8f16d0709).
It was built with its pinned nix submodule and run only as a black-box peer;
no implementation code, tests or comments were copied.

[IPv4 and IPv6 captures](../tests/fixtures/residual-ber/teaparty-592558a.json)
show Extra Padding Type 1 followed by separate four-byte Types 9 (count) and
10 (pattern). These are not the successor's combined value; Types 9 and 10
are assigned to RFC 9503 extensions. The capture is incompatibility evidence,
not a successful successor exchange or a reason to adopt those codepoints.
Check a newer independent implementation before making an interoperability
claim. Cisco IOS XR 26.1.1 is another implementation named by the draft;
no Cisco device was available for this check.

## Test evidence

[Hand-encoded values](../tests/fixtures/residual-ber/values.json) derive directly
from the draft's field diagrams. Tests cover network byte order, omitted and
explicit patterns, five-byte patterns, zero burst with nonzero count, unknown
sub-TLVs/flags, truncation, duplicates, short patterns and aggregate length
limits. Property tests exercise arbitrary bytes and generated nested values.
The `residual_ber_value` fuzz target uses the same framing/semantic boundary;
its CI corpus is seeded from these independent hex vectors.

The [BER matrix](conformance/draft-stamp-ber.md) now records the retired
legacy profile as Excluded. T5c will replace it with successor requirements
and independent live evidence, then move the monitored identity/pin. The
replaced-draft standards finding remains open until that evidence is complete.

T5a local validation: eight codec tests and the complete all-feature suite
pass (1,398 tests, 12 privileged tests ignored). Rust 1.87 checks the production
library; Clippy, Rustdoc, formatting, Python tests and conformance bookkeeping
pass. A 31-second seeded libFuzzer run completed 9,042,076 executions with
address and leak checking enabled. This is parser evidence, not live endpoint
or physical-link BER evidence.

## T5b endpoint behavior

Both roles use the combined value. The sender validates parent and nested
flags after integrity/session admission, rejects duplicate or mismatched
patterns and changed padding denominators, and disables BER on an admitted
U response while keeping delay/loss measurements. Nonzero count with zero
maximum burst contributes a count sample but no burst sample; JSON/CSV retain
null burst values and zero burst sample counts when unavailable.

The reflector checks BER before other semantic updates so malformed nested
framing preserves the outer processing stop boundary. Short known pattern
values get nested M; unknown sub-TLVs get U and retain their values. Missing or
duplicate padding/BER/patterns and misalignment get outer C. Short outer values
get both M and C. Invalid HMAC metadata and padding remain opaque.

The sender fits padding in whole pattern repetitions after accounting for the
combined metadata. Linux reply fitting handles both a single BER reply and a
reply with optional reflected headers: remove eligible headers first, then
reduce BER padding if needed. Resized metadata gets C and is signed again.
Route-MTU lookup is still Linux-only; no end-to-end path-MTU probing or
physical-link BER accuracy is implied. T5c's independent wire evidence and
successor conformance scoring remain pending.

T5b local verification: default/all-feature/pnet suites pass 1,307/1,408/1,263
tests (12/12/13 privileged tests ignored). All three Clippy profiles, Rust 1.87
all-target checks, Rustdoc, root/fuzz formatting, Python tests and bookkeeping
pass. Default production cross-checks compile for macOS and Windows; their
native runtime evidence remains pending. A final seeded reflector fuzz run
passed 820,478 executions in 31 seconds with ASan/LSan enabled. This validates
parser/assembly paths; T5c still owns independent live-wire conformance evidence.
