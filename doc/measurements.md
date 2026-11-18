# Sender reply and directional measurements

What the sender reports about replies, Direct Measurement counters, Follow-Up
delays, clock quality and session state.

JSON reports include `measurements` and `ber` objects, and text reports print a
summary of each. CSV embeds JSON in the `ber`, `measurements` and
`owd_clock_quality` columns. Read CSV columns by name, and use a CSV parser so
the quoted commas inside the JSON are handled. `owd_clock_quality` is empty
when there are no OWD samples.

```bash
stamp-suite --remote-addr 192.0.2.10 --count 100 --direct-measurement \
  --follow-up-telemetry --reflected-control-count 3 --timeout 2 --output-format json
```

The reflector has to support the extensions you request. Follow-Up needs a
stateful reflector. A stock reflector keeps Reflected Test Packet Control
(RFC 10052) off until it is started with `--reflected-control-max-count`, and
it can limit or refuse the burst you ask for. The `--ber` options add bit and
packet error totals for each direction in a separate `ber` object.

## Probes, reply copies, and duplicates

`packets_received` and the RTT and OWD fields count the first accepted reply
to each pending probe. `packets_lost` and the loss percentage count probes
that timed out, pending records that were retired, and records still
unanswered when the run ends. If a probe has already been counted as lost, a
late first reply does not undo the loss or add a top-level delay sample.
Prometheus and SNMP counters and `-R` details count probes the same way.

Limiting the number of pending records is optional (`--max-pending-probes`,
default 0, meaning no limit). The `measurements` fields `pending_limit`,
`pending_probes`, `pending_high_watermark` and `pending_evictions` show how
hard the sender pushed against that local limit. Reusing a sequence number
also retires the old unanswered generation and counts it, instead of quietly
overwriting it. These retirements say nothing about loss on the network. They
do not change send timing or the reply denominators. See
[retention policy](usage.md#pending-probe-retention).

The reply collector runs after base authentication, TLV validation and session
admission. It matches the full echoed sender sequence number and all eight
bytes of the wire timestamp (T1) against a pending probe or the retained
history. Only after that does it apply the SSID policy, learn IDs, acknowledge
Access Reports or act on CE feedback. A reply with a known sequence number but
a missing or different T1 is rejected. The collector counts individual
reflected packets:

| Field | Meaning |
| --- | --- |
| `requested_replies` | Probes sent successfully, multiplied by the configured reply count (at least one). |
| `unique_replies` | Distinct accepted replies within the retained history, including late replies. |
| `answered_probes` | Retained probes with at least one accepted reply, including late first replies. |
| `additional_replies` | Distinct replies that arrived after a probe's first reply, including requested burst copies. |
| `late_replies` | First replies to retained probes that were no longer pending. |
| `duplicate_replies` | Replies whose `(echoed sender sequence, echoed T1, reflector sequence, T3)` repeats a recent reply. |
| `unknown_replies` | Replies that match neither a retained probe nor a pending probe. |
| `mismatched_replies` | Replies with a known sequence number but a missing or different echoed T1. They do not use up a pending probe or update measurement or control state. |
| `reordered_replies` | Replies whose reflector sequence is behind the highest one seen, compared with 32-bit serial arithmetic. |
| `unobserved_requested_replies` | Requested copies minus observed copies, capped separately for each probe. |
| `reply_rtt` | Count and cumulative minimum, mean and maximum RTT over all unique replies. |

`last_reflector_sequence` holds the most recent reflector sequence number seen.
`independent_sequence_observations` counts replies where that number differs
from the echoed sender sequence. Neither shows which sequencing mode the peer
uses, and a counter reset can look like reordering. The sender does not infer
directional loss from sequence gaps alone.

When a kernel TX timestamp corrects T1 for delay calculations, the wire T1
stays as it was sent. A delayed TX report also has to match the local send
context before it can correct a pending probe. These checks tell apart reused
sequence numbers that carry different wire timestamps. They are not
cryptographic replay protection. If a peer repeats the same sequence number
and wire T1, or a clock reset produces the same pair again, those bytes alone
cannot show that a reply is fresh. Unauthenticated traffic still relies on the
deployment's trust boundary.

When a sequence number is reused, the session-state monitor replaces the older
outstanding deadline. The old deadline can then neither expire the newer probe
nor linger after the newer probe is answered.

Lenient reply parsing can zero-fill unused fields at the end of a short reply,
but it cannot make up identity bytes. An unauthenticated reply has to include
the whole echoed T1, which ends at byte 36. A 41-byte TWAMP Light reply does.
Authenticated replies also have to pass the base HMAC check. Short requests
arriving at the reflector follow a separate parsing policy. TLV diagnostics
are counted before this identity check, so a stale reply that is rejected can
still add diagnostic counts. When a Micro-session ID is required, a reply is
accepted only as the first reply to a live pending probe or as an additional
copy for a retained probe that was already answered.

Requested replies can go unobserved because of policy caps, unsupported
requests, validation rejection, timeouts or network loss. **They are not a
network-loss estimate.** Extra replies to one probe cannot make up for
another probe's missing ones. With bursts, the final receive phase keeps
running after the first reply until every requested copy has arrived or the
final `--timeout` expires. An Access Report acknowledgement confirms that the
report was delivered, not that the reply burst it asked for is complete. An
echo with the U flag set is not an acknowledgement, so a reflector that does
not process the report receives every retry. Once
delivery is acknowledged or abandoned, replies to the remaining retries are
collected for up to `--timeout` after the last successful retry. An
acknowledgement, or running out of retries, does not restart that window. The
same rule covers retries sent near the end of the initial reply drain.
`--on-zero-ssid stop` ends reception early. A run without bursts finishes as
soon as every probe has its first accepted reply. Packets that arrive after
that are unobserved.

The histories of recent probes and of reply identities each keep at most
**4096** entries. `history_limit`, `probes_evicted` and `replies_evicted`
report the limit and how many entries were evicted. A probe that is still
pending can supply timing after it leaves the history, but its original
Direct Measurement ordinal is lost. Replies outside the retained histories
cannot be correlated or deduplicated. After an eviction, an old duplicate can
show up as an additional reply if its probe is still known. Identical
stateless burst copies with the same T3 cannot be told apart from network
duplicates, because the packet has no field that identifies the copy.

## Extension validation diagnostics

Interim and final JSON reports include `measurements.tlv_validation`, and CSV
embeds it in the `measurements` column. Getting an RTT back does not show that
the reflector processed the extensions or that the TLVs arrived intact.

| Field | Meaning |
| --- | --- |
| `evaluated_replies` | Replies whose TLVs were evaluated, including required Micro-session ID checks on an empty list. |
| `rejected_replies` | Evaluated replies discarded because required Micro-session ID validation failed. |
| `observed_tlvs` | Every parsed TLV occurrence, including HMAC and the duplicate HMAC entries that lenient parsing keeps. |
| `hmac` | Reply counts for the `not_requested`, `missing`, `verified`, `unverified` and `failed` TLV HMAC outcomes. |
| `flags` | TLV occurrence counts for `unrecognized` (U), `malformed` (M), `integrity_failed` (I) and `conformant_reflected` (C). M also counts truncation and invalid known-type lengths that the sender found itself, even if the peer did not set M. |
| `by_type` | Occurrence and flag counts grouped by the decimal wire type codepoint; for example, `"8"` is HMAC and `"11"` is Micro-session ID. |

The counts are taken before SSID admission and deduplication, so they include
repeats and replies that are rejected later. Packets dropped before
evaluation, such as those that fail the base HMAC, are not counted. Base-only
replies add nothing, and neither do empty TLV lists when no Micro-session ID
is required. The counters survive reply-history eviction.

The sender decides whether a reply carries extensions from the received
payload length, even when it sent a base-only probe. It checks the length of
every known outer TLV before using any value, including types this run does
not use. The first M stops processing of later values, whether the peer set it
on the wire or the sender derived it. HMAC verification runs over the bytes as
received, so local diagnostic markers do not change what the signature
covers. A usable base reply still gives an RTT when the extensions are
unusable. Replies that fail a required identity check are still rejected.

For Location, an invalid nested header or body, or an invalid known-type
length, also sets M on the outer TLV. A child M received from the peer is
promoted to the local outer diagnostic and stops processing of later outer
values. The I bit of a Location child is ignored. These counters count outer
TLV occurrences, so nested errors do not add child entries to `by_type` or
`observed_tlvs`.

In Timestamp Information, an incomplete optional child also sets M on the
outer TLV, even when this sender does not use that TLV. Complete unknown
children are treated as opaque and do not add child entries to the outer-TLV
counters.

The HMAC outcomes mean:

- `not_requested`: there was no HMAC or no key.
- `missing`: a key is configured but an optional or exempt HMAC was absent. A
  missing required HMAC counts as `failed`.
- `unverified`: the HMAC could not be verified, for example because there is
  no key or the flags make it unusable.
- `verified`: the digest matched, but an I flag can still block values.
- `failed`: TLV values are blocked. Base timing may still be usable unless a
  required session binding fails.

Flags count parsed occurrences, including the M the parser adds on
truncation. They do not count every error inside a typed value, and one TLV
can carry several flags. Clear flags, or C on its own, do not prove the values
are usable, because the HMAC and any earlier M also matter. A TLV missing from
the reply is not counted as unsupported.

## Direct Measurement counter window

[RFC 8972 §4.5](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.5)
defines the three counters. The window estimates below are this
implementation's own reporting policy. They only make sense when both
endpoints count the same session and packet profile. Other in-profile traffic
or duplicate requests can change the result.

`direct_measurement.anchor` is the first usable counter observation in the
current window. `latest_transmit` is the observation with the highest
reflector transmit count in that window. Both contain `sender_tx`,
`reflector_rx` and `reflector_tx`. Differences use wrapping 32-bit arithmetic.
A span longer than half the counter range is treated as a reset or an older
epoch rather than as forward progress. The echoed sender counter must equal
the number of successful sends the sender recorded. Reflector counters that
are all zero do not show that the reflector supports the measurement.

Once there are at least two distinct usable observations:

- `sender_packets` is the largest sender-counter difference from the anchor.
- `reflector_received` is the largest receive-counter difference seen at an advancing transmit count.
- `forward_missing` is `sender_packets - reflector_received`, or null if negative.
- `reflector_transmitted` is the largest transmit-counter difference from the anchor.
- `replies_received` counts distinct usable transmit-counter values after the anchor.
- `reverse_missing` is `reflector_transmitted - replies_received`, or null if negative.

For example, the observations `(S,Rrx,Rtx) = (1,1,0), (3,2,1), (4,3,3)` give
forward missing 1 and reverse missing 1 over that window. A late observation
for transmit counter 2 closes the reverse gap. The estimates are provisional,
because packets in flight, reordering and rejected metadata can leave gaps
that later fill in. Reverse missing counts missing *usable counter
observations*. That includes replies whose DM metadata was missing or
rejected, and the count cannot tell those apart from transport loss.

The anchor itself is not part of the differences. Nothing is inferred about
packets before the anchor, an unobserved tail, or windows discarded after a
discontinuity. Until there is enough usable data, the fields are null, not
zero. `observations`, `unavailable`, `discontinuities` and `reordered` count
how the counter observations were handled, usable or not. Repeated transmit
counters on distinct replies, backward spans beyond half the range, and
detected resets invalidate the current estimates. The set of distinct counter
values holds at most 4096 entries. Going over that clears the window and sets
the `history_exceeded` flag, which stays set. The next usable observation
starts a new window. Totals are not carried across discarded windows.

## Follow-Up corrected reverse delay

[RFC 8972 §4.7](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.7) gives
the sequence number, timestamp and timestamping method of the previous
reflection. The sender looks up that reflector sequence number in its recent
reply history and computes `previous T4 - corrected T3`, applying
`--reflector-utc-offset`. The timestamp is decoded in the NTP or PTP format of
the previous packet. Neither the current packet's format nor the Follow-Up
timestamping-method byte affects decoding.

`follow_up.reverse_delay` holds the cumulative sample count and the minimum,
mean and maximum in signed milliseconds. `matched` counts corrections.
`repeated` counts later references to a reply that was already corrected.
Only the first usable correction for a uniquely identified reply adds a
sample. `unmatched` counts references to replies that are not in the history,
including replies that have not arrived yet. These references are not queued
to be resolved later. `ambiguous` counts reused or self-referencing sequence
numbers and possible stateless burst identities. Unknown methods, zero
placeholder timestamps and invalid timestamps count as `unavailable`. The last
reply gets no correction unless another reply carries a Follow-Up for it.

These timestamps do not synchronize the clocks. Clock skew still affects the
signed reverse delay, and a software Follow-Up timestamp is not necessarily
more accurate than the original one. Follow-Up does not replace the original
OWD summary.

## Integrity and BER

Active BER uses the combined successor TLV (experimental Type 243) with an
optional pattern sub-TLV (Type 241). The default pattern is the four bytes
FF00FF00. The U, M, I and C checks on the parent and nested TLVs run before
anything is recorded. U on the BER TLV or a sub-TLV, in any TLV order, sets
`disabled_by_peer`; U on the Extra Padding TLV alone only drops that sample.
A nonzero error count with a maximum burst of zero still
records its bit and packet error sample but no burst sample. Burst maxima and
averages that are unavailable stay null. Legacy outer Types 240–242 are not
interpreted. See [migration guidance](ber-migration.md).

DM and Follow-Up need exactly one usable TLV of their type. U skips a value, M
stops processing of the rest, and any I flag blocks all values. A bad length
stops processing of later values. With a key configured, these measurement
values also need a verified HMAC TLV. Missing, invalid or unverifiable
metadata adds no directional sample, but the authenticated base reply is
still counted. Without a key, these measurements are not authenticated.

BER records one observation per probe, taken from the first accepted reply to
a pending probe. Burst copies therefore do not count the forward bit errors
again or inflate the reverse BER totals. The `ber` object holds the
directional totals, intervals, alarms and omission counts. It is not a
per-copy BER metric. See [BER history](statistics.md#memory-and-ber-history),
the [TLV reference](architecture.md#tlv-extensions-reference) and the
[BER draft conformance](conformance/draft-stamp-ber.md).

## Clock quality accompanying delay

`owd.clock_quality` in JSON and `owd_clock_quality` in CSV describe exactly
the original OWD samples, the ones taken from first replies to pending
probes. Text reports show their synchronization categories and the largest
combined advertised error. `measurements.follow_up` has its own
`clock_quality` object. It covers only the matched correction samples and
uses the metadata of the referenced previous reply. Missing or ambiguous
references and duplicates add no quality samples.

| Field | Meaning |
| --- | --- |
| `samples` | Number of delay samples described. |
| `both_synchronized` | Both endpoints set S=1 and sent valid nonzero error multipliers. |
| `unsynchronized` | The error estimates are usable, and at least one endpoint set S=0. |
| `invalid_estimate` | At least one error estimate is invalid, such as Multiplier=0. |
| `unknown` | Local or remote quality metadata is unavailable (for example, samples recorded through the library without metadata). |
| `last_sender`, `last_reflector` | The most recent sample's S bit, NTP/PTP format, Scale, Multiplier and decoded `error_ms`; null when there is no metadata. |
| `max_combined_error_ms` | The largest sum of two usable advertised errors over the samples; null if there is none. |

The four categories do not overlap and add up to `samples`. An invalid error
is reported as null, never as zero uncertainty. The maximum also includes
usable estimates from unsynchronized clocks, so it is **not a bound on actual
OWD accuracy**. A later unknown sample clears `last_sender` and
`last_reflector`, but the cumulative counts and the maximum from earlier
usable estimates are kept.

For its own side the sender uses its configured Error Estimate, not the sender
field the reflector echoes back. The remote estimate comes from the accepted
base reply. The S bits are only what the operator and the peer declare.
Neither proves that NTP or PTP is locked, that a PHC is aligned, or that the
clocks share a timescale. The small default scale and multiplier are
configured wire values, not a measured timing precision. RTT and OWD values
are reported even when a clock is declared unsynchronized or the declaration
is invalid. The metadata describes the samples and never removes them.

[RFC 8762 §4.2.1](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.2.1)
uses the error formula from
[RFC 4656 §4.1.2](https://www.rfc-editor.org/rfc/rfc4656.html#section-4.1.2):
`error_seconds = Multiplier * 2^(Scale - 32)`. A zero Multiplier is invalid.
The same error units apply to NTP and PTP timestamps. A set S bit asserts
synchronization to an external UTC source, whatever the Z bit says.

Set `--clock-synchronized`, `--error-scale`, `--error-multiplier` and
`--reflector-utc-offset` to match how the endpoints' clocks are set up. The
sender does not detect clock discipline or discover timescale offsets.

## Session-state notifications

These notifications follow draft-ietf-ippm-stamp-ext-hdr-26 §9.2.

The sender logs state changes with target `stamp_suite::session_state` and
includes `session_state` in the `measurements` part of its summaries. The
session becomes active after a validated reply while the sender is
transmitting. It becomes failed after `--session-loss-threshold` consecutive
unanswered probes, and active again when replies come back. Each probe's
deadline is its `--timeout`, so a timeout of 0 turns off loss-driven failure.
A session that never got a reply also becomes failed once it reaches the loss
threshold. The sender reports idle when it stops transmitting. Replies
collected during the final drain still count toward timing and loss, but they
do not make an idle sender active again. If an Access Report retry sends
another probe, monitoring resumes and that probe's loss deadlines are tracked
until the retries finish. On ordinary errors or cancellation the monitor is
dropped, and it reports idle if a transition is needed.

Notifications count probes, not requested burst copies. Duplicate replies,
replies for invalid sessions and unauthenticated replies do not reset failure
detection. A validated reply to a newer probe ends the current loss run. Older
unanswered probes still count as packet loss but cannot cause a new failure
after recovery. Notification counters are cumulative. Individual events are
only logged, not stored. Give the endpoints enough capacity for the traffic
you send, and compare failed states with the reflector's queue, session-cap
and rate-limit counters: a missing reply looks the same whether the reflector
was overloaded or the path lost it.

## ECN observations

`--cos` adds `measurements.ecn` to JSON and to the CSV `measurements` cell,
and text reports print the same counters. Without `--cos` the object is
absent. The counters cover accepted distinct reply copies, including retained
late replies and additional burst copies. Duplicates, wrong SSIDs, stale
echoed timestamps and rejected replies are not counted.

`requested_ecn` is the configured EC1 request. `configured_egress_ecn` is the
marking the local socket accepted, or null when that is unavailable. A
successful socket setting does not prove the packet keeps that marking after
local traffic policies, or on the wire. On Linux and macOS the sender reads
the reply's IP ECN for all four requested codepoints, including Not-ECT and
CE. Other platforms report the IP metadata as unavailable. AIMD still starts
only for ECT(1) and ECT(0), and these observation counters do not drive it.

The four entries of `received_ec2`, `echoed_ec1` and `reply_ip_ecn` count
Not-ECT (0), ECT(1) (1), ECT(0) (2) and CE (3), in that order. `rpe` and `rpd`
use the numeric wire order 0, 1, 2, 3. RPE=0 is compatible with legacy
reflectors. Under
[draft-ietf-bpm-stamp-cos-ecn-00](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-cos-ecn-00.txt),
1 reports that the reflector could apply neither EC1 nor Not-ECT, 2 reports
the Not-ECT fallback, and 3 reports that EC1 was applied. RPE=2 alone cannot
tell a policy refusal from a platform limitation. RPD=1 reports a DSCP policy
refusal and does not mean ECN was refused. `conformant_reflected` counts CoS
C flags separately from RPE.

`usable_cos` needs exactly one CoS TLV that U/M processing reaches, no I flag
anywhere in the list, and a verified TLV HMAC when a key is configured. A CoS
TLV that is missing, ambiguous, malformed or failed integrity counts as
`unavailable_cos`, and the sender does not read received values from its
zeros. C does not erase the raw observation, but it keeps it out of the
reverse comparison. Reply IP metadata is not covered by TLV integrity
protection, and it is recorded on its own, including when CoS is unavailable.

`reverse_comparable` and `reverse_unknown` keep their meaning and equal
`reverse.comparable` and `reverse.unknown` in the directional diagnostics
below. The raw histograms are separate totals. Use the paired transitions to
analyze changes. The underlying CoS profile is
[draft-ietf-bpm-stamp-cos-ecn-00](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-cos-ecn-00.html),
a work in progress.

### Directional ECN diagnostics

`measurements.ecn.forward` compares the marking the local socket accepted with
the validated ingress EC2 from the same reply. If the local marking or a usable
CoS TLV is missing, the comparison is unknown. RPE, C and the echoed EC1 limit
what the sender can conclude about reverse marking, but they do not erase a
usable forward ingress observation.

`measurements.ecn.reverse` compares the echoed EC1 with that reply's IP ECN
only when CoS is usable, C=0, RPE=3, EC1 matches the request and IP metadata
is available. An RPE=2 refusal with a Not-ECT reply counts as unknown, not as
bleaching on the path. RPD alone is a DSCP policy signal and does not prevent
the ECN comparison.

Each direction has a 4-by-4 `transitions` matrix. Rows are baseline
codepoints and columns are observed codepoints, both in numeric order 0..3.
Each pair is classified before it is added to the totals, so the IP marking of
a refused reply cannot be paired with the applied EC1 of another reply. The
four outcome counters do not overlap and add up to `comparable`:

| Counter | Baseline → observation |
|---------|------------------------|
| `unchanged` | Equal codepoints, including CE → CE |
| `bleaching` | ECT(1), ECT(0) or CE → Not-ECT |
| `ce_marked` | ECT(1) or ECT(0) → CE |
| `remarked` | Other unequal pairs, including ECT swaps, Not-ECT → CE and CE → ECT |

`ce_observed` counts comparable pairs that end in CE, so it overlaps the
outcome counters. CE → CE does not show that congestion marking was newly
added, and Not-ECT → CE is classified as other remarking. The raw
`reply_ip_ecn` histogram still records IP CE when directional analysis is
unavailable.

`comparable + unknown` equals the number of admitted distinct reply copies.
`unknown_reasons` gives each unknown comparison one primary reason, so its
counters add up to `unknown`. For forward analysis, unusable CoS takes
precedence over unavailable local marking. For reverse analysis the order is
unusable CoS, C, RPE=0 (legacy/unconfirmed), RPE=1 (reflector marking
unavailable), RPE=2 (reflector unable), echoed EC1 mismatch, then missing or
invalid IP metadata. A legacy reply that zeroes EC1 is therefore counted as
legacy/unconfirmed, not as a request mismatch. A reply can have several of
these limitations at once, and the raw RPE, C and IP totals are kept
separately. RPE=2 cannot show whether policy or platform capability caused the
refusal. The `reflector_marking_unavailable` reason records RPE=1. None of
this shows that a peer implements the successor draft's separate DSCP fallback
requirements.

Text reports print the outcome counts and the unknown-reason counts. JSON and
CSV carry the full matrix in the `measurements` object, and the CSV columns
and older raw counters stay as they were. For example, `--cos --ecn 2
--output-format json` gives ECT(0) comparisons with separate ECT-to-CE and
bleaching totals.

These counters compare what the two endpoints see. They do not prove that a
particular hop is faulty or show what caused congestion. The forward baseline
is a socket setting the sender accepted, and the reverse baseline is what the
reflector reports. Local policies, tunnels and processing along the path can
affect either comparison, and equal values at the endpoints can hide changes
in between. Cross-check with independent packet captures and the
[ECN deployment guidance](usage.md#ecn-deployment-and-interpretation). The
diagnostics do not affect AIMD feedback, admission rules or integrity
requirements.

The [controlled ECN rewrite fixture](testing-netns.md#directional-ecn-rewrites)
checks these reports with real sender and reflector processes, separate
kernel rewrites in each direction, packet captures and policy-refusal
controls. It runs on loopback, so it cannot show where a change happened on an
external path. Use the captured IP fields and the matching report to check
your reading of the counters before you apply the same analysis to a
deployment.
