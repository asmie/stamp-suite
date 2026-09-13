# Sender reply and directional measurements

JSON reports include `measurements` and `ber` objects; text reports print their
summaries. CSV embeds JSON in the `ber`, `measurements`, and `owd_clock_quality`
columns. Read columns by name and use a CSV parser to handle quoted commas.
`owd_clock_quality` is empty when no OWD samples exist.

```bash
stamp-suite --remote-addr 192.0.2.10 --count 100 --direct-measurement \
  --follow-up-telemetry --reflected-control-count 3 --timeout 2 --output-format json
```

The reflector must support the requested extensions. Follow-Up requires a
stateful reflector. Reflected Packet Control is an experimental draft extension;
the reflector can limit or decline the requested burst. `--ber` options
add directional bit/packet error totals under the separate `ber` object.

## Probes, reply copies, and duplicates

`packets_received`, RTT and OWD fields count the first accepted reply
for each pending probe. Timeout-based `packets_lost` and loss percentage
count expired probes. A late first reply does not undo an expired probe's loss.
Prometheus/SNMP counters and `-R` details retain this probe-based behavior.

The reply collector runs after base authentication, TLV validation and session
admission. Its counters distinguish individual reflected packets:

| Field | Meaning |
| --- | --- |
| `requested_replies` | Successful probes sent multiplied by the configured reply count (at least one). |
| `unique_replies` | Accepted distinct reply identities within retained history, including late replies. |
| `answered_probes` | Retained probes with at least one accepted reply, including late first replies. |
| `additional_replies` | Distinct replies after a probe's first reply. These include requested burst copies. |
| `late_replies` | First replies for retained probes that are no longer pending. |
| `duplicate_replies` | Repeated recent `(echoed sender sequence, reflector sequence, T3)` identities. |
| `unknown_replies` | Replies with neither a retained probe nor a pending probe. |
| `reordered_replies` | Reflector sequence behind the highest observed sequence using 32-bit serial arithmetic. |
| `unobserved_requested_replies` | Requested copies less observed copies, capped separately per probe. |
| `reply_rtt` | Count and cumulative minimum/mean/maximum RTT for all unique replies. |

`last_reflector_sequence` preserves the latest observed independent sequence;
`independent_sequence_observations` counts replies where it differs from the
echoed sender sequence. Neither proves which sequencing mode the peer uses.
Counter resets can resemble reordering. No directional loss is inferred from
sequence gaps alone.

Requested-but-unobserved replies include policy caps, unsupported requests,
validation rejection, timeout and network loss. **They are not a network-loss
estimate.** Extra replies to one probe cannot satisfy another probe's request.
For bursts, the final receive phase continues after the first response, until
all requested copies have been observed or the final `--timeout` expires.
Zero-SSID stop policy still terminates reception. Ordinary single-reply runs
finish after their first accepted reply; packets arriving after exit are unobserved.

The recent probe and reply identity histories each retain at most **4096**
entries. `history_limit`, `probes_evicted` and `replies_evicted` disclose this
bound and evictions. A still-pending probe can supply timing after history eviction,
but its original Direct Measurement ordinal is then unavailable. Correlation and
deduplication beyond the retained histories are unavailable. After eviction, an
old duplicate can appear as an additional reply if its probe is still known.
Identical stateless burst copies with the same T3 are indistinguishable from
network duplicates because the wire packet has no separate copy identifier.

## Direct Measurement counter window

The three counters are defined by
[RFC 8972 §4.5](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.5).
The following window estimates are this implementation's reporting policy.
Interpret them only when both endpoints count the same session and packet
profile; other in-profile traffic or duplicate requests can change the result.

`direct_measurement.anchor` is the first usable counter observation in the
current window; `latest_transmit` is the observation with the highest reflector
transmit count in that window. Each exposes `sender_tx`, `reflector_rx` and
`reflector_tx`. Differences use wrapping 32-bit arithmetic, with a half-range
limit to distinguish plausible forward spans from resets or older epochs.
The echoed sender counter must match the locally recorded successful-send count.
All-zero reflector counters do not establish measurement support.

After at least two distinct usable observations:

- `sender_packets` is the highest observed sender-counter difference from the anchor.
- `reflector_received` is the highest receive-counter difference observed at an advancing transmit count.
- `forward_missing` is `sender_packets - reflector_received`, or null if negative.
- `reflector_transmitted` is the highest transmit-counter difference from the anchor.
- `replies_received` counts distinct usable transmit-counter values after the anchor.
- `reverse_missing` is `reflector_transmitted - replies_received`, or null if negative.

For example, `(S,Rrx,Rtx) = (1,1,0), (3,2,1), (4,3,3)` reports forward missing
1 and reverse missing 1 over the observed window. A late observation for transmit
counter 2 closes the reverse gap. Estimates are provisional: in-flight packets,
reordering and metadata rejection can leave apparent gaps. Reverse missing
counts absent *usable counter observations*, including replies whose DM metadata
was missing or rejected; it cannot distinguish those cases from transport loss.

The anchor is excluded from the differences. No inference covers packets before
the anchor, an unobserved tail, or windows discarded on discontinuity. Before
there is enough usable data, fields are null, not zero. `observations`,
`unavailable`, `discontinuities` and `reordered` disclose usable/invalid counter
processing. Repeated transmit counters on distinct replies, backward half-range
spans and detected resets invalidate the current estimates. The distinct-counter
set is also bounded at 4096; exceeding it clears the window and sets the sticky
`history_exceeded` flag. The next usable observation starts a new window. Totals
across discarded windows are deliberately not accumulated.

## Follow-Up corrected reverse delay

[RFC 8972 §4.7](https://www.rfc-editor.org/rfc/rfc8972.html#section-4.7) supplies
the previous reflection's sequence, timestamp and timestamping method.
The sender looks up that independent sequence in recent reply history and
computes `previous T4 - corrected T3`, applying `--reflector-utc-offset`.
Decoding uses the previous packet's NTP/PTP format, not the current packet's
format or the Follow-Up timestamping-method byte.

`follow_up.reverse_delay` contains cumulative sample count and minimum/mean/
maximum signed milliseconds. `matched` counts corrections; `repeated` counts
further references to an already corrected reply. Only the first usable correction
for a uniquely identified reply contributes a sample. `unmatched` records a
reference absent from history, including a reply that has not arrived yet; these
references are not queued for later resolution. `ambiguous` records reused or
self-referencing sequences and possible stateless burst identities. Unknown
methods, zero placeholder timestamps and invalid timestamps are `unavailable`.
The last reply has no correction unless another reply carries its Follow-Up.

These timestamps do not establish clock synchronization. Clock skew still affects
signed reverse delay, and a software Follow-Up is not necessarily more accurate
than the original timestamp. Follow-Up does not replace the original OWD summary.

## Integrity and BER

DM and Follow-Up require a unique usable TLV of their type. U skips a value,
M stops processing the remainder, and any I flag blocks all values. Bad lengths
stop subsequent value processing. If a key is configured, a verified HMAC TLV
is required for these measurement values. Missing, invalid or unverifiable
metadata contributes no directional sample; authenticated base reply accounting
can still proceed. Unsigned, unkeyed measurements remain unauthenticated.

BER remains one accepted pending-probe observation per probe, so burst copies do
not repeat the forward bit denominator or inflate the residual BER
aggregate. Its directional totals, intervals, alarms and omission counts remain
in `ber`; they do not represent a per-burst-copy BER metric. See
[statistics retention](statistics.md) and [BER behavior](architecture.md#bit-error-rate-tlvs-draft-gandhi-ippm-stamp-ber).


## Clock quality accompanying delay

`owd.clock_quality` in JSON and `owd_clock_quality` in CSV describe exactly the
original first-pending-reply OWD samples. Text reports their synchronization
categories and maximum combined advertised error. `measurements.follow_up` has
its own `clock_quality` object describing only matched correction samples,
using metadata from the referenced previous reply. Missing/ambiguous references
and duplicates do not contribute quality samples.

| Field | Meaning |
| --- | --- |
| `samples` | Number of associated delay samples. |
| `both_synchronized` | Both endpoints asserted S=1 and supplied valid nonzero error multipliers. |
| `unsynchronized` | Usable error estimates, with at least one endpoint asserting S=0. |
| `invalid_estimate` | At least one invalid error estimate, such as Multiplier=0. |
| `unknown` | Local/remote quality metadata unavailable (for example, the library's plain `OwdCollector::record`). |
| `last_sender`, `last_reflector` | Most recent sample's S bit, NTP/PTP format, Scale, Multiplier and decoded `error_ms`; null when metadata is absent. |
| `max_combined_error_ms` | Largest sum of two usable advertised errors over the samples; null if none. |

The four categories are mutually exclusive and sum to `samples`. Invalid errors
are null, never a claim of zero uncertainty. The maximum includes usable estimates
from unsynchronized clocks, so it is **not a bound on actual OWD accuracy**.
A later unknown sample clears the last endpoints while retaining cumulative counts
and the maximum from earlier usable estimates.

The sender uses its configured Error Estimate, rather than the reflector's echoed
sender field. The remote estimate comes from the accepted base reply. Their S bits
remain operator/peer declarations: neither proves that NTP/PTP is locked, a PHC is
aligned, or clocks share a compatible timescale. The default tiny scale/multiplier
is a configured wire value, not a measured workstation timing precision. Existing
RTT/OWD values remain available with an unsynchronized or invalid declaration;
metadata qualifies them instead of silently removing previously accepted samples.

[RFC 8762 §4.2.1](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.2.1)
uses the error interpretation from
[RFC 4656 §4.1.2](https://www.rfc-editor.org/rfc/rfc4656.html#section-4.1.2):
`error_seconds = Multiplier * 2^(Scale - 32)`. Zero Multiplier is invalid. The
same error units apply to NTP and PTP timestamp encodings. A synchronized S bit
indicates an external UTC synchronization assertion, independent of the Z bit.

Configure `--clock-synchronized`, `--error-scale`, `--error-multiplier`, and
`--reflector-utc-offset` from the endpoints' clock setup. The sender does not
detect clock discipline or discover timescale offsets.

### Session-state notifications (draft ext-hdr-13 §7.1)

The sender logs state changes with target `stamp_suite::session_state` and includes
`session_state` within `measurements` in summaries. It becomes active after a
validated reply while transmitting, failed after `--session-loss-threshold`
consecutive unanswered probes, and active again when replies resume. Each probe's
`--timeout` supplies its deadline; timeout 0 disables loss-driven failure. A session
that never received a reply is not falsely declared failed from an active state.
The sender reports idle when transmission stops; final draining still contributes
timing/loss statistics but does not reactivate an idle sender. If an Access Report
retry originates another probe, monitoring resumes and its own loss deadlines
are serviced until retries finish. Normal errors/cancellation drop the monitor
and report idle when a transition is needed.

Notifications count probes, not requested burst copies. Duplicate, invalid-session
and unauthenticated replies do not reset failure detection. A newer successful
probe ends the preceding loss run; older unanswered probes still count as packet
loss but cannot trigger a fresh failure after recovery. Notification counters are cumulative; event history is not retained. Configure enough endpoint
capacity for offered traffic and correlate queue/cap/policing counters with failed
state: local overload and path loss are indistinguishable from missing replies.
