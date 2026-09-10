# Sender reply and directional measurements

The sender includes a `measurements` object in interim and final JSON reports,
prints a text summary, and appends a quoted JSON `measurements` column to CSV.
CSV now has 28 columns: its first 26 scalar columns and column 27 (`ber`) retain
their positions. Use a CSV parser because both JSON columns contain commas.
Library users constructing `stats::StatsSnapshot` directly must supply the new
optional field; `with_measurements` attaches a summary. The summary types are
exported from `stats`.

```bash
stamp-suite --remote-addr 192.0.2.10 --count 100 --direct-measurement \
  --follow-up-telemetry --reflected-control-count 3 --timeout 2 --output-format json
```

The reflector must support the requested extensions. Follow-Up requires a
stateful reflector. Reflected Packet Control is an experimental draft extension;
the reflector can limit or decline the requested burst. Existing `--ber` options
add directional bit/packet error totals under the separate `ber` object.

## Probes, reply copies, and duplicates

Existing `packets_received`, RTT and OWD fields count the first accepted reply
for each pending probe. Existing timeout-based `packets_lost` and loss percentage
retain their meaning. A late first reply does not undo an expired probe's loss.
Prometheus/SNMP counters and `-R` details retain this probe-based behavior.

The new collector runs after base authentication, TLV validation and session
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
all requested copies have been observed or the existing final `--timeout` expires.
Zero-SSID stop policy still terminates reception. Ordinary single-reply runs
retain their existing finish condition; packets arriving after exit are unobserved.

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
not repeat the forward bit denominator or inflate its existing residual BER
aggregate. Its directional totals, intervals, alarms and omission counts remain
in `ber`; they do not represent a per-burst-copy BER metric. See
[statistics retention](statistics.md) and [BER behavior](architecture.md#bit-error-rate-tlvs-draft-gandhi-ippm-stamp-ber).
