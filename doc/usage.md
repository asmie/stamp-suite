# Usage

How to configure and run the sender and the reflector, and what they report.
For a quick start, see the [README](../README.md) or `stamp-suite -h`. For
every option and its default in your build, run `stamp-suite --help` or read
the [man page](../dist/man/stamp-suite.1).

## Configuration file

Use `--config <PATH>` to load settings from a TOML file. Settings you omit
from both the file and the command line use their built-in defaults.
Put deployment settings in the file: provisioned sessions, destination
policies, resource limits, and the metrics, SNMP and control settings. Use CLI
flags for per-run changes and diagnostics. `--help` also lists the advanced
flags.

```bash
stamp-suite --config /etc/stamp/reflector.toml
```

### Precedence

A command-line value overrides the environment, the environment overrides the
file, and the file overrides the built-in default. The only option read from
the environment is `STAMP_HMAC_KEY`, which supplies the inline HMAC key when
`--hmac-key` is absent. You can configure only one key source, so a key in the
environment together with a key file or key directory in the TOML file fails
startup.
See [key sourcing and rotation](security.md#key-sourcing-and-rotation).

### Sender and reflector examples

The [example sender](../examples/sender.toml) and
[example reflector](../examples/reflector.toml) use loopback port 8620 and need
no privileged port. Start them in separate terminals:

```sh
stamp-suite --config examples/reflector.toml
stamp-suite --config examples/sender.toml
```

Change the sender's destination for another host, or override a file value:

```sh
stamp-suite --config examples/sender.toml --remote-addr 192.0.2.10 --count 100
```

Use `/usr/share/doc/stamp-suite/examples/` for DEB/RPM installations, or the
`examples/` directory in a binary archive. Copy a template before editing it.

### Reflector deployment settings

Add settings like these to your reflector file as needed:

```toml
is_reflector = true
local_addr = "192.0.2.10"
local_port = 862

auth_mode = "O"              # "A" for authenticated, "O" for open
clock_source = "NTP"         # timestamp encoding: "NTP" or "PTP"
clock_sync_source = "local"  # declared system-clock discipline
hardware_clock_sync_source = "local" # declared NIC PHC discipline
tlv_mode = "echo"            # "echo" or "ignore"
stateful_reflector = true
session_timeout = 300

metrics = true
metrics_addr = "127.0.0.1:9090"

# The file names a key file; it cannot hold the key itself.
hmac_key_file = "/etc/stamp/hmac.key"
```

### Supported keys

A file key is the long option name in snake_case: `--remote-addr` becomes
`remote_addr`. Three keys differ from that rule: repeated `--reflector-session`
entries go in the `reflector_sessions` array, `-R` is `print_stats`, and
`--remote-addr` accepts a string or an array of strings. The parser rejects
unknown or misspelled keys. Common value types:

| Field | TOML type | Example |
|-------|-----------|---------|
| `remote_addr` | string or string array (IPv4 or IPv6) | `"192.0.2.10"`, `["192.0.2.10", "2001:db8::1"]` |
| `local_addr`, `dest_node_addr`, `return_address` | string (IPv4 or IPv6) | `"192.0.2.10"`, `"2001:db8::1"` |
| `send_delay` | integer (ms) or string with unit | `1000`, `"250us"`, `"1.5ms"` |
| `metrics_addr` | string (`addr:port`) | `"127.0.0.1:9090"` |
| `auth_mode` | enum | `"A"` or `"O"` |
| `clock_source` | enum | `"NTP"` or `"PTP"` (encoding only) |
| `clock_sync_source`, `hardware_clock_sync_source` | enum | `"local"`, `"ntp"`, `"ptp"`, `"ssu-bits"`, `"gps"`, `"glonass"`, `"loran-c"`, `"bds"`, `"galileo"` |
| `reflector_utc_offset` | signed integer | `37`. Default `0`. See [Remote clock offset](#remote-clock-offset). |
| `tlv_mode` | enum | `"echo"` or `"ignore"` |
| `output_format` | enum | `"text"`, `"json"`, or `"csv"` |
| `return_sr_mpls_labels` | integer array | `[100, 200, 300]` |
| `return_srv6_sids` | string array (IPv6) | `["2001:db8::1", "2001:db8::2"]` |
| `hmac_key_file` | string (path) | `"/etc/stamp/hmac.key"` |

The file does not accept `hmac_key`, so a plaintext key cannot end up in a
configuration file, or `config`, which would be recursive.
`stamp-suite --print-config-schema` prints a JSON Schema of the file format for
editors and validators.

### Validation

Unknown keys, invalid TOML and wrong types fail startup with an error that
gives the line and column. Values from the file go through the same range and
combination checks as CLI values. On Unix, a config file that group or others
can write triggers a warning; see [file permissions](security.md#file-permissions).

## Sender

The sender is the default role. It sends test packets to one or more
reflectors, matches the replies and reports delay and loss statistics.

### Basic run

```bash
stamp-suite --remote-addr 192.0.2.10 --count 100 --send-delay 100ms --timeout 2
```

This sends 100 probes to UDP port 862 on 192.0.2.10, one every 100 ms, waits
up to 2 seconds for the last replies and prints a summary. The options that
control a run:

| Option | Unit | Default | Meaning |
|--------|------|---------|---------|
| `-d`, `--send-delay` | interval; a plain number is milliseconds, or use `us`, `ms`, `s` | `1000` (1 s) | Gap between probes. Resolution 1 µs, maximum one hour. |
| `-c`, `--count` | probes | `1000` | Scheduled probes to send; timer-driven Access Report retries are additional. `0` sends until `--duration` ends or the sender is interrupted. |
| `--duration` | seconds | none | Stop scheduled probes after this time, even if `--count` probes have not all been sent. Must be at least 1. |
| `-L`, `--timeout` | seconds (0 to 255) | `5` | How long to wait for a reply before the probe counts as lost. |
| `--max-pending-probes` | probes per target | `0` (unlimited) | Caps the unanswered probes kept per target. When a new successful send needs room, the oldest is counted as lost and added to `pending_evictions`. |

With the defaults a run sends 1000 probes at one per second, so it takes about
17 minutes. After the last probe the sender waits up to `--timeout` seconds for
outstanding replies, then prints the final report and exits 0.

The text report looks like this (some lines omitted):

```text
--- STAMP Statistics ---
Packets sent: 100
Packets received: 100
Packets lost: 0 (0.0%)
Quantiles: exact through 4096 samples per series; otherwise <0.78125% magnitude error
Replies: 100 unique, 0 additional, 0 late, 0 duplicates, 0 reordered, 0 unknown
...
Min RTT: 0.252 ms
Max RTT: 0.375 ms
Avg RTT: 0.317 ms
Median RTT: 0.323 ms
P95 RTT: 0.375 ms
P99 RTT: 0.375 ms
Jitter: 0.050 ms
Std Dev: 0.043 ms
OWD clock declarations: 0 both synchronized, 100 unsynchronized, 0 invalid, 0 unknown; max advertised combined error 0.000 ms (not verified accuracy)
One-way delay (assumes synchronized clocks, n=100):
  Forward (sender→reflector): min 0.141 / avg 0.200 / med 0.213 / max 0.233 ms
  Reverse (reflector→sender): min 0.071 / avg 0.090 / med 0.087 / max 0.112 ms
```

RTT, loss and one-way delay (OWD) count the first accepted reply to each probe.
One-way delays are only meaningful when both clocks are synchronized; see
[Timestamps and clocks](#timestamps-and-clocks). The `Replies` line and the
other reply-copy lines are explained in
[measurement semantics](measurements.md).

Ctrl-C or SIGTERM stops sending at once. The sender then prints the statistics
collected so far and exits 0; probes still awaiting a reply count as lost.

### Pending-probe retention

`--max-pending-probes N` caps how many unanswered probes the sender keeps for
each target. When a probe is sent successfully and the table is full, the
oldest unanswered probe is removed and counted as lost. The cap does not slow
sending: no scheduled probe is skipped, and the count, interval and Access
Report retry budget stay as configured.

A sequence number that is reused while its old probe is still pending also
removes the old probe, even with no cap. The old probe is counted as lost
instead of being overwritten.

The default, 0, means no cap. `--timeout 0` turns off timed expiry and
loss-driven session failure, so without a cap the pending table keeps growing
for as long as replies are lost. For example:

```sh
stamp-suite --remote-addr 192.0.2.10 --count 0 --duration 600 \
  --timeout 0 --max-pending-probes 4096 --report-interval 60 --output-format json
```

The `measurements` object in JSON and in the CSV `measurements` cell contains
`pending_limit`, `pending_probes` (probes still pending),
`pending_high_watermark` and the running total `pending_evictions`. Text
reports show these when a cap is set or a probe was removed because its
sequence number was reused. The first removal logs a warning that names the
target. With several targets each one has its own cap, so N allows up to
N × number-of-targets pending probes.

A removed probe means the sender stopped waiting for it, not that the network
lost it. It counts once toward packet loss and the observer counters. If its
reply arrives later while the probe is still in measurement history,
`late_replies` goes up, but the reply adds no RTT, OWD or BER sample and does
not undo the loss. Timed expiry works the same way. Evictions from measurement
history (`probes_evicted`) are counted separately. At shutdown only the probes
still pending are added to the loss, so earlier removals are not counted twice.
The final `pending_probes` value shows those unresolved probes even though the
run has finished. See [measurement semantics](measurements.md).

The cap limits the pending map and its ordered index, not the memory of the
whole process. With a nonzero timeout the failure monitor keeps its own
time-based window, which session-state notifications depend on. The collector,
history, reports and platform buffers have their own limits. See
[memory limits](statistics.md#report-output-and-pending-probes).

### Send schedule

`--send-schedule poisson` draws exponentially distributed gaps with
`--send-delay` as their mean (RFC 2330 §11.1.1). The default `periodic` uses
a fixed gap (RFC 3432).

Send times follow a fixed timeline, so the time spent building and sending a
probe does not stretch the gap. Tokio timers have 1 ms resolution, so the
sender busy-waits gaps shorter than 1 ms, and rates above 1000 probes per
second keep one CPU core busy. A gap of exactly 1 ms uses the timer. If the
sender falls more than 2 ms behind its timeline, it restarts the timeline
instead of sending a burst to catch up. At exactly 2 ms behind it stays on the
original timeline.

On Windows, active senders request 1 ms timer resolution and ask Windows to
honor it even when the process is hidden. When the last sender exits, also by
cancellation, the previous process timer policy is restored.

The first probe goes out immediately. `--count` and `--duration` decide whether
another probe may start. A send that has already started can finish after the
duration ends. The duration also cuts short the wait after each probe. Once
no further probe may start, the sender goes straight to the reply drain,
which waits up to `--timeout` and ends as soon as every probe has its reply.

Access Report retries can go out between scheduled probes. They do not move
the measurement timeline, draw a new Poisson gap or use up the `--count`
quota. If a scheduled probe is already due, it can carry the report itself.
The final reply drain and an unfinished Access Report exchange continue after
the count or duration limit, and packet statistics include every successful
send.

After a receive error other than ICMP during pacing, the sender stops reading
the socket until its next wait. Cancellation, reporting and Access Report
timers keep running, and the next scheduled probe keeps its deadline.

```bash
# 4000 probes per second for ten minutes, with a report every 10 s.
stamp-suite --remote-addr 192.0.2.10 --send-delay 250us --count 0 --duration 600 \
  --report-interval 10
```

`--report-interval SECONDS` prints an interim report at that interval
(default 0, disabled). Interim reports are cumulative; reporting never resets
the statistics.

### Several reflectors

Repeat `--remote-addr`, or separate addresses with commas, to measure several
reflectors from one process. Each address gets its own session, socket and
statistics. All sessions share the other options, including `--remote-port`.
Several addresses need `--local-port 0` so that each session gets its own
port, and the same address cannot be listed twice. Targets can mix IPv4 and
IPv6; without `--local-addr` each session binds its target's family (see
[Local address](#local-address)). Every session is set up before any probe
is sent, and a startup error in one session stops the run.

Reports name their target: a `Target:` line in text, a `target` field in
JSON, and a leading `target` column in CSV. These labels appear only when the
sender has more than one target. Prometheus and SNMP counters add up all
sessions, and the SNMP configuration objects describe the first target.

```bash
stamp-suite --remote-addr 192.0.2.10,192.0.2.11 --remote-addr 2001:db8::20 \
  --count 0 --report-interval 60 --output-format json
```

### Output streams

`--output-format text|json|csv` selects the measurement output on stdout.

- JSON is newline-delimited. Interim reports have `"type":"interim"` and the
  final report has `"type":"summary"`.
- CSV prints one header, then one row per report. The last row is the final
  summary. Every column is always present and empty when it does not apply.
  The `ber`, `measurements` and `owd_clock_quality` cells hold CSV-quoted JSON.
  With several targets a leading `target` column shifts every position by one,
  so read columns by name and use a CSV parser.

Diagnostic logs go to stderr. `--log-format text|json` selects their format,
and `RUST_LOG` or `-v`/`-vv` sets their verbosity. Per-packet details from `-R`
go to stdout with text output and to stderr with JSON or CSV output. These
details are plain text and stay visible with `RUST_LOG=off`. Startup and
validation errors can also be plain text even with `--log-format json`. Every
other diagnostic, including send and receive errors and rejected replies, is a
log record; per-packet ones are throttled to the 1st, 10th, 100th, ...
occurrence.

```bash
stamp-suite --remote-addr 192.0.2.10 --output-format json > measurements.jsonl 2> diagnostics.log
stamp-suite --remote-addr 192.0.2.10 --output-format csv --report-interval 10 > measurements.csv 2> diagnostics.log
```

Reports also carry [reply and directional measurements](measurements.md) under
`measurements`: individual burst copies, duplicates and reordering, Direct
Measurement counter windows, Follow-Up reverse delays and the session state.
JSON also exposes TLV HMAC outcomes and per-type U/M/I/C flag counts under
`measurements.tlv_validation`; see [extension validation diagnostics](measurements.md#extension-validation-diagnostics).
The `RTT`, `OWD` and probe-loss fields always describe the first reply to each
probe. The count of requested reply copies that never arrived includes copies
the reflector declined by policy, so do not read it as network loss.

RTT and OWD quantiles are exact up to 4096 samples per series and come from a
fixed-size histogram after that. See [statistics precision and retention](statistics.md).

For the reflector shutdown summary, see
[Capacity, drain and shutdown](#capacity-drain-and-shutdown). To print reports
from library code, see the [architecture](architecture.md).

### Session state

The sender logs session state changes (idle, active, failed) with the log
target `stamp_suite::session_state` and reports the current state in
`measurements.session_state`. The session is reported failed after
`--session-loss-threshold` consecutive probes (default 3, range 1 to 65535)
time out under `--timeout`. With `--timeout 0` the session is never reported
failed. See [session-state notifications](measurements.md#session-state-notifications).

### Micro-session ID validation

`--micro-session-id ID` adds a Micro-session ID TLV (RFC 9534) to every probe
and turns on ID validation. Every accepted measurement then needs exactly one
usable Micro-session ID TLV in the reply; a reply without TLVs cannot satisfy
it. A reply whose ID is missing, flagged U, M or I, malformed, duplicated,
wrong or unverifiable leaves the probe pending and produces no RTT or OWD
sample. With an HMAC key configured, the ID also needs a valid TLV HMAC. A
valid later reply can still satisfy the probe before its timeout.

IDs must be nonzero. On a sender, `--reflector-member-link-id` sets the
expected reflector ID and requires `--micro-session-id`. Without it, the
sender learns the reflector ID from the first accepted reply to a pending probe
and rejects any later change. Unsolicited replies are never used for learning.
Sessions without micro-session options accept replies that carry no
Micro-session ID TLV.

These options do not bind IDs to interfaces, steer packets over a specific LAG
member or identify the physical ingress member. Per-member LAG measurement is
not supported. See the [RFC 9534 scope and gaps](conformance/rfc9534.md).

### TLV-driven sender features

**Probe identity.** The sender first matches the echoed sequence number and
the eight-byte sender timestamp of a reply against its pending and retained
probes. A reply whose echo is unknown, missing or mismatched cannot complete a
probe, trigger the SSID stop policy, acknowledge an Access Report or apply
congestion feedback. Reports count these replies separately in
`measurements.unknown_replies` and `measurements.mismatched_replies`. Kernel TX
timestamp corrections never change the original timestamp used for matching.
A reply may omit trailing fields, but it must contain the complete echo.
See [reply accounting and limits](measurements.md#probes-reply-copies-and-duplicates).

**SSID checks.** With a nonzero `--ssid`, the sender rejects a reply that
carries a different nonzero SSID. The reply is rejected before it can record
RTT or OWD, complete a pending probe, set the learned reflector micro-session
ID, acknowledge an Access Report or apply congestion feedback.
[RFC 8972 §3](https://www.rfc-editor.org/rfc/rfc8972.html#section-3) permits a
reply with a zero SSID, and `--on-zero-ssid continue|stop` (default
`continue`) decides what the sender does with one. With `continue`, later
nonzero replies are still checked. Without `--ssid`, or with `--ssid 0`, the
sender does not check SSIDs.

With `stop`, the sender stops waiting for pending probes at once, including
waits that ECN backoff has extended. It skips the reply drain and the Access
Report retries, and the unanswered probes are reported as lost. A reply with
an unknown sequence number or a mismatched echoed timestamp cannot trigger this
stop.

**TLV integrity.** Access Report acknowledgement and ECN congestion control
work the same with or without `-R`, and with any logging or output format. If
a TLV HMAC is present but unusable (no key, invalid flags or failed
verification), the sender ignores every reflected TLV control value. An Access
Report with an invalid length cannot stop its retry timer. A U flag makes the
sender skip that TLV, an M flag stops processing of the remaining TLVs, and an
I flag blocks all values. When the HMAC TLV is absent, the sender still accepts
the optional TLVs, so peers that do not send one keep working. Required
Micro-session IDs, BER, Direct Measurement and Follow-Up have stricter rules.

The sender finds returned TLVs from the received packet length, even when its
probe carried no extensions. It checks the length of every known outer TLV,
whether or not it requested that value. A malformed value it did not ask for
still stops processing of the TLVs after it, and the diagnostics count the M
errors the sender detected itself. Signature verification still covers the
original bytes received from the peer.

For a Location TLV the sender checks the port prefix and every nested header,
including declared sizes and the lengths of known types. A malformed child
makes the whole Location unusable and stops processing of later outer values.
The sender honors an M flag on a child even when the peer did not set M on the
outer TLV. An I flag on a nested value is ignored. The reflector validates the
whole Location before it answers any field, and it keeps the TLV's original
size. Signed echoes that failed integrity checks or are structurally malformed
keep their original nested value bytes.

Timestamp Information also needs complete optional child headers and values.
Unknown children that are complete are passed through without being
interpreted. Bad framing sets M on the outer TLV and stops processing of later
values. A valid Access Report that was processed is echoed with its ID and
Return Code and with the reserved fields zeroed. Valid Follow-Up replies have
their reserved bytes zeroed in both stateful and stateless mode. Invalid
Access IDs, and values that were skipped or failed integrity checks, follow
the usual copy rules. When processing is allowed, a malformed Follow-Up has
whatever sequence and timestamp fields it contains zeroed. A signed error reply
that was copied keeps its original values all the way to transmission.

With `-R`, the per-packet line shows TLV results in a fixed order: HMAC, Access
Report, CE, Micro-session ID, then U/M/I counts. Each result appears once even
when several TLVs support it. `HMAC:unverified` marks a present HMAC that could
not be verified, `HMAC:fail` a failed verification, and `no-hmac` an absent
HMAC.

**Access Report retries.** `--access-report-timeout` (default 3 seconds) and
`--access-report-retries` (default 4) control how the sender delivers an
Access Report. Retries continue after the main send loop ends, until the
reflector acknowledges the report or the retries run out. A silent peer can
therefore make a short run last longer, by the retry budget plus the reply
window after the final retry. The Access Report timer runs both while probes
are being paced and during the final reply wait, so long scheduled gaps or a
longer `--timeout` do not delay retries. Retries follow
`--access-report-timeout` even when congestion backoff has stretched the
measurement gap. The pacing of reflected bursts within each retry still uses
the current congestion factor.

Retries do not restart the initial reply-drain deadline; an unfinished
exchange simply continues after it. Once the report is acknowledged or the
retries run out, the sender keeps collecting replies until `--timeout` after
the last successful retry. This catches later burst copies without restarting
the window at the moment of acknowledgement or exhaustion. Collection ends
early when every requested reply has arrived. Shutdown and
`--on-zero-ssid stop` still end it at once.

The acknowledgement timer starts only after a successful UDP send. A failed or
short write does not use up a report retry or extend reply collection. It goes
through the sender's normal I/O retry and error handling, which has its own
limit. If the first report was never sent, no delivery exchange runs after the
loop.

An acknowledgement must contain exactly one usable Access Report with the
original Access ID and Return Code. Wrong values or duplicate reports leave the
retry timer running. Reserved bits and bytes are ignored. An echo with the U
flag set is not an acknowledgement either: it means the reflector did not
process the report. RFC 8972 §4.6 disarms the timer on a reply that "includes
the Access Report TLV", but §4 says to skip TLVs with U set, and the sender
follows §4. Against a reflector without Access Report support, the sender
therefore retransmits until the retry budget runs out. Such replies can
still give valid RTT and loss measurements from the base packet.

The CoS support follows draft-ietf-bpm-stamp-cos-ecn-00: the EC1/RPE extension
with ECN capability reporting, and DSCP fallback to an admitted value. The
[successor review](conformance/draft-stamp-cos-ecn.md#bpm-00-successor-changes)
lists how this differs from RFC 8972 and from the earlier IPPM -02 draft. The
remaining twelve Reserved bits are sent as zero. EC1 and RPE take four bits of
the sixteen-bit Reserved field defined in RFC 8972, so the frozen RFC rule that
these bits are sent as zero is scored Partial in the
[conformance matrix](conformance/rfc8972.md#cos-format-profiles). The draft
expects legacy peers to ignore the added bits. Check that the peer supports
them, and look at the RPE it reports, before you interpret reverse ECN.

**ECN response.** `--cos` with `--ecn 1` or `--ecn 2` turns on AIMD pacing. A
CE-marked reply multiplies the send interval by `--ecn-backoff-factor`, up to
`--ecn-max-delay` milliseconds. If the multiplication would round back to the
same interval, the sender adds 1 ns instead (the resolution of the duration
type), still without going past the cap. This keeps factors very close to 1
from stalling. It does not mean the wire timing is accurate to a nanosecond.

Each reply with exactly one usable non-CE CoS report and no reverse CE
shortens the interval by `--ecn-recovery-step` milliseconds, down to
`--send-delay`. Missing, ambiguous or unusable CoS feedback leaves the
interval as it is. With a key configured, recovery needs a verified TLV HMAC,
so an unsigned or unverifiable report cannot speed up sending. Such replies can
still give valid RTT and loss observations from the base packet.

Backoff also pushes back the deadline of the next pending probe. With a
Poisson schedule it scales the gap that was already drawn. Each backoff is
computed from the original draw and the original interval, so a series of small
increases is not lost to rounding. Clean feedback does not shorten a wait that
is already running; recovery takes effect when the next gap is drawn.
`--duration` still caps the wait.

Forward feedback comes from the EC2 field of the CoS TLV. Reverse feedback
comes from the IP ECN bits of the reply, which the sender can read only on
Linux and macOS. Other platforms log a warning and use forward feedback alone.

The same factor scales the Type-12 interval of later requests, including
Access Report retries. The number of reply copies requested stays the same.
While the sender is backed off, a zero burst interval is raised to 1 ms and
then scaled by the same factor. Control-only requests keep their required zero
interval. With `--send-delay 0`, the 1 ms burst floor stays in force at a 1 ms
ECN cap and during partial recovery below 1 ms. It goes away only when the
probe interval is back to zero.

Reports show CE observations, backoffs, and the current and peak intervals.

### ECN deployment and interpretation

With `--cos`, text, JSON and CSV reports include
[ECN observation counters](measurements.md#ecn-observations). They keep the
CoS TLV values apart from the reply's IP header values, and they say when a
reverse comparison is unknown.
[Directional diagnostics](measurements.md#directional-ecn-diagnostics) tell
bleaching, ECT-to-CE marking and other remarking apart, and explain unknown
comparisons without blaming a particular hop.

Before measuring ECN, check that both peers implement the extended CoS TLV,
and capture a short exchange for each address family and codepoint. On the
wire, confirm DSCP, ECN and RPE:

- RPE=11: EC1 was applied.
- RPE=10: the Not-ECT fallback was used.
- RPE=01: neither EC1 nor Not-ECT could be applied.
- RPE=00: possibly a legacy peer.

The C flag is separate from this capability report. Windows reflectors report
RPE=01 because the backend cannot verify the marking. On macOS the marking read
back from the socket option still has to be checked on the wire. Receiving
reverse ECN needs Linux or macOS. Draw conclusions only about the capabilities
you actually observed; the tool does not detect legacy peers or bleaching on
its own.

Write down your `--allowed-dscp`, destination override and `--allowed-ecn`
policies, and agree on them with the other network domains involved. Capture
EC2, RPE and the reply's IP ECN together, next to the CE counters. To look for
forward bleaching, compare the ECN you sent with EC2. For the reverse path,
compare EC1, RPE and C with the reply's ECN. Rule out policy rejection and
platform limits before you blame network remarking. Make sure the markings
survive before you compare delay or loss between codepoints. Traceroute-style
diagnostics and on-path telemetry need separate tools and cooperating nodes.
A CoS TLV alone cannot find the device that changed a marking.

Congestion response stays on for CoS ECT0 and ECT1, and also scales later Type
12 intervals. The interval controller backs off, but it has not been shown to
meet every requirement of RFC 3168 and RFC 9330, in particular L4S scalable
control for ECT(1); see [response limits](conformance/draft-stamp-cos-ecn.md#response-limits).
Revision 02 allows a fixed traffic pattern despite CE only in a controlled
environment agreed with the operators of every network under test. This tool
has no option to turn its response off. Limit runs with `--duration` or
`--count`, choose a conservative `--send-delay`, and cap reflected traffic
with `--reflected-control-max-count`, `--reflected-control-max-rate`,
`--reflected-control-max-volume` and `--reflected-control-max-duration-ms`.
Keep tests away from traffic outside the
agreed scope, and include Access Report retries in your time budget.

See [ECN security](security.md#ecn-measurement-integrity) for TLV protection
and destination-port choices.

## Reflector

Run a reflector with `-i` (`--is-reflector`). It listens on UDP port 862 by
default and answers every admitted test packet.

```bash
stamp-suite -i --local-addr 192.0.2.10
```

By default the reflector is stateless: it echoes the sender's sequence number.
`--stateful-reflector` keeps a separate sequence counter for each session, so
the sender can detect loss on the reverse path. `--tlv-mode echo` (default)
processes the TLVs it supports and flags the rest; `--tlv-mode ignore` copies
everything after the base packet unprocessed. By default a short packet is
zero-filled for TWAMP-Light interoperability; `--strict-packets` drops it
instead (RFC 8762 §4.6).

### Base-field validation

`--validate-base-fields` (TOML `validate_base_fields = true`) makes a
reflector check the base packet more strictly. It drops a packet unless the
base is complete (44 bytes in open mode, 112 in authenticated mode), even
without `--strict-packets`. It also drops a packet whose Error Estimate
multiplier is zero or whose PTP nanoseconds value is outside 0–999,999,999.
The Z bit of the incoming Error Estimate decides which timestamp format is
checked, so a PTP sender can use an NTP reflector and the other way round. The
checks run after base authentication, if it is configured, and before the
reflector allocates a session, refreshes its activity, counts the packet as
received or classifies it for replay. Rejected datagrams still count in the
aggregate receive and drop counters.

```bash
stamp-suite --is-reflector --local-addr 192.0.2.10 --validate-base-fields
```

Every NTP value passes, including zero and values after the era wrap. The
option does not check how fresh a timestamp is or whether the clocks are
synchronized. Received MBZ fields are ignored. Sequence gaps, reordering and
serial wrap go through the normal replay policy; `--drop-replayed` is a
separate option. A packet with a valid base still gets the normal TLV M and I
responses when its extensions fail validation. The option works with both
address families and both backends, whatever the UDP checksum handling. It
does not turn on zero-checksum sending, and on its own it does not provide the
complete [zero-checksum BER admission profile](ber-migration.md#zero-checksum-ingress-boundary).
The option is off by default, and the reflector then handles base fields
leniently.

### TLV framing admission

`--validate-tlv-framing` (TOML `validate_tlv_framing = true`) makes a
reflector drop packets with incomplete TLV headers or values before it
allocates or updates a session. That covers trailing fragments of one to three
bytes, and incomplete children inside Location, Timestamp Information, Return
Path, Reflected Control and Residual BER TLVs. Unknown layouts and child values
are not interpreted. The scan does a limited amount of work and allocates no
memory.

The option is off by default. It applies to both address families and both
backends, also with `--tlv-mode ignore`, and whatever the UDP checksum or the
received TLV flags. A rejected packet counts in the aggregate receive and drop
counters, but it does not touch session activity, session counters, replay
history or queued replies. Without the option, a malformed TLV is echoed back
with flags set. With it, an incomplete frame is dropped instead. TLVs that are
fully framed but semantically wrong, and failed TLV HMACs, still get the
normal M or I replies, and a complete Type 12 request still gets its
ordering-error response.

The option does not check base fields, timestamp freshness, what a TLV means
or whether it is intact. Combine it with `--validate-base-fields`, provisioning
and authentication as needed. On its own it does not provide the complete
[zero-checksum BER admission profile](ber-migration.md#zero-checksum-ingress-boundary).

### Session provisioning

[RFC 8972 §3](https://www.rfc-editor.org/rfc/rfc8972.html#section-3) requires
provisioned session identification and dropping unmatched packets. Turn this
on with `--session-admission provisioned`. The default, `permissive`, learns
sessions from incoming traffic and does not enforce those requirements. The
admission policy works with or without `--stateful-reflector`, which only
controls sequence numbering.

```toml
is_reflector = true
local_addr = "192.0.2.20"
local_port = 862
session_admission = "provisioned"
reflector_sessions = [
  "42,192.0.2.10:4862,192.0.2.20:862",
  "43,192.0.2.10:4862,192.0.2.20:862,7",
]
```

Each entry is `SSID,SOURCE_IP:PORT,DESTINATION_IP:PORT[,SENDER_MICRO_ID]`.
On the command line, repeat `--reflector-session`. IPv6 endpoints use brackets,
for example `42,[2001:db8::10]:4862,[2001:db8::20]:862,7`. All fields must
match exactly. Addresses must be concrete and ports nonzero. A reflector bound
to a wildcard address can accept provisioned concrete destinations of the same
address family and port. SSID 0 provisions a session without an SSID. An entry
without a micro ID matches only packets that carry no Micro-session ID TLV; it
is not a wildcard. `--reflector-member-link-id` sets the reflector's own
micro-session ID.

An empty provisioned list denies all traffic. Startup fails on invalid or
duplicate entries, entries that do not fit the bind address, and entries given
in permissive mode. Per-SSID HMAC keys play no part in admission: installing a
key does not provision an endpoint. Session timeout and control-plane expiry
remove runtime counters and replay state, not admission rules. Changing the provisioned sessions requires a configuration change and a
restart.

In both admission modes, a session is identified by source endpoint,
destination endpoint, SSID and sender micro-session ID. Each session has its
own sequence numbers, counters, replay window and Follow-Up state. A packet
with duplicate Micro-session ID TLVs is dropped as ambiguous. A malformed TLV
contributes no micro-session ID, and the packet still gets the normal M-flag
echo if the rest of its identity is admitted. The shutdown summary and the
control API list these sessions separately. SNMP lists them by its internal
session index and source address.

A packet rejected at the base-packet level does not create a session, extend
its idle timeout, increment its receive count, consume a stateful sequence
number, or change replay and Follow-Up state. This covers bad base HMACs,
unknown or revoked per-SSID keys, and short packets rejected by
`--strict-packets`, plus failures of `--validate-base-fields` or
`--validate-tlv-framing` when enabled. Such packets still count in the
aggregate receive and drop counters. A valid base packet with a failed TLV HMAC gets the RFC 8972 I-flag
reply.

### Capacity, drain and shutdown

**Session cap.** `--max-sessions` limits the number of runtime sessions
(default 65536; `0` means unlimited). At the cap, packets for a new session get
no reply in either sequencing mode. The rejected packet creates no session,
consumes no session ID or sequence number, and counts as dropped. Existing
sessions continue normally. Lowering the cap at runtime never evicts them.

Provisioning controls which sessions may be admitted; it does not reserve
capacity or bypass the cap, so size the cap for the expected number of
concurrent sessions. Idle cleanup, manual expiry or a higher cap frees room.
`--session-timeout SECONDS` (default 300) sets the idle cleanup time, and
`--session-timeout 0` turns idle cleanup off.

When a session expires, by manual expiry or idle cleanup, a send already in
progress finishes and the session's other queued replies are discarded. The
next admitted packet for the same identity starts a new session with sequence
zero and fresh measurement and replay state; its provisioning entry still
applies. Outgoing burst copies do not refresh the idle timeout. Restarting the
sender alone does not reset a reflector session that is still active.

**Reply queue.** `--reflector-queue-capacity` (default 1024, must be positive)
limits the number of requests in progress, from packet processing to the last
burst copy. Each request holds one slot until every copy is sent or the
request is discarded; `--reflected-control-max-duration-ms` bounds how long a
burst can take. When the queue is full, new requests are dropped before
authentication or any session change; accepted work keeps its slots. The limit
counts requests, not bytes.

**Drain.** The control API's drain switch (`POST /v1/drain`) rejects new
sessions, even with an unlimited cap. Existing sessions and their queued
replies continue, subject to the queue limit. Turning drain off restores
admission subject to provisioning and capacity. Once the API acknowledges a
drain or cap change, every new session uses the new policy.

**Shutdown.** Ctrl-C, SIGTERM (on Unix) and `POST /v1/shutdown` stop the
reflector. It stops reading packets at once.
`--reflector-shutdown-grace-ms` (0 to 60000, default 0) lets queued replies
finish for up to that long; 0 cancels them immediately. The reflector exits as
soon as the queue is empty, and repeated shutdown requests do not extend the
deadline. Scheduling and an in-progress send can add a little latency. To
finish accepted work and exit, use shutdown with a grace period; drain alone
does not stop the process.

```toml
reflector_queue_capacity = 1024
reflector_shutdown_grace_ms = 500
```

The shutdown summary goes to stdout in the `--output-format` format: text, one
JSON object, or one CSV header and row. It includes `reply_queue_rejected`
(requests refused because the queue was full) and `queued_replies_cancelled`
(requests whose remaining copies were discarded at shutdown or on a failed
handoff). In CSV these are the last two columns, after `uptime_seconds`. Each
queue rejection, and each cancelled request regardless of how many copies it
still had, adds one to the total dropped packets. Startup notices go to
stderr.

**Key reload.** On Unix, SIGHUP reloads the HMAC keys from `--hmac-key-file`
or `--hmac-key-dir` and replaces the reflector's keys. Keys added through the
control API are discarded by the reload. If the reload fails, the reflector
logs a warning and continues with its current keys. Provisioned sessions are
not reloaded; they need a restart.

```bash
sudo systemctl kill --signal=SIGHUP stamp-suite.service
```

### Rate limits

`--max-pps N` limits reflected packets per second for each source IP address
(default 0, unlimited). Each Type-12 burst copy counts as one packet.
`--reflector-rate-burst` sets the token-bucket size in packets; 0 uses the
`--max-pps` value.

Size these limits for the total traffic and the bursts you expect across all
sessions. The reflector does not check its limits against the load senders
actually transmit or against link capacity. When a sender reports loss,
compare it with the reflector's rate-limiting counters.

### Burst replies (Type 12)

A Reflected Test Packet Control TLV (Type 12,
[RFC 10052 §3](https://www.rfc-editor.org/rfc/rfc10052.html#section-3)) asks
the reflector for several reply copies. Type-12 reflection is off by default:
`--reflected-control-max-count 0` treats the TLV as unsupported and answers
with one U-flagged reply. The Address Group filters below are still checked
first, so a request whose filter does not match is dropped without a reply,
even with Type 12 disabled. Set a positive cap (for example 16) to turn it on,
and pair it with `--max-pps` to limit amplification. Requests above
`--reflected-control-max-count`, `--reflected-control-max-rate`,
`--reflected-control-max-volume` or `--reflected-control-max-duration-ms`, or
below `--reflected-control-min-interval-ns`, get one reply with the C flag set.

`--reflected-control-max-duration-ms` (default 1000) caps (count - 1) ×
interval, the time from the first copy to the last. A burst holds one reply
queue slot for that long, so without the cap a few hundred requests with long
intervals could fill the queue for minutes. A burst of exactly the limit is
admitted.

Fractional rate excess also gets C: a 500-byte reply every 99,999,999 ns exceeds
a 5,000 B/s ceiling. A rate or volume exactly equal to its ceiling is admitted.
Each well-formed Address Group filter must match a local address; any mismatch
suppresses the reply even if a later filter matches. Local MAC addresses are
six bytes, so an L2 group with a two- or eight-byte mask (Sub-TLV Length 4 or
16) never matches and always drops the request.

To protect Type 12 with authentication, configure a key source,
`--auth-mode A` and `--verify-tlv-hmac` on the reflector before you enable it.
A packet whose base fails the integrity check is dropped. If extension
integrity is missing or fails, the burst is not sent. In open mode the HMAC
stays optional even with `--verify-tlv-hmac`, so a key plus that switch does
not force senders to sign their requests.

When you configure a burst on the sender, the first request already asks for
the full count. The sender does not first send a count-one request to estimate
the load, so pick conservative values for the first request.

Every copy gets its own T3 and, in stateful mode, a sequence number assigned in
transmission order. T2 and the echoed sender fields identify the original
request. Direct Measurement and Follow-Up fields describe the session at the
time each copy is sent, and the counters advance after each successful send.
Requests that arrive during a burst do not change its CoS, source address or
return path. All copies are signed with the key selected when the request was
accepted. Copy timing is best effort and can exceed the requested interval
under load. Rate limiting or a send failure can end a burst early.

### Reply size and route MTU

`--reflected-control-max-size` (default 1500) is an administrative limit on the
STAMP payload of a padded reply (RFC 10052 §3). On Linux, both reflector
backends also look up the reply's route in the kernel before each send, and
this works with wildcard binds and alternate return addresses. With
`--interface`, the lookup is limited to that interface or VRF, as the reply
itself is. The payload
budget is the smaller of the route MTU and the egress interface MTU, minus the
IP and UDP headers and any Segment Routing Header. A plain 1500-byte link
allows 1472 STAMP bytes over IPv4 or 1452 over IPv6. Tunnel MTUs account for
their outer headers, and the overhead of supported SRv6 route encapsulation is
subtracted too. If a route uses an encapsulation the reflector does not know,
it rejects the route rather than assume the encapsulation adds nothing.

Replies are sent with fragmentation disabled. To fit the budget, the reflector
can shrink padding and remove optional reflected-header TLVs, and the HMACs
cover the final packet. A Type-12 reply clamped by the MTU has the C flag set
and ends the burst. If fewer than four padding bytes would remain, the reply
stays slightly shorter because a TLV header cannot fit. Mandatory fields are
never truncated: if they cannot fit, or the route MTU is unknown, the reply is
dropped. Windows reflectors query the selected route, cached path MTU and
interface MTU through IP Helper on every attempt, including burst copies.
They use the smaller of the path and interface values and subtract the IP and
UDP headers. If there is no path entry, the reply is dropped; there is no
fixed-size fallback. Interface pinning and SRv6 are not supported on Windows.

macOS reflectors look up native unicast IPv6 destinations on every attempt,
including burst copies and standalone BER replies. To read the kernel
estimate, the reflector binds a temporary socket to the reply source (or the
wildcard address). It sends no UDP probes and does not connect the live
reflector socket. The temporary socket has an ephemeral local port, so the
result is an estimate for the destination route, not a lookup of any
port-specific policy. This lookup does not support IPv4, IPv4-mapped peers,
interface pinning (including `--interface`) or SRv6, so those
size-controlled replies are dropped. The IPv6 fragmentation setting is turned on for
size-controlled replies and off for ordinary replies, regardless of the CoS
settings. Other platforms have no route MTU lookup, so they cannot send
size-controlled or reflected-header replies.

Raising the administrative limit allows larger replies on routes that can
carry them. `PATCH /v1/caps` changes that limit at runtime; the route limits
still apply at send time, and requests already queued use the limit in force
when they were accepted. The lookup reads kernel route and interface data; it
does not probe the path. NIC offloads, policy rewriting and encapsulation that
the route does not show need separate validation. The route cache is described
in the [architecture](architecture.md).

### Replay detection

After base validation and authentication, the reflector classifies each
sender sequence number against its session's highest sequence and a 31-entry
replay window ([RFC 10052 §5](https://www.rfc-editor.org/rfc/rfc10052.html#section-5)):
new, reordered, duplicated, or older than the window. Serial arithmetic
handles wraparound from `u32::MAX` to zero. A packet with a bad base HMAC
cannot move the window.

A usable Type-12 request with any verdict other than new gets one reply with
the U flag set on its Type-12 TLV, without the requested burst, padding or
interval. This applies in both sequencing modes and takes precedence over
`--drop-replayed`, the Type-12 limits and a zero requested count. The usual
identity, integrity and address checks still apply, and invalid TLVs get their
normal M or I flags. A later new request can again receive its burst.

`--drop-replayed` drops duplicated packets that carry no handled Type-12
request. With `--tlv-mode ignore`, Type 12 is not handled. Reordered and
out-of-window packets get their normal reply. The `packets_replayed` and
`packets_reordered` counters appear in `/v1/status`. These verdicts do not
prove an attack: a sender restarted on the same session identity can produce
them until its numbering moves past the window or the session expires.
Individual events are logged at debug level.

### CoS and Location policy

`--allowed-dscp`, `--allowed-ecn` and `--allowed-dscp-for PREFIX/LEN=SPEC`
control which requested DSCP and ECN values the reflector may apply to its
replies. By default all values are allowed. The longest matching destination
prefix replaces the global DSCP policy. The socket must still support the
value.

If the requested DSCP1 is refused, the reflector falls back to the received
DSCP2, but only when that value is permitted, and reports RPD=0b01. If both
are forbidden, it uses the lowest allowed DSCP, reports RPD=0b01 and sets C.
DSCP2 still records the ingress value. With `none` nothing is admitted, so the
reply uses the default DSCP 0 (the marking of ordinary replies), reports
RPD=0b01 and sets C. The CoS request is still answered, as RFC 8972 §4.4
requires, so `none` does not block CoS senders. The marking policy does not
apply to ordinary traffic without CoS or to opaque echoes of packets that
failed integrity checks. When a reply is retried on a return path, the policy
is checked again for the actual reply destination.

A refused ECN value is replaced by Not-ECT, with RPE=0b10. If the backend
fails to set the marking, it retries with Not-ECT and an admitted DSCP. If that
also fails, a restricted DSCP policy, including `none`, suppresses the reply.
An unrestricted policy can still send it with RPE=0b01, and you then need to
check the actual IP marking yourself. `--allowed-ecn none` refuses every EC1,
so CoS replies carry Not-ECT and RPE=0b10. Windows cannot enforce restricted
DSCP policies, so it suppresses those CoS replies. Replies dropped at send
time because a restricted DSCP policy cannot be enforced, including on a
return-path retry, are counted with the `cos_policy` drop reason.

`--location-disclose` controls which Location TLV fields the reflector reports:
`all` (default), `none`, or a comma-separated list of `src-port`, `dst-port`,
`ports`, `src-ip`, `dst-ip`, `ips` and `src-mac`. Withheld fields are zeroed.
A withheld IP address is answered with the generic sub-TLV type, so the reply
does not reveal the address family.

## Authentication

`-A A` selects authenticated mode: the base packet carries an HMAC-SHA-256
truncated to 16 bytes ([RFC 8762 §4.4](https://www.rfc-editor.org/rfc/rfc8762.html#section-4.4)).
`-A O` (default) is open mode. Authenticated mode needs a key from one of
`--hmac-key` (or `STAMP_HMAC_KEY`), `--hmac-key-file`, or, on a reflector,
`--hmac-key-dir`; without one, startup fails. Both endpoints must use the same
mode and key. With a key configured, the sender also adds an HMAC TLV that
protects its TLVs (RFC 8972 §4.8; see `--tlv-hmac`), and a reflector checks it
with `--verify-tlv-hmac`. A keyed reflector signs an open-mode reply only when
the request carried an HMAC TLV, unless it runs with `--tlv-hmac on`, so
replies to unsigned and TWAMP Light probes keep the request's size. With
`--tlv-hmac on`, a reply to an unsigned request that carries TLVs is 20 bytes
larger than the request, and a sender without the key cannot verify it and
ignores the values in the reply's TLVs. In open mode this TLV HMAC does not authenticate the
base packet and does not give authenticated-mode admission.

```bash
stamp-suite -i -A A --hmac-key-file /etc/stamp/hmac.key
stamp-suite --remote-addr 192.0.2.10 -A A --hmac-key-file /etc/stamp/hmac.key
```

A reflector with `--hmac-key-dir` uses the key for the request's SSID, or the
directory's `default.key` when there is no SSID-specific key. An authenticated
request with neither is rejected. The key selected when a request is accepted
also signs all of its replies, including burst copies and fallback replies.

Key files, key directories, permissions, SIGHUP reload and safe key rotation
are described in [key sourcing and rotation](security.md#key-sourcing-and-rotation).

## Timestamps and clocks

### Timestamp formats

`--clock-source NTP|PTP` selects wire encoding (default NTP), not clock
synchronization. The sender decodes T1/T4 using its setting and T2/T3 using
the reflector's Error Estimate Z bit (0=NTP, 1=truncated PTP). The two ends
may use different formats, also in authenticated mode. The sender converts
both to Unix time before computing T2−T1 and T4−T3.

The 32-bit seconds field is unfolded to the era closest to the local wall
clock, so the true time must be within about 68 years of the local clock. This
handles the NTP wrap in 2036 and the truncated PTP wrap in 2106.

Unknown clock offset between the endpoints shifts the forward and reverse OWD
in opposite directions; negative values are reported as measured. A PTP
nanoseconds field of one second or more is invalid: that reply gives no OWD
sample, but its RTT and receive accounting are kept. Leap seconds, leap smears
and unsynchronized NIC hardware clocks need deployment-specific handling.

### Remote clock offset

`--reflector-utc-offset SECONDS` subtracts a known clock offset from decoded
T2/T3. Local timestamps and RTT are not affected. The default, 0, matches this
suite's own software timestamps, which come from the UTC CLOCK_REALTIME clock
in both formats. For a peer that runs on TAI, use its configured TAI−UTC
offset and update it when a leap second occurs. The Z bit does not carry the
offset. For a peer configured at 37 seconds:

```bash
stamp-suite --remote-addr 192.0.2.1 --clock-source NTP --reflector-utc-offset 37
```

The TOML key is `reflector_utc_offset = 37`. A command-line value, including
zero or a negative value, overrides the file. This setting does not configure a
synchronization service, adjust a PHC, or switch the suite's own PTP timestamps
to TAI. The standard truncated PTP format uses the TAI epoch, so deployments
must account for the peer's actual time source
([RFC 8877 §4.3](https://datatracker.ietf.org/doc/html/rfc8877#section-4.3)).

### Clock synchronization metadata

`--clock-synchronized` sets the S bit of the Error Estimate, and
`--error-scale` and `--error-multiplier` set its error fields. The reflector's
Timestamp Information TLV (Type 3, RFC 8972 §4.3) reports the synchronization
source from `--clock-sync-source` for system-clock timestamps, and from
`--hardware-clock-sync-source` when T2 comes from a NIC hardware clock (PHC).
Both default to `local`, which asserts no external discipline. These are
operator declarations; the program does not detect which clock service runs.
None of these settings changes the others.

| Source setting | RFC 8972 Table 7 wire value |
| --- | --- |
| `ntp` | 1 |
| `ptp` | 2 |
| `ssu-bits` | 3 |
| `gps`, `glonass`, `loran-c`, `bds`, `galileo` | 4 (one shared external-source class) |
| `local` | 5 (local free-running) |

For example, a host disciplined by NTP can still encode timestamps as PTP:

```bash
stamp-suite --is-reflector --clock-source PTP --clock-sync-source ntp
```

The sender requests Type 3 with `--timestamp-info`. Type 3 describes the
reflector's T2 and T3. The ingress method is hardware only when T2 actually
comes from the NIC. T3 is taken in software before sending, so its method is
software, also when `--hwtstamp on` requests a NIC transmit timestamp. When T2
falls back to software, the reported source is the system-clock source, not the
PHC source.

In stateful mode, the Follow-Up Telemetry TLV reports the previous reply's
stored timestamp together with the method used to take it. A kernel software
timestamp is reported as software; a later matching hardware timestamp can
replace both. Stateless replies carry zero Follow-Up sequence and timestamp
fields.

These declarations do not align a PHC with the system clock, check lock
quality or correct for different timescales. Align the clocks used in one
measurement: even RTT can be biased when T2 is a hardware timestamp and T3 a
software one. The sender reports these declarations next to each OWD summary;
see [clock quality](measurements.md#clock-quality-accompanying-delay).

`--hwtstamp auto|on|off` (default `auto`) selects kernel software or NIC
hardware timestamps where the build and platform support them. See the
[architecture](architecture.md) and
[hardware timestamp testing](testing-hardware-timestamps.md).

## Networking

### Local address

Without `--local-addr` (or `local_addr` in TOML) the sender binds `0.0.0.0`
for an IPv4 target and `::` for an IPv6 target, so `--remote-addr ::1` needs
no other option. With several targets each session picks its own. A local
address you set is used as given for every target. An IPv4 address cannot
reach an IPv6 target, while `::` also reaches IPv4 targets unless
`net.ipv6.bindv6only` is set. The reflector binds `0.0.0.0` by default.

### Ports and TTL

With local port 0 the sender picks a random port from 49152–65535. If the
port is busy, or Windows returns WSAEACCES (10013), it tries another one, up to
128 candidates. Any other error, or a failure to bind a port you set yourself,
stops startup. The reflector defaults to port 862, and the sender's local and
remote ports must differ. When you reuse a reflector config for a sender, set
`local_port = 0`.

On a host with several local IP addresses, pick sender source ports separately
from the ports local reflectors use. Different addresses can share a port
number, and stamp-suite does not look for other local reflector services or
refuse that reuse.

With `--local-port 0` the reflector uses a port assigned by the kernel and
prints it in the startup message. The pnet backend uses that port for its
capture and reply sockets in every address family available. The configured
family must bind. If the other family is unavailable, the reflector still runs
on the configured one. An IPv6 wildcard bind uses a separate IPv6-only socket
next to the IPv4 one.

With the nix backend, a reflector bound to `::` also answers IPv4 clients,
which reach it as IPv4-mapped addresses, unless `net.ipv6.bindv6only` is set.
Their TTL and DSCP/ECN are read as for an IPv4 bind. A datagram that arrives
without TTL metadata is counted as dropped (`processing_rejected`) rather than
skipped silently.

The pnet backend does not reassemble IP fragments, so a request larger than
the path MTU, which the sending kernel fragments, gets no reply. It is counted
as received and dropped (`fragmented`) once, on its first fragment, which is
the only one that carries the UDP port, and a throttled warning names the
sender. Keep probes within the path MTU, or use the nix backend, which gets
reassembled datagrams from the kernel.

Outgoing packets use TTL/Hop Limit 255, as draft-ietf-ippm-stamp-ext-hdr-26
requires. `--ttl` accepts only 255. Received packets with a lower hop count are
accepted.

### Interface binding

`--interface NAME` binds the sender or reflector socket to a network interface
or VRF device (Linux `SO_BINDTODEVICE`, macOS `IP_BOUND_IF` and
`IPV6_BOUND_IF`). It is available on Linux and macOS only. Probes and replies
then use that device's routes, and on Linux the reflector accepts only packets
that arrive on it. The pnet backend captures on the named interface and then
also accepts a wildcard `--local-addr`.

The reflector uses the nix (UDP socket) backend by default on Linux and macOS,
and the pnet (packet capture) backend on Windows or in builds with the
`ttl-pnet` feature but not `ttl-nix`. See the [architecture](architecture.md) for the backends.

### Link-local IPv6 interface zones

Use numeric interface indices for a link-local local or remote address:

```bash
ip -j link show eth0  # read this host's or namespace's ifindex
# Example only: replace 2 with the actual local interface index.
stamp-suite --local-addr fe80::1 --local-scope-id 2 --local-port 0 \
  --remote-addr fe80::2 --remote-scope-id 2 --count 10
stamp-suite -i --local-addr fe80::2 --local-scope-id 2
```

Pass numeric zones separately from addresses; `%eth0` is not accepted in
`--local-addr` or `--remote-addr`. TOML `local_scope_id` and `remote_scope_id`
are u32, default 0. A nonzero zone is rejected for IPv4, and a link-local bind
or sender destination needs one. A missing interface fails at bind or connect
time. Indices are local to each host or namespace, so they need not match
between the endpoints.
See [RFC 4007 §11](https://www.rfc-editor.org/rfc/rfc4007.html#section-11).

The nix backend records the link-local source zone and the arrival interface
of each packet. A reflector bound to `::` can therefore reply to link-local
senders and keys each session by its scoped endpoints. Global and loopback
endpoints use zone 0, so the arrival interface does not create a separate
session for a global address. Flow labels do not identify sessions.

Provisioned session endpoints use the numeric socket-address syntax, for
example `42,[fe80::1%2]:5000,[fe80::2%2]:862`. Both zones are interface indices
on the **reflector** host. The pnet backend takes the zone from its capture
interface and uses `local_scope_id` to choose between interfaces that share an
address. It needs a concrete local address and captures on one interface per
process.

Delayed replies and fallback replies use the original zone. A link-local
Return Address TLV cannot carry a zone on the wire, so it uses the zone of the
original link-local sender, and the source address and route MTU lookup use
that interface too. Returning a reply on a different interface than the request
arrived on, and multicast sessions, are not supported. The
[namespace tests](testing-netns.md) cover these cases.

### IPv6 extension headers

The sender can attach IPv6 Hop-by-Hop and Destination Options headers and ask
the reflector to return them (draft-ietf-ippm-stamp-ext-hdr-26). Type 246
returns IPv6 extension headers and Type 247 the fixed IP header. Both types
are experimental codepoints, so both endpoints must implement revision 26 of
the draft. Header reflection is denied by default. On the reflector, configure
`--reflect-ipv6-ext-header-from IP` for extension headers and
`--reflect-fixed-header-from IP` for fixed headers; repeat a flag for each
permitted sender. The TOML equivalents are `reflect_ipv6_ext_header_from` and
`reflect_fixed_header_from` arrays. An unlisted sender receives C without
header data. Provision both endpoints and their rate/burst limits before sending.

```bash
# On the reflector, permit extension-header data for this sender.
stamp-suite --is-reflector --local-addr 2001:db8::20 --reflect-ipv6-ext-header-from 2001:db8::10

# On the sender, attach an eight-byte Hop-by-Hop header and ask for it back.
stamp-suite --remote-addr 2001:db8::20 --local-addr 2001:db8::10 --attach-ext-hdr hbh
```

- `--attach-ext-hdr hbh|dest[:HEX]` attaches a header and requests its
  reflection. It requires Linux and an IPv6 destination. Unsupported platforms
  and attachment failures stop startup.
- `--reflected-ipv6-ext-hdr LEN[:SELECTORHEX]` replaces the automatic requests.
  Requests must match attached headers in wire order.
- `--reflected-fixed-hdr [SELECTORHEX]` requests the received fixed IP header.
- Header requests need a known egress route MTU. The sender reads it before
  startup and before each send on Linux, on Windows, and on macOS for
  supported IPv6 sockets. If the budget is unknown, or the mandatory part of
  the packet is too large, startup fails before anything is sent. Later in the
  run the same conditions skip the probe instead, since the route can change.
  Skipped probes count toward the limit of eight consecutive send failures,
  after which the run ends with an error.
  Header TLVs that do not fit are removed from that probe and a warning is
  logged. Each probe starts again from the configured requests, so the removed
  TLVs come back when the MTU grows. These platforms send header probes with
  fragmentation disabled. Windows also honors an MTU cap set on the socket.
  On macOS the lookup works for connected native unicast IPv6 and honors the
  socket's minimum-MTU setting. It gives no estimate for pinned interfaces,
  IPv4 or IPv4-mapped peers. All of these are kernel estimates, not
  end-to-end path-MTU measurements. Windows and macOS support fixed-header
  requests, but attaching IPv6 extension headers still needs Linux.

Type 246 has an eight-byte Requested field; Type 247 has a four-byte one. A
nonzero Requested value matches only its nonzero octets: zero octets are
wildcards. It must select exactly one unmatched header and is returned
unchanged; zero or multiple matches return C without copying data. An all-zero
Requested field selects the first unmatched header of the requested length and
is filled with its first bytes in the reply. Selectors must zero every octet
containing mutable fields: IPv4 byte 1, IPv6 bytes 0–1, or mutable IPv6 option
data. The CLI rejects ambiguous extension-header selectors and mutable matches.

If several headers have the same length and cannot be told apart, requests
must not select only some of them. This sender sends one fixed header and at
most one hbh header followed by one dest header. CLI and TOML validation
enforce that and reject ambiguous subsets. For a captured group of headers
with identical prefixes, use one all-zero request per header in wire order. A
repeated nonzero selector returns C under the ambiguity rule of revision 26.
The draft's example that conflicts with this rule is discussed in the
[conformance interpretation](conformance/draft-stamp-ext-hdr.md#revision-26-interpretation).

On Linux, the nix reflector reads IPv6 extension headers from the socket's
ancillary data and reflects them. It cannot read the fixed IP header, so Type
247 requests get the C flag; use the pnet backend to reflect fixed headers.
Reflected-header replies need the Linux, Windows or macOS route MTU lookup described in
[Reply size and route MTU](#reply-size-and-route-mtu). The pnet capture path
drops packets with a zero, corrupt or incomplete UDP checksum, so capture where
the packets carry complete checksums, not before checksum offload fills them
in. Zero-checksum mode is not supported. See the
[ext-hdr conformance matrix](conformance/draft-stamp-ext-hdr.md) for the
clause-by-clause status.

### SRv6 return-path verification

`--srv6-return-forwarding` makes a reflector on Linux add a Segment Routing
Header to its IPv6 reply when a Return Path TLV carries an SRv6 segment list
(RFC 9503 §4). It requires the nix backend. The segment list may name transit
SIDs only or also include the final UDP destination; the reflector reserves the
final destination slot either way. The 127-entry SRH limit includes that slot.
When a path is not supported, including on the pnet backend, the reply goes
out normally with the U flag set on the Return Path TLV. The
[namespace tests](testing-netns.md) verify transit routing and check that a
fallback cannot hide a failure.

## Observability

- `--metrics` serves Prometheus metrics at `/metrics` on `--metrics-addr`
  (default `127.0.0.1:9090`). Requires the `metrics` build feature.
- `--snmp` runs an SNMP AgentX sub-agent on `--snmp-socket` (default
  `/var/agentx/master`). Requires the `snmp` feature and a Unix platform.
- `--control` serves the reflector's runtime control API on `--control-addr`
  (default `127.0.0.1:9091`). Reflector only; requires the `control` feature.
  See the [control API endpoints](control-plane.md#endpoints).

Every build accepts these flags and TOML keys. Requesting an unbuilt service
fails startup and names the option. For metrics and MIB contents, see
[architecture](architecture.md).

A Prometheus series appears only after its first event, and each labeled
series (one drop reason, one conformance reason) after its own first event. A
scrape before any traffic can return an empty page. This includes the BER and
TLV conformance counters, which `/v1/status` always lists with zeros. Treat a
missing series as zero, not as an error, in alerts and dashboards.

### Failure semantics

A requested metrics or control endpoint that cannot bind stops startup, and the
error names the service, the address and the OS error. A failed initial AgentX
connection logs a warning and STAMP keeps running without SNMP: the sub-agent
does not retry, and the MIB subtree stays unregistered until stamp-suite
restarts. Only an established AgentX connection that drops is reconnected,
with backoff from 1 to 30 s. Start `snmpd` with AgentX enabled before
stamp-suite, or restart stamp-suite once it is up. Systemd ordering can start
`snmpd` first, but it does not check that AgentX is ready.

SNMP stops on role shutdown and when its owner exits, including a finite
sender run or failed startup. A silent initial or reconnect handshake is
cancellable; each administrative read and write has a 30-second deadline.

`--count` counts successful sends. The sender validates the complete UDP
payload before probing and again after dynamic TLV changes. Invalid options
or permission errors stop the run; other send failures stop it after eight
consecutive failures. Any successful send resets that retry budget.

Prometheus counts each successful reply copy at transmission. Drop reasons
are `rate_limited`, `queue_full`, `processing_rejected`, `session_expired`,
`suppressed`, `cos_policy`, `mtu_exceeded`, `send_failed`, `cancelled` and
`fragmented`. `fragmented` is a request the pnet backend received as IP
fragments, which it does not reassemble.
`cos_policy` is a reply whose restricted DSCP policy cannot be enforced at send time,
`mtu_exceeded` one whose mandatory fields do not fit the route MTU, and
`send_failed` a socket error. Processing rejection includes
parsing, authentication, admission and replay policy; HMAC failures also have
their own counter. These totals use the same events as the shutdown summary.

`stamp_reflector_ber_conformance_total{reason="..."}` counts datagrams that
were sent successfully with a BER C condition the reflector raised itself.
The seven fixed reasons also appear in control status. Each reason is logged
on its 1st, 10th and 100th occurrence and on every later power of ten, counted
separately per reason. The occurrences in between produce no per-packet debug
message. Log entries contain reason labels and counts, but no packet contents
or session identifiers. See
[BER conformance diagnostics](ber-migration.md#conformance-diagnostics).

`stamp_reflector_tlv_conformance_total{reason="..."}` uses the same counting
and logging rules for 20 fixed reasons. They cover Type 12, header reflection,
CoS, nested control and preserved peer C flags, appear in
[control status](control-plane.md#status), and include successful MTU shaping
at send time. A header reason counts only when the offending header stays in
the sent reply. The log target is `stamp_suite::tlv::conformance`; BER uses
`stamp_suite::ber::conformance`. The Type 12 and BER counters are separate.
Metrics disabled at runtime emit no series.

- `cos_marking_unavailable` counts RPE=01 after a marking failure.
- `cos_dscp_fallback` counts replies where the reflector picked a third DSCP
  value and set C.
- The nested control counts follow C flags the reflector set on child TLVs.
- `peer_c_preserved` counts C flags copied from the peer in complete child
  headers of known container layouts, including opaque echoes of packets that
  failed integrity checks. It does not claim that the packet was verified or
  that a network fault occurred.

The tail that the legacy TLV-ignore mode copies is not interpreted.

Report output goes through a size-limited queue and must finish within five
seconds. A slow reader can cause interim reports or text packet details to be
skipped. If the final output fails, the run stops with an error. See
[report output](statistics.md#report-output-and-pending-probes).

## Residual bit error rate

`--ber` uses the combined Residual BER in Padding TLV from
`draft-ietf-bpm-stamp-ber-01`, with the experimental outer Type 243 and an
optional pattern sub-TLV of Type 241. These are local allocations, so both
peers must agree on them. The old outer Types 240–242 now get U. If a peer
returns U for the new TLV or one of its sub-TLVs, the sender turns BER off and
keeps measuring delay and loss.

The default padding pattern is `ff00ff00`, sent without a pattern sub-TLV.
For a custom pattern, use `--ber-pattern aa55aa55 --ber-padding-size 64`. A
pattern you set must be at least four bytes long, and the padding must hold a
whole number of repetitions; a five-byte pattern works with a matching size.
To keep an old two-byte pattern, write it out repeated. Remove
`--ber-omit-burst` and `ber_omit_burst = true` from your setup: the burst field
in the successor draft is fixed and cannot be omitted, so the old option now
fails validation.

The BER fields in JSON, CSV and text output keep their names. Nonzero errors
with a zero burst field mean the burst length is unavailable: the error count
is still usable, but burst statistics leave that sample out. Invalid parent or
nested flags, failed integrity, wrong patterns or resized padding never produce
a clean sample. See [measurement semantics](measurements.md#integrity-and-ber)
and [migration details](ber-migration.md). This wire change came with release
1.1.0 and does not work with the 1.0.x BER profile.

### Zero-checksum BER transmission

On Linux, an IPv4 sender can use `--zero-udp-checksum` (TOML
`zero_udp_checksum = true`) together with `--ber --auth-mode A` and a
configured key. The base and TLV HMACs protect the measurement fields. Extra
Padding is left out of the TLV HMAC, so a checksum-zero request can still reach
a reflector that accepts it when the padding has bit errors. Startup fails in
open mode (with or without a key), with `--tlv-hmac off`, in reflector mode,
with IPv6 (including mapped addresses or a mix of targets) and on other
platforms. By default the sender sends normal checksums.

```bash
stamp-suite --remote-addr 192.0.2.20 --ber --auth-mode A \
  --hmac-key-file /etc/stamp-suite/session.key --zero-udp-checksum
```

The option applies to every probe on each sender socket, including probes sent
after a peer has turned BER off with U. Authentication stays on. Only requests
are sent with a zero checksum: received packets are still checksum-checked,
and the reflector sends its replies as usual. The peer must accept IPv4
traffic with a zero checksum. This application's pnet reflector rejects it;
the Linux nix reflector accepts it. Sending needs no raw-socket privilege. The
[open-mode admission limitation](ber-migration.md#zero-checksum-ingress-boundary)
is still Partial, and the software-loopback tests say nothing about capturing
errors on a physical link or about FEC behavior.

## See also

- [Architecture](architecture.md)
- [Measurement semantics](measurements.md) and [statistics precision](statistics.md)
- [Security](security.md) and [runtime control API](control-plane.md)
- [Standards conformance](conformance/README.md)
