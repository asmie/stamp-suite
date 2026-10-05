# Usage

Sender and reflector configuration, output and runtime behavior.
For a quick start, see the [README](../README.md) or `stamp-suite -h`.
For all options and defaults
in your build, use `stamp-suite --help` or the [man page](../dist/man/stamp-suite.1).

## Configuration file

Use `--config <PATH>` to load settings from a TOML file. Settings you omit
from both the file and the command line use their built-in defaults.
Keep deployment settings such as provisioned sessions, destination policies,
resource limits and metrics/SNMP/control settings in the file. CLI flags are
useful for per-run changes and diagnostics; advanced flags appear in `--help`.

```bash
stamp-suite --config /etc/stamp/reflector.toml
```

### Precedence

A command-line value overrides the environment, the environment overrides the
file, and the file overrides the built-in default. The only option read from
the environment is `STAMP_HMAC_KEY`, which supplies the inline HMAC key when
`--hmac-key` is absent. Key sources are mutually exclusive: an environment key
combined with a key file or key directory from the TOML file fails startup.
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

Unknown keys, invalid TOML and wrong types fail startup with line/column
errors. Merged settings receive the same range and combination checks as CLI
values. On Unix, group- or other-writable config files warn; see
[file permissions](security.md#file-permissions).

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
| `-c`, `--count` | probes | `1000` | Probes to send. `0` sends until `--duration` ends or the sender is interrupted. |
| `--duration` | seconds | none | Stop sending after this time, even if `--count` probes have not all been sent. Must be at least 1. |
| `-L`, `--timeout` | seconds (0 to 255) | `5` | How long to wait for a reply before the probe counts as lost. |

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

### Send schedule

`--send-schedule poisson` draws exponentially distributed gaps with
`--send-delay` as their mean (RFC 2330 §11.1.1). The default `periodic` uses
a fixed gap (RFC 3432).

Send times follow a fixed timeline, so the time spent building and sending a
probe does not stretch the gap. Gaps under 1 ms are busy-waited because Tokio
timers have 1 ms resolution, so rates above 1000 probes per second keep one CPU
core busy. A sender that falls more than 2 ms behind its timeline restarts the
timeline instead of sending a burst to catch up.

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
port, and the same address cannot be listed twice. Every session is set up
before any probe is sent, and a startup error in one session stops the run.

Reports name their target: a `Target:` line in text, a `target` field in
JSON, and a leading `target` column in CSV. These labels appear only when the
sender has more than one target. Prometheus and SNMP counters add up all
sessions, and the SNMP configuration objects describe the first target.

```bash
stamp-suite --remote-addr 192.0.2.10,192.0.2.11 --remote-addr 2001:db8::20 \
  --local-addr :: --count 0 --report-interval 60 --output-format json
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
validation errors can also be plain text even with `--log-format json`.

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
probe. Requested reply copies that were never observed include copies the
reflector declined by policy, so they are not a network-loss count.

RTT and OWD quantiles are exact up to 4096 samples per series and use a bounded
histogram after that. See [statistics precision and retention](statistics.md).

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

**SSID checks.** With a nonzero `--ssid`, the sender rejects a reply that
carries a different nonzero SSID before it records RTT or OWD, completes a
pending probe, learns a reflector micro-session ID, acknowledges an Access
Report or applies congestion feedback. A reply with a zero SSID is handled by
`--on-zero-ssid continue|stop` (default `continue`), as
[RFC 8972 §3](https://www.rfc-editor.org/rfc/rfc8972.html#section-3) permits.
After a zero-SSID reply under `continue`, later nonzero replies are still
checked. Without `--ssid`, or with `--ssid 0`, the sender does not check SSIDs.

**TLV integrity.** Access Report acknowledgement and ECN congestion control
work the same regardless of `-R`, logging and output format. A TLV HMAC that is
present but unusable (no key, invalid flags or failed verification) blocks all
reflected TLV control values. An Access Report with an invalid length cannot
stop its retry timer. A U flag skips that TLV, an M flag stops processing the
rest, and an I flag blocks all values. When the HMAC TLV is absent, the sender
accepts the optional TLVs from peers that do not send one. Required
Micro-session IDs, BER, Direct Measurement and Follow-Up have stricter rules.

With `-R`, the per-packet line shows TLV results in a fixed order: HMAC, Access
Report, CE, Micro-session ID, then U/M/I counts. Each result appears once even
when several TLVs support it. `HMAC:unverified` marks a present HMAC that could
not be verified, `HMAC:fail` a failed verification, and `no-hmac` an absent
HMAC.

**Access Report retries.** `--access-report-timeout` (default 3 seconds) and
`--access-report-retries` (default 4) bound the delivery procedure. Retries
continue after the main send loop until the reflector acknowledges the report
or the retries run out. A silent peer can therefore extend a short run by up to
15 seconds with the defaults.

**ECN response.** `--cos` with `--ecn 1` or `--ecn 2` turns on AIMD pacing. A
CE-marked reply multiplies the send interval by `--ecn-backoff-factor`, up to
`--ecn-max-delay` milliseconds. Each clean reply shortens it by
`--ecn-recovery-step` milliseconds, down to `--send-delay`. Forward feedback
comes from the CoS TLV's EC2 field. Reverse feedback reads the reply's IP ECN
bits, which works on Linux and macOS only; other platforms log a warning and
use forward feedback alone. The same factor scales the Type-12 interval of
later requests, including Access Report retries; reply counts do not change.
Reports show CE observations, backoffs, and the current and peak intervals.

## Reflector

Run a reflector with `-i` (`--is-reflector`). It listens on UDP port 862 by
default and answers every admitted test packet.

```bash
stamp-suite -i --local-addr 192.0.2.10
```

By default the reflector is stateless: it echoes the sender's sequence number.
`--stateful-reflector` keeps an independent sequence counter per session, so
the sender can detect loss on the reverse path. `--tlv-mode echo` (default)
processes the TLVs it supports and flags the rest; `--tlv-mode ignore` copies
everything after the base packet unprocessed. By default a short packet is
zero-filled for TWAMP-Light interoperability; `--strict-packets` drops it
instead (RFC 8762 §4.6).

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
in permissive mode. Per-SSID HMAC keys are independent of admission:
installing a key does not provision an endpoint. Session timeout and
control-plane expiry remove runtime counters and replay state, not admission
rules. Changing the provisioned sessions requires a configuration change and a
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
`--strict-packets`. Such packets still count in the aggregate receive and drop
counters. A valid base packet with a failed TLV HMAC gets the RFC 8972 I-flag
reply.

### Capacity, drain and shutdown

**Session cap.** `--max-sessions` limits the number of runtime sessions
(default 65536; `0` means unlimited). At the cap, packets for a new session get
no reply in either sequencing mode. The rejected packet creates no session,
consumes no session ID or sequence number, and counts as dropped. Existing
sessions continue normally. Lowering the cap at runtime never evicts them.

Provisioning controls which sessions may be admitted; it does not reserve
capacity or bypass the cap, so size the cap for the expected number of
concurrent sessions. Idle cleanup, explicit expiry or a higher cap frees room.
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
request is discarded. When the queue is full, new requests are dropped before
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

### Burst replies (Type 12)

A Reflected Test Packet Control TLV (Type 12,
[RFC 10052 §3](https://www.rfc-editor.org/rfc/rfc10052.html#section-3)) asks
the reflector for several reply copies. Type-12 reflection is off by default:
`--reflected-control-max-count 0` treats the TLV as unsupported and answers
with one U-flagged reply. Set a positive cap (for example 16) to turn it on,
and pair it with `--max-pps` to limit amplification. Requests above
`--reflected-control-max-count`, `--reflected-control-max-rate`,
`--reflected-control-max-volume` or below `--reflected-control-min-interval-ns`
get one reply with the C flag set.

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
this works with wildcard binds and alternate return addresses. The payload
budget is the smaller of the route MTU and the egress interface MTU, minus the
IP and UDP headers and any Segment Routing Header. A plain 1500-byte link
allows 1472 STAMP bytes over IPv4 or 1452 over IPv6. Tunnel MTUs account for
their outer headers, and supported SRv6 route encapsulation reserves its
overhead. A route with an unknown encapsulation is rejected rather than
treated as free.

Replies are sent with fragmentation disabled. To fit the budget, the reflector
can shrink padding and remove optional reflected-header TLVs, and the HMACs
cover the final packet. A Type-12 reply clamped by the MTU has the C flag set
and ends the burst. If fewer than four padding bytes would remain, the reply
stays slightly shorter because a TLV header cannot fit. Mandatory fields are
never truncated: if they cannot fit, or the route MTU is unknown, the reply is
dropped. Route MTU lookup is Linux-only, so reflectors on other platforms
cannot send size-controlled or reflected-header replies.

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

A refused DSCP leaves the received DSCP on the reply and reports RPD=0b01. A
refused ECN sends the reply as Not-ECT and reports RPE=0b10.

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
with `--verify-tlv-hmac`. In open mode this TLV HMAC does not authenticate the
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
the reflector's Error Estimate Z bit (0=NTP, 1=truncated PTP). Formats may
differ, including in authenticated mode; both convert to Unix time before
computing T2−T1 and T4−T3.

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
T2/T3; local timestamps and RTT are unchanged. Default 0 matches this suite's
UTC CLOCK_REALTIME software timestamps in both formats. For a TAI peer, use
its configured TAI−UTC offset and update it on leap seconds. Z does not encode
the offset. Example for a peer configured at 37 seconds:

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

### Ports and TTL

Local port 0 chooses a random sender port from 49152–65535, retrying up to
128 candidates on busy ports or Windows WSAEACCES (10013). Other errors and
explicit-port failures stop startup. The reflector defaults to 862; sender
and remote ports must differ. When reusing a reflector config for a sender,
set `local_port = 0`.

Outgoing packets use TTL/Hop Limit 255, as draft-ietf-ippm-stamp-ext-hdr-15
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
are u32, default 0. IPv4 rejects nonzero zones; link-local binds and sender
destinations require one. Missing interfaces fail at bind/connect. Indices
are local to each host or namespace and need not match across endpoints.
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
the reflector to return them (draft-ietf-ippm-stamp-ext-hdr-15). Type 246
returns IPv6 extension headers and Type 247 the fixed IP header. Both types
are experimental codepoints, so both endpoints must implement revision 15 of
the draft.

```bash
# Attach an eight-byte Hop-by-Hop header and ask for it back.
stamp-suite --remote-addr 2001:db8::20 --local-addr 2001:db8::10 --attach-ext-hdr hbh
```

- `--attach-ext-hdr hbh|dest[:HEX]` attaches a header and requests its
  reflection. It works on Linux with an IPv6 destination; elsewhere the header
  is not attached and a warning is logged. If attaching fails on Linux,
  startup fails.
- `--reflected-ipv6-ext-hdr LEN[:SELECTORHEX]` replaces the automatic requests.
  Requests must match attached headers in wire order.
- `--reflected-fixed-hdr [SELECTORHEX]` requests the received fixed IP header.
- Header requests need a known egress route MTU, which the sender reads on
  Linux. Without it, startup fails. Header TLVs that do not fit the MTU are
  removed from the probe and a warning is logged.

Type 246 has an eight-byte Requested field; Type 247 has a four-byte one. A
nonzero Requested value selects the header whose first bytes match it and is
returned unchanged. A zero Requested value selects the first header of the
requested length and is filled with that header's first bytes in the reply.

On Linux, the nix reflector reads IPv6 extension headers from the socket's
ancillary data and reflects them. It cannot read the fixed IP header, so Type
247 requests get the C flag; use the pnet backend to reflect fixed headers.
Reflected-header replies need the Linux route MTU lookup described in
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

### Failure semantics

A requested metrics or control endpoint that cannot bind stops startup, and the
error names the service, the address and the OS error. A failed initial AgentX
connection logs a warning and STAMP keeps running. If an established AgentX
connection drops, the sub-agent reconnects. Systemd ordering can start `snmpd`
first, but it does not check that AgentX is ready.

SNMP stops on role shutdown and when its owner exits, including a finite
sender run or failed startup. A silent initial or reconnect handshake is
cancellable; each administrative read and write has a 30-second deadline.

`--count` counts successful sends. The sender validates the complete UDP
payload before probing and again after dynamic TLV changes. Invalid options
or permission errors stop the run; other send failures stop it after eight
consecutive failures. Any successful send resets that retry budget.

Prometheus counts each successful reply copy at transmission. Drop reasons
are `rate_limited`, `queue_full`, `processing_rejected`, `session_expired`,
`suppressed`, `send_failed` and `cancelled`. Processing rejection includes
parsing, authentication, admission and replay policy; HMAC failures also have
their own counter. These totals use the same events as the shutdown summary.

Report output has a bounded queue and a five-second completion deadline. A
slow reader can cause interim reports or text packet details to be skipped;
a final-output failure stops the run with an error. See
[report output](statistics.md#report-output-and-pending-probes).

## See also

- [Architecture](architecture.md)
- [Measurement semantics](measurements.md) and [statistics precision](statistics.md)
- [Security](security.md) and [runtime control API](control-plane.md)
- [Standards conformance](conformance/README.md)
