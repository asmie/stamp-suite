# Usage

Reference manual for running `stamp-suite`: configuration file format, every supported TOML key, and the complete CLI flag list. The top-level [README](../README.md) has quick-start examples for the reflector and sender; this document is the deep reference for every option they can take.

## Configuration File

Any option accepted on the command line can also be supplied through a TOML
configuration file via `--config <PATH>`. Values in the file are used as
defaults; any key not present in the file keeps its built-in default.

```bash
stamp-suite --config /etc/stamp/reflector.toml
```

### Precedence

From highest to lowest priority:

1. Command-line flag (e.g. `--remote-port 1234`)
2. `STAMP_HMAC_KEY` environment variable (for the HMAC key only)
3. Value from the `--config` TOML file
4. Hardcoded default

In other words: the file provides new defaults; CLI flags and env vars still
override them field-by-field.

#### Caveat for the HMAC key

Precedence works field-by-field, but `--hmac-key` (also fed by `STAMP_HMAC_KEY`)
and `--hmac-key-file` are **mutually exclusive** — both `Configuration::validate()`
and clap's `conflicts_with` enforce that. As a consequence, supplying
`STAMP_HMAC_KEY` in the environment **and** `hmac_key_file = "..."` in the TOML
file fails startup with `Invalid configuration: hmac_key and hmac_key_file are
mutually exclusive`. Pick exactly one source for the key:

- environment / CLI: `STAMP_HMAC_KEY=...` or `--hmac-key <HEX>`
- on-disk path: `--hmac-key-file <PATH>` or `hmac_key_file = "..."` in the TOML

### Example `reflector.toml`

```toml
# Reflector bound on a specific address/port
is_reflector = true
local_addr = "192.0.2.10"
local_port = 862

# Protocol behaviour
auth_mode = "O"              # "A" for authenticated, "O" for open
clock_source = "NTP"         # timestamp encoding: "NTP" or "PTP"
clock_sync_source = "local"  # declared system-clock discipline
hardware_clock_sync_source = "local" # declared NIC PHC discipline
tlv_mode = "echo"            # "echo" or "ignore"
stateful_reflector = true
session_timeout = 300

# Optional features
metrics = true
metrics_addr = "127.0.0.1:9090"

# HMAC key – only a PATH can be set from the config file.
# The plaintext `hmac_key` field is deliberately rejected; pass the raw
# key via --hmac-key or the STAMP_HMAC_KEY environment variable instead.
hmac_key_file = "/etc/stamp/hmac.key"
```

### Supported keys

Every long-form CLI flag is available in the file using its snake_case
name (e.g. `--remote-addr` becomes `remote_addr`, `--ber-padding-size`
becomes `ber_padding_size`). Examples of non-trivial types:

| Field | TOML type | Example |
|-------|-----------|---------|
| `remote_addr`, `local_addr`, `dest_node_addr`, `return_address` | string (IPv4 or IPv6) | `"192.0.2.10"`, `"2001:db8::1"` |
| `metrics_addr` | string (`addr:port`) | `"127.0.0.1:9090"` |
| `auth_mode` | enum | `"A"` or `"O"` |
| `clock_source` | enum | `"NTP"` or `"PTP"` (encoding only) |
| `clock_sync_source`, `hardware_clock_sync_source` | enum | `"local"`, `"ntp"`, `"ptp"`, `"ssu-bits"`, `"gps"`, `"glonass"`, `"loran-c"`, `"bds"`, `"galileo"` |
| `reflector_utc_offset` | signed integer | Sender: remote clock seconds ahead of UTC; subtract from T2/T3 for OWD. Default `0`. |
| `tlv_mode` | enum | `"echo"` or `"ignore"` |
| `output_format` | enum | `"text"`, `"json"`, or `"csv"` |
| `return_sr_mpls_labels` | integer array | `[100, 200, 300]` |
| `return_srv6_sids` | string array (IPv6) | `["2001:db8::1", "2001:db8::2"]` |
| `hmac_key_file` | string (path) | `"/etc/stamp/hmac.key"` |

The `hmac_key` and `config` fields are intentionally **not** accepted
from the file — the former to keep plaintext secrets out of config files,
the latter because it would be recursive. See [security.md](security.md) for
key-management details.

### Validation and error messages

Failures are reported with actionable messages:

- **Unknown key** (typo): the parse error lists every valid field name.
  ```text
  Configuration file error: parse error in /etc/stamp.toml:
  TOML parse error at line 1, column 1
    |
  1 | remote_portt = 1234
    | ^^^^^^^^^^^^
  unknown field `remote_portt`, expected one of `remote_addr`, `local_addr`, ...
  ```
- **Wrong type / bad enum variant / malformed TOML**: reported with the
  exact line/column and caret marker from the `toml` crate.
- **Out-of-range values** (e.g. `dscp = 200`, `error_scale = 100`, or
  `auth_mode = "A"` without an HMAC key): caught by
  `Configuration::validate()` after the merge, with a message naming the
  offending field.

## Full CLI reference

The canonical reference is `stamp-suite --help` (this list is generated from the same `clap` definitions). The flags below match `stamp-suite 1.0.0`.

### General

```
      --config <PATH>              TOML configuration file (see "Configuration File" above)
  -r, --remote-addr <ADDR>         Remote address for Session Reflector [default: 0.0.0.0]
  -S, --local-addr <ADDR>          Local address to bind for [default: 0.0.0.0]
  -p, --remote-port <PORT>         UDP port for outgoing packets [default: 862]
  -o, --local-port <PORT>          UDP port for incoming packets [default: 862]
  -K, --clock-source <NTP|PTP>     Timestamp wire encoding [default: NTP]
      --clock-sync-source <SOURCE> Declared system-clock discipline [default: local]
      --hardware-clock-sync-source <SOURCE> Declared NIC PHC discipline [default: local]
  -d, --send-delay <MS>            Delay between packets in milliseconds [default: 1000]
  -c, --count <N>                  Number of packets to send [default: 1000]
  -L, --timeout <SEC>              Timeout for lost packets in seconds [default: 5]
  -A, --auth-mode <A|O>            A=authenticated, O=open [default: O]
  -R                               Print per-packet statistics (stderr for JSON/CSV)
  -i, --is-reflector               Run as Session-Reflector instead of Session-Sender
      --output-format <text|json|csv>  Statistics output format [default: text]
      --log-format <text|json>     Diagnostic log format on stderr [default: text]
  -v, --verbose...                 Increase log verbosity (-v debug, -vv trace);
                                   RUST_LOG overrides
      --hwtstamp <auto|on|off>     Kernel/hardware timestamp handling [default: auto]
                                   (build with --features hwtstamp; `auto` = kernel
                                   software timestamps, `on` = attempt NIC hardware
                                   with graceful fallback, `off` = userspace only)
      --print-config-schema        Print JSON Schema for the TOML config and exit
      --report-interval <SEC>      Periodic reporting interval, sender only (0 = disabled) [default: 0]
      --max-pps <PPS>              Reflector rate limit per source (0 = unlimited) [default: 0]
  -h, --help                       Print help
  -V, --version                    Print version
```

### Output streams

`--output-format` selects measurement output on **stdout**. Sender JSON is
newline-delimited: periodic snapshots have `"type":"interim"` and the final
snapshot has `"type":"summary"`. CSV emits one header followed by snapshot rows;
the final row is the final summary. Optional columns remain present, and the
`ber` cell contains CSV-quoted JSON when BER is enabled. Reflectors emit one
shutdown summary, as a JSON object or a CSV header and row.
Reflector summaries include `reply_queue_rejected` (requests refused at the
work limit) and `queued_replies_cancelled` (unsent copies discarded on shutdown
or a failed handoff). CSV appends these two columns after `uptime_seconds`.
Queue rejection adds one to aggregate dropped packets; cancelling the remainder
of a queued request also adds one, regardless of its number of unsent copies.

Diagnostic logs and reflector startup notices go to **stderr**. `--log-format`
controls tracing events there; `RUST_LOG` and `-v` control their verbosity.
`-R` packet details remain on stdout for text output and move to stderr for
JSON/CSV. These explicitly requested details stay plain text and remain visible
with `RUST_LOG=off`; startup/validation errors can also be plain text even with
`--log-format json`.

```bash
stamp-suite --remote-addr 192.0.2.10 --output-format json > measurements.jsonl 2> diagnostics.log
stamp-suite --remote-addr 192.0.2.10 --output-format csv --report-interval 10 > measurements.csv 2> diagnostics.log
```

`--print-config-schema` emits only the schema on stdout and exits before logger
initialization. In library code, reuse `stats::StatsOutput` with
`sender::run_sender_with_output` and the returned final snapshot to share CSV
header state. The older snapshot printing methods emit standalone reports.

### Reflector mode

```
      --stateful-reflector         Per-client sequence numbering (RFC 8972 §4)
      --session-admission <MODE>   permissive (legacy default) or provisioned
      --reflector-session <SPEC>   SSID,SOURCE,DESTINATION[,SENDER_MICRO_ID]; repeatable
      --session-timeout <SEC>      Idle runtime session reaping [default: 300]
      --tlv-mode <ignore|echo>     How to treat incoming TLVs [default: echo]
      --reflector-member-link-id <ID>  Configured reflector Micro-session ID (decimal or 0x-hex)
      --srv6-return-forwarding     Best-effort SRv6 Return Path SRH forwarding
                                   (RFC 9503 §5; Linux+IPv6; off by default,
                                   graceful U-flag fallback when unsupported)
      --allowed-dscp <SPEC>        DSCP codepoints the reflector may apply to a
                                   reply (RFC 8972 §4.4/§6, cos-ecn-01 §3.2):
                                   all (default) | none | list of values and
                                   ranges, e.g. 0,8,10-14,46. A refused DSCP1
                                   is not applied; the reply keeps the received
                                   DSCP and the echoed TLV reports RPD=0b01
      --allowed-ecn <SPEC>         ECN codepoints the reflector may apply:
                                   all (default) | none | list of 0-3. A refused
                                   EC1 forces the reply's ECN to Not-ECT and the
                                   echoed TLV reports RPE=0b10
      --allowed-dscp-for <RULE>    Destination-scoped DSCP policy overriding
                                   --allowed-dscp for replies inside a prefix:
                                   PREFIX/LEN=SPEC, e.g. 192.0.2.0/24=0,46.
                                   REPEATABLE; the most specific matching prefix
                                   wins regardless of order, and a matching rule
                                   replaces the global set rather than adding
                                   to it
      --location-disclose <FIELDS>  Which Location TLV fields the reflector may
                                   report (RFC 8972 §4.2.2 policy control):
                                   all (default) | none | any of src-port,
                                   dst-port, ports, src-ip, dst-ip, ips.
                                   Withheld fields are answered as zeroes, so
                                   the reply's size and TLV layout do not change
      --drop-replayed              Suppress ordinary duplicated packets.
                                   Handled Type-12 requests instead receive one
                                   U-flagged reply on non-monotonic ordering,
                                   even with this flag set (draft §5).
                                   Off by default; detection/counting always on
      --strict-packets             Reject short packets instead of zero-filling (RFC 8762 §4.6)
      --require-hmac               Error out at startup if no HMAC key is configured
      --verify-tlv-hmac            Verify HMAC TLV (RFC 8972) on incoming packets
```

**CoS admission policy — permitted vs capable (RFC 8972 §4.4/§6,
draft-ietf-ippm-stamp-cos-ecn-01 §3.2).** The RFC requires the reflector to "use
the local policy to verify whether the CoS corresponding to the value of the
DSCP1 field is permitted in the domain". Attempting the setsockopt and treating
failure as refusal only answers a different question — whether the host is
*capable* — because the kernel knows nothing about the operator's domain policy
and will happily apply a codepoint the network is not meant to carry.
`--allowed-dscp`, `--allowed-ecn` and `--allowed-dscp-for` supply the *permitted*
answer; the socket still supplies the *capable* one, and a request must clear
both. A refused DSCP1 is reported with RPD=0b01 and the reply keeps the received
DSCP; a refused EC1 is reported with RPE=0b10 and the reply's ECN is forced to
Not-ECT. Nothing is dropped and no TLV is flagged malformed — refusal is a
reported outcome, not an error. Defaults permit everything.

**Burst replies.** When Type-12 reflection is enabled, every copy gets its own
T3 and, in stateful mode, a sequence number assigned in transmission order.
T2 and the echoed sender fields identify the original request. DM and Follow-Up
fields reflect the session at each send; counters advance after successful sends.
Interleaved requests do not change a burst's CoS, source-address, or return-path
settings. All copies use the key selected when the request was accepted.
The nix loop schedules copies by deadline; a dedicated pnet worker keeps burst
waits off the capture thread. Timing is best-effort and can exceed the requested
interval under load. Rate limiting or a send failure can stop a burst early.
`--reflector-queue-capacity` bounds pending requests across packet processing,
capture handoff, scheduled deadlines and the active send. Its default is 1024;
zero is rejected. Each request holds one slot until every copy finishes or the
request is discarded. At capacity, new requests are dropped before authentication
or session mutation; already accepted work keeps its slots. This is a request
count limit, not a byte quota; retained payload sizes vary. Session expiry still
retires queued work, whose slot is released when it is serviced or discarded.

Ctrl-C, SIGTERM on Unix, and `POST /v1/shutdown` stop new packet intake.
`--reflector-shutdown-grace-ms` allows already queued replies to finish for up
to the configured interval (0–60000 ms); the default 0 cancels immediately.
An empty queue exits early. Repeated shutdown requests do not extend the deadline.
Remaining copies are cancelled at the deadline and included in the shutdown
summary. The interval starts when the send loop observes shutdown; polling,
OS scheduling and an in-progress syscall can add latency. Pnet capture checks
idle shutdown at 100 ms intervals independently of `--session-timeout`, including
when session expiry is disabled. Its handoff is bounded and nonblocking; capture
and send workers are joined before the final summary.

The session drain switch (`POST /v1/drain`) remains separate: it rejects new
session identities while existing sessions can submit work subject to the queue
limit. To finish accepted work and exit, use shutdown with a grace period.

The equivalent TOML settings are:

```toml
reflector_queue_capacity = 1024
reflector_shutdown_grace_ms = 500
```

**Reply-size cap and the actual reply route (draft-ietf-ippm-asymmetrical-pkts-14
§3).** `--reflected-control-max-size` is an administrative STAMP payload limit.
On Linux, both reflector backends also query the reply's UDP route with
`RTM_GETROUTE`, including source/destination addresses, UDP ports, DSCP and IPv6
scope. This works with wildcard binds and alternate return addresses. The budget
uses the smaller of the route MTU metric and egress interface MTU, less IP/UDP
headers and any attached SRH. A plain 1500-byte link allows 1472 STAMP bytes over
IPv4 or 1452 over IPv6. Tunnel-device MTUs account for their outer headers;
supported SRv6 lightweight route encapsulation reserves its additional overhead.
Unknown lightweight encapsulation is rejected rather than treated as zero cost.

The per-send-owner cache holds at most 256 routes for 250 ms. Route, interface,
address and routing-rule notifications invalidate it; unavailable notification
subscriptions disable caching. Each burst copy and routing fallback checks its
budget. Fragmentation is disabled for these sends; `EMSGSIZE` forces one fresh
lookup and resizing retry. Padding can shrink and optional reflected header TLVs
can be removed; final HMACs cover all changes. An MTU-clamped Type-12 response
sets C and ends the burst. If fewer than four padding bytes would be needed, the
reply stays slightly shorter because a TLV header cannot fit. Mandatory fields
are never truncated: an unsatisfiable budget or unavailable route MTU drops the
reply. Route MTU lookup is currently Linux-only, so non-Linux reflectors cannot
send size-controlled or reflected-header replies through this path.

Raising the administrative limit permits larger replies on suitable routes.
`PATCH /v1/caps` reports that configured limit, with route limits still applied
at send time. Already queued requests retain their captured administrative cap.
This performs kernel route/interface lookup, not active path MTU probing; NIC
offload, arbitrary policy rewriting and encapsulation not visible in the route
require separate deployment validation.

**Replay detection (draft-ietf-ippm-asymmetrical-pkts-14 §5).** After base
validation and configured authentication, the reflector classifies each sender
Sequence Number against its session's high-water mark and 31-entry replay
bitmap: new, reordered, duplicated, or older than the window. Serial arithmetic
handles wraparound from `u32::MAX` to zero. The window is committed after
response assembly; a failed base HMAC cannot plant a sequence number.

A usable Type-12 request with any non-new verdict receives a single response
with U=1 on Type 12. Its requested burst, padding, and interval are not applied.
This behavior is active with either sequencing mode and takes precedence over
`--drop-replayed`, the Type-12 count/size controls, and a zero requested count.
Existing identity, integrity, and address-group rejection rules still apply;
invalid TLVs retain their M/I handling. Base/TLV response signatures cover the
final flags. A subsequent new request can again receive its requested burst.

`--drop-replayed` optionally suppresses duplicated packets without a handled
Type-12 request; with `--tlv-mode ignore`, Type 12 is not handled. Reordered and
out-of-window ordinary packets retain their normal response. Counters
`packets_replayed` and `packets_reordered` appear in `/v1/status`; ordering
failures do not prove an attack. Restarting a sender on the same session identity
may produce these verdicts until numbering advances or the session expires.
Per-event logging remains at debug level.

RFC 8972 §4.2.2 lets a reflector "leave some fields unreported by filling them
with zeroes" under local policy and requires an implementation to provide
control over that policy; `--location-disclose` is that control. It only
affects what the reflector *answers* — a request for a withheld field is still
echoed as Answered (not flagged unrecognized), and a withheld IP request keeps
its generic sub-TLV type rather than being rewritten to the IPv4/IPv6 variant,
since the variant would itself disclose the observed address family.

### Micro-session ID validation

`--micro-session-id` enables numeric ID validation. The sender requires one usable
Micro-session ID TLV in every accepted measurement; a base-only reply cannot satisfy
it. Missing, U/M/I-flagged, malformed, duplicate, wrong, or unverifiable IDs leave
the probe pending and do not produce RTT/OWD samples. With a configured HMAC key,
the ID requires a usable, valid TLV HMAC too. A valid later reply can still satisfy
the probe before its timeout.

The reflector ID must be nonzero. `--reflector-member-link-id` supplies an expected
value; on a sender it requires `--micro-session-id`. Without a preconfigured
reflector ID, the sender learns it from the first accepted reply to a pending
probe and rejects later changes. Learning does not trust unsolicited replies.
Ordinary sessions without micro-session options retain base-only compatibility.

These flags do **not** bind IDs to interfaces, steer packets over a specific LAG
member, or identify the physical ingress member. Full per-member LAG measurement
is unsupported; configuring numbers or UDP tuples alone does not verify it.
See the [RFC 9534 scope and gaps](conformance/rfc9534.md).

### Authentication

A reflector with `--hmac-key-dir` resolves the request's SSID-specific key first,
then the directory's default key if present. Once a keyset exists, it takes
precedence over the legacy single key. An authenticated request with no matching
or default key is rejected.

The selected key is retained through final reply signing, including CoS rejection,
unsupported/failed SRv6 return paths, alternate-address fallback, and burst copies.
Runtime rotation or revocation affects newly processed requests. Replies already
accepted into the queue finish with their original key; changing keys does not
cancel those copies. Keep the old key available to the sender long enough to
validate any outstanding replies during a planned rotation. Removing a per-SSID
entry still permits that SSID through a configured default key; remove the default
as well when access must be revoked. Open-mode TLV integrity does not authenticate
the base packet and does not provide authenticated-mode admission semantics.

```
      --hmac-key <HEX>             HMAC key, hex string (also via STAMP_HMAC_KEY env)
      --hmac-key-file <PATH>       Path to file containing HMAC key
```

### Timestamp / clock

The sender decodes its own T1/T4 using `--clock-source` and the reflector's
T2/T3 using the reflector Error Estimate's Z bit (0 = NTP, 1 = truncated PTP).
Both endpoint formats can differ, including in authenticated sessions.
Decoded timestamps use a common Unix epoch before computing T2−T1 and T4−T3.
The 32-bit seconds field is unfolded to the era nearest the local wall clock;
the true timestamp must be within about 68 years of that reference. This handles
the NTP wrap in 2036 and truncated PTP wrap in 2106 without an era-sized delay.

`--reflector-utc-offset <SECONDS>` is a sender setting for a **known** remote
clock offset after epoch conversion. It is subtracted from T2/T3, not applied
to local timestamps or RTT. Default `0` matches this suite's software timestamps:
both wire encodings are generated from UTC/CLOCK_REALTIME. For a TAI-based peer,
set the peer's configured TAI−UTC offset; do not infer it from the Z bit or
assume a fixed offset will remain valid through future leap seconds. For
example, if the peer configuration specifies an offset of 37 seconds:

```bash
stamp-suite --remote-addr 192.0.2.1 --clock-source NTP --reflector-utc-offset 37
```

The equivalent TOML key is `reflector_utc_offset = 37`; an explicit CLI value,
including zero or a negative value, overrides the file. This does not configure
a synchronization service, adjust a PHC, or change the suite's outgoing PTP
clock to TAI. The standard truncated PTP format uses a TAI epoch; deployments
must account for the peer's actual time source ([RFC 8877 §4.3](https://datatracker.ietf.org/doc/html/rfc8877#section-4.3)).

Unknown clock skew still shifts the two signed OWD measurements in opposite
directions; negative values are retained. A PTP nanoseconds word of one second
or more is invalid and omits that reply's OWD sample while preserving valid RTT
and receive accounting. Leap-second/smear transitions and unsynchronized NIC
hardware clocks still require deployment-specific clock handling.

```
      --error-scale <0..63>        Error estimate scale [default: 0]
      --error-multiplier <0..255>  Error estimate multiplier [default: 1]
      --reflector-utc-offset <SECONDS>  Sender: remote clock offset from UTC [default: 0]
      --clock-synchronized         Mark clock as synchronized in error estimate
```

### TLV-driven sender features

```
      --ssid <ID>                  Session-Sender Identifier (RFC 8972 §3)
      --on-zero-ssid <ACTION>      What to do when a reply comes back with a
                                   zeroed SSID field, i.e. the reflector is not
                                   demultiplexing on SSID (RFC 8972 §3):
                                   continue (default, logs once) | stop (ends
                                   the session on the first such reply).
                                   Inert unless a non-zero --ssid was set
      --cos                        Class of Service TLV (RFC 8972 §4.4).
                                   Also marks the egress IP header (TOS /
                                   IPv6 Traffic Class) to match DSCP/ECN
                                   (Linux/macOS).
      --dscp <0..63>               DSCP requested via CoS TLV [default: 0]
      --ecn <0..3>                 ECN requested via CoS TLV [default: 0]
      --ecn-backoff-factor <F>     AIMD congestion-response backoff factor
                                   (draft-ietf-ippm-stamp-cos-ecn-01 §3.4);
                                   must be > 1.0 [default: 2.0]
      --ecn-max-delay <MS>         AIMD send-interval cap, milliseconds
                                   (draft-ietf-ippm-stamp-cos-ecn-01 §3.4)
                                   [default: 30000]
      --ecn-recovery-step <MS>     AIMD recovery step per clean reply,
                                   milliseconds; interval never goes below
                                   --send-delay
                                   (draft-ietf-ippm-stamp-cos-ecn-01 §3.4)
                                   [default: 50]
      --ttl <1..255>               IP TTL / IPv6 Hop Limit for outgoing test
                                   packets [default: OS default] (Linux/macOS)
      --location                   Location TLV (RFC 8972 §4.2)
      --timestamp-info             Timestamp Information TLV (RFC 8972 §4.3)
      --direct-measurement         Direct Measurement TLV (RFC 8972 §4.5)
      --follow-up-telemetry        Follow-Up Telemetry TLV (RFC 8972 §4.7)
      --access-report <1..15>      Access Report TLV with Access ID (RFC 8972 §4.6;
                                   1=3GPP, 2=Non-3GPP are the only currently
                                   defined values; 3-15 warn at startup)
      --access-return-code <CODE>  Return code for Access Report TLV [default: 1]
      --access-report-timeout <SECS>  Access Report TLV retransmission timer,
                                   in seconds (RFC 8972 §4.6) [default: 3]
      --access-report-retries <N>  Max Access Report TLV retransmissions before
                                   the procedure is aborted (RFC 8972 §4.6);
                                   0 disables retransmission [default: 4]
      --dest-node-addr <IP>        Destination Node Address TLV (RFC 9503 §4, requires --ssid)
      --return-path-cc <0|1>       Return Path control code (RFC 9503 §5)
      --return-address <IP>        Return Path alternate reply address (RFC 9503 §5)
      --return-sr-mpls-labels <L>  Comma-separated SR-MPLS label stack (RFC 9503 §5)
      --return-srv6-sids <S>       Comma-separated SRv6 segment list (RFC 9503 §5)
      --micro-session-id <ID>      Sender numeric Micro-session ID (no physical-link selection)
      --reflected-control-count <N>     Asymmetrical reply count (draft-ietf-ippm-asymmetrical-pkts) [default: 1]
      --reflected-control-length <LEN>  Requested reply packet length, 0 = don't pad [default: 0]
      --reflected-control-interval-ns <NS>  Inter-packet gap [default: 1_000_000]
                                            NOTE: if --send-delay is shorter
                                            than (count - 1) x interval, the
                                            next request would start while the
                                            reflector is still replying to the
                                            previous one; the sender warns at
                                            startup and names the minimum
                                            (draft-ietf-ippm-asymmetrical-pkts
                                            §5 SHOULD NOT)
      --reflected-fixed-hdr [SELECTORHEX]   Request a reflected IPv4/IPv6 fixed header (TLV 247, draft-ietf-ippm-stamp-ext-hdr §3.2). REPEATABLE: one occurrence per requested IP header (e.g. outer+inner for an IP-in-IP tunnel), each pairing positionally with the reflector's outer→inner capture. Optional inline §5.2 selector hex.
      --reflected-fixed-hdr-selector <HEX>  §5.2 selector (single-header form only): first bytes must match the received IP header, else the reflector sets the C flag (requires exactly one --reflected-fixed-hdr with no inline selector)
      --reflected-ipv6-ext-hdr [LEN[:SELECTORHEX]]  Request a reflected IPv6 extension header (TLV 246, draft-ietf-ippm-stamp-ext-hdr §3.1). REPEATABLE: one occurrence per requested header, in order, with matching lengths. LEN = the header's on-wire size (default 8); optional inline §5.1 selector hex.
      --reflected-ipv6-ext-hdr-selector <HEX>  §5.1 selector (single-header form only): return only the matching extension header; the 4 bytes are the header's on-wire first 4 octets — byte 0 is its Next Header field, NOT its type (requires exactly one --reflected-ipv6-ext-hdr with no inline selector)
      --attach-ext-hdr <KIND[:HEX]>  Attach a REAL IPv6 extension header to the sender's egress packets and request its reflection (draft-ietf-ippm-stamp-ext-hdr §3.1). REPEATABLE. KIND = hbh (Hop-by-Hop, IPV6_HOPOPTS) or dest (Destination Options, IPV6_DSTOPTS); optional HEX is the full header buffer (multiple of 8 octets, byte 0 kernel-assigned; default = 8-octet PadN). Each attached header also emits a matching Type-246 request TLV. Linux + IPv6 destination only (the sticky socket options are not exposed by `libc` on Darwin); elsewhere a warning is logged (on non-IPv4 the request TLV is still sent).
      --ber                        Enable BER-07 measurement (experimental Types 240/241/242)
      --ber-pattern <HEX>          Padding bit pattern (default: ff00)
      --ber-padding-size <BYTES>   Positive multiple of pattern length [default: 64]
      --ber-interval <N>           Computation window = N × send-delay [default: 10]
      --ber-bit-threshold <PPM>    Optional bit-error threshold, both directions (0..1000000)
      --ber-packet-threshold <PPM> Optional errored-packet threshold, both directions (0..1000000)
      --ber-omit-burst             Omit the Max Bit Error Burst Size TLV
                                   (Type 242) from --ber packets. Type 242 is in
                                   the Experimental Use range (RFC 8972 §5.1) and
                                   is used independently, with an incompatible
                                   wire format, by another implementation's
                                   "Heartbeat" TLV; this keeps the rest of the
                                   BER exchange usable against such a peer
      --extra-padding <BYTES>      Append an Extra Padding TLV of this many value
                                   octets to every packet (RFC 8972 §4.1),
                                   independent of --ber. Pseudorandom fill per
                                   §4.2. Conflicts with --ber, which fills the
                                   padding TLV with its own known pattern
      --tlv-hmac <auto|on|off>     Whether the sender originates an HMAC TLV
                                   (RFC 8972 §4.8) [default: auto].
                                   auto = originate when a key is configured,
                                   on = always (requires a key),
                                   off = never, even with a key — the key is
                                   then used only for base-packet auth and for
                                   verifying reflected TLV HMACs
      --malformed <bad-flags|bad-length>
                                   Diagnostic: append a deliberately malformed
                                   TLV to test a reflector's RFC 8972 §4.2
                                   handling (conformance testing only)
```

With a nonzero `--ssid`, the sender rejects replies carrying a different nonzero
SSID before recording RTT/OWD, consuming pending probes, learning a reflector
micro-session ID, acknowledging Access Reports, or applying congestion feedback.
A matching reply can still complete the pending probe. A zero reply uses
`--on-zero-ssid continue|stop` (default `continue`), as permitted by
[RFC 8972 §3](https://www.rfc-editor.org/rfc/rfc8972.html#section-3).
Continuing after a zero reply does not disable checks on later nonzero replies.
Omitting `--ssid`, or setting it to `0`, leaves SSID validation inactive.

**Note:** `--access-report`'s retransmission procedure (RFC 8972 §4.6) can extend the sender's total run time past what `--count`/`--send-delay` alone would predict. If the reflector never echoes the Access Report TLV back, the sender keeps retransmitting and waiting — independently of the main send loop — until the retry budget (`access-report-timeout * (1 + access-report-retries)`, up to 15 seconds at the defaults of 3s/4 retries) is exhausted, at which point the procedure aborts and the run ends (the measurement itself is unaffected either way). A run using `--count 1` with `--access-report` set will therefore take at least as long as that retry budget whenever the reflector doesn't support (or drops) the TLV.

**Note (AIMD congestion response, draft-ietf-ippm-stamp-cos-ecn-01 §3.4):** whenever `--cos` is combined with `--ecn 1` (ECT1) or `--ecn 2` (ECT0), the sender activates an AIMD controller that dictates the inter-packet send interval instead of a fixed `--send-delay`. On each CE (Congestion Experienced) observation the interval is multiplied by `--ecn-backoff-factor` (capped at `--ecn-max-delay`); after each reply that was *not* CE-marked, the interval shrinks by `--ecn-recovery-step` back toward `--send-delay` (never faster). CE is detected from either direction the draft's §3.4 MUSTs cover: the reflected CoS TLV's EC2 field (forward path, sender→reflector) and the reply packet's own on-wire ECN (reverse path, reflector→sender). Reading the reply's on-wire ECN requires `IP_RECVTOS`/`IPV6_RECVTCLASS` support and is available on **Linux and macOS only**; on other platforms only the forward-path (EC2) direction is detected — a startup warning is logged. When a Reflected Test Packet Control TLV is also requested (`--reflected-control-count` > 1 or `--reflected-control-no-ext-hdr`), its `interval_nanoseconds` field is scaled by the same controller for future packets (§3.4-3). There is no flag to disable this response while ECN measurement is requested — the draft's MUST is unconditional in that case. Congestion-response counters (CE replies seen, backoffs applied, current/peak interval) appear in the stats output; see `--print-stats`/`--output-format`.

### Observability

All flags in this group are compiled out unless the matching Cargo feature is built in. Pre-built DEB/RPM packages from GitHub Releases include both `metrics` and `snmp` (Unix). For source builds, pass `--features metrics,snmp` to `cargo build` / `cargo install`. Without the feature, the flag is silently absent from `--help` and supplying it in a config file is rejected as an unknown key.

```
      --metrics                    Enable Prometheus endpoint (requires `metrics` feature)
      --metrics-addr <ADDR>        Metrics bind address [default: 127.0.0.1:9090]
      --snmp                       Enable SNMP AgentX sub-agent (requires `snmp` feature, Unix only)
      --snmp-socket <PATH>         AgentX master socket [default: /var/agentx/master]
```

#### Failure semantics

The two observability subsystems handle initialization failure differently, by design:

- **`--metrics` fails fast.** If the operator explicitly requested a Prometheus endpoint and the bind fails (`AddrInUse`, `AddrNotAvailable`, `PermissionDenied`, …), `stamp-suite` exits non-zero with a specific error message. The reasoning: silently disabling the endpoint would leave dashboards and alerts running blind without any signal that they are.
- **`--snmp` degrades gracefully.** If the AgentX master socket is absent or unreachable (e.g. `net-snmpd` hasn't started yet during boot), `stamp-suite` logs a warning and continues. The reflector's primary duty — forwarding STAMP packets — is unaffected. Operators who want SNMP-required-to-start semantics can wrap `stamp-suite.service` with a systemd ordering directive (`After=snmpd.service`, `Requires=snmpd.service`).

## See Also

- [README](../README.md) — install and quick-start.
- [architecture.md](architecture.md) — module layout, receiver backends, TLV reference, Prometheus and SNMP subsystems.
- [security.md](security.md) — HMAC, key management, systemd hardening.

## Session provisioning

RFC 8972 §3 requires provisioned session identification and dropping unmatched
packets. Enable this with `--session-admission provisioned`. The default,
`permissive`, keeps legacy discovery from incoming traffic and does not enforce
those provisioning requirements. This policy applies with or without
`--stateful-reflector`; that flag controls independent reflector sequence
numbers instead of echoing the sender's sequence.

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
Repeat `--reflector-session` on the CLI. IPv6 endpoints use brackets, for example
`42,[2001:db8::10]:4862,[2001:db8::20]:862,7`. All fields match exactly;
addresses must be concrete and ports nonzero. A wildcard reflector bind may
accept provisioned concrete destinations of the same family and bound port.
SSID 0 explicitly provisions a base session without an assigned SSID. Omitting
the micro ID matches packets without a Micro-Session ID TLV; it is not a wildcard.
The reflector member ID remains controlled by `--reflector-member-link-id`.

An empty provisioned list denies all traffic. Invalid/duplicate entries,
entries incompatible with the bind address, sender-side admission options, and
entries supplied in permissive mode fail startup validation. Per-SSID HMAC keys
are independent of admission: installing a key does not provision an endpoint.
Session timeout and control-plane expiry remove runtime counters/replay state,
not admission rules. Provisioning changes require configuration and restart.

Both admission modes separate sequence numbers, counters, replay windows, and
Follow-Up state by source endpoint, actual destination endpoint, SSID, and sender
micro-session ID. Duplicate Micro-Session ID TLVs are dropped as ambiguous.
Malformed TLVs provide no micro-session identity and retain ordinary M-flag
echo processing if the remaining identity is admitted.
Shutdown JSON/text and the control API identify these distinct sessions; SNMP
retains its existing unique internal session index and source-address columns.

Base-packet rejection does not allocate a session, extend its idle timeout,
increment its receive count, consume a stateful sequence, or affect replay and
Follow-Up state. This includes bad base HMACs, unknown/revoked per-SSID keys,
and short packets rejected by `--strict-packets`. These packets still enter
aggregate receive/drop counters. A valid base packet with a failed TLV HMAC
retains RFC 8972's I-flag reply behavior. Session caps and drain behavior remain
separate from authentication admission.


### Clock synchronization metadata

`--clock-source NTP|PTP` selects the timestamp encoding. It does not establish
which service disciplines the clock. The reflector's Type-3 Timestamp Information
TLV uses `--clock-sync-source` for system-clock timestamps and
`--hardware-clock-sync-source` when T2 actually comes from a NIC PHC. Both default
to `local`: no external discipline is asserted. Sources are explicit operator
configuration, not clock-service detection. `--clock-synchronized` independently
sets the Error Estimate S bit; neither setting changes the other.

| Source setting | RFC 8972 Table 7 wire value |
| --- | --- |
| `ntp` | 1 |
| `ptp` | 2 |
| `ssu-bits` | 3 |
| `gps`, `glonass`, `loran-c`, `bds`, `galileo` | 4 (one shared external-source class) |
| `local` | 5 (local free-running) |

For example, a host disciplined by NTP can still encode timestamps as PTP:

```sh
stamp-suite --is-reflector --clock-source PTP --clock-sync-source ntp
```

Type 3 describes the reflector's T2 and T3; the sender requests it with zeroed
information fields. Ingress method is hardware only for an actual hardware T2.
Current T3 is generated in software before sending, so its method is software,
including when `--hwtstamp on` requests a later NIC transmit timestamp. A fallback
to software T2 uses the system source, not the PHC source.

Stateful Follow-Up Telemetry reports the previous reply's stored timestamp and
its actual acquisition method together. A kernel software report stays software;
a later matching hardware report can upgrade both timestamp and method. Delayed
reports for a different sequence and software downgrades of an existing hardware
record are rejected. Every burst copy refreshes this record before signing.
Stateless replies retain zero Follow-Up sequence/timestamp fields.

These declarations do not align a PHC with the system clock, verify lock quality,
or compensate for different timescales. Align clocks used in the same measurement;
even round-trip calculations can be biased when T2 is hardware and T3 is software.
The live regression covers software fallback on loopback; NIC hardware provenance
and separate clock disciplines use deterministic fixtures, not a physical PTP testbed.

Library callers now supply `ProcessingContext::clock_sync_source`,
`hardware_clock_sync_source`, and `last_reflection_method` (replacing `tx_method`).
`SyncSource::from_byte(4)` returns `External`: the wire cannot distinguish the
individual sources in that class. Named source aliases encode to 4; 6–9 are no
longer assigned the incorrect legacy meanings.

### Session capacity, drain, and restart

`--max-sessions` bounds runtime entries keyed by both UDP endpoints, SSID, and
optional sender micro ID (default 65536; `0` means unlimited). At the cap, new
identities receive no reply in either sequencing mode. Rejection creates no
session, consumes no session ID or stateful sequence, and enters the aggregate
drop counter. Existing sessions continue with their sequences, counters,
replay windows, and Follow-Up state. A smaller runtime cap never evicts them.

Provisioning controls which identities may be admitted; it does not reserve
capacity or bypass the cap. Size the cap for the intended concurrent sessions.
Idle cleanup, explicit expiry, or increasing the cap can free admission capacity.
With `--session-timeout 0`, automatic idle cleanup is disabled.

The control API's drain switch rejects new identities, even with an unlimited
cap, while allowing existing sessions and their queued replies to continue.
Turning drain off restores admission subject to provisioning and capacity.
Drain/cap changes serialize with session creation; once a change is acknowledged,
new acquisitions use the updated policy.

Manual expiry or idle cleanup ends a runtime session. Expiry waits for a send
already in progress, then prevents the old instance's queued replies from
transmitting. Queued entries are discarded when the send queue next services
them. A subsequent admitted packet for the same identity starts a new internal
session with sequence zero and fresh measurement/replay state; provisioning
remains intact. Outgoing burst copies do not refresh the receive-idle timeout.
A sender restart alone does not reset a still-active reflector session.

BER output includes directional packet and padding-bit totals, error ratios,
maximum/average error bursts, and nonempty computation windows. `ber_interval`,
`ber_bit_threshold` and `ber_packet_threshold` are also TOML keys. See
[BER behavior and limits](architecture.md#bit-error-rate-tlvs-draft-gandhi-ippm-stamp-ber).

AgentX query ordering, partial-frame handling, resource limits and verification scope
are documented in the [AgentX review](conformance/agentx-review.md).
