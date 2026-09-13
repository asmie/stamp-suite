# Usage

Configuration and behavior reference. Start with the [README](../README.md);
use `stamp-suite --help` or the [man page](../dist/man/stamp-suite.1) for the complete
option list.

## Configuration File

Use `--config <PATH>` to load TOML settings. Explicit CLI values override file
values; omitted settings keep their built-in defaults.

```bash
stamp-suite --config /etc/stamp/reflector.toml
```

### Precedence

CLI values override TOML values, which override built-in defaults.
`STAMP_HMAC_KEY` supplies the inline HMAC key when `--hmac-key` is absent.
Key sources are mutually exclusive: an environment key combined with a file
or directory key source fails startup. See [key sourcing](security.md#key-sourcing--precedence).

### Example `reflector.toml`

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

# TOML accepts key paths, not inline keys.
hmac_key_file = "/etc/stamp/hmac.key"
```

### Supported keys

File keys generally use the CLI name in snake_case: `--remote-addr` becomes
`remote_addr`. Repeated `--reflector-session` entries use `reflector_sessions`.
The parser rejects unsupported or misspelled keys. Common value types:

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

`hmac_key` and `config` are not accepted in TOML. See [security.md](security.md) for
key-management details.

### Validation

Unknown keys, invalid TOML, and wrong value types report a parse error with a
line and column. Merged values then undergo range and combination checks,
including settings supplied only by the file.

## CLI and behavior

Run `stamp-suite --help` for options and defaults supported by your build.

### Statistics precision and retention

RTT/OWD quantiles are exact through 4,096 samples per series, then use a bounded
histogram with less than 0.78125% value error. Counts, moments, and extrema remain
cumulative. BER keeps 1,024 completed intervals and 1,024 alarms, with eviction
counters. See [statistics](statistics.md) for precision, output fields, and retention.

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

The sender also reports [reply and directional measurements](measurements.md):
individual burst copies, duplicates/reordering, Direct Measurement counter
windows and Follow-Up reverse delays. These appear under `measurements` in JSON
and in CSV column 28; `ber` remains column 27. Clock quality accompanies OWD
in JSON/text and is appended as CSV column 29 (`owd_clock_quality`). Requested copies
that remain unobserved include reflector policy limits and are not a network-loss
total. Ordinary RTT/OWD and probe-loss fields retain their first-reply semantics.

### Reflector mode

**CoS policy.** `--allowed-dscp`, `--allowed-ecn`, and destination-specific
`--allowed-dscp-for PREFIX/LEN=SPEC` control which requested values the reflector
may apply. Defaults permit all values. The most specific destination prefix
replaces the global DSCP policy. Kernel capability is checked separately.

A refused DSCP keeps the received DSCP and reports RPD=0b01. A refused ECN uses
Not-ECT and reports RPE=0b10. `--location-disclose` controls reported Location
fields: `all`, `none`, or a list of `src-port`, `dst-port`, `ports`, `src-ip`,
`dst-ip`, and `ips`. Withheld fields are zeroed; withheld IPs retain the generic
sub-TLV type to avoid disclosing the address family.

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

### TLV-driven sender features

With a nonzero `--ssid`, the sender rejects replies carrying a different nonzero
SSID before recording RTT/OWD, consuming pending probes, learning a reflector
micro-session ID, acknowledging Access Reports, or applying congestion feedback.
A matching reply can still complete the pending probe. A zero reply uses
`--on-zero-ssid continue|stop` (default `continue`), as permitted by
[RFC 8972 §3](https://www.rfc-editor.org/rfc/rfc8972.html#section-3).
Continuing after a zero reply does not disable checks on later nonzero replies.
Omitting `--ssid`, or setting it to `0`, leaves SSID validation inactive.

Access Report acknowledgement and ECN congestion control operate independently
of `-R`, logging and output format. An unusable present TLV HMAC (missing key,
invalid flags or failed verification) blocks reflected TLV control values;
invalid-length Access Reports cannot disarm the timer. U skips a TLV, M stops the
remainder, and I blocks all values. An absent HMAC retains the optional legacy-peer
policy; required Micro-session IDs, BER, Direct Measurement and Follow-Up have
stricter requirements.

With `-R`, diagnostic TLV tokens appear in fixed order (HMAC, Access Report, CE,
Micro-session ID, U/M/I counts), with each decision shown once even if repeated
TLVs support it. Text details use stdout; JSON/CSV details use stderr. `HMAC:unverified` distinguishes a present HMAC that could
not be verified from `HMAC:fail` and the absent-HMAC `no-hmac` diagnostic.

**Access Report retries.** `--access-report-timeout` (default 3 seconds) and
`--access-report-retries` (default 4) bound the delivery procedure. It continues
after the main send loop until acknowledgment or exhaustion. A silent peer can
therefore extend a short run to the 15-second default retry budget.

**ECN response.** `--cos` with `--ecn 1` or `2` enables AIMD pacing. A CE reply
multiplies the send interval by `--ecn-backoff-factor`, capped at
`--ecn-max-delay`. Clean replies reduce it by `--ecn-recovery-step` toward
`--send-delay`. Forward feedback comes from CoS EC2; reverse IP ECN is available
on Linux/macOS only. Other platforms warn and use forward feedback alone.
The same factor scales Type-12 intervals on future requests, including Access
Report retries. Reply counts stay unchanged. Summaries report CE observations,
backoffs, and current/peak intervals.

### Observability

`--metrics`, `--snmp`, and `--control` require their corresponding build features.
The flags and TOML keys remain parseable without those features; enabling an
unavailable service fails startup. See the [architecture](architecture.md) for
platform limits and the [control API](control-plane.md) for runtime management.

#### Failure semantics

A requested metrics or control endpoint that cannot bind stops startup. An
initial AgentX connection failure logs a warning and leaves STAMP running.
After an established connection drops, the sub-agent attempts reconnection.
Systemd ordering can start `snmpd` first; it does not verify AgentX readiness.

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

### Link-local IPv6 interface zones

Use numeric interface indices for a link-local local or remote address:

```sh
ip -j link show eth0  # read this host/network namespace's ifindex
# Example only: replace 2 with the actual local interface index.
stamp-suite --local-addr fe80::1 --local-scope-id 2 --local-port 0 \
  --remote-addr fe80::2 --remote-scope-id 2 --count 10
stamp-suite -i --local-addr fe80::2 --local-scope-id 2
```

The CLI accepts the IP and its numeric zone separately; `%eth0` is not part of
`--local-addr`/`--remote-addr`. Config files use `local_scope_id` and
`remote_scope_id` (unsigned 32-bit values, default 0). IPv4 endpoints reject a
nonzero scope. Link-local binds and sender destinations require a nonzero zone;
an unavailable interface still causes the operating system's bind/connect error.
Zone numbers are host/namespace-local and need not match between endpoints.
See [RFC 4007 §11](https://www.rfc-editor.org/rfc/rfc4007.html#section-11).

The nix backend preserves the source link-local scope returned by `recvmsg` and
retains the destination interface from IPv6 packet info. A wildcard `::` bind
can therefore return scoped replies and key each session by scoped source and
destination endpoints. Global/loopback endpoints keep zone 0, so an ingress
interface does not create a different global-address session. Flow labels are
not session identifiers.

Provisioned session endpoints use Rust's numeric socket-address syntax, for
example `42,[fe80::1%2]:5000,[fe80::2%2]:862`. Both zones identify interfaces on
the **reflector** host. The pnet backend gets the zone from its capture interface
and uses `local_scope_id` to disambiguate an address present on multiple interfaces;
it still requires a concrete local address and captures one interface per process.

Delayed replies and fallback-to-original sends retain scope. A link-local Return
Address TLV cannot carry a zone on the wire; it inherits the original link-local
sender's zone. Source pinning and route-MTU queries continue on that interface.
This does not implement arbitrary cross-interface link-local return routing or
multicast session support. Linux namespace tests cover wildcard/concrete nix binds,
concrete pnet binds, authenticated/open bursts, alternate returns and CLI senders.

The [clock-quality fields](measurements.md#clock-quality-accompanying-delay)
expose synchronization declarations and error estimates without claiming to verify
clock-service or hardware synchronization.

### Draft revision 13 migration

Header reflection follows revision 13, which remains an Internet-Draft.
Upgrade both endpoints together: Type 246's Requested selector grew from four
bytes to eight. Type 247 stays at four. Selectors are preserved in replies; an
all-zero eight-byte Type 246 request has no reflected data tail.

The default sender local port is 0, selecting a randomized port in
49152–65535. Automatic selection tries another candidate when a port is busy
or Windows rejects it with WSAEACCES (10013), up to 128 candidate selections.
Other errors are reported immediately; explicitly requested ports are not retried.
A reflector still defaults to 862. Explicit sender local and remote
ports must differ. Outgoing TTL/Hop Limit is 255; lower `--ttl` or TOML values
are rejected, while lower received hop counts are accepted. Set `local_port = 0`
in sender configurations that previously copied the reflector's listening port.

`--session-loss-threshold N` / `session_loss_threshold = N` configures consecutive
unanswered probes before failure (default 3, range 1–65535). Per-probe `--timeout`
defines loss. With timeout 0 no deadline-based failure is generated. State logs
and the JSON/CSV `measurements.session_state` record report idle, active, failed
and recovery; see [measurement semantics](measurements.md). Existing output
columns remain in place; the nested measurements object gains a field.

Header requests require Linux and a known egress route MTU. Explicit Type 246
requests require matching `--attach-ext-hdr` headers; omit explicit requests to
reflect all attached headers automatically. Zero-checksum mode is not exposed.
Raw capture rejects corrupt or incomplete offloaded checksums; arrange a capture
point with complete wire checksums rather than disabling validation.

### SRv6 return-path verification

`--srv6-return-forwarding` uses Linux's sticky `IPV6_RTHDR` option on the nix
backend. A return segment list may name transit SIDs only or include the final
UDP destination; the reflector reserves the final destination slot in either
case. The 127-entry SRH capacity includes that slot. Unsupported paths retain
the U-flag fallback, including pnet. The sole send owner clears a previous SRH
before sending ordinary replies. The [required namespace test](testing-netns.md)
verifies successful transit routing and prevents fallback from masking failures.

## See also

- [Architecture](architecture.md)
- [Measurement semantics](measurements.md) and [statistics precision](statistics.md)
- [Security](security.md) and [runtime control API](control-plane.md)
