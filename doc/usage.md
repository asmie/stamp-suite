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
clock_source = "NTP"         # "NTP" or "PTP"
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
| `clock_source` | enum | `"NTP"` or `"PTP"` |
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

The canonical reference is `stamp-suite --help` (this list is generated from the same `clap` definitions). The flags below match `stamp-suite 0.8.0`.

### General

```
      --config <PATH>              TOML configuration file (see "Configuration File" above)
  -r, --remote-addr <ADDR>         Remote address for Session Reflector [default: 0.0.0.0]
  -S, --local-addr <ADDR>          Local address to bind for [default: 0.0.0.0]
  -p, --remote-port <PORT>         UDP port for outgoing packets [default: 862]
  -o, --local-port <PORT>          UDP port for incoming packets [default: 862]
  -K, --clock-source <NTP|PTP>     Clock format used for timestamps [default: NTP]
  -d, --send-delay <MS>            Delay between packets in milliseconds [default: 1000]
  -c, --count <N>                  Number of packets to send [default: 1000]
  -L, --timeout <SEC>              Timeout for lost packets in seconds [default: 5]
  -A, --auth-mode <A|O>            A=authenticated, O=open [default: O]
  -R                               Print per-packet statistics
  -i, --is-reflector               Run as Session-Reflector instead of Session-Sender
      --output-format <text|json|csv>  Statistics output format [default: text]
      --log-format <text|json>     Diagnostic log format [default: text]
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

### Reflector mode

```
      --stateful-reflector         Per-client sequence numbering (RFC 8972 §4)
      --session-timeout <SEC>      Idle session reaping for stateful mode [default: 300]
      --tlv-mode <ignore|echo>     How to treat incoming TLVs [default: echo]
      --reflector-member-link-id <ID>  RFC 9534 LAG member link ID (decimal or 0x-hex)
      --srv6-return-forwarding     Best-effort SRv6 Return Path SRH forwarding
                                   (RFC 9503 §5; Linux+IPv6; off by default,
                                   graceful U-flag fallback when unsupported)
      --location-disclose <FIELDS>  Which Location TLV fields the reflector may
                                   report (RFC 8972 §4.2.2 policy control):
                                   all (default) | none | any of src-port,
                                   dst-port, ports, src-ip, dst-ip, ips.
                                   Withheld fields are answered as zeroes, so
                                   the reply's size and TLV layout do not change
      --drop-replayed              Suppress the reply to a packet whose Sequence
                                   Number was already seen on its session
                                   (draft-ietf-ippm-asymmetrical-pkts §5).
                                   Detection and counting are always on; this
                                   only decides whether a duplicate is answered.
                                   Off by default — a Session-Sender restarted
                                   mid-run replays its own numbering, and
                                   dropping its traffic would break an honest
                                   measurement
      --strict-packets             Reject short packets instead of zero-filling (RFC 8762 §4.6)
      --require-hmac               Error out at startup if no HMAC key is configured
      --verify-tlv-hmac            Verify HMAC TLV (RFC 8972) on incoming packets
```

**Reply-size cap and the live egress MTU (draft-ietf-ippm-asymmetrical-pkts
§3).** `--reflected-control-max-size` bounds the STAMP reply the reflector will
pad up to for a Type-12 `length` request. On Linux, when `--local-addr` names a
single interface, the reflector also reads that interface's MTU via `SIOCGIFMTU`
at startup and enforces whichever cap is smaller, logging the reduction. The
practical effect at the defaults: on a 1500-byte link the effective cap is 1472
(MTU less the IPv4 and UDP headers, or 1452 for IPv6), so a maximum-length
request gets the draft's C-flag/single-reply treatment instead of producing a
1528-byte datagram that the path would have to fragment. Raise the flag for a
jumbo link, or lower it to cap replies below the path MTU. The query is
best-effort — a wildcard bind has no single egress interface, and a failed query
or a non-Linux platform simply leaves the flag as the only cap. The sender does
the equivalent check with `getsockopt(IP_MTU)`, which only answers on a
connected socket and so cannot be used by a reflector.

**Replay detection (draft-ietf-ippm-asymmetrical-pkts §5).** The reflector
tracks the Sequence Number of every received packet against a 31-entry
per-session window and classifies it as new, reordered, replayed, or older than
the window. This runs unconditionally — the draft notes the HMAC TLV is no
defence here, since a replayed packet carries a valid HMAC. Two counters,
`packets_replayed` and `packets_reordered`, appear in the control-plane
`/v1/status` response (reordering is separated out because it is ordinary on a
real path). Detection never changes what is sent unless `--drop-replayed` is
set. Per-event logging stays at debug level on purpose: the sequence numbers are
attacker-controlled, so warning per event would hand a remote peer a
log-amplification lever.

RFC 8972 §4.2.2 lets a reflector "leave some fields unreported by filling them
with zeroes" under local policy and requires an implementation to provide
control over that policy; `--location-disclose` is that control. It only
affects what the reflector *answers* — a request for a withheld field is still
echoed as Answered (not flagged unrecognized), and a withheld IP request keeps
its generic sub-TLV type rather than being rewritten to the IPv4/IPv6 variant,
since the variant would itself disclose the observed address family.

### Authentication

```
      --hmac-key <HEX>             HMAC key, hex string (also via STAMP_HMAC_KEY env)
      --hmac-key-file <PATH>       Path to file containing HMAC key
```

### Timestamp / clock

```
      --error-scale <0..63>        Error estimate scale [default: 0]
      --error-multiplier <0..255>  Error estimate multiplier [default: 1]
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
      --micro-session-id <ID>      Sender micro-session ID for LAG measurement (RFC 9534)
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
      --ber                        Enable BER TLVs (draft-gandhi-ippm-stamp-ber, Types 240/241/242)
      --ber-pattern <HEX>          Padding bit pattern (default: ff00)
      --ber-padding-size <BYTES>   Extra Padding length used with --ber [default: 64]
      --malformed <bad-flags|bad-length>
                                   Diagnostic: append a deliberately malformed
                                   TLV to test a reflector's RFC 8972 §4.2
                                   handling (conformance testing only)
```

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
