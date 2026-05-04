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

The canonical reference is `stamp-suite --help` (this list is generated from the same `clap` definitions). The flags below match `stamp-suite 0.7.0`.

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
      --strict-packets             Reject short packets instead of zero-filling (RFC 8762 §4.6)
      --require-hmac               Error out at startup if no HMAC key is configured
      --verify-tlv-hmac            Verify HMAC TLV (RFC 8972) on incoming packets
```

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
      --cos                        Class of Service TLV (RFC 8972 §4.4)
      --dscp <0..63>               DSCP requested via CoS TLV [default: 0]
      --ecn <0..3>                 ECN requested via CoS TLV [default: 0]
      --location                   Location TLV (RFC 8972 §4.2)
      --timestamp-info             Timestamp Information TLV (RFC 8972 §4.3)
      --direct-measurement         Direct Measurement TLV (RFC 8972 §4.5)
      --follow-up-telemetry        Follow-Up Telemetry TLV (RFC 8972 §4.7)
      --access-report <0..15>      Access Report TLV with Access ID (RFC 8972 §4.6)
      --access-return-code <CODE>  Return code for Access Report TLV [default: 1]
      --dest-node-addr <IP>        Destination Node Address TLV (RFC 9503 §4, requires --ssid)
      --return-path-cc <0|1>       Return Path control code (RFC 9503 §5)
      --return-address <IP>        Return Path alternate reply address (RFC 9503 §5)
      --return-sr-mpls-labels <L>  Comma-separated SR-MPLS label stack (RFC 9503 §5)
      --return-srv6-sids <S>       Comma-separated SRv6 segment list (RFC 9503 §5)
      --micro-session-id <ID>      Sender micro-session ID for LAG measurement (RFC 9534)
      --reflected-control-count <N>     Asymmetrical reply count (draft-ietf-ippm-asymmetrical-pkts) [default: 1]
      --reflected-control-length <LEN>  Requested reply packet length, 0 = don't pad [default: 0]
      --reflected-control-interval-ns <NS>  Inter-packet gap [default: 1_000_000]
      --reflected-fixed-hdr        Request reflected IPv4/IPv6 fixed header (TLV 247, draft-ietf-ippm-stamp-ext-hdr §4)
      --reflected-ipv6-ext-hdr     Request reflected IPv6 extension headers (TLV 246, draft-ietf-ippm-stamp-ext-hdr §3)
      --ber                        Enable BER TLVs (draft-gandhi-ippm-stamp-ber, Types 240/241/242)
      --ber-pattern <HEX>          Padding bit pattern (default: ff00)
      --ber-padding-size <BYTES>   Extra Padding length used with --ber [default: 64]
```

### Observability

All flags in this group are compiled out unless the matching Cargo feature is built in. Pre-built DEB/RPM packages from GitHub Releases include both `metrics` and `snmp` (Unix). For source builds, pass `--features metrics,snmp` to `cargo build` / `cargo install`. Without the feature, the flag is silently absent from `--help` and supplying it in a config file is rejected as an unknown key.

```
      --metrics                    Enable Prometheus endpoint (requires `metrics` feature)
      --metrics-addr <ADDR>        Metrics bind address [default: 127.0.0.1:9090]
      --snmp                       Enable SNMP AgentX sub-agent (requires `snmp` feature, Unix only)
      --snmp-socket <PATH>         AgentX master socket [default: /var/agentx/master]
```

## See Also

- [README](../README.md) — install and quick-start.
- [architecture.md](architecture.md) — module layout, receiver backends, TLV reference, Prometheus and SNMP subsystems.
- [security.md](security.md) — HMAC, key management, systemd hardening.
