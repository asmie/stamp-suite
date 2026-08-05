use std::{fmt, net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};
use thiserror::Error;

use crate::{
    cos_policy::{parse_destination_rule, CosAdmissionPolicy, DscpSet, EcnSet},
    tlv::LocationDisclosure,
};

pub use crate::clock_format::ClockFormat;
pub use crate::hwtstamp::HwTsMode;
pub use crate::stats::OutputFormat;

/// A secret string sourced from the CLI (`--hmac-key`) or the environment
/// (`STAMP_HMAC_KEY`).
///
/// Wrapped so the plaintext key is (a) zeroized on drop — it cannot be
/// recovered from a core dump or freed heap once the value is gone — and
/// (b) redacted from `Debug`, so it never leaks through a `{:?}` of
/// `Configuration`. A plain `String` would do neither.
#[derive(Clone)]
pub struct SecretString(zeroize::Zeroizing<String>);

impl SecretString {
    /// Borrows the secret as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for SecretString {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(zeroize::Zeroizing::new(s.to_owned())))
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

/// Diagnostic log output format. Selected via `--log-format`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Default,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable single-line output (the default; matches the
    /// historic `env_logger` style).
    #[default]
    Text,
    /// Structured JSON, one event per line. Suitable for ingestion by
    /// log shippers (Fluent Bit, Vector, journald JSON forwarder).
    Json,
}

/// STAMP authentication mode per RFC 8762.
///
/// A STAMP session is either authenticated or unauthenticated (open), not both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Deserialize)]
pub enum AuthMode {
    /// Authenticated mode - packets include HMAC for integrity verification.
    #[value(name = "A")]
    #[serde(rename = "A")]
    Authenticated,
    /// Open (unauthenticated) mode - packets are sent without HMAC authentication.
    #[default]
    #[value(name = "O")]
    #[serde(rename = "O")]
    Open,
}

impl AuthMode {
    /// Returns true if this is authenticated mode.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self, AuthMode::Authenticated)
    }
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated => write!(f, "A"),
            Self::Open => write!(f, "O"),
        }
    }
}

/// TLV handling mode for the reflector.
///
/// Controls how the reflector handles TLV extensions in incoming packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlvHandlingMode {
    /// Ignore TLVs - strip them from reflected packets (zero-pad to preserve length).
    Ignore,
    /// Echo TLVs back to sender, marking unknown types with U-flag per RFC 8972.
    #[default]
    Echo,
}

impl fmt::Display for TlvHandlingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ignore => write!(f, "ignore"),
            Self::Echo => write!(f, "echo"),
        }
    }
}

/// What the Session-Sender does when a reflected packet comes back with a
/// zeroed SSID field.
///
/// RFC 8972 §3 describes a reflector that returns a zeroed SSID (it does not
/// support the field, or declines to echo it) and requires that "an
/// implementation of a Session-Sender MUST support control of its behavior in
/// such a scenario". This enum is that control. Only meaningful when the sender
/// actually set a non-zero `--ssid`: without one, a zeroed reply field carries
/// no information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZeroSsidAction {
    /// Keep measuring, logging the condition once. The RFC permits continuing,
    /// and it is the useful default for a probe pointed at an unknown peer.
    #[default]
    Continue,
    /// Stop the session on the first zeroed-SSID reply. For an operator who
    /// requires SSID-demultiplexed sessions, a reflector that drops the field
    /// makes the measurement meaningless.
    Stop,
}

impl fmt::Display for ZeroSsidAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::Stop => write!(f, "stop"),
        }
    }
}

/// Selects the kind of deliberately malformed TLV the sender injects (for
/// conformance-testing a reflector's RFC 8972 §4.2 malformed/flag handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MalformedMode {
    /// A structurally valid TLV whose flags octet has reserved bits set
    /// (RFC 8972 §4.2 requires reserved bits to be zero).
    BadFlags,
    /// A TLV whose Length field far exceeds the bytes actually present, so a
    /// conformant reflector must set the M-flag and stop processing.
    BadLength,
}

/// Command-line configuration for the STAMP application.
///
/// This struct defines all configurable parameters for both sender and reflector modes,
/// parsed from command-line arguments using clap.
#[derive(Parser, Debug)]
#[clap(author = "Piotr Olszewski", version, about, long_about = None)]
pub struct Configuration {
    /// Path to a TOML configuration file. Values loaded from the file are used
    /// as defaults; command-line flags and environment variables always
    /// override them.
    #[clap(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the JSON Schema for the TOML configuration file to stdout
    /// and exit. The schema can be fed to validators like the
    /// `jsonschema` CLI or used by IDE plugins for autocomplete:
    ///
    /// `stamp-suite --print-config-schema > stamp-suite-config.schema.json`
    ///
    /// Then `jsonschema -i my-config.toml stamp-suite-config.schema.json`
    /// (after a TOML→JSON conversion via `taplo`/`yj`).
    #[clap(long, exclusive = true)]
    pub print_config_schema: bool,
    /// Remote address for Session Reflector
    #[clap(short, long, default_value = "0.0.0.0")]
    pub remote_addr: std::net::IpAddr,
    /// Local address to bind for
    #[clap(short = 'S', long, default_value = "0.0.0.0")]
    pub local_addr: std::net::IpAddr,
    /// UDP port number for outgoing packets
    #[clap(short = 'p', long, default_value_t = 862)]
    pub remote_port: u16,
    /// UDP port number for incoming packets
    #[clap(short = 'o', long, default_value_t = 862)]
    pub local_port: u16,
    /// Clock source to be used
    #[clap(short = 'K', long, default_value = "NTP")]
    pub clock_source: ClockFormat,
    /// Delay between next packets
    #[clap(short = 'd', long, default_value_t = 1000)]
    pub send_delay: u16,
    /// Count of packets to be sent
    #[clap(short = 'c', long, default_value_t = 1000)]
    pub count: u16,
    /// Amount of time to wait for packet until consider it lost (in seconds).
    #[clap(short = 'L', long, default_value_t = 5)]
    pub timeout: u8,
    /// Specify work mode - A for authenticated, O for open (unauthenticated) - default "O".
    #[clap(short = 'A', long, value_enum, default_value_t = AuthMode::Open)]
    pub auth_mode: AuthMode,
    /// Print individual statistics for each packet.
    #[clap(short = 'R')]
    pub print_stats: bool,
    /// Run as Session Reflector instead of Session Sender.
    #[clap(short = 'i', long, default_value_t = false)]
    pub is_reflector: bool,

    /// Error estimate scale (0-63). Default: 0
    #[clap(long, default_value_t = 0)]
    pub error_scale: u8,

    /// Error estimate multiplier (0-255). Default: 1
    #[clap(long, default_value_t = 1)]
    pub error_multiplier: u8,

    /// Mark clock as synchronized in error estimate.
    #[clap(long)]
    pub clock_synchronized: bool,

    /// HMAC key as hex string; at least 32 hex chars (16 bytes) are required.
    ///
    /// A shorter key is rejected outright, not warned about. 64 hex chars
    /// (32 bytes, matching the HMAC-SHA-256 output length) is a good default.
    ///
    /// Note: a key passed on the command line is visible in `ps` /
    /// `/proc/<pid>/cmdline` to other local users, and an env-var key is
    /// visible to anyone who can read the process environment. Prefer
    /// `--hmac-key-file` in production. The value is held zeroize-on-drop and
    /// is redacted from debug output (see `SecretString`).
    #[clap(long, env = "STAMP_HMAC_KEY")]
    pub hmac_key: Option<SecretString>,

    /// Path to file containing HMAC key.
    #[clap(long, conflicts_with = "hmac_key")]
    pub hmac_key_file: Option<PathBuf>,

    /// Path to a directory of per-SSID HMAC key files. Each file's name
    /// (minus extension) is interpreted as the SSID in hex; a file named
    /// `default.key` becomes the fallback for unknown SSIDs. Mutually
    /// exclusive with `--hmac-key` and `--hmac-key-file`. Lets a single
    /// reflector serve multiple senders without sharing a key, and
    /// enables key rotation by re-running with a new directory.
    #[clap(long, conflicts_with_all = ["hmac_key", "hmac_key_file"])]
    pub hmac_key_dir: Option<PathBuf>,

    /// Require HMAC key to be configured (error if missing in auth mode).
    /// Note: When an HMAC key is present, verification is always mandatory per RFC 8762 §4.4.
    #[clap(long)]
    pub require_hmac: bool,

    /// Reject short packets instead of zero-filling (RFC 8762 Section 4.6).
    /// By default, missing bytes are zero-filled for TWAMP-Light interoperability.
    #[clap(long)]
    pub strict_packets: bool,

    /// Enable stateful reflector mode per RFC 8972 Section 4. The reflector maintains
    /// independent sequence counters for each client (IP:port) instead of echoing
    /// the sender's sequence number, allowing clients to detect reflector-side packet loss.
    #[clap(long)]
    pub stateful_reflector: bool,

    /// Session timeout in seconds for stateful reflector mode. Sessions inactive for
    /// this duration may be cleaned up. Default: 300 (5 minutes). Set to 0 to disable.
    #[clap(long, default_value_t = 300)]
    pub session_timeout: u64,

    /// DSCP codepoints the reflector may apply to a reply when a Class of
    /// Service TLV requests them (RFC 8972 §4.4/§6, cos-ecn-01 §3.2).
    ///
    /// `all` (default), `none`, or a comma-separated list of values and
    /// inclusive ranges: `0,8,10-14,46`. A refused DSCP1 is not applied; the
    /// reply keeps the received DSCP and the echoed TLV reports RPD=0b01.
    ///
    /// This is the *permitted* check the RFC asks for. Whether the value can
    /// actually be set — *capable* — remains a separate question answered by
    /// the socket, and a request must clear both.
    ///
    /// Reflector-side only.
    #[clap(long, default_value = "all", value_name = "SPEC")]
    pub allowed_dscp: String,

    /// ECN codepoints the reflector may apply to a reply's IP header when a
    /// Class of Service TLV requests them (cos-ecn-01 §3.2).
    ///
    /// `all` (default), `none`, or a comma-separated list of 0-3. A refused EC1
    /// forces the reply's ECN bits to Not-ECT and the echoed TLV reports
    /// RPE=0b10.
    ///
    /// Reflector-side only.
    #[clap(long, default_value = "all", value_name = "SPEC")]
    pub allowed_ecn: String,

    /// Destination-scoped DSCP policy, overriding `--allowed-dscp` for replies
    /// addressed inside a prefix: `PREFIX/LEN=SPEC`, e.g.
    /// `--allowed-dscp-for 192.0.2.0/24=0,46`.
    ///
    /// Repeatable. The most specific matching prefix wins regardless of the
    /// order given, and a matching rule *replaces* the global set rather than
    /// adding to it. cos-ecn-01 §3.2 names exactly this shape: "a policy ...
    /// configured for specific destination addresses or networks".
    ///
    /// Reflector-side only.
    #[clap(long, value_name = "PREFIX/LEN=SPEC")]
    pub allowed_dscp_for: Vec<String>,

    /// Suppress the reply to a packet whose Sequence Number was already seen
    /// on its session (draft-ietf-ippm-asymmetrical-pkts-14 §5).
    ///
    /// Detection is always on and counted; this flag makes the reflector act on
    /// it. Off by default because a duplicate is not proof of an attack — a
    /// Session-Sender restarted mid-run replays its own numbering, and dropping
    /// its traffic would break an honest measurement. Turn it on where replayed
    /// Type-12 requests are a real amplification concern.
    ///
    /// Reflector-side only.
    #[clap(long)]
    pub drop_replayed: bool,

    /// Which Location TLV fields the reflector may report (RFC 8972 §4.2.2).
    ///
    /// §4.2.2 lets a reflector "leave some fields unreported by filling them
    /// with zeroes" under local policy, and requires an implementation to
    /// provide control over that policy. Comma-separated: `all` (default),
    /// `none`, or any of `src-port`, `dst-port`, `ports`, `src-ip`, `dst-ip`,
    /// `ips`. A withheld field is answered as zeroes, so the reply's size and
    /// TLV structure are unchanged.
    ///
    /// Reflector-side only; ignored by the sender.
    #[clap(long, default_value = "all", value_name = "FIELDS")]
    pub location_disclose: String,

    /// TLV handling mode for the reflector (RFC 8972). Default: echo.
    /// - ignore: Strip TLVs from reflected packets (zero-pad to preserve length)
    /// - echo: Echo TLVs back, marking unknown types with U-flag
    #[clap(long, value_enum, default_value_t = TlvHandlingMode::Echo)]
    pub tlv_mode: TlvHandlingMode,

    /// Verify HMAC TLV in incoming packets (RFC 8972). Requires HMAC key.
    #[clap(long)]
    pub verify_tlv_hmac: bool,

    /// Session-Sender Identifier to include in sender packets (RFC 8972 §3).
    /// Encoded in the two octets of the base STAMP header immediately after
    /// Error Estimate (bytes 14-15 unauth / 26-27 auth).
    #[clap(long)]
    pub ssid: Option<u16>,

    /// What to do when a reflected packet returns a zeroed SSID field
    /// (RFC 8972 §3): `continue` (default) keeps measuring and logs the
    /// condition once, `stop` ends the session on the first such reply.
    ///
    /// Sender-side only, and only meaningful together with a non-zero
    /// `--ssid` — without one there is nothing for the reflector to echo.
    #[clap(long, default_value_t = ZeroSsidAction::Continue, value_name = "ACTION")]
    pub on_zero_ssid: ZeroSsidAction,

    /// Enable Prometheus metrics endpoint (requires "metrics" feature).
    #[clap(long)]
    pub metrics: bool,

    /// Address to bind the metrics HTTP server.
    #[clap(long, default_value = "127.0.0.1:9090")]
    pub metrics_addr: SocketAddr,

    /// Enable Class of Service TLV for DSCP/ECN measurement (RFC 8972 §4.4).
    /// When enabled, the sender includes a CoS TLV with the requested DSCP/ECN values,
    /// and the reflector reports the received DSCP/ECN values.
    #[clap(long)]
    pub cos: bool,

    /// DSCP value to request for reflected packets (0-63).
    /// Only used when --cos is enabled. Common values:
    /// 0=Best Effort, 10=AF11, 18=AF21, 26=AF31, 34=AF41, 46=EF
    #[clap(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..64))]
    pub dscp: u8,

    /// ECN value to request for reflected packets (0-3).
    /// Only used when --cos is enabled.
    /// 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE (Congestion Experienced)
    #[clap(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..4))]
    pub ecn: u8,

    /// Multiplicative backoff factor for the AIMD congestion-response
    /// controller (draft-ietf-ippm-stamp-cos-ecn-01 §3.4): each time a
    /// CE-marked reply is observed, the send interval is multiplied by this
    /// factor (capped at `--ecn-max-delay`). Must be > 1.0. Active only
    /// when `--cos` is set and `--ecn` requests ECT0 (2) or ECT1 (1) —
    /// see `--ecn-max-delay` / `--ecn-recovery-step` for the other two
    /// AIMD parameters.
    #[clap(long, default_value_t = 2.0)]
    pub ecn_backoff_factor: f64,

    /// Upper bound (milliseconds) on the AIMD-controlled send interval —
    /// caps how far repeated CE observations can back the sender off
    /// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4). Must be >= `--send-delay`
    /// when the controller is active.
    #[clap(long, default_value_t = 30_000)]
    pub ecn_max_delay: u32,

    /// Additive recovery step (milliseconds): after each reply that was
    /// NOT CE-marked, the AIMD-controlled send interval shrinks by this
    /// amount, down to (never below) `--send-delay`
    /// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
    #[clap(long, default_value_t = 50)]
    pub ecn_recovery_step: u32,

    /// IP TTL (IPv4) / Hop Limit (IPv6) for outgoing test packets (1-255).
    /// When unset the operating-system default is used. The sender applies
    /// this to the egress socket (Linux/macOS only).
    #[clap(long, value_parser = clap::value_parser!(u8).range(1..=255))]
    pub ttl: Option<u8>,

    /// Diagnostic: append a deliberately malformed TLV to every sent packet to
    /// test a reflector's RFC 8972 §4.2 handling. `bad-flags` sets reserved
    /// flag bits; `bad-length` declares a TLV length that overruns the packet.
    /// Not for normal measurements.
    #[clap(long, value_enum)]
    pub malformed: Option<MalformedMode>,

    /// Enable Access Report TLV (RFC 8972 §4.6) with the given Access ID
    /// (1-15; the field is 4 bits wide). Only 1 (3GPP Network) and 2
    /// (Non-3GPP Network) are currently defined; 0 is never valid and is
    /// rejected. Values 3-15 are accepted (the field may gain further
    /// definitions) but log a startup warning since they are not yet a
    /// recognized Access ID.
    /// The reflector echoes this TLV unchanged.
    #[clap(long, value_parser = clap::value_parser!(u8).range(1..=15))]
    pub access_report: Option<u8>,

    /// Return code for Access Report TLV (default: 1 = available).
    /// Only used when --access-report is enabled.
    #[clap(long, default_value_t = 1)]
    pub access_return_code: u8,

    /// Access Report TLV retransmission timer, in seconds (RFC 8972 §4.6:
    /// "The default value of the retransmission timer for the Access
    /// Report TLV SHOULD be three seconds"). The sender arms this timer
    /// after sending a packet carrying the Access Report TLV and
    /// retransmits it in the next test packet(s) if the timer expires
    /// before the reflector's echo is received. Only used when
    /// --access-report is enabled.
    #[clap(long, default_value_t = crate::sender::DEFAULT_ACCESS_REPORT_TIMEOUT.as_secs() as u32, value_parser = clap::value_parser!(u32).range(1..=3600))]
    pub access_report_timeout: u32,

    /// Maximum number of Access Report TLV retransmissions before the
    /// procedure is aborted (RFC 8972 §4.6: "This retransmission SHOULD be
    /// repeated up to four times before the procedure is aborted"). 0
    /// disables retransmission: the procedure aborts on the first missed
    /// acknowledgment. Only used when --access-report is enabled.
    #[clap(long, default_value_t = crate::sender::DEFAULT_ACCESS_REPORT_RETRIES, value_parser = clap::value_parser!(u32).range(0..=255))]
    pub access_report_retries: u32,

    /// Enable Timestamp Information TLV (RFC 8972 §4.3).
    /// The sender includes its sync source and timestamp method;
    /// the reflector fills in its own values.
    #[clap(long)]
    pub timestamp_info: bool,

    /// Enable Direct Measurement TLV (RFC 8972 §4.5).
    /// The sender includes its transmit count; the reflector fills
    /// receive and transmit counters.
    #[clap(long)]
    pub direct_measurement: bool,

    /// Enable Location TLV (RFC 8972 §4.2).
    /// The reflector fills in the observed source/destination addresses and ports.
    #[clap(long)]
    pub location: bool,

    /// Enable Follow-Up Telemetry TLV (RFC 8972 §4.7).
    /// The reflector fills in the previous reflection's sequence number
    /// and timestamp.
    #[clap(long)]
    pub follow_up_telemetry: bool,

    /// Enable SNMP AgentX sub-agent (requires "snmp" feature).
    #[clap(long)]
    pub snmp: bool,

    /// AgentX master agent socket path.
    #[clap(long, default_value = "/var/agentx/master")]
    pub snmp_socket: String,

    /// Enable the runtime control-plane REST API (reflector only;
    /// requires the "control" build feature). Design: doc/control-plane.md.
    #[clap(long)]
    pub control: bool,

    /// Address to bind the control-plane HTTP server. Keep this on
    /// loopback unless network-level access control is in place.
    #[clap(long, default_value = "127.0.0.1:9091", value_name = "ADDR")]
    pub control_addr: SocketAddr,

    /// Path to a file containing a static bearer token. When set, every
    /// control-plane request must carry `Authorization: Bearer <token>`.
    #[clap(long, value_name = "PATH")]
    pub control_token_file: Option<PathBuf>,

    /// Output format for statistics (text, json, csv).
    #[clap(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output_format: OutputFormat,

    /// Diagnostic log format — `text` (default) for journalctl-friendly
    /// human-readable lines, `json` for structured one-line-per-event
    /// output suitable for log aggregators. `RUST_LOG` continues to
    /// control verbosity in both modes.
    #[clap(long, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,

    /// Increase log verbosity (-v debug, -vv trace); RUST_LOG overrides.
    /// Repeatable: absent keeps the current default (`RUST_LOG` if set,
    /// otherwise `info`), one `-v` raises it to `debug`, two or more
    /// (`-vv`, `-vvv`, ...) raise it to `trace`. An explicit `RUST_LOG`
    /// environment variable always wins over `-v`, at any count -- see
    /// `resolve_log_filter`.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Kernel/hardware timestamp handling (requires the "hwtstamp" build
    /// feature for the read paths). `auto` (default): kernel software
    /// timestamps — precise T2/T4 and error-queue TX correction on Linux,
    /// SO_TIMESTAMP receive timestamps on macOS; no privileges, no NIC
    /// changes. `on`: additionally attempt NIC hardware timestamping
    /// (SIOCSHWTSTAMP + raw-hardware tier; needs CAP_NET_ADMIN and a
    /// synchronized PHC), warning + software fallback when unavailable.
    /// `off`: userspace timestamps only.
    #[clap(long, value_enum, default_value_t = HwTsMode::Auto)]
    pub hwtstamp: HwTsMode,

    /// Periodic reporting interval in seconds (0 = disabled, sender only).
    #[clap(long, default_value_t = 0)]
    pub report_interval: u32,

    /// Destination Node Address for SR networks (RFC 9503 §4). Requires --ssid.
    #[clap(long, value_name = "IP")]
    pub dest_node_addr: Option<std::net::IpAddr>,

    /// Return Path control code (RFC 9503 §5): 0=no reply, 1=same link reply.
    #[clap(
        long,
        value_parser = clap::value_parser!(u32),
        conflicts_with_all = ["return_address", "return_sr_mpls_labels", "return_srv6_sids"]
    )]
    pub return_path_cc: Option<u32>,

    /// Return Path alternate reply address (RFC 9503 §5).
    #[clap(long, value_name = "IP", conflicts_with = "return_path_cc")]
    pub return_address: Option<std::net::IpAddr>,

    /// Return Path SR-MPLS label stack (RFC 9503 §5). Comma-separated 20-bit labels.
    #[clap(
        long,
        value_name = "LABELS",
        value_delimiter = ',',
        conflicts_with_all = ["return_path_cc", "return_srv6_sids"]
    )]
    pub return_sr_mpls_labels: Option<Vec<u32>>,

    /// Return Path SRv6 segment list (RFC 9503 §5). Comma-separated IPv6 SIDs.
    #[clap(
        long,
        value_name = "SIDS",
        value_delimiter = ',',
        conflicts_with_all = ["return_path_cc", "return_sr_mpls_labels"]
    )]
    pub return_srv6_sids: Option<Vec<std::net::Ipv6Addr>>,

    /// Reflector: attempt best-effort SRv6 return-path forwarding per RFC 9503
    /// §5 and RFC 8754. When a received Return Path TLV carries an SRv6 Segment
    /// List and the kernel supports it, the reflector inserts a Segment Routing
    /// Header on its IPv6 reply. Disabled by default; when off (or on a
    /// non-Linux/IPv4/unsupported path) the reflector replies normally and sets
    /// the Return Path U-flag. Linux only.
    #[clap(long)]
    pub srv6_return_forwarding: bool,

    /// Reflector: honour a Return Path TLV "Return Address" sub-TLV (RFC 9503
    /// §5) by sending the reply to the requested address instead of the packet
    /// source. Disabled by default: an open reflector that honours arbitrary
    /// return addresses can be abused as a traffic-redirection / reflection
    /// gadget aimed at third parties. When off, a Return Address sub-TLV is
    /// echoed with the U-flag set and the reply goes to the packet source.
    /// Only enable inside a controlled (and preferably HMAC-authenticated)
    /// measurement domain.
    #[clap(long)]
    pub return_path_allow_alternate: bool,

    /// Sender micro-session member link ID for LAG measurement (RFC 9534).
    /// When set, includes a Micro-session ID TLV in test packets.
    /// Accepts decimal (e.g. `255`) or `0x`-prefixed hex (e.g. `0xff`).
    #[clap(long, value_parser = parse_u16_nonzero_dec_or_hex)]
    pub micro_session_id: Option<u16>,

    /// Reflector member link ID for LAG micro-sessions (RFC 9534).
    /// When set, the reflector fills this ID into reflected Micro-session ID TLVs.
    /// Accepts decimal (e.g. `171`) or `0x`-prefixed hex (e.g. `0xab`).
    #[clap(long, value_parser = parse_u16_nonzero_dec_or_hex)]
    pub reflector_member_link_id: Option<u16>,

    /// Maximum packets per second per source (0 = unlimited).
    /// Implemented as a per-(source IP, SSID) token bucket; see
    /// `--reflector-rate-burst` for the bucket capacity. Kept under the
    /// historic `--max-pps` name for backward compatibility.
    #[clap(long, default_value_t = 0)]
    pub max_pps: u32,

    /// Per-client token-bucket burst capacity in packets. 0 = use
    /// `--max-pps` (one-second worth of capacity), which matches the
    /// classic fixed-window behaviour. Ignored when `--max-pps` is 0.
    #[clap(long, default_value_t = 0)]
    pub reflector_rate_burst: u32,

    /// Maximum number of concurrently tracked client sessions (0 = unlimited).
    /// The reflector creates a session entry per distinct source `IP:port` to
    /// hold Direct Measurement / Follow-Up Telemetry counters, so without a cap
    /// an unauthenticated peer spraying packets from many source ports (or
    /// spoofed addresses) can grow the table until the process is OOM-killed.
    /// When the cap is reached, new clients are still answered but not tracked
    /// (transient counters); stale entries are reclaimed by the periodic
    /// cleanup. Defaults to 65536. Raise it for very large measurement meshes,
    /// or set 0 to disable the cap (not recommended on an open reflector).
    #[clap(long, default_value_t = 65536)]
    pub max_sessions: u32,

    /// Enable the BER TLVs (draft-gandhi-ippm-stamp-ber-05):
    /// Bit Pattern in Padding (Type 240), Bit Error Count (Type 241), and
    /// Max Bit Error Burst Size (Type 242). Sender-side only; the reflector
    /// computes the counts against the incoming Extra Padding.
    #[clap(long)]
    pub ber: bool,

    /// Bit pattern used to fill the Extra Padding TLV when `--ber` is set.
    /// Hex string (e.g. "ff00" or "aa55"). Defaults to the draft's recommended
    /// pattern (0xFF00). Ignored unless `--ber` is set.
    #[clap(long, value_name = "HEX")]
    pub ber_pattern: Option<String>,

    /// Padding length in bytes for the Extra Padding TLV that accompanies the
    /// BER TLVs. Ignored unless `--ber` is set.
    #[clap(long, default_value_t = 64)]
    pub ber_padding_size: usize,

    /// Request asymmetrical reply traffic (draft-ietf-ippm-asymmetrical-pkts §3).
    /// The sender includes a Reflected Test Packet Control TLV (Type 12) asking
    /// the reflector to emit N copies of the reply. Setting this to a value
    /// greater than 1 activates the TLV.
    #[clap(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u16)
    )]
    pub reflected_control_count: u16,

    /// Requested reply packet length for the Reflected Test Packet Control TLV.
    /// 0 means "don't pad" (the reflector will set C flag anyway if it cannot
    /// honour). Ignored unless `--reflected-control-count` > 1.
    #[clap(long, default_value_t = 0)]
    pub reflected_control_length: u16,

    /// Inter-packet gap in nanoseconds for the Reflected Test Packet Control TLV.
    /// Ignored unless `--reflected-control-count` > 1.
    #[clap(long, default_value_t = 1_000_000)]
    pub reflected_control_interval_ns: u32,

    /// Append the IPv6 Extension Header Control sub-TLV
    /// (draft-ietf-ippm-stamp-ext-hdr-11 §5.3) to the Reflected Test Packet
    /// Control TLV. Under -11 this sub-TLV asks the reflector to add matching
    /// IPv6 extension headers to its own reply packets; a reflector that cannot
    /// do so returns the sub-TLV with the C flag set in its Sub-TLV Flags.
    /// Implies emitting the Reflected Control TLV even when
    /// `--reflected-control-count` is 1.
    #[clap(long)]
    pub reflected_control_no_ext_hdr: bool,

    /// Reflector-side amplification cap (the per-request *volume* limit of
    /// draft-ietf-ippm-asymmetrical-pkts-14 §3): maximum number of reply
    /// packets the reflector will emit in response to a single Reflected
    /// Test Packet Control TLV request. When the sender requests more, the
    /// reflector sends a single reflected packet with the C flag set on the
    /// echoed TLV, as the draft requires.
    ///
    /// Default 0, which **disables** asymmetric reflection — the reflector
    /// sends only the single normal reply and sets the C flag. This honours
    /// draft-ietf-ippm-asymmetrical-pkts-14 §5, which requires the feature be
    /// administratively controllable and disabled by default. Set a positive
    /// value to opt in (e.g. 16); pair with `--max-pps` to bound amplification.
    #[clap(long, default_value_t = 0)]
    pub reflected_control_max_count: u16,

    /// Reflector-side amplification cap for
    /// draft-ietf-ippm-asymmetrical-pkts-14 §3: maximum reply packet size (in
    /// bytes) the reflector will pad up to when honouring a Reflected Test
    /// Packet Control TLV `length` request. When the requested length exceeds
    /// the effective cap, a single reflected packet padded to it is sent with
    /// the C flag set on the echoed TLV.
    ///
    /// On Linux with a non-wildcard `--local-addr`, the reflector also reads
    /// the egress interface's MTU (`SIOCGIFMTU`) and enforces whichever cap is
    /// smaller. So on a 1500-byte link the effective cap is 1472 — the MTU
    /// minus the IP and UDP headers — even at this flag's 1500 default, which
    /// is what keeps a maximum-length reply from becoming a 1528-byte
    /// datagram. Raise this flag for a jumbo link; lower it to cap replies
    /// below what the path would allow. Best-effort: a wildcard bind, a failed
    /// query, or a non-Linux platform leaves this value as the only cap.
    #[clap(long, default_value_t = 1500)]
    pub reflected_control_max_size: u16,

    /// Reflector-side amplification cap (the per-request *rate* limit of
    /// draft-ietf-ippm-asymmetrical-pkts-14 §3): minimum inter-packet
    /// interval in nanoseconds. A multi-packet request with a shorter
    /// interval gets a single reflected packet with the C flag set on the
    /// echoed TLV. Default 1000 (1 µs).
    #[clap(long, default_value_t = 1_000)]
    pub reflected_control_min_interval_ns: u32,

    /// Request that the reflector copy the received IP fixed header
    /// (IPv4: 20 bytes, IPv6: 40 bytes) back via TLV Type 247
    /// (draft-ietf-ippm-stamp-ext-hdr-11 §§3.2, 5.2). Reflectors built with the
    /// `ttl-nix` backend cannot observe the IP header and will echo the
    /// TLV with the C flag (Conformance) set.
    ///
    /// Repeatable (`--reflected-fixed-hdr --reflected-fixed-hdr ...`): each
    /// occurrence adds one Type-247 request TLV, so multiple stacked IP headers
    /// (e.g. an IP-in-IP tunnel) can each be requested and paired positionally
    /// with the reflector's outer→inner capture (§3.2 rule 2). Each occurrence
    /// takes an OPTIONAL inline value `[SELECTORHEX]` — a hex §5.2 selector
    /// (the target IP header's first 4 on-wire octets) used to disambiguate
    /// same-length headers. Bare `--reflected-fixed-hdr` (no value) requests one
    /// header with an all-zeros Requested field; the standalone
    /// `--reflected-fixed-hdr-selector` remains valid for that single-header
    /// form.
    #[clap(
        long,
        value_name = "[SELECTORHEX]",
        num_args = 0..=1,
        default_missing_value = "",
        action = clap::ArgAction::Append
    )]
    pub reflected_fixed_hdr: Vec<String>,

    /// Request that the reflector copy IPv6 Hop-by-Hop and Destination
    /// Options extension headers back via TLV Type 246
    /// (draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 5.1). Reflectors built with the
    /// `ttl-nix` backend cannot observe extension headers and will echo
    /// the TLV with the C flag (Conformance) set.
    ///
    /// Repeatable: each occurrence adds one Type-246 request TLV, so multiple
    /// IPv6 extension headers can be requested with matching lengths and in
    /// order (§3.1 rule 2). Each occurrence takes an OPTIONAL inline value
    /// `[LEN[:SELECTORHEX]]`: `LEN` is the requested TLV Length (the target
    /// extension header's on-wire size, default 8) and `SELECTORHEX` is an
    /// optional hex §5.1 selector (the header's first 4 on-wire octets). Bare
    /// `--reflected-ipv6-ext-hdr` (no value) requests one header at the default
    /// length with an all-zeros Requested field; the standalone
    /// `--reflected-ipv6-ext-hdr-selector` remains valid for that single-header
    /// form.
    #[clap(
        long,
        value_name = "[LEN[:SELECTORHEX]]",
        num_args = 0..=1,
        default_missing_value = "",
        action = clap::ArgAction::Append
    )]
    pub reflected_ipv6_ext_hdr: Vec<String>,

    /// Attach a real IPv6 extension header to the sender's own egress packets
    /// and request its reflection (draft-ietf-ippm-stamp-ext-hdr-11 §3.1: "the
    /// Session-Sender MUST add a corresponding 'Reflected IPv6 Extension Header
    /// Data' TLV"). Repeatable; each occurrence takes `KIND[:HEX]` where KIND is
    /// `hbh` (Hop-by-Hop, attached via `IPV6_HOPOPTS`) or `dest` (Destination
    /// Options, `IPV6_DSTOPTS`) and the optional HEX is the full extension
    /// header buffer (a multiple of 8 octets; byte 0, the Next Header field, is
    /// overwritten by the kernel). With no HEX an 8-octet PadN header is used.
    /// Each attached header also gets a matching Type-246 request TLV (Length =
    /// header size, all-zeros Requested field: byte 0 is kernel-assigned so no
    /// selector can be predicted; positional pairing handles ordering).
    /// Linux + IPv6 destinations only (the sticky `IPV6_HOPOPTS`/`IPV6_DSTOPTS`
    /// options are not exposed by `libc` on Darwin); on other platforms or an
    /// IPv4 destination the header is not attached (a one-time warning is
    /// logged), though on non-IPv4 the request TLV is still emitted.
    #[clap(long, value_name = "KIND[:HEX]", action = clap::ArgAction::Append)]
    pub attach_ext_hdr: Vec<String>,

    /// Selector for the Type 246 Requested field
    /// (draft-ietf-ippm-stamp-ext-hdr-11 §5.1). Hex string (e.g. "11000102");
    /// its bytes populate the 4-octet Requested field so the reflector returns
    /// only the matching extension header (disambiguating multiple same-length
    /// headers). These are the target header's on-wire first 4 octets: byte 0
    /// is the header's own Next Header field (naming what follows it), byte 1 is
    /// HdrExtLen, then the first 2 option octets — NOT the header's own type.
    /// Must contain at least one non-zero byte. Requires
    /// `--reflected-ipv6-ext-hdr`.
    #[clap(long, value_name = "HEX")]
    pub reflected_ipv6_ext_hdr_selector: Option<String>,

    /// Selector for the Type 247 Requested field
    /// (draft-ietf-ippm-stamp-ext-hdr-11 §5.2). Hex string whose bytes populate
    /// the 4-octet Requested field and must match the start of the received IP
    /// fixed header; on mismatch the reflector echoes the TLV with the C flag
    /// (Conformance) set. At most 20 bytes (IPv4) or 40 bytes (IPv6) by the
    /// destination family, and at least one non-zero byte. Requires
    /// `--reflected-fixed-hdr`.
    #[clap(long, value_name = "HEX")]
    pub reflected_fixed_hdr_selector: Option<String>,
}

impl Configuration {
    /// Validates the configuration parameters.
    ///
    /// Returns an error if any configuration value is invalid.
    /// Checks the sender's own pacing against the reflected burst it requests
    /// (draft-ietf-ippm-asymmetrical-pkts-14 §5): "A Session-Sender SHOULD NOT
    /// send the next STAMP test packet with the Reflected Test Packet Control
    /// TLV before the Session-Reflector is expected to complete transmitting
    /// all reflected packets in response to the ... TLV in the previous test
    /// packet."
    ///
    /// Returns the operator-facing warning when `--send-delay` is shorter than
    /// the requested burst's expected duration, `None` when the pacing is fine
    /// or no burst was requested. This is advisory (a SHOULD NOT governing the
    /// sender's own self-inflicted overlap, not a wire violation), so it warns
    /// rather than refusing to start — an operator deliberately measuring
    /// under overlap keeps that option.
    ///
    /// The reflector sends `count` packets separated by `interval_ns`, so the
    /// last one leaves at `(count - 1) * interval_ns`.
    #[must_use]
    pub fn reflected_burst_pacing_warning(&self) -> Option<String> {
        if self.reflected_control_count <= 1 {
            return None;
        }
        let burst_ns = u64::from(self.reflected_control_count - 1)
            * u64::from(self.reflected_control_interval_ns);
        let send_delay_ns = u64::from(self.send_delay) * 1_000_000;
        if send_delay_ns >= burst_ns {
            return None;
        }
        Some(format!(
            "--send-delay {} ms is shorter than the {:.3} ms the reflected burst \
             is expected to take (--reflected-control-count {} x \
             --reflected-control-interval-ns {}); the next test packet will be \
             sent while the reflector is still replying to the previous one \
             (draft-ietf-ippm-asymmetrical-pkts-14 §5 SHOULD NOT). Raise \
             --send-delay to at least {} ms, or lower the count/interval.",
            self.send_delay,
            burst_ns as f64 / 1_000_000.0,
            self.reflected_control_count,
            self.reflected_control_interval_ns,
            burst_ns.div_ceil(1_000_000),
        ))
    }

    /// Builds the reflector's CoS admission policy from `--allowed-dscp`,
    /// `--allowed-ecn` and any `--allowed-dscp-for` rules.
    ///
    /// # Errors
    /// Returns the parse error, naming the flag, for a bad value list, a
    /// malformed prefix rule, or an out-of-range codepoint.
    pub fn cos_admission_policy(&self) -> Result<CosAdmissionPolicy, ConfigurationError> {
        let cfg_err = ConfigurationError::InvalidConfiguration;
        let dscp = DscpSet::parse(&self.allowed_dscp)
            .map_err(|e| cfg_err(format!("invalid --allowed-dscp: {e}")))?;
        let ecn = EcnSet::parse(&self.allowed_ecn)
            .map_err(|e| cfg_err(format!("invalid --allowed-ecn: {e}")))?;
        let mut destinations = Vec::with_capacity(self.allowed_dscp_for.len());
        for rule in &self.allowed_dscp_for {
            destinations.push(
                parse_destination_rule(rule)
                    .map_err(|e| cfg_err(format!("invalid --allowed-dscp-for `{rule}`: {e}")))?,
            );
        }
        Ok(CosAdmissionPolicy::new(dscp, ecn, destinations))
    }

    /// Parses `--location-disclose` into the reflector's RFC 8972 §4.2.2
    /// field-disclosure policy.
    ///
    /// # Errors
    /// Returns the parse error for an unknown or contradictory field list.
    pub fn location_disclosure(&self) -> Result<LocationDisclosure, ConfigurationError> {
        LocationDisclosure::parse(&self.location_disclose).map_err(|e| {
            ConfigurationError::InvalidConfiguration(format!("invalid --location-disclose: {e}"))
        })
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        // Surface a bad Location disclosure list at startup rather than
        // silently falling back to a default policy per packet.
        self.location_disclosure()?;

        // Same for the CoS admission policy: a typo must not degrade silently
        // into "permit everything" on every packet.
        self.cos_admission_policy()?;

        if self.error_scale > 63 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "Error scale {} exceeds maximum of 63",
                self.error_scale
            )));
        }

        // Validate --verify-tlv-hmac requires HMAC key to be configured
        if self.verify_tlv_hmac
            && self.hmac_key.is_none()
            && self.hmac_key_file.is_none()
            && self.hmac_key_dir.is_none()
        {
            return Err(ConfigurationError::InvalidConfiguration(
                "--verify-tlv-hmac requires --hmac-key, --hmac-key-file, or --hmac-key-dir"
                    .to_string(),
            ));
        }

        // Validate authenticated mode requires HMAC key (RFC 8762 §4.4)
        if self.auth_mode.is_authenticated()
            && self.hmac_key.is_none()
            && self.hmac_key_file.is_none()
            && self.hmac_key_dir.is_none()
        {
            let mode_desc = if self.is_reflector {
                "reflector"
            } else {
                "sender"
            };
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "Authenticated mode {} (-A A) requires --hmac-key, --hmac-key-file, or --hmac-key-dir",
                mode_desc
            )));
        }

        // Validate --dest-node-addr requires --ssid (RFC 9503 mandates SSID)
        if self.dest_node_addr.is_some() && self.ssid.is_none() {
            return Err(ConfigurationError::InvalidConfiguration(
                "--dest-node-addr requires --ssid to be specified (RFC 9503)".to_string(),
            ));
        }

        // Validate --return-path-cc value must be 0 or 1
        if let Some(cc) = self.return_path_cc {
            if cc > 1 {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "--return-path-cc value {} is invalid, must be 0 or 1",
                    cc
                )));
            }
        }

        // Validate --return-sr-mpls-labels values are 20-bit
        if let Some(ref labels) = self.return_sr_mpls_labels {
            for label in labels {
                if *label > 0xFFFFF {
                    return Err(ConfigurationError::InvalidConfiguration(format!(
                        "--return-sr-mpls-labels value {} exceeds 20-bit maximum (0xFFFFF)",
                        label
                    )));
                }
            }
        }

        // Range checks duplicated here so values supplied through the TOML
        // file are validated. clap's `value_parser!(_).range(...)` only
        // runs on CLI-parsed values.
        if self.dscp > 63 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "dscp value {} exceeds maximum of 63",
                self.dscp
            )));
        }
        if self.ecn > 3 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "ecn value {} exceeds maximum of 3",
                self.ecn
            )));
        }
        // draft-ietf-ippm-stamp-cos-ecn-01 §3.4: the AIMD congestion-response
        // controller's own parameters must describe an actual backoff/
        // recovery cycle, regardless of whether the controller ends up
        // active this run (mirrors dscp/ecn above, which are validated
        // unconditionally too).
        if !self.ecn_backoff_factor.is_finite() || self.ecn_backoff_factor <= 1.0 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "ecn_backoff_factor value {} must be a finite number greater than 1.0 \
                 (a CE observation must actually increase the send interval)",
                self.ecn_backoff_factor
            )));
        }
        if self.ecn_recovery_step == 0 {
            return Err(ConfigurationError::InvalidConfiguration(
                "ecn_recovery_step must be >= 1 (millisecond); 0 would never recover \
                 the send interval back toward --send-delay"
                    .to_string(),
            ));
        }
        if self.ecn_max_delay == 0 {
            return Err(ConfigurationError::InvalidConfiguration(
                "ecn_max_delay must be >= 1 (millisecond)".to_string(),
            ));
        }
        // Only checked when the controller is actually active: an
        // unrelated `--send-delay` bump should not spuriously break a run
        // that never touches --cos/--ecn.
        if self.cos
            && matches!(self.ecn, 1 | 2)
            && (self.ecn_max_delay as u64) < (self.send_delay as u64)
        {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "ecn_max_delay ({} ms) must be >= send_delay ({} ms) when the AIMD \
                 congestion-response controller is active (--cos with --ecn 1 or 2)",
                self.ecn_max_delay, self.send_delay
            )));
        }
        if self.ttl == Some(0) {
            return Err(ConfigurationError::InvalidConfiguration(
                "ttl value 0 is invalid (must be 1-255)".to_string(),
            ));
        }
        if let Some(id) = self.access_report {
            // RFC 8972 §4.6: the Access ID is a 4-bit field; 0 has no
            // defined meaning and is never valid. Only 1 (3GPP Network)
            // and 2 (Non-3GPP Network) are currently defined, but values
            // up to the 4-bit maximum (15) are accepted so a future
            // registry allocation is not blocked by this CLI — they just
            // get a startup warning since they're not (yet) recognized.
            if id == 0 {
                return Err(ConfigurationError::InvalidConfiguration(
                    "access_report value 0 is invalid: RFC 8972 §4.6 defines no Access ID 0 \
                     (valid range is 1-15)"
                        .to_string(),
                ));
            }
            if id > 15 {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "access_report value {} exceeds maximum of 15",
                    id
                )));
            }
            if id > 2 {
                // validate() runs before init_logging(), so a log::warn! here
                // would be silently dropped; pre-init diagnostics go to stderr
                // like the other configuration messages on this path.
                eprintln!(
                    "warning: access_report Access ID {id} is not in the RFC 8972 §4.6 registry \
                     (only 1=3GPP Network and 2=Non-3GPP Network are currently defined); \
                     proceeding since it may be a future registry allocation"
                );
            }
        }
        // RFC 8972 §4.6: "An implementation MUST provide control of the
        // retransmission timer value and the number of retransmissions."
        // clap's `.range()` only runs on CLI-parsed values; duplicate the
        // bounds here so a TOML-sourced value is validated too.
        if self.access_report_timeout == 0 {
            return Err(ConfigurationError::InvalidConfiguration(
                "access_report_timeout must be >= 1 (seconds)".to_string(),
            ));
        }
        if self.access_report_timeout > 3600 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "access_report_timeout value {} exceeds maximum of 3600 seconds",
                self.access_report_timeout
            )));
        }
        if self.access_report_retries > 255 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "access_report_retries value {} exceeds maximum of 255",
                self.access_report_retries
            )));
        }
        if let Some(id) = self.micro_session_id {
            if id == 0 {
                return Err(ConfigurationError::InvalidConfiguration(
                    "micro_session_id must be >= 1".to_string(),
                ));
            }
        }
        if let Some(id) = self.reflector_member_link_id {
            if id == 0 {
                return Err(ConfigurationError::InvalidConfiguration(
                    "reflector_member_link_id must be >= 1".to_string(),
                ));
            }
        }

        // Mutual-exclusion checks duplicated here so combinations coming
        // from the TOML file are rejected. clap's `conflicts_with` /
        // `conflicts_with_all` only fire when both values are supplied on
        // the command line; merging a conflicting value from a file after
        // parse time bypasses them.
        if self.hmac_key.is_some() && self.hmac_key_file.is_some() {
            return Err(ConfigurationError::InvalidConfiguration(
                "hmac_key and hmac_key_file are mutually exclusive".to_string(),
            ));
        }
        if self.hmac_key_dir.is_some() && (self.hmac_key.is_some() || self.hmac_key_file.is_some())
        {
            return Err(ConfigurationError::InvalidConfiguration(
                "hmac_key_dir cannot be combined with hmac_key or hmac_key_file".to_string(),
            ));
        }
        if self.return_path_cc.is_some() {
            if self.return_address.is_some() {
                return Err(ConfigurationError::InvalidConfiguration(
                    "return_path_cc conflicts with return_address".to_string(),
                ));
            }
            if self.return_sr_mpls_labels.is_some() {
                return Err(ConfigurationError::InvalidConfiguration(
                    "return_path_cc conflicts with return_sr_mpls_labels".to_string(),
                ));
            }
            if self.return_srv6_sids.is_some() {
                return Err(ConfigurationError::InvalidConfiguration(
                    "return_path_cc conflicts with return_srv6_sids".to_string(),
                ));
            }
        }
        // The control plane manages reflector state; sender mode has none.
        if self.control && !self.is_reflector {
            return Err(ConfigurationError::InvalidConfiguration(
                "--control is only available in reflector mode".to_string(),
            ));
        }
        // draft-ietf-ippm-asymmetrical-pkts-14 §4.3: a Session-Sender MUST NOT
        // combine a "no reply requested" Return Path control code with a
        // non-zero Reflected Test Packet Control TLV. The TLV is emitted when
        // reflected_control_count > 1 or when the ext-hdr-control sub-TLV is
        // requested.
        if self.return_path_cc == Some(0)
            && (self.reflected_control_count > 1 || self.reflected_control_no_ext_hdr)
        {
            return Err(ConfigurationError::InvalidConfiguration(
                "return_path_cc 0 (no reply requested) cannot be combined with a \
                 Reflected Test Packet Control TLV (reflected_control_count > 1 or \
                 reflected_control_no_ext_hdr; draft-ietf-ippm-asymmetrical-pkts-14 §4.3)"
                    .to_string(),
            ));
        }
        if self.return_sr_mpls_labels.is_some() && self.return_srv6_sids.is_some() {
            return Err(ConfigurationError::InvalidConfiguration(
                "return_sr_mpls_labels conflicts with return_srv6_sids".to_string(),
            ));
        }

        // draft-ietf-ippm-stamp-ext-hdr-11 §§3.1/3.2/5.1/5.2 header-reflection
        // request flags (repeatable) plus the §3.1 real-header attachment flag.
        self.validate_ext_hdr_flags()?;

        Ok(())
    }

    /// Validates the draft-ietf-ippm-stamp-ext-hdr-11 header-reflection flags:
    /// the repeatable `--reflected-ipv6-ext-hdr` / `--reflected-fixed-hdr`
    /// request specs, the `--attach-ext-hdr` attachment specs, and the
    /// backward-compatible standalone selector flags. Each occurrence is parsed
    /// with the same helpers the sender uses to build the wire TLVs, so a parse
    /// failure here is reported before any packet is sent.
    fn validate_ext_hdr_flags(&self) -> Result<(), ConfigurationError> {
        let cfg_err = ConfigurationError::InvalidConfiguration;

        // Parse each repeatable occurrence (fails fast on bad hex/length).
        for spec in &self.reflected_ipv6_ext_hdr {
            parse_ext_hdr_request_spec(spec)
                .map_err(|e| cfg_err(format!("invalid --reflected-ipv6-ext-hdr `{spec}`: {e}")))?;
        }
        let fixed_max = if self.remote_addr.is_ipv4() { 20 } else { 40 };
        for spec in &self.reflected_fixed_hdr {
            let parsed = parse_fixed_hdr_request_spec(spec)
                .map_err(|e| cfg_err(format!("invalid --reflected-fixed-hdr `{spec}`: {e}")))?;
            if let Some(sel) = &parsed.selector {
                if sel.len() > fixed_max {
                    return Err(cfg_err(format!(
                        "--reflected-fixed-hdr selector is {} bytes; the maximum for the \
                         destination family is {fixed_max} (the IP fixed-header length)",
                        sel.len()
                    )));
                }
            }
        }
        for spec in &self.attach_ext_hdr {
            parse_attach_ext_hdr_spec(spec)
                .map_err(|e| cfg_err(format!("invalid --attach-ext-hdr `{spec}`: {e}")))?;
        }

        // Backward-compatible standalone selectors: valid only for the
        // single-header form (exactly one occurrence, no inline selector).
        if let Some(sel) = &self.reflected_ipv6_ext_hdr_selector {
            if self.reflected_ipv6_ext_hdr.is_empty() {
                return Err(cfg_err(
                    "--reflected-ipv6-ext-hdr-selector requires --reflected-ipv6-ext-hdr"
                        .to_string(),
                ));
            }
            if self.reflected_ipv6_ext_hdr.len() > 1 {
                return Err(cfg_err(
                    "--reflected-ipv6-ext-hdr-selector cannot be combined with multiple \
                     --reflected-ipv6-ext-hdr occurrences; use the inline `LEN:SELECTORHEX` \
                     form per occurrence instead"
                        .to_string(),
                ));
            }
            if parse_ext_hdr_request_spec(&self.reflected_ipv6_ext_hdr[0])
                .map(|s| s.selector.is_some())
                .unwrap_or(false)
            {
                return Err(cfg_err(
                    "--reflected-ipv6-ext-hdr-selector conflicts with an inline selector on \
                     --reflected-ipv6-ext-hdr"
                        .to_string(),
                ));
            }
            let bytes = decode_selector(sel)
                .map_err(|e| cfg_err(format!("invalid --reflected-ipv6-ext-hdr-selector: {e}")))?;
            if bytes.len() > MAX_IPV6_EXT_HDR_SELECTOR_BYTES {
                return Err(cfg_err(format!(
                    "--reflected-ipv6-ext-hdr-selector is {} bytes; the maximum is {} \
                     (one IPv6 extension header)",
                    bytes.len(),
                    MAX_IPV6_EXT_HDR_SELECTOR_BYTES
                )));
            }
        }
        if let Some(sel) = &self.reflected_fixed_hdr_selector {
            if self.reflected_fixed_hdr.is_empty() {
                return Err(cfg_err(
                    "--reflected-fixed-hdr-selector requires --reflected-fixed-hdr".to_string(),
                ));
            }
            if self.reflected_fixed_hdr.len() > 1 {
                return Err(cfg_err(
                    "--reflected-fixed-hdr-selector cannot be combined with multiple \
                     --reflected-fixed-hdr occurrences; use the inline SELECTORHEX form per \
                     occurrence instead"
                        .to_string(),
                ));
            }
            if parse_fixed_hdr_request_spec(&self.reflected_fixed_hdr[0])
                .map(|s| s.selector.is_some())
                .unwrap_or(false)
            {
                return Err(cfg_err(
                    "--reflected-fixed-hdr-selector conflicts with an inline selector on \
                     --reflected-fixed-hdr"
                        .to_string(),
                ));
            }
            let bytes = decode_selector(sel)
                .map_err(|e| cfg_err(format!("invalid --reflected-fixed-hdr-selector: {e}")))?;
            if bytes.len() > fixed_max {
                return Err(cfg_err(format!(
                    "--reflected-fixed-hdr-selector is {} bytes; the maximum for the \
                     destination family is {fixed_max} (the IP fixed-header length)",
                    bytes.len()
                )));
            }
        }

        Ok(())
    }

    /// Parses CLI arguments, optionally merges values from the TOML file
    /// referenced by `--config`, runs validation, and returns the final
    /// configuration.
    ///
    /// Precedence (highest first): CLI flag, `STAMP_HMAC_KEY` env var,
    /// TOML file value, hardcoded default.
    pub fn load() -> Result<Self, ConfigurationError> {
        let matches = <Self as clap::CommandFactory>::command().get_matches();
        Self::load_from_matches(matches)
    }

    /// Variant of [`Self::load`] that accepts a pre-built `ArgMatches`, used
    /// for testing.
    fn load_from_matches(matches: clap::ArgMatches) -> Result<Self, ConfigurationError> {
        let mut conf = <Self as clap::FromArgMatches>::from_arg_matches(&matches)
            .map_err(|e| ConfigurationError::InvalidConfiguration(e.to_string()))?;

        if let Some(path) = conf.config.clone() {
            let contents = std::fs::read_to_string(&path).map_err(|e| {
                ConfigurationError::ConfigFileError(format!(
                    "failed to read {}: {e}",
                    path.display()
                ))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = std::fs::metadata(&path) {
                    let mode = md.permissions().mode();
                    if mode & 0o022 != 0 {
                        log::warn!(
                            "Config file {:?} is writable by group or other (mode {:o}). \
                             An attacker with write access could change any STAMP setting \
                             including hmac_key_file. Recommended: chmod 600",
                            path,
                            mode & 0o777
                        );
                    }
                }
            }
            let file: FileConfiguration = toml::from_str(&contents).map_err(|e| {
                ConfigurationError::ConfigFileError(format!(
                    "parse error in {}: {e}",
                    path.display()
                ))
            })?;
            conf.merge_file(file, &matches);
        }

        conf.validate()?;
        Ok(conf)
    }

    /// Overrides fields that were not explicitly set on the command line (or
    /// via an env var) with values from the parsed TOML file.
    fn merge_file(&mut self, file: FileConfiguration, matches: &clap::ArgMatches) {
        use clap::parser::ValueSource;

        // True when clap considers the value to have come from the CLI or an
        // env var. In those cases the TOML value must NOT override it.
        let user_set = |name: &str| {
            matches!(
                matches.value_source(name),
                Some(ValueSource::CommandLine) | Some(ValueSource::EnvVariable)
            )
        };

        macro_rules! merge {
            ($field:ident) => {
                if !user_set(stringify!($field)) {
                    if let Some(v) = file.$field {
                        self.$field = v;
                    }
                }
            };
        }
        macro_rules! merge_opt {
            ($field:ident) => {
                if !user_set(stringify!($field)) && file.$field.is_some() {
                    self.$field = file.$field;
                }
            };
        }

        merge!(remote_addr);
        merge!(local_addr);
        merge!(remote_port);
        merge!(local_port);
        merge!(clock_source);
        merge!(send_delay);
        merge!(count);
        merge!(timeout);
        merge!(auth_mode);
        merge!(print_stats);
        merge!(is_reflector);
        merge!(error_scale);
        merge!(error_multiplier);
        merge!(clock_synchronized);
        merge_opt!(hmac_key_file);
        merge_opt!(hmac_key_dir);
        merge!(require_hmac);
        merge!(strict_packets);
        merge!(stateful_reflector);
        merge!(session_timeout);
        merge!(location_disclose);
        merge!(drop_replayed);
        merge!(allowed_dscp);
        merge!(allowed_ecn);
        merge!(allowed_dscp_for);
        merge!(tlv_mode);
        merge!(verify_tlv_hmac);
        merge_opt!(ssid);
        merge!(on_zero_ssid);
        merge!(metrics);
        merge!(metrics_addr);
        merge!(cos);
        merge!(dscp);
        merge!(ecn);
        merge!(ecn_backoff_factor);
        merge!(ecn_max_delay);
        merge!(ecn_recovery_step);
        merge_opt!(ttl);
        merge_opt!(malformed);
        merge_opt!(access_report);
        merge!(access_return_code);
        merge!(access_report_timeout);
        merge!(access_report_retries);
        merge!(timestamp_info);
        merge!(direct_measurement);
        merge!(location);
        merge!(follow_up_telemetry);
        merge!(snmp);
        merge!(snmp_socket);
        merge!(control);
        merge!(control_addr);
        merge_opt!(control_token_file);
        merge!(output_format);
        merge!(log_format);
        merge!(hwtstamp);
        merge!(report_interval);
        merge_opt!(dest_node_addr);
        merge_opt!(return_path_cc);
        merge_opt!(return_address);
        merge_opt!(return_sr_mpls_labels);
        merge_opt!(return_srv6_sids);
        merge!(srv6_return_forwarding);
        merge!(return_path_allow_alternate);
        merge_opt!(micro_session_id);
        merge_opt!(reflector_member_link_id);
        merge!(max_pps);
        merge!(reflector_rate_burst);
        merge!(max_sessions);
        merge!(ber);
        merge_opt!(ber_pattern);
        merge!(ber_padding_size);
        merge!(reflected_control_count);
        merge!(reflected_control_length);
        merge!(reflected_control_interval_ns);
        merge!(reflected_control_no_ext_hdr);
        merge!(reflected_control_max_count);
        merge!(reflected_control_max_size);
        merge!(reflected_control_min_interval_ns);
        merge!(reflected_fixed_hdr);
        merge!(reflected_ipv6_ext_hdr);
        merge!(attach_ext_hdr);
        merge_opt!(reflected_ipv6_ext_hdr_selector);
        merge_opt!(reflected_fixed_hdr_selector);
    }
}

/// Error type for configuration validation failures.
#[derive(Error, Debug)]
pub enum ConfigurationError {
    /// Indicates an invalid configuration parameter.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    /// Indicates a problem reading or parsing the TOML configuration file.
    #[error("Configuration file error: {0}")]
    ConfigFileError(String),
}

/// Deserializable mirror of [`Configuration`] used to load defaults from a
/// TOML file. Every field is optional; missing keys fall through to the
/// hardcoded clap defaults.
///
/// `hmac_key` and `config` are intentionally absent: the former to prevent
/// plaintext secrets from being stored in config files (use `hmac_key_file`
/// or the `STAMP_HMAC_KEY` environment variable instead), the latter because
/// it would be recursive.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfiguration {
    pub remote_addr: Option<std::net::IpAddr>,
    pub local_addr: Option<std::net::IpAddr>,
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
    pub clock_source: Option<ClockFormat>,
    pub send_delay: Option<u16>,
    pub count: Option<u16>,
    pub timeout: Option<u8>,
    pub auth_mode: Option<AuthMode>,
    pub print_stats: Option<bool>,
    pub is_reflector: Option<bool>,
    pub error_scale: Option<u8>,
    pub error_multiplier: Option<u8>,
    pub clock_synchronized: Option<bool>,
    pub hmac_key_file: Option<PathBuf>,
    pub hmac_key_dir: Option<PathBuf>,
    pub require_hmac: Option<bool>,
    pub strict_packets: Option<bool>,
    pub stateful_reflector: Option<bool>,
    pub session_timeout: Option<u64>,
    pub location_disclose: Option<String>,
    pub drop_replayed: Option<bool>,
    pub allowed_dscp: Option<String>,
    pub allowed_ecn: Option<String>,
    pub allowed_dscp_for: Option<Vec<String>>,
    pub tlv_mode: Option<TlvHandlingMode>,
    pub verify_tlv_hmac: Option<bool>,
    pub ssid: Option<u16>,
    pub on_zero_ssid: Option<ZeroSsidAction>,
    pub metrics: Option<bool>,
    pub metrics_addr: Option<SocketAddr>,
    pub cos: Option<bool>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub ecn_backoff_factor: Option<f64>,
    pub ecn_max_delay: Option<u32>,
    pub ecn_recovery_step: Option<u32>,
    pub ttl: Option<u8>,
    pub malformed: Option<MalformedMode>,
    pub access_report: Option<u8>,
    pub access_return_code: Option<u8>,
    pub access_report_timeout: Option<u32>,
    pub access_report_retries: Option<u32>,
    pub timestamp_info: Option<bool>,
    pub direct_measurement: Option<bool>,
    pub location: Option<bool>,
    pub follow_up_telemetry: Option<bool>,
    pub snmp: Option<bool>,
    pub snmp_socket: Option<String>,
    pub control: Option<bool>,
    pub control_addr: Option<SocketAddr>,
    pub control_token_file: Option<PathBuf>,
    pub output_format: Option<OutputFormat>,
    pub log_format: Option<LogFormat>,
    pub hwtstamp: Option<HwTsMode>,
    pub report_interval: Option<u32>,
    pub dest_node_addr: Option<std::net::IpAddr>,
    pub return_path_cc: Option<u32>,
    pub return_address: Option<std::net::IpAddr>,
    pub return_sr_mpls_labels: Option<Vec<u32>>,
    pub return_srv6_sids: Option<Vec<std::net::Ipv6Addr>>,
    pub srv6_return_forwarding: Option<bool>,
    pub return_path_allow_alternate: Option<bool>,
    pub micro_session_id: Option<u16>,
    pub reflector_member_link_id: Option<u16>,
    pub max_pps: Option<u32>,
    pub reflector_rate_burst: Option<u32>,
    pub max_sessions: Option<u32>,
    pub ber: Option<bool>,
    pub ber_pattern: Option<String>,
    pub ber_padding_size: Option<usize>,
    pub reflected_control_count: Option<u16>,
    pub reflected_control_length: Option<u16>,
    pub reflected_control_interval_ns: Option<u32>,
    pub reflected_control_no_ext_hdr: Option<bool>,
    pub reflected_control_max_count: Option<u16>,
    pub reflected_control_max_size: Option<u16>,
    pub reflected_control_min_interval_ns: Option<u32>,
    pub reflected_fixed_hdr: Option<Vec<String>>,
    pub reflected_ipv6_ext_hdr: Option<Vec<String>>,
    pub attach_ext_hdr: Option<Vec<String>>,
    pub reflected_ipv6_ext_hdr_selector: Option<String>,
    pub reflected_fixed_hdr_selector: Option<String>,
}

/// JSON Schema (draft 2020-12) for the TOML config file accepted by
/// `--config`. Returned by the `--print-config-schema` CLI flag so
/// external tooling (taplo, `jsonschema` CLI, IDE auto-completion) can
/// validate config files before deployment.
///
/// Maintained by hand alongside [`FileConfiguration`]; adding a field
/// there requires adding a property here. The schema deliberately
/// matches `#[serde(deny_unknown_fields)]` on `FileConfiguration` so
/// extra keys fail validation in the same way they fail at runtime.
pub const CONFIG_JSON_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/asmie/stamp-suite/schema/stamp-suite-config.json",
  "title": "stamp-suite TOML configuration",
  "description": "Schema for the file consumed by `stamp-suite --config <PATH>`. Keys map 1:1 to CLI flags (long form with underscores instead of dashes).",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "remote_addr": { "type": "string", "format": "ipvanyaddress" },
    "local_addr":  { "type": "string", "format": "ipvanyaddress" },
    "remote_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "local_port":  { "type": "integer", "minimum": 0, "maximum": 65535 },
    "clock_source": { "enum": ["NTP", "PTP"] },
    "send_delay":  { "type": "integer", "minimum": 0, "maximum": 65535 },
    "count":       { "type": "integer", "minimum": 0, "maximum": 65535 },
    "timeout":     { "type": "integer", "minimum": 0, "maximum": 255 },
    "auth_mode":   { "enum": ["A", "O"] },
    "print_stats": { "type": "boolean" },
    "is_reflector": { "type": "boolean" },
    "error_scale": { "type": "integer", "minimum": 0, "maximum": 63 },
    "error_multiplier": { "type": "integer", "minimum": 0, "maximum": 255 },
    "clock_synchronized": { "type": "boolean" },
    "hmac_key_file": { "type": "string" },
    "hmac_key_dir":  { "type": "string" },
    "require_hmac":  { "type": "boolean" },
    "strict_packets": { "type": "boolean" },
    "stateful_reflector": { "type": "boolean" },
    "session_timeout": { "type": "integer", "minimum": 0 },
    "tlv_mode": { "enum": ["echo", "ignore"] },
    "verify_tlv_hmac": { "type": "boolean" },
    "ssid": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "metrics": { "type": "boolean" },
    "metrics_addr": { "type": "string" },
    "cos": { "type": "boolean" },
    "dscp": { "type": "integer", "minimum": 0, "maximum": 63 },
    "ecn":  { "type": "integer", "minimum": 0, "maximum": 3 },
    "ecn_backoff_factor": { "type": "number", "exclusiveMinimum": 1.0 },
    "ecn_max_delay": { "type": "integer", "minimum": 1 },
    "ecn_recovery_step": { "type": "integer", "minimum": 1 },
    "ttl":  { "type": "integer", "minimum": 1, "maximum": 255 },
    "malformed": { "enum": ["bad-flags", "bad-length"] },
    "access_report": { "type": "integer", "minimum": 1, "maximum": 15 },
    "access_return_code": { "type": "integer", "minimum": 0, "maximum": 15 },
    "access_report_timeout": { "type": "integer", "minimum": 1, "maximum": 3600 },
    "access_report_retries": { "type": "integer", "minimum": 0, "maximum": 255 },
    "timestamp_info": { "type": "boolean" },
    "direct_measurement": { "type": "boolean" },
    "location": { "type": "boolean" },
    "follow_up_telemetry": { "type": "boolean" },
    "snmp": { "type": "boolean" },
    "snmp_socket": { "type": "string" },
    "control": { "type": "boolean" },
    "control_addr": { "type": "string" },
    "control_token_file": { "type": "string" },
    "output_format": { "enum": ["text", "json", "csv"] },
    "log_format": { "enum": ["text", "json"] },
    "hwtstamp":   { "enum": ["auto", "on", "off"] },
    "report_interval": { "type": "integer", "minimum": 0 },
    "dest_node_addr": { "type": "string", "format": "ipvanyaddress" },
    "return_path_cc": { "type": "integer", "minimum": 0, "maximum": 1 },
    "return_address": { "type": "string", "format": "ipvanyaddress" },
    "return_sr_mpls_labels": { "type": "array", "items": { "type": "integer", "minimum": 0 } },
    "return_srv6_sids": { "type": "array", "items": { "type": "string", "format": "ipv6" } },
    "srv6_return_forwarding": { "type": "boolean" },
    "return_path_allow_alternate": { "type": "boolean" },
    "micro_session_id": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflector_member_link_id": { "type": "integer", "minimum": 1, "maximum": 65535 },
    "max_pps": { "type": "integer", "minimum": 0 },
    "reflector_rate_burst": { "type": "integer", "minimum": 0 },
    "max_sessions": { "type": "integer", "minimum": 0 },
    "ber": { "type": "boolean" },
    "ber_pattern": { "type": "string", "pattern": "^[0-9a-fA-F]+$" },
    "ber_padding_size": { "type": "integer", "minimum": 0 },
    "reflected_control_count": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_length": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_interval_ns": { "type": "integer", "minimum": 0 },
    "reflected_control_no_ext_hdr": { "type": "boolean" },
    "reflected_control_max_count": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_max_size":  { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_min_interval_ns": { "type": "integer", "minimum": 0 },
    "reflected_fixed_hdr":    { "type": "array", "items": { "type": "string" } },
    "reflected_ipv6_ext_hdr": { "type": "array", "items": { "type": "string" } },
    "attach_ext_hdr":         { "type": "array", "items": { "type": "string" } },
    "reflected_ipv6_ext_hdr_selector": { "type": "string", "pattern": "^[0-9a-fA-F]+$" },
    "reflected_fixed_hdr_selector":    { "type": "string", "pattern": "^[0-9a-fA-F]+$" }
  }
}"##;

/// Checks if authenticated mode is enabled.
#[inline]
pub fn is_auth(mode: AuthMode) -> bool {
    mode.is_authenticated()
}

/// Resolves the effective `tracing-subscriber` env-filter directive from
/// the `-v`/`-vv` repeat count and the current `RUST_LOG` value (or lack
/// thereof).
///
/// Precedence (highest first):
/// 1. `env`, when `Some` and non-empty: an operator who has already set
///    `RUST_LOG` (possibly with per-module directives like
///    `stamp_suite=trace,tower=warn`) is assumed to know what they want,
///    and `-v` must not silently override it.
/// 2. The verbosity count: `0` keeps the historic default (`"info"`),
///    `1` (`-v`) raises it to `"debug"`, `2` or more (`-vv`, `-vvv`, ...)
///    raises it to `"trace"`.
///
/// Pure and free of any global/subscriber/process-environment state, so
/// it is unit-testable on its own; callers are expected to pass
/// `std::env::var("RUST_LOG").ok()` for `env`.
#[must_use]
pub fn resolve_log_filter(verbose: u8, env: Option<&str>) -> String {
    if let Some(value) = env {
        if !value.is_empty() {
            return value.to_string();
        }
    }
    match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
    .to_string()
}

/// Maximum length of a Type 246 selector: one full IPv6 extension header,
/// `(255 + 1) * 8` bytes (draft-ietf-ippm-stamp-ext-hdr-11 §5.1).
pub(crate) const MAX_IPV6_EXT_HDR_SELECTOR_BYTES: usize = 2048;

/// Decodes a hex selector string (optional `0x` prefix) into bytes for the
/// draft-ietf-ippm-stamp-ext-hdr-11 §5.1/§5.2 Requested-field request TLVs.
/// Requires non-empty input with at least one non-zero byte — an all-zero
/// Requested field would be indistinguishable from "no selector requested".
pub(crate) fn decode_selector(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if trimmed.is_empty() {
        return Err("empty selector".to_string());
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("invalid hex `{s}`: {e}"))?;
    if bytes.iter().all(|&b| b == 0) {
        return Err("selector must contain at least one non-zero byte".to_string());
    }
    Ok(bytes)
}

/// A parsed `--reflected-ipv6-ext-hdr` occurrence
/// (draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 5.1). Each occurrence becomes one
/// Type-246 request TLV of Length `length`, with an optional inline §5.1
/// selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtHdrRequestSpec {
    /// Requested TLV Length (the target extension header's on-wire size).
    pub length: usize,
    /// Inline §5.1 Requested-field selector bytes, if the occurrence carried
    /// one (`LEN:SELECTORHEX`).
    pub selector: Option<Vec<u8>>,
}

/// A parsed `--reflected-fixed-hdr` occurrence
/// (draft-ietf-ippm-stamp-ext-hdr-11 §§3.2, 5.2). Each occurrence becomes one
/// Type-247 request TLV (Length is the destination family's IP fixed-header
/// size), with an optional inline §5.2 selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedHdrRequestSpec {
    /// Inline §5.2 Requested-field selector bytes, if any.
    pub selector: Option<Vec<u8>>,
}

/// Which IPv6 extension header `--attach-ext-hdr` attaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachExtHdrKind {
    /// Hop-by-Hop Options header, attached via `IPV6_HOPOPTS`.
    HopByHop,
    /// Destination Options header, attached via `IPV6_DSTOPTS`.
    DestOpts,
}

/// A parsed `--attach-ext-hdr` occurrence: a real IPv6 extension header the
/// sender attaches to its own egress packets (draft-ietf-ippm-stamp-ext-hdr-11
/// §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachExtHdrSpec {
    /// Header kind (selects the `IPV6_HOPOPTS` / `IPV6_DSTOPTS` socket option).
    pub kind: AttachExtHdrKind,
    /// Full extension-header buffer as handed to `setsockopt` (a non-zero
    /// multiple of 8 octets). Byte 0 (Next Header) is overwritten by the kernel.
    pub bytes: Vec<u8>,
}

/// Default zero-selector 8-octet Destination/Hop-by-Hop header buffer: byte 0
/// (Next Header) is kernel-filled, byte 1 (HdrExtLen) is 0 ⇒ 8 octets, then a
/// PadN option (type 1, len 4, four zero bytes). Matches the netns tier's
/// `build_destopts_padn` reference bytes.
const DEFAULT_ATTACH_EXT_HDR_PADN: [u8; 8] = [0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00];

/// Parses one `--reflected-ipv6-ext-hdr` occurrence value. Grammar:
/// `""` (bare flag) → default length, no selector; `LEN` → that length;
/// `LEN:SELECTORHEX` or `:SELECTORHEX` → optional length plus a §5.1 selector.
pub(crate) fn parse_ext_hdr_request_spec(s: &str) -> Result<ExtHdrRequestSpec, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(ExtHdrRequestSpec {
            length: crate::tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY,
            selector: None,
        });
    }
    let (len_part, sel_part) = match s.split_once(':') {
        Some((l, r)) => (l.trim(), Some(r.trim())),
        None => (s, None),
    };
    let mut length = if len_part.is_empty() {
        crate::tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY
    } else {
        len_part
            .parse::<usize>()
            .map_err(|e| format!("invalid length `{len_part}`: {e}"))?
    };
    if length > MAX_IPV6_EXT_HDR_SELECTOR_BYTES {
        return Err(format!(
            "length {length} exceeds the maximum of {MAX_IPV6_EXT_HDR_SELECTOR_BYTES} \
             (one IPv6 extension header)"
        ));
    }
    let selector = match sel_part {
        Some(hex) if !hex.is_empty() => {
            let bytes = decode_selector(hex)?;
            if bytes.len() > MAX_IPV6_EXT_HDR_SELECTOR_BYTES {
                return Err(format!(
                    "selector is {} bytes; the maximum is {MAX_IPV6_EXT_HDR_SELECTOR_BYTES}",
                    bytes.len()
                ));
            }
            length = length.max(bytes.len());
            Some(bytes)
        }
        _ => None,
    };
    Ok(ExtHdrRequestSpec { length, selector })
}

/// Parses one `--reflected-fixed-hdr` occurrence value: `""` (bare flag) → no
/// selector; otherwise the whole value is a §5.2 selector hex string.
pub(crate) fn parse_fixed_hdr_request_spec(s: &str) -> Result<FixedHdrRequestSpec, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(FixedHdrRequestSpec { selector: None });
    }
    Ok(FixedHdrRequestSpec {
        selector: Some(decode_selector(s)?),
    })
}

/// Parses one `--attach-ext-hdr` occurrence: `KIND[:HEX]` where KIND is `hbh`
/// or `dest` and HEX (optional) is the full extension-header buffer.
pub(crate) fn parse_attach_ext_hdr_spec(s: &str) -> Result<AttachExtHdrSpec, String> {
    let s = s.trim();
    let (kind_part, hex_part) = match s.split_once(':') {
        Some((k, h)) => (k.trim(), Some(h.trim())),
        None => (s, None),
    };
    let kind = match kind_part.to_ascii_lowercase().as_str() {
        "hbh" | "hop-by-hop" | "hopopts" => AttachExtHdrKind::HopByHop,
        "dest" | "dst" | "destopts" | "dstopts" => AttachExtHdrKind::DestOpts,
        other => return Err(format!("unknown kind `{other}` (expected `hbh` or `dest`)")),
    };
    let bytes = match hex_part {
        Some(h) if !h.is_empty() => {
            let trimmed = h
                .strip_prefix("0x")
                .or_else(|| h.strip_prefix("0X"))
                .unwrap_or(h);
            hex::decode(trimmed).map_err(|e| format!("invalid hex `{h}`: {e}"))?
        }
        _ => DEFAULT_ATTACH_EXT_HDR_PADN.to_vec(),
    };
    if bytes.is_empty() || bytes.len() % 8 != 0 {
        return Err(format!(
            "extension-header buffer is {} bytes; it must be a non-zero multiple of 8 octets \
             (RFC 8200)",
            bytes.len()
        ));
    }
    Ok(AttachExtHdrSpec { kind, bytes })
}

impl Configuration {
    /// Returns the parsed `--reflected-ipv6-ext-hdr` occurrences. Assumes
    /// `validate()` has run (parse failures degrade to skipping the occurrence).
    #[must_use]
    pub fn ext_hdr_requests(&self) -> Vec<ExtHdrRequestSpec> {
        self.reflected_ipv6_ext_hdr
            .iter()
            .filter_map(|s| parse_ext_hdr_request_spec(s).ok())
            .collect()
    }

    /// Returns the parsed `--reflected-fixed-hdr` occurrences.
    #[must_use]
    pub fn fixed_hdr_requests(&self) -> Vec<FixedHdrRequestSpec> {
        self.reflected_fixed_hdr
            .iter()
            .filter_map(|s| parse_fixed_hdr_request_spec(s).ok())
            .collect()
    }

    /// Returns the parsed `--attach-ext-hdr` occurrences.
    #[must_use]
    pub fn attach_ext_hdrs(&self) -> Vec<AttachExtHdrSpec> {
        self.attach_ext_hdr
            .iter()
            .filter_map(|s| parse_attach_ext_hdr_spec(s).ok())
            .collect()
    }
}

/// clap value_parser: parse a u16 from decimal or `0x`-prefixed hex, rejecting 0.
///
/// Accepts: `255`, `0xff`, `0XFF`, `0x00ab`. Rejects: `0`, `0x0`, empty, `ff`,
/// out-of-range. Used by LAG identifier flags where the RFC 9534 wire field is
/// commonly written in hex.
fn parse_u16_nonzero_dec_or_hex(s: &str) -> Result<u16, String> {
    let trimmed = s.trim();
    let parsed = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u16::from_str_radix(rest, 16).map_err(|e| format!("invalid hex value `{s}`: {e}"))?
    } else {
        trimmed
            .parse::<u16>()
            .map_err(|e| format!("invalid value `{s}`: {e}"))?
    };
    if parsed == 0 {
        return Err(format!("value `{s}` must be in range 1..=65535"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use std::net::IpAddr;

    use super::*;

    #[test]
    fn test_valid_configuration_parsing() {
        let args = vec![
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--local-addr",
            "0.0.0.0",
            "--remote-port",
            "862",
            "--local-port",
            "862",
            "--clock-source",
            "NTP",
            "--send-delay",
            "1000",
            "--count",
            "1000",
            "--timeout",
            "5",
            "--auth-mode",
            "A",
            "--is-reflector",
            "--hmac-key",
            "0123456789abcdef0123456789abcdef",
        ];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.remote_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(conf.local_addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(conf.remote_port, 862);
        assert_eq!(conf.local_port, 862);
        assert_eq!(conf.clock_source, ClockFormat::NTP);
        assert_eq!(conf.send_delay, 1000);
        assert_eq!(conf.count, 1000);
        assert_eq!(conf.timeout, 5);
        assert_eq!(conf.auth_mode, AuthMode::Authenticated);
        assert!(conf.is_reflector);
        assert!(conf.hmac_key.is_some());
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_invalid_configuration_parsing() {
        let args = vec!["test", "--remote-addr", "invalid_addr"];
        let conf = Configuration::try_parse_from(args);
        assert!(conf.is_err());
    }

    /// A known-good argument set that passes `validate()`, for tests that want
    /// to isolate a single new validation rule.
    fn base_valid_args() -> Vec<String> {
        [
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--local-addr",
            "0.0.0.0",
            "--remote-port",
            "862",
            "--local-port",
            "862",
            "--clock-source",
            "NTP",
            "--send-delay",
            "1000",
            "--count",
            "1000",
            "--timeout",
            "5",
            "--auth-mode",
            "A",
            "--is-reflector",
            "--hmac-key",
            "0123456789abcdef0123456789abcdef",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    #[test]
    fn ext_hdr_selector_requires_enabling_flag() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-ipv6-ext-hdr-selector".to_string(),
            "3c000102".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn ext_hdr_selector_with_flag_is_accepted() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-ipv6-ext-hdr".to_string(),
            "--reflected-ipv6-ext-hdr-selector".to_string(),
            "3c000102".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_ok());
        assert_eq!(
            conf.reflected_ipv6_ext_hdr_selector.as_deref(),
            Some("3c000102")
        );
    }

    #[test]
    fn all_zero_ext_hdr_selector_is_rejected() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-ipv6-ext-hdr".to_string(),
            "--reflected-ipv6-ext-hdr-selector".to_string(),
            "00000000".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn fixed_hdr_selector_requires_enabling_flag() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-fixed-hdr-selector".to_string(),
            "45000054".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn multi_ext_hdr_occurrences_parse_and_validate() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-ipv6-ext-hdr".to_string(),
            "8".to_string(),
            "--reflected-ipv6-ext-hdr".to_string(),
            "16:3c000102".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_ok());
        let specs = conf.ext_hdr_requests();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].length, 8);
        assert!(specs[0].selector.is_none());
        assert_eq!(specs[1].length, 16);
        assert_eq!(
            specs[1].selector.as_deref(),
            Some(&[0x3c, 0x00, 0x01, 0x02][..])
        );
    }

    #[test]
    fn standalone_selector_rejected_with_multiple_ext_hdr_occurrences() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-ipv6-ext-hdr".to_string(),
            "--reflected-ipv6-ext-hdr".to_string(),
            "--reflected-ipv6-ext-hdr-selector".to_string(),
            "3c000102".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn attach_ext_hdr_default_and_custom_parse() {
        let mut args = base_valid_args();
        args.extend([
            "--attach-ext-hdr".to_string(),
            "hbh".to_string(),
            "--attach-ext-hdr".to_string(),
            "dest:0000010400000000".to_string(),
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_ok());
        let attaches = conf.attach_ext_hdrs();
        assert_eq!(attaches.len(), 2);
        assert_eq!(attaches[0].kind, AttachExtHdrKind::HopByHop);
        assert_eq!(attaches[0].bytes.len(), 8);
        assert_eq!(attaches[1].kind, AttachExtHdrKind::DestOpts);
        assert_eq!(attaches[1].bytes.len(), 8);
    }

    #[test]
    fn attach_ext_hdr_unknown_kind_is_rejected() {
        let mut args = base_valid_args();
        args.extend(["--attach-ext-hdr".to_string(), "bogus".to_string()]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn attach_ext_hdr_non_multiple_of_8_is_rejected() {
        let mut args = base_valid_args();
        args.extend(["--attach-ext-hdr".to_string(), "dest:000001".to_string()]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn fixed_hdr_selector_too_long_for_ipv4_is_rejected() {
        let mut args = base_valid_args();
        args.extend([
            "--reflected-fixed-hdr".to_string(),
            "--reflected-fixed-hdr-selector".to_string(),
            "01".repeat(21), // 21 bytes > 20-byte IPv4 fixed header
        ]);
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_control_plane_flags() {
        let args = vec![
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--is-reflector",
            "--control",
            "--control-addr",
            "127.0.0.1:9999",
        ];
        let conf = Configuration::parse_from(args);
        assert!(conf.control);
        assert_eq!(conf.control_addr, "127.0.0.1:9999".parse().unwrap());
        assert!(conf.control_token_file.is_none());
        assert!(conf.validate().is_ok());

        // --control is reflector-only.
        let args = vec!["test", "--remote-addr", "127.0.0.1", "--control"];
        let conf = Configuration::parse_from(args);
        assert!(
            conf.validate().is_err(),
            "--control without --is-reflector must be rejected"
        );
    }

    #[test]
    fn test_return_path_no_reply_conflicts_with_reflected_control() {
        // draft-ietf-ippm-asymmetrical-pkts-14 §4.3: a sender MUST NOT
        // combine a Return Path "no reply requested" control code with a
        // non-zero Reflected Test Packet Control TLV.
        let args = vec![
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--return-path-cc",
            "0",
            "--reflected-control-count",
            "4",
        ];
        let conf = Configuration::parse_from(args);
        assert!(
            conf.validate().is_err(),
            "no-reply control code + reflected-control-count > 1 must be rejected"
        );

        // cc=1 (reply requested) combines fine.
        let args = vec![
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--return-path-cc",
            "1",
            "--reflected-control-count",
            "4",
        ];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());

        // The ext-hdr-control sub-TLV also makes the TLV non-zero, even at
        // the default count of 1 — same §4.3 conflict.
        let args = vec![
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--return-path-cc",
            "0",
            "--reflected-control-no-ext-hdr",
        ];
        let conf = Configuration::parse_from(args);
        assert!(
            conf.validate().is_err(),
            "no-reply control code + ext-hdr-control sub-TLV must be rejected"
        );
    }

    #[test]
    fn test_is_auth() {
        assert!(is_auth(AuthMode::Authenticated));
        assert!(!is_auth(AuthMode::Open));
    }

    #[test]
    fn test_auth_mode_method() {
        assert!(AuthMode::Authenticated.is_authenticated());
        assert!(!AuthMode::Open.is_authenticated());
    }

    #[test]
    fn test_default_configuration() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.remote_addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(conf.local_addr, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(conf.remote_port, 862);
        assert_eq!(conf.local_port, 862);
        assert_eq!(conf.clock_source, ClockFormat::NTP);
        assert_eq!(conf.send_delay, 1000);
        assert_eq!(conf.count, 1000);
        assert_eq!(conf.timeout, 5);
        assert_eq!(conf.auth_mode, AuthMode::Open); // RFC 8762 default
        assert!(!conf.print_stats);
        assert!(!conf.is_reflector);
        assert_eq!(conf.error_scale, 0);
        assert_eq!(conf.error_multiplier, 1);
        assert!(!conf.clock_synchronized);
        assert!(conf.hmac_key.is_none());
        assert!(conf.hmac_key_file.is_none());
        assert!(!conf.require_hmac);
    }

    #[test]
    fn test_ipv6_address_parsing() {
        let args = vec!["test", "--remote-addr", "::1", "--local-addr", "fe80::1"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.remote_addr, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(conf.local_addr, "fe80::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_short_flags() {
        let args = vec!["test", "-R", "-i"];
        let conf = Configuration::parse_from(args);
        assert!(conf.print_stats);
        assert!(conf.is_reflector);
    }

    #[test]
    fn test_timeout_values() {
        let args = vec!["test", "--timeout", "0"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.timeout, 0);

        let args = vec!["test", "--timeout", "255"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.timeout, 255);
    }

    #[test]
    fn test_send_delay_values() {
        let args = vec!["test", "--send-delay", "0"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.send_delay, 0);

        let args = vec!["test", "--send-delay", "65535"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.send_delay, 65535);
    }

    #[test]
    fn test_clock_source_ptp() {
        let args = vec!["test", "--clock-source", "PTP"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.clock_source, ClockFormat::PTP);
    }

    #[test]
    fn test_invalid_clock_source() {
        let args = vec!["test", "--clock-source", "INVALID"];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_mode_variations() {
        // Authenticated mode (requires HMAC key)
        let args = vec![
            "test",
            "--auth-mode",
            "A",
            "--hmac-key",
            "0123456789abcdef0123456789abcdef",
        ];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
        assert!(is_auth(conf.auth_mode));
        assert_eq!(conf.auth_mode, AuthMode::Authenticated);

        // Open mode
        let args = vec!["test", "--auth-mode", "O"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
        assert!(!is_auth(conf.auth_mode));
        assert_eq!(conf.auth_mode, AuthMode::Open);
    }

    #[test]
    fn test_auth_mode_invalid_rejected_by_clap() {
        // Invalid values are now rejected by clap at parse time
        let invalid_modes = ["AO", "OA", "AA", "E", "X", "AE", "", "a", "o"];
        for mode in invalid_modes {
            let args = vec!["test", "--auth-mode", mode];
            let result = Configuration::try_parse_from(args);
            assert!(result.is_err(), "Mode '{}' should be rejected", mode);
        }
    }

    #[test]
    fn test_auth_mode_display() {
        assert_eq!(AuthMode::Authenticated.to_string(), "A");
        assert_eq!(AuthMode::Open.to_string(), "O");
    }

    #[test]
    fn test_auth_mode_default() {
        assert_eq!(AuthMode::default(), AuthMode::Open);
    }

    #[test]
    fn test_auth_reflector_requires_hmac_key() {
        // Authenticated mode reflector without HMAC key should fail validation
        let args = vec!["test", "-i", "--auth-mode", "A"];
        let conf = Configuration::parse_from(args);
        let result = conf.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires --hmac-key"));
    }

    #[test]
    fn test_auth_reflector_with_hmac_key_valid() {
        // Authenticated mode reflector with HMAC key should pass validation
        let args = vec![
            "test",
            "-i",
            "--auth-mode",
            "A",
            "--hmac-key",
            "0123456789abcdef0123456789abcdef",
        ];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_auth_sender_requires_hmac_key() {
        // Authenticated mode sender requires HMAC key
        let args = vec!["test", "--auth-mode", "A"];
        let conf = Configuration::parse_from(args);
        let err = conf.validate().unwrap_err();
        assert!(err.to_string().contains("requires --hmac-key"));
    }

    #[test]
    fn test_auth_sender_with_hmac_key_valid() {
        // Authenticated mode sender with HMAC key is valid
        let args = vec![
            "test",
            "--auth-mode",
            "A",
            "--hmac-key",
            "0123456789abcdef0123456789abcdef",
        ];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_invalid_port_number() {
        let args = vec!["test", "--remote-port", "99999"];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    fn test_error_estimate_options() {
        let args = vec![
            "test",
            "--error-scale",
            "10",
            "--error-multiplier",
            "100",
            "--clock-synchronized",
        ];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.error_scale, 10);
        assert_eq!(conf.error_multiplier, 100);
        assert!(conf.clock_synchronized);
    }

    #[test]
    fn test_error_scale_validation() {
        let args = vec!["test", "--error-scale", "63"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());

        let args = vec!["test", "--error-scale", "64"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_hmac_key_option() {
        let args = vec!["test", "--hmac-key", "0123456789abcdef0123456789abcdef"];
        let conf = Configuration::parse_from(args);

        assert_eq!(
            conf.hmac_key.as_ref().map(SecretString::as_str),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert!(conf.hmac_key_file.is_none());
    }

    #[test]
    fn test_secret_string_redacts_debug_and_roundtrips() {
        use std::str::FromStr;
        let secret = "0123456789abcdef0123456789abcdef";
        let s = SecretString::from_str(secret).unwrap();
        assert_eq!(s.as_str(), secret, "as_str must roundtrip the value");

        // Debug must NOT leak the secret (it is held redacted on purpose).
        let dbg = format!("{s:?}");
        assert!(
            !dbg.contains(secret),
            "Debug output must not contain the secret: {dbg}"
        );
        assert!(dbg.contains("redacted"));

        // And through the Configuration struct's Debug as well.
        let conf = Configuration::parse_from(vec!["test", "--hmac-key", secret]);
        assert!(
            !format!("{conf:?}").contains(secret),
            "Configuration Debug must not leak the HMAC key"
        );
    }

    #[test]
    fn test_hmac_key_file_option() {
        let args = vec!["test", "--hmac-key-file", "/path/to/key"];
        let conf = Configuration::parse_from(args);

        assert!(conf.hmac_key.is_none());
        assert_eq!(
            conf.hmac_key_file,
            Some(std::path::PathBuf::from("/path/to/key"))
        );
    }

    #[test]
    fn test_require_hmac_option() {
        let args = vec!["test", "--require-hmac"];
        let conf = Configuration::parse_from(args);

        assert!(conf.require_hmac);
    }

    #[test]
    fn test_strict_packets_option() {
        let args = vec!["test", "--strict-packets"];
        let conf = Configuration::parse_from(args);

        assert!(conf.strict_packets);
    }

    #[test]
    fn test_strict_packets_default_false() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        // Default is false (lenient mode is default per RFC 8762 §4.6)
        assert!(!conf.strict_packets);
    }

    #[test]
    fn test_log_format_default_text() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.log_format, LogFormat::Text);
    }

    #[test]
    fn test_log_format_explicit_json() {
        let args = vec!["test", "--log-format", "json"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.log_format, LogFormat::Json);
    }

    #[test]
    fn test_log_format_explicit_text() {
        let args = vec!["test", "--log-format", "text"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.log_format, LogFormat::Text);
    }

    #[test]
    fn test_log_format_rejects_invalid() {
        let args = vec!["test", "--log-format", "yaml"];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err(), "unknown log format must be rejected");
    }

    #[test]
    fn test_log_format_toml_round_trip() {
        let toml_str = r#"
            remote_addr = "127.0.0.1"
            log_format = "json"
        "#;
        let file: FileConfiguration = toml::from_str(toml_str).expect("parse");
        assert_eq!(file.log_format, Some(LogFormat::Json));
    }

    // -----------------------------------------------------------------------
    // D4: --print-config-schema.

    /// The exported schema is well-formed JSON.
    #[test]
    fn test_config_schema_is_valid_json() {
        let v: serde_json::Value =
            serde_json::from_str(CONFIG_JSON_SCHEMA).expect("schema must parse as JSON");
        assert!(v.is_object(), "schema root must be an object");
        let obj = v.as_object().unwrap();
        assert_eq!(
            obj.get("$schema").and_then(|s| s.as_str()),
            Some("https://json-schema.org/draft/2020-12/schema"),
            "must declare draft 2020-12"
        );
        assert_eq!(obj.get("type").and_then(|s| s.as_str()), Some("object"));
        assert_eq!(
            obj.get("additionalProperties").and_then(|b| b.as_bool()),
            Some(false),
            "schema must mirror FileConfiguration's deny_unknown_fields"
        );
    }

    /// Every field in FileConfiguration appears in the schema's
    /// properties block — guards against forgetting to update the
    /// schema when adding a new field.
    #[test]
    fn test_config_schema_covers_every_file_config_field() {
        let v: serde_json::Value = serde_json::from_str(CONFIG_JSON_SCHEMA).unwrap();
        let props = v
            .get("properties")
            .and_then(|p| p.as_object())
            .expect("schema must have a properties object");

        // Hand-maintained list of every FileConfiguration field. Update
        // this list when adding a new field to FileConfiguration and
        // CONFIG_JSON_SCHEMA — the test guarantees both stay in sync.
        let expected = [
            "remote_addr",
            "local_addr",
            "remote_port",
            "local_port",
            "clock_source",
            "send_delay",
            "count",
            "timeout",
            "auth_mode",
            "print_stats",
            "is_reflector",
            "error_scale",
            "error_multiplier",
            "clock_synchronized",
            "hmac_key_file",
            "hmac_key_dir",
            "require_hmac",
            "strict_packets",
            "stateful_reflector",
            "session_timeout",
            "tlv_mode",
            "verify_tlv_hmac",
            "ssid",
            "metrics",
            "metrics_addr",
            "cos",
            "dscp",
            "ecn",
            "ecn_backoff_factor",
            "ecn_max_delay",
            "ecn_recovery_step",
            "ttl",
            "malformed",
            "access_report",
            "access_return_code",
            "access_report_timeout",
            "access_report_retries",
            "timestamp_info",
            "direct_measurement",
            "location",
            "follow_up_telemetry",
            "snmp",
            "snmp_socket",
            "control",
            "control_addr",
            "control_token_file",
            "output_format",
            "log_format",
            "hwtstamp",
            "report_interval",
            "dest_node_addr",
            "return_path_cc",
            "return_address",
            "return_sr_mpls_labels",
            "return_srv6_sids",
            "srv6_return_forwarding",
            "return_path_allow_alternate",
            "micro_session_id",
            "reflector_member_link_id",
            "max_pps",
            "reflector_rate_burst",
            "max_sessions",
            "ber",
            "ber_pattern",
            "ber_padding_size",
            "reflected_control_count",
            "reflected_control_length",
            "reflected_control_interval_ns",
            "reflected_control_max_count",
            "reflected_control_max_size",
            "reflected_control_min_interval_ns",
            "reflected_fixed_hdr",
            "reflected_ipv6_ext_hdr",
            "attach_ext_hdr",
        ];
        for name in expected {
            assert!(
                props.contains_key(name),
                "schema is missing property '{name}'; update CONFIG_JSON_SCHEMA"
            );
        }
    }

    #[test]
    fn test_print_config_schema_flag_parses() {
        let args = vec!["test", "--print-config-schema"];
        let conf = Configuration::parse_from(args);
        assert!(conf.print_config_schema);
    }

    #[test]
    fn test_print_config_schema_default_false() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);
        assert!(!conf.print_config_schema);
    }

    // -----------------------------------------------------------------------
    // F1: --hwtstamp.

    #[test]
    fn test_hwtstamp_default_auto() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.hwtstamp, HwTsMode::Auto);
    }

    #[test]
    fn test_reflected_control_max_count_defaults_to_zero() {
        // draft-ietf-ippm-asymmetrical-pkts: the reflected-packet feature MUST
        // be disabled by default. A zero cap means no amplification unless the
        // operator opts in via --reflected-control-max-count.
        let conf = Configuration::parse_from(["test"]);
        assert_eq!(
            conf.reflected_control_max_count, 0,
            "Type 12 reflection must be disabled by default"
        );
    }

    #[test]
    fn test_hwtstamp_explicit_on() {
        let args = vec!["test", "--hwtstamp", "on"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.hwtstamp, HwTsMode::On);
    }

    #[test]
    fn test_hwtstamp_explicit_off() {
        let args = vec!["test", "--hwtstamp", "off"];
        let conf = Configuration::parse_from(args);
        assert_eq!(conf.hwtstamp, HwTsMode::Off);
    }

    #[test]
    fn test_hwtstamp_rejects_invalid_value() {
        let args = vec!["test", "--hwtstamp", "always"];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err(), "unknown hwtstamp mode must be rejected");
    }

    #[test]
    fn test_hwtstamp_toml_round_trip() {
        let toml_str = r#"
            remote_addr = "127.0.0.1"
            hwtstamp = "on"
        "#;
        let file: FileConfiguration = toml::from_str(toml_str).expect("parse");
        assert_eq!(file.hwtstamp, Some(HwTsMode::On));
    }

    #[test]
    fn test_stateful_reflector_option() {
        let args = vec!["test", "--stateful-reflector"];
        let conf = Configuration::parse_from(args);

        assert!(conf.stateful_reflector);
    }

    #[test]
    fn test_stateful_reflector_default_false() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        assert!(!conf.stateful_reflector);
    }

    #[test]
    fn test_session_timeout_default() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.session_timeout, 300);
    }

    #[test]
    fn test_session_timeout_custom() {
        let args = vec!["test", "--session-timeout", "600"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.session_timeout, 600);
    }

    #[test]
    fn test_session_timeout_zero_disables() {
        let args = vec!["test", "--session-timeout", "0"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.session_timeout, 0);
    }

    #[test]
    fn test_stateful_reflector_with_timeout() {
        let args = vec!["test", "--stateful-reflector", "--session-timeout", "120"];
        let conf = Configuration::parse_from(args);

        assert!(conf.stateful_reflector);
        assert_eq!(conf.session_timeout, 120);
    }

    #[test]
    fn test_tlv_mode_default() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.tlv_mode, TlvHandlingMode::Echo);
    }

    #[test]
    fn test_tlv_mode_ignore() {
        let args = vec!["test", "--tlv-mode", "ignore"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.tlv_mode, TlvHandlingMode::Ignore);
    }

    #[test]
    fn test_tlv_mode_echo() {
        let args = vec!["test", "--tlv-mode", "echo"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.tlv_mode, TlvHandlingMode::Echo);
    }

    #[test]
    fn test_verify_tlv_hmac_with_key() {
        let args = vec![
            "test",
            "--verify-tlv-hmac",
            "--hmac-key",
            "0123456789abcdef",
        ];
        let conf = Configuration::parse_from(args);

        assert!(conf.verify_tlv_hmac);
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_verify_tlv_hmac_with_key_file() {
        let args = vec![
            "test",
            "--verify-tlv-hmac",
            "--hmac-key-file",
            "/path/to/key",
        ];
        let conf = Configuration::parse_from(args);

        assert!(conf.verify_tlv_hmac);
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_verify_tlv_hmac_requires_key() {
        // --verify-tlv-hmac without HMAC key should fail validation
        let args = vec!["test", "--verify-tlv-hmac"];
        let conf = Configuration::parse_from(args);

        assert!(conf.verify_tlv_hmac);
        let result = conf.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("--verify-tlv-hmac requires"));
    }

    #[test]
    fn test_verify_tlv_hmac_default() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        assert!(!conf.verify_tlv_hmac);
    }

    #[test]
    fn test_ssid_option() {
        let args = vec!["test", "--ssid", "12345"];
        let conf = Configuration::parse_from(args);

        assert_eq!(conf.ssid, Some(12345));
    }

    #[test]
    fn test_ssid_default_none() {
        let args = vec!["test"];
        let conf = Configuration::parse_from(args);

        assert!(conf.ssid.is_none());
    }

    #[test]
    fn test_tlv_handling_mode_from_str() {
        // ValueEnum::from_str(value, ignore_case)
        assert_eq!(
            TlvHandlingMode::from_str("ignore", false).unwrap(),
            TlvHandlingMode::Ignore
        );
        assert_eq!(
            TlvHandlingMode::from_str("echo", false).unwrap(),
            TlvHandlingMode::Echo
        );
        // Case-insensitive parsing
        assert_eq!(
            TlvHandlingMode::from_str("ECHO", true).unwrap(),
            TlvHandlingMode::Echo
        );
        assert!(TlvHandlingMode::from_str("invalid", false).is_err());
        assert!(TlvHandlingMode::from_str("process", false).is_err());
    }

    #[test]
    fn test_tlv_handling_mode_display() {
        assert_eq!(TlvHandlingMode::Ignore.to_string(), "ignore");
        assert_eq!(TlvHandlingMode::Echo.to_string(), "echo");
    }

    // ===== RFC 9503 Configuration Tests =====

    #[test]
    fn test_dest_node_addr_requires_ssid() {
        let args = vec!["test", "--dest-node-addr", "192.168.1.1"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_dest_node_addr_with_ssid_ok() {
        let args = vec!["test", "--dest-node-addr", "192.168.1.1", "--ssid", "42"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_return_path_cc_valid_values() {
        let args = vec!["test", "--return-path-cc", "0"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());

        let args = vec!["test", "--return-path-cc", "1"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
    }

    #[test]
    fn test_return_path_cc_invalid_value() {
        let args = vec!["test", "--return-path-cc", "2"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_return_path_cc_conflicts_with_return_address() {
        let result = Configuration::try_parse_from(vec![
            "test",
            "--return-path-cc",
            "0",
            "--return-address",
            "10.0.0.1",
        ]);
        assert!(result.is_err()); // clap conflict
    }

    #[test]
    fn test_return_sr_mpls_labels_valid() {
        let args = vec!["test", "--return-sr-mpls-labels", "100,200,300"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
        assert_eq!(conf.return_sr_mpls_labels, Some(vec![100, 200, 300]));
    }

    #[test]
    fn test_return_sr_mpls_labels_exceeds_20bit() {
        let args = vec!["test", "--return-sr-mpls-labels", "1048576"]; // 0x100000
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_return_srv6_sids_parsed() {
        let args = vec!["test", "--return-srv6-sids", "2001:db8::1,2001:db8::2"];
        let conf = Configuration::parse_from(args);
        assert_eq!(
            conf.return_srv6_sids,
            Some(vec![
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ])
        );
    }

    #[test]
    fn test_return_sr_mpls_conflicts_with_srv6() {
        let args = vec![
            "test",
            "--return-sr-mpls-labels",
            "100,200",
            "--return-srv6-sids",
            "2001:db8::1",
        ];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err());
    }

    // ===== TOML Configuration File Tests =====

    use clap::CommandFactory;

    fn load_from_args(args: &[&str]) -> Result<Configuration, ConfigurationError> {
        let matches = Configuration::command().get_matches_from(args);
        Configuration::load_from_matches(matches)
    }

    #[test]
    fn test_file_config_parses_minimal_toml() {
        let file: FileConfiguration = toml::from_str("").expect("empty TOML parses");
        assert!(file.remote_addr.is_none());
        assert!(file.remote_port.is_none());
        assert!(file.auth_mode.is_none());
        assert!(file.ber.is_none());
    }

    #[test]
    fn test_file_config_parses_all_common_fields() {
        let toml_str = r#"
            remote_addr = "127.0.0.1"
            local_addr = "192.168.1.1"
            remote_port = 10862
            local_port = 20862
            clock_source = "PTP"
            send_delay = 500
            count = 10
            timeout = 2
            auth_mode = "A"
            is_reflector = true
            ber = true
            ber_padding_size = 128
            return_sr_mpls_labels = [100, 200, 300]
            return_srv6_sids = ["2001:db8::1", "2001:db8::2"]
            output_format = "json"
            tlv_mode = "ignore"
        "#;
        let file: FileConfiguration = toml::from_str(toml_str).expect("parses");
        assert_eq!(file.remote_addr, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(file.remote_port, Some(10862));
        assert_eq!(file.clock_source, Some(ClockFormat::PTP));
        assert_eq!(file.auth_mode, Some(AuthMode::Authenticated));
        assert_eq!(file.is_reflector, Some(true));
        assert_eq!(file.ber, Some(true));
        assert_eq!(file.ber_padding_size, Some(128));
        assert_eq!(file.return_sr_mpls_labels, Some(vec![100, 200, 300]));
        assert_eq!(
            file.return_srv6_sids,
            Some(vec![
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
            ])
        );
        assert_eq!(file.output_format, Some(OutputFormat::Json));
        assert_eq!(file.tlv_mode, Some(TlvHandlingMode::Ignore));
    }

    #[test]
    fn test_file_config_rejects_unknown_key() {
        let toml_str = r#"remote_adddr = "127.0.0.1""#;
        let err = toml::from_str::<FileConfiguration>(toml_str)
            .expect_err("unknown key must be rejected");
        assert!(err.to_string().contains("remote_adddr"));
    }

    #[test]
    fn test_file_config_rejects_plaintext_hmac_key() {
        let toml_str = r#"hmac_key = "deadbeef""#;
        let err = toml::from_str::<FileConfiguration>(toml_str)
            .expect_err("hmac_key must not be accepted from TOML");
        assert!(err.to_string().contains("hmac_key"));
    }

    #[test]
    fn test_file_config_allows_hmac_key_file() {
        let toml_str = r#"hmac_key_file = "/etc/stamp/key""#;
        let file: FileConfiguration = toml::from_str(toml_str).expect("parses");
        assert_eq!(file.hmac_key_file, Some(PathBuf::from("/etc/stamp/key")));
    }

    #[test]
    fn test_merge_cli_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "remote_port = 5678\n").unwrap();

        let conf = load_from_args(&[
            "test",
            "--config",
            path.to_str().unwrap(),
            "--remote-port",
            "1234",
        ])
        .expect("load ok");
        assert_eq!(conf.remote_port, 1234);
    }

    #[test]
    fn test_merge_file_overrides_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "remote_port = 5678\n").unwrap();

        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
        assert_eq!(conf.remote_port, 5678);
    }

    #[test]
    fn test_merge_default_when_neither_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "").unwrap();

        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
        assert_eq!(conf.remote_port, 862);
    }

    #[test]
    fn test_merge_bool_flag_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "ber = true\nstateful_reflector = true\n").unwrap();

        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
        assert!(conf.ber);
        assert!(conf.stateful_reflector);
    }

    #[test]
    fn test_merge_vec_field_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "return_sr_mpls_labels = [100, 200]\n").unwrap();

        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
        assert_eq!(conf.return_sr_mpls_labels, Some(vec![100, 200]));
    }

    #[test]
    fn test_merge_option_field_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "ssid = 42\nhmac_key_file = \"/etc/stamp/key\"\n").unwrap();

        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
        assert_eq!(conf.ssid, Some(42));
        assert_eq!(conf.hmac_key_file, Some(PathBuf::from("/etc/stamp/key")));
    }

    #[test]
    fn test_merge_cli_overrides_file_for_bool() {
        // File sets ber=true but CLI does not; ber must be true.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "ber = true\n").unwrap();
        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
        assert!(conf.ber);
    }

    #[test]
    fn test_merge_cli_overrides_file_for_option_field() {
        // File sets ssid=42, CLI passes --ssid 99; CLI must win.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "ssid = 42\n").unwrap();

        let conf = load_from_args(&["test", "--config", path.to_str().unwrap(), "--ssid", "99"])
            .expect("load ok");
        assert_eq!(conf.ssid, Some(99));
    }

    #[test]
    fn test_load_with_nonexistent_config_path() {
        let err = load_from_args(&["test", "--config", "/no/such/file/stamp.toml"])
            .expect_err("non-existent file must error");
        match err {
            ConfigurationError::ConfigFileError(msg) => {
                assert!(msg.contains("/no/such/file/stamp.toml"));
            }
            other => panic!("expected ConfigFileError, got {other:?}"),
        }
    }

    #[test]
    fn test_load_with_malformed_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "remote_port = \"oops\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("malformed TOML must error");
        match err {
            ConfigurationError::ConfigFileError(msg) => {
                assert!(msg.contains(path.to_str().unwrap()));
            }
            other => panic!("expected ConfigFileError, got {other:?}"),
        }
    }

    #[test]
    fn test_load_runs_validation_after_merge() {
        // File sets auth_mode to A but no HMAC key -> validate() must fail.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "auth_mode = \"A\"\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("authenticated mode without key must fail validation");
        assert!(matches!(err, ConfigurationError::InvalidConfiguration(_)));
    }

    #[test]
    fn test_validate_rejects_out_of_range_dscp_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "dscp = 200\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("dscp > 63 must fail");
        assert!(err.to_string().contains("dscp"));
    }

    #[test]
    fn test_validate_rejects_out_of_range_ecn_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "ecn = 10\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("ecn > 3 must fail");
        assert!(err.to_string().contains("ecn"));
    }

    // ===== AIMD congestion-response (F2, draft-ietf-ippm-stamp-cos-ecn-01 §3.4) =====

    #[test]
    fn test_validate_rejects_ecn_backoff_factor_not_greater_than_one() {
        let err = load_from_args(&["test", "--ecn-backoff-factor", "1.0"])
            .expect_err("backoff factor of exactly 1.0 must fail (no actual backoff)");
        assert!(err.to_string().contains("ecn_backoff_factor"));
    }

    #[test]
    fn test_validate_rejects_ecn_backoff_factor_below_one() {
        let err = load_from_args(&["test", "--ecn-backoff-factor", "0.5"])
            .expect_err("backoff factor < 1.0 must fail");
        assert!(err.to_string().contains("ecn_backoff_factor"));
    }

    #[test]
    fn test_validate_rejects_ecn_backoff_factor_non_finite() {
        let err = load_from_args(&["test", "--ecn-backoff-factor", "inf"])
            .expect_err("non-finite backoff factor must fail");
        assert!(err.to_string().contains("ecn_backoff_factor"));
    }

    #[test]
    fn test_validate_rejects_ecn_recovery_step_zero() {
        let err = load_from_args(&["test", "--ecn-recovery-step", "0"])
            .expect_err("recovery step 0 must fail (would never recover)");
        assert!(err.to_string().contains("ecn_recovery_step"));
    }

    #[test]
    fn test_validate_rejects_ecn_max_delay_zero() {
        let err =
            load_from_args(&["test", "--ecn-max-delay", "0"]).expect_err("max delay 0 must fail");
        assert!(err.to_string().contains("ecn_max_delay"));
    }

    #[test]
    fn test_validate_rejects_ecn_max_delay_below_send_delay_when_active() {
        let err = load_from_args(&[
            "test",
            "--cos",
            "--ecn",
            "1",
            "--send-delay",
            "50000",
            "--ecn-max-delay",
            "1000",
        ])
        .expect_err("ecn_max_delay below send_delay while the controller is active must fail");
        assert!(err.to_string().contains("ecn_max_delay"));
    }

    #[test]
    fn test_validate_allows_ecn_max_delay_below_send_delay_when_controller_inactive() {
        // No --cos: the controller never activates, so the default
        // ecn_max_delay (30000ms) being smaller than a large --send-delay
        // must not spuriously fail validation.
        let conf = load_from_args(&["test", "--send-delay", "50000"])
            .expect("controller inactive, cross-check must not apply");
        assert_eq!(conf.send_delay, 50000);
    }

    #[test]
    fn test_validate_allows_ecn_max_delay_below_send_delay_when_ecn_zero() {
        // --cos set but --ecn left at its default (0 = Not-ECT): the
        // controller is inactive (activation requires ECT0/ECT1), so this
        // must not fail either.
        let conf = load_from_args(&[
            "test",
            "--cos",
            "--send-delay",
            "50000",
            "--ecn-max-delay",
            "1000",
        ])
        .expect("controller inactive when ecn=0, cross-check must not apply");
        assert_eq!(conf.send_delay, 50000);
    }

    #[test]
    fn test_validate_accepts_default_ecn_aimd_parameters() {
        let conf = load_from_args(&["test", "--cos", "--ecn", "1"])
            .expect("defaults must satisfy validate()");
        assert!((conf.ecn_backoff_factor - 2.0).abs() < f64::EPSILON);
        assert_eq!(conf.ecn_max_delay, 30_000);
        assert_eq!(conf.ecn_recovery_step, 50);
    }

    #[test]
    fn test_validate_rejects_out_of_range_access_report_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "access_report = 99\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("access_report > 15 must fail");
        assert!(err.to_string().contains("access_report"));
    }

    /// RFC 8972 §4.6: the Access ID field has no defined value of 0 — only
    /// 1 (3GPP) and 2 (Non-3GPP) are defined. 0 must always be rejected,
    /// whether supplied on the CLI (clap's `range` parser) or via the TOML
    /// file (the duplicated `validate()` check).
    ///
    /// Uses `try_get_matches_from` rather than the `load_from_args` helper:
    /// `Configuration::command().get_matches_from` calls `process::exit` on
    /// a parse error instead of returning a `Result`, which would abort the
    /// whole test binary.
    #[test]
    fn test_access_report_cli_rejects_zero() {
        let result =
            Configuration::command().try_get_matches_from(["test", "--access-report", "0"]);
        assert!(
            result.is_err(),
            "--access-report 0 must be rejected by the CLI parser"
        );
    }

    #[test]
    fn test_validate_rejects_zero_access_report_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "access_report = 0\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("access_report == 0 must fail (no defined Access ID 0, RFC 8972 §4.6)");
        assert!(err.to_string().contains("access_report"));
    }

    /// Values 1 (3GPP) and 2 (Non-3GPP) are the RFC 8972 §4.6-defined
    /// Access IDs and must be accepted without any error.
    #[test]
    fn test_access_report_accepts_defined_registry_values() {
        for value in ["1", "2"] {
            let conf = load_from_args(&["test", "--access-report", value])
                .unwrap_or_else(|e| panic!("--access-report {value} must be accepted: {e}"));
            assert_eq!(conf.access_report, Some(value.parse().unwrap()));
        }
    }

    /// Values 3-15 are not currently defined by RFC 8972 §4.6, but the
    /// field is a 4-bit wire value and a future registry allocation must
    /// not be blocked by the CLI. They are accepted (with a startup
    /// warning logged, not asserted here — no log-capture harness in this
    /// crate) rather than rejected outright.
    #[test]
    fn test_access_report_accepts_undefined_registry_values_within_4_bits() {
        for value in ["3", "15"] {
            let conf = load_from_args(&["test", "--access-report", value])
                .unwrap_or_else(|e| panic!("--access-report {value} must be accepted: {e}"));
            assert_eq!(conf.access_report, Some(value.parse().unwrap()));
        }
    }

    /// The field is 4 bits wide: 16 and above must still be rejected.
    #[test]
    fn test_access_report_cli_rejects_above_4_bit_range() {
        let result =
            Configuration::command().try_get_matches_from(["test", "--access-report", "16"]);
        assert!(
            result.is_err(),
            "--access-report 16 exceeds the 4-bit field width and must be rejected"
        );
    }

    /// RFC 8972 §4.6: "The default value of the retransmission timer for
    /// the Access Report TLV SHOULD be three seconds."
    #[test]
    fn test_access_report_timeout_default_is_three_seconds() {
        let conf = load_from_args(&["test"]).unwrap();
        assert_eq!(conf.access_report_timeout, 3);
    }

    /// RFC 8972 §4.6: "This retransmission SHOULD be repeated up to four
    /// times before the procedure is aborted."
    #[test]
    fn test_access_report_retries_default_is_four() {
        let conf = load_from_args(&["test"]).unwrap();
        assert_eq!(conf.access_report_retries, 4);
    }

    /// RFC 8972 §4.6: "An implementation MUST provide control of the
    /// retransmission timer value and the number of retransmissions" —
    /// both must be overridable via the CLI.
    #[test]
    fn test_access_report_timeout_and_retries_are_configurable() {
        let conf = load_from_args(&[
            "test",
            "--access-report-timeout",
            "10",
            "--access-report-retries",
            "2",
        ])
        .unwrap();
        assert_eq!(conf.access_report_timeout, 10);
        assert_eq!(conf.access_report_retries, 2);
    }

    #[test]
    fn test_access_report_timeout_cli_rejects_zero() {
        let result =
            Configuration::command().try_get_matches_from(["test", "--access-report-timeout", "0"]);
        assert!(
            result.is_err(),
            "--access-report-timeout 0 must be rejected by the CLI parser"
        );
    }

    #[test]
    fn test_access_report_retries_accepts_zero() {
        // 0 is a legitimate operator choice: abort immediately on the first
        // missed acknowledgment instead of retransmitting.
        let conf = load_from_args(&["test", "--access-report-retries", "0"]).unwrap();
        assert_eq!(conf.access_report_retries, 0);
    }

    #[test]
    fn test_validate_rejects_zero_access_report_timeout_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "access_report_timeout = 0\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("access_report_timeout == 0 must fail");
        assert!(err.to_string().contains("access_report_timeout"));
    }

    #[test]
    fn test_validate_rejects_out_of_range_access_report_timeout_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "access_report_timeout = 99999\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("access_report_timeout > 3600 must fail");
        assert!(err.to_string().contains("access_report_timeout"));
    }

    #[test]
    fn test_validate_rejects_out_of_range_access_report_retries_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "access_report_retries = 99999\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("access_report_retries > 255 must fail");
        assert!(err.to_string().contains("access_report_retries"));
    }

    #[test]
    fn test_validate_rejects_zero_micro_session_id_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "micro_session_id = 0\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("micro_session_id == 0 must fail");
        assert!(err.to_string().contains("micro_session_id"));
    }

    #[test]
    fn test_validate_rejects_zero_reflector_member_link_id_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "reflector_member_link_id = 0\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("reflector_member_link_id == 0 must fail");
        assert!(err.to_string().contains("reflector_member_link_id"));
    }

    #[test]
    fn test_parse_u16_nonzero_dec_or_hex_accepts_decimal() {
        assert_eq!(parse_u16_nonzero_dec_or_hex("1").unwrap(), 1);
        assert_eq!(parse_u16_nonzero_dec_or_hex("255").unwrap(), 255);
        assert_eq!(parse_u16_nonzero_dec_or_hex("65535").unwrap(), 65535);
    }

    #[test]
    fn test_parse_u16_nonzero_dec_or_hex_accepts_hex() {
        assert_eq!(parse_u16_nonzero_dec_or_hex("0x1").unwrap(), 1);
        assert_eq!(parse_u16_nonzero_dec_or_hex("0xff").unwrap(), 255);
        assert_eq!(parse_u16_nonzero_dec_or_hex("0xFF").unwrap(), 255);
        assert_eq!(parse_u16_nonzero_dec_or_hex("0X00ab").unwrap(), 0xab);
        assert_eq!(parse_u16_nonzero_dec_or_hex("0xffff").unwrap(), 65535);
    }

    #[test]
    fn test_parse_u16_nonzero_dec_or_hex_rejects_zero() {
        assert!(parse_u16_nonzero_dec_or_hex("0").is_err());
        assert!(parse_u16_nonzero_dec_or_hex("0x0").is_err());
        assert!(parse_u16_nonzero_dec_or_hex("0x0000").is_err());
    }

    #[test]
    fn test_parse_u16_nonzero_dec_or_hex_rejects_garbage() {
        assert!(parse_u16_nonzero_dec_or_hex("").is_err());
        assert!(parse_u16_nonzero_dec_or_hex("ff").is_err()); // hex without 0x prefix
        assert!(parse_u16_nonzero_dec_or_hex("0x1g").is_err());
        assert!(parse_u16_nonzero_dec_or_hex("0x10000").is_err()); // > u16::MAX
        assert!(parse_u16_nonzero_dec_or_hex("65536").is_err());
        // Empty string after stripping `0x` prefix → from_str_radix rejects.
        assert!(parse_u16_nonzero_dec_or_hex("0x").is_err());
        assert!(parse_u16_nonzero_dec_or_hex("0X").is_err());
    }

    #[test]
    fn test_parse_u16_nonzero_dec_or_hex_handles_whitespace() {
        // clap doesn't usually pass whitespace, but the parser trims defensively
        // (e.g. when values are loaded from the TOML config file).
        assert_eq!(parse_u16_nonzero_dec_or_hex(" 0xff").unwrap(), 0xff);
        assert_eq!(parse_u16_nonzero_dec_or_hex("0xff ").unwrap(), 0xff);
        assert_eq!(parse_u16_nonzero_dec_or_hex(" 255 ").unwrap(), 255);
        assert_eq!(parse_u16_nonzero_dec_or_hex("\t0x1\n").unwrap(), 1);
    }

    #[test]
    fn test_micro_session_id_accepts_hex_on_cli() {
        let conf = load_from_args(&[
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--micro-session-id",
            "0xff",
            "--reflector-member-link-id",
            "0xab",
        ])
        .unwrap();
        assert_eq!(conf.micro_session_id, Some(0xff));
        assert_eq!(conf.reflector_member_link_id, Some(0xab));
    }

    #[test]
    fn test_micro_session_id_accepts_decimal_on_cli() {
        let conf = load_from_args(&[
            "test",
            "--remote-addr",
            "127.0.0.1",
            "--micro-session-id",
            "255",
        ])
        .unwrap();
        assert_eq!(conf.micro_session_id, Some(255));
    }

    #[test]
    fn test_validate_rejects_return_path_cc_with_sr_mpls_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(
            &path,
            "return_path_cc = 0\nreturn_sr_mpls_labels = [100, 200]\n",
        )
        .unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("conflicting return-path options must fail");
        let msg = err.to_string();
        assert!(msg.contains("return_path_cc"));
        assert!(msg.contains("return_sr_mpls_labels"));
    }

    #[test]
    fn test_validate_rejects_return_path_cc_with_srv6_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(
            &path,
            "return_path_cc = 1\nreturn_srv6_sids = [\"2001:db8::1\"]\n",
        )
        .unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("conflicting return-path options must fail");
        assert!(err.to_string().contains("return_srv6_sids"));
    }

    #[test]
    fn test_cos_policy_defaults_to_permit_all() {
        let conf = load_from_args(&["test"]).unwrap();
        assert_eq!(conf.allowed_dscp, "all");
        assert_eq!(conf.allowed_ecn, "all");
        assert!(
            conf.cos_admission_policy().unwrap().is_permissive(),
            "a measurement tool must answer every CoS request by default"
        );
    }

    #[test]
    fn test_cos_policy_parses_flags_and_destination_rules() {
        let conf = load_from_args(&[
            "test",
            "--allowed-dscp",
            "0,46",
            "--allowed-ecn",
            "0,2",
            "--allowed-dscp-for",
            "192.0.2.0/24=34",
            "--allowed-dscp-for",
            "10.0.0.0/8=none",
        ])
        .expect("a valid policy must load");
        let policy = conf.cos_admission_policy().unwrap();
        assert!(!policy.is_permissive());
        assert!(policy.permits_dscp(None, 46));
        assert!(!policy.permits_dscp(None, 34));
        assert!(policy.permits_ecn(2));
        assert!(!policy.permits_ecn(1));
        // Destination rules replace the global set inside their prefix.
        let inside: std::net::IpAddr = "192.0.2.9".parse().unwrap();
        assert!(policy.permits_dscp(Some(inside), 34));
        assert!(!policy.permits_dscp(Some(inside), 46));
        let denied: std::net::IpAddr = "10.1.1.1".parse().unwrap();
        assert!(!policy.permits_dscp(Some(denied), 46));
    }

    #[test]
    fn test_validate_rejects_bad_cos_policy() {
        // Each flag must fail at startup rather than degrading to permit-all
        // on every packet.
        let err =
            load_from_args(&["test", "--allowed-dscp", "64"]).expect_err("DSCP 64 is out of range");
        assert!(err.to_string().contains("allowed-dscp"), "{err}");

        let err =
            load_from_args(&["test", "--allowed-ecn", "9"]).expect_err("ECN 9 is out of range");
        assert!(err.to_string().contains("allowed-ecn"), "{err}");

        let err = load_from_args(&["test", "--allowed-dscp-for", "192.0.2.0/24"])
            .expect_err("a rule without '=' is malformed");
        assert!(err.to_string().contains("allowed-dscp-for"), "{err}");

        let err = load_from_args(&["test", "--allowed-dscp-for", "192.0.2.0/33=46"])
            .expect_err("prefix length out of range");
        assert!(err.to_string().contains("allowed-dscp-for"), "{err}");
    }

    #[test]
    fn test_cos_policy_merges_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(
            &path,
            "allowed_dscp = \"46\"\nallowed_ecn = \"none\"\nallowed_dscp_for = [\"192.0.2.0/24=0\"]\n",
        )
        .unwrap();
        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect("file-configured policy must load");
        let policy = conf.cos_admission_policy().unwrap();
        assert!(policy.permits_dscp(None, 46));
        assert!(!policy.permits_dscp(None, 0));
        assert!(
            !policy.permits_ecn(0),
            "allowed_ecn = none refuses every value"
        );
        let inside: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        assert!(
            policy.permits_dscp(Some(inside), 0),
            "file rule must reach the policy"
        );
    }

    #[test]
    fn test_drop_replayed_defaults_off_and_merges_from_file() {
        let conf = load_from_args(&["test"]).unwrap();
        assert!(
            !conf.drop_replayed,
            "acting on a duplicate must be opt-in: a restarted sender replays \
             its own numbering and dropping it would break honest measurement"
        );

        let conf = load_from_args(&["test", "--drop-replayed"]).unwrap();
        assert!(conf.drop_replayed);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "drop_replayed = true\n").unwrap();
        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).unwrap();
        assert!(conf.drop_replayed);
    }

    #[test]
    fn test_reflected_burst_pacing_warning_absent_without_a_burst() {
        // count defaults to 1: no Type-12 burst is requested, so the §5
        // SHOULD NOT cannot be violated.
        let conf = load_from_args(&["test"]).unwrap();
        assert_eq!(conf.reflected_control_count, 1);
        assert!(conf.reflected_burst_pacing_warning().is_none());
    }

    #[test]
    fn test_reflected_burst_pacing_warning_fires_when_send_delay_too_short() {
        // 20 packets, 10 ms apart => the burst runs 190 ms; a 50 ms
        // --send-delay starts the next request mid-burst.
        let conf = load_from_args(&[
            "test",
            "--send-delay",
            "50",
            "--reflected-control-count",
            "20",
            "--reflected-control-interval-ns",
            "10000000",
        ])
        .unwrap();
        let w = conf
            .reflected_burst_pacing_warning()
            .expect("overlapping pacing must warn");
        assert!(w.contains("190.000 ms"), "expected burst duration in: {w}");
        assert!(w.contains("at least 190 ms"), "expected remedy in: {w}");
    }

    #[test]
    fn test_reflected_burst_pacing_warning_silent_when_delay_is_sufficient() {
        // Same burst (190 ms) with a 200 ms gap: no overlap, no warning.
        let conf = load_from_args(&[
            "test",
            "--send-delay",
            "200",
            "--reflected-control-count",
            "20",
            "--reflected-control-interval-ns",
            "10000000",
        ])
        .unwrap();
        assert!(conf.reflected_burst_pacing_warning().is_none());
    }

    #[test]
    fn test_reflected_burst_pacing_boundary_is_not_a_violation() {
        // Exactly equal is compliant: the SHOULD NOT is about sending
        // *before* the reflector is expected to be done.
        let conf = load_from_args(&[
            "test",
            "--send-delay",
            "10",
            "--reflected-control-count",
            "11",
            "--reflected-control-interval-ns",
            "1000000",
        ])
        .unwrap();
        assert!(conf.reflected_burst_pacing_warning().is_none());
    }

    #[test]
    fn test_on_zero_ssid_defaults_to_continue_and_parses() {
        let conf = load_from_args(&["test"]).unwrap();
        assert_eq!(
            conf.on_zero_ssid,
            ZeroSsidAction::Continue,
            "continuing is RFC-permitted and the useful default for a probe"
        );

        let conf = load_from_args(&["test", "--on-zero-ssid", "stop"]).unwrap();
        assert_eq!(conf.on_zero_ssid, ZeroSsidAction::Stop);
    }

    #[test]
    fn test_on_zero_ssid_merges_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "on_zero_ssid = \"stop\"\n").unwrap();
        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect("file-configured action must load");
        assert_eq!(conf.on_zero_ssid, ZeroSsidAction::Stop);
    }

    #[test]
    fn test_location_disclose_defaults_to_all_and_parses() {
        let conf = load_from_args(&["test"]).expect("defaults must be valid");
        assert_eq!(conf.location_disclose, "all");
        assert_eq!(
            conf.location_disclosure().unwrap(),
            LocationDisclosure::all(),
            "the default policy must keep answering every field"
        );

        let conf = load_from_args(&["test", "--location-disclose", "ports,src-ip"])
            .expect("a valid field list must load");
        let policy = conf.location_disclosure().unwrap();
        assert!(policy.src_port && policy.dst_port && policy.src_ip);
        assert!(!policy.dst_ip);
    }

    #[test]
    fn test_validate_rejects_bad_location_disclose() {
        // A typo must fail at startup, not silently degrade to a default
        // policy on every packet.
        let err = load_from_args(&["test", "--location-disclose", "src-mac"])
            .expect_err("an unknown Location field must be rejected");
        assert!(
            err.to_string().contains("location-disclose"),
            "error must name the offending flag: {err}"
        );

        let err = load_from_args(&["test", "--location-disclose", "none,src-ip"])
            .expect_err("mixing a wildcard with named fields must be rejected");
        assert!(err.to_string().contains("location-disclose"), "{err}");
    }

    #[test]
    fn test_location_disclose_merges_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "location_disclose = \"none\"\n").unwrap();
        let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect("file-configured policy must load");
        assert!(
            conf.location_disclosure().unwrap().discloses_nothing(),
            "the file value must reach the parsed policy"
        );
    }

    #[test]
    fn test_validate_rejects_return_path_cc_with_return_address_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "return_path_cc = 0\nreturn_address = \"10.0.0.1\"\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("conflicting return-path options must fail");
        assert!(err.to_string().contains("return_address"));
    }

    #[test]
    fn test_validate_rejects_sr_mpls_with_srv6_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(
            &path,
            "return_sr_mpls_labels = [100]\nreturn_srv6_sids = [\"2001:db8::1\"]\n",
        )
        .unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("conflicting return-path options must fail");
        assert!(err.to_string().contains("return_sr_mpls_labels"));
    }

    #[test]
    fn test_validate_rejects_cli_return_path_cc_merged_with_file_srv6() {
        // CLI sets return_path_cc; file sets return_srv6_sids. The merge
        // leaves both present even though each side alone would be fine.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "return_srv6_sids = [\"2001:db8::1\"]\n").unwrap();
        let err = load_from_args(&[
            "test",
            "--config",
            path.to_str().unwrap(),
            "--return-path-cc",
            "0",
        ])
        .expect_err("CLI + file conflict must fail");
        assert!(err.to_string().contains("return_srv6_sids"));
    }

    #[test]
    fn test_validate_rejects_cli_hmac_key_merged_with_file_hmac_key_file() {
        // CLI sets --hmac-key; file sets hmac_key_file. Both end up in
        // the final config even though the CLI would have rejected them
        // together.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "hmac_key_file = \"/etc/stamp/key\"\n").unwrap();
        let err = load_from_args(&[
            "test",
            "--config",
            path.to_str().unwrap(),
            "--hmac-key",
            "0123456789abcdef0123456789abcdef",
        ])
        .expect_err("hmac_key + hmac_key_file must be rejected");
        assert!(err.to_string().contains("hmac_key"));
        assert!(err.to_string().contains("hmac_key_file"));
    }

    #[test]
    fn test_verbose_flag_defaults_to_zero() {
        let conf = Configuration::parse_from(["test"]);
        assert_eq!(conf.verbose, 0);
    }

    #[test]
    fn test_verbose_flag_counts() {
        let conf = Configuration::parse_from(["test", "-v"]);
        assert_eq!(conf.verbose, 1);

        let conf = Configuration::parse_from(["test", "-vv"]);
        assert_eq!(conf.verbose, 2);

        let conf = Configuration::parse_from(["test", "-vvv"]);
        assert_eq!(conf.verbose, 3);

        // Long form is repeatable too, and combines with the short form.
        let conf = Configuration::parse_from(["test", "--verbose", "--verbose"]);
        assert_eq!(conf.verbose, 2);
        let conf = Configuration::parse_from(["test", "-v", "--verbose"]);
        assert_eq!(conf.verbose, 2);
    }

    #[test]
    fn test_resolve_log_filter_default_is_info() {
        assert_eq!(resolve_log_filter(0, None), "info");
    }

    #[test]
    fn test_resolve_log_filter_single_v_is_debug() {
        assert_eq!(resolve_log_filter(1, None), "debug");
    }

    #[test]
    fn test_resolve_log_filter_double_v_and_beyond_is_trace() {
        assert_eq!(resolve_log_filter(2, None), "trace");
        assert_eq!(resolve_log_filter(5, None), "trace");
    }

    #[test]
    fn test_resolve_log_filter_rust_log_env_overrides_verbose() {
        // An explicit, non-empty RUST_LOG always wins over -v/-vv, no
        // matter how many times the flag was repeated.
        assert_eq!(resolve_log_filter(0, Some("warn")), "warn");
        assert_eq!(
            resolve_log_filter(2, Some("stamp_suite=trace,tower=warn")),
            "stamp_suite=trace,tower=warn"
        );
    }

    #[test]
    fn test_resolve_log_filter_empty_rust_log_env_falls_back_to_verbose() {
        // An empty RUST_LOG (e.g. present in the environment but set to
        // the empty string) must not be treated as "explicitly set" --
        // fall back to the -v/-vv-derived level instead.
        assert_eq!(resolve_log_filter(0, Some("")), "info");
        assert_eq!(resolve_log_filter(1, Some("")), "debug");
    }
}
