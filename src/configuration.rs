use std::{fmt, net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};
use thiserror::Error;

use crate::{
    cos_policy::{parse_destination_rule, CosAdmissionPolicy, DscpSet, EcnSet},
    tlv::LocationDisclosure,
};

use crate::session_identity::{SessionAdmission, SessionKey};

pub use crate::clock_format::ClockFormat;
pub use crate::hwtstamp::HwTsMode;
pub use crate::stats::OutputFormat;

/// A CLI or environment secret, zeroized on drop and redacted from `Debug`.
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

/// The probe interval from `--send-delay`. A plain number is milliseconds;
/// `us`, `ms` and `s` suffixes select the unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProbeInterval(std::time::Duration);

impl ProbeInterval {
    /// The longest accepted interval.
    pub const MAX: std::time::Duration = std::time::Duration::from_secs(3600);

    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(std::time::Duration::from_millis(ms))
    }

    #[must_use]
    pub const fn duration(self) -> std::time::Duration {
        self.0
    }
}

impl std::str::FromStr for ProbeInterval {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let split = text
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(text.len());
        let (number, unit) = text.split_at(split);
        let scale = match unit.trim() {
            "" | "ms" => 1e-3,
            "us" | "µs" => 1e-6,
            "s" => 1.0,
            other => return Err(format!("unknown unit {other:?}; use us, ms or s")),
        };
        let value: f64 = number
            .parse()
            .map_err(|_| format!("invalid interval {text:?}"))?;
        let seconds = value * scale;
        if !seconds.is_finite() || seconds > Self::MAX.as_secs_f64() {
            return Err(format!(
                "interval {text:?} exceeds {}s",
                Self::MAX.as_secs()
            ));
        }
        // Microsecond resolution; finer values are rounded.
        let micros = (seconds * 1e6).round() as u64;
        Ok(Self(std::time::Duration::from_micros(micros)))
    }
}

impl fmt::Display for ProbeInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let micros = self.0.as_micros();
        if micros % 1000 == 0 {
            write!(f, "{}", micros / 1000)
        } else {
            write!(f, "{micros}us")
        }
    }
}

impl serde::Serialize for ProbeInterval {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ProbeInterval {
    /// Accepts a number of milliseconds or a string with a unit.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Millis(u64),
            Text(String),
        }
        match Repr::deserialize(deserializer)? {
            Repr::Millis(ms) => format!("{ms}").parse(),
            Repr::Text(text) => text.parse(),
        }
        .map_err(serde::de::Error::custom)
    }
}

/// How probe send times are spaced.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum SendSchedule {
    /// A fixed interval (RFC 3432).
    #[default]
    Periodic,
    /// Exponentially distributed gaps with the interval as their mean
    /// (RFC 2330 §11.1.1).
    Poisson,
}

/// Operator-declared clock discipline, independent of STAMP timestamp encoding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ClockSyncSource {
    Ntp,
    Ptp,
    Gps,
    Glonass,
    LoranC,
    Bds,
    Galileo,
    /// No external synchronization source is asserted (the default).
    #[default]
    Local,
    SsuBits,
}

impl From<ClockSyncSource> for crate::tlv::SyncSource {
    fn from(source: ClockSyncSource) -> Self {
        match source {
            ClockSyncSource::Ntp => Self::Ntp,
            ClockSyncSource::Ptp => Self::Ptp,
            ClockSyncSource::Gps => Self::Gps,
            ClockSyncSource::Glonass => Self::Glonass,
            ClockSyncSource::LoranC => Self::LoranC,
            ClockSyncSource::Bds => Self::Bds,
            ClockSyncSource::Galileo => Self::Galileo,
            ClockSyncSource::Local => Self::Local,
            ClockSyncSource::SsuBits => Self::SsuBits,
        }
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum TlvHandlingMode {
    /// Copy TLVs unprocessed, as a reflector without TLV support does.
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

/// Controls sender HMAC TLV origination (RFC 8972 §4.8).
///
/// A configured key also serves reply verification and base authentication.
/// Unauthenticated senders can disable TLV origination while retaining the key.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum TlvHmacMode {
    /// Originate an HMAC TLV whenever a key is configured and TLVs are in use.
    /// The long-standing behaviour, and the default.
    #[default]
    Auto,
    /// Always originate; startup fails if no key is configured.
    On,
    /// Never originate, even with a key configured. The key is then used only
    /// for base-packet authentication and for verifying reflected TLV HMACs.
    Off,
}

impl fmt::Display for TlvHmacMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::On => write!(f, "on"),
            Self::Off => write!(f, "off"),
        }
    }
}

/// Sender policy for a zeroed reply SSID (RFC 8972 §3).
///
/// Applies only when the sender requested a non-zero `--ssid`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Serialize, serde::Deserialize,
)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize)]
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
#[derive(Parser, Debug, Clone)]
#[clap(author = "Piotr Olszewski", version, about, long_about = None)]
pub struct Configuration {
    /// Path to a TOML configuration file. Values loaded from the file are used
    /// as defaults; command-line flags and environment variables always
    /// override them.
    #[clap(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the TOML configuration's JSON Schema to stdout and exit.
    ///
    /// `stamp-suite --print-config-schema > stamp-suite-config.schema.json`
    ///
    /// Use the schema with an IDE or validator; JSON validators require converting
    /// TOML input to JSON first.
    #[clap(long, exclusive = true)]
    pub print_config_schema: bool,
    /// Session-Reflector address. Repeat the option or separate addresses with
    /// commas to measure several reflectors at once, each in its own session.
    #[clap(
        short,
        long,
        default_value = "0.0.0.0",
        value_delimiter = ',',
        help_heading = "Endpoints"
    )]
    pub remote_addr: Vec<std::net::IpAddr>,
    /// Local address to bind for
    #[clap(
        short = 'S',
        long,
        default_value = "0.0.0.0",
        help_heading = "Endpoints",
        help_heading = "Endpoints"
    )]
    pub local_addr: std::net::IpAddr,
    /// Numeric IPv6 interface zone for the local bind address (0 = default).
    #[clap(long, default_value_t = 0, help_heading = "Endpoints")]
    pub local_scope_id: u32,
    /// Numeric IPv6 interface zone for the sender destination (0 = default).
    #[clap(long, default_value_t = 0, help_heading = "Endpoints")]
    pub remote_scope_id: u32,
    /// UDP port number for outgoing packets
    #[clap(short = 'p', long, default_value_t = 862, help_heading = "Endpoints")]
    pub remote_port: u16,
    /// Local UDP port: randomized dynamic sender port (0), or 862 for a reflector.
    #[clap(
        short = 'o',
        long,
        default_value_t = 0,
        default_value_if("is_reflector", "true", "862"),
        help_heading = "Endpoints"
    )]
    pub local_port: u16,
    /// Bind the socket to this network interface or VRF device. Linux uses
    /// SO_BINDTODEVICE and macOS IP_BOUND_IF; the pnet backend captures on it.
    #[clap(long, value_name = "NAME", help_heading = "Endpoints")]
    pub interface: Option<String>,
    /// Timestamp wire encoding (NTP or PTP); does not configure clock synchronization.
    #[clap(
        short = 'K',
        long,
        default_value = "NTP",
        help_heading = "Timestamps and clock"
    )]
    pub clock_source: ClockFormat,
    /// Reflector: declared synchronization source of the system clock (Type 3 TLV).
    /// Independent of --clock-source and --clock-synchronized; no clock service is probed.
    #[clap(
        long,
        value_enum,
        default_value = "local",
        help_heading = "Timestamps and clock"
    )]
    pub clock_sync_source: ClockSyncSource,
    /// Reflector: declared synchronization source of NIC hardware clocks used for T2.
    /// Only used when a received timestamp actually comes from hardware. Ensure the
    /// PHC is aligned with the system clock; this setting does not synchronize it.
    #[clap(
        long,
        value_enum,
        default_value = "local",
        help_heading = "Timestamps and clock"
    )]
    pub hardware_clock_sync_source: ClockSyncSource,
    /// Sender: seconds the reflector clock is ahead of UTC after epoch conversion.
    /// Subtracted from T2/T3 for one-way delay; zero for this suite's UTC clocks.
    /// Set from the peer's time configuration (e.g. its TAI-UTC offset), not its Z bit.
    #[clap(
        long,
        default_value_t = 0,
        allow_hyphen_values = true,
        help_heading = "Timestamps and clock"
    )]
    pub reflector_utc_offset: i32,
    /// Interval between probes. A plain number is milliseconds; `us`, `ms`
    /// and `s` suffixes select the unit (for example `250us` or `1.5ms`).
    /// With `--send-schedule poisson` this is the mean interval.
    #[clap(
        short = 'd',
        long,
        default_value = "1000",
        value_name = "INTERVAL",
        help_heading = "Sender"
    )]
    pub send_delay: ProbeInterval,
    /// How probe send times are spaced: `periodic` (RFC 3432) or `poisson`,
    /// with exponentially distributed gaps (RFC 2330 §11.1.1).
    #[clap(long, value_enum, default_value_t = SendSchedule::Periodic, help_heading = "Sender")]
    pub send_schedule: SendSchedule,
    /// Number of probes to send; 0 sends until `--duration` ends or the
    /// sender is interrupted.
    #[clap(short = 'c', long, default_value_t = 1000, help_heading = "Sender")]
    pub count: u32,
    /// Stop sending after this many seconds, even if `--count` probes have
    /// not all been sent. Replies are still awaited for `--timeout`.
    #[clap(long, value_name = "SECONDS", help_heading = "Sender")]
    pub duration: Option<u32>,
    /// Amount of time to wait for packet until consider it lost (in seconds).
    #[clap(short = 'L', long, default_value_t = 5, help_heading = "Sender")]
    pub timeout: u8,
    /// Consecutive unanswered probes before an active session is reported failed.
    /// Uses --timeout per probe; 0 timeout disables loss-driven state changes.
    #[clap(long, default_value_t = 3, value_parser = clap::value_parser!(u16).range(1..), help_heading = "Sender")]
    pub session_loss_threshold: u16,
    /// Specify work mode - A for authenticated, O for open (unauthenticated) - default "O".
    #[clap(short = 'A', long, value_enum, default_value_t = AuthMode::Open, help_heading = "Authentication")]
    pub auth_mode: AuthMode,
    /// Print individual packet statistics (stderr for JSON/CSV output, stdout for text).
    #[clap(short = 'R', help_heading = "Sender")]
    pub print_stats: bool,
    /// Run as Session Reflector instead of Session Sender.
    #[clap(short = 'i', long, default_value_t = false, help_heading = "Endpoints")]
    pub is_reflector: bool,

    /// Error Estimate scale (0-63).
    #[clap(long, default_value_t = 0, help_heading = "Timestamps and clock")]
    pub error_scale: u8,

    /// Error Estimate multiplier (1-255). RFC 4656 §4.1.2 forbids zero.
    #[clap(long, default_value_t = 1, help_heading = "Timestamps and clock")]
    pub error_multiplier: u8,

    /// Assert the Error Estimate S bit; independent of wire format and Type 3 source.
    #[clap(long, help_heading = "Timestamps and clock")]
    pub clock_synchronized: bool,

    /// HMAC key in hex; requires at least 32 hex chars (16 bytes).
    /// 64 hex chars (32 bytes) matches the HMAC-SHA-256 output length.
    ///
    /// CLI keys are visible in process arguments; environment keys are visible to
    /// users who can read the process environment. Prefer `--hmac-key-file` in
    /// production. The stored value is zeroized on drop and redacted from `Debug`.
    #[clap(long, env = "STAMP_HMAC_KEY", help_heading = "Authentication")]
    pub hmac_key: Option<SecretString>,

    /// Path to file containing HMAC key.
    #[clap(long, conflicts_with = "hmac_key", help_heading = "Authentication")]
    pub hmac_key_file: Option<PathBuf>,

    /// Directory of per-SSID HMAC keys. File stems are hexadecimal SSIDs;
    /// `default.key` supplies the fallback. Conflicts with `--hmac-key` and
    /// `--hmac-key-file`. Restart with updated files to rotate keys.
    #[clap(long, conflicts_with_all = ["hmac_key", "hmac_key_file"], help_heading = "Authentication")]
    pub hmac_key_dir: Option<PathBuf>,

    /// Require HMAC key to be configured (error if missing in auth mode).
    /// Note: When an HMAC key is present, verification is always mandatory per RFC 8762 §4.4.
    #[clap(long, help_heading = "Authentication")]
    pub require_hmac: bool,

    /// Reject short packets instead of zero-filling (RFC 8762 Section 4.6).
    /// By default, missing bytes are zero-filled for TWAMP-Light interoperability.
    #[clap(long, help_heading = "Reflector")]
    pub strict_packets: bool,

    /// Enable stateful reflector mode per RFC 8762 Section 4.2. The reflector maintains
    /// independent sequence counters for each full session identity instead of echoing
    /// the sender's sequence number, allowing clients to detect reflector-side packet loss.
    #[clap(long, help_heading = "Reflector")]
    pub stateful_reflector: bool,

    /// Session admission: permissive learns incoming sessions; provisioned only
    /// answers exact --reflector-session identities (RFC 8972 Section 3).
    #[clap(
        long,
        value_enum,
        default_value = "permissive",
        help_heading = "Reflector"
    )]
    pub session_admission: SessionAdmission,

    /// Provision an exact session; repeat for each tuple/SSID/member. SSID 0
    /// selects a base session without an explicit SSID. IPv6 uses brackets.
    #[clap(
        long = "reflector-session",
        value_name = "SSID,SOURCE,DESTINATION[,MICRO_ID]",
        help_heading = "Reflector"
    )]
    pub reflector_sessions: Vec<String>,

    /// Session timeout in seconds for reflector runtime state. Sessions inactive for
    /// this duration may be cleaned up. Default: 300 (5 minutes). Set to 0 to disable.
    #[clap(long, default_value_t = 300, help_heading = "Reflector")]
    pub session_timeout: u64,

    /// DSCP codepoints permitted on reflector replies (RFC 8972 §4.4/§6,
    /// cos-ecn-01 §3.2): `all` (default), `none`, or values and inclusive ranges
    /// such as `0,8,10-14,46`. Rejected DSCP1 requests retain the received DSCP
    /// and report RPD=0b01. Permitted values still require socket support.
    ///
    /// Reflector-side only.
    #[clap(
        long,
        default_value = "all",
        value_name = "SPEC",
        help_heading = "Reflector"
    )]
    pub allowed_dscp: String,

    /// ECN codepoints the reflector may apply to a reply's IP header when a
    /// Class of Service TLV requests them (cos-ecn-01 §3.2).
    ///
    /// `all` (default), `none`, or a comma-separated list of 0-3. A refused EC1
    /// forces the reply's ECN bits to Not-ECT and the echoed TLV reports
    /// RPE=0b10.
    ///
    /// Reflector-side only.
    #[clap(
        long,
        default_value = "all",
        value_name = "SPEC",
        help_heading = "Reflector"
    )]
    pub allowed_ecn: String,

    /// Destination DSCP policy overriding `--allowed-dscp` (cos-ecn-01 §3.2).
    /// Repeatable `PREFIX/LEN=SPEC`, e.g. `--allowed-dscp-for 192.0.2.0/24=0,46`.
    /// The longest matching prefix replaces the global set, regardless of order.
    ///
    /// Reflector-side only.
    #[clap(long, value_name = "PREFIX/LEN=SPEC", help_heading = "Reflector")]
    pub allowed_dscp_for: Vec<String>,

    /// Suppress duplicated packets without a handled Type-12 request.
    ///
    /// Non-monotonic Type-12 requests always receive a single U-flagged reply
    /// after validation (RFC 10052 §5), even with this
    /// flag set. Detection and counting are always active. Off by default:
    /// restarting a sender can repeat sequence numbers without an attack.
    ///
    /// Reflector-side only.
    #[clap(long, help_heading = "Reflector")]
    pub drop_replayed: bool,

    /// Location TLV fields the reflector may report (RFC 8972 §4.2.2).
    /// Comma-separated: `all` (default), `none`, or `src-port`, `dst-port`,
    /// `ports`, `src-ip`, `dst-ip`, `ips`, `src-mac`. Withheld fields are
    /// zeroed without changing the TLV length or structure.
    ///
    /// Reflector-side only; ignored by the sender.
    #[clap(
        long,
        default_value = "all",
        value_name = "FIELDS",
        help_heading = "Reflector"
    )]
    pub location_disclose: String,

    /// Reflector TLV handling (RFC 8972).
    /// - echo: process supported TLVs and set U/M/I flags
    /// - ignore: copy everything after the base packet unprocessed, like a
    ///   reflector without TLV support
    #[clap(long, value_enum, default_value_t = TlvHandlingMode::Echo, help_heading = "Reflector")]
    pub tlv_mode: TlvHandlingMode,

    /// Verify HMAC TLV in incoming packets (RFC 8972). Requires HMAC key.
    #[clap(long, help_heading = "Authentication")]
    pub verify_tlv_hmac: bool,

    /// Session-Sender Identifier to include in sender packets (RFC 8972 §3).
    /// Encoded in the two octets of the base STAMP header immediately after
    /// Error Estimate (bytes 14-15 unauth / 26-27 auth).
    #[clap(long, help_heading = "Sender")]
    pub ssid: Option<u16>,

    /// What to do when a reflected packet returns a zeroed SSID field
    /// (RFC 8972 §3): `continue` (default) keeps measuring and logs the
    /// condition once, `stop` ends the session on the first such reply.
    ///
    /// Sender-side only, and only meaningful together with a non-zero
    /// `--ssid` — without one there is nothing for the reflector to echo.
    #[clap(long, default_value_t = ZeroSsidAction::Continue, value_name = "ACTION", help_heading = "Sender")]
    pub on_zero_ssid: ZeroSsidAction,

    /// Enable Prometheus metrics endpoint (requires "metrics" feature).
    #[clap(long, help_heading = "Services")]
    pub metrics: bool,

    /// Address to bind the metrics HTTP server.
    #[clap(long, default_value = "127.0.0.1:9090", help_heading = "Services")]
    pub metrics_addr: SocketAddr,

    /// Enable Class of Service TLV for DSCP/ECN measurement (RFC 8972 §4.4).
    /// When enabled, the sender includes a CoS TLV with the requested DSCP/ECN values,
    /// and the reflector reports the received DSCP/ECN values.
    #[clap(long, help_heading = "Class of Service and ECN")]
    pub cos: bool,

    /// DSCP value to request for reflected packets (0-63).
    /// Only used when --cos is enabled. Common values:
    /// 0=Best Effort, 10=AF11, 18=AF21, 26=AF31, 34=AF41, 46=EF
    #[clap(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..64), help_heading = "Class of Service and ECN")]
    pub dscp: u8,

    /// ECN value to request for reflected packets (0-3).
    /// Only used when --cos is enabled.
    /// 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE (Congestion Experienced)
    #[clap(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..4), help_heading = "Class of Service and ECN")]
    pub ecn: u8,

    /// Multiply the send interval by this factor on each CE-marked reply,
    /// capped at `--ecn-max-delay` (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
    /// Must exceed 1.0. Active with `--cos` and `--ecn` ECT0 (2) or ECT1 (1).
    /// See `--ecn-recovery-step` for recovery pacing.
    #[clap(long, default_value_t = 2.0, help_heading = "Class of Service and ECN")]
    pub ecn_backoff_factor: f64,

    /// Upper bound (milliseconds) on the AIMD-controlled send interval —
    /// caps how far repeated CE observations can back the sender off
    /// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4). Must be >= `--send-delay`
    /// when the controller is active.
    #[clap(
        long,
        default_value_t = 30_000,
        help_heading = "Class of Service and ECN"
    )]
    pub ecn_max_delay: u32,

    /// Additive recovery step (milliseconds): after each reply that was
    /// NOT CE-marked, the AIMD-controlled send interval shrinks by this
    /// amount, down to (never below) `--send-delay`
    /// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
    #[clap(long, default_value_t = 50, help_heading = "Class of Service and ECN")]
    pub ecn_recovery_step: u32,

    /// Outgoing TTL / Hop Limit. Draft ext-hdr-15 requires 255 (the default).
    #[clap(long, value_parser = clap::value_parser!(u8).range(255..=255), help_heading = "Sender")]
    pub ttl: Option<u8>,

    /// Diagnostic: append a deliberately malformed TLV to every sent packet to
    /// test a reflector's RFC 8972 §4.2 handling. `bad-flags` sets reserved
    /// flag bits; `bad-length` declares a TLV length that overruns the packet.
    /// Not for normal measurements.
    #[clap(long, value_enum, help_heading = "Sender")]
    pub malformed: Option<MalformedMode>,

    /// Send an Access Report TLV with this Access ID (RFC 8972 §4.6):
    /// 1 = 3GPP Network, 2 = Non-3GPP Network. A reflector discards other IDs.
    #[clap(long, value_parser = clap::value_parser!(u8).range(1..=2), help_heading = "Sender TLVs")]
    pub access_report: Option<u8>,

    /// Return code for Access Report TLV (default: 1 = available).
    /// Only used when --access-report is enabled.
    #[clap(long, default_value_t = 1, help_heading = "Sender TLVs")]
    pub access_return_code: u8,

    /// Access Report retransmission timeout in seconds (RFC 8972 §4.6;
    /// default 3). Armed after sending the TLV and disarmed on its reflected
    /// echo. Expiry triggers retransmission. Requires `--access-report`.
    #[clap(long, default_value_t = crate::sender::DEFAULT_ACCESS_REPORT_TIMEOUT.as_secs() as u32, value_parser = clap::value_parser!(u32).range(1..=3600), help_heading = "Sender TLVs")]
    pub access_report_timeout: u32,

    /// Maximum Access Report retransmissions (RFC 8972 §4.6; default 4).
    /// Zero aborts on the first missed acknowledgment without retransmitting.
    /// Requires `--access-report`.
    #[clap(long, default_value_t = crate::sender::DEFAULT_ACCESS_REPORT_RETRIES, value_parser = clap::value_parser!(u32).range(0..=255), help_heading = "Sender TLVs")]
    pub access_report_retries: u32,

    /// Enable Timestamp Information TLV (RFC 8972 §4.3).
    /// The sender requests the reflector's synchronization sources and timestamp
    /// methods using zeroed information fields; the reflector fills in its values.
    #[clap(long, help_heading = "Sender TLVs")]
    pub timestamp_info: bool,

    /// Enable Direct Measurement TLV (RFC 8972 §4.5).
    /// The sender includes its transmit count; the reflector fills
    /// receive and transmit counters.
    #[clap(long, help_heading = "Sender TLVs")]
    pub direct_measurement: bool,

    /// Enable Location TLV (RFC 8972 §4.2).
    /// The reflector fills in the observed source/destination addresses and ports.
    #[clap(long, help_heading = "Sender TLVs")]
    pub location: bool,

    /// Enable Follow-Up Telemetry TLV (RFC 8972 §4.7).
    /// The reflector fills in the previous reflection's sequence number
    /// and timestamp.
    #[clap(long, help_heading = "Sender TLVs")]
    pub follow_up_telemetry: bool,

    /// Enable SNMP AgentX sub-agent (requires "snmp" feature).
    #[clap(long, help_heading = "Services")]
    pub snmp: bool,

    /// AgentX master agent socket path.
    #[clap(long, default_value = "/var/agentx/master", help_heading = "Services")]
    pub snmp_socket: String,

    /// Enable the runtime control-plane REST API (reflector only;
    /// requires the "control" build feature). Design: doc/control-plane.md.
    #[clap(long, help_heading = "Services")]
    pub control: bool,

    /// Address to bind the control-plane HTTP server. Keep this on
    /// loopback unless network-level access control is in place.
    #[clap(
        long,
        default_value = "127.0.0.1:9091",
        value_name = "ADDR",
        help_heading = "Services"
    )]
    pub control_addr: SocketAddr,

    /// Path to a file containing a static bearer token. When set, every
    /// control-plane request must carry `Authorization: Bearer <token>`.
    #[clap(long, value_name = "PATH", help_heading = "Services")]
    pub control_token_file: Option<PathBuf>,

    /// PEM certificate chain for the control API. Enables HTTPS and requires
    /// `--control-tls-key` and a bearer token for session/key management and shutdown.
    #[clap(
        long,
        value_name = "PATH",
        requires = "control_tls_key",
        help_heading = "Services"
    )]
    pub control_tls_cert: Option<PathBuf>,

    /// PEM private key matching `--control-tls-cert`.
    #[clap(
        long,
        value_name = "PATH",
        requires = "control_tls_cert",
        help_heading = "Services"
    )]
    pub control_tls_key: Option<PathBuf>,

    /// Statistics format on stdout (text, JSON lines, or CSV with one header per run).
    #[clap(long, value_enum, default_value_t = OutputFormat::Text, help_heading = "Output")]
    pub output_format: OutputFormat,

    /// Diagnostic log format on stderr — `text` (default) for journalctl-friendly
    /// human-readable lines, `json` for structured one-line-per-event
    /// output suitable for log aggregators. `RUST_LOG` continues to
    /// control verbosity in both modes.
    #[clap(long, value_enum, default_value_t = LogFormat::Text, help_heading = "Output")]
    pub log_format: LogFormat,

    /// Increase log verbosity: `-v` for debug, `-vv` or more for trace.
    /// Defaults to info. A non-empty `RUST_LOG` overrides this flag.
    #[clap(short = 'v', long, action = clap::ArgAction::Count, help_heading = "Output")]
    pub verbose: u8,

    /// Kernel/hardware timestamp handling (requires the "hwtstamp" build
    /// feature for the read paths). `auto` (default): kernel software
    /// timestamps — precise T2/T4 and error-queue TX correction on Linux,
    /// SO_TIMESTAMP receive timestamps on macOS; no privileges, no NIC
    /// changes. `on`: additionally attempt NIC hardware timestamping
    /// (SIOCSHWTSTAMP + raw-hardware tier; needs CAP_NET_ADMIN and a
    /// synchronized PHC), warning + software fallback when unavailable.
    /// `off`: userspace timestamps only.
    #[clap(long, value_enum, default_value_t = HwTsMode::Auto, help_heading = "Timestamps and clock")]
    pub hwtstamp: HwTsMode,

    /// Periodic reporting interval in seconds (0 = disabled, sender only).
    #[clap(long, default_value_t = 0, help_heading = "Sender")]
    pub report_interval: u32,

    /// Destination Node Address for SR networks (RFC 9503 §3). Requires --ssid.
    #[clap(long, value_name = "IP", help_heading = "Return Path")]
    pub dest_node_addr: Option<std::net::IpAddr>,

    /// Return Path control code (RFC 9503 §4): 0=no reply, 1=same link reply.
    #[clap(
        long,
        value_parser = clap::value_parser!(u32),
        conflicts_with_all = ["return_address", "return_sr_mpls_labels", "return_srv6_sids"],
        help_heading = "Return Path",
    )]
    pub return_path_cc: Option<u32>,

    /// Return Path alternate reply address (RFC 9503 §4).
    #[clap(
        long,
        value_name = "IP",
        conflicts_with = "return_path_cc",
        help_heading = "Return Path"
    )]
    pub return_address: Option<std::net::IpAddr>,

    /// Return Path SR-MPLS label stack (RFC 9503 §4). Comma-separated 20-bit labels.
    #[clap(
        long,
        value_name = "LABELS",
        value_delimiter = ',',
        conflicts_with_all = ["return_path_cc", "return_srv6_sids"],
        help_heading = "Return Path",
    )]
    pub return_sr_mpls_labels: Option<Vec<u32>>,

    /// Return Path SRv6 segment list (RFC 9503 §4). Comma-separated IPv6 SIDs.
    #[clap(
        long,
        value_name = "SIDS",
        value_delimiter = ',',
        conflicts_with_all = ["return_path_cc", "return_sr_mpls_labels"],
        help_heading = "Return Path",
    )]
    pub return_srv6_sids: Option<Vec<std::net::Ipv6Addr>>,

    /// Reflector: attempt best-effort SRv6 return-path forwarding per RFC 9503
    /// §5 and RFC 8754. When a received Return Path TLV carries an SRv6 Segment
    /// List and the kernel supports it, the reflector inserts a Segment Routing
    /// Header on its IPv6 reply. Disabled by default; when off (or on a
    /// non-Linux/IPv4/unsupported path) the reflector replies normally and sets
    /// the Return Path U-flag. Linux only.
    #[clap(long, help_heading = "Return Path")]
    pub srv6_return_forwarding: bool,

    /// Reflector: honour a Return Path TLV "Return Address" sub-TLV (RFC 9503
    /// §5) by sending the reply to the requested address instead of the packet
    /// source. Disabled by default: an open reflector that honours arbitrary
    /// return addresses can be abused as a traffic-redirection / reflection
    /// gadget aimed at third parties. When off, a Return Address sub-TLV is
    /// echoed with the U-flag set and the reply goes to the packet source.
    /// Only enable inside a controlled (and preferably HMAC-authenticated)
    /// measurement domain.
    #[clap(long, help_heading = "Return Path")]
    pub return_path_allow_alternate: bool,

    /// Sender Micro-session ID for RFC 9534 TLV validation; does not select a physical link.
    /// When set, includes a Micro-session ID TLV in test packets.
    /// Accepts decimal (e.g. `255`) or `0x`-prefixed hex (e.g. `0xff`).
    #[clap(long, value_parser = parse_u16_nonzero_dec_or_hex, help_heading = "Sender TLVs")]
    pub micro_session_id: Option<u16>,

    /// Configured reflector ID for RFC 9534 TLV validation; no physical-link association.
    /// When set, the reflector fills this ID into reflected Micro-session ID TLVs.
    /// Accepts decimal (e.g. `171`) or `0x`-prefixed hex (e.g. `0xab`).
    #[clap(long, value_parser = parse_u16_nonzero_dec_or_hex, help_heading = "Sender TLVs")]
    pub reflector_member_link_id: Option<u16>,

    /// Maximum reflected packets per second per source IP address (0 = unlimited).
    /// A token bucket; `--reflector-rate-burst` sets its capacity. Each
    /// Type-12 copy counts as one packet.
    #[clap(long, default_value_t = 0, help_heading = "Reflector")]
    pub max_pps: u32,

    /// Token-bucket capacity per source IP, in packets. 0 uses the
    /// `--max-pps` value (one second of traffic). Ignored when `--max-pps` is 0.
    #[clap(long, default_value_t = 0, help_heading = "Reflector")]
    pub reflector_rate_burst: u32,

    /// Maximum pending reflector requests across processing, handoff and bursts.
    /// Full queues drop new requests; slots remain reserved until all copies finish.
    #[clap(long, default_value_t = 1024, value_parser = clap::value_parser!(u32).range(1..), help_heading = "Reflector")]
    pub reflector_queue_capacity: u32,

    /// Stop accepting packets on shutdown, then finish queued replies for at most
    /// this many milliseconds. Zero cancels immediately (the default).
    #[clap(long, default_value_t = 0, value_parser = clap::value_parser!(u32).range(0..=60_000), help_heading = "Reflector")]
    pub reflector_shutdown_grace_ms: u32,

    /// Maximum number of tracked session identities (0 = unlimited).
    /// Sessions use both UDP endpoints, SSID, and optional sender micro ID.
    /// At the cap, new sessions are rejected in both sequencing modes;
    /// existing sessions continue with their counters and sequence state.
    /// Periodic idle expiry or manual expiry frees slots. Lowering the cap
    /// never evicts active entries. Defaults to 65536.
    #[clap(long, default_value_t = 65536, help_heading = "Reflector")]
    pub max_sessions: u32,

    /// Enable the BER TLVs (draft-gandhi-ippm-stamp-ber-07):
    /// Bit Pattern in Padding (Type 240), Bit Error Count (Type 241), and
    /// Max Bit Error Burst Size (Type 242). Sender-side only; the reflector
    /// computes the counts against the incoming Extra Padding.
    #[clap(long, help_heading = "Bit Error Rate")]
    pub ber: bool,

    /// Append an Extra Padding TLV with this many value octets (RFC 8972 §4.1).
    /// Uses pseudorandom bytes as §4.2 recommends, for MTU or fragmentation tests.
    /// With `--ber`, BER measurement supplies the padding and its known pattern.
    #[clap(
        long,
        value_name = "BYTES",
        conflicts_with = "ber",
        help_heading = "Sender TLVs"
    )]
    pub extra_padding: Option<usize>,

    /// Omit Max Bit Error Burst Size TLV (Type 242) from `--ber` packets.
    /// This experimental codepoint (RFC 8972 §5.1) conflicts with another
    /// implementation's incompatible Heartbeat TLV. Other BER TLVs are unchanged.
    /// Ignored unless `--ber` is set.
    #[clap(long, help_heading = "Bit Error Rate")]
    pub ber_omit_burst: bool,

    /// Whether the sender originates an HMAC TLV (RFC 8972 §4.8):
    /// `auto` (default, originate when a key is configured), `on` (always;
    /// requires a key), `off` (never, even with a key).
    #[clap(long, default_value_t = TlvHmacMode::Auto, value_name = "MODE", help_heading = "Authentication")]
    pub tlv_hmac: TlvHmacMode,

    /// Bit pattern used to fill the Extra Padding TLV when `--ber` is set.
    /// Hex string (e.g. "ff00" or "aa55"). Defaults to the draft's recommended
    /// pattern (0xFF00). Ignored unless `--ber` is set.
    #[clap(long, value_name = "HEX", help_heading = "Bit Error Rate")]
    pub ber_pattern: Option<String>,

    /// Padding length in bytes for the Extra Padding TLV that accompanies the
    /// BER TLVs. Ignored unless `--ber` is set.
    #[clap(long, default_value_t = 64, help_heading = "Bit Error Rate")]
    pub ber_padding_size: usize,

    /// BER computation interval in multiples of --send-delay (must be positive).
    #[clap(long, default_value_t = 10, help_heading = "Bit Error Rate")]
    pub ber_interval: u32,

    /// Alarm threshold for bit errors per million padding bits, in either direction.
    #[clap(long, help_heading = "Bit Error Rate")]
    pub ber_bit_threshold: Option<f64>,

    /// Alarm threshold for packets with errors per million measured packets.
    #[clap(long, help_heading = "Bit Error Rate")]
    pub ber_packet_threshold: Option<f64>,

    /// Request asymmetrical reply traffic (RFC 10052 §3).
    /// The sender includes a Reflected Test Packet Control TLV (Type 12) asking
    /// the reflector to emit N copies of the reply. Setting this to a value
    /// greater than 1 activates the TLV.
    #[clap(
        long,
        default_value_t = 1,
        value_parser = clap::value_parser!(u16),
        help_heading = "Reflected Test Packet Control",
    )]
    pub reflected_control_count: u16,

    /// Requested reply packet length for the Reflected Test Packet Control TLV.
    /// 0 means "don't pad" (the reflector will set C flag anyway if it cannot
    /// honour). Ignored unless `--reflected-control-count` > 1.
    #[clap(
        long,
        default_value_t = 0,
        help_heading = "Reflected Test Packet Control"
    )]
    pub reflected_control_length: u16,

    /// Inter-packet gap in nanoseconds for the Reflected Test Packet Control TLV.
    /// Ignored unless `--reflected-control-count` > 1.
    #[clap(
        long,
        default_value_t = 1_000_000,
        help_heading = "Reflected Test Packet Control"
    )]
    pub reflected_control_interval_ns: u32,

    /// Append the IPv6 Extension Header Control sub-TLV
    /// (draft-ietf-ippm-stamp-ext-hdr-15 §5.1) to the Reflected Test Packet
    /// Control TLV. Under -11 this sub-TLV asks the reflector to add matching
    /// IPv6 extension headers to its own reply packets; a reflector that cannot
    /// do so returns the sub-TLV with the C flag set in its Sub-TLV Flags.
    /// Implies emitting the Reflected Control TLV even when
    /// `--reflected-control-count` is 1.
    #[clap(long, help_heading = "Reflected Test Packet Control")]
    pub reflected_control_no_ext_hdr: bool,

    /// Maximum replies per Reflected Test Packet Control request
    /// (RFC 10052 §3). Requests above the cap receive
    /// one C-flagged reply.
    ///
    /// Default 0 disables Type 12 (RFC 10052 §5): the TLV is treated as
    /// unsupported and gets U in a single normal reply.
    /// Set a positive cap (e.g. 16) to enable it; pair with `--max-pps` to limit
    /// amplification.
    #[clap(
        long,
        default_value_t = 0,
        help_heading = "Reflected Test Packet Control"
    )]
    pub reflected_control_max_count: u16,

    /// Reflector-side amplification cap for
    /// RFC 10052 §3: maximum reply packet size (in
    /// bytes) the reflector will pad up to when honouring a Reflected Test
    /// Packet Control TLV `length` request. When the requested length exceeds
    /// the effective cap, a single reflected packet padded to it is sent with
    /// the C flag set on the echoed TLV.
    ///
    /// Linux checks the actual reply route before each send, including wildcard
    /// binds and alternate destinations. IP/UDP and SRH overhead reduce the
    /// payload budget (1472 bytes on a plain 1500-byte IPv4 link, 1452 on IPv6).
    /// Route/interface notifications and a short cache expiry track changes.
    /// Replies are dropped if the MTU cannot be determined or mandatory fields
    /// cannot fit. Non-Linux route MTU lookup is unavailable. Runtime cap updates
    /// change this administrative limit; they cannot bypass send-time MTU checks.
    #[clap(
        long,
        default_value_t = 1500,
        help_heading = "Reflected Test Packet Control"
    )]
    pub reflected_control_max_size: u16,

    /// Reflector-side amplification cap (the per-request *rate* limit of
    /// RFC 10052 §3): minimum inter-packet
    /// interval in nanoseconds. A multi-packet request with a shorter
    /// interval gets a single reflected packet with the C flag set on the
    /// echoed TLV. Default 1000 (1 µs).
    #[clap(
        long,
        default_value_t = 1_000,
        help_heading = "Reflected Test Packet Control"
    )]
    pub reflected_control_min_interval_ns: u32,

    /// Type 12 data-rate limit per request, in bytes per second (RFC 10052 §3):
    /// reply size × 10⁹ / interval. A request above it gets one C-flagged reply.
    #[clap(long, default_value_t = crate::receiver::REFLECTED_CONTROL_MAX_RATE,
           value_parser = clap::value_parser!(u64).range(1..))]
    pub reflected_control_max_rate: u64,

    /// Type 12 data-volume limit per request, in bytes (RFC 10052 §3):
    /// reply size × count. A request above it gets one C-flagged reply.
    #[clap(long, default_value_t = crate::receiver::REFLECTED_CONTROL_MAX_VOLUME,
           value_parser = clap::value_parser!(u32).range(1..))]
    pub reflected_control_max_volume: u32,

    /// Request the received IP fixed header in Type 247 (draft ext-hdr-15 §§6.2, 6.1).
    /// The sender originates one IP header and permits one request. The optional hex
    /// selector is at most four bytes, zero-padded to the four-octet Requested field.
    /// Nix reflectors return C when raw headers are unavailable. Header requests
    /// require a known Linux egress route MTU.
    #[clap(
        long,
        value_name = "[SELECTORHEX]",
        num_args = 0..=1,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        help_heading = "Header reflection",
        help_heading = "Reflected Test Packet Control",
        help_heading = "Reflected Test Packet Control",
    )]
    pub reflected_fixed_hdr: Vec<String>,

    /// Select attached IPv6 headers for Type 246 reflection (draft ext-hdr-15 §§4.2, 4.1).
    /// Repeatable `LEN[:SELECTORHEX]` values replace the automatic --attach-ext-hdr
    /// requests. LEN is a multiple of eight (8..2048); the selector is at most eight
    /// bytes, zero-padded to the eight-octet Requested field. Requests must match
    /// attached headers in wire order. Ambiguous subsets require a selector.
    /// Nix reflectors return C when raw headers are unavailable.
    #[clap(
        long,
        value_name = "[LEN[:SELECTORHEX]]",
        num_args = 0..=1,
        default_missing_value = "",
        action = clap::ArgAction::Append,
        help_heading = "Header reflection",
    )]
    pub reflected_ipv6_ext_hdr: Vec<String>,

    /// Attach an IPv6 Hop-by-Hop (hbh) or Destination Options (dest) header and
    /// request its reflection (draft ext-hdr-15 §4.2). Linux/IPv6 only. At most one
    /// of each kind, in hbh then dest order. Optional HEX supplies the entire header
    /// whose size must match Hdr Ext Len; byte 0 (Next Header) is kernel-assigned.
    /// Default: an eight-byte PadN header. Attachment failure aborts startup.
    /// Explicit --reflected-ipv6-ext-hdr requests replace automatic requests.
    #[clap(long, value_name = "KIND[:HEX]", action = clap::ArgAction::Append, help_heading = "Header reflection")]
    pub attach_ext_hdr: Vec<String>,

    /// Type 246 eight-octet Requested selector (draft ext-hdr-15 §4.1), e.g.
    /// 1100010400000000. The header's Next Header byte comes first; up to eight
    /// hex-decoded bytes are zero-padded. Requires one --reflected-ipv6-ext-hdr
    /// and a matching attached header. At least one byte must be nonzero.
    #[clap(long, value_name = "HEX", help_heading = "Header reflection")]
    pub reflected_ipv6_ext_hdr_selector: Option<String>,

    /// Type 247 four-octet Requested selector (draft ext-hdr-15 §6.1). Up to four
    /// hex-decoded bytes, zero-padded; at least one must be nonzero. Requires one
    /// --reflected-fixed-hdr without an inline selector.
    #[clap(long, value_name = "HEX", help_heading = "Header reflection")]
    pub reflected_fixed_hdr_selector: Option<String>,
}

impl Configuration {
    /// Returns a warning if `--send-delay` would overlap reflected bursts
    /// (RFC 10052 §5), otherwise `None`.
    ///
    /// A burst lasts `(count - 1) * interval_ns`. Overlap is advisory and does
    /// not prevent startup.
    #[must_use]
    pub fn reflected_burst_pacing_warning(&self) -> Option<String> {
        if self.reflected_control_count <= 1 {
            return None;
        }
        let burst_ns = u64::from(self.reflected_control_count - 1)
            * u64::from(self.reflected_control_interval_ns);
        let send_delay_ns =
            u64::try_from(self.send_delay.duration().as_nanos()).unwrap_or(u64::MAX);
        if send_delay_ns >= burst_ns {
            return None;
        }
        Some(format!(
            "--send-delay {:?} is shorter than the {:.3} ms the reflected burst \
             is expected to take (--reflected-control-count {} x \
             --reflected-control-interval-ns {}); the next test packet will be \
             sent while the reflector is still replying to the previous one \
             (RFC 10052 §5 SHOULD NOT). Raise \
             --send-delay to at least {} ms, or lower the count/interval.",
            self.send_delay.duration(),
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

    /// The configured HMAC key sources.
    #[must_use]
    pub fn key_source(&self) -> crate::crypto::KeySource<'_> {
        crate::crypto::KeySource {
            hex: self.hmac_key.as_ref().map(SecretString::as_str),
            file: self.hmac_key_file.as_deref(),
            dir: self.hmac_key_dir.as_deref(),
        }
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

    pub fn provisioned_sessions(
        &self,
    ) -> Result<std::collections::HashSet<SessionKey>, ConfigurationError> {
        let invalid = |msg: String| ConfigurationError::InvalidConfiguration(msg);
        if (!self.reflector_sessions.is_empty()
            || self.session_admission == SessionAdmission::Provisioned)
            && !self.is_reflector
        {
            return Err(invalid(
                "session admission options require --is-reflector".into(),
            ));
        }
        if !self.reflector_sessions.is_empty()
            && self.session_admission != SessionAdmission::Provisioned
        {
            return Err(invalid(
                "--reflector-session requires --session-admission provisioned".into(),
            ));
        }
        let mut keys = std::collections::HashSet::new();
        for spec in &self.reflector_sessions {
            let key: SessionKey = spec.parse().map_err(invalid)?;
            if key.local.is_ipv4() != self.local_addr.is_ipv4()
                || (!self.local_addr.is_unspecified() && key.local.ip() != self.local_addr)
                || key.local.port() != self.local_port
            {
                return Err(invalid(format!(
                    "provisioned destination {} does not match reflector bind address/port",
                    key.local
                )));
            }
            if !keys.insert(key) {
                return Err(invalid(format!("duplicate provisioned session: {key}")));
            }
        }
        Ok(keys)
    }

    pub fn local_socket_addr(&self) -> std::net::SocketAddr {
        Self::socket_addr(self.local_addr, self.local_port, self.local_scope_id)
    }
    pub fn remote_socket_addr(&self) -> std::net::SocketAddr {
        Self::socket_addr(self.remote_ip(), self.remote_port, self.remote_scope_id)
    }

    /// The first (for a single-target run, the only) reflector address.
    #[must_use]
    pub fn remote_ip(&self) -> std::net::IpAddr {
        self.remote_addr
            .first()
            .copied()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
    }

    /// One configuration per `--remote-addr`, each naming a single target.
    #[must_use]
    pub fn per_target(&self) -> Vec<Configuration> {
        self.remote_addr
            .iter()
            .map(|addr| Configuration {
                remote_addr: vec![*addr],
                ..self.clone()
            })
            .collect()
    }
    fn socket_addr(ip: std::net::IpAddr, port: u16, scope: u32) -> std::net::SocketAddr {
        match ip {
            std::net::IpAddr::V4(_) => std::net::SocketAddr::new(ip, port),
            std::net::IpAddr::V6(ip) => std::net::SocketAddrV6::new(ip, port, 0, scope).into(),
        }
    }

    /// Rejects flags for features this binary was built without.
    fn validate_features(&self) -> Result<(), ConfigurationError> {
        let missing = |flag: &str, feature: &str| {
            Err(ConfigurationError::InvalidConfiguration(format!(
                "{flag} requires a build with the \"{feature}\" feature"
            )))
        };
        if self.metrics && !cfg!(feature = "metrics") {
            return missing("--metrics", "metrics");
        }
        if self.control && !cfg!(feature = "control") {
            return missing("--control", "control");
        }
        if self.snmp && !cfg!(unix) {
            return Err(ConfigurationError::InvalidConfiguration(
                "--snmp requires a Unix platform (AgentX uses Unix domain sockets)".into(),
            ));
        }
        if self.snmp && !cfg!(feature = "snmp") {
            return missing("--snmp", "snmp");
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigurationError> {
        self.validate_features()?;
        self.validate_sender_run()?;
        self.validate_addresses()?;
        self.validate_reflector_policies()?;
        self.validate_keys()?;
        self.validate_padding()?;
        self.validate_control()?;
        self.validate_error_estimate()?;
        self.validate_return_path()?;
        self.validate_cos()?;
        self.validate_access_report()?;
        self.validate_micro_session()?;
        // draft-ietf-ippm-stamp-ext-hdr-15 §§4.2/6.2/4.1/6.1 header-reflection
        // request flags (repeatable) plus the §3.1 real-header attachment flag.
        self.validate_ext_hdr_flags()
    }

    /// Sender-only run parameters.
    fn validate_sender_run(&self) -> Result<(), ConfigurationError> {
        if self.duration == Some(0) {
            return Err(ConfigurationError::InvalidConfiguration(
                "--duration must be at least 1 second".into(),
            ));
        }
        if self.send_delay.duration() > ProbeInterval::MAX {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "send_delay exceeds {} seconds",
                ProbeInterval::MAX.as_secs()
            )));
        }

        if self.session_loss_threshold == 0 {
            return Err(ConfigurationError::InvalidConfiguration(
                "session_loss_threshold must be positive".into(),
            ));
        }
        if !self.is_reflector && self.local_port != 0 && self.local_port == self.remote_port {
            return Err(ConfigurationError::InvalidConfiguration(
                "sender local and remote ports must differ to distinguish reverse-direction probes"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Address scope IDs, interface binding and the probe TTL.
    fn validate_addresses(&self) -> Result<(), ConfigurationError> {
        if let Some(name) = self.interface.as_deref() {
            if !cfg!(any(
                target_os = "linux",
                target_os = "android",
                target_os = "macos"
            )) {
                return Err(ConfigurationError::InvalidConfiguration(
                    "--interface is supported on Linux and macOS".into(),
                ));
            }
            // IFNAMSIZ is 16 bytes including the terminating NUL.
            if name.is_empty() || name.len() > 15 || name.contains('\0') {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "invalid interface name {name:?}"
                )));
            }
        }
        if self.remote_addr.is_empty() {
            return Err(ConfigurationError::InvalidConfiguration(
                "remote_addr must name at least one address".into(),
            ));
        }
        if !self.is_reflector && self.remote_addr.len() > 1 {
            let mut seen = std::collections::HashSet::new();
            if let Some(dup) = self.remote_addr.iter().find(|a| !seen.insert(**a)) {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "remote_addr {dup} is listed twice"
                )));
            }
            if self.local_port != 0 {
                return Err(ConfigurationError::InvalidConfiguration(
                    "several remote addresses need --local-port 0, so each \
                     session gets its own port"
                        .into(),
                ));
            }
        }
        let remotes = self.remote_addr.iter().filter(|_| !self.is_reflector);
        let addresses = std::iter::once(("local", self.local_addr, self.local_scope_id))
            .chain(remotes.map(|addr| ("remote", *addr, self.remote_scope_id)));
        for (name, addr, scope) in addresses {
            if addr.is_ipv4() && scope != 0 {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "{name}_scope_id requires an IPv6 address"
                )));
            }
            if matches!(addr, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local()) && scope == 0
            {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "link-local {name}_addr requires a nonzero {name}_scope_id"
                )));
            }
        }

        if self.ttl.is_some_and(|ttl| ttl != 255) {
            return Err(ConfigurationError::InvalidConfiguration(
                "ttl must be 255 for draft ext-hdr-15".to_string(),
            ));
        }
        Ok(())
    }

    /// Reflector queue, shutdown and admission policies. Policy lists are
    /// parsed here so a typo fails at startup instead of falling back to a
    /// default on every packet.
    fn validate_reflector_policies(&self) -> Result<(), ConfigurationError> {
        if self.reflector_queue_capacity == 0 {
            return Err(ConfigurationError::InvalidConfiguration(
                "reflector_queue_capacity must be greater than zero".into(),
            ));
        }
        if self.reflector_shutdown_grace_ms > 60_000 {
            return Err(ConfigurationError::InvalidConfiguration(
                "reflector_shutdown_grace_ms must not exceed 60000".into(),
            ));
        }
        self.provisioned_sessions()?;
        // Surface a bad Location disclosure list at startup rather than
        // silently falling back to a default policy per packet.
        self.location_disclosure()?;

        // Same for the CoS admission policy: a typo must not degrade silently
        // into "permit everything" on every packet.
        self.cos_admission_policy()?;
        Ok(())
    }

    /// HMAC key sources and the options that depend on them. Conflicts are
    /// checked again here because config-file values bypass clap.
    fn validate_keys(&self) -> Result<(), ConfigurationError> {
        // `--tlv-hmac on` promises an HMAC TLV on every packet, which is
        // impossible without a key. Fail at startup rather than silently
        // sending unauthenticated packets.
        if self.tlv_hmac == TlvHmacMode::On && !self.key_source().is_configured() {
            return Err(ConfigurationError::InvalidConfiguration(
                "tlv_hmac = on requires an HMAC key (--hmac-key, --hmac-key-file \
                 or --hmac-key-dir)"
                    .to_string(),
            ));
        }

        // RFC 8972 §4.8: in authenticated mode the sender's TLV-bearing
        // packets always carry an HMAC TLV — the auth send path cannot honor
        // `--tlv-hmac off`, and silently originating one anyway would ignore
        // an explicit interop control. Reject the combination instead.
        if !self.is_reflector
            && self.auth_mode.is_authenticated()
            && self.tlv_hmac == TlvHmacMode::Off
        {
            return Err(ConfigurationError::InvalidConfiguration(
                "tlv_hmac = off is not supported in authenticated mode (-A A): \
                 authenticated TLV-bearing packets always originate an HMAC TLV \
                 (RFC 8972 §4.8); use open mode to suppress it"
                    .to_string(),
            ));
        }

        // Validate --verify-tlv-hmac requires HMAC key to be configured
        if self.verify_tlv_hmac && !self.key_source().is_configured() {
            return Err(ConfigurationError::InvalidConfiguration(
                "--verify-tlv-hmac requires --hmac-key, --hmac-key-file, or --hmac-key-dir"
                    .to_string(),
            ));
        }

        // Validate authenticated mode requires HMAC key (RFC 8762 §4.4)
        if self.auth_mode.is_authenticated() && !self.key_source().is_configured() {
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

        // Repeat clap's conflict checks after TOML merging: file values can
        // introduce conflicts that were absent during CLI parsing.
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

        // Per-SSID key directories are reflector-only; a sender uses one key.
        if self.hmac_key_dir.is_some() && !self.is_reflector {
            return Err(ConfigurationError::InvalidConfiguration(
                "hmac_key_dir is reflector-only (it is a per-SSID keyset); a \
                 Session-Sender uses a single key — pass hmac_key_file instead"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Extra Padding and BER (padding sizes, pattern, intervals, thresholds).
    fn validate_padding(&self) -> Result<(), ConfigurationError> {
        // clap's `conflicts_with` covers the CLI; a config file can set both.
        // BER owns the padding TLV when enabled — its pattern is what the
        // reflector XOR-compares, so a second, pseudorandom padding TLV would
        // corrupt the measurement.
        if self.ber && self.extra_padding.is_some() {
            return Err(ConfigurationError::InvalidConfiguration(
                "extra_padding conflicts with ber: BER fills the Extra Padding \
                 TLV with its own known pattern (use ber_padding_size)"
                    .to_string(),
            ));
        }

        // Padding sizes need a finite, wire-safe bound: the value is
        // allocated before any protocol check (an absurd value is a
        // capacity-overflow panic or an OOM), and anything past the TLV's
        // 16-bit Length field would serialize with a truncated length.
        if let Some(bytes) = self.extra_padding {
            if bytes > MAX_PADDING_BYTES {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "extra_padding value {bytes} exceeds the maximum of \
                     {MAX_PADDING_BYTES} bytes (the largest padding TLV that fits \
                     a maximum-size UDP payload alongside the base packet and \
                     per-packet TLVs)"
                )));
            }
        }
        if self.ber_padding_size > MAX_PADDING_BYTES {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "ber_padding_size value {} exceeds the maximum of \
                 {MAX_PADDING_BYTES} bytes",
                self.ber_padding_size
            )));
        }

        if self.ber {
            let pattern = crate::ber::parse_pattern(self.ber_pattern.as_deref().unwrap_or("ff00"))
                .map_err(|e| {
                    ConfigurationError::InvalidConfiguration(format!("Invalid --ber-pattern: {e}"))
                })?;
            if self.ber_padding_size == 0 || self.ber_padding_size % pattern.len() != 0 {
                return Err(ConfigurationError::InvalidConfiguration(
                    "ber_padding_size must be positive and a multiple of the pattern length".into(),
                ));
            }
            if self.ber_interval == 0 || self.send_delay.duration().is_zero() {
                return Err(ConfigurationError::InvalidConfiguration(
                    "BER requires positive ber_interval and send_delay".into(),
                ));
            }
            for threshold in [self.ber_bit_threshold, self.ber_packet_threshold]
                .into_iter()
                .flatten()
            {
                if !threshold.is_finite() || !(0.0..=1_000_000.0).contains(&threshold) {
                    return Err(ConfigurationError::InvalidConfiguration(
                        "BER thresholds must be finite and between 0 and 1000000".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Control API placement and TLS material.
    fn validate_control(&self) -> Result<(), ConfigurationError> {
        // Validate TLS certificate/key pairing after TOML merging, which bypasses
        // clap's `requires` checks. TLS also requires a bearer token.
        match (&self.control_tls_cert, &self.control_tls_key) {
            (Some(_), None) => {
                return Err(ConfigurationError::InvalidConfiguration(
                    "control_tls_cert requires control_tls_key".to_string(),
                ))
            }
            (None, Some(_)) => {
                return Err(ConfigurationError::InvalidConfiguration(
                    "control_tls_key requires control_tls_cert".to_string(),
                ))
            }
            (Some(_), Some(_)) if self.control_token_file.is_none() => {
                return Err(ConfigurationError::InvalidConfiguration(
                    "control-plane TLS requires --control-token-file: an \
                     unauthenticated key-management and shutdown API should not \
                     be exposed, encrypted or not"
                        .to_string(),
                ))
            }
            _ => {}
        }

        // The control plane manages reflector state; sender mode has none.
        if self.control && !self.is_reflector {
            return Err(ConfigurationError::InvalidConfiguration(
                "--control is only available in reflector mode".to_string(),
            ));
        }
        Ok(())
    }

    /// Error Estimate fields (RFC 8762 §4.2.1).
    fn validate_error_estimate(&self) -> Result<(), ConfigurationError> {
        if self.error_scale > 63 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "Error scale {} exceeds maximum of 63",
                self.error_scale
            )));
        }
        if self.error_multiplier == 0 {
            return Err(ConfigurationError::InvalidConfiguration(
                "Error multiplier must not be 0 (RFC 4656 §4.1.2, used by RFC 8762 §4.2.1)".into(),
            ));
        }
        Ok(())
    }

    /// Return Path TLV options (RFC 9503, RFC 10052).
    fn validate_return_path(&self) -> Result<(), ConfigurationError> {
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

        // RFC 10052 §4.3: a Session-Sender MUST NOT
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
                 reflected_control_no_ext_hdr; RFC 10052 §4.3)"
                    .to_string(),
            ));
        }
        if self.return_sr_mpls_labels.is_some() && self.return_srv6_sids.is_some() {
            return Err(ConfigurationError::InvalidConfiguration(
                "return_sr_mpls_labels conflicts with return_srv6_sids".to_string(),
            ));
        }
        Ok(())
    }

    /// CoS, ECN and AIMD congestion-response parameters. Range checks repeat
    /// clap's because config-file values bypass it.
    fn validate_cos(&self) -> Result<(), ConfigurationError> {
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
        // Validate AIMD backoff and recovery parameters even when ECN measurement
        // is disabled (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
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
            && std::time::Duration::from_millis(u64::from(self.ecn_max_delay))
                < self.send_delay.duration()
        {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "ecn_max_delay ({} ms) must be >= send_delay ({:?}) when the AIMD \
                 congestion-response controller is active (--cos with --ecn 1 or 2)",
                self.ecn_max_delay,
                self.send_delay.duration()
            )));
        }
        Ok(())
    }

    /// Access Report options (RFC 8972 §4.6).
    fn validate_access_report(&self) -> Result<(), ConfigurationError> {
        if let Some(id) = self.access_report {
            // RFC 8972 §4.6: reflectors MUST discard Access IDs other than 1 and 2.
            if !matches!(id, 1 | 2) {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "access_report value {id} is invalid: RFC 8972 §4.6 defines Access ID 1 \
                     (3GPP Network) and 2 (Non-3GPP Network)"
                )));
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
        Ok(())
    }

    /// Micro-session IDs (RFC 9534).
    fn validate_micro_session(&self) -> Result<(), ConfigurationError> {
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

        if !self.is_reflector
            && self.reflector_member_link_id.is_some()
            && self.micro_session_id.is_none()
        {
            return Err(ConfigurationError::InvalidConfiguration(
                "sender reflector_member_link_id requires micro_session_id".to_string(),
            ));
        }
        Ok(())
    }

    /// Validates header-reflection requests and attachments before sending
    /// (draft-ietf-ippm-stamp-ext-hdr-15). Uses the sender's wire-TLV parsers,
    /// including those for standalone selector flags.
    fn validate_ext_hdr_flags(&self) -> Result<(), ConfigurationError> {
        let cfg_err = ConfigurationError::InvalidConfiguration;

        // Parse each repeatable occurrence (fails fast on bad hex/length).
        for spec in &self.reflected_ipv6_ext_hdr {
            parse_ext_hdr_request_spec(spec)
                .map_err(|e| cfg_err(format!("invalid --reflected-ipv6-ext-hdr `{spec}`: {e}")))?;
        }
        let fixed_max = 4;
        for spec in &self.reflected_fixed_hdr {
            let parsed = parse_fixed_hdr_request_spec(spec)
                .map_err(|e| cfg_err(format!("invalid --reflected-fixed-hdr `{spec}`: {e}")))?;
            if let Some(sel) = &parsed.selector {
                if sel.len() > fixed_max {
                    return Err(cfg_err(format!(
                        "--reflected-fixed-hdr selector is {} bytes; the maximum for the \
                         Requested field is {fixed_max} octets",
                        sel.len()
                    )));
                }
            }
        }
        for spec in &self.attach_ext_hdr {
            parse_attach_ext_hdr_spec(spec)
                .map_err(|e| cfg_err(format!("invalid --attach-ext-hdr `{spec}`: {e}")))?;
        }

        if !self.is_reflector {
            if self.reflected_fixed_hdr.len() > 1 {
                return Err(cfg_err("only one fixed IP header is originated; at most one fixed-header request is allowed".into()));
            }
            let attached = self.attach_ext_hdrs();
            if !attached.is_empty() {
                if !self.remote_addr.iter().all(std::net::IpAddr::is_ipv6) {
                    return Err(cfg_err(
                        "--attach-ext-hdr requires an IPv6 destination".into(),
                    ));
                }
                #[cfg(not(target_os = "linux"))]
                return Err(cfg_err("--attach-ext-hdr requires Linux".into()));
                #[cfg(target_os = "linux")]
                if attached.len() > 2
                    || attached.windows(2).any(|pair| {
                        pair[0].kind != AttachExtHdrKind::HopByHop
                            || pair[1].kind != AttachExtHdrKind::DestOpts
                    })
                {
                    return Err(cfg_err(
                        "attach at most one hbh and one dest header, in that order".into(),
                    ));
                }
            }
            let requests = self.ext_hdr_requests();
            if requests.len() > attached.len() {
                return Err(cfg_err("each IPv6 header request requires a corresponding --attach-ext-hdr; explicit requests replace automatic requests".into()));
            }
            let mut next = 0;
            for request in &requests {
                let selector = request.selector.clone().or_else(|| {
                    self.reflected_ipv6_ext_hdr_selector
                        .as_deref()
                        .and_then(|s| decode_selector(s).ok())
                });
                let mut requested = [0u8; 8];
                if let Some(bytes) = selector.as_ref() {
                    if bytes.len() <= 8 {
                        requested[..bytes.len()].copy_from_slice(bytes);
                    }
                }
                let matched = attached
                    .iter()
                    .enumerate()
                    .skip(next)
                    .find(|(index, header)| {
                        let mut first = header.bytes[..8].to_vec();
                        first[0] = if *index + 1 < attached.len() { 60 } else { 17 };
                        header.bytes.len() == request.length
                            && (selector.is_none() || first == requested)
                    });
                let Some((index, _)) = matched else {
                    return Err(cfg_err(
                        "IPv6 header requests must match attached lengths/selectors in wire order"
                            .into(),
                    ));
                };
                if selector.is_none()
                    && requests.len() < attached.len()
                    && attached
                        .iter()
                        .filter(|h| h.bytes.len() == request.length)
                        .count()
                        > 1
                {
                    return Err(cfg_err("selecting a subset of same-length headers requires an eight-octet selector".into()));
                }
                next = index + 1;
            }
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
                     (the Requested field)",
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
                     Requested field is {fixed_max} octets",
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

        let mut local_port_configured =
            matches.value_source("local_port") == Some(clap::parser::ValueSource::CommandLine);
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
            local_port_configured |= file.local_port.is_some();
            conf.merge_file(file, &matches);
        }

        if !local_port_configured {
            conf.local_port = if conf.is_reflector { 862 } else { 0 };
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

        // No `..`: a new file field fails to compile until it is merged here.
        let FileConfiguration {
            remote_addr,
            local_addr,
            local_scope_id,
            remote_scope_id,
            remote_port,
            local_port,
            interface,
            clock_source,
            clock_sync_source,
            hardware_clock_sync_source,
            reflector_utc_offset,
            send_delay,
            send_schedule,
            count,
            duration,
            timeout,
            session_loss_threshold,
            auth_mode,
            print_stats,
            is_reflector,
            error_scale,
            error_multiplier,
            clock_synchronized,
            hmac_key_file,
            hmac_key_dir,
            require_hmac,
            strict_packets,
            stateful_reflector,
            session_admission,
            reflector_sessions,
            session_timeout,
            location_disclose,
            drop_replayed,
            allowed_dscp,
            allowed_ecn,
            allowed_dscp_for,
            tlv_mode,
            verify_tlv_hmac,
            ssid,
            on_zero_ssid,
            metrics,
            metrics_addr,
            cos,
            dscp,
            ecn,
            ecn_backoff_factor,
            ecn_max_delay,
            ecn_recovery_step,
            ttl,
            malformed,
            access_report,
            access_return_code,
            access_report_timeout,
            access_report_retries,
            timestamp_info,
            direct_measurement,
            location,
            follow_up_telemetry,
            snmp,
            snmp_socket,
            control,
            control_addr,
            control_token_file,
            control_tls_cert,
            control_tls_key,
            output_format,
            log_format,
            hwtstamp,
            report_interval,
            dest_node_addr,
            return_path_cc,
            return_address,
            return_sr_mpls_labels,
            return_srv6_sids,
            srv6_return_forwarding,
            return_path_allow_alternate,
            micro_session_id,
            reflector_member_link_id,
            max_pps,
            reflector_rate_burst,
            reflector_queue_capacity,
            reflector_shutdown_grace_ms,
            max_sessions,
            ber,
            ber_pattern,
            ber_padding_size,
            ber_interval,
            ber_bit_threshold,
            ber_packet_threshold,
            extra_padding,
            ber_omit_burst,
            tlv_hmac,
            reflected_control_count,
            reflected_control_length,
            reflected_control_interval_ns,
            reflected_control_no_ext_hdr,
            reflected_control_max_count,
            reflected_control_max_size,
            reflected_control_min_interval_ns,
            reflected_control_max_rate,
            reflected_control_max_volume,
            reflected_fixed_hdr,
            reflected_ipv6_ext_hdr,
            attach_ext_hdr,
            reflected_ipv6_ext_hdr_selector,
            reflected_fixed_hdr_selector,
        } = file;

        macro_rules! merge {
            ($field:ident) => {
                if !user_set(stringify!($field)) {
                    if let Some(v) = $field {
                        self.$field = v;
                    }
                }
            };
        }
        macro_rules! merge_opt {
            ($field:ident) => {
                if !user_set(stringify!($field)) && $field.is_some() {
                    self.$field = $field;
                }
            };
        }

        merge!(remote_addr);
        merge!(local_addr);
        merge!(local_scope_id);
        merge!(remote_scope_id);
        merge!(remote_port);
        merge!(local_port);
        merge_opt!(interface);
        merge!(clock_source);
        merge!(clock_sync_source);
        merge!(hardware_clock_sync_source);
        merge!(reflector_utc_offset);
        merge!(send_delay);
        merge!(send_schedule);
        merge!(count);
        merge_opt!(duration);
        merge!(timeout);
        merge!(session_loss_threshold);
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
        merge!(session_admission);
        merge!(reflector_sessions);
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
        merge_opt!(control_tls_cert);
        merge_opt!(control_tls_key);
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
        merge!(reflector_queue_capacity);
        merge!(reflector_shutdown_grace_ms);
        merge!(max_sessions);
        merge!(ber);
        merge_opt!(ber_pattern);
        merge!(ber_padding_size);
        merge!(ber_interval);
        merge_opt!(ber_bit_threshold);
        merge_opt!(ber_packet_threshold);
        merge_opt!(extra_padding);
        merge!(ber_omit_burst);
        merge!(tlv_hmac);
        merge!(reflected_control_count);
        merge!(reflected_control_length);
        merge!(reflected_control_interval_ns);
        merge!(reflected_control_no_ext_hdr);
        merge!(reflected_control_max_count);
        merge!(reflected_control_max_size);
        merge!(reflected_control_min_interval_ns);
        merge!(reflected_control_max_rate);
        merge!(reflected_control_max_volume);
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

/// Accepts a single value or an array of values.
fn one_or_many<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        One(T),
        Many(Vec<T>),
    }
    let value: OneOrMany<T> = serde::Deserialize::deserialize(deserializer)?;
    Ok(Some(match value {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    }))
}

/// Deserializable mirror of [`Configuration`] used to load defaults from a
/// TOML file. Every field is optional; missing keys fall through to the
/// hardcoded clap defaults.
///
/// `hmac_key` and `config` are intentionally absent: the former to prevent
/// plaintext secrets from being stored in config files (use `hmac_key_file`
/// or the `STAMP_HMAC_KEY` environment variable instead), the latter because
/// it would be recursive.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfiguration {
    #[serde(default, deserialize_with = "one_or_many")]
    pub remote_addr: Option<Vec<std::net::IpAddr>>,
    pub local_addr: Option<std::net::IpAddr>,
    pub local_scope_id: Option<u32>,
    pub remote_scope_id: Option<u32>,
    pub remote_port: Option<u16>,
    pub local_port: Option<u16>,
    pub interface: Option<String>,
    pub clock_source: Option<ClockFormat>,
    pub clock_sync_source: Option<ClockSyncSource>,
    pub hardware_clock_sync_source: Option<ClockSyncSource>,
    pub reflector_utc_offset: Option<i32>,
    pub send_delay: Option<ProbeInterval>,
    pub send_schedule: Option<SendSchedule>,
    pub count: Option<u32>,
    pub duration: Option<u32>,
    pub timeout: Option<u8>,
    pub session_loss_threshold: Option<u16>,
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
    pub session_admission: Option<SessionAdmission>,
    pub reflector_sessions: Option<Vec<String>>,
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
    pub control_tls_cert: Option<PathBuf>,
    pub control_tls_key: Option<PathBuf>,
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
    pub reflector_queue_capacity: Option<u32>,
    pub reflector_shutdown_grace_ms: Option<u32>,
    pub max_sessions: Option<u32>,
    pub ber: Option<bool>,
    pub ber_pattern: Option<String>,
    pub ber_padding_size: Option<usize>,
    pub ber_interval: Option<u32>,
    pub ber_bit_threshold: Option<f64>,
    pub ber_packet_threshold: Option<f64>,
    pub extra_padding: Option<usize>,
    pub ber_omit_burst: Option<bool>,
    pub tlv_hmac: Option<TlvHmacMode>,
    pub reflected_control_count: Option<u16>,
    pub reflected_control_length: Option<u16>,
    pub reflected_control_interval_ns: Option<u32>,
    pub reflected_control_no_ext_hdr: Option<bool>,
    pub reflected_control_max_count: Option<u16>,
    pub reflected_control_max_size: Option<u16>,
    pub reflected_control_min_interval_ns: Option<u32>,
    pub reflected_control_max_rate: Option<u64>,
    pub reflected_control_max_volume: Option<u32>,
    pub reflected_fixed_hdr: Option<Vec<String>>,
    pub reflected_ipv6_ext_hdr: Option<Vec<String>>,
    pub attach_ext_hdr: Option<Vec<String>>,
    pub reflected_ipv6_ext_hdr_selector: Option<String>,
    pub reflected_fixed_hdr_selector: Option<String>,
}

/// JSON Schema (draft 2020-12) for `--config`, emitted by `--print-config-schema`.
///
/// Keep properties in sync with [`FileConfiguration`]. Unknown keys are rejected
/// to match its `#[serde(deny_unknown_fields)]` behavior.
pub const CONFIG_JSON_SCHEMA: &str = r##"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/asmie/stamp-suite/schema/stamp-suite-config.json",
  "title": "stamp-suite TOML configuration",
  "description": "Schema for the file consumed by `stamp-suite --config <PATH>`. Keys map 1:1 to CLI flags (long form with underscores instead of dashes).",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "remote_addr": { "anyOf": [
      { "type": "string", "format": "ipvanyaddress" },
      { "type": "array", "minItems": 1, "items": { "type": "string", "format": "ipvanyaddress" } }
    ] },
    "local_addr":  { "type": "string", "format": "ipvanyaddress" },
    "local_scope_id": { "type": "integer", "minimum": 0, "maximum": 4294967295 },
    "remote_scope_id": { "type": "integer", "minimum": 0, "maximum": 4294967295 },
    "remote_port": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "local_port":  { "type": "integer", "minimum": 0, "maximum": 65535 },
    "interface":   { "type": "string", "minLength": 1, "maxLength": 15 },
    "clock_source": { "enum": ["NTP", "PTP"] },
    "clock_sync_source": { "enum": ["ntp", "ptp", "gps", "glonass", "loran-c", "bds", "galileo", "local", "ssu-bits"] },
    "hardware_clock_sync_source": { "enum": ["ntp", "ptp", "gps", "glonass", "loran-c", "bds", "galileo", "local", "ssu-bits"] },
    "reflector_utc_offset": { "type": "integer", "minimum": -2147483648, "maximum": 2147483647 },
    "send_delay":  { "anyOf": [
      { "type": "integer", "minimum": 0, "maximum": 3600000 },
      { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)?(us|µs|ms|s)?$" }
    ] },
    "send_schedule": { "enum": ["periodic", "poisson"] },
    "count":       { "type": "integer", "minimum": 0, "maximum": 4294967295 },
    "duration":    { "type": "integer", "minimum": 1, "maximum": 4294967295 },
    "session_loss_threshold": { "type": "integer", "minimum": 1, "maximum": 65535 },
    "timeout":     { "type": "integer", "minimum": 0, "maximum": 255 },
    "auth_mode":   { "enum": ["A", "O"] },
    "print_stats": { "type": "boolean" },
    "is_reflector": { "type": "boolean" },
    "error_scale": { "type": "integer", "minimum": 0, "maximum": 63 },
    "error_multiplier": { "type": "integer", "minimum": 1, "maximum": 255 },
    "clock_synchronized": { "type": "boolean" },
    "hmac_key_file": { "type": "string" },
    "hmac_key_dir":  { "type": "string" },
    "require_hmac":  { "type": "boolean" },
    "strict_packets": { "type": "boolean" },
    "stateful_reflector": { "type": "boolean" },
    "session_admission": { "type": "string", "enum": ["permissive", "provisioned"] },
    "reflector_sessions": { "type": "array", "items": { "type": "string" } },
    "session_timeout": { "type": "integer", "minimum": 0 },
    "location_disclose": { "type": "string" },
    "drop_replayed": { "type": "boolean" },
    "allowed_dscp": { "type": "string" },
    "allowed_ecn": { "type": "string" },
    "allowed_dscp_for": { "type": "array", "items": { "type": "string" } },
    "tlv_mode": { "enum": ["echo", "ignore"] },
    "verify_tlv_hmac": { "type": "boolean" },
    "ssid": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "on_zero_ssid": { "enum": ["continue", "stop"] },
    "metrics": { "type": "boolean" },
    "metrics_addr": { "type": "string" },
    "cos": { "type": "boolean" },
    "dscp": { "type": "integer", "minimum": 0, "maximum": 63 },
    "ecn":  { "type": "integer", "minimum": 0, "maximum": 3 },
    "ecn_backoff_factor": { "type": "number", "exclusiveMinimum": 1.0 },
    "ecn_max_delay": { "type": "integer", "minimum": 1 },
    "ecn_recovery_step": { "type": "integer", "minimum": 1 },
    "ttl":  { "type": "integer", "const": 255 },
    "malformed": { "enum": ["bad-flags", "bad-length"] },
    "access_report": { "type": "integer", "minimum": 1, "maximum": 2 },
    "access_return_code": { "type": "integer", "minimum": 0, "maximum": 255 },
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
    "control_tls_cert": { "type": "string" },
    "control_tls_key": { "type": "string" },
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
    "reflector_queue_capacity": { "type": "integer", "minimum": 1, "maximum": 4294967295 },
    "reflector_shutdown_grace_ms": { "type": "integer", "minimum": 0, "maximum": 60000 },
    "max_sessions": { "type": "integer", "minimum": 0 },
    "ber": { "type": "boolean" },
    "ber_pattern": { "type": "string", "pattern": "^(0x)?([0-9a-fA-F]{2})+$" },
    "ber_padding_size": { "type": "integer", "minimum": 0, "maximum": 65347 },
    "extra_padding": { "type": "integer", "minimum": 0, "maximum": 65347 },
    "ber_interval": { "type": "integer", "minimum": 1, "maximum": 4294967295 },
    "ber_bit_threshold": { "type": "number", "minimum": 0, "maximum": 1000000 },
    "ber_packet_threshold": { "type": "number", "minimum": 0, "maximum": 1000000 },
    "ber_omit_burst": { "type": "boolean" },
    "tlv_hmac": { "type": "string", "enum": ["auto", "on", "off"] },
    "reflected_control_count": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_length": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_interval_ns": { "type": "integer", "minimum": 0 },
    "reflected_control_no_ext_hdr": { "type": "boolean" },
    "reflected_control_max_count": { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_max_size":  { "type": "integer", "minimum": 0, "maximum": 65535 },
    "reflected_control_min_interval_ns": { "type": "integer", "minimum": 0 },
    "reflected_control_max_rate": { "type": "integer", "minimum": 1 },
    "reflected_control_max_volume": { "type": "integer", "minimum": 1, "maximum": 4294967295 },
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

/// Resolves the log filter: a non-empty `env` wins, otherwise verbosity maps
/// 0 to `info`, 1 to `debug`, and 2 or more to `trace`.
///
/// Pass `std::env::var("RUST_LOG").ok()` as `env`.
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

/// Maximum padding value size for `--extra-padding` and `--ber-padding-size`.
///
/// From the IPv4 UDP payload limit (65507), reserve the authenticated base (112),
/// padding header (4), HMAC (20), Direct Measurement (16), and Access Report (8).
/// Validate before allocation to reject oversized input.
pub const MAX_PADDING_BYTES: usize = 65_507 - 112 - 4 - 20 - 16 - 8;

/// Type 246 Requested field width (draft-ietf-ippm-stamp-ext-hdr-15 §4.1).
pub(crate) const MAX_IPV6_EXT_HDR_SELECTOR_BYTES: usize = 8;

/// Decodes a hex selector string (optional `0x` prefix) into bytes for the
/// draft-ietf-ippm-stamp-ext-hdr-15 §4.1/§6.1 Requested-field request TLVs.
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
/// (draft-ietf-ippm-stamp-ext-hdr-15 §§4.2, 4.1). Each occurrence becomes one
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
/// (draft-ietf-ippm-stamp-ext-hdr-15 §§6.2, 6.1). Each occurrence becomes one
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
/// sender attaches to its own egress packets (draft-ietf-ippm-stamp-ext-hdr-15
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
    let length = if len_part.is_empty() {
        crate::tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY
    } else {
        len_part
            .parse::<usize>()
            .map_err(|e| format!("invalid length `{len_part}`: {e}"))?
    };
    // A zero-length request names no extension header. Omit the value to get
    // the default length instead of asking for nothing.
    if length < 8 || length % 8 != 0 {
        return Err("length must be a positive multiple of 8 octets".to_string());
    }
    if length > 2048 {
        return Err(format!(
            "length {length} exceeds the maximum of 2048 \
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
    if bytes.len() > 2048 || bytes.len() != (usize::from(bytes[1]) + 1) * 8 {
        return Err(
            "extension-header size must match Hdr Ext Len and be at most 2048 octets".into(),
        );
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
mod tests;
