use std::{fmt, net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};
use thiserror::Error;

pub use crate::clock_format::ClockFormat;
pub use crate::stats::OutputFormat;

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

    /// HMAC key as hex string (32+ hex chars recommended).
    #[clap(long, env = "STAMP_HMAC_KEY")]
    pub hmac_key: Option<String>,

    /// Path to file containing HMAC key.
    #[clap(long, conflicts_with = "hmac_key")]
    pub hmac_key_file: Option<PathBuf>,

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

    /// TLV handling mode for the reflector (RFC 8972). Default: echo.
    /// - ignore: Strip TLVs from reflected packets (zero-pad to preserve length)
    /// - echo: Echo TLVs back, marking unknown types with U-flag
    #[clap(long, value_enum, default_value_t = TlvHandlingMode::Echo)]
    pub tlv_mode: TlvHandlingMode,

    /// Verify HMAC TLV in incoming packets (RFC 8972). Requires HMAC key.
    #[clap(long)]
    pub verify_tlv_hmac: bool,

    /// Session-Sender Identifier to include in sender packets (RFC 8972).
    /// Will be encoded in an Extra Padding TLV.
    #[clap(long)]
    pub ssid: Option<u16>,

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

    /// Enable Access Report TLV (RFC 8972 §4.6) with the given Access ID (0-15).
    /// The reflector echoes this TLV unchanged.
    #[clap(long, value_parser = clap::value_parser!(u8).range(0..16))]
    pub access_report: Option<u8>,

    /// Return code for Access Report TLV (default: 1 = available).
    /// Only used when --access-report is enabled.
    #[clap(long, default_value_t = 1)]
    pub access_return_code: u8,

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

    /// Output format for statistics (text, json, csv).
    #[clap(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output_format: OutputFormat,

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

    /// Sender micro-session member link ID for LAG measurement (RFC 9534).
    /// When set, includes a Micro-session ID TLV in test packets.
    #[clap(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub micro_session_id: Option<u16>,

    /// Reflector member link ID for LAG micro-sessions (RFC 9534).
    /// When set, the reflector fills this ID into reflected Micro-session ID TLVs.
    #[clap(long, value_parser = clap::value_parser!(u16).range(1..))]
    pub reflector_member_link_id: Option<u16>,

    /// Maximum packets per second per source (0 = unlimited).
    #[clap(long, default_value_t = 0)]
    pub max_pps: u32,

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
}

impl Configuration {
    /// Validates the configuration parameters.
    ///
    /// Returns an error if any configuration value is invalid.
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if self.error_scale > 63 {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "Error scale {} exceeds maximum of 63",
                self.error_scale
            )));
        }

        // Validate --verify-tlv-hmac requires HMAC key to be configured
        if self.verify_tlv_hmac && self.hmac_key.is_none() && self.hmac_key_file.is_none() {
            return Err(ConfigurationError::InvalidConfiguration(
                "--verify-tlv-hmac requires --hmac-key or --hmac-key-file to be specified"
                    .to_string(),
            ));
        }

        // Validate authenticated mode requires HMAC key (RFC 8762 §4.4)
        if self.auth_mode.is_authenticated()
            && self.hmac_key.is_none()
            && self.hmac_key_file.is_none()
        {
            let mode_desc = if self.is_reflector {
                "reflector"
            } else {
                "sender"
            };
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "Authenticated mode {} (-A A) requires --hmac-key or --hmac-key-file",
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
        if let Some(id) = self.access_report {
            if id > 15 {
                return Err(ConfigurationError::InvalidConfiguration(format!(
                    "access_report value {} exceeds maximum of 15",
                    id
                )));
            }
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
        if self.return_sr_mpls_labels.is_some() && self.return_srv6_sids.is_some() {
            return Err(ConfigurationError::InvalidConfiguration(
                "return_sr_mpls_labels conflicts with return_srv6_sids".to_string(),
            ));
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
        merge!(require_hmac);
        merge!(strict_packets);
        merge!(stateful_reflector);
        merge!(session_timeout);
        merge!(tlv_mode);
        merge!(verify_tlv_hmac);
        merge_opt!(ssid);
        merge!(metrics);
        merge!(metrics_addr);
        merge!(cos);
        merge!(dscp);
        merge!(ecn);
        merge_opt!(access_report);
        merge!(access_return_code);
        merge!(timestamp_info);
        merge!(direct_measurement);
        merge!(location);
        merge!(follow_up_telemetry);
        merge!(snmp);
        merge!(snmp_socket);
        merge!(output_format);
        merge!(report_interval);
        merge_opt!(dest_node_addr);
        merge_opt!(return_path_cc);
        merge_opt!(return_address);
        merge_opt!(return_sr_mpls_labels);
        merge_opt!(return_srv6_sids);
        merge_opt!(micro_session_id);
        merge_opt!(reflector_member_link_id);
        merge!(max_pps);
        merge!(ber);
        merge_opt!(ber_pattern);
        merge!(ber_padding_size);
        merge!(reflected_control_count);
        merge!(reflected_control_length);
        merge!(reflected_control_interval_ns);
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
    pub require_hmac: Option<bool>,
    pub strict_packets: Option<bool>,
    pub stateful_reflector: Option<bool>,
    pub session_timeout: Option<u64>,
    pub tlv_mode: Option<TlvHandlingMode>,
    pub verify_tlv_hmac: Option<bool>,
    pub ssid: Option<u16>,
    pub metrics: Option<bool>,
    pub metrics_addr: Option<SocketAddr>,
    pub cos: Option<bool>,
    pub dscp: Option<u8>,
    pub ecn: Option<u8>,
    pub access_report: Option<u8>,
    pub access_return_code: Option<u8>,
    pub timestamp_info: Option<bool>,
    pub direct_measurement: Option<bool>,
    pub location: Option<bool>,
    pub follow_up_telemetry: Option<bool>,
    pub snmp: Option<bool>,
    pub snmp_socket: Option<String>,
    pub output_format: Option<OutputFormat>,
    pub report_interval: Option<u32>,
    pub dest_node_addr: Option<std::net::IpAddr>,
    pub return_path_cc: Option<u32>,
    pub return_address: Option<std::net::IpAddr>,
    pub return_sr_mpls_labels: Option<Vec<u32>>,
    pub return_srv6_sids: Option<Vec<std::net::Ipv6Addr>>,
    pub micro_session_id: Option<u16>,
    pub reflector_member_link_id: Option<u16>,
    pub max_pps: Option<u32>,
    pub ber: Option<bool>,
    pub ber_pattern: Option<String>,
    pub ber_padding_size: Option<usize>,
    pub reflected_control_count: Option<u16>,
    pub reflected_control_length: Option<u16>,
    pub reflected_control_interval_ns: Option<u32>,
}

/// Checks if authenticated mode is enabled.
#[inline]
pub fn is_auth(mode: AuthMode) -> bool {
    mode.is_authenticated()
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
            conf.hmac_key,
            Some("0123456789abcdef0123456789abcdef".to_string())
        );
        assert!(conf.hmac_key_file.is_none());
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

    #[test]
    fn test_validate_rejects_out_of_range_access_report_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, "access_report = 99\n").unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("access_report > 15 must fail");
        assert!(err.to_string().contains("access_report"));
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
}
