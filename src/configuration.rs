use std::{fmt, path::PathBuf, str::FromStr};

use clap::{Parser, ValueEnum};
use thiserror::Error;

pub use crate::{clock_format::ClockFormat, stamp_modes::StampModes};

/// TLV handling mode for the reflector.
///
/// Controls how the reflector handles TLV extensions in incoming packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
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

impl FromStr for TlvHandlingMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ignore" => Ok(Self::Ignore),
            "echo" => Ok(Self::Echo),
            _ => Err(format!(
                "Invalid TLV mode '{}'. Valid options: ignore, echo",
                s
            )),
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
    /// Force IPv4 addresses.
    #[clap(short = '4')]
    pub force_ipv4: bool,
    /// Force IPv6 addresses.
    #[clap(short = '6')]
    pub force_ipv6: bool,
    /// Specify work mode - A for authenticated, O for open (unauthenticated) - default "O".
    #[clap(short = 'A', long, default_value = "O")]
    pub auth_mode: String,
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

        // Validate auth mode - only A (authenticated) or O (open) are valid per RFC 8762
        // A STAMP session is either authenticated or unauthenticated, not both
        if self.auth_mode != "A" && self.auth_mode != "O" {
            return Err(ConfigurationError::InvalidConfiguration(format!(
                "Invalid auth mode '{}'. Must be exactly 'A' (authenticated) or 'O' (open/unauthenticated)",
                self.auth_mode
            )));
        }

        // Validate --verify-tlv-hmac requires HMAC key to be configured
        if self.verify_tlv_hmac && self.hmac_key.is_none() && self.hmac_key_file.is_none() {
            return Err(ConfigurationError::InvalidConfiguration(
                "--verify-tlv-hmac requires --hmac-key or --hmac-key-file to be specified"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Error type for configuration validation failures.
#[derive(Error, Debug)]
pub enum ConfigurationError {
    /// Indicates an invalid configuration parameter.
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

/// Checks if authenticated mode is enabled.
///
/// Returns `true` if the mode string is exactly "A".
pub fn is_auth(mode_str: &str) -> bool {
    mode_str == "A"
}

/// Checks if open (unauthenticated) mode is enabled.
///
/// Returns `true` if the mode string is exactly "O".
pub fn is_open(mode_str: &str) -> bool {
    mode_str == "O"
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
        assert_eq!(conf.auth_mode, "A");
        assert!(conf.is_reflector);
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
        assert!(is_auth("A"));
        assert!(!is_auth("O"));
        assert!(!is_auth("AO")); // Composite strings are not valid
        assert!(!is_auth(""));
    }

    #[test]
    fn test_is_open() {
        assert!(is_open("O"));
        assert!(!is_open("A"));
        assert!(!is_open("AO")); // Composite strings are not valid
        assert!(!is_open(""));
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
        assert_eq!(conf.auth_mode, "O"); // RFC 8762 default: open/unauthenticated mode
        assert!(!conf.force_ipv4);
        assert!(!conf.force_ipv6);
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
        let args = vec!["test", "-4", "-6", "-R", "-i"];
        let conf = Configuration::parse_from(args);
        assert!(conf.force_ipv4);
        assert!(conf.force_ipv6);
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
        // Authenticated mode
        let args = vec!["test", "--auth-mode", "A"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
        assert!(is_auth(&conf.auth_mode));
        assert!(!is_open(&conf.auth_mode));

        // Open mode
        let args = vec!["test", "--auth-mode", "O"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_ok());
        assert!(!is_auth(&conf.auth_mode));
        assert!(is_open(&conf.auth_mode));
    }

    #[test]
    fn test_auth_mode_combinations_invalid() {
        // Composite strings like "AO" are not valid - must be exactly "A" or "O"
        let args = vec!["test", "--auth-mode", "AO"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());

        // "OA" is also invalid
        let args = vec!["test", "--auth-mode", "OA"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());

        // "AA" is also invalid
        let args = vec!["test", "--auth-mode", "AA"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_auth_mode_invalid() {
        // E (encrypted) is not supported per RFC 8762
        let args = vec!["test", "--auth-mode", "E"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());

        // Invalid character
        let args = vec!["test", "--auth-mode", "X"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());

        // Mixed valid and invalid
        let args = vec!["test", "--auth-mode", "AE"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_auth_mode_empty() {
        let args = vec!["test", "--auth-mode", ""];
        let conf = Configuration::parse_from(args);
        // Empty auth mode is invalid - must specify at least one mode
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_auth_mode_case_sensitive() {
        // Lowercase should not match the mode checks
        assert!(!is_auth("ao"));
        assert!(!is_open("ao"));

        // But lowercase is also invalid in validation
        let args = vec!["test", "--auth-mode", "a"];
        let conf = Configuration::parse_from(args);
        assert!(conf.validate().is_err());
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
        assert_eq!(
            "ignore".parse::<TlvHandlingMode>().unwrap(),
            TlvHandlingMode::Ignore
        );
        assert_eq!(
            "ECHO".parse::<TlvHandlingMode>().unwrap(),
            TlvHandlingMode::Echo
        );
        assert!("invalid".parse::<TlvHandlingMode>().is_err());
        assert!("process".parse::<TlvHandlingMode>().is_err());
    }

    #[test]
    fn test_tlv_handling_mode_display() {
        assert_eq!(TlvHandlingMode::Ignore.to_string(), "ignore");
        assert_eq!(TlvHandlingMode::Echo.to_string(), "echo");
    }
}
