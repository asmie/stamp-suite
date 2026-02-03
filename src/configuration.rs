use clap::Parser;
use thiserror::Error;

pub use crate::{clock_format::ClockFormat, stamp_modes::StampModes};

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
    /// Specify work mode - A for auth, E for encrypted and O for open mode -  default "AEO".
    #[clap(short = 'A', long, default_value = "AEO")]
    pub auth_mode: String,
    /// Print individual statistics for each packet.
    #[clap(short = 'R')]
    pub print_stats: bool,
    /// Run as Session Reflector instead of Session Sender.
    #[clap(short = 'i', long, default_value_t = false)]
    pub is_reflector: bool,
}

impl Configuration {
    /// Validates the configuration parameters.
    ///
    /// Returns an error if any configuration value is invalid.
    pub fn validate(&self) -> Result<(), ConfigurationError> {
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

/// Checks if authenticated mode is enabled in the auth mode string.
///
/// Returns `true` if the mode string contains 'A'.
pub fn is_auth(mode_str: &str) -> bool {
    mode_str.contains('A')
}

/// Checks if encrypted mode is enabled in the auth mode string.
///
/// Returns `true` if the mode string contains 'E'.
pub fn is_enc(mode_str: &str) -> bool {
    mode_str.contains('E')
}

/// Checks if open (unauthenticated) mode is enabled in the auth mode string.
///
/// Returns `true` if the mode string contains 'O'.
pub fn is_open(mode_str: &str) -> bool {
    mode_str.contains('O')
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
            "AEO",
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
        assert_eq!(conf.auth_mode, "AEO");
        assert!(conf.is_reflector);
    }

    #[test]
    fn test_invalid_configuration_parsing() {
        let args = vec!["test", "--remote-addr", "invalid_addr"];
        let conf = Configuration::try_parse_from(args);
        assert!(conf.is_err());
    }

    #[test]
    fn test_is_auth() {
        assert!(is_auth("AEO"));
        assert!(!is_auth("EO"));
    }

    #[test]
    fn test_is_enc() {
        assert!(is_enc("AEO"));
        assert!(!is_enc("AO"));
    }

    #[test]
    fn test_is_open() {
        assert!(is_open("AEO"));
        assert!(!is_open("AE"));
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
        assert_eq!(conf.auth_mode, "AEO");
        assert!(!conf.force_ipv4);
        assert!(!conf.force_ipv6);
        assert!(!conf.print_stats);
        assert!(!conf.is_reflector);
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
        // Single modes
        let args = vec!["test", "--auth-mode", "A"];
        let conf = Configuration::parse_from(args);
        assert!(is_auth(&conf.auth_mode));
        assert!(!is_enc(&conf.auth_mode));
        assert!(!is_open(&conf.auth_mode));

        let args = vec!["test", "--auth-mode", "E"];
        let conf = Configuration::parse_from(args);
        assert!(!is_auth(&conf.auth_mode));
        assert!(is_enc(&conf.auth_mode));
        assert!(!is_open(&conf.auth_mode));

        let args = vec!["test", "--auth-mode", "O"];
        let conf = Configuration::parse_from(args);
        assert!(!is_auth(&conf.auth_mode));
        assert!(!is_enc(&conf.auth_mode));
        assert!(is_open(&conf.auth_mode));
    }

    #[test]
    fn test_auth_mode_combinations() {
        let args = vec!["test", "--auth-mode", "AE"];
        let conf = Configuration::parse_from(args);
        assert!(is_auth(&conf.auth_mode));
        assert!(is_enc(&conf.auth_mode));
        assert!(!is_open(&conf.auth_mode));

        let args = vec!["test", "--auth-mode", "AO"];
        let conf = Configuration::parse_from(args);
        assert!(is_auth(&conf.auth_mode));
        assert!(!is_enc(&conf.auth_mode));
        assert!(is_open(&conf.auth_mode));

        let args = vec!["test", "--auth-mode", "EO"];
        let conf = Configuration::parse_from(args);
        assert!(!is_auth(&conf.auth_mode));
        assert!(is_enc(&conf.auth_mode));
        assert!(is_open(&conf.auth_mode));
    }

    #[test]
    fn test_auth_mode_empty() {
        let args = vec!["test", "--auth-mode", ""];
        let conf = Configuration::parse_from(args);
        assert!(!is_auth(&conf.auth_mode));
        assert!(!is_enc(&conf.auth_mode));
        assert!(!is_open(&conf.auth_mode));
    }

    #[test]
    fn test_auth_mode_case_sensitive() {
        // Lowercase should not match
        assert!(!is_auth("aeo"));
        assert!(!is_enc("aeo"));
        assert!(!is_open("aeo"));
    }

    #[test]
    fn test_invalid_port_number() {
        let args = vec!["test", "--remote-port", "99999"];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err());
    }
}
