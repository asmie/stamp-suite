use std::fmt;

use clap::ValueEnum;

/// This enum represents the clock format used in the application.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default, ValueEnum)]
pub enum ClockFormat {
    /// Network Time Protocol timestamp format (RFC 5905).
    #[default]
    #[value(name = "NTP")]
    NTP,
    /// Precision Time Protocol timestamp format (IEEE 1588).
    #[value(name = "PTP")]
    PTP,
}

impl fmt::Display for ClockFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClockFormat::NTP => write!(f, "NTP"),
            ClockFormat::PTP => write!(f, "PTP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_format_parsing() {
        assert_eq!(
            ClockFormat::from_str("NTP", false).unwrap(),
            ClockFormat::NTP
        );
        assert_eq!(
            ClockFormat::from_str("PTP", false).unwrap(),
            ClockFormat::PTP
        );
        assert!(ClockFormat::from_str("INVALID", false).is_err());
    }

    #[test]
    fn test_clock_format_display() {
        assert_eq!(ClockFormat::NTP.to_string(), "NTP");
        assert_eq!(ClockFormat::PTP.to_string(), "PTP");
    }

    #[test]
    fn test_clock_format_case_insensitive() {
        // ValueEnum supports case-insensitive parsing with ignore_case=true
        assert_eq!(
            ClockFormat::from_str("ntp", true).unwrap(),
            ClockFormat::NTP
        );
        assert_eq!(
            ClockFormat::from_str("ptp", true).unwrap(),
            ClockFormat::PTP
        );
    }

    #[test]
    fn test_clock_format_case_sensitive() {
        // With ignore_case=false, only exact match works
        assert!(ClockFormat::from_str("ntp", false).is_err());
        assert!(ClockFormat::from_str("ptp", false).is_err());
        assert!(ClockFormat::from_str("Ntp", false).is_err());
    }

    #[test]
    fn test_clock_format_empty_string() {
        assert!(ClockFormat::from_str("", false).is_err());
    }

    #[test]
    fn test_clock_format_whitespace() {
        assert!(ClockFormat::from_str(" NTP", false).is_err());
        assert!(ClockFormat::from_str("NTP ", false).is_err());
    }

    #[test]
    fn test_clock_format_roundtrip() {
        // Parse -> Display -> Parse should give same result
        let ntp = ClockFormat::from_str("NTP", false).unwrap();
        let ntp_str = ntp.to_string();
        let ntp_again = ClockFormat::from_str(&ntp_str, false).unwrap();
        assert_eq!(ntp, ntp_again);

        let ptp = ClockFormat::from_str("PTP", false).unwrap();
        let ptp_str = ptp.to_string();
        let ptp_again = ClockFormat::from_str(&ptp_str, false).unwrap();
        assert_eq!(ptp, ptp_again);
    }
}
