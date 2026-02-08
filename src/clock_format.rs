use std::{fmt, str::FromStr};

use thiserror::Error;

/// This enum represents the clock format used in the application.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ClockFormat {
    /// Network Time Protocol timestamp format (RFC 5905).
    NTP,
    /// Precision Time Protocol timestamp format (IEEE 1588).
    PTP,
}

/// Represents the error that can occur when parsing the clock format.
#[derive(Error, Debug)]
pub enum ClockFormatError {
    #[error("Invalid clock source")]
    InvalidClockSource,
}

impl FromStr for ClockFormat {
    type Err = ClockFormatError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NTP" => Ok(ClockFormat::NTP),
            "PTP" => Ok(ClockFormat::PTP),
            _ => Err(ClockFormatError::InvalidClockSource),
        }
    }
}

impl fmt::Display for ClockFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
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
        assert_eq!("NTP".parse::<ClockFormat>().unwrap(), ClockFormat::NTP);
        assert_eq!("PTP".parse::<ClockFormat>().unwrap(), ClockFormat::PTP);
        assert!("INVALID".parse::<ClockFormat>().is_err());
    }

    #[test]
    fn test_clock_format_display() {
        assert_eq!(ClockFormat::NTP.to_string(), "NTP");
        assert_eq!(ClockFormat::PTP.to_string(), "PTP");
    }

    #[test]
    fn test_clock_format_case_sensitive() {
        // Lowercase should fail
        assert!("ntp".parse::<ClockFormat>().is_err());
        assert!("ptp".parse::<ClockFormat>().is_err());
        assert!("Ntp".parse::<ClockFormat>().is_err());
        assert!("Ptp".parse::<ClockFormat>().is_err());
    }

    #[test]
    fn test_clock_format_empty_string() {
        assert!("".parse::<ClockFormat>().is_err());
    }

    #[test]
    fn test_clock_format_whitespace() {
        assert!(" NTP".parse::<ClockFormat>().is_err());
        assert!("NTP ".parse::<ClockFormat>().is_err());
        assert!(" NTP ".parse::<ClockFormat>().is_err());
    }

    #[test]
    fn test_clock_format_roundtrip() {
        // Parse -> Display -> Parse should give same result
        let ntp = "NTP".parse::<ClockFormat>().unwrap();
        let ntp_str = ntp.to_string();
        let ntp_again = ntp_str.parse::<ClockFormat>().unwrap();
        assert_eq!(ntp, ntp_again);

        let ptp = "PTP".parse::<ClockFormat>().unwrap();
        let ptp_str = ptp.to_string();
        let ptp_again = ptp_str.parse::<ClockFormat>().unwrap();
        assert_eq!(ptp, ptp_again);
    }
}
