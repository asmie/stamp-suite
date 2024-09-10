use std::{fmt, str::FromStr};

use thiserror::Error;

/// This enum represents the clock format used in the application.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum ClockFormat {
    NTP,
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
}
