pub use clap::Parser;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[derive(Debug)]
pub struct ConfigurationError {
    details: String,
}

impl ConfigurationError {
    fn new(msg: &str) -> ConfigurationError {
        ConfigurationError {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for ConfigurationError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Copy, Clone)]
pub enum StampModes {
    Unauthenticated,
    Authenticated,
}

impl FromStr for StampModes {
    type Err = ConfigurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "u" => Ok(StampModes::Unauthenticated),
            "a" => Ok(StampModes::Authenticated),
            _ => Err(ConfigurationError::new("Invalid STAMP mode")),
        }
    }
}

impl fmt::Display for StampModes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StampModes::Unauthenticated => write!(f, "u"),
            StampModes::Authenticated => write!(f, "a"),
        }
    }
}

impl fmt::Debug for StampModes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StampModes::Unauthenticated => write!(f, "u"),
            StampModes::Authenticated => write!(f, "a"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum ClockFormat {
    NTP,
    PTP,
}

impl FromStr for ClockFormat {
    type Err = ConfigurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NTP" => Ok(ClockFormat::NTP),
            "PTP" => Ok(ClockFormat::PTP),
            _ => Err(ConfigurationError::new("Invalid clock source")),
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

impl fmt::Debug for ClockFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClockFormat::NTP => write!(f, "NTP"),
            ClockFormat::PTP => write!(f, "PTP"),
        }
    }
}

pub fn is_auth(mode_str: &str) -> bool {
    mode_str.contains('A')
}

pub fn is_enc(mode_str: &str) -> bool {
    mode_str.contains('E')
}

pub fn is_open(mode_str: &str) -> bool {
    mode_str.contains('O')
}

#[cfg(test)]
mod tests {
    use crate::configuration::ClockFormat;

    #[test]
    fn clock_source_test() {
        let cs = ClockFormat::NTP;
    }
}
