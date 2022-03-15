pub use clap::{ArgEnum, Parser};
use std::str::FromStr;
use std::fmt;
use std::error::Error;
use std::net::IpAddr;

#[derive(Debug)]
pub struct ConfigurationError {
    details: String
}

impl ConfigurationError {
    fn new(msg: &str) -> ConfigurationError {
        ConfigurationError{details: msg.to_string()}
    }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
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

    fn from_str(s: &str) -> Result<Self, Self::Err>
    {
        match s {
            "u" => Ok(StampModes::Unauthenticated),
            "a" => Ok(StampModes::Authenticated),
            _ => Err(ConfigurationError::new("Invalid STAMP mode"))
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
pub enum ClockSource {
    NTP,
    PTP,
}

impl FromStr for ClockSource {
    type Err = ConfigurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err>
    {
        match s {
            "NTP" => Ok(ClockSource::NTP),
            "PTP" => Ok(ClockSource::PTP),
            _ => Err(ConfigurationError::new("Invalid clock source"))
        }
    }
}

impl fmt::Display for ClockSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClockSource::NTP => write!(f, "NTP"),
            ClockSource::PTP => write!(f, "PTP"),
        }
    }
}

impl fmt::Debug for ClockSource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ClockSource::NTP => write!(f, "NTP"),
            ClockSource::PTP => write!(f, "PTP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::ClockSource;

    #[test]
    fn clock_source_test() {
        let cs = ClockSource::NTP;

    }
}