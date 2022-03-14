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

#[derive(Copy, Clone)]
pub enum StampReflectorModes {
    Stateless,
    Stateful,
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


#[derive(Parser, Debug)]
#[clap(author = "Piotr Olszewski", version, about, long_about = None)]
pub struct Configuration {
    /// Remote address for Session Reflector
    #[clap(short, long)]
    pub remote_addr: Option<std::net::IpAddr>,
    /// Local address to bind for
    #[clap(short, long, default_value = "0.0.0.0")]
    pub local_addr: std::net::IpAddr,
    /// UDP port number for outgoing packets
    #[clap(short = 'p', long, default_value_t = 852)]
    pub remote_port: u16,
    /// UDP port number for incoming packets
    #[clap(short = 'o', long, default_value_t = 852)]
    pub local_port: u16,
    /// Clock source to be used
    #[clap(short, long, default_value = "NTP")]
    pub clock_source: ClockSource,
    // The path to the file to read
    //#[clap(parse(from_os_str))]
    //pub configuration_file: std::path::PathBuf,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), ConfigurationError>
    {

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::ToSocketAddrs;
    use super::*;

    #[test]
    fn validate_configuration_correct_test() {
        let conf = Configuration {
            remote_port: 123,
            remote_addr: Some(IpAddr::from_str("127.0.0.1").unwrap()),
            clock_source: ClockSource::NTP,
            local_port: 123,
            local_addr: IpAddr::from_str("127.0.0.1").unwrap(),
        };

        let res = conf.validate();
        
    }

    #[test]
    fn validate_configuration_incorrect_test() {

    }
}