use std::{error::Error, fmt, str::FromStr};

pub use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author = "Piotr Olszewski", version, about, long_about = None)]
pub struct Configuration {
    /// Remote address for Session Reflector
    #[clap(short, long)]
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
    /// Amount of time to wait for packet until consider it lost [s].
    #[clap(short = 'L', default_value_t = 5)]
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
    #[clap(short = 'd', long, default_value = false)]
    pub is_reflector: bool,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        Ok(())
    }
}

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

    #[test]
    fn clock_source_test() {}
}
