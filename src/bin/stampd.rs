#[macro_use]
extern crate log;

use stamp_suite::configuration;
use stamp_suite::packets;
use stamp_suite::sender;
use stamp_suite::receiver;

use crate::configuration::*;

use std::thread;
use std::net::UdpSocket;

fn main()
{
    env_logger::init();

    let args = Configuration::parse();
    args.validate().expect("Configuration is broken!");           // Panic if configuration is messed up!

    info!("Configuration valid. Starting up...");

    let worker = thread::spawn(move || worker(args));

    // Now we need to set up the communication channels and implement high-level logic.

    worker.join();
}

fn worker(conf : Configuration)
{
    let socket = UdpSocket::bind((conf.local_addr, conf.local_port)).expect("Cannot bind to address");

    loop {
        let mut buf = [0u8; 65535];

        let (num_bytes_read, _) = loop {
            match socket.recv_from(&mut buf) {
                Ok(n) => break n,
                Err(e) => panic!("encountered IO error: {}", e),
            }
        };



        //println!("bytes: {:?}", &buf[..num_bytes_read]);
    }
}

#[derive(Parser, Debug)]
#[clap(author = "Piotr Olszewski", version, about, long_about = None)]
pub struct Configuration {
    /// Local address to bind for
    #[clap(short, long, default_value = "0.0.0.0")]
    pub local_addr: std::net::IpAddr,
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
    use std::net::IpAddr;
    use super::*;

    #[test]
    fn validate_configuration_correct_test() {
        let conf = Configuration {
            clock_source: ClockSource::NTP,
            local_port: 123,
            local_addr: IpAddr::from_str("127.0.0.1").unwrap(),
        };

        assert_eq!((), conf.validate().unwrap());
    }

    #[test]
    fn validate_configuration_incorrect_test() {

    }
}