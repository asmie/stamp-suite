#[macro_use]
extern crate log;

use std::borrow::Borrow;
use stamp_suite::{configuration, packets, sender, receiver, packets::*};
use crate::configuration::*;

use std::thread;
use std::net::UdpSocket;
use std::io::Read;
use std::mem;
use std::slice;
use std::io;



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


type BufferType = [u8; 65535];

fn worker(conf : Configuration)
{
    let socket = UdpSocket::bind((conf.local_addr, conf.local_port)).expect("Cannot bind to address");

    loop {
        let mut buf : BufferType = [0u8; 65535];

        let (num_bytes_read, src_addr) = loop {
            match socket.recv_from(&mut buf) {
                Ok(n) => break n,
                Err(e) => panic!("encountered IO error: {}", e),
            }
        };

        println!("bytes: {:?}", &buf[..num_bytes_read]);

        let mut packet = read_struct::<PacketUnauthenticated, &[u8]>(&mut buf).unwrap();

        let mut packet_resp = ReflectedPacketUnauthenticated {
            sess_sender_timestamp: packet.timestamp,
            sess_sender_err_estimate: packet.error_estimate,
            sess_sender_seq_number: packet.sequence_number,
            sess_sender_ttl: 0,
            sequence_number: packet.sequence_number,
            error_estimate: packet.error_estimate,
            timestamp:0,
            receive_timestamp: 0,
            mbz1: 0,
            mbz2: 0,
            mbz3a: 0,
            mbz3b: 0,
        };

        let buf_resp = unsafe { any_as_u8_slice::<ReflectedPacketUnauthenticated>(&packet_resp) };

        socket.send_to(buf_resp, src_addr);



    }
}

#[derive(Parser, Debug)]
#[clap(author = "Piotr Olszewski", version, about, long_about = None)]
pub struct Configuration {
    /// Local address to bind for
    #[clap(short = 'S', long, default_value = "0.0.0.0")]
    pub local_addr: std::net::IpAddr,
    /// UDP port number for incoming packets
    #[clap(short = 'o', long, default_value_t = 852)]
    pub local_port: u16,
    /// Clock source to be used
    #[clap(short = 'K', long, default_value = "NTP")]
    pub clock_source: ClockFormat,
    /// Amount of time to wait for packet until consider it lost [s].
    #[clap(short = 'L', default_value_t = 5)]
    pub timeout : u8,
    /// Force IPv4 addresses.
    #[clap(short = '4')]
    pub force_ipv4 : bool,
    /// Force IPv6 addresses.
    #[clap(short = '6')]
    pub force_ipv6 : bool,
    /// Specify work mode - A for auth, E for encryped and O for open mode -  default "AEO".
    #[clap(short = 'A', long, default_value = "AEO")]
    pub auth_mode : String,
    /// Print individual statistics for each packet.
    #[clap(short = 'R')]
    pub print_stats : bool,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), ConfigurationError>
    {

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
    use super::*;

    #[test]
    fn validate_configuration_correct_test() {
        let conf = Configuration {
            clock_source: ClockFormat::NTP,
            local_port: 123,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            print_stats: false,
            auth_mode: String::from("AEO"),
            timeout: 5,
            force_ipv4: false,
            force_ipv6: false,
        };

        assert_eq!((), conf.validate().unwrap());
    }

    #[test]
    fn validate_configuration_incorrect_test() {

    }
}