#[macro_use]
extern crate log;

use std::borrow::Borrow;
use stamp_suite::{configuration, packets, sender, receiver::*, packets::*};
use crate::configuration::*;

use std::thread;
use std::net::UdpSocket;
use std::io::Read;
use std::mem;
use std::slice;
use std::io;
use stamp_suite::time::generate_timestamp;
//use std::os::unix::io::AsRawFd;
//use nix::sys::socket;
//use nix::sys::socket::setsockopt;
//use nix::sys::socket::sockopt;

fn main()
{
    env_logger::init();

    let args = Configuration::parse();
    args.validate().expect("Configuration is broken!");           // Panic if configuration is messed up!

    info!("Configuration valid. Starting up...");

    let worker = thread::spawn(move || worker(args));

    worker.join();
}


type BufferType = [u8; 65535];

fn worker(conf : Configuration)
{
    let socket = UdpSocket::bind((conf.local_addr, conf.local_port)).expect("Cannot bind to address");
    //let raw_fd: RawFd = socket.as_raw_fd();

    //setsockopt(raw_fd, sockopt::IpRecvErr, &true).expect("sockopt failed");
    //setsockopt(raw_fd, sockopt::IpRecvTtl, &true).expect("sockopt failed");
    //setsockopt(raw_fd, sockopt::IpMtuDiscover, &true).expect("sockopt failed");

    loop {
        let mut buf : BufferType = [0u8; 65535];

        let (num_bytes_read, src_addr) = socket.recv_from(&mut buf).expect("socket error!");
        let rcv_timestamp = generate_timestamp(conf.clock_source);

        println!("bytes: {:?}", &buf[..num_bytes_read]);

        let mut packet = read_struct::<PacketUnauthenticated, &[u8]>(&mut buf).unwrap();

        let mut packet_resp = assemble_unauth_answer(&packet, conf.clock_source, rcv_timestamp);

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