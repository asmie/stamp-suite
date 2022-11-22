#[macro_use]
extern crate log;

use crate::configuration::*;
use stamp_suite::{configuration, packets::*};

use std::net::UdpSocket;
use std::thread;

use stamp_suite::sender::{assemble_auth_packet, assemble_unauth_packet};
use stamp_suite::session::Session;
use stamp_suite::time::generate_timestamp;

fn main() {
    env_logger::init();

    let conf = Configuration::parse();
    conf.validate().expect("Configuration is broken!");

    info!("Configuration valid. Starting up...");

    let socket =
        UdpSocket::bind((conf.local_addr, conf.local_port)).expect("Cannot bind to address");
    socket
        .connect((conf.remote_addr, conf.remote_port))
        .expect("Cannot connect to address");

    let sess = Session::new(0); // Client has no multi-sess right now.

    loop {
        if is_auth(&conf.auth_mode) {
            let mut packet = assemble_auth_packet();
            packet.sequence_number = sess.generate_sequence_number();
            packet.timestamp = generate_timestamp(conf.clock_source);
            let buf = any_as_u8_slice(&packet).unwrap();
            socket.send(&buf).unwrap();
        } else {
            let mut packet = assemble_unauth_packet();
            packet.sequence_number = sess.generate_sequence_number();
            packet.timestamp = generate_timestamp(conf.clock_source);
            let buf = any_as_u8_slice(&packet).unwrap();
            socket.send(&buf).unwrap();
        }

        thread::sleep(std::time::Duration::from_millis(conf.send_delay as u64));
    }
}

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
    #[clap(short = 'p', long, default_value_t = 852)]
    pub remote_port: u16,
    /// UDP port number for incoming packets
    #[clap(short = 'o', long, default_value_t = 852)]
    pub local_port: u16,
    /// Clock source to be used
    #[clap(short = 'K', long, default_value = "NTP")]
    pub clock_source: ClockFormat,
    /// Delay between next packets
    #[clap(short = 'd', long, default_value_t = 1000)]
    pub send_delay: u16,
    /// Count of packets to be sent
    #[clap(short = 'c', long, default_value_t = 852)]
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
    /// Specify work mode - A for auth, E for encryped and O for open mode -  default "AEO".
    #[clap(short = 'A', long, default_value = "AEO")]
    pub auth_mode: String,
    /// Print individual statistics for each packet.
    #[clap(short = 'R')]
    pub print_stats: bool,
}

impl Configuration {
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        Ok(())
    }
}
