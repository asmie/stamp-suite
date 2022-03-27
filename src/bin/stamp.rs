#[macro_use]
extern crate log;

use stamp_suite::configuration;
use stamp_suite::packets;
use stamp_suite::sender;
use stamp_suite::receiver;

use crate::configuration::*;

use std::net::UdpSocket;
use std::{io, thread};
use std::time::Duration;

use std::sync::Arc;

fn main()
{
    env_logger::init();

    let args = Configuration::parse();
    args.validate().expect("Configuration is broken!");           // Panic if configuration is messed up!

    info!("Configuration valid. Starting up...");

    // Now we need to set up the communication channels and implement high-level logic.

    // Binding to whatever OS will like as this is send-only socket.
    //let socket = UdpSocket::bind("0.0.0.0:0").expect("Cannot bind to address");
    //socket.connect((conf.remote_addr.unwrap(), conf.remote_port)).expect("Cannot connect to address");

    let curr_seq = 0;

    loop {


        thread::sleep(Duration::from_secs(1));
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
    pub clock_source: ClockFormat,
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