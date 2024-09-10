#[macro_use]
extern crate log;

pub mod clock_format;
pub mod configuration;
pub mod packets;
pub mod receiver;
pub mod sender;
pub mod session;
pub mod stamp_modes;
pub mod time;

use std::{net::UdpSocket, thread};

use crate::{configuration::*, session::Session};
use clap::Parser;

#[tokio::main]
async fn main() {
    env_logger::init();

    let conf = Configuration::parse();
    conf.validate().expect("Configuration is broken!");

    info!("Configuration valid. Starting up...");

    /*if conf.is_reflector {
        receiver::run_receiver(conf);
    } else {
        sender::run_sender(conf);
    }

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
    }*/
}
