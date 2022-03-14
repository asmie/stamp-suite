use crate::configuration::*;
use std::sync::Arc;
use std::net::UdpSocket;
use std::io;

pub fn receive_worker(conf :Arc<Configuration>) {
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