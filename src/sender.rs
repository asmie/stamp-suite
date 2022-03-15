use crate::configuration::*;
use crate::packets::*;
use std::sync::Arc;
use std::net::UdpSocket;
use std::{io, thread};
use std::time::Duration;

pub fn sender_worker(conf :Arc<Configuration>) {
    // Binding to whatever OS will like as this is send-only socket.
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Cannot bind to address");
    socket.connect((conf.remote_addr.unwrap(), conf.remote_port)).expect("Cannot connect to address");

    let curr_seq = 0;

    loop {


        thread::sleep(Duration::from_secs(1));
    }


    socket.send(&[0,1,2,3,4,5,6,7]);
    socket.send(&[10,9,2,3,4,5,6,7]);
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_message_test() {

    }
}


