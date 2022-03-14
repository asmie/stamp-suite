use crate::configuration::*;
use std::sync::Arc;
use std::net::UdpSocket;
use std::io;

pub fn sender_worker(conf :Arc<Configuration>) {
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Cannot bind to address");
    socket.connect((conf.remote_addr.unwrap(), conf.remote_port)).expect("Cannot connect to address");

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


