#[macro_use]
extern crate log;

use stamp_suite::configuration;
use stamp_suite::packets;
use stamp_suite::sender;
use stamp_suite::receiver;

use crate::configuration::*;
use std::thread;

use std::sync::Arc;

fn main()
{
    env_logger::init();

    let receiver;
    let sender;


    let args = Configuration::parse();
    args.validate().expect("Configuration is broken!");           // Panic if configuration is messed up!

    info!("Configuration valid. Starting up...");

    let args_ptr = Arc::new(args);

    // Configuration is now known and correct and cannot change during the execution. So spawn the ogars :)
    {
        let arg = args_ptr.clone();
        receiver = thread::spawn(move || receiver::receive_worker(arg));
    }
    {
        let arg = args_ptr.clone();
        sender = thread::spawn(move || sender::sender_worker(arg));
    }

    // Now we need to set up the communication channels and implement high-level logic.


    receiver.join();
    sender.join();
}
