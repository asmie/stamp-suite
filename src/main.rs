mod configuration;
mod packets;
mod sender;
mod receiver;

use crate::configuration::*;
use std::thread;

use std::sync::Arc;

fn main()
{
    let receiver;
    let sender;

    let args = Configuration::parse();
    args.validate().expect("Configuration is broken!");           // Panic if configuration is messed up!

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
