//! STAMP Suite binary entry point.

#[macro_use]
extern crate log;

use clap::Parser;
use stamp_suite::configuration::*;
use stamp_suite::{receiver, sender};

#[tokio::main]
async fn main() {
    env_logger::init();

    let conf = Configuration::parse();
    if let Err(e) = conf.validate() {
        eprintln!("Configuration error: {}", e);
        std::process::exit(1);
    }

    info!("Configuration valid. Starting up...");

    if conf.is_reflector {
        receiver::run_receiver(&conf).await;
    } else {
        sender::run_sender(&conf).await.print_summary();
    }
}
