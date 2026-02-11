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

    // Initialize metrics server if enabled
    #[cfg(feature = "metrics")]
    let _metrics_server = if conf.metrics {
        match stamp_suite::metrics::init(conf.metrics_addr).await {
            Ok(server) => {
                info!("Metrics server started on {}", conf.metrics_addr);
                Some(server)
            }
            Err(e) => {
                eprintln!("Failed to start metrics server: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    #[cfg(not(feature = "metrics"))]
    if conf.metrics {
        eprintln!("Warning: --metrics flag requires the 'metrics' feature to be enabled");
    }

    if conf.is_reflector {
        receiver::run_receiver(&conf).await;
    } else {
        sender::run_sender(&conf).await.print(conf.output_format);
    }
}
