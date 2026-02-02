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

use crate::configuration::*;
use clap::Parser;

#[tokio::main]
async fn main() {
    env_logger::init();

    let conf = Configuration::parse();
    conf.validate().expect("Configuration is broken!");

    info!("Configuration valid. Starting up...");

    if conf.is_reflector {
        receiver::run_receiver(&conf).await;
    } else {
        let stats = sender::run_sender(&conf).await;
        println!("\n--- STAMP Statistics ---");
        println!("Packets sent: {}", stats.packets_sent);
        println!("Packets received: {}", stats.packets_received);
        println!(
            "Packets lost: {} ({:.1}%)",
            stats.packets_lost,
            if stats.packets_sent > 0 {
                (stats.packets_lost as f64 / stats.packets_sent as f64) * 100.0
            } else {
                0.0
            }
        );
        if let Some(min_rtt) = stats.min_rtt_ns {
            println!("Min RTT: {:.3} ms", min_rtt as f64 / 1_000_000.0);
        }
        if let Some(max_rtt) = stats.max_rtt_ns {
            println!("Max RTT: {:.3} ms", max_rtt as f64 / 1_000_000.0);
        }
        if let Some(avg_rtt) = stats.avg_rtt_ns {
            println!("Avg RTT: {:.3} ms", avg_rtt as f64 / 1_000_000.0);
        }
    }
}
