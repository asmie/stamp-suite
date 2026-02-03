//! STAMP Suite - Simple Two-Way Active Measurement Protocol implementation.
//!
//! This crate provides a client-server application pair for measuring packet loss
//! and network delays according to RFC 8762 and RFC 8972.
//!
//! # Usage
//!
//! Run as a sender (client):
//! ```bash
//! stamp-suite --remote-addr 192.168.1.1 --remote-port 862
//! ```
//!
//! Run as a reflector (server):
//! ```bash
//! stamp-suite -i --local-addr 0.0.0.0 --local-port 862
//! ```

#[macro_use]
extern crate log;

/// Clock format definitions (NTP/PTP).
pub mod clock_format;
/// Command-line configuration and validation.
pub mod configuration;
/// STAMP packet structures and serialization.
pub mod packets;
/// Session Reflector implementations.
pub mod receiver;
/// Session Sender implementation.
pub mod sender;
/// Session state management.
pub mod session;
/// STAMP authentication mode definitions.
pub mod stamp_modes;
/// Timestamp generation utilities.
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
