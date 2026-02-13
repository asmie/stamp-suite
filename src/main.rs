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
        let shared = receiver::create_shared_state(&conf);

        #[cfg(all(unix, feature = "snmp"))]
        let _snmp_server = if conf.snmp {
            match stamp_suite::snmp::init(
                conf.snmp_socket.clone(),
                std::sync::Arc::new(stamp_suite::snmp::state::SnmpState {
                    config: stamp_suite::snmp::state::SnmpConfig {
                        is_reflector: true,
                        listen_addr: conf.local_addr,
                        listen_port: conf.local_port,
                        remote_addr: conf.remote_addr,
                        remote_port: conf.remote_port,
                        auth_mode: conf.auth_mode.to_string(),
                        tlv_mode: conf.tlv_mode,
                        stateful_reflector: conf.stateful_reflector,
                        session_timeout: conf.session_timeout,
                        packet_count: conf.count,
                        send_delay: conf.send_delay,
                    },
                    reflector_counters: Some(std::sync::Arc::clone(&shared.counters)),
                    session_manager: Some(std::sync::Arc::clone(&shared.session_manager)),
                    start_time: shared.start_time,
                    sender_stats: None,
                }),
            )
            .await
            {
                Ok(server) => {
                    info!(
                        "SNMP AgentX sub-agent started (socket: {})",
                        conf.snmp_socket
                    );
                    Some(server)
                }
                Err(e) => {
                    eprintln!("Failed to start SNMP sub-agent: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        #[cfg(not(all(unix, feature = "snmp")))]
        if conf.snmp {
            #[cfg(not(unix))]
            eprintln!(
                "Error: --snmp flag requires a Unix platform (AgentX uses Unix domain sockets)"
            );
            #[cfg(unix)]
            eprintln!("Warning: --snmp flag requires the 'snmp' feature to be enabled");
            #[cfg(not(unix))]
            std::process::exit(1);
        }

        receiver::run_receiver(&conf, &shared).await;
    } else {
        #[cfg(all(unix, feature = "snmp"))]
        let sender_stats = std::sync::Arc::new(stamp_suite::snmp::state::SenderSnmpStats::new());

        #[cfg(all(unix, feature = "snmp"))]
        let _snmp_server = if conf.snmp {
            match stamp_suite::snmp::init(
                conf.snmp_socket.clone(),
                std::sync::Arc::new(stamp_suite::snmp::state::SnmpState {
                    config: stamp_suite::snmp::state::SnmpConfig {
                        is_reflector: false,
                        listen_addr: conf.local_addr,
                        listen_port: conf.local_port,
                        remote_addr: conf.remote_addr,
                        remote_port: conf.remote_port,
                        auth_mode: conf.auth_mode.to_string(),
                        tlv_mode: conf.tlv_mode,
                        stateful_reflector: conf.stateful_reflector,
                        session_timeout: conf.session_timeout,
                        packet_count: conf.count,
                        send_delay: conf.send_delay,
                    },
                    reflector_counters: None,
                    session_manager: None,
                    start_time: std::time::Instant::now(),
                    sender_stats: Some(std::sync::Arc::clone(&sender_stats)),
                }),
            )
            .await
            {
                Ok(server) => {
                    info!(
                        "SNMP AgentX sub-agent started (socket: {})",
                        conf.snmp_socket
                    );
                    Some(server)
                }
                Err(e) => {
                    eprintln!("Failed to start SNMP sub-agent: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        #[cfg(not(all(unix, feature = "snmp")))]
        if conf.snmp {
            #[cfg(not(unix))]
            eprintln!(
                "Error: --snmp flag requires a Unix platform (AgentX uses Unix domain sockets)"
            );
            #[cfg(unix)]
            eprintln!("Warning: --snmp flag requires the 'snmp' feature to be enabled");
            #[cfg(not(unix))]
            std::process::exit(1);
        }

        #[cfg(all(unix, feature = "snmp"))]
        {
            sender::run_sender(&conf, Some(sender_stats))
                .await
                .print(conf.output_format);
        }
        #[cfg(not(all(unix, feature = "snmp")))]
        {
            sender::run_sender(&conf, None)
                .await
                .print(conf.output_format);
        }
    }
}
