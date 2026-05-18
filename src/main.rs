//! STAMP Suite binary entry point.

#[macro_use]
extern crate log;

use stamp_suite::configuration::*;
use stamp_suite::{receiver, sender};

/// Initialise diagnostic logging via `tracing-subscriber`. Bridges
/// existing `log::*` call sites via `tracing-log` (enabled by the
/// `tracing-log` feature in Cargo.toml) so the migration from
/// `env_logger` is transparent to the rest of the codebase.
///
/// Verbosity continues to be controlled by `RUST_LOG`; the new
/// `--log-format` flag selects between human-readable text (default,
/// matches the historic `env_logger` output) and one-line JSON for
/// structured log shippers.
fn init_logging(format: LogFormat) {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        LogFormat::Text => {
            // Returns Err if a subscriber is already installed (e.g. by
            // a test process in the same address space); discard that
            // case so re-init doesn't panic.
            let _ = fmt().with_env_filter(filter).with_target(true).try_init();
        }
        LogFormat::Json => {
            let _ = fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .with_current_span(false)
                .with_span_list(false)
                .try_init();
        }
    }
}

#[tokio::main]
async fn main() {
    // Parse args BEFORE initialising logging so we know the user's
    // --log-format choice. Errors from Configuration::load are printed
    // raw to stderr; the tracing layer isn't up yet.
    let conf = match Configuration::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    // --print-config-schema: dump the JSON Schema and exit. Side-stepping
    // logger init is intentional — this path is for tooling, not for
    // operators tailing journalctl.
    if conf.print_config_schema {
        println!("{}", stamp_suite::configuration::CONFIG_JSON_SCHEMA);
        return;
    }

    init_logging(conf.log_format);

    // F1: when the operator explicitly requested HW timestamping via
    // --hwtstamp on, fail-fast if the host probe says it's unavailable.
    // `auto` and `off` always continue; `auto` will silently use SW.
    if matches!(conf.hwtstamp, stamp_suite::configuration::HwTsMode::On) {
        let cap = stamp_suite::hwtstamp::probe(None);
        if !cap.any_hw_supported() {
            eprintln!(
                "--hwtstamp on requires hardware timestamping but the host probe \
                 reported no capability. Build with --features hwtstamp on a \
                 capable NIC, or use --hwtstamp auto/off to fall back to software."
            );
            std::process::exit(1);
        }
    }

    if std::env::var("STAMP_HMAC_KEY").is_ok() && conf.hmac_key.is_some() {
        log::warn!(
            "HMAC key loaded from STAMP_HMAC_KEY environment variable. \
             This is less secure than using --hmac-key-file. \
             Environment variables may be visible in /proc/pid/environ and process listings."
        );
    }

    info!("Configuration valid. Starting up...");

    // Initialize metrics server if enabled.
    //
    // Metrics is fail-fast: if the operator passed --metrics they want
    // observability, and silently disabling the endpoint would hide that
    // their dashboards and alerts are running blind. Surface the underlying
    // bind error (port in use vs. address not available vs. permission
    // denied) so the cause is obvious in journalctl.
    #[cfg(feature = "metrics")]
    let _metrics_server = if conf.metrics {
        match stamp_suite::metrics::init(conf.metrics_addr).await {
            Ok(server) => {
                info!("Metrics server started on {}", conf.metrics_addr);
                Some(server)
            }
            Err(stamp_suite::metrics::MetricsError::BindError(io_err)) => {
                let detail = match io_err.kind() {
                    std::io::ErrorKind::AddrInUse => "address already in use",
                    std::io::ErrorKind::AddrNotAvailable => "address not available on this host",
                    std::io::ErrorKind::PermissionDenied => "permission denied (privileged port?)",
                    _ => "bind failed",
                };
                eprintln!(
                    "Failed to start metrics server on {}: {} ({})",
                    conf.metrics_addr, detail, io_err
                );
                std::process::exit(1);
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
                    // SNMP is graceful: if the AgentX master is absent
                    // (e.g. net-snmpd not running yet during boot, or the
                    // socket is unreachable), the reflector's primary duty
                    // — forwarding STAMP packets — is unaffected. Log the
                    // failure and continue without SNMP rather than killing
                    // the daemon. Operators who want SNMP-required-to-start
                    // semantics can wrap stamp-suite in a systemd unit
                    // ordered after snmpd.service.
                    log::warn!("SNMP sub-agent disabled: {} (continuing without SNMP)", e);
                    None
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
                    // SNMP is graceful: if the AgentX master is absent
                    // (e.g. net-snmpd not running yet during boot, or the
                    // socket is unreachable), the reflector's primary duty
                    // — forwarding STAMP packets — is unaffected. Log the
                    // failure and continue without SNMP rather than killing
                    // the daemon. Operators who want SNMP-required-to-start
                    // semantics can wrap stamp-suite in a systemd unit
                    // ordered after snmpd.service.
                    log::warn!("SNMP sub-agent disabled: {} (continuing without SNMP)", e);
                    None
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
