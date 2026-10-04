//! STAMP Suite binary entry point.

#[macro_use]
extern crate log;

use std::sync::Arc;

use stamp_suite::{
    configuration::*,
    receiver, sender,
    shutdown::{cancel_on_signal, CancellationToken},
    StartupError,
};

/// Initializes stderr logging, including `log` calls via `tracing-log`.
/// `RUST_LOG` overrides verbosity; `--log-format` selects text or JSON.
/// Stdout is reserved for measurement output.
fn init_logging(format: LogFormat, verbose: u8) {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter_str = resolve_log_filter(verbose, std::env::var("RUST_LOG").ok().as_deref());
    let filter = EnvFilter::try_new(&filter_str).unwrap_or_else(|_| EnvFilter::new("info"));

    match format {
        LogFormat::Text => {
            // Returns Err if a subscriber is already installed (e.g. by
            // a test process in the same address space); discard that
            // case so re-init doesn't panic.
            let _ = fmt()
                .with_writer(std::io::stderr)
                .with_env_filter(filter)
                .with_target(true)
                .try_init();
        }
        LogFormat::Json => {
            let _ = fmt()
                .json()
                .with_writer(std::io::stderr)
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
    // Parse args before initialising logging so we know the user's
    // --log-format choice. Configuration errors go to stderr directly.
    let conf = match Configuration::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    // --print-config-schema is for tooling: print and exit without logging.
    if conf.print_config_schema {
        println!("{}", stamp_suite::configuration::CONFIG_JSON_SCHEMA);
        return;
    }

    init_logging(conf.log_format, conf.verbose);

    // A role that never got off the ground exits non-zero: the shipped
    // systemd unit restarts on failure and reads exit 0 as a deliberate stop.
    if let Err(e) = run(&conf).await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

async fn run(conf: &Configuration) -> Result<(), StartupError> {
    // Probe the bound interface's timestamping capabilities and report
    // startup warnings. Socket setup configures the requested timestamp tier.
    let hw_iface = conf
        .interface
        .clone()
        .or_else(|| stamp_suite::hwtstamp::interface_for_addr(conf.local_addr));
    let hw_cap = stamp_suite::hwtstamp::probe(hw_iface.as_deref());
    log::info!(
        "hwtstamp probe: interface={} rx_hw={} tx_hw={} ptp={}",
        hw_iface.as_deref().unwrap_or("<none/wildcard>"),
        hw_cap.rx_hw,
        hw_cap.tx_hw,
        hw_cap.ptp_supported
    );
    if let stamp_suite::hwtstamp::StartupAction::ContinueWithWarning(msg) =
        stamp_suite::hwtstamp::startup_action(conf.hwtstamp, &hw_cap)
    {
        log::warn!("{msg}");
    }

    if std::env::var("STAMP_HMAC_KEY").is_ok() && conf.hmac_key.is_some() {
        log::warn!(
            "HMAC key loaded from STAMP_HMAC_KEY environment variable. \
             This is less secure than using --hmac-key-file. \
             Environment variables may be visible in /proc/pid/environ and process listings."
        );
    }

    info!("Configuration valid. Starting up...");

    // Bind the requested metrics endpoint before starting the measurement
    // role, so startup cannot silently omit metrics.
    #[cfg(feature = "metrics")]
    let _metrics_server = if conf.metrics {
        let server = stamp_suite::metrics::init(conf.metrics_addr)
            .await
            .map_err(|e| {
                StartupError::service(
                    format!("Cannot start the metrics server on {}", conf.metrics_addr),
                    e,
                )
            })?;
        info!("Metrics server started on {}", conf.metrics_addr);
        Some(server)
    } else {
        None
    };

    if conf.is_reflector {
        run_reflector(conf).await
    } else {
        run_sender(conf).await
    }
}

async fn run_reflector(conf: &Configuration) -> Result<(), StartupError> {
    let shared = Arc::new(receiver::create_shared_state(conf)?);
    cancel_on_signal(shared.shutdown.clone());
    #[cfg(unix)]
    reload_keys_on_hangup(conf, &shared)?;

    // An operator who asked for the control API must not get a reflector
    // that silently runs without it. Design: doc/control-plane.md.
    #[cfg(feature = "control")]
    let _control_server = if conf.control {
        Some(start_control(conf, &shared).await?)
    } else {
        None
    };

    #[cfg(all(unix, feature = "snmp"))]
    let _snmp_server = if conf.snmp {
        start_snmp(
            conf,
            shared.shutdown.clone(),
            stamp_suite::snmp::state::SnmpState {
                config: stamp_suite::snmp::state::SnmpConfig::from_conf(conf),
                reflector_counters: Some(Arc::clone(&shared.counters)),
                session_manager: Some(Arc::clone(&shared.session_manager)),
                start_time: shared.start_time,
                sender_stats: None,
            },
        )
        .await
    } else {
        None
    };

    receiver::run_receiver(conf, &shared).await
}

/// SIGHUP reloads the HMAC keys from their configured file or directory.
#[cfg(unix)]
fn reload_keys_on_hangup(
    conf: &Configuration,
    shared: &Arc<receiver::ReceiverSharedState>,
) -> Result<(), StartupError> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hangup = signal(SignalKind::hangup())
        .map_err(|e| StartupError::io("Cannot install the SIGHUP handler", e))?;
    let conf = conf.clone();
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            match receiver::reload_keys(&conf, &shared) {
                Ok(count) => info!("SIGHUP: reloaded HMAC keys ({count} per-SSID)"),
                Err(e) => log::warn!("SIGHUP: keeping the current HMAC keys: {e}"),
            }
        }
    });
    Ok(())
}

async fn run_sender(conf: &Configuration) -> Result<(), StartupError> {
    let shutdown = CancellationToken::new();
    cancel_on_signal(shutdown.clone());

    #[allow(unused_mut)]
    let mut observers = sender::SenderObservers::default();
    #[cfg(feature = "metrics")]
    if conf.metrics {
        observers.push(Arc::new(
            stamp_suite::metrics::sender_metrics::PrometheusSenderObserver,
        ));
    }

    #[cfg(all(unix, feature = "snmp"))]
    let _snmp_server = if conf.snmp {
        let stats = Arc::new(stamp_suite::snmp::state::SenderSnmpStats::new());
        observers.push(stats.clone());
        start_snmp(
            conf,
            shutdown.clone(),
            stamp_suite::snmp::state::SnmpState {
                config: stamp_suite::snmp::state::SnmpConfig::from_conf(conf),
                reflector_counters: None,
                session_manager: None,
                start_time: std::time::Instant::now(),
                sender_stats: Some(stats),
            },
        )
        .await
    } else {
        None
    };

    let output = stamp_suite::stats::StatsOutput::new(conf.output_format)
        .map_err(|e| StartupError::io("Cannot start measurement output", e))?;
    for stats in sender::run_senders(conf, &output, observers, shutdown).await? {
        output
            .print_final(stats)
            .await
            .map_err(|e| StartupError::io("Cannot write measurement output", e))?;
    }
    Ok(())
}

#[cfg(feature = "control")]
async fn start_control(
    conf: &Configuration,
    shared: &receiver::ReceiverSharedState,
) -> Result<stamp_suite::control::ControlServer, StartupError> {
    let token = match conf.control_token_file.as_deref() {
        // Same descriptor-based permission check as HMAC key files: a
        // group/world-readable token hands any local user the key-management
        // and shutdown endpoints.
        Some(path) => Some(
            stamp_suite::crypto::read_token_file(path)
                .map_err(|e| StartupError::service(format!("Cannot read {}", path.display()), e))?
                .trim()
                .to_string(),
        ),
        None => None,
    };
    let state = stamp_suite::control::ControlState {
        counters: Arc::clone(&shared.counters),
        session_manager: Arc::clone(&shared.session_manager),
        start_time: shared.start_time,
        rate_limiter: Arc::clone(&shared.rate_limiter),
        hmac_keys: Arc::clone(&shared.hmac_keys),
        caps: Arc::clone(&shared.caps),
        shutdown: shared.shutdown.clone(),
        token,
    };
    // Load the certificate and key before binding, so a bad path fails at
    // startup rather than on the first request.
    let tls = match (&conf.control_tls_cert, &conf.control_tls_key) {
        (Some(cert), Some(key)) => Some(
            stamp_suite::control::ControlTls::load(cert, key).map_err(|e| {
                StartupError::service("Cannot load the control-plane TLS material", e)
            })?,
        ),
        _ => None,
    };
    stamp_suite::control::init(conf.control_addr, state, tls)
        .await
        .map_err(|e| {
            StartupError::io(
                format!("Cannot start the control API on {}", conf.control_addr),
                e,
            )
        })
}

/// Starts the AgentX sub-agent. Without a reachable master agent the
/// measurement still runs; the failure is logged.
#[cfg(all(unix, feature = "snmp"))]
async fn start_snmp(
    conf: &Configuration,
    shutdown: CancellationToken,
    state: stamp_suite::snmp::state::SnmpState,
) -> Option<stamp_suite::snmp::SnmpServer> {
    match stamp_suite::snmp::init_with_shutdown(conf.snmp_socket.clone(), Arc::new(state), shutdown)
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
            log::warn!("SNMP sub-agent disabled: {} (continuing without SNMP)", e);
            None
        }
    }
}
