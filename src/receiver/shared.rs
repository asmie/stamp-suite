//! State shared by the reflector backends, the control plane and SNMP.

use super::*;

/// Ctrl-C on all platforms and SIGTERM on Unix use the same queue shutdown policy.
pub(super) fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    // Register Unix listeners synchronously before accepting any traffic.
    #[cfg(unix)]
    let signals = (
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()),
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()),
    );
    async move {
        #[cfg(unix)]
        if let (Ok(mut interrupt), Ok(mut terminate)) = signals {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            return;
        }
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Shared state created externally and passed into receiver backends.
///
/// This allows the SNMP sub-agent, the control plane, and other
/// subsystems to access reflector counters and session state concurrently.
pub struct ReceiverSharedState {
    pub counters: Arc<ReflectorCounters>,
    pub session_manager: Arc<SessionManager>,
    pub start_time: Instant,
    /// Always constructed; `rate() == 0` means unlimited, so limiting can
    /// be enabled at runtime via the control plane.
    pub rate_limiter: Arc<RateLimiter>,
    /// Flag observable by a future readiness probe (and the pnet
    /// `spawn_blocking` join path). Set to `false` when the capture / receive
    /// loop exits unexpectedly so external monitors can distinguish
    /// "process alive but not reflecting" from "process alive and healthy".
    pub capture_alive: Arc<std::sync::atomic::AtomicBool>,
    /// Per-SSID HMAC keyset; runtime-mutable via the control plane. The
    /// legacy single `--hmac-key` stays startup-immutable and backend-local.
    /// Packet loops take short read guards that never cross an `.await`.
    pub hmac_keys: Arc<std::sync::RwLock<Option<crate::crypto::HmacKeySet>>>,
    /// Runtime-adjustable reflector caps (see [`RuntimeCaps`]).
    pub caps: Arc<RuntimeCaps>,
    /// Set by the control plane's shutdown endpoint; both backends poll it
    /// and exit gracefully.
    pub shutdown_requested: Arc<std::sync::atomic::AtomicBool>,
}

/// Creates the shared state for the receiver, using configuration values.
pub fn create_shared_state(conf: &Configuration) -> ReceiverSharedState {
    let session_timeout = if conf.session_timeout > 0 {
        Some(Duration::from_secs(conf.session_timeout))
    } else {
        None
    };

    // Always constructed: rate 0 short-circuits to "allow", and the
    // control plane can raise the rate at runtime.
    let rate_limiter = Arc::new(RateLimiter::with_burst(
        conf.max_pps,
        conf.reflector_rate_burst,
    ));

    // Bound the session table so an unauthenticated peer cannot grow it until
    // the process is OOM-killed (0 = operator-disabled, unlimited).
    let max_sessions = if conf.max_sessions > 0 {
        Some(conf.max_sessions as usize)
    } else {
        None
    };

    ReceiverSharedState {
        counters: Arc::new(ReflectorCounters::new()),
        session_manager: Arc::new(match conf.provisioned_sessions() {
            Ok(keys) => SessionManager::with_admission(
                session_timeout,
                max_sessions,
                conf.session_admission,
                keys,
            ),
            Err(error) => {
                // Startup validates first. Library callers that skip validation
                // must still fail closed rather than enabling permissive admission.
                log::error!("Invalid session admission configuration: {error}");
                SessionManager::with_admission(
                    session_timeout,
                    max_sessions,
                    crate::session::SessionAdmission::Provisioned,
                    Default::default(),
                )
            }
        }),
        start_time: Instant::now(),
        rate_limiter,
        capture_alive: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        hmac_keys: Arc::new(std::sync::RwLock::new(load_hmac_key_set(conf))),
        caps: Arc::new(RuntimeCaps::from_conf(conf)),
        shutdown_requested: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

/// Builds and prints the reflector shutdown statistics.
pub fn print_reflector_stats(
    counters: &ReflectorCounters,
    session_manager: &SessionManager,
    start_time: Instant,
    output_format: OutputFormat,
) {
    let mut stats = stats::build_reflector_stats(
        counters.packets_received.load(Ordering::Relaxed),
        counters.packets_reflected.load(Ordering::Relaxed),
        counters.packets_dropped.load(Ordering::Relaxed),
        session_manager.session_summaries_by_key(),
        session_manager.session_count(),
        start_time.elapsed().as_secs_f64(),
    );
    stats.reply_queue_rejected = counters.reply_queue_rejected.load(Ordering::Relaxed);
    stats.queued_replies_cancelled = counters.queued_replies_cancelled.load(Ordering::Relaxed);
    stats.print(output_format);
}
