//! State shared by the reflector backends, the control plane and SNMP.

use super::*;

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
    /// Per-SSID HMAC keyset; runtime-mutable via the control plane. The
    /// legacy single `--hmac-key` stays startup-immutable and backend-local.
    /// Packet loops take short read guards that never cross an `.await`.
    pub hmac_keys: Arc<std::sync::RwLock<Option<crate::crypto::HmacKeySet>>>,
    /// Runtime-adjustable reflector caps (see [`RuntimeCaps`]).
    pub caps: Arc<RuntimeCaps>,
    /// Cancelled by a signal (see [`crate::shutdown::cancel_on_signal`]) or
    /// the control API. Both backends then drain queued replies and return.
    pub shutdown: crate::shutdown::CancellationToken,
}

/// Reloads the HMAC keys from the configured key file or directory and
/// replaces the reflector's keyset, including keys added through the control
/// API. On error the current keyset stays in place. Returns the number of
/// per-SSID keys loaded.
///
/// # Errors
/// Fails when no key source is configured or the source cannot be loaded.
pub fn reload_keys(
    conf: &Configuration,
    shared: &ReceiverSharedState,
) -> Result<usize, crate::StartupError> {
    let source = conf.key_source();
    if !source.is_configured() {
        return Err(crate::StartupError::config(
            "no HMAC key source is configured",
        ));
    }
    let set = source.load_key_set()?;
    let count = set.as_ref().map_or(0, |set| set.ssids().len());
    *shared.hmac_keys.write().unwrap_or_else(|e| e.into_inner()) = set;
    Ok(count)
}

/// Creates the shared state for the receiver, using configuration values.
pub fn create_shared_state(
    conf: &Configuration,
) -> Result<ReceiverSharedState, crate::StartupError> {
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

    let provisioned = conf
        .provisioned_sessions()
        .map_err(crate::StartupError::config)?;
    let hmac_keys = conf.key_source().load_key_set()?;

    #[allow(unused_mut)]
    let mut counters = ReflectorCounters::new();
    #[cfg(feature = "metrics")]
    {
        counters.metrics_enabled = conf.metrics;
    }
    Ok(ReceiverSharedState {
        counters: Arc::new(counters),
        session_manager: Arc::new(SessionManager::with_admission(
            session_timeout,
            max_sessions,
            conf.session_admission,
            provisioned,
        )),
        start_time: Instant::now(),
        rate_limiter,
        hmac_keys: Arc::new(std::sync::RwLock::new(hmac_keys)),
        caps: Arc::new(RuntimeCaps::from_conf(conf)),
        shutdown: crate::shutdown::CancellationToken::new(),
    })
}

/// Builds and prints the reflector shutdown statistics.
pub(crate) fn print_reflector_stats(
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
    if let Err(error) = stats.write_report(&mut std::io::stdout().lock(), output_format) {
        log::error!("Cannot write reflector summary: {error}");
    }
}
