//! SNMP AgentX sub-agent for STAMP-SUITE-MIB.
//!
//! Connects to an existing net-snmpd master agent via Unix socket (AgentX protocol,
//! RFC 2741) and exposes reflector/sender configuration, counters, and session state.
//!
//! # Usage
//!
//! ```bash
//! # Start with default AgentX socket
//! stamp-suite -i --snmp
//!
//! # Custom AgentX socket path
//! stamp-suite -i --snmp --snmp-socket /var/agentx/master
//! ```
//!
//! # Production-path panic audit
//!
//! All buffer indexing in the AgentX decoder (`agentx::decode_header`,
//! `agentx::decode_oid`, `agentx::decode_search_range`,
//! `agentx::AgentXSession::handle_get_bulk`) is preceded by an explicit length
//! check that returns `AgentXError::Protocol`. The `MibHandler` dispatch
//! (`handler::StampMibHandler::get`/`get_next`) bounds-checks OIDs via
//! `Oid::starts_with` before any `oid.0[i]` indexing. There are no `unwrap()`,
//! `expect()`, `panic!`, or `unreachable!()` reachable from the AgentX event
//! loop in `agentx.rs`, `handler.rs`, or `state.rs` outside `#[cfg(test)]`.
//!
//! For belt-and-braces, the `spawn_blocking` join handle is observed by a
//! supervisor task that logs panics rather than silently dropping them.

pub mod agentx;
mod handler;
pub mod oids;
pub mod state;

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use handler::StampMibHandler;
use state::SnmpState;

/// Error type for SNMP initialization failures.
#[derive(Debug, thiserror::Error)]
pub enum SnmpError {
    /// Failed to connect to the AgentX master agent.
    #[error("Failed to connect to AgentX master agent: {0}")]
    ConnectionFailed(#[from] agentx::AgentXError),
    /// Failed to connect to the AgentX socket.
    #[error("Failed to connect to AgentX socket: {0}")]
    IoError(#[from] std::io::Error),
}

/// Handle to the running SNMP sub-agent.
pub struct SnmpServer {
    cancel: Arc<AtomicBool>,
}

impl SnmpServer {
    /// Signals the SNMP sub-agent to shut down.
    pub fn shutdown(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Description string sent to the AgentX master on every (re)connect.
const AGENTX_DESCRIPTION: &str = "stamp-suite SNMP sub-agent";

/// Initial reconnect backoff after an AgentX session drops.
const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(1);

/// Maximum reconnect backoff (cap for the exponential growth).
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Initializes the SNMP AgentX sub-agent.
///
/// Connects to the master agent, registers the STAMP-SUITE-MIB subtree,
/// and spawns a blocking task for the AgentX event loop. If the master later
/// closes the session or the socket errors (e.g. net-snmpd restarts), the
/// background task reconnects with capped exponential backoff until shutdown
/// is requested — the sub-agent no longer stays down for the life of the
/// process after a single master restart.
///
/// The initial connect/register is performed synchronously so a misconfigured
/// socket path is reported to the caller (fail-fast) rather than retried
/// silently forever.
///
/// # Arguments
/// * `socket_path` - Path to the AgentX master agent Unix socket
/// * `state` - Shared state for the MIB handler
pub async fn init(socket_path: String, state: Arc<SnmpState>) -> Result<SnmpServer, SnmpError> {
    let cancel = Arc::new(AtomicBool::new(false));

    // Validate connectivity up front (fail-fast on a bad socket path).
    let mut session = agentx::AgentXSession::connect(&socket_path, AGENTX_DESCRIPTION)?;
    session.register(&oids::stamp_suite_root())?;

    log::info!("SNMP AgentX sub-agent connected to {}", socket_path);

    // Spawn the event loop in a blocking task (synchronous socket I/O), wrapped
    // in a reconnect loop. The first iteration reuses the validated session.
    let cancel_loop = Arc::clone(&cancel);
    let join = tokio::task::spawn_blocking(move || {
        let handler = StampMibHandler::new(state);
        let mut session = session;
        loop {
            if let Err(e) = session.run_loop(&handler, &cancel_loop) {
                if !cancel_loop.load(Ordering::Relaxed) {
                    log::warn!("AgentX event loop error: {e}; will attempt to reconnect");
                }
            }
            // run_loop returned: either we were asked to shut down, or the
            // master went away. Stop on shutdown; otherwise reconnect.
            if cancel_loop.load(Ordering::Relaxed) {
                break;
            }
            match reconnect(&socket_path, &cancel_loop) {
                Some(s) => session = s,
                None => break, // cancellation requested during backoff
            }
        }
        log::info!("SNMP AgentX sub-agent stopped");
    });

    // Supervisor: log a panic in the blocking task rather than dropping it
    // silently (which would leave the sub-agent dead with no signal).
    let cancel_for_supervisor = Arc::clone(&cancel);
    tokio::spawn(async move {
        if let Err(join_err) = join.await {
            if !cancel_for_supervisor.load(Ordering::Relaxed) {
                if join_err.is_panic() {
                    log::error!("AgentX event loop panicked: {join_err}; SNMP sub-agent is down");
                } else {
                    log::error!("AgentX event loop terminated abnormally: {join_err}");
                }
            }
        }
    });

    Ok(SnmpServer { cancel })
}

/// (Re)connects to the AgentX master and re-registers the subtree, retrying
/// with capped exponential backoff until it succeeds or `cancel` is set.
///
/// Returns `None` if shutdown was requested before a connection was
/// re-established.
fn reconnect(socket_path: &str, cancel: &AtomicBool) -> Option<agentx::AgentXSession> {
    let mut backoff = RECONNECT_BACKOFF_START;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        match agentx::AgentXSession::connect(socket_path, AGENTX_DESCRIPTION) {
            Ok(mut session) => match session.register(&oids::stamp_suite_root()) {
                Ok(()) => {
                    log::info!("SNMP AgentX sub-agent reconnected to {socket_path}");
                    return Some(session);
                }
                Err(e) => {
                    log::warn!("AgentX re-registration failed: {e}; retrying in {backoff:?}");
                }
            },
            Err(e) => {
                log::debug!("AgentX reconnect to {socket_path} failed: {e}; retrying in {backoff:?}");
            }
        }
        sleep_cancellable(backoff, cancel);
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// Sleeps for up to `dur`, returning early if `cancel` becomes set. Runs on the
/// blocking thread, so it polls `cancel` in short steps to stay responsive to
/// shutdown.
fn sleep_cancellable(dur: Duration, cancel: &AtomicBool) {
    let step = Duration::from_millis(200);
    let mut remaining = dur;
    while !remaining.is_zero() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let s = remaining.min(step);
        std::thread::sleep(s);
        remaining -= s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_sleep_cancellable_returns_early_when_cancelled() {
        let cancel = AtomicBool::new(true);
        let start = Instant::now();
        sleep_cancellable(Duration::from_secs(10), &cancel);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "must return promptly when already cancelled"
        );
    }

    #[test]
    fn test_reconnect_returns_none_when_cancelled() {
        // Already cancelled: reconnect must bail immediately without attempting
        // (or blocking on) a connection.
        let cancel = AtomicBool::new(true);
        let start = Instant::now();
        assert!(reconnect("/nonexistent/stamp-agentx.sock", &cancel).is_none());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
