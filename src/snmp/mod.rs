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

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
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

/// Initializes the SNMP AgentX sub-agent.
///
/// Connects to the master agent, registers the STAMP-SUITE-MIB subtree,
/// and spawns a blocking task for the AgentX event loop.
///
/// # Arguments
/// * `socket_path` - Path to the AgentX master agent Unix socket
/// * `state` - Shared state for the MIB handler
pub async fn init(socket_path: String, state: Arc<SnmpState>) -> Result<SnmpServer, SnmpError> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_clone = cancel.clone();

    // Test connectivity before spawning the background task
    let mut session = agentx::AgentXSession::connect(&socket_path, "stamp-suite SNMP sub-agent")?;
    session.register(&oids::stamp_suite_root())?;

    log::info!("SNMP AgentX sub-agent connected to {}", socket_path);

    // Spawn the event loop in a blocking task (synchronous socket I/O).
    // A separate supervisor `tokio::spawn` awaits the JoinHandle so that an
    // unforeseen panic in the handler dispatch is logged rather than silently
    // dropped on the floor (which would leave the SNMP sub-agent dead with no
    // signal to operators).
    let cancel_for_supervisor = Arc::clone(&cancel);
    let join = tokio::task::spawn_blocking(move || {
        let handler = StampMibHandler::new(state);
        if let Err(e) = session.run_loop(&handler, &cancel_clone) {
            if !cancel_clone.load(Ordering::Relaxed) {
                log::error!("AgentX event loop error: {}", e);
            }
        }
    });
    tokio::spawn(async move {
        if let Err(join_err) = join.await {
            if !cancel_for_supervisor.load(Ordering::Relaxed) {
                if join_err.is_panic() {
                    log::error!(
                        "AgentX event loop panicked: {}; SNMP sub-agent is down",
                        join_err
                    );
                } else {
                    log::error!("AgentX event loop terminated abnormally: {}", join_err);
                }
            }
        }
    });

    Ok(SnmpServer { cancel })
}
