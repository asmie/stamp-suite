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

    // Spawn the event loop in a blocking task (synchronous socket I/O)
    tokio::task::spawn_blocking(move || {
        let handler = StampMibHandler::new(state);
        if let Err(e) = session.run_loop(&handler, &cancel_clone) {
            if !cancel_clone.load(Ordering::Relaxed) {
                log::error!("AgentX event loop error: {}", e);
            }
        }
    });

    Ok(SnmpServer { cancel })
}
