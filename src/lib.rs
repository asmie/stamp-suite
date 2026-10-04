//! STAMP Suite - Simple Two-Way Active Measurement Protocol implementation.
//!
//! Sender and reflector for measuring packet loss and network delay
//! according to RFC 8762 and RFC 8972.
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
//!
//! # Stability
//!
//! The stable 1.x interface is the CLI, configuration schema, and wire behavior.
//! Library modules are public for integration tests, benchmarks, and fuzzing;
//! they are internal and may change in any 1.x release. MSRV: Rust 1.86.

#[doc(hidden)]
pub mod ber;

/// Clock format definitions (NTP/PTP).
#[doc(hidden)]
pub mod clock_format;

/// Command-line configuration and validation.
#[doc(hidden)]
pub mod configuration;
/// Reflector CoS admission policy: which DSCP and ECN values a reply may use.
#[doc(hidden)]
pub mod cos_policy;
mod net_policy;
mod net_scope;

#[doc(hidden)]
pub mod crypto;

/// Error estimate encoding/decoding for timestamps.
#[doc(hidden)]
pub mod error_estimate;
/// Kernel/hardware timestamping with software fallback.
/// Linux supports RX/TX; macOS supports software RX. See [`hwtstamp`]
/// and `doc/architecture.md` for platform support and PHC requirements.
#[doc(hidden)]
pub mod hwtstamp;
#[doc(hidden)]
pub mod log_throttle;
/// STAMP packet structures and serialization.
#[doc(hidden)]
pub mod packets;
/// AIMD response to CE-marked replies (draft-ietf-ippm-stamp-cos-ecn-01 §3.4),
/// driven by `sender::run_sender`.
#[doc(hidden)]
pub mod rate_control;
/// Session Reflector implementations.
#[doc(hidden)]
pub mod receiver;
/// Process shutdown on signals and control-API requests.
pub mod shutdown;

/// The TOS / Traffic Class octet.
pub mod tos;

#[doc(hidden)]
pub mod reply_source;
/// Session Sender implementation.
#[doc(hidden)]
pub mod sender;
/// Session state management.
#[doc(hidden)]
pub mod session;
pub mod session_identity;
/// Best-effort SRv6 return-path forwarding (RFC 9503 §4 + RFC 8754).
#[doc(hidden)]
pub mod srv6;
/// Statistics collection and reporting.
#[doc(hidden)]
pub mod stats;
/// Timestamp generation utilities.
#[doc(hidden)]
pub mod time;
/// TLV extension support per RFC 8972.
#[doc(hidden)]
pub mod tlv;

/// Runtime control-plane REST API (requires "control" feature; reflector
/// only). Design: doc/control-plane.md.
#[cfg(feature = "control")]
#[doc(hidden)]
pub mod control;

/// Prometheus metrics support (requires "metrics" feature).
#[cfg(feature = "metrics")]
#[doc(hidden)]
pub mod metrics;

/// SNMP AgentX sub-agent support (requires "snmp" feature, Unix only).
#[cfg(all(unix, feature = "snmp"))]
#[doc(hidden)]
pub mod snmp;

/// A startup or terminal runtime failure, such as a bind error, missing key,
/// repeated send failure, or broken measurement output.
///
/// Distinct from normal shutdown so `main` exits non-zero and supervisors can
/// restart the process. `main` prints the diagnostic once.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// The configuration cannot be used as given.
    #[error("{0}")]
    Config(String),
    /// A socket or file operation failed.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    /// A configured HMAC key could not be loaded.
    #[error(transparent)]
    Key(#[from] crypto::KeyLoadError),
    /// The metrics endpoint, control API or another service did not start.
    #[error("{context}: {source}")]
    Service {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl StartupError {
    /// A configuration problem described by `msg`.
    #[must_use]
    pub fn config(msg: impl std::fmt::Display) -> Self {
        Self::Config(msg.to_string())
    }

    /// A failed socket or file operation; `context` says what was attempted.
    #[must_use]
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    /// A service that failed to start; `context` says which and where.
    #[must_use]
    pub fn service(
        context: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Service {
            context: context.into(),
            source: source.into(),
        }
    }
}
