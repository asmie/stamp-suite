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

/// Clock format definitions (NTP/PTP).
pub mod clock_format;
/// Command-line configuration and validation.
pub mod configuration;
/// HMAC cryptographic operations for packet authentication.
pub mod crypto;
/// Error estimate encoding/decoding for timestamps.
pub mod error_estimate;
/// Hardware-assisted timestamping support (F1). On Linux, kernel RX+TX
/// timestamps via `SO_TIMESTAMPING` and `MSG_ERRQUEUE` (read via cmsg),
/// with optional NIC hardware timestamping under `--hwtstamp on` via
/// `SIOCSHWTSTAMP` (graceful fallback). macOS supports kernel RX timestamps
/// only via `SO_TIMESTAMP`. Windows is not supported. The probe queries
/// ETHTOOL_GET_TS_INFO on Linux. See `doc/architecture.md` for details.
pub mod hwtstamp;
/// STAMP packet structures and serialization.
pub mod packets;
/// Session Reflector implementations.
pub mod receiver;
/// Session Sender implementation.
pub mod sender;
/// Session state management.
pub mod session;
/// Best-effort SRv6 return-path forwarding (RFC 9503 §5 + RFC 8754).
pub mod srv6;
/// Statistics collection and reporting.
pub mod stats;
/// Timestamp generation utilities.
pub mod time;
/// TLV extension support per RFC 8972.
pub mod tlv;

/// Runtime control-plane REST API (requires "control" feature; reflector
/// only). Design: doc/control-plane.md.
#[cfg(feature = "control")]
pub mod control;

/// Prometheus metrics support (requires "metrics" feature).
#[cfg(feature = "metrics")]
pub mod metrics;

/// SNMP AgentX sub-agent support (requires "snmp" feature, Unix only).
#[cfg(all(unix, feature = "snmp"))]
pub mod snmp;
