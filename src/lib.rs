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
//!
//! # Stability
//!
//! This crate ships the `stamp-suite` binaries. The library modules
//! (`clock_format`, `configuration`, `crypto`, `hwtstamp`, `packets`,
//! `receiver`, `sender`, `session`, `srv6`, `stats`, `time`, `tlv`, and the
//! optional `control`/`metrics`/`snmp` modules) are internal implementation
//! detail: they are `pub` only so that this crate's own integration tests,
//! benches, and fuzz targets can reach them, and they are exempt from semver
//! — any of them may change, move, or disappear in any 1.x release without
//! notice. The stable 1.x surface is the CLI flags, the config-file schema,
//! and on-the-wire behavior. This crate has an MSRV of Rust 1.93.

/// Clock format definitions (NTP/PTP).
#[doc(hidden)]
pub mod clock_format;
/// Command-line configuration and validation.
#[doc(hidden)]
pub mod configuration;
/// HMAC cryptographic operations for packet authentication.
#[doc(hidden)]
pub mod cos_policy;

#[doc(hidden)]
pub mod crypto;
/// Error estimate encoding/decoding for timestamps.
#[doc(hidden)]
pub mod error_estimate;
/// Hardware-assisted timestamping support (F1). On Linux, kernel RX+TX
/// timestamps via `SO_TIMESTAMPING` and `MSG_ERRQUEUE` (read via cmsg),
/// with optional NIC hardware timestamping under `--hwtstamp on` via
/// `SIOCSHWTSTAMP` (graceful fallback). macOS supports kernel RX timestamps
/// only via `SO_TIMESTAMP`. Windows is not supported. The probe queries
/// ETHTOOL_GET_TS_INFO on Linux. See `doc/architecture.md` for details.
#[doc(hidden)]
pub mod hwtstamp;
/// STAMP packet structures and serialization.
#[doc(hidden)]
pub mod packets;
/// AIMD congestion-response controller for CE-marked replies (F2,
/// draft-ietf-ippm-stamp-cos-ecn-01 §3.4). Pure state machine; driven by
/// `sender::run_sender`.
#[doc(hidden)]
pub mod rate_control;
/// Session Reflector implementations.
#[doc(hidden)]
pub mod receiver;
/// Session Sender implementation.
#[doc(hidden)]
pub mod sender;
/// Session state management.
#[doc(hidden)]
pub mod session;
/// Best-effort SRv6 return-path forwarding (RFC 9503 §5 + RFC 8754).
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
