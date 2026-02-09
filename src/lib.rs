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
/// STAMP packet structures and serialization.
pub mod packets;
/// Session Reflector implementations.
pub mod receiver;
/// Session Sender implementation.
pub mod sender;
/// Session state management.
pub mod session;
/// Timestamp generation utilities.
pub mod time;
/// TLV extension support per RFC 8972.
pub mod tlv;

/// Prometheus metrics support (requires "metrics" feature).
#[cfg(feature = "metrics")]
pub mod metrics;
