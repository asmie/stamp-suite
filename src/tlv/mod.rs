//! TLV (Type-Length-Value) extension support per RFC 8972 Section 4.
//!
//! This module provides structures and functions for parsing and serializing
//! STAMP TLV extensions, enabling optional features like Session-Sender Identifier,
//! timestamps, telemetry, and HMAC for TLV integrity.
//!
//! # TLV Wire Format (RFC 8972 Section 4.2)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |STAMP TLV Flags|    Type       |         Length                |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Value...                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

mod core;
mod list;
mod traits;
mod typed;

// Re-export public API — this is the only external surface.

// Trait
pub use traits::TypedTlv;

// Core types and constants
pub use self::core::{
    RawTlv, TlvError, TlvFlags, TlvType, ACCESS_REPORT_TLV_VALUE_SIZE, BER_BURST_TLV_VALUE_SIZE,
    BER_COUNT_TLV_VALUE_SIZE, COS_TLV_VALUE_SIZE, DEST_NODE_ADDR_IPV4_SIZE,
    DEST_NODE_ADDR_IPV6_SIZE, DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
    FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE, HMAC_TLV_VALUE_SIZE, LOCATION_TLV_MIN_VALUE_SIZE,
    MICRO_SESSION_ID_TLV_VALUE_SIZE, REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE,
    RETURN_PATH_CONTROL_CODE_SIZE, TIMESTAMP_INFO_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
};

// Collection
pub use list::TlvList;

// Type 1 — Extra Padding
pub use typed::ExtraPaddingTlv;

// Type 2 — Location
pub use typed::{LocationSubTlv, LocationSubType, LocationTlv, PacketAddressInfo};

// Type 3 — Timestamp Information
pub use typed::{SyncSource, TimestampInfoTlv, TimestampMethod};

// Type 4 — Class of Service
pub use typed::ClassOfServiceTlv;

// Type 5 — Direct Measurement
pub use typed::DirectMeasurementTlv;

// Type 6 — Access Report
pub use typed::AccessReportTlv;

// Type 7 — Follow-Up Telemetry
pub use typed::FollowUpTelemetryTlv;

// Type 8 — HMAC
pub use typed::HmacTlv;

// Type 9 — Destination Node Address (RFC 9503)
pub use typed::DestinationNodeAddressTlv;

// Type 10 — Return Path (RFC 9503)
pub use typed::{ReturnPathAction, ReturnPathSubType, ReturnPathTlv};

// Type 11 — Micro-session ID (RFC 9534)
pub use typed::MicroSessionIdTlv;

// Type 12 — Reflected Test Packet Control (draft-ietf-ippm-asymmetrical-pkts)
pub use typed::ReflectedControlTlv;

// Type 240 — BER Bit Pattern in Padding (draft-gandhi-ippm-stamp-ber)
pub use typed::{BerPatternTlv, BER_DEFAULT_PATTERN};

// Type 241 — BER Bit Error Count in Padding (draft-gandhi-ippm-stamp-ber)
pub use typed::BerCountTlv;

// Type 242 — BER Max Bit Error Burst Size (draft-gandhi-ippm-stamp-ber)
pub use typed::BerBurstTlv;

// Type 246 — Reflected IPv6 Extension Header Data (draft-ietf-ippm-stamp-ext-hdr)
pub use typed::{ReflectedIpv6ExtHdrTlv, DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY};

// Type 247 — Reflected Fixed Header Data (draft-ietf-ippm-stamp-ext-hdr)
pub use typed::{ReflectedFixedHdrTlv, IPV4_FIXED_HEADER_SIZE, IPV6_FIXED_HEADER_SIZE};
