//! Typed TLV implementations for each STAMP TLV extension type.

mod access_report;
mod ber_burst;
mod ber_count;
mod ber_pattern;
mod cos;
mod destination_node_address;
mod direct_measurement;
mod extra_padding;
mod follow_up_telemetry;
mod hmac;
mod location;
mod micro_session;
mod reflected_control;
mod return_path;
mod timestamp_info;

// Type 1 — Extra Padding
pub use extra_padding::{ExtraPaddingTlv, SessionSenderId};

// Type 2 — Location
pub use location::{LocationSubTlv, LocationSubType, LocationTlv, PacketAddressInfo};

// Type 3 — Timestamp Information
pub use timestamp_info::{SyncSource, TimestampInfoTlv, TimestampMethod};

// Type 4 — Class of Service
pub use cos::ClassOfServiceTlv;

// Type 5 — Direct Measurement
pub use direct_measurement::DirectMeasurementTlv;

// Type 6 — Access Report
pub use access_report::AccessReportTlv;

// Type 7 — Follow-Up Telemetry
pub use follow_up_telemetry::FollowUpTelemetryTlv;

// Type 8 — HMAC
pub use hmac::HmacTlv;

// Type 9 — Destination Node Address (RFC 9503)
pub use destination_node_address::DestinationNodeAddressTlv;

// Type 10 — Return Path (RFC 9503)
pub use return_path::{ReturnPathAction, ReturnPathSubType, ReturnPathTlv};

// Type 11 — Micro-session ID (RFC 9534)
pub use micro_session::MicroSessionIdTlv;

// Type 12 — Reflected Test Packet Control (draft-ietf-ippm-asymmetrical-pkts)
pub use reflected_control::ReflectedControlTlv;

// Type 240 — BER Bit Pattern in Padding (draft-gandhi-ippm-stamp-ber)
pub use ber_pattern::{BerPatternTlv, BER_DEFAULT_PATTERN};

// Type 241 — BER Bit Error Count in Padding (draft-gandhi-ippm-stamp-ber)
pub use ber_count::BerCountTlv;

// Type 242 — BER Max Bit Error Burst Size (draft-gandhi-ippm-stamp-ber)
pub use ber_burst::BerBurstTlv;
