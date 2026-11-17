//! Typed TLV implementations for each STAMP TLV extension type.

mod access_report;
mod cos;
mod destination_node_address;
mod direct_measurement;
mod extra_padding;
mod follow_up_telemetry;
mod hmac;
mod location;
mod micro_session;
mod reflected_control;
mod reflected_fixed_hdr;
mod reflected_ipv6_ext_hdr;
mod return_path;
mod timestamp_info;

// Type 1: Extra Padding
pub use extra_padding::ExtraPaddingTlv;

// Type 2: Location
pub use location::{
    LocationDisclosure, LocationSubTlv, LocationSubType, LocationTlv, PacketAddressInfo,
};

// Type 3: Timestamp Information
pub use timestamp_info::{SyncSource, TimestampInfoTlv, TimestampMethod};

// Type 4: Class of Service
pub use cos::ClassOfServiceTlv;

// Type 5: Direct Measurement
pub use direct_measurement::DirectMeasurementTlv;

// Type 6: Access Report
pub use access_report::AccessReportTlv;

// Type 7: Follow-Up Telemetry
pub use follow_up_telemetry::FollowUpTelemetryTlv;

// Type 8: HMAC
pub use hmac::HmacTlv;

// Type 9: Destination Node Address (RFC 9503)
pub use destination_node_address::DestinationNodeAddressTlv;

// Type 10: Return Path (RFC 9503)
pub use return_path::{ReturnPathAction, ReturnPathSubType, ReturnPathTlv, SegmentList};

// Type 11: Micro-session ID (RFC 9534)
pub use micro_session::MicroSessionIdTlv;

// Type 12: Reflected Test Packet Control (RFC 10052)
pub use reflected_control::ReflectedControlTlv;

// Type 246: Reflected IPv6 Extension Header Data (draft-ietf-ippm-stamp-ext-hdr)
pub use reflected_ipv6_ext_hdr::{ReflectedIpv6ExtHdrTlv, DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY};

// Type 247: Reflected Fixed Header Data (draft-ietf-ippm-stamp-ext-hdr)
pub use reflected_fixed_hdr::{
    ReflectedFixedHdrTlv, IPV4_FIXED_HEADER_SIZE, IPV6_FIXED_HEADER_SIZE,
};
