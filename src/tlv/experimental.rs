//! Experimental codepoints, kept together for renumbering.
//! RFC 8972 §§5.1, 5.3 reserve 240–251. Peers must agree on their meaning;
//! collisions are possible and runtime overrides are unavailable.
//! On IANA assignment, update the constant, bump the minor version and
//! record the wire change in CHANGELOG.md. See doc/conformance/README.md.

/// Bit Pattern in Padding TLV (draft-gandhi-ippm-stamp-ber-07 §5.1).
/// Experimental Type 240; replace with the IANA assignment when allocated.
/// BER TLV allocations are independent, so update each constant separately.
pub const BER_PATTERN_TLV_TYPE: u8 = 240;

/// Bit Error Count in Padding TLV (draft-gandhi-ippm-stamp-ber-07 §5.2).
/// Experimental Type 241; replace when IANA assigns this TLV's codepoint.
pub const BER_COUNT_TLV_TYPE: u8 = 241;

/// Max Bit Error Burst Size TLV (draft-gandhi-ippm-stamp-ber-07 §5.3).
/// Type 242 is this implementation's experimental choice, not a draft allocation.
///
/// It conflicts with another implementation's incompatible Heartbeat TLV.
/// See `doc/conformance/README.md` and `doc/architecture.md` for the disclosure.
/// Replace this constant when IANA assigns the TLV's codepoint.
pub const BER_MAX_BURST_TLV_TYPE: u8 = 242;

/// Reflected IPv6 Extension Header Data TLV
/// (draft-ietf-ippm-stamp-ext-hdr-15 §§4.1, 4.2).
/// Experimental Type 246 stands in for TBA1. Replace when IANA assigns it;
/// check the related TBA2/TBA3 constants at the same time.
/// See `doc/conformance/draft-stamp-ext-hdr.md` for peer agreement requirements.
pub const REFLECTED_IPV6_EXT_HDR_TLV_TYPE: u8 = 246;

/// Reflected Fixed Header Data TLV (draft-ietf-ippm-stamp-ext-hdr-15 §§6.1, 6.2).
/// Experimental Type 247 stands in for TBA2; replace when IANA assigns it.
/// See [`REFLECTED_IPV6_EXT_HDR_TLV_TYPE`] for the related allocations.
pub const REFLECTED_FIXED_HDR_TLV_TYPE: u8 = 247;

/// IPv6 Extension Header Control sub-TLV inside Type 12
/// (draft-ietf-ippm-stamp-ext-hdr-15 §5.1).
///
/// Experimental Sub-TLV Type 240 stands in for TBA3; replace on IANA allocation.
/// This uses the separate STAMP Sub-TLV Types registry, so it does not conflict
/// with top-level `BER_PATTERN_TLV_TYPE` (also 240).
/// Check the related TBA1/TBA2 constants when renumbering.
pub const REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL: u8 = 240;
