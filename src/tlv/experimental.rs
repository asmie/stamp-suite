//! Experimental codepoints, kept together for renumbering.
//! RFC 8972 §§5.1, 5.3 reserve 240–251. Peers must agree on their meaning;
//! collisions are possible and runtime overrides are unavailable.
//! On IANA assignment, update the constant, bump the minor version and
//! record the wire change in CHANGELOG.md. See doc/conformance/README.md.

// Top-level Types 240–242 carried draft-gandhi-ippm-stamp-ber-07 TLVs up to
// release 1.0.x (pattern, count, maximum burst). They are retired: endpoints
// treat them as unrecognized and answer with U. Do not reuse them for another
// layout without a minor release.

/// Residual BER in Padding, draft-ietf-bpm-stamp-ber-01 §4 (TBA1).
/// Local experimental outer type; peers must agree on this revision/allocation.
/// The retired outer Types 240–242 are never reinterpreted as this format.
pub const RESIDUAL_BER_TLV_TYPE: u8 = 243;

/// Bit Pattern in Padding sub-TLV, draft-ietf-bpm-stamp-ber-01 §4.1 (TBA2).
/// This is in the separate sub-TLV registry, not the retired outer Type 241.
pub const RESIDUAL_BER_PATTERN_SUBTLV_TYPE: u8 = 241;

/// Reflected IPv6 Extension Header Data TLV
/// (draft-ietf-ippm-stamp-ext-hdr-26 §§4.1, 4.2).
/// Experimental Type 246 stands in for TBA1. Replace when IANA assigns it;
/// check the related TBA2/TBA3 constants at the same time.
/// See `doc/conformance/draft-stamp-ext-hdr.md` for peer agreement requirements.
pub const REFLECTED_IPV6_EXT_HDR_TLV_TYPE: u8 = 246;

/// Reflected Fixed Header Data TLV (draft-ietf-ippm-stamp-ext-hdr-26 §§6.1, 6.2).
/// Experimental Type 247 stands in for TBA2; replace when IANA assigns it.
/// See [`REFLECTED_IPV6_EXT_HDR_TLV_TYPE`] for the related allocations.
pub const REFLECTED_FIXED_HDR_TLV_TYPE: u8 = 247;

/// IPv6 Extension Header Control sub-TLV inside Type 12
/// (draft-ietf-ippm-stamp-ext-hdr-26 §5.1).
///
/// Experimental Sub-TLV Type 240 stands in for TBA3; replace on IANA allocation.
/// This uses the separate STAMP Sub-TLV Types registry, so it does not conflict
/// with the retired top-level Type 240.
/// Check the related TBA1/TBA2 constants when renumbering.
pub const REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL: u8 = 240;
