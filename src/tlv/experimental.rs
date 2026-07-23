//! Experimental-range codepoint stand-ins — single edit point.
//!
//! Several TLVs and sub-TLVs implemented by this crate belong to drafts that
//! have not (yet) received a final IANA codepoint allocation. Per RFC 8972
//! §5.1/§5.2, both the "STAMP TLV Types" registry and the "STAMP Sub-TLV
//! Types" registry (the latter scoped to sub-TLVs of the Reflected Test
//! Packet Control TLV, Type 12) reserve the range **240-251** for
//! "Experimental Use" — implementations may use these numbers without
//! registering them, at the cost of possible collisions with another
//! implementation's unrelated use of the same number (see
//! [`BER_MAX_BURST_TLV_TYPE`] below for a real one).
//!
//! This module exists so that every such stand-in has exactly **one**
//! place to look and exactly one place to edit when a draft eventually gets
//! a real IANA allocation: change the const here, bump a minor version
//! (these are on-wire-visible constants, but they're pre-standard by
//! definition, so a minor bump is this project's chosen severity — see
//! `doc/conformance/README.md`'s "Experimental-codepoint disclosure"
//! section and the top-level `CHANGELOG.md`'s Versioning policy), and
//! release-note it. `TlvType::from_byte`/`to_byte` (in `super::core`) are
//! the only call sites that reference these constants; nothing else in the
//! crate hard-codes these numbers.
//!
//! **Deliberately no runtime/config override mechanism exists for these
//! values** (no `--experimental-type-*` flag, no config-file section). Two
//! independent stamp-suite processes must run the same build to interop on
//! an experimental codepoint regardless; a runtime knob would let them
//! silently disagree instead of failing to build, which is worse, and no
//! user has ever asked for one. YAGNI until that changes.

/// Bit Pattern in Padding TLV — `draft-gandhi-ippm-stamp-ber-05` §3.2.
///
/// The draft defines this TLV but leaves its Type value as an unassigned
/// placeholder (no IANA allocation exists at revision -05); this crate uses
/// **240** from the "STAMP TLV Types" registry's Experimental Use range
/// (240-251, RFC 8972 §5.1).
///
/// **IANA action that triggers renumbering:** the draft (or a successor RFC)
/// assigning a concrete, IANA-registered Type value to the Bit Pattern in
/// Padding TLV — expected either on WG adoption (a `draft-ietf-*` revision
/// naming a TBD placeholder, the same pattern `draft-ietf-ippm-stamp-ext-hdr`
/// used for its TBA1-3 before this project stood in 246/247/240 for those)
/// or on eventual RFC publication.
///
/// This constant is the single edit point: update this value, then update
/// [`BER_COUNT_TLV_TYPE`] and [`BER_MAX_BURST_TLV_TYPE`] only if the draft
/// also renumbers them in the same revision (their allocations are
/// independent codepoints and may land separately).
pub const BER_PATTERN_TLV_TYPE: u8 = 240;

/// Bit Error Count in Padding TLV — `draft-gandhi-ippm-stamp-ber-05` §3.3.
///
/// Same situation as [`BER_PATTERN_TLV_TYPE`]: no IANA allocation exists at
/// revision -05, so this crate uses **241** from the "STAMP TLV Types"
/// Experimental Use range (240-251).
///
/// **IANA action that triggers renumbering:** the draft (or a successor RFC)
/// assigning a concrete Type value to the Bit Error Count in Padding TLV.
/// See [`BER_PATTERN_TLV_TYPE`] for the expected trigger event and the
/// renumbering procedure; this constant is the single edit point for this
/// TLV's Type value.
pub const BER_COUNT_TLV_TYPE: u8 = 241;

/// Max Bit Error Burst Size TLV — `draft-gandhi-ippm-stamp-ber-05` §3.4.
///
/// The draft defines this TLV alongside the two above, but — unlike
/// [`BER_PATTERN_TLV_TYPE`]/[`BER_COUNT_TLV_TYPE`], which the draft's own
/// Implementation Status section cites as already used by at least one
/// implementation at Types 240/241 — the draft does not cite any known
/// implementation using a Type value for this TLV. This crate's use of
/// **242** for it is therefore this implementation's *own* extension into
/// the shared Experimental Use range (240-251), not a value the draft
/// itself reports as already in use.
///
/// **Known collision (disclosed, not a bug):** Type 242 in the Experimental
/// Use range is also used, independently, by another STAMP implementation
/// for an unrelated, incompatible experimental "Heartbeat" TLV. Per RFC 8972
/// §5.1 this is not an IANA violation — the whole point of the Experimental
/// range is that no single number is reserved for one implementation — but
/// the two TLVs are wire-format-incompatible: a stamp-suite reflector talking
/// to that other implementation's Heartbeat sender (or vice versa) will
/// misparse the value. See `doc/conformance/README.md`'s
/// "Experimental-codepoint disclosure" section for the full disclosure and
/// `doc/architecture.md` for the original collision note.
///
/// **IANA action that triggers renumbering:** the draft (or a successor RFC)
/// assigning a concrete Type value to the Max Bit Error Burst Size TLV. See
/// [`BER_PATTERN_TLV_TYPE`] for the expected trigger event; this constant is
/// the single edit point for this TLV's Type value. Renumbering this one
/// also resolves the 242 collision, independent of what happens to the
/// other implementation's Heartbeat TLV.
pub const BER_MAX_BURST_TLV_TYPE: u8 = 242;

/// Reflected IPv6 Extension Header Data TLV — `draft-ietf-ippm-stamp-ext-hdr-11`
/// §§3.1, 5.1. IANA codepoint **TBA1** in the draft text.
///
/// This crate uses **246** from the "STAMP TLV Types" registry's
/// Experimental Use range (240-251, RFC 8972 §5.1) as the stand-in, per
/// `doc/conformance/draft-stamp-ext-hdr.md`'s codepoint note (that file
/// records the cross-implementation agreement this stand-in depends on:
/// two independent implementations must agree on the same numbers to
/// interoperate at all before IANA assigns real ones).
///
/// **IANA action that triggers renumbering:** IANA allocating a real Type
/// value for TBA1 in the "STAMP TLV Types" registry, expected when the
/// draft is approved for publication as an RFC. This constant is the single
/// edit point — update it here (and expect to update
/// [`REFLECTED_FIXED_HDR_TLV_TYPE`] and the sub-TLV constant
/// `REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` in the same pass, since
/// TBA1/TBA2/TBA3 are allocated together in the draft's IANA Considerations
/// section).
pub const REFLECTED_IPV6_EXT_HDR_TLV_TYPE: u8 = 246;

/// Reflected Fixed Header Data TLV — `draft-ietf-ippm-stamp-ext-hdr-11`
/// §§3.2, 5.2. IANA codepoint **TBA2** in the draft text.
///
/// This crate uses **247** from the "STAMP TLV Types" registry's
/// Experimental Use range (240-251) as the stand-in. See
/// [`REFLECTED_IPV6_EXT_HDR_TLV_TYPE`] for the shared codepoint-agreement
/// context.
///
/// **IANA action that triggers renumbering:** IANA allocating a real Type
/// value for TBA2, expected on RFC publication of the draft. This constant
/// is the single edit point for this TLV's Type value.
pub const REFLECTED_FIXED_HDR_TLV_TYPE: u8 = 247;

/// IPv6 Extension Header Control sub-TLV, carried inside the Reflected Test
/// Packet Control TLV (Type 12) — `draft-ietf-ippm-stamp-ext-hdr-11` §5.3.
/// IANA codepoint **TBA3** in the draft text.
///
/// Note the registry: unlike the three constants above (which are top-level
/// "STAMP TLV Types"), this one is a **sub-TLV** type scoped to the "STAMP
/// Sub-TLV Types" registry that Type 12 defines for its own sub-TLVs (RFC
/// 8972's Type 12 successor, `draft-ietf-ippm-asymmetrical-pkts`). That
/// registry separately reserves 240-251 for Experimental Use, so the value
/// **240** used here is not the same codepoint slot as
/// `BER_PATTERN_TLV_TYPE` (also 240) even though the numbers coincide —
/// the two live in different registries and are distinguished on the wire by
/// context (top-level TLV Type byte vs. sub-TLV Type byte inside a Type 12
/// value), never confusable in practice.
///
/// **IANA action that triggers renumbering:** IANA allocating a real Sub-TLV
/// Type value for TBA3, expected on RFC publication of
/// `draft-ietf-ippm-stamp-ext-hdr`. This constant is the single edit point;
/// see `REFLECTED_IPV6_EXT_HDR_TLV_TYPE` for the sibling TBA1/TBA2
/// constants that are expected to be renumbered in the same pass.
pub const REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL: u8 = 240;
