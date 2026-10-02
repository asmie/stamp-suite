//! Reflected Test Packet Control TLV (Type 12, RFC 10052): reply behaviour,
//! sub-TLV parsing and Address Group matching.

use super::*;
use crate::tlv::TlvSpan;

/// Behaviour requested by a Reflected Test Packet Control TLV
/// (RFC 10052 §3).
///
/// Tells the backend how many *additional* copies of the reply to emit (on
/// top of the primary reply), and the inter-packet gap in nanoseconds. If
/// `extra_copies` is 0, no additional sends are needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReflectedControlBehavior {
    /// Administrative payload cap captured when this request was processed.
    pub max_size: u16,
    /// Additional reply packets to emit after the primary reply
    /// (i.e. total replies = 1 + `extra_copies`).
    pub extra_copies: u16,
    /// Nanoseconds between consecutive sends.
    pub interval_ns: u32,
    /// Exactly one IPv6 Extension Header Control sub-TLV was present
    /// (draft-ietf-ippm-stamp-ext-hdr-15 §5.1). Neither backend attaches reply
    /// headers, so the sub-TLV gets C set. Duplicate requests also get C set
    /// but leave this field false.
    pub suppress_reply_ext_headers: bool,
}

/// Reflected Control sub-TLV types per RFC 10052 §3.
pub(super) const REFLECTED_CONTROL_SUBTLV_L2_GROUP: u8 = 10;

pub(super) const REFLECTED_CONTROL_SUBTLV_L3_GROUP: u8 = 11;

/// Parsed Reflected Control sub-TLV per RFC 10052 §3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ReflectedControlSubTlv {
    /// Layer 2 Address Group (sub-TLV type 10, draft-ietf-ippm-
    /// RFC 10052 §3.1.1) — bitwise mask/group filter matched
    /// against the reflector's own local MAC addresses. `mask` and `group`
    /// are always equal length (half of the validated Sub-TLV Length: 2, 6,
    /// or 8 octets).
    L2Group { mask: Vec<u8>, group: Vec<u8> },
    /// Layer 3 Address Group (sub-TLV type 11) — IP prefix match.
    L3Group { prefix_len: u8, prefix: Vec<u8> },
    /// IPv6 Extension Header Control (draft-ietf-ippm-stamp-ext-hdr-15
    /// §5.3) — presence-only (Sub-TLV Length 0) request to add matching IPv6
    /// extension headers to the reply. This reflector cannot add reply
    /// extension headers, so its presence yields the C flag on the reflected
    /// sub-TLV (rule 4); more than one is a cardinality violation.
    Ipv6ExtHdrControl,
    /// Anything else (including the 4-byte zero placeholder that pads the
    /// TLV to the draft-14 §3 12-octet minimum). Ignored by the reflector.
    Unknown {
        #[allow(dead_code)]
        type_byte: u8,
    },
}

/// Parses a chain of Reflected Control sub-TLVs from a raw byte slice. Uses
/// the standard 4-byte STAMP sub-TLV header (flags + type + length).
/// Returns an empty vec if the body is empty, malformed, or contains only
/// the all-zeros placeholder.
pub(super) fn parse_reflected_control_sub_tlvs(body: &[u8]) -> Vec<ReflectedControlSubTlv> {
    let mut out = Vec::new();
    let mut offset = 0;
    // A truncated sub-TLV ends parsing.
    while let Some(sub) = TlvSpan::at(body, offset) {
        let type_byte = sub.tlv_type.to_byte();
        let length = sub.len;
        let value_end = sub.end();
        let value = &body[sub.value()];
        match type_byte {
            REFLECTED_CONTROL_SUBTLV_L2_GROUP => {
                // RFC 10052 §3.1.1: equal Mask/Group
                // halves require lengths 4, 12, or 16. Skip malformed sub-TLVs;
                // they do not participate in matching.
                let len = value.len();
                if len == 4 || len == 12 || len == 16 {
                    let half = len / 2;
                    let mask = value[..half].to_vec();
                    let group = value[half..].to_vec();
                    out.push(ReflectedControlSubTlv::L2Group { mask, group });
                }
            }
            REFLECTED_CONTROL_SUBTLV_L3_GROUP => {
                // RFC 10052 §3.1.2: prefix_len(1) + reserved(3) + prefix(4 or 16).
                // Skip lengths other than 8 (IPv4) or 20 (IPv6).
                let len = value.len();
                if len == 4 + 4 || len == 4 + 16 {
                    let prefix_len = value[0];
                    let prefix = value[4..].to_vec();
                    out.push(ReflectedControlSubTlv::L3Group { prefix_len, prefix });
                }
            }
            // Presence-only; ext-hdr-15 §5.1 defines no value fields, so any
            // length is accepted and the value ignored.
            REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL => {
                out.push(ReflectedControlSubTlv::Ipv6ExtHdrControl);
            }
            // An all-zero 4-octet header pads the TLV to its 12-octet minimum
            // (RFC 10052 §3).
            0 if length == 0 => {}
            other => out.push(ReflectedControlSubTlv::Unknown { type_byte: other }),
        }
        offset = value_end;
    }
    out
}

/// Returns true if the L3 Address Group prefix matches any of the
/// reflector's local addresses. Per draft §3, the comparison is "bitwise
/// AND the prefix mask with each local address and check equality with
/// the prefix field." Empty `locals` is treated as "no match" (drop).
pub(super) fn l3_group_matches_any_local(
    prefix_len: u8,
    prefix: &[u8],
    locals: &[std::net::IpAddr],
) -> bool {
    use std::net::IpAddr;
    for local in locals {
        let local_bytes: Vec<u8> = match local {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        if local_bytes.len() != prefix.len() {
            continue; // family mismatch
        }
        let prefix_bits = prefix_len as usize;
        if prefix_bits > local_bytes.len() * 8 {
            continue;
        }
        let full_bytes = prefix_bits / 8;
        let extra_bits = prefix_bits % 8;
        let mut matched = true;
        for i in 0..full_bytes {
            if local_bytes[i] != prefix[i] {
                matched = false;
                break;
            }
        }
        if matched && extra_bits > 0 {
            let mask = 0xFFu8 << (8 - extra_bits);
            if (local_bytes[full_bytes] & mask) != (prefix[full_bytes] & mask) {
                matched = false;
            }
        }
        if matched {
            return true;
        }
    }
    false
}

/// Tests whether any local MAC satisfies `addr & mask == group`
/// (RFC 10052 §3.1.1).
///
/// Rechecks equal Mask/Group lengths. Local addresses are EUI-48, so only
/// six-byte halves can match. Empty `locals` means no match; the caller drops
/// the packet.
pub(super) fn l2_group_matches_any_local(mask: &[u8], group: &[u8], locals: &[[u8; 6]]) -> bool {
    if mask.len() != 6 || group.len() != 6 {
        return false;
    }
    for local in locals {
        let matched = (0..6).all(|i| (local[i] & mask[i]) == group[i]);
        if matched {
            return true;
        }
    }
    false
}
