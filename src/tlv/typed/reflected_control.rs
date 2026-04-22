//! Reflected Test Packet Control TLV (Type 12)
//! per draft-ietf-ippm-asymmetrical-pkts-14 §3.
//!
//! Lets the Session-Sender request asymmetrical reply traffic: the
//! Session-Reflector produces `count` copies of the reply, each padded to
//! `length` octets (using an Extra Padding TLV), spaced by `interval`
//! nanoseconds. Optional sub-TLVs filter which reflector groups should
//! respond.

use crate::tlv::core::{TlvError, TlvType, REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE};
use crate::tlv::traits::TypedTlv;

/// Reflected Test Packet Control TLV (Type 12).
///
/// # Wire Format
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |Length of the Reflected Packet |Number of the Reflected Packets|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Interval Between the Reflected Packets            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ~                            Sub-TLVs                           ~
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// The Conformant-Reflected-Packet (C) flag in the TLV's flags byte is set by
/// the reflector when it could not honour the request (MTU exceeded, rate /
/// volume cap). The draft leaves the C flag's exact bit position TBA; this
/// implementation places it at bit 3 of the STAMP TLV Flags octet (0x10),
/// the first bit position unused by RFC 8972's U/M/I triple.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectedControlTlv {
    /// Requested reply packet length in octets.
    pub length_of_reflected_packet: u16,
    /// Number of reply packets the reflector should emit.
    pub number_of_reflected_packets: u16,
    /// Gap between successive reply packets, in nanoseconds.
    pub interval_nanoseconds: u32,
    /// Raw sub-TLV bytes (Layer 2 / Layer 3 Address Group filters, opaque here).
    pub sub_tlvs: Vec<u8>,
}

impl ReflectedControlTlv {
    /// Creates a new Reflected Control TLV with no sub-TLVs.
    #[must_use]
    pub fn new(length: u16, count: u16, interval_ns: u32) -> Self {
        Self {
            length_of_reflected_packet: length,
            number_of_reflected_packets: count,
            interval_nanoseconds: interval_ns,
            sub_tlvs: Vec::new(),
        }
    }

    /// Creates a Reflected Control TLV with raw sub-TLV bytes appended.
    #[must_use]
    pub fn with_sub_tlvs(length: u16, count: u16, interval_ns: u32, sub_tlvs: Vec<u8>) -> Self {
        Self {
            length_of_reflected_packet: length,
            number_of_reflected_packets: count,
            interval_nanoseconds: interval_ns,
            sub_tlvs,
        }
    }
}

impl TypedTlv for ReflectedControlTlv {
    const TYPE: TlvType = TlvType::ReflectedControl;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        if value.len() < REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE {
            return Err(TlvError::InvalidReflectedControlLength(value.len()));
        }
        let length_of_reflected_packet = u16::from_be_bytes([value[0], value[1]]);
        let number_of_reflected_packets = u16::from_be_bytes([value[2], value[3]]);
        let interval_nanoseconds = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
        let sub_tlvs = value[REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE..].to_vec();
        Ok(Self {
            length_of_reflected_packet,
            number_of_reflected_packets,
            interval_nanoseconds,
            sub_tlvs,
        })
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.length_of_reflected_packet.to_be_bytes());
        out.extend_from_slice(&self.number_of_reflected_packets.to_be_bytes());
        out.extend_from_slice(&self.interval_nanoseconds.to_be_bytes());
        out.extend_from_slice(&self.sub_tlvs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_reflected_control_new() {
        let tlv = ReflectedControlTlv::new(1500, 4, 1_000_000);
        assert_eq!(tlv.length_of_reflected_packet, 1500);
        assert_eq!(tlv.number_of_reflected_packets, 4);
        assert_eq!(tlv.interval_nanoseconds, 1_000_000);
        assert!(tlv.sub_tlvs.is_empty());
    }

    #[test]
    fn test_reflected_control_roundtrip() {
        let original =
            ReflectedControlTlv::with_sub_tlvs(1500, 4, 1_000_000, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::ReflectedControl);
        let parsed = ReflectedControlTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_reflected_control_wire_format() {
        let tlv = ReflectedControlTlv::new(0x0100, 0x0200, 0x0300_0400);
        let raw = tlv.to_raw();
        // 2 bytes length + 2 bytes count + 4 bytes interval = 8 bytes minimum
        assert_eq!(raw.value.len(), 8);
        assert_eq!(&raw.value[0..2], &0x0100u16.to_be_bytes());
        assert_eq!(&raw.value[2..4], &0x0200u16.to_be_bytes());
        assert_eq!(&raw.value[4..8], &0x0300_0400u32.to_be_bytes());
    }

    #[test]
    fn test_reflected_control_invalid_length() {
        let raw = RawTlv::new(TlvType::ReflectedControl, vec![0; 4]);
        let result = ReflectedControlTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidReflectedControlLength(4))
        ));
    }

    #[test]
    fn test_reflected_control_parses_subtlvs_as_opaque() {
        // 8 bytes fixed + 4 bytes "sub-TLV bytes" should be preserved as-is.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u16.to_be_bytes()); // length
        bytes.extend_from_slice(&2u16.to_be_bytes()); // count
        bytes.extend_from_slice(&500u32.to_be_bytes()); // interval
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // sub-tlv bytes
        let raw = RawTlv::new(TlvType::ReflectedControl, bytes);
        let parsed = ReflectedControlTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed.sub_tlvs, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
