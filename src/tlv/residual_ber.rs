//! Value codec for draft-ietf-bpm-stamp-ber-01 §§4–4.1.
//!
//! This codec does not register a top-level type or enable endpoint processing.
//! Codepoints remain caller-supplied until the wire migration is integrated.
//! Successful decoding does not identify the peer's draft revision.
//! Structural decoding preserves unknown sub-TLVs and their flag octets;
//! endpoint code must apply flag, HMAC and session-admission checks separately.

use thiserror::Error;

use super::{TlvFlags, TLV_HEADER_SIZE};

/// Count and maximum burst occupy the first eight value octets (§4).
pub const RESIDUAL_BER_FIXED_VALUE_SIZE: usize = 8;
/// The optional pattern sub-TLV needs at least four value octets (§4.1).
pub const RESIDUAL_BER_MIN_PATTERN_SIZE: usize = 4;
/// Default when no explicit or locally configured pattern is selected (§5.1.2).
pub const RESIDUAL_BER_DEFAULT_PATTERN: [u8; 4] = [0xFF, 0x00, 0xFF, 0x00];

/// A nested sub-TLV. Its type belongs to the sub-TLV registry, independently
/// of top-level STAMP type numbers. Unknown values remain opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualBerSubTlv {
    /// The complete received flags octet; decoding does not acknowledge it.
    pub flags: u8,
    pub kind: u8,
    pub value: Vec<u8>,
}

/// The successor BER value, excluding its four-octet outer TLV header.
/// Default constructs a request with zero counters and no explicit pattern.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResidualBerValue {
    pub count: u32,
    pub max_burst: u32,
    pub sub_tlvs: Vec<ResidualBerSubTlv>,
}

/// Structural errors and pattern conformance errors are separate so a future
/// reflector can apply M to malformed framing/patterns and C to duplicates.
/// Offsets are relative to the outer TLV's value, never to the packet base.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResidualBerError {
    #[error("BER value needs at least 8 octets, got {length}")]
    ShortValue { length: usize },
    #[error("BER value exceeds the 65535-octet length field")]
    ValueTooLong,
    #[error("truncated BER sub-TLV header at value offset {offset}")]
    ShortSubTlvHeader { offset: usize },
    #[error("BER sub-TLV at value offset {offset} declares {length} unavailable value octets")]
    TruncatedSubTlv { offset: usize, length: usize },
    #[error("more than one BER bit-pattern sub-TLV")]
    DuplicatePattern,
    #[error("BER bit-pattern sub-TLV {index} needs at least 4 octets, got {length}")]
    ShortPattern { index: usize, length: usize },
}

impl ResidualBerValue {
    /// Build a sender value, with U=1 on an optional explicit pattern. The
    /// pattern codepoint is supplied independently of the outer TLV type.
    pub fn request(pattern_type: u8, pattern: Option<&[u8]>) -> Result<Self, ResidualBerError> {
        let mut value = Self::default();
        if let Some(pattern) = pattern {
            if pattern.len() < RESIDUAL_BER_MIN_PATTERN_SIZE {
                return Err(ResidualBerError::ShortPattern {
                    index: 0,
                    length: pattern.len(),
                });
            }
            if pattern.len()
                > usize::from(u16::MAX) - RESIDUAL_BER_FIXED_VALUE_SIZE - TLV_HEADER_SIZE
            {
                return Err(ResidualBerError::ValueTooLong);
            }
            value.sub_tlvs.push(ResidualBerSubTlv {
                flags: TlvFlags::U,
                kind: pattern_type,
                value: pattern.to_vec(),
            });
        }
        Ok(value)
    }

    /// Decode complete framing without discarding unknown or semantically
    /// invalid sub-TLVs. Use `explicit_pattern` to check pattern multiplicity
    /// and size. Keep the original bytes on error for malformed reflection.
    pub fn decode_value(value: &[u8]) -> Result<Self, ResidualBerError> {
        if value.len() < RESIDUAL_BER_FIXED_VALUE_SIZE {
            return Err(ResidualBerError::ShortValue {
                length: value.len(),
            });
        }
        if value.len() > usize::from(u16::MAX) {
            return Err(ResidualBerError::ValueTooLong);
        }
        let mut result = Self {
            count: u32::from_be_bytes(value[..4].try_into().expect("validated fixed fields")),
            max_burst: u32::from_be_bytes(value[4..8].try_into().expect("validated fixed fields")),
            sub_tlvs: Vec::new(),
        };
        let mut offset = RESIDUAL_BER_FIXED_VALUE_SIZE;
        while offset < value.len() {
            let remaining = &value[offset..];
            if remaining.len() < TLV_HEADER_SIZE {
                return Err(ResidualBerError::ShortSubTlvHeader { offset });
            }
            let length = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
            if length > remaining.len() - TLV_HEADER_SIZE {
                return Err(ResidualBerError::TruncatedSubTlv { offset, length });
            }
            result.sub_tlvs.push(ResidualBerSubTlv {
                flags: remaining[0],
                kind: remaining[1],
                value: remaining[TLV_HEADER_SIZE..TLV_HEADER_SIZE + length].to_vec(),
            });
            offset += TLV_HEADER_SIZE + length;
        }
        Ok(result)
    }

    /// Return the sole explicit pattern, or None so endpoint policy can select
    /// a local/default pattern. This validates size and multiplicity only;
    /// the caller must first validate received flags and integrity.
    pub fn explicit_pattern(&self, pattern_type: u8) -> Result<Option<&[u8]>, ResidualBerError> {
        let mut patterns = self
            .sub_tlvs
            .iter()
            .enumerate()
            .filter(|(_, s)| s.kind == pattern_type);
        let Some((index, pattern)) = patterns.next() else {
            return Ok(None);
        };
        if patterns.next().is_some() {
            return Err(ResidualBerError::DuplicatePattern);
        }
        if pattern.value.len() < RESIDUAL_BER_MIN_PATTERN_SIZE {
            return Err(ResidualBerError::ShortPattern {
                index,
                length: pattern.value.len(),
            });
        }
        Ok(Some(&pattern.value))
    }

    /// Append value bytes only after checking every length. Failure leaves
    /// `out` unchanged, including when a nested length or aggregate overflows.
    /// Invalid pattern semantics can be encoded for malformed-packet testing.
    pub fn encode_value(&self, out: &mut Vec<u8>) -> Result<(), ResidualBerError> {
        let mut length = RESIDUAL_BER_FIXED_VALUE_SIZE;
        for sub in &self.sub_tlvs {
            if sub.value.len() > usize::from(u16::MAX) {
                return Err(ResidualBerError::ValueTooLong);
            }
            length += TLV_HEADER_SIZE + sub.value.len();
            if length > usize::from(u16::MAX) {
                return Err(ResidualBerError::ValueTooLong);
            }
        }
        out.reserve(length);
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.max_burst.to_be_bytes());
        for sub in &self.sub_tlvs {
            out.extend_from_slice(&[sub.flags, sub.kind]);
            out.extend_from_slice(&(sub.value.len() as u16).to_be_bytes());
            out.extend_from_slice(&sub.value);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
