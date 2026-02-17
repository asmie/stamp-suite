//! TlvList collection with HMAC, parsing, serialization, and flag management.

mod processing;

use crate::crypto::HmacKey;
use crate::tlv::core::{RawTlv, TlvError, TlvType, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

/// A list of TLVs with special handling for HMAC TLV.
///
/// Per RFC 8972, the HMAC TLV must always be the last TLV in the list.
/// For failure echo paths, wire order is preserved to comply with RFC 8972 §4.8.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlvList {
    /// The TLVs in the list (excluding HMAC).
    tlvs: Vec<RawTlv>,
    /// Optional HMAC TLV (always serialized last in normal mode).
    hmac_tlv: Option<RawTlv>,
    /// All TLVs in original wire order (used for failure echo per RFC 8972 §4.8).
    /// When set, `to_bytes()` will use this order instead of the separated fields.
    wire_order_tlvs: Option<Vec<RawTlv>>,
}

impl TlvList {
    /// Creates a new empty TlvList.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the list is empty (no TLVs including HMAC).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        if let Some(ref wire_order) = self.wire_order_tlvs {
            wire_order.is_empty()
        } else {
            self.tlvs.is_empty() && self.hmac_tlv.is_none()
        }
    }

    /// Returns the number of TLVs (including HMAC if present).
    #[must_use]
    pub fn len(&self) -> usize {
        if let Some(ref wire_order) = self.wire_order_tlvs {
            wire_order.len()
        } else {
            self.tlvs.len() + usize::from(self.hmac_tlv.is_some())
        }
    }

    /// Returns true if using wire-order preservation mode (for failure echo).
    #[must_use]
    pub fn is_wire_order_mode(&self) -> bool {
        self.wire_order_tlvs.is_some()
    }

    /// Adds a TLV to the list.
    ///
    /// HMAC TLVs are stored separately to ensure they're serialized last.
    ///
    /// # Errors
    /// Returns an error if trying to add multiple HMAC TLVs.
    pub fn push(&mut self, tlv: RawTlv) -> Result<(), TlvError> {
        if tlv.tlv_type.is_hmac() {
            if self.hmac_tlv.is_some() {
                return Err(TlvError::MultipleHmacTlvs);
            }
            self.hmac_tlv = Some(tlv);
        } else {
            self.tlvs.push(tlv);
        }
        Ok(())
    }

    /// Returns an iterator over all TLVs (non-HMAC first, then HMAC).
    pub fn iter(&self) -> impl Iterator<Item = &RawTlv> {
        self.tlvs.iter().chain(self.hmac_tlv.iter())
    }

    /// Returns a reference to the HMAC TLV if present.
    #[must_use]
    pub fn hmac_tlv(&self) -> Option<&RawTlv> {
        self.hmac_tlv.as_ref()
    }

    /// Returns the non-HMAC TLVs.
    #[must_use]
    pub fn non_hmac_tlvs(&self) -> &[RawTlv] {
        &self.tlvs
    }

    /// Parses a TLV list from a buffer.
    ///
    /// # Errors
    /// Returns an error if parsing fails or HMAC TLV is not last.
    pub fn parse(buf: &[u8]) -> Result<Self, TlvError> {
        let mut list = Self::new();
        let mut offset = 0;
        let mut found_hmac = false;

        while offset < buf.len() {
            if buf.len() - offset < TLV_HEADER_SIZE {
                break;
            }

            let (tlv, consumed) = RawTlv::parse(&buf[offset..])?;

            if found_hmac {
                return Err(TlvError::HmacNotLast);
            }

            if tlv.tlv_type.is_hmac() {
                found_hmac = true;
                if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                    return Err(TlvError::InvalidHmacLength(tlv.value.len()));
                }
            }

            list.push(tlv)?;
            offset += consumed;
        }

        Ok(list)
    }

    /// Parses a TLV list leniently, marking malformed TLVs with M-flag.
    ///
    /// Unlike `parse()`, this method:
    /// - Handles truncated TLVs by marking them as malformed (M-flag)
    /// - Continues parsing after recoverable errors
    /// - Does not fail on HMAC length mismatch (marks as malformed instead)
    /// - Preserves wire order for RFC 8972 §4.8 "copy all TLVs" compliance
    ///
    /// # Returns
    /// A tuple of (TlvList, bool) where the bool indicates if any TLV was malformed.
    pub fn parse_lenient(buf: &[u8]) -> (Self, bool) {
        let mut parsed_tlvs: Vec<RawTlv> = Vec::new();
        let mut offset = 0;
        let mut found_hmac = false;
        let mut any_malformed = false;
        let mut has_multiple_hmac = false;

        while offset < buf.len() {
            if buf.len() - offset < TLV_HEADER_SIZE {
                break;
            }

            let header = &buf[offset..offset + TLV_HEADER_SIZE];
            if header == [0, 0, 0, 0] && buf[offset..].iter().all(|&b| b == 0) {
                break;
            }

            match RawTlv::parse_lenient(&buf[offset..]) {
                Ok((mut tlv, consumed, malformed)) => {
                    if malformed {
                        any_malformed = true;
                    }

                    if found_hmac {
                        tlv.set_malformed();
                        any_malformed = true;
                    }

                    if tlv.tlv_type.is_hmac() {
                        if found_hmac {
                            has_multiple_hmac = true;
                        }
                        found_hmac = true;
                        if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                            tlv.set_malformed();
                            any_malformed = true;
                        }
                    }

                    parsed_tlvs.push(tlv);
                    offset += consumed;

                    if malformed {
                        break;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }

        let need_wire_order = any_malformed || has_multiple_hmac;

        let mut list = Self::new();

        if need_wire_order {
            for tlv in &parsed_tlvs {
                if tlv.tlv_type.is_hmac() {
                    list.hmac_tlv = Some(tlv.clone());
                } else {
                    list.tlvs.push(tlv.clone());
                }
            }
            list.wire_order_tlvs = Some(parsed_tlvs);
        } else {
            for tlv in parsed_tlvs {
                if tlv.tlv_type.is_hmac() {
                    list.hmac_tlv = Some(tlv);
                } else {
                    list.tlvs.push(tlv);
                }
            }
        }

        (list, any_malformed)
    }

    /// Serializes the TLV list to bytes.
    ///
    /// If wire-order mode is active (from lenient parsing with issues),
    /// TLVs are serialized in their original wire order per RFC 8972 §4.8.
    /// Otherwise, HMAC TLV is always serialized last per RFC 8972.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        self.write_to(&mut buf);
        buf
    }

    /// Writes the TLV list to the provided buffer without allocating.
    #[inline]
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        if let Some(ref wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                tlv.write_to(buf);
            }
            return;
        }

        for tlv in &self.tlvs {
            tlv.write_to(buf);
        }

        if let Some(ref hmac) = self.hmac_tlv {
            hmac.write_to(buf);
        }
    }

    /// Returns the total wire size of all TLVs.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        if let Some(ref wire_order) = self.wire_order_tlvs {
            wire_order.iter().map(|t| t.wire_size()).sum()
        } else {
            self.iter().map(|t| t.wire_size()).sum()
        }
    }

    /// Builds the HMAC input data per RFC 8972 §4.8.
    fn build_hmac_input(&self, sequence_number_bytes: &[u8], tlv_bytes: &[u8]) -> Vec<u8> {
        let non_hmac_size: usize = self.tlvs.iter().map(|t| t.wire_size()).sum();

        let mut data = Vec::with_capacity(4 + non_hmac_size);

        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }

        if non_hmac_size <= tlv_bytes.len() {
            data.extend_from_slice(&tlv_bytes[..non_hmac_size]);
        }

        data
    }

    /// Extracts the expected HMAC bytes from the HMAC TLV value.
    fn extract_hmac_bytes(hmac_tlv: &RawTlv) -> Result<[u8; 16], TlvError> {
        hmac_tlv
            .value
            .as_slice()
            .try_into()
            .map_err(|_| TlvError::InvalidHmacLength(hmac_tlv.value.len()))
    }

    /// Verifies the HMAC TLV if present per RFC 8972 §4.8.
    ///
    /// # Errors
    /// Returns an error if HMAC verification fails.
    pub fn verify_hmac(
        &self,
        key: &HmacKey,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
    ) -> Result<(), TlvError> {
        let Some(hmac_tlv) = &self.hmac_tlv else {
            return Ok(());
        };

        let data = self.build_hmac_input(sequence_number_bytes, tlv_bytes);
        let expected = Self::extract_hmac_bytes(hmac_tlv)?;

        if key.verify(&data, &expected) {
            Ok(())
        } else {
            Err(TlvError::HmacVerificationFailed)
        }
    }

    /// Verifies HMAC and marks ALL TLVs with I-flag on failure per RFC 8972 §4.8.
    ///
    /// # Returns
    /// `true` if HMAC verification passed (or no HMAC present), `false` if failed.
    pub fn verify_hmac_and_mark(
        &mut self,
        key: &HmacKey,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
    ) -> bool {
        let Some(hmac_tlv) = &self.hmac_tlv else {
            return true;
        };

        let data = self.build_hmac_input(sequence_number_bytes, tlv_bytes);

        let Ok(expected) = Self::extract_hmac_bytes(hmac_tlv) else {
            self.mark_all_integrity_failed();
            return false;
        };

        if key.verify(&data, &expected) {
            true
        } else {
            self.mark_all_integrity_failed();
            false
        }
    }

    /// Marks ALL TLVs (including HMAC) with I-flag per RFC 8972 §4.8.
    pub fn mark_all_integrity_failed(&mut self) {
        for tlv in &mut self.tlvs {
            tlv.set_integrity_failed();
        }
        if let Some(ref mut hmac) = self.hmac_tlv {
            hmac.set_integrity_failed();
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                tlv.set_integrity_failed();
            }
        }
    }

    /// Returns true if the TLV list contains only Extra Padding TLVs.
    #[must_use]
    pub fn contains_only_extra_padding(&self) -> bool {
        if self.hmac_tlv.is_some() {
            return false;
        }
        !self.tlvs.is_empty()
            && self
                .tlvs
                .iter()
                .all(|t| t.tlv_type == TlvType::ExtraPadding)
    }

    /// Counts TLVs with each error flag type (U, M, I).
    ///
    /// Returns a tuple of (unrecognized_count, malformed_count, integrity_failed_count).
    #[must_use]
    pub fn count_error_flags(&self) -> (usize, usize, usize) {
        let mut unrecognized = 0;
        let mut malformed = 0;
        let mut integrity_failed = 0;

        for tlv in &self.tlvs {
            if tlv.is_unrecognized() {
                unrecognized += 1;
            }
            if tlv.is_malformed() {
                malformed += 1;
            }
            if tlv.is_integrity_failed() {
                integrity_failed += 1;
            }
        }

        if let Some(ref hmac) = self.hmac_tlv {
            if hmac.is_unrecognized() {
                unrecognized += 1;
            }
            if hmac.is_malformed() {
                malformed += 1;
            }
            if hmac.is_integrity_failed() {
                integrity_failed += 1;
            }
        }

        (unrecognized, malformed, integrity_failed)
    }

    /// Computes and sets the HMAC TLV per RFC 8972 §4.8.
    pub fn set_hmac(&mut self, key: &HmacKey, sequence_number_bytes: &[u8]) {
        let tlvs_size: usize = self.tlvs.iter().map(|t| t.wire_size()).sum();
        let mut data = Vec::with_capacity(4 + tlvs_size);

        if sequence_number_bytes.len() >= 4 {
            data.extend_from_slice(&sequence_number_bytes[..4]);
        } else {
            data.extend_from_slice(sequence_number_bytes);
        }

        for tlv in &self.tlvs {
            tlv.write_to(&mut data);
        }

        let hmac = key.compute(&data);
        self.hmac_tlv = Some(RawTlv::new(TlvType::Hmac, hmac.to_vec()));
    }

    /// Marks unrecognized TLV types with the U flag.
    pub fn mark_unrecognized_types(&mut self) {
        for tlv in &mut self.tlvs {
            if !tlv.tlv_type.is_recognized() {
                tlv.set_unrecognized();
            }
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if !tlv.tlv_type.is_recognized() {
                    tlv.set_unrecognized();
                }
            }
        }
    }

    /// Applies all reflector-side flag updates per RFC 8972.
    ///
    /// # Returns
    /// `true` if HMAC verification passed (or no key/HMAC), `false` if failed.
    pub fn apply_reflector_flags(
        &mut self,
        hmac_key: Option<&HmacKey>,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
    ) -> bool {
        self.apply_reflector_flags_strict(hmac_key, sequence_number_bytes, tlv_bytes, false)
    }

    /// Applies reflector-side flag updates with optional strict HMAC TLV requirement.
    ///
    /// # Returns
    /// `true` if verification passed, `false` if failed or HMAC TLV missing when required.
    pub fn apply_reflector_flags_strict(
        &mut self,
        hmac_key: Option<&HmacKey>,
        sequence_number_bytes: &[u8],
        tlv_bytes: &[u8],
        require_hmac_tlv: bool,
    ) -> bool {
        self.mark_unrecognized_types();
        self.validate_known_tlv_lengths();

        if let Some(key) = hmac_key {
            if require_hmac_tlv && self.hmac_tlv.is_none() {
                if !self.contains_only_extra_padding() {
                    self.mark_all_integrity_failed();
                    return false;
                }
                return true;
            }

            self.verify_hmac_and_mark(key, sequence_number_bytes, tlv_bytes)
        } else if self.hmac_tlv.is_some() {
            self.mark_all_integrity_failed();
            false
        } else {
            true
        }
    }

    /// Validates known TLV types for correct value sizes and sets M-flag on mismatches.
    pub fn validate_known_tlv_lengths(&mut self) {
        Self::validate_known_tlv_lengths_slice(&mut self.tlvs);

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            Self::validate_known_tlv_lengths_slice(wire_order);
        }
    }

    /// Validates known TLV lengths on a single slice and sets M-flag on mismatches.
    fn validate_known_tlv_lengths_slice(tlvs: &mut [RawTlv]) {
        use crate::tlv::core::{
            ACCESS_REPORT_TLV_VALUE_SIZE, COS_TLV_VALUE_SIZE, DEST_NODE_ADDR_IPV4_SIZE,
            DEST_NODE_ADDR_IPV6_SIZE, DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
            FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE, LOCATION_TLV_MIN_VALUE_SIZE,
            MICRO_SESSION_ID_TLV_VALUE_SIZE, TIMESTAMP_INFO_TLV_VALUE_SIZE,
        };

        for tlv in tlvs {
            let malformed = match tlv.tlv_type {
                TlvType::ClassOfService => tlv.value.len() != COS_TLV_VALUE_SIZE,
                TlvType::AccessReport => tlv.value.len() != ACCESS_REPORT_TLV_VALUE_SIZE,
                TlvType::TimestampInfo => tlv.value.len() != TIMESTAMP_INFO_TLV_VALUE_SIZE,
                TlvType::DirectMeasurement => tlv.value.len() != DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
                TlvType::Location => tlv.value.len() < LOCATION_TLV_MIN_VALUE_SIZE,
                TlvType::FollowUpTelemetry => tlv.value.len() != FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE,
                TlvType::DestinationNodeAddress => {
                    tlv.value.len() != DEST_NODE_ADDR_IPV4_SIZE
                        && tlv.value.len() != DEST_NODE_ADDR_IPV6_SIZE
                }
                TlvType::ReturnPath => tlv.value.len() < TLV_HEADER_SIZE,
                TlvType::MicroSessionId => tlv.value.len() != MICRO_SESSION_ID_TLV_VALUE_SIZE,
                _ => false,
            };
            if malformed {
                tlv.set_malformed();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_list_empty() {
        let list = TlvList::new();
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_tlv_list_push() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_tlv_list_hmac_separate() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Hmac, vec![0; 16])).unwrap();

        assert_eq!(list.len(), 2);
        assert!(list.hmac_tlv().is_some());
        assert_eq!(list.non_hmac_tlvs().len(), 1);
    }

    #[test]
    fn test_tlv_list_multiple_hmac_error() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Hmac, vec![0; 16])).unwrap();
        let result = list.push(RawTlv::new(TlvType::Hmac, vec![0; 16]));
        assert!(matches!(result, Err(TlvError::MultipleHmacTlvs)));
    }

    #[test]
    fn test_tlv_list_to_bytes_hmac_last() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Hmac, vec![0xFF; 16]))
            .unwrap();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0xAA, 0xBB]))
            .unwrap();

        let bytes = list.to_bytes();
        assert_eq!(bytes[1], 1); // ExtraPadding first
        let hmac_start = 6;
        assert_eq!(bytes[hmac_start + 1], 8); // HMAC last
    }

    #[test]
    fn test_tlv_list_parse() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB]);
        bytes.extend_from_slice(&[0x00, 0x08, 0x00, 0x10]);
        bytes.extend_from_slice(&[0xFF; 16]);

        let list = TlvList::parse(&bytes).unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.hmac_tlv().is_some());
        assert_eq!(list.non_hmac_tlvs().len(), 1);
    }

    #[test]
    fn test_tlv_list_parse_hmac_not_last_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x00, 0x08, 0x00, 0x10]);
        bytes.extend_from_slice(&[0xFF; 16]);
        bytes.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xAA, 0xBB]);

        let result = TlvList::parse(&bytes);
        assert!(matches!(result, Err(TlvError::HmacNotLast)));
    }

    #[test]
    fn test_tlv_list_roundtrip() {
        let mut original = TlvList::new();
        original
            .push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0, 0, 0]))
            .unwrap();
        original
            .push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        original
            .push(RawTlv::new(TlvType::Hmac, vec![0xAB; 16]))
            .unwrap();

        let bytes = original.to_bytes();
        let parsed = TlvList::parse(&bytes).unwrap();

        assert_eq!(original, parsed);
    }

    #[test]
    fn test_tlv_list_mark_unrecognized() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Unknown(10), vec![]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Reserved, vec![])).unwrap();

        list.mark_unrecognized_types();

        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
        assert!(list.non_hmac_tlvs()[1].is_unrecognized());
        assert!(list.non_hmac_tlvs()[2].is_unrecognized());
    }

    #[test]
    fn test_count_error_flags() {
        let mut list = TlvList::new();

        let mut unrecognized_tlv = RawTlv::new(TlvType::Unknown(99), vec![1, 2]);
        unrecognized_tlv.set_unrecognized();

        let mut malformed_tlv = RawTlv::new(TlvType::ExtraPadding, vec![]);
        malformed_tlv.set_malformed();

        let mut integrity_failed_tlv = RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]);
        integrity_failed_tlv.set_integrity_failed();

        let normal_tlv = RawTlv::new(TlvType::ClassOfService, vec![0; 4]);

        list.push(unrecognized_tlv).unwrap();
        list.push(malformed_tlv).unwrap();
        list.push(integrity_failed_tlv).unwrap();
        list.push(normal_tlv).unwrap();

        let (u, m, i) = list.count_error_flags();
        assert_eq!(u, 1, "Expected 1 unrecognized TLV");
        assert_eq!(m, 1, "Expected 1 malformed TLV");
        assert_eq!(i, 1, "Expected 1 integrity-failed TLV");
    }

    #[test]
    fn test_count_error_flags_includes_hmac() {
        let mut list = TlvList::new();
        let mut hmac_tlv = RawTlv::new(TlvType::Hmac, vec![0xAB; 16]);
        hmac_tlv.set_integrity_failed();
        list.push(hmac_tlv).unwrap();

        let (u, m, i) = list.count_error_flags();
        assert_eq!(u, 0);
        assert_eq!(m, 0);
        assert_eq!(i, 1, "HMAC TLV integrity flag should be counted");
    }

    #[test]
    fn test_tlv_list_wire_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![0; 8]))
            .unwrap();
        assert_eq!(list.wire_size(), 20);
    }

    #[test]
    fn test_tlv_list_set_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        assert!(list.hmac_tlv().is_some());
        let hmac_tlv = list.hmac_tlv().unwrap();
        assert_eq!(hmac_tlv.tlv_type, TlvType::Hmac);
        assert_eq!(hmac_tlv.value.len(), 16);
    }

    #[test]
    fn test_tlv_list_verify_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac(&key, &base_packet, &tlv_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_tlv_list_verify_hmac_wrong_key() {
        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key1, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac(&key2, &base_packet, &tlv_bytes);
        assert!(matches!(result, Err(TlvError::HmacVerificationFailed)));
    }

    #[test]
    fn test_verify_hmac_and_mark_success() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac_and_mark(&key, &base_packet, &tlv_bytes);

        assert!(result);
        assert!(!list.hmac_tlv().unwrap().is_integrity_failed());
    }

    #[test]
    fn test_verify_hmac_and_mark_failure() {
        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key1, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.verify_hmac_and_mark(&key2, &base_packet, &tlv_bytes);

        assert!(!result);
        assert!(list.hmac_tlv().unwrap().is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Unknown(15), vec![1, 2]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags(Some(&key), &base_packet, &tlv_bytes);

        assert!(result);
        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
        assert!(list.non_hmac_tlvs()[1].is_unrecognized());
    }

    #[test]
    fn test_apply_reflector_flags_hmac_failure() {
        let key1 = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key1, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags(Some(&key2), &base_packet, &tlv_bytes);

        assert!(!result);
        assert!(list.hmac_tlv().unwrap().is_integrity_failed());
    }

    #[test]
    fn test_contains_only_extra_padding_true() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 8]))
            .unwrap();
        assert!(list.contains_only_extra_padding());
    }

    #[test]
    fn test_contains_only_extra_padding_false_with_other_tlv() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        assert!(!list.contains_only_extra_padding());
    }

    #[test]
    fn test_contains_only_extra_padding_false_with_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);
        assert!(!list.contains_only_extra_padding());
    }

    #[test]
    fn test_contains_only_extra_padding_empty() {
        let list = TlvList::new();
        assert!(!list.contains_only_extra_padding());
    }

    #[test]
    fn test_apply_reflector_flags_strict_missing_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, true);

        assert!(!result);
        assert!(list.non_hmac_tlvs()[0].is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags_strict_extra_padding_only_exception() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, true);

        assert!(result);
        assert!(!list.non_hmac_tlvs()[0].is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags_strict_with_valid_hmac() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, true);

        assert!(result);
    }

    #[test]
    fn test_apply_reflector_flags_strict_non_strict_mode() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags_strict(Some(&key), &base_packet, &tlv_bytes, false);

        assert!(result);
        assert!(!list.non_hmac_tlvs()[0].is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags_no_key_with_hmac_tlv() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let seq = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![1, 2, 3, 4]))
            .unwrap();
        list.set_hmac(&key, &seq);

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags(None, &seq, &tlv_bytes);

        assert!(!result, "Should return false when HMAC present but no key");
        for tlv in list.non_hmac_tlvs() {
            assert!(
                tlv.is_integrity_failed(),
                "Non-HMAC TLV type {:?} should have I-flag set",
                tlv.tlv_type
            );
        }
        assert!(
            list.hmac_tlv().unwrap().is_integrity_failed(),
            "HMAC TLV should have I-flag set"
        );
    }

    #[test]
    fn test_apply_reflector_flags_no_key_no_hmac_tlv() {
        let seq = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ExtraPadding, vec![0xCC; 4]))
            .unwrap();

        let tlv_bytes = list.to_bytes();
        let result = list.apply_reflector_flags(None, &seq, &tlv_bytes);

        assert!(result, "Should pass when no HMAC TLV and no key");
        assert!(
            !list.non_hmac_tlvs()[0].is_integrity_failed(),
            "No I-flag should be set"
        );
    }

    #[test]
    fn test_wire_order_preserved_for_malformed_tlvs() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);

        buf.push(0x00);
        buf.push(0x01);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB]);

        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xCC; 8]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(had_malformed);
        assert!(list.is_wire_order_mode());

        let output = list.to_bytes();
        assert_eq!(output[1], 0x02);
        assert_eq!(output[9], 0x01);
        assert_eq!(output[15], 0x08);
    }

    #[test]
    fn test_wire_order_preserved_for_multiple_hmac_tlvs() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 16]);

        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xBB; 16]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(had_malformed);
        assert!(list.is_wire_order_mode());
        assert_eq!(list.len(), 2);

        let output = list.to_bytes();
        assert_eq!(output[1], 0x08);
        assert_eq!(&output[4..20], &[0xAA; 16]);
        assert_eq!(output[21], 0x08);
        assert_eq!(&output[24..40], &[0xBB; 16]);
    }

    #[test]
    fn test_wire_order_not_used_for_valid_tlvs() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x01);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[0; 4]);

        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 16]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert!(!list.is_wire_order_mode());
    }

    #[test]
    fn test_mark_all_integrity_failed_updates_wire_order() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);

        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xCC; 8]);

        let (mut list, _) = TlvList::parse_lenient(&buf);
        assert!(list.is_wire_order_mode());

        list.mark_all_integrity_failed();

        let output = list.to_bytes();
        assert_eq!(output[0] & 0x20, 0x20);
        assert_eq!(output[8] & 0x20, 0x20);
    }

    #[test]
    fn test_parse_lenient_skips_zero_padding() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        buf.extend_from_slice(&[0u8; 16]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert_eq!(list.len(), 1);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_parse_lenient_all_zero_buffer() {
        let buf = [0u8; 32];
        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn test_parse_lenient_zero_padding_after_hmac() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x08);
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 16]);
        buf.extend_from_slice(&[0u8; 8]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert_eq!(list.len(), 1);
        assert!(list.hmac_tlv().is_some());
        assert!(list.non_hmac_tlvs().is_empty());
    }

    #[test]
    fn test_parse_lenient_reserved_tlv_zero_length_not_padding() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x00);
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert_eq!(list.len(), 2);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Reserved);
        assert_eq!(list.non_hmac_tlvs()[0].value.len(), 0);
        assert_eq!(list.non_hmac_tlvs()[1].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_parse_lenient_reserved_tlv_followed_by_trailing_zeros() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);

        buf.push(0x00);
        buf.push(0x00);
        buf.extend_from_slice(&0u16.to_be_bytes());

        buf.extend_from_slice(&[0u8; 8]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert_eq!(list.len(), 1);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_parse_lenient_reserved_tlv_with_value_not_padding() {
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x00);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]);

        buf.push(0x00);
        buf.push(0x02);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);

        let (list, had_malformed) = TlvList::parse_lenient(&buf);
        assert!(!had_malformed);
        assert_eq!(list.len(), 2);
        assert_eq!(list.non_hmac_tlvs()[0].tlv_type, TlvType::Reserved);
        assert_eq!(list.non_hmac_tlvs()[0].value.len(), 2);
        assert_eq!(list.non_hmac_tlvs()[1].tlv_type, TlvType::Location);
    }

    #[test]
    fn test_validate_known_tlv_lengths_correct_sizes() {
        use crate::tlv::core::*;

        let mut list = TlvList::new();
        list.push(RawTlv::new(
            TlvType::ClassOfService,
            vec![0; COS_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::AccessReport,
            vec![0; ACCESS_REPORT_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::TimestampInfo,
            vec![0; TIMESTAMP_INFO_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::DirectMeasurement,
            vec![0; DIRECT_MEASUREMENT_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::Location,
            vec![0; LOCATION_TLV_MIN_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::FollowUpTelemetry,
            vec![0; FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE],
        ))
        .unwrap();
        list.push(RawTlv::new(
            TlvType::MicroSessionId,
            vec![0; MICRO_SESSION_ID_TLV_VALUE_SIZE],
        ))
        .unwrap();

        list.validate_known_tlv_lengths();

        for tlv in list.non_hmac_tlvs() {
            assert!(
                !tlv.is_malformed(),
                "TLV {:?} should not be malformed",
                tlv.tlv_type
            );
        }
    }

    #[test]
    fn test_validate_known_tlv_lengths_wrong_sizes() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 2]))
            .unwrap();
        list.push(RawTlv::new(TlvType::AccessReport, vec![0; 5]))
            .unwrap();
        list.push(RawTlv::new(TlvType::TimestampInfo, vec![0; 1]))
            .unwrap();
        list.push(RawTlv::new(TlvType::DirectMeasurement, vec![0; 8]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Location, vec![0; 2]))
            .unwrap();
        list.push(RawTlv::new(TlvType::FollowUpTelemetry, vec![0; 10]))
            .unwrap();
        list.push(RawTlv::new(TlvType::MicroSessionId, vec![0; 2]))
            .unwrap();

        list.validate_known_tlv_lengths();

        for tlv in list.non_hmac_tlvs() {
            assert!(
                tlv.is_malformed(),
                "TLV {:?} should be malformed",
                tlv.tlv_type
            );
        }
    }

    #[test]
    fn test_validate_known_tlv_lengths_location_longer_ok() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![0; 20]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_known_tlv_lengths_unknown_types_ignored() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Unknown(99), vec![0; 3]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_destination_node_address_correct_sizes() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 4]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 16]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_destination_node_address_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DestinationNodeAddress, vec![0; 8]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_return_path_correct_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ReturnPath, vec![0; 4]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(!list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_validate_return_path_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ReturnPath, vec![0; 2]))
            .unwrap();
        list.validate_known_tlv_lengths();
        assert!(list.non_hmac_tlvs()[0].is_malformed());
    }

    #[test]
    fn test_tlv_type_is_recognized_for_rfc9503_types() {
        assert!(TlvType::DestinationNodeAddress.is_recognized());
        assert!(TlvType::ReturnPath.is_recognized());
    }

    #[test]
    fn test_micro_session_id_tlv_type_recognized() {
        assert!(TlvType::MicroSessionId.is_recognized());
    }
}
