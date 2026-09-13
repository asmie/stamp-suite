//! TlvList collection with HMAC, parsing, serialization, and flag management.

mod processing;

use crate::crypto::HmacKey;
use crate::tlv::core::{RawTlv, TlvError, TlvFlags, TlvType, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

/// A list of TLVs with special handling for HMAC TLV.
///
/// Per RFC 8972, only Extra Padding may follow the HMAC TLV.
/// For failure echo paths, wire order is preserved to comply with RFC 8972 §4.8.
#[derive(Debug, Clone, Default)]
pub struct TlvList {
    /// One owner per TLV: non-HMAC entries first in encounter order, then
    /// HMAC entries. The prefix keeps non_hmac_tlvs() a borrowed slice.
    entries: Vec<RawTlv>,
    non_hmac_len: usize,
    /// Original order for malformed echoes or padding after HMAC, as indices.
    /// No payload is cloned and semantic mutations update only the owner.
    wire_order: Option<Vec<usize>>,
    has_ber: bool,
    malformed_echo: bool,
    /// HMAC offset in the received TLV area (RFC 8972 §4.8).
    /// Coverage ends here; permitted trailing Extra Padding is excluded.
    /// Locally built lists use `None` and compute the prefix size from entries.
    hmac_wire_offset: Option<usize>,
    /// A TLV that is neither the HMAC nor an Extra Padding TLV followed the
    /// HMAC TLV on the wire, so the HMAC is not in its required position.
    ///
    /// RFC 8972 §4.8: "If the HMAC TLV appears in any other position in a
    /// STAMP extended test packet, then the situation MUST be processed as
    /// HMAC verification failure" — see `apply_reflector_flags_strict`.
    hmac_misplaced: bool,
}

/// Equality compares TLV *content and arrangement* only.
///
/// `hmac_wire_offset` and `hmac_misplaced` are provenance recorded by the
/// parsers so HMAC coverage can be computed correctly; they are deliberately
/// excluded so a locally-built list still equals its own parsed round trip.
impl PartialEq for TlvList {
    fn eq(&self, other: &Self) -> bool {
        self.serialized_tlvs().eq(other.serialized_tlvs())
    }
}

impl Eq for TlvList {}

impl TlvList {
    /// Creates a new empty TlvList.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if the list is empty (no TLVs including HMAC).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of TLVs (including HMAC if present).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true for malformed failure echoes. Valid parsed lists may also
    /// retain padding after HMAC without entering this failure-only mode.
    #[must_use]
    pub fn is_wire_order_mode(&self) -> bool {
        self.malformed_echo
    }

    /// Adds a TLV to the list.
    ///
    /// HMAC stays in the canonical suffix; valid edits use the outgoing layout.
    /// Malformed echoes append to their indexed wire view as well.
    ///
    /// # Errors
    /// Returns an error if trying to add multiple HMAC TLVs.
    pub fn push(&mut self, tlv: RawTlv) -> Result<(), TlvError> {
        let is_hmac = tlv.tlv_type.is_hmac();
        if is_hmac && self.hmac_tlv().is_some() {
            return Err(TlvError::MultipleHmacTlvs);
        }
        if !self.malformed_echo {
            self.wire_order = None;
        }
        self.has_ber |= crate::ber::is_ber(tlv.tlv_type);
        let index = if is_hmac {
            self.entries.len()
        } else {
            self.non_hmac_len
        };
        if let Some(order) = &mut self.wire_order {
            for old in order.iter_mut() {
                if *old >= index {
                    *old += 1;
                }
            }
            order.push(index);
        }
        self.entries.insert(index, tlv);
        if !is_hmac {
            self.non_hmac_len += 1;
        }
        self.hmac_wire_offset = None;
        Ok(())
    }

    /// Removes every Extra Padding TLV and repairs any wire-order indices.
    ///
    /// Used by Reflected Test Packet Control processing: rule (a) of
    /// draft-ietf-ippm-asymmetrical-pkts-14 §3 computes the reflected length
    /// "excluding any Extra Padding TLVs" so a Session-Sender can request
    /// replies *shorter* than its test packet.
    pub fn remove_extra_padding_tlvs(&mut self) {
        self.retain_non_hmac(|t| t.tlv_type != TlvType::ExtraPadding);
    }

    /// Returns an iterator over all TLVs (non-HMAC first, then HMAC).
    pub fn iter(&self) -> impl Iterator<Item = &RawTlv> {
        self.non_hmac_tlvs().iter().chain(self.hmac_tlv())
    }

    /// Returns a reference to the HMAC TLV if present.
    #[must_use]
    pub fn hmac_tlv(&self) -> Option<&RawTlv> {
        self.entries[self.non_hmac_len..].last()
    }

    /// Returns the non-HMAC TLVs.
    #[must_use]
    pub fn non_hmac_tlvs(&self) -> &[RawTlv] {
        &self.entries[..self.non_hmac_len]
    }

    fn non_hmac_tlvs_mut(&mut self) -> &mut [RawTlv] {
        &mut self.entries[..self.non_hmac_len]
    }

    fn hmac_tlv_mut(&mut self) -> Option<&mut RawTlv> {
        self.entries[self.non_hmac_len..].last_mut()
    }

    fn retain_non_hmac(&mut self, mut keep: impl FnMut(&RawTlv) -> bool) {
        let mut mapping = self
            .wire_order
            .as_ref()
            .map(|_| vec![usize::MAX; self.entries.len()]);
        let old_prefix = self.non_hmac_len;
        let mut old = 0;
        let mut new = 0;
        self.non_hmac_len = 0;
        self.entries.retain(|tlv| {
            let retain = old >= old_prefix || keep(tlv);
            if retain {
                if let Some(mapping) = &mut mapping {
                    mapping[old] = new;
                }
                new += 1;
                if old < old_prefix {
                    self.non_hmac_len += 1;
                }
            }
            old += 1;
            retain
        });
        if let (Some(order), Some(mapping)) = (&mut self.wire_order, mapping) {
            order.retain_mut(|index| {
                *index = mapping[*index];
                *index != usize::MAX
            });
        }
        self.has_ber = self
            .non_hmac_tlvs()
            .iter()
            .any(|t| crate::ber::is_ber(t.tlv_type));
        self.hmac_wire_offset = None;
    }

    fn remove_non_hmac(&mut self, index: usize) {
        self.entries.remove(index);
        self.non_hmac_len -= 1;
        if let Some(order) = &mut self.wire_order {
            order.retain_mut(|old| {
                if *old == index {
                    return false;
                }
                if *old > index {
                    *old -= 1;
                }
                true
            });
        }
        self.has_ber = self
            .non_hmac_tlvs()
            .iter()
            .any(|t| crate::ber::is_ber(t.tlv_type));
        self.hmac_wire_offset = None;
    }

    /// Test-only borrowed view of preserved wire order. Production serialization
    /// follows indices without allocating a view or cloning payloads.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn wire_order_tlvs(&self) -> Option<Vec<&RawTlv>> {
        self.wire_order
            .as_ref()
            .map(|order| order.iter().map(|&i| &self.entries[i]).collect())
    }

    /// Parses a TLV list from a buffer.
    ///
    /// # Errors
    /// Returns an error if parsing fails or a non-padding TLV follows HMAC.
    pub fn parse(buf: &[u8]) -> Result<Self, TlvError> {
        let mut list = Self::new();
        let mut offset = 0;
        let mut found_hmac = false;

        while offset < buf.len() {
            if buf.len() - offset < TLV_HEADER_SIZE {
                break;
            }

            let (tlv, consumed) = RawTlv::parse(&buf[offset..])?;

            // RFC 8972 §4.8: "The HMAC TLV MUST follow all TLVs included in a
            // STAMP test packet except for the Extra Padding TLV" — trailing
            // Extra Padding is pure filler outside the HMAC's coverage, so it
            // is a legal position, not a misplaced HMAC.
            if found_hmac && tlv.tlv_type != TlvType::ExtraPadding {
                return Err(TlvError::HmacNotLast);
            }

            if tlv.tlv_type.is_hmac() {
                found_hmac = true;
                if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                    return Err(TlvError::InvalidHmacLength(tlv.value.len()));
                }
            }

            let is_hmac = tlv.tlv_type.is_hmac();
            let previous_offset = list.hmac_wire_offset;
            list.push(tlv)?;
            list.hmac_wire_offset = if is_hmac {
                Some(offset)
            } else {
                previous_offset
            };
            offset += consumed;
        }

        if let Some(at) = list.hmac_wire_offset.filter(|at| at + 20 < offset) {
            let mut prefix_bytes = 0;
            let before_hmac = list
                .non_hmac_tlvs()
                .iter()
                .take_while(|tlv| {
                    if prefix_bytes < at {
                        prefix_bytes += tlv.wire_size();
                        true
                    } else {
                        false
                    }
                })
                .count();
            list.wire_order = Some(
                (0..before_hmac)
                    .chain(std::iter::once(list.non_hmac_len))
                    .chain(before_hmac..list.non_hmac_len)
                    .collect(),
            );
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
        let mut hmac_wire_offset: Option<usize> = None;
        let mut hmac_misplaced = false;

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

                    if found_hmac && tlv.tlv_type != TlvType::ExtraPadding {
                        // RFC 8972 §4.8: the HMAC TLV must precede only Extra
                        // Padding TLVs. Anything else after it leaves the HMAC
                        // misplaced, which §4.8 says "MUST be processed as
                        // HMAC verification failure" — recorded here and acted
                        // on in `apply_reflector_flags_strict`. The M flag is
                        // set via the parser variant as well, so the
                        // structural signal survives the reflector's
                        // clear-and-rederive pass.
                        tlv.mark_malformed_by_parser();
                        any_malformed = true;
                        hmac_misplaced = true;
                    }

                    if tlv.tlv_type.is_hmac() {
                        if found_hmac {
                            has_multiple_hmac = true;
                        } else {
                            hmac_wire_offset = Some(offset);
                        }
                        found_hmac = true;
                        if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                            tlv.mark_malformed_by_parser();
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

        let malformed_echo = any_malformed || has_multiple_hmac;
        let need_wire_order = malformed_echo
            || (found_hmac && parsed_tlvs.last().is_some_and(|t| !t.tlv_type.is_hmac()));
        let non_hmac_len = parsed_tlvs.iter().filter(|t| !t.tlv_type.is_hmac()).count();
        let has_ber = parsed_tlvs.iter().any(|t| crate::ber::is_ber(t.tlv_type));
        let wire_order: Option<Vec<usize>> = need_wire_order.then(|| {
            let mut next_non_hmac = 0;
            let mut next_hmac = non_hmac_len;
            parsed_tlvs
                .iter()
                .map(|tlv| {
                    let next = if tlv.tlv_type.is_hmac() {
                        &mut next_hmac
                    } else {
                        &mut next_non_hmac
                    };
                    let index = *next;
                    *next += 1;
                    index
                })
                .collect()
        });
        if has_multiple_hmac {
            // Arbitrary duplicate HMACs must not turn the stable partition
            // quadratic. Each swap puts one owner in its final position;
            // scratch contains only indices, never duplicated payloads.
            let mut destinations: Vec<usize> = wire_order.as_ref().unwrap().clone();
            for index in 0..destinations.len() {
                while destinations[index] != index {
                    let destination = destinations[index];
                    parsed_tlvs.swap(index, destination);
                    destinations.swap(index, destination);
                }
            }
        } else {
            // With at most one HMAC, each rotation shifts at most two owners.
            let mut prefix = 0;
            for index in 0..parsed_tlvs.len() {
                if !parsed_tlvs[index].tlv_type.is_hmac() {
                    if index != prefix {
                        parsed_tlvs[prefix..=index].rotate_right(1);
                    }
                    prefix += 1;
                }
            }
        }
        let mut list = Self {
            entries: parsed_tlvs,
            non_hmac_len,
            wire_order,
            has_ber,
            malformed_echo,
            ..Self::default()
        };

        list.hmac_wire_offset = hmac_wire_offset;
        list.hmac_misplaced = hmac_misplaced;

        (list, any_malformed)
    }

    /// True when a TLV other than Extra Padding followed the HMAC TLV on the
    /// wire, leaving the HMAC out of its RFC 8972 §4.8 position.
    #[must_use]
    pub fn hmac_misplaced(&self) -> bool {
        self.hmac_misplaced
    }

    /// Serializes the TLV list to bytes.
    ///
    /// Preserved parsed order is used for malformed echoes and legal padding
    /// after HMAC. Newly built/signed lists put HMAC before BER padding or last.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        self.write_to(&mut buf);
        buf
    }

    /// BER padding remains outside TLV-HMAC coverage so residual errors can
    /// be measured without accepting corruption of the measurement metadata.
    fn ber_padding_after_hmac(&self) -> bool {
        self.has_ber
    }

    /// Appends TLVs without a temporary serialization buffer. The supplied
    /// buffer may grow if its capacity is insufficient.
    #[inline]
    pub fn write_to(&self, buf: &mut Vec<u8>) {
        for tlv in self.serialized_tlvs() {
            tlv.write_to(buf);
        }
    }

    fn serialized_tlvs(&self) -> impl Iterator<Item = &RawTlv> {
        let normal = self.wire_order.is_none();
        let trailing_padding = self.hmac_tlv().is_some() && self.ber_padding_after_hmac();
        self.wire_order
            .iter()
            .flatten()
            .map(|&index| &self.entries[index])
            .chain(
                self.non_hmac_tlvs()
                    .iter()
                    .take(if normal { self.non_hmac_len } else { 0 })
                    .filter(move |t| !trailing_padding || t.tlv_type != TlvType::ExtraPadding),
            )
            .chain(self.hmac_tlv().into_iter().filter(move |_| normal))
            .chain(
                self.non_hmac_tlvs()
                    .iter()
                    .take(if normal && trailing_padding {
                        self.non_hmac_len
                    } else {
                        0
                    })
                    .filter(|t| t.tlv_type == TlvType::ExtraPadding),
            )
    }

    /// Returns the total wire size of all TLVs.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        self.entries.iter().map(RawTlv::wire_size).sum()
    }

    /// Borrows the original covered prefix, or the current layout after an edit.
    /// An incomplete supplied prefix is rejected rather than silently omitted.
    fn hmac_prefix<'a>(&self, tlv_bytes: &'a [u8]) -> Option<&'a [u8]> {
        let size = self.hmac_wire_offset.unwrap_or_else(|| {
            if let Some(order) = &self.wire_order {
                return order
                    .iter()
                    .map(|&index| &self.entries[index])
                    .take_while(|tlv| !tlv.tlv_type.is_hmac())
                    .map(RawTlv::wire_size)
                    .sum();
            }
            self.non_hmac_tlvs()
                .iter()
                .filter(|t| !self.ber_padding_after_hmac() || t.tlv_type != TlvType::ExtraPadding)
                .map(RawTlv::wire_size)
                .sum()
        });
        tlv_bytes.get(..size)
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
        let Some(hmac) = self.hmac_tlv() else {
            return Ok(());
        };
        let expected = Self::extract_hmac_bytes(hmac)?;
        let prefix = self
            .hmac_prefix(tlv_bytes)
            .ok_or(TlvError::HmacVerificationFailed)?;
        let sequence = &sequence_number_bytes[..sequence_number_bytes.len().min(4)];
        if key.verify_parts([sequence, prefix], &expected) {
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
        if self
            .verify_hmac(key, sequence_number_bytes, tlv_bytes)
            .is_ok()
        {
            true
        } else {
            self.mark_all_integrity_failed();
            false
        }
    }

    /// Marks ALL TLVs (including HMAC) with I-flag per RFC 8972 §4.8.
    pub fn mark_all_integrity_failed(&mut self) {
        for tlv in &mut self.entries {
            tlv.set_integrity_failed();
        }
    }

    /// Returns true if the TLV list contains only Extra Padding TLVs.
    #[must_use]
    pub fn contains_only_extra_padding(&self) -> bool {
        !self.entries.is_empty()
            && self
                .entries
                .iter()
                .all(|t| t.tlv_type == TlvType::ExtraPadding)
    }

    /// Counts TLVs with each error flag type (U, M, I).
    ///
    /// Returns a tuple of (unrecognized_count, malformed_count, integrity_failed_count).
    #[must_use]
    pub fn count_error_flags(&self) -> (usize, usize, usize) {
        self.entries.iter().fold((0, 0, 0), |(u, m, i), tlv| {
            (
                u + usize::from(tlv.is_unrecognized()),
                m + usize::from(tlv.is_malformed()),
                i + usize::from(tlv.is_integrity_failed()),
            )
        })
    }

    /// Computes and sets the HMAC TLV per RFC 8972 §4.8 for the **sender** path.
    ///
    /// The resulting HMAC TLV carries sender-default flags (U=1, M=0, I=0)
    /// per RFC 8972 §4. Reflectors regenerating an HMAC for a response
    /// should call [`Self::set_hmac_response`] instead. Malformed echo lists
    /// are left unchanged; their received HMAC must not be regenerated.
    pub fn set_hmac(&mut self, key: &HmacKey, sequence_number_bytes: &[u8]) {
        // Malformed failure echoes preserve received HMAC bytes and flags.
        if self.malformed_echo {
            return;
        }
        // New signatures use the outbound layout; incoming verification used the
        // original offset and borrowed bytes before semantic mutation.
        self.wire_order = None;
        let mut signer = key.signer();
        signer.update(&sequence_number_bytes[..sequence_number_bytes.len().min(4)]);
        for tlv in self.non_hmac_tlvs() {
            if !self.ber_padding_after_hmac() || tlv.tlv_type != TlvType::ExtraPadding {
                signer.update(&tlv.wire_header());
                signer.update(&tlv.value);
            }
        }
        let value = signer.finish();
        let hmac = RawTlv::new(TlvType::Hmac, value.to_vec());
        if let Some(old) = self.hmac_tlv_mut() {
            *old = hmac;
        } else {
            self.entries.push(hmac);
        }
        self.hmac_wire_offset = None;
    }

    /// Computes the reflector's HMAC TLV with U=0 (RFC 8972 §4).
    ///
    /// A configured key protects the reply independently of the request's HMAC TLV.
    /// RFC 8972 §4.8 requires TLV authentication in authenticated mode (except a
    /// sole Extra Padding TLV) and permits it in unauthenticated mode.
    /// Callers skip this when TLV handling is `Ignore`.
    pub fn set_hmac_response(&mut self, key: &HmacKey, sequence_number_bytes: &[u8]) {
        if self.malformed_echo {
            return;
        }
        self.set_hmac(key, sequence_number_bytes);
        if let Some(hmac) = self.hmac_tlv_mut() {
            hmac.flags = TlvFlags::default();
        }
    }

    /// Marks unrecognized TLV types with the U flag.
    pub fn mark_unrecognized_types(&mut self) {
        for tlv in self.non_hmac_tlvs_mut() {
            if !tlv.tlv_type.is_recognized() {
                tlv.set_unrecognized();
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
        // RFC 8972 §4: the reflector overwrites U/M/I. The "Otherwise"
        // clauses require setting each to 0 when the named condition does not
        // hold, so clear them first and let the setters below raise as needed.
        for tlv in &mut self.entries {
            tlv.clear_reflector_flags();
            if !tlv.tlv_type.is_recognized() {
                tlv.set_unrecognized();
            }
            Self::validate_known_tlv_lengths_slice(std::slice::from_mut(tlv));
        }

        // A misplaced HMAC sets I on every TLV (RFC 8972 §4.8), even without
        // a configured key. Check position before verification branches.
        if self.hmac_misplaced {
            self.mark_all_integrity_failed();
            return false;
        }

        if let Some(key) = hmac_key {
            if require_hmac_tlv && self.hmac_tlv().is_none() {
                if !self.contains_only_extra_padding() {
                    self.mark_all_integrity_failed();
                    return false;
                }
                return true;
            }

            self.verify_hmac_and_mark(key, sequence_number_bytes, tlv_bytes)
        } else if self.hmac_tlv().is_some() {
            self.mark_all_integrity_failed();
            false
        } else {
            true
        }
    }

    /// Clears U, M, I *and* the C/Conformant bit on every TLV (reserved bits
    /// and the parser's own malformed marker are preserved) so the setters in
    /// `apply_reflector_flags_strict` can re-derive each flag per RFC 8972 §4.
    ///
    /// C is cleared rather than preserved because the Session-Reflector MUST
    /// ignore the received C value and derive its own
    /// (draft-ietf-ippm-asymmetrical-pkts-14 §3) — see
    /// [`RawTlv::clear_reflector_flags`], which this delegates to.
    pub fn clear_reflector_flags(&mut self) {
        for tlv in &mut self.entries {
            tlv.clear_reflector_flags();
        }
    }

    /// Re-derives the M-flag on every TLV held by this list, per RFC 8972 §4.
    ///
    /// For each TLV, sets M=1 when **either**:
    /// - the parser previously detected a structural / positional error and
    ///   recorded it via `mark_malformed_by_parser` (truncation, TLV after
    ///   HMAC, bad HMAC length — preserved across the reflector's flag-clear
    ///   pass via the parser-marker), or
    /// - the value length doesn't match the type's RFC-defined size for
    ///   recognized types.
    ///
    /// Visits each canonical entry once, including duplicate HMAC entries
    /// retained in malformed input.
    pub fn validate_known_tlv_lengths(&mut self) {
        Self::validate_known_tlv_lengths_slice(&mut self.entries);
    }

    /// Validates known TLV lengths on a single slice and sets M-flag on mismatches.
    fn validate_known_tlv_lengths_slice(tlvs: &mut [RawTlv]) {
        use crate::tlv::core::{
            ACCESS_REPORT_TLV_VALUE_SIZE, BER_BURST_TLV_VALUE_SIZE, BER_COUNT_TLV_VALUE_SIZE,
            COS_TLV_VALUE_SIZE, DEST_NODE_ADDR_IPV4_SIZE, DEST_NODE_ADDR_IPV6_SIZE,
            DIRECT_MEASUREMENT_TLV_VALUE_SIZE, FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE,
            LOCATION_TLV_MIN_VALUE_SIZE, MICRO_SESSION_ID_TLV_VALUE_SIZE,
            REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE, TIMESTAMP_INFO_TLV_VALUE_SIZE,
        };

        for tlv in tlvs {
            let bad_length = match tlv.tlv_type {
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
                TlvType::Hmac => tlv.value.len() != HMAC_TLV_VALUE_SIZE,
                TlvType::MicroSessionId => tlv.value.len() != MICRO_SESSION_ID_TLV_VALUE_SIZE,
                TlvType::ReflectedControl => tlv.value.len() < REFLECTED_CONTROL_TLV_MIN_VALUE_SIZE,
                // BerPattern: empty = default pattern. 246/247: variable Value
                // is valid (request: zeros sized to header; response: filled).
                TlvType::BerPattern | TlvType::ReflectedIpv6ExtHdr | TlvType::ReflectedFixedHdr => {
                    false
                }
                TlvType::BerCount => tlv.value.len() != BER_COUNT_TLV_VALUE_SIZE,
                TlvType::BerBurst => tlv.value.len() != BER_BURST_TLV_VALUE_SIZE,
                _ => false,
            };
            if tlv.is_parser_marked_malformed() || bad_length {
                tlv.set_malformed();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    proptest::proptest! {
        #[test]
        fn canonical_interleaved_duplicate_hmacs_preserve_wire_order(
            kinds in proptest::collection::vec(proptest::prelude::any::<bool>(), 2..128),
        ) {
            let mut bytes = Vec::new();
            let mut expected = Vec::new();
            let mut seen_hmac = false;
            for (i, hmac) in kinds.into_iter().enumerate() {
                let kind = if hmac { 8 } else { 1 };
                bytes.extend_from_slice(&[0, kind, 0, 16]);
                bytes.extend_from_slice(&[i as u8; 16]);
                expected.extend_from_slice(&[if hmac && seen_hmac { 0x40 } else { 0 }, kind, 0, 16]);
                expected.extend_from_slice(&[i as u8; 16]);
                seen_hmac |= hmac;
            }
            let (mut list, _) = TlvList::parse_lenient(&bytes);
            proptest::prop_assert_eq!(list.to_bytes(), expected.clone());
            list.remove_extra_padding_tlvs();
            let hmac_bytes: Vec<u8> = expected.chunks_exact(20)
                .filter(|tlv| tlv[1] == 8).flatten().copied().collect();
            proptest::prop_assert_eq!(list.to_bytes(), hmac_bytes);
        }

        #[test]
        fn canonical_malformed_tail_preserves_bytes_and_removal_order(
            values in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..32), 0..16),
            tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
            hmac_first in proptest::prelude::any::<bool>(),
        ) {
            // Independent encoder: valid padding/unknown entries followed by an
            // opaque truncated tail, which itself includes HMAC-looking bytes.
            let mut segments = Vec::new();
            for (i, value) in values.iter().enumerate() {
                let kind = if i % 2 == 0 { 1 } else { 253 };
                let mut bytes = vec![0, kind, 0, value.len() as u8];
                bytes.extend_from_slice(value);
                segments.push(bytes);
            }
            if hmac_first {
                let mut hmac = vec![0, 8, 0, 16];
                hmac.extend_from_slice(&[0xAB; 16]);
                segments.push(hmac);
            }
            let mut opaque = vec![0, 250, 0, (tail.len() + 60) as u8];
            opaque.extend_from_slice(&tail);
            opaque.extend_from_slice(&[0, 8, 0, 16]);
            opaque.extend_from_slice(&[0xCD; 16]);
            segments.push(opaque);
            let (mut list, malformed) = TlvList::parse_lenient(&segments.concat());
            proptest::prop_assert!(malformed);
            segments.last_mut().unwrap()[0] |= 0x40;
            proptest::prop_assert_eq!(list.to_bytes(), segments.concat());
            proptest::prop_assert_eq!(list.hmac_misplaced(), hmac_first);
            let order = list.wire_order.as_ref().unwrap();
            let mut indices = order.clone();
            indices.sort_unstable();
            proptest::prop_assert_eq!(indices, (0..list.entries.len()).collect::<Vec<_>>());
            for tlv in list.non_hmac_tlvs() {
                proptest::prop_assert!(order.iter().any(|&i| std::ptr::eq(tlv, &list.entries[i])));
            }
            list.remove_extra_padding_tlvs();
            segments.retain(|bytes| bytes[1] != 1);
            proptest::prop_assert_eq!(list.to_bytes(), segments.concat());
            proptest::prop_assert_eq!(list.len(), segments.len());
            proptest::prop_assert_eq!(list.wire_size(), segments.iter().map(Vec::len).sum::<usize>());
            list.mark_all_integrity_failed();
            for bytes in &mut segments { bytes[0] |= 0x20; }
            proptest::prop_assert_eq!(list.to_bytes(), segments.concat());
        }

        #[test]
        fn streamed_tlv_hmac_matches_serialized_prefix_with_ber_padding(
            padding in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
            seq in proptest::prelude::any::<[u8; 4]>(),
            ber in proptest::prelude::any::<bool>(),
        ) {
            let key = HmacKey::new(vec![0xAB; 32]).unwrap();
            let mut list = TlvList::new();
            list.push(RawTlv::new(TlvType::ExtraPadding, padding)).unwrap();
            list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 4])).unwrap();
            if ber { list.push(RawTlv::new(TlvType::BerCount, vec![0; 4])).unwrap(); }
            list.set_hmac(&key, &seq);
            let bytes = list.to_bytes();
            let prefix = if ber { 16 } else { bytes.len() - 20 };
            let expected = key.compute(&[seq.as_slice(), &bytes[..prefix]].concat());
            proptest::prop_assert_eq!(&list.hmac_tlv().unwrap().value, &expected.to_vec());
            let mut parsed = TlvList::parse(&bytes).unwrap();
            proptest::prop_assert!(parsed.verify_hmac(&key, &seq, &bytes).is_ok());
            // A structural mutation followed by regeneration must discard the old
            // parsed offset and sign the current prefix.
            parsed.remove_extra_padding_tlvs();
            parsed.set_hmac_response(&key, &seq);
            proptest::prop_assert!(parsed.verify_hmac(&key, &seq, &parsed.to_bytes()).is_ok());
        }
    }

    #[test]
    fn canonical_duplicate_hmac_flags_and_header_trim_stay_in_wire_order() {
        let mut bytes = vec![0, 247, 0, 8];
        bytes.extend_from_slice(&[7; 8]);
        for value in [0xAB, 0xCD] {
            bytes.extend_from_slice(&[0, 8, 0, 16]);
            bytes.extend_from_slice(&[value; 16]);
        }
        let (mut list, malformed) = TlvList::parse_lenient(&bytes);
        assert!(malformed);
        assert_eq!(list.len(), 3);
        assert_eq!(list.hmac_tlv().unwrap().value, vec![0xCD; 16]);
        list.mark_all_integrity_failed();
        assert_eq!(list.count_error_flags().2, 3);
        assert_eq!(list.trim_reflected_headers_to_size(44, 84), 1);
        let echoed = list.to_bytes();
        assert_eq!(echoed.len(), 40);
        assert_eq!(echoed[0], 0x20);
        assert_eq!(echoed[20], 0x60);
        assert_eq!(&echoed[4..20], &[0xAB; 16]);
        assert_eq!(&echoed[24..40], &[0xCD; 16]);
    }

    #[test]
    fn hmac_verification_rejects_missing_prefix_bytes() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let seq = [0; 4];
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 4]))
            .unwrap();
        list.push(RawTlv::new(TlvType::Hmac, key.compute(&seq).to_vec()))
            .unwrap();
        assert!(list.verify_hmac(&key, &seq, &[]).is_err());
    }

    #[test]
    fn malformed_failure_echo_does_not_regenerate_hmac_or_clear_flags() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        for has_hmac in [false, true] {
            let mut bytes = Vec::new();
            if has_hmac {
                bytes.extend_from_slice(&[0, 8, 0, 16]);
                bytes.extend_from_slice(&[0xCD; 16]);
            }
            bytes.extend_from_slice(&[0, 4, 0, 4, 1]);
            let (mut list, _) = TlvList::parse_lenient(&bytes);
            list.mark_all_integrity_failed();
            let before = list.to_bytes();
            list.set_hmac(&key, &[0; 4]);
            list.set_hmac_response(&key, &[0; 4]);
            assert_eq!(list.to_bytes(), before);
            assert_eq!(list.entries.len(), list.wire_order.as_ref().unwrap().len());
        }
    }

    #[test]
    fn legal_padding_on_both_sides_of_hmac_keeps_its_received_position() {
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let seq = [1, 2, 3, 4];
        let mut bytes = vec![0, 1, 0, 1, 7, 0, 4, 0, 4, 0, 0, 0, 0];
        let digest = key.compute(&[seq.as_slice(), bytes.as_slice()].concat());
        bytes.extend_from_slice(&[0, 8, 0, 16]);
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&[0, 1, 0, 1, 9]);
        for mut list in [
            TlvList::parse(&bytes).unwrap(),
            TlvList::parse_lenient(&bytes).0,
        ] {
            assert_eq!(list.to_bytes(), bytes);
            assert!(list.verify_hmac(&key, &seq, &bytes).is_ok());
            let wrong_key = HmacKey::new(vec![0xCD; 32]).unwrap();
            assert!(!list.apply_reflector_flags(Some(&wrong_key), &seq, &bytes));
            let mut expected = bytes.clone();
            for offset in [0, 5, 13, 33] {
                expected[offset] |= 0x20;
            }
            assert_eq!(list.to_bytes(), expected);
        }
    }

    #[test]
    fn canonical_push_updates_failure_echo_and_logical_views() {
        let (mut list, _) = TlvList::parse_lenient(&[0, 4, 0, 8, 1]);
        let previous = list.to_bytes();
        let extra = RawTlv::new(TlvType::ExtraPadding, vec![2, 3]);
        let extra_bytes = extra.to_bytes();
        list.push(extra).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list.to_bytes(), [previous, extra_bytes].concat());
    }

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
        // A Class of Service TLV after the HMAC. (Extra Padding here would be
        // legal per RFC 8972 §4.8's explicit exemption — see
        // `test_strict_parse_allows_only_extra_padding_after_hmac`.)
        bytes.extend_from_slice(&[0x00, 0x04, 0x00, 0x02, 0xAA, 0xBB]);

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
        // Cleared flags isolate the U-flag behavior under test;
        // sender-default U=1 (RFC 8972 §4) would otherwise mask it.
        let mut list = TlvList::new();
        list.push(RawTlv::with_flags(
            TlvFlags::default(),
            TlvType::ExtraPadding,
            vec![],
        ))
        .unwrap();
        list.push(RawTlv::with_flags(
            TlvFlags::default(),
            TlvType::Unknown(10),
            vec![],
        ))
        .unwrap();
        list.push(RawTlv::with_flags(
            TlvFlags::default(),
            TlvType::Reserved,
            vec![],
        ))
        .unwrap();

        list.mark_unrecognized_types();

        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
        assert!(list.non_hmac_tlvs()[1].is_unrecognized());
        assert!(list.non_hmac_tlvs()[2].is_unrecognized());
    }

    #[test]
    fn test_count_error_flags() {
        let mut list = TlvList::new();

        let mut unrecognized_tlv =
            RawTlv::with_flags(TlvFlags::default(), TlvType::Unknown(99), vec![1, 2]);
        unrecognized_tlv.set_unrecognized();

        let mut malformed_tlv =
            RawTlv::with_flags(TlvFlags::default(), TlvType::ExtraPadding, vec![]);
        malformed_tlv.set_malformed();

        let mut integrity_failed_tlv =
            RawTlv::with_flags(TlvFlags::default(), TlvType::Location, vec![1, 2, 3, 4]);
        integrity_failed_tlv.set_integrity_failed();

        let normal_tlv =
            RawTlv::with_flags(TlvFlags::default(), TlvType::ClassOfService, vec![0; 4]);

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
        let mut hmac_tlv = RawTlv::with_flags(TlvFlags::default(), TlvType::Hmac, vec![0xAB; 16]);
        hmac_tlv.set_integrity_failed();
        list.push(hmac_tlv).unwrap();

        let (u, m, i) = list.count_error_flags();
        assert_eq!(u, 0);
        assert_eq!(m, 0);
        assert_eq!(i, 1, "HMAC TLV integrity flag should be counted");
    }

    #[test]
    fn test_apply_reflector_flags_overwrites_uim() {
        // RFC 8972 §4: the reflector MUST set U=0 when the type is
        // recognized (and M=0 / I=0 absent the named conditions). Sender
        // sends U=1 by mandate, so an "echo" must not preserve it.
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 4]))
            .unwrap();
        let raw = list.to_bytes();

        list.apply_reflector_flags(None, &[0u8; 4], &raw);

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(!tlv.is_unrecognized());
        assert!(!tlv.is_malformed());
        assert!(!tlv.is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags_drops_incoming_c_flag() {
        // draft-ietf-ippm-asymmetrical-pkts-14 §3: the Session-Sender MUST
        // zero the C flag on transmission and the Session-Reflector MUST
        // ignore its received value — C is reflector-owned output, re-derived
        // by Reflected Test Packet Control processing after this clear pass.
        let mut list = TlvList::new();
        let mut tlv = RawTlv::new(TlvType::ReflectedControl, vec![0; 8]);
        tlv.set_conformant_reflected();
        list.push(tlv).unwrap();
        let raw = list.to_bytes();

        list.apply_reflector_flags(None, &[0u8; 4], &raw);

        let echoed = &list.non_hmac_tlvs()[0];
        assert!(!echoed.is_unrecognized());
        assert!(!echoed.flags.conformant_reflected);
    }

    #[test]
    fn test_apply_reflector_flags_clears_uim_then_sets_i_on_hmac_failure() {
        // Verifies the clear-then-rederive pipeline survives the HMAC branch:
        // even when the sender sets U=1 on a recognized TLV (per RFC mandate),
        // the reflector must end up with U=0 (recognized) and I=1 (HMAC fail)
        // — not U=1 (echoed-from-sender) plus I=1.
        let key_sender = HmacKey::new(vec![0xAB; 32]).unwrap();
        let key_refl = HmacKey::new(vec![0xCD; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key_sender, &base_packet);
        let tlv_bytes = list.to_bytes();

        let result = list.apply_reflector_flags(Some(&key_refl), &base_packet, &tlv_bytes);

        assert!(!result, "HMAC verification must fail with mismatched keys");
        let cos = &list.non_hmac_tlvs()[0];
        assert!(!cos.is_unrecognized(), "U must be 0 for recognized type");
        assert!(!cos.is_malformed(), "M must be 0 for valid TLV");
        assert!(cos.is_integrity_failed(), "I must be 1 on HMAC failure");
        assert!(list.hmac_tlv().unwrap().is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags_preserves_parser_m_on_truncated_tlv() {
        // parse_lenient marks the truncated TLV as malformed via the parser
        // marker. The clear-then-rederive pass in apply_reflector_flags must
        // re-set M so the echoed response advertises malformed-ness to peers
        // and metrics, per RFC 8972 §4 + §4.8.
        let mut buf = Vec::new();
        // ExtraPadding TLV with declared length 100 but only 4 bytes available.
        buf.push(0x00);
        buf.push(0x01);
        buf.extend_from_slice(&100u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let (mut list, any_malformed) = TlvList::parse_lenient(&buf);
        assert!(any_malformed);
        assert!(list.non_hmac_tlvs()[0].is_malformed());

        let raw = list.to_bytes();
        list.apply_reflector_flags(None, &[0u8; 4], &raw);

        let echoed = &list.non_hmac_tlvs()[0];
        assert!(
            echoed.is_malformed(),
            "M-flag must be preserved across the reflector clear pass"
        );
    }

    #[test]
    fn test_apply_reflector_flags_preserves_parser_m_on_after_hmac_tlv() {
        // RFC 8972 §4.8: the HMAC TLV must be followed by nothing except an
        // Extra Padding TLV. A *Class of Service* TLV after it leaves the HMAC
        // misplaced — the positional signal must reach the echoed response.
        let mut buf = Vec::new();
        // Valid HMAC TLV (16-byte value).
        buf.push(0x00);
        buf.push(0x08); // HMAC type
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 16]);
        // Class of Service TLV after the HMAC — illegal position.
        buf.push(0x00);
        buf.push(0x04); // ClassOfService
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[0xBB; 4]);

        let (mut list, any_malformed) = TlvList::parse_lenient(&buf);
        assert!(any_malformed);

        let raw = list.to_bytes();
        list.apply_reflector_flags(None, &[0u8; 4], &raw);

        // The post-HMAC TLV is retained in indexed wire order because parse_lenient
        // routed everything there once it detected malformed-ness.
        let wire_order = list
            .wire_order_tlvs()
            .expect("malformed packet preserves wire order");
        let post_hmac = wire_order
            .iter()
            .find(|t| t.tlv_type == TlvType::ClassOfService)
            .expect("post-HMAC TLV preserved");
        assert!(
            post_hmac.is_malformed(),
            "TLV after HMAC must keep M-flag through the clear pass"
        );
    }

    /// RFC8972-4.8-3: "If the HMAC TLV appears in any other position ... the
    /// situation MUST be processed as HMAC verification failure" — the §4.8
    /// failure procedure sets the I flag on *every* TLV, so an M flag on the
    /// offending TLV alone is not enough.
    #[test]
    fn test_misplaced_hmac_runs_verification_failure_procedure() {
        let key = HmacKey::new(vec![0x33; 32]).unwrap();
        let mut buf = Vec::new();
        // A recognized TLV, then the HMAC, then another recognized TLV.
        buf.push(0x00);
        buf.push(0x04); // ClassOfService
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[0x11; 4]);
        buf.push(0x00);
        buf.push(0x08); // HMAC
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0xAA; 16]);
        buf.push(0x00);
        buf.push(0x05); // DirectMeasurement — not Extra Padding
        buf.extend_from_slice(&16u16.to_be_bytes());
        buf.extend_from_slice(&[0x22; 16]);

        let (mut list, any_malformed) = TlvList::parse_lenient(&buf);
        assert!(
            any_malformed,
            "a misplaced HMAC is still structurally flagged"
        );
        assert!(list.hmac_misplaced(), "the misplaced HMAC must be recorded");

        let raw = list.to_bytes();
        let ok = list.apply_reflector_flags(Some(&key), &[0u8; 4], &raw);
        assert!(
            !ok,
            "a misplaced HMAC must be reported as a verification failure"
        );

        let wire_order = list.wire_order_tlvs().expect("wire order preserved");
        for tlv in wire_order {
            assert!(
                tlv.is_integrity_failed(),
                "§4.8 failure procedure sets I on every TLV; {:?} lacks it",
                tlv.tlv_type
            );
        }
    }

    /// RFC8972-4.8-2: "The HMAC TLV MUST follow all TLVs included in a STAMP
    /// test packet **except for the Extra Padding TLV**" — so Extra Padding
    /// after the HMAC TLV is a legal layout from a conformant peer. It must
    /// not be marked malformed, and the HMAC must still verify: that trailing
    /// padding lies outside the HMAC's coverage.
    #[test]
    fn test_extra_padding_after_hmac_is_legal_and_verifies() {
        let key = HmacKey::new(vec![0x44; 32]).unwrap();
        let seq = [0u8, 0, 0, 7];

        // Covered prefix: one Class of Service TLV.
        let covered = RawTlv::new(TlvType::ClassOfService, vec![0x11; 4]);
        let mut covered_bytes = Vec::new();
        covered.write_to(&mut covered_bytes);

        // The peer's HMAC is over seq + the covered prefix only.
        let mut hmac_input = Vec::new();
        hmac_input.extend_from_slice(&seq);
        hmac_input.extend_from_slice(&covered_bytes);
        let mac = key.compute(&hmac_input);

        let mut buf = covered_bytes.clone();
        RawTlv::new(TlvType::Hmac, mac.to_vec()).write_to(&mut buf);
        // Trailing filler, outside the HMAC's coverage.
        RawTlv::new(TlvType::ExtraPadding, vec![0xBB; 8]).write_to(&mut buf);

        let (mut list, any_malformed) = TlvList::parse_lenient(&buf);
        assert!(
            !any_malformed,
            "Extra Padding after the HMAC TLV is a legal position, not malformed"
        );
        assert!(!list.hmac_misplaced(), "the HMAC is correctly positioned");

        let ok = list.apply_reflector_flags(Some(&key), &seq, &buf);
        assert!(
            ok,
            "the HMAC must verify — trailing Extra Padding is not covered by it"
        );
        for tlv in list.iter() {
            assert!(
                !tlv.is_integrity_failed(),
                "no TLV may carry I on a successful verification; {:?} does",
                tlv.tlv_type
            );
        }
    }

    /// The strict parser gets the same §4.8 exemption: trailing Extra Padding
    /// is accepted, anything else after the HMAC TLV is still `HmacNotLast`.
    #[test]
    fn test_strict_parse_allows_only_extra_padding_after_hmac() {
        let mut ok_buf = Vec::new();
        RawTlv::new(TlvType::Hmac, vec![0xAA; 16]).write_to(&mut ok_buf);
        RawTlv::new(TlvType::ExtraPadding, vec![0xBB; 4]).write_to(&mut ok_buf);
        let list = TlvList::parse(&ok_buf).expect("trailing Extra Padding is legal");
        assert_eq!(list.len(), 2);

        let mut bad_buf = Vec::new();
        RawTlv::new(TlvType::Hmac, vec![0xAA; 16]).write_to(&mut bad_buf);
        RawTlv::new(TlvType::ClassOfService, vec![0xBB; 4]).write_to(&mut bad_buf);
        assert!(matches!(
            TlvList::parse(&bad_buf),
            Err(TlvError::HmacNotLast)
        ));
    }

    #[test]
    fn test_apply_reflector_flags_preserves_parser_m_on_bad_hmac_length() {
        // HMAC TLV with the wrong Value length is structurally malformed.
        // parse_lenient marks it via the parser marker; apply_reflector_flags
        // must re-set M after clearing.
        let mut buf = Vec::new();
        buf.push(0x00);
        buf.push(0x08); // HMAC type
        buf.extend_from_slice(&8u16.to_be_bytes()); // wrong: 8 instead of 16
        buf.extend_from_slice(&[0xAA; 8]);

        let (mut list, any_malformed) = TlvList::parse_lenient(&buf);
        assert!(any_malformed);

        let raw = list.to_bytes();
        list.apply_reflector_flags(None, &[0u8; 4], &raw);

        let hmac = list.hmac_tlv().expect("HMAC TLV stored");
        assert!(hmac.is_malformed(), "bad-length HMAC must keep M-flag");
    }

    #[test]
    fn test_set_hmac_sender_variant_uses_u1() {
        // Sender path: per RFC 8972 §4 the sender MUST set U=1.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut list = TlvList::new();
        list.set_hmac(&key, &[0u8; 4]);
        let hmac = list.hmac_tlv().unwrap();
        assert!(hmac.is_unrecognized(), "sender HMAC TLV must have U=1");
        assert!(!hmac.is_malformed());
        assert!(!hmac.is_integrity_failed());
    }

    #[test]
    fn test_set_hmac_variants_compute_identical_bytes() {
        // `set_hmac_response` is a thin wrapper over `set_hmac` that only
        // mutates the flags byte; the HMAC value bytes must stay identical.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let seq = [0x01, 0x02, 0x03, 0x04];

        let mut sender = TlvList::new();
        sender
            .push(RawTlv::new(TlvType::ClassOfService, vec![0; 4]))
            .unwrap();
        sender.set_hmac(&key, &seq);

        let mut response = TlvList::new();
        response
            .push(RawTlv::new(TlvType::ClassOfService, vec![0; 4]))
            .unwrap();
        response.set_hmac_response(&key, &seq);

        let s_hmac = sender.hmac_tlv().unwrap();
        let r_hmac = response.hmac_tlv().unwrap();

        assert_eq!(s_hmac.value, r_hmac.value, "HMAC bytes must match");
        assert_ne!(
            s_hmac.flags, r_hmac.flags,
            "flags must differ (sender U=1, response U=0)"
        );
        assert!(s_hmac.is_unrecognized()); // sender variant
        assert!(!r_hmac.is_unrecognized()); // response variant
    }

    #[test]
    fn test_set_hmac_response_variant_uses_u0() {
        // Reflector path: HMAC type is recognized, so U=0 per RFC 8972 §4.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let mut list = TlvList::new();
        list.set_hmac_response(&key, &[0u8; 4]);
        let hmac = list.hmac_tlv().unwrap();
        assert!(
            !hmac.is_unrecognized(),
            "reflector-regenerated HMAC TLV must have U=0"
        );
        assert!(!hmac.is_malformed());
        assert!(!hmac.is_integrity_failed());
    }

    #[test]
    fn test_apply_reflector_flags_clears_uim_and_keeps_i_zero_on_hmac_ok() {
        // Same pipeline, matched keys: U/M/I should all be 0 after the pass.
        let key = HmacKey::new(vec![0xAB; 32]).unwrap();
        let base_packet = vec![0x01, 0x02, 0x03, 0x04];

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::ClassOfService, vec![0; 4]))
            .unwrap();
        list.set_hmac(&key, &base_packet);
        let tlv_bytes = list.to_bytes();

        let result = list.apply_reflector_flags(Some(&key), &base_packet, &tlv_bytes);

        assert!(result, "matched keys must verify");
        let cos = &list.non_hmac_tlvs()[0];
        assert!(!cos.is_unrecognized());
        assert!(!cos.is_malformed());
        assert!(!cos.is_integrity_failed());
        assert!(!list.hmac_tlv().unwrap().is_integrity_failed());
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
