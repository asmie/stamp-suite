//! TlvList collection with HMAC, parsing, serialization, and flag management.

mod processing;

use crate::crypto::HmacKey;
use crate::tlv::core::{RawTlv, TlvError, TlvFlags, TlvType, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE};

/// A list of TLVs with special handling for HMAC TLV.
///
/// Per RFC 8972, only Extra Padding may follow the HMAC TLV.
/// Failure echoes preserve wire order, since the reflector copies the received
/// TLVs (RFC 8972 §4 and §4.8).
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
    /// HMAC verification failure". See `apply_reflector_flags_strict`.
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

    #[cfg(test)]
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
    /// RFC 10052 §3 computes the reflected length
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

    #[cfg(test)]
    /// Test-only borrowed view of preserved wire order. Production serialization
    /// follows indices without allocating a view or cloning payloads.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn wire_order_tlvs(&self) -> Option<Vec<&RawTlv>> {
        self.wire_order
            .as_ref()
            .map(|order| order.iter().map(|&i| &self.entries[i]).collect())
    }

    /// Parses a TLV list from a buffer. A trailing fragment shorter than a
    /// TLV header is not a TLV and is ignored.
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
            // STAMP test packet except for the Extra Padding TLV". Trailing
            // Extra Padding is pure filler outside the HMAC's coverage, so it
            // is a legal position, not a misplaced HMAC.
            if found_hmac && tlv.tlv_type != TlvType::ExtraPadding {
                return Err(TlvError::HmacNotLast);
            }

            if tlv.tlv_type.is_hmac() {
                found_hmac = true;
                if tlv.value.len() != HMAC_TLV_VALUE_SIZE {
                    return Err(TlvError::InvalidLength {
                        kind: TlvType::Hmac,
                        length: tlv.value.len(),
                    });
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

        // Keep the received order when serialization would change it: an HMAC
        // followed by Extra Padding, or (with BER, whose padding is written
        // after the HMAC) Extra Padding received before the HMAC.
        if let Some(at) = list.hmac_wire_offset {
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
            let hmac_not_last = at + TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE < offset;
            let padding_moves = list.ber_padding_after_hmac()
                && list.non_hmac_tlvs()[..before_hmac]
                    .iter()
                    .any(|tlv| tlv.tlv_type == TlvType::ExtraPadding);
            if hmac_not_last || padding_moves {
                list.wire_order = Some(
                    (0..before_hmac)
                        .chain(std::iter::once(list.non_hmac_len))
                        .chain(before_hmac..list.non_hmac_len)
                        .collect(),
                );
            }
        }
        Ok(list)
    }

    /// Parses a TLV list leniently, marking malformed TLVs with M-flag.
    ///
    /// Unlike `parse()`, this method:
    /// - Handles truncated TLVs by marking them as malformed (M-flag)
    /// - Continues parsing after recoverable errors
    /// - Does not fail on HMAC length mismatch (marks as malformed instead)
    /// - Preserves wire order so failure echoes copy the received TLVs
    ///   (RFC 8972 §4 and §4.8)
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
        // An all-zero remainder is padding, not a run of empty Type-0 TLVs.
        // Computed once: rescanning the tail at every zero header is
        // quadratic in the datagram size.
        let data_end = buf.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);

        while offset < buf.len() {
            if buf.len() - offset < TLV_HEADER_SIZE || offset >= data_end {
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
                        // HMAC verification failure". This is recorded here and
                        // acted on in `apply_reflector_flags_strict`. The M flag is
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
        let has_ber = parsed_tlvs.iter().any(|t| crate::ber::is_ber(t.tlv_type));
        // With BER, serialization writes Extra Padding after the HMAC; keep
        // the received order if padding arrived before it.
        let padding_moves = has_ber
            && parsed_tlvs
                .iter()
                .take_while(|t| !t.tlv_type.is_hmac())
                .any(|t| t.tlv_type == TlvType::ExtraPadding)
            && found_hmac;
        let need_wire_order = malformed_echo
            || padding_moves
            || (found_hmac && parsed_tlvs.last().is_some_and(|t| !t.tlv_type.is_hmac()));
        let non_hmac_len = parsed_tlvs.iter().filter(|t| !t.tlv_type.is_hmac()).count();
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
            .map_err(|_| TlvError::InvalidLength {
                kind: TlvType::Hmac,
                length: hmac_tlv.value.len(),
            })
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

    /// True when the list is exactly one Extra Padding TLV, the only case in
    /// which authenticated mode may omit the HMAC TLV (RFC 8972 §4.8).
    #[must_use]
    pub fn contains_only_extra_padding(&self) -> bool {
        matches!(self.entries.as_slice(), [only] if only.tlv_type == TlvType::ExtraPadding)
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
    ///
    /// Returns false, leaving the list unchanged, for structurally malformed
    /// lists: a new HMAC TLV cannot follow a truncated TLV.
    pub fn set_hmac_response(&mut self, key: &HmacKey, sequence_number_bytes: &[u8]) -> bool {
        if self.malformed_echo {
            return false;
        }
        self.set_hmac(key, sequence_number_bytes);
        if let Some(hmac) = self.hmac_tlv_mut() {
            hmac.flags = TlvFlags::default();
        }
        true
    }

    /// Whether the TLVs before the first malformed one may be processed.
    /// A structurally malformed list that carries an HMAC TLV is only echoed:
    /// processing would change bytes its HMAC covers, and the reply cannot
    /// be re-signed without changing the received layout.
    #[must_use]
    pub fn allows_processing(&self) -> bool {
        !(self.malformed_echo && self.hmac_tlv().is_some())
    }

    #[cfg(test)]
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
        self.mark_unprocessed_after_malformed();

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

    /// RFC 8972 §4: "If a TLV is malformed, the processing of extension TLVs
    /// MUST be stopped" and the remainder is copied. Every non-HMAC TLV after
    /// the first malformed one, in wire order, gets U (not processed) instead
    /// of the flags derived for it. The HMAC TLV is still verified.
    fn mark_unprocessed_after_malformed(&mut self) {
        let mut stopped = false;
        let non_hmac_len = self.non_hmac_len;
        for position in 0..self.entries.len() {
            let index = self.wire_order.as_ref().map_or(position, |o| o[position]);
            let tlv = &mut self.entries[index];
            if stopped && index < non_hmac_len {
                tlv.clear_reflector_flags();
                tlv.set_unrecognized();
            } else if tlv.is_malformed() && index < non_hmac_len {
                stopped = true;
            }
        }
    }

    /// Clears U, M, I *and* the C/Conformant bit on every TLV (the parser's
    /// own malformed marker is preserved) so the setters in
    /// `apply_reflector_flags_strict` can re-derive each flag per RFC 8972 §4.
    ///
    /// C is cleared rather than preserved because the Session-Reflector MUST
    /// ignore the received C value and derive its own (RFC 10052 §3). See
    /// [`RawTlv::clear_reflector_flags`], which this delegates to.
    pub fn clear_reflector_flags(&mut self) {
        for tlv in &mut self.entries {
            tlv.clear_reflector_flags();
        }
    }

    #[cfg(test)]
    /// Re-derives the M-flag on every TLV held by this list, per RFC 8972 §4.
    ///
    /// For each TLV, sets M=1 when **either**:
    /// - the parser previously detected a structural / positional error and
    ///   recorded it via `mark_malformed_by_parser` (truncation, TLV after
    ///   HMAC, bad HMAC length; the marker survives the reflector's
    ///   flag-clear pass), or
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
                // Optional sub-TLVs may follow the four fields (RFC 8972 §4.3).
                TlvType::TimestampInfo => tlv.value.len() < TIMESTAMP_INFO_TLV_VALUE_SIZE,
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
                // BerPattern: any length parses; BER processing sets C on an
                // empty one. 246/247: variable Value is valid (request: zeros
                // sized to header; response: filled).
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
mod tests;
