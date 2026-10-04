//! In-place reflector updates for `TlvList`.

use crate::ber::xor_popcount_and_max_burst;
use crate::tlv::core::{
    RawTlv, TlvFlags, TlvSpan, TlvType, ACCESS_REPORT_TLV_VALUE_SIZE, BER_BURST_TLV_VALUE_SIZE,
    BER_COUNT_TLV_VALUE_SIZE, COS_TLV_VALUE_SIZE, DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
    FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE, LOCATION_TLV_MIN_VALUE_SIZE,
    REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL, REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE,
    TIMESTAMP_INFO_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
};
use crate::tlv::{
    ClassOfServiceTlv, DestinationNodeAddressTlv, LocationDisclosure, LocationSubType,
    MicroSessionIdTlv, PacketAddressInfo, ReflectedControlTlv, ReturnPathAction, ReturnPathTlv,
    SegmentList, SyncSource, TimestampMethod, TypedTlv, BER_DEFAULT_PATTERN,
};

use super::TlvList;

/// Result of matching a Destination Node Address TLV (RFC 9503 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationNodeAddressOutcome {
    /// No Destination Node Address TLV was present.
    Absent,
    /// The TLV named one of the reflector's own addresses. RFC 9503 §3: "it
    /// SHOULD be used as the Source Address in the IP header of the reply test
    /// packet".
    Matched(std::net::IpAddr),
    /// The TLV named an address that is not ours; the echoed TLV carries the
    /// U-flag and there is nothing to pin.
    Unmatched,
}

impl DestinationNodeAddressOutcome {
    /// The address to pin as the reply's source, if any.
    #[must_use]
    pub fn pinned_source(self) -> Option<std::net::IpAddr> {
        match self {
            Self::Matched(addr) => Some(addr),
            Self::Absent | Self::Unmatched => None,
        }
    }

    #[cfg(test)]
    /// True unless a TLV was present and named an address that is not ours.
    #[must_use]
    pub fn matched_or_absent(self) -> bool {
        !matches!(self, Self::Unmatched)
    }
}

impl TlvList {
    /// Calls `f` once on each processable non-HMAC owner for which `pred`
    /// returns true. See [`RawTlv::is_processable`].
    fn for_each_matching_tlv(
        &mut self,
        mut pred: impl FnMut(&RawTlv) -> bool,
        mut f: impl FnMut(&mut RawTlv),
    ) {
        for tlv in self.non_hmac_tlvs_mut() {
            if tlv.is_processable() && pred(tlv) {
                f(tlv);
            }
        }
    }

    /// Extracts the requested DSCP1/ECN1 from the first CoS TLV, when that
    /// TLV is processable and valid.
    #[must_use]
    pub fn get_cos_request(&self) -> Option<(u8, u8)> {
        let tlv = self
            .non_hmac_tlvs()
            .iter()
            .find(|tlv| tlv.tlv_type == TlvType::ClassOfService)
            .filter(|tlv| tlv.is_processable())?;
        let cos = ClassOfServiceTlv::from_raw(tlv).ok()?;
        Some((cos.dscp1, cos.ecn1))
    }

    /// Updates CoS DSCP2/EC2 from ingress metadata and RPD/RPE from the reply
    /// policy (RFC 8972 §4.4, erratum 8199; draft-ietf-ippm-stamp-cos-ecn-01 §3.2).
    /// Preserves requested DSCP1/EC1, zeroes the Reserved bits, and mutates
    /// without allocation.
    ///
    /// `policy_rejected` sets RPD for DSCP1 rejection. `reply_ecn_applied` selects
    /// RPE=0b11 (applied) or 0b10 (unable). For 0b10, the backend must also force
    /// the reply IP header to Not-ECT via `reply_wire_tos` or `cos_unable_fallback_tos`.
    pub fn update_cos_tlvs(
        &mut self,
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
        reply_ecn_applied: bool,
    ) {
        self.for_each_matching_tlv(
            |tlv| tlv.tlv_type == TlvType::ClassOfService && tlv.value.len() == COS_TLV_VALUE_SIZE,
            |tlv| {
                Self::update_cos_value_in_place(
                    &mut tlv.value,
                    received_dscp,
                    received_ecn,
                    policy_rejected,
                    reply_ecn_applied,
                );
            },
        );
    }

    /// Updates CoS TLV value bytes in-place.
    ///
    /// Modifies DSCP2/EC2/RPD/RPE without allocating a new value buffer,
    /// preserving the sender's DSCP1/EC1 bits. Assumes value is exactly
    /// `COS_TLV_VALUE_SIZE` (4) bytes.
    #[inline]
    fn update_cos_value_in_place(
        value: &mut [u8],
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
        reply_ecn_applied: bool,
    ) {
        // Byte 0: keep DSCP1 (bits 7:2), write DSCP2's upper 2 bits.
        value[0] = (value[0] & 0xFC) | ((received_dscp >> 4) & 0x03);

        // Byte 1: DSCP2's lower 4 bits | EC2 | RPD.
        let rpd = if policy_rejected { 0b01 } else { 0b00 };
        value[1] = ((received_dscp & 0x0F) << 4) | ((received_ecn & 0x03) << 2) | rpd;

        // Byte 2: keep EC1 (bits 7:6), write RPE, zero Reserved (bits 3:0).
        // Byte 3 is Reserved; reserved bits MUST be zeroed on transmission
        // (RFC 8972 §4.4, draft-ietf-ippm-stamp-cos-ecn-01 §3.1).
        let rpe = if reply_ecn_applied { 0b11 } else { 0b10 };
        value[2] = (value[2] & 0xC0) | (rpe << 4);
        value[3] = 0;
    }

    #[cfg(test)]
    /// Fills all Timestamp Information fields with reflector clock metadata
    /// (RFC 8972 §4.3). Ingress describes T2; egress describes T3.
    /// Report the methods separately because they can differ. Sender values are
    /// replaced, as requests must zero all four bytes (RFC 8972 §4.3).
    pub fn update_timestamp_info_tlvs(
        &mut self,
        sync_src: SyncSource,
        ingress_method: TimestampMethod,
        egress_method: TimestampMethod,
    ) {
        self.update_timestamp_info_tlvs_with_sources(
            sync_src,
            ingress_method,
            sync_src,
            egress_method,
        );
    }

    /// Report the separately disciplined ingress and egress clocks.
    pub fn update_timestamp_info_tlvs_with_sources(
        &mut self,
        ingress_source: SyncSource,
        ingress_method: TimestampMethod,
        egress_source: SyncSource,
        egress_method: TimestampMethod,
    ) {
        let ingress_byte = ingress_method.to_byte();
        let egress_byte = egress_method.to_byte();
        self.for_each_matching_tlv(
            |tlv| {
                tlv.tlv_type == TlvType::TimestampInfo
                    && tlv.value.len() >= TIMESTAMP_INFO_TLV_VALUE_SIZE
            },
            |tlv| {
                tlv.value[0] = ingress_source.to_byte();
                tlv.value[1] = ingress_byte;
                tlv.value[2] = egress_source.to_byte();
                tlv.value[3] = egress_byte;
            },
        );
    }

    /// Updates Direct Measurement TLVs with the reflector's packet counters.
    ///
    /// Per RFC 8972 §4.5, the Session-Reflector fills `R_RxC` and `R_TxC`
    /// (bytes 4-11 of the value) while preserving `S_TxC` (bytes 0-3).
    pub fn update_direct_measurement_tlvs(&mut self, rx_count: u32, tx_count: u32) {
        let rx_bytes = rx_count.to_be_bytes();
        let tx_bytes = tx_count.to_be_bytes();
        self.for_each_matching_tlv(
            |tlv| {
                tlv.tlv_type == TlvType::DirectMeasurement
                    && tlv.value.len() == DIRECT_MEASUREMENT_TLV_VALUE_SIZE
            },
            |tlv| {
                tlv.value[4..8].copy_from_slice(&rx_bytes);
                tlv.value[8..12].copy_from_slice(&tx_bytes);
            },
        );
    }

    /// Updates Location TLVs with the observed packet address information.
    ///
    /// Per RFC 8972 §4.2, the Session-Reflector fills in the ports and adds
    /// sub-TLVs for the source and destination IP addresses it observed,
    /// subject to `policy`, the operator-managed field-disclosure control of
    /// §4.2.2 (see [`LocationDisclosure`]).
    pub fn update_location_tlvs(&mut self, info: &PacketAddressInfo, policy: LocationDisclosure) {
        self.for_each_matching_tlv(
            |tlv| {
                tlv.tlv_type == TlvType::Location && tlv.value.len() >= LOCATION_TLV_MIN_VALUE_SIZE
            },
            |tlv| Self::update_location_value_in_place(&mut tlv.value, info, policy),
        );
    }

    /// Updates Location ports and request sub-TLVs in place (RFC 8972 §4.2/§4.2.2).
    /// Generic requests become specific responses: Source IP 7→8/9,
    /// Destination IP 4→5/6, Source MAC 1→2/3. Each retains its original size.
    ///
    /// Unknown sub-TLVs keep their bytes and get U set. Invalid lengths get M set
    /// and stop sub-TLV processing. Preserve trailing bytes and the total TLV length.
    fn update_location_value_in_place(
        value: &mut [u8],
        info: &PacketAddressInfo,
        policy: LocationDisclosure,
    ) {
        // Ports always fit: callers only invoke this for values that are
        // already >= LOCATION_TLV_MIN_VALUE_SIZE (4 octets). A port the
        // disclosure policy withholds is left as zeroes per §4.2.2's "MAY
        // leave some fields unreported by filling them with zeroes".
        if policy.dst_port {
            value[0..2].copy_from_slice(&info.dst_port.to_be_bytes());
        } else {
            value[0..2].fill(0);
        }
        if policy.src_port {
            value[2..4].copy_from_slice(&info.src_port.to_be_bytes());
        } else {
            value[2..4].fill(0);
        }

        let mut offset = LOCATION_TLV_MIN_VALUE_SIZE;
        while offset + TLV_HEADER_SIZE <= value.len() {
            let length = u16::from_be_bytes([value[offset + 2], value[offset + 3]]) as usize;
            let end = match offset
                .checked_add(TLV_HEADER_SIZE)
                .and_then(|h| h.checked_add(length))
            {
                Some(end) if end <= value.len() => end,
                // Truncated: the sub-TLV runs past the end of the value.
                // RFC 8972 §4 M-flag rule → mark malformed and stop.
                _ => {
                    set_sub_tlv_flag(&mut value[offset..], LocationSubFlag::Malformed);
                    break;
                }
            };
            if Self::answer_location_sub_tlv(&mut value[offset..end], info, policy)
                == LocationSubOutcome::Malformed
            {
                // §4: processing of extension TLVs MUST stop; the remainder is
                // copied verbatim (it is left untouched by the in-place edit).
                break;
            }
            offset = end;
        }
    }

    /// Answers a single Location sub-TLV in place (its slice spans the 4-octet
    /// header and value). Returns the outcome so the caller can stop on a
    /// malformed sub-TLV per RFC 8972 §4.
    fn answer_location_sub_tlv(
        sub: &mut [u8],
        info: &PacketAddressInfo,
        policy: LocationDisclosure,
    ) -> LocationSubOutcome {
        let sub_type = LocationSubType::from_byte(sub[1]);
        let vlen = sub.len() - TLV_HEADER_SIZE;

        // A recognized type whose Length is not the RFC-mandated value is
        // malformed (RFC 8972 §4: "the Length field value is not valid for the
        // particular type").
        if let Some(expected) = sub_type.mandated_value_len() {
            if vlen != expected {
                set_sub_tlv_flag(sub, LocationSubFlag::Malformed);
                return LocationSubOutcome::Malformed;
            }
        }

        match sub_type {
            LocationSubType::SourceMac => {
                // §4.2.2: an EUI-48 source MAC is copied into a Source EUI-48
                // answer. Without one (the nix backend has no link layer) the
                // answer is Source EUI-64 with the field zeroed.
                if !policy.src_mac {
                    Self::suppress_sub_tlv_answer(sub);
                    return LocationSubOutcome::Answered;
                }
                sub[TLV_HEADER_SIZE..].fill(0);
                match info.src_mac {
                    Some(mac) => {
                        sub[1] = LocationSubType::SourceEui48.to_byte();
                        sub[TLV_HEADER_SIZE..TLV_HEADER_SIZE + 6].copy_from_slice(&mac);
                    }
                    None => sub[1] = LocationSubType::SourceEui64.to_byte(),
                }
                set_sub_tlv_flag(sub, LocationSubFlag::Answered);
                LocationSubOutcome::Answered
            }
            LocationSubType::DestinationIp => {
                if policy.dst_ip {
                    Self::write_ip_sub_tlv_answer(sub, info.dst_addr, true);
                } else {
                    Self::suppress_sub_tlv_answer(sub);
                }
                LocationSubOutcome::Answered
            }
            LocationSubType::SourceIp => {
                if policy.src_ip {
                    Self::write_ip_sub_tlv_answer(sub, info.src_addr, false);
                } else {
                    Self::suppress_sub_tlv_answer(sub);
                }
                LocationSubOutcome::Answered
            }
            // Any other type (including the specific answer types, which a
            // Session-Sender is not expected to request) is not a generic
            // request we can act on: echo it and set the U flag (RFC 8972 §4
            // unrecognized-TLV rule).
            _ => {
                set_sub_tlv_flag(sub, LocationSubFlag::Unrecognized);
                LocationSubOutcome::Unrecognized
            }
        }
    }

    /// Zeroes a withheld field without changing its generic request type
    /// (RFC 8972 §4.2.2). Choosing an IPv4/IPv6 response type would disclose
    /// the address family even with a zeroed value.
    fn suppress_sub_tlv_answer(sub: &mut [u8]) {
        sub[TLV_HEADER_SIZE..].fill(0);
        set_sub_tlv_flag(sub, LocationSubFlag::Answered);
    }

    /// Writes a generic Destination/Source IP request answer in place, choosing
    /// the IPv4 or IPv6 specific type from the observed address family and
    /// zeroing the MBZ tail (RFC 8972 §4.2.1/§4.2.2). `sub` spans the 4-octet
    /// header plus a validated 16-octet value.
    fn write_ip_sub_tlv_answer(sub: &mut [u8], addr: std::net::IpAddr, is_dest: bool) {
        match addr {
            std::net::IpAddr::V4(a) => {
                sub[1] = if is_dest {
                    LocationSubType::DestinationIpv4.to_byte()
                } else {
                    LocationSubType::SourceIpv4.to_byte()
                };
                let body = &mut sub[TLV_HEADER_SIZE..];
                body[..4].copy_from_slice(&a.octets());
                body[4..].fill(0);
            }
            std::net::IpAddr::V6(a) => {
                sub[1] = if is_dest {
                    LocationSubType::DestinationIpv6.to_byte()
                } else {
                    LocationSubType::SourceIpv6.to_byte()
                };
                sub[TLV_HEADER_SIZE..].copy_from_slice(&a.octets());
            }
        }
        set_sub_tlv_flag(sub, LocationSubFlag::Answered);
    }

    /// Updates Follow-Up Telemetry (RFC 8972 §4.7).
    /// `Some` reports the previous stateful reflection; `None` zeroes
    /// sequence/timestamp for stateless mode.
    /// Invalid-length TLVs also zero any present sequence/timestamp bytes
    /// (erratum 8339); length validation sets M separately.
    pub fn update_follow_up_telemetry_tlvs(
        &mut self,
        reflection: Option<(u32, u64)>,
        mode: TimestampMethod,
    ) {
        let mode_byte = mode.to_byte();
        // Not `for_each_matching_tlv`: an invalid-length TLV carries M and
        // must still have its fields zeroed (erratum 8339).
        for tlv in self.non_hmac_tlvs_mut() {
            if tlv.tlv_type != TlvType::FollowUpTelemetry
                || tlv.is_unrecognized()
                || tlv.is_integrity_failed()
            {
                continue;
            }
            {
                let valid_len = tlv.value.len() == FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE;
                match reflection {
                    // Stateful mode + well-formed TLV: report the previous
                    // reflection's seq/timestamp/method.
                    Some((last_seq, last_ts)) if valid_len => {
                        tlv.value[0..4].copy_from_slice(&last_seq.to_be_bytes());
                        tlv.value[4..12].copy_from_slice(&last_ts.to_be_bytes());
                        tlv.value[12] = mode_byte;
                        tlv.value[13..16].fill(0); // Reserved
                    }
                    // Stateless mode OR invalid length (RFC 8972 §4.7): zero
                    // the Sequence Number and Follow-Up Timestamp fields (the
                    // first 12 octets), clamped to whatever the value holds.
                    _ => {
                        let end = tlv.value.len().min(12);
                        tlv.value[..end].fill(0);
                    }
                }
            }
        }
    }

    /// Marks well-formed Access Reports with IDs other than 1 or 2 unrecognized
    /// (RFC 8972 §4.6). U makes the sender skip the report (§4) while preserving
    /// the echoed bytes and symmetric packet size (RFC 8762 §4.3/§4.6).
    /// Invalid lengths are handled separately by the M-flag validator.
    pub fn discard_invalid_access_report_tlvs(&mut self) {
        self.for_each_matching_tlv(
            |tlv| {
                if tlv.tlv_type != TlvType::AccessReport
                    || tlv.value.len() != ACCESS_REPORT_TLV_VALUE_SIZE
                {
                    return false;
                }
                let access_id = (tlv.value[0] >> 4) & 0x0F;
                access_id != 1 && access_id != 2
            },
            RawTlv::set_unrecognized,
        );
    }

    /// Processes Destination Node Address TLVs per RFC 9503 §3.
    ///
    /// Finds the first Destination Node Address TLV and checks if the address
    /// matches one of the reflector's local addresses. If not, sets the U-flag.
    ///
    /// Returns the outcome, which carries the matched address: RFC 9503 §3 says
    /// it SHOULD become the reply's IP source address, so the send path needs it
    /// and not merely a yes/no.
    pub fn process_destination_node_address(
        &mut self,
        local_addrs: &[std::net::IpAddr],
    ) -> DestinationNodeAddressOutcome {
        let mut outcome = DestinationNodeAddressOutcome::Absent;

        // The non-HMAC prefix retains encounter order.
        for tlv in self.non_hmac_tlvs_mut() {
            if tlv.tlv_type == TlvType::DestinationNodeAddress {
                if !tlv.is_processable() {
                    break;
                }
                if let Ok(dna) = DestinationNodeAddressTlv::from_raw(tlv) {
                    if local_addrs.contains(&dna.address) {
                        outcome = DestinationNodeAddressOutcome::Matched(dna.address);
                    } else {
                        tlv.set_unrecognized();
                        outcome = DestinationNodeAddressOutcome::Unmatched;
                    }
                }
                break;
            }
        }

        outcome
    }

    /// Processes the first Return Path TLV (RFC 9503 §4).
    /// Uses `sender_port` for alternate-address replies. When `allow_alternate`
    /// is false, Return Address requests get U set and replies use the packet source.
    /// `ingress_ifindex` is the arrival interface when the reply can be pinned
    /// to it; without it a same-link request gets U.
    pub fn process_return_path(
        &mut self,
        sender_port: u16,
        allow_alternate: bool,
        ingress_ifindex: Option<u32>,
    ) -> ReturnPathAction {
        // Find the first Return Path TLV
        let rp_idx = self
            .non_hmac_tlvs()
            .iter()
            .position(|tlv| tlv.tlv_type == TlvType::ReturnPath);

        let Some(idx) = rp_idx.filter(|&i| self.non_hmac_tlvs()[i].is_processable()) else {
            return ReturnPathAction::Normal;
        };

        let Ok(rp) = ReturnPathTlv::from_raw(&self.non_hmac_tlvs()[idx]) else {
            // A Return Path TLV that does not parse gets U.
            self.non_hmac_tlvs_mut()[idx].set_unrecognized();

            return ReturnPathAction::Normal;
        };

        // RFC 9503 §4.1.1: only Control Code bit 0 (reply request) is
        // meaningful; the remaining bits are reserved and ignored.
        if let Some(cc) = rp.get_control_code() {
            if cc & 1 == 0 {
                return ReturnPathAction::SuppressReply;
            }
            // Bit 0 requests a reply on the incoming link (RFC 9503 §4.1.1).
            // The send path sets U if pinning the interface fails.
            return match ingress_ifindex {
                Some(index) => ReturnPathAction::SameLink(index),
                None => {
                    self.set_return_path_u_flag();
                    ReturnPathAction::Normal
                }
            };
        }

        // A Return Address and a segment list may be combined (RFC 9503 §4.1).
        let destination = match rp.get_return_address() {
            Some(addr) if allow_alternate => Some(std::net::SocketAddr::new(addr, sender_port)),
            Some(_) => {
                // Redirection not permitted (default): signal "unsupported"
                // with U and reply to the packet source. Otherwise an
                // unauthenticated peer could aim replies, and any Type-12
                // amplification, at an arbitrary victim.
                self.set_return_path_u_flag();
                return ReturnPathAction::Normal;
            }
            None => None,
        };

        match rp.first_segment_list() {
            // The send path attempts SRH forwarding and sets U on fallback
            // (RFC 9503 §4, RFC 8754).
            Some(SegmentList::Srv6(sids)) => ReturnPathAction::Srv6Forward { sids, destination },
            // SR-MPLS cannot be sent from a userspace UDP socket.
            Some(SegmentList::SrMpls) => {
                self.set_return_path_u_flag();
                ReturnPathAction::UnsupportedSr
            }
            Some(SegmentList::Invalid) => {
                self.set_return_path_u_flag();
                ReturnPathAction::Normal
            }
            None => match destination {
                Some(destination) => ReturnPathAction::AlternateAddress(destination),
                None => {
                    // No usable sub-TLV.
                    self.set_return_path_u_flag();
                    ReturnPathAction::Normal
                }
            },
        }
    }

    /// Sets the U-flag on the first Return Path owner.
    ///
    /// Public so the receiver can flag the Return Path TLV in the
    /// RFC 10052 §4.3 conflict case (no-reply
    /// control code combined with a non-zero Reflected Test Packet Control
    /// TLV).
    pub fn set_return_path_u_flag(&mut self) {
        for tlv in self.non_hmac_tlvs_mut() {
            if tlv.tlv_type == TlvType::ReturnPath {
                tlv.set_unrecognized();
                break;
            }
        }
    }

    /// Processes Micro-session ID TLVs per RFC 9534 §3.2.
    ///
    /// For each Micro-session ID TLV:
    /// - Validates that if `reflector_micro_session_id` is non-zero, it matches
    ///   `reflector_member_link_id` (returns `false` on mismatch → packet discarded)
    /// - Echoes the sender's micro-session ID unchanged
    /// - Sets the reflector's micro-session ID to `reflector_member_link_id`
    ///
    /// Indexed wire views observe the same mutation.
    ///
    /// Returns `true` if all validations pass, `false` if a mismatch was found.
    pub fn update_micro_session_id_tlvs(&mut self, reflector_member_link_id: u16) -> bool {
        if !Self::apply_micro_session_id(self.non_hmac_tlvs_mut(), reflector_member_link_id) {
            return false;
        }

        true
    }

    /// Returns the first Reflected Test Packet Control TLV request, if present.
    ///
    /// Per RFC 10052 §3, only the first occurrence is
    /// honoured; duplicates are ignored.
    #[must_use]
    pub fn get_reflected_control_request(&self) -> Option<ReflectedControlTlv> {
        let tlv = self
            .non_hmac_tlvs()
            .iter()
            .find(|tlv| tlv.tlv_type == TlvType::ReflectedControl)
            .filter(|tlv| tlv.is_processable())?;
        ReflectedControlTlv::from_raw(tlv).ok()
    }

    /// Marks the first Reflected Test Packet Control TLV with U when its request
    /// cannot be honored, including a conflicting no-reply Return Path control
    /// (RFC 10052 §4.3).
    /// Address Group mismatches (§3.1.1/§3.1.2) instead drop the packet.
    pub fn set_reflected_control_u_flag(&mut self) {
        for tlv in self.non_hmac_tlvs_mut() {
            if tlv.tlv_type == TlvType::ReflectedControl {
                tlv.set_unrecognized();
                break;
            }
        }
    }

    /// Marks the first Reflected Test Packet Control TLV with the C flag
    /// (Conformant Reflected Packet, RFC 10052 §3).
    /// Call this when the reflector cannot fully honour the request
    /// (MTU exceeded, rate/volume cap, or local policy).
    ///
    /// The serialized wire view refers to this same owner.
    pub fn set_reflected_control_c_flag(&mut self) {
        for tlv in self.non_hmac_tlvs_mut() {
            if tlv.tlv_type == TlvType::ReflectedControl {
                tlv.set_conformant_reflected();
                break;
            }
        }
    }

    /// Measures and repairs BER padding (draft-gandhi-ippm-stamp-ber-07 §4.2).
    /// Invalid multiplicity or pattern alignment is reflected with C=1.
    pub fn process_ber(&mut self) {
        // Locate indices in self.non_hmac_tlvs()
        let mut padding_count = 0usize;
        let mut padding_idx: Option<usize> = None;
        let mut pattern_count = 0usize;
        let mut pattern_idx: Option<usize> = None;
        let mut count_count = 0usize;
        let mut count_idx: Option<usize> = None;
        let mut burst_count = 0usize;
        let mut burst_idx: Option<usize> = None;

        for (i, tlv) in self.non_hmac_tlvs().iter().enumerate() {
            if !tlv.is_processable() {
                continue;
            }
            match tlv.tlv_type {
                TlvType::ExtraPadding => {
                    padding_count += 1;
                    if padding_idx.is_none() {
                        padding_idx = Some(i);
                    }
                }
                TlvType::BerPattern => {
                    pattern_count += 1;
                    if pattern_idx.is_none() {
                        pattern_idx = Some(i);
                    }
                }
                TlvType::BerCount => {
                    count_count += 1;
                    if count_idx.is_none() {
                        count_idx = Some(i);
                    }
                }
                TlvType::BerBurst => {
                    burst_count += 1;
                    if burst_idx.is_none() {
                        burst_idx = Some(i);
                    }
                }
                _ => {}
            }
        }

        // No BER TLVs at all → nothing to do.
        if count_idx.is_none() && burst_idx.is_none() && pattern_idx.is_none() {
            return;
        }

        // draft-gandhi-ippm-stamp-ber-07 §4.2.1: invalid multiplicity is a
        // conformance error.
        let has_duplicate = pattern_count > 1 || count_count > 1 || burst_count > 1;

        // draft-gandhi-ippm-stamp-ber-07 §4.2.1 requires exactly one Extra Padding TLV.
        // Treat missing-or-duplicate Extra Padding as a protocol error too.
        let padding_invalid = padding_count != 1;

        if has_duplicate || padding_invalid {
            Self::mark_ber_tlvs_nonconformant(self.non_hmac_tlvs_mut());

            return;
        }

        // Borrow distinct owners directly: scan and repair without cloning the pattern.
        let (count, max_burst, aligned) = {
            let (pattern, padding) = self.ber_padding_slices(padding_idx.unwrap(), pattern_idx);
            let aligned = !pattern.is_empty() && padding.len() % pattern.len() == 0;
            if aligned {
                let (count, burst) = xor_popcount_and_max_burst(padding, pattern);
                for (i, byte) in padding.iter_mut().enumerate() {
                    *byte = pattern[i % pattern.len()];
                }
                (count, burst, true)
            } else {
                (0, 0, false)
            }
        };
        if !aligned {
            if pattern_idx.is_none() {
                Self::mark_ber_tlvs_nonconformant(self.non_hmac_tlvs_mut());
            }
            for tlv in self.non_hmac_tlvs_mut() {
                if tlv.tlv_type == TlvType::BerPattern && tlv.is_processable() {
                    tlv.set_conformant_reflected();
                }
            }
            return;
        }

        if let Some(i) = count_idx {
            Self::write_ber_count(&mut self.non_hmac_tlvs_mut()[i], count);
        }
        if let Some(i) = burst_idx {
            Self::write_ber_burst(&mut self.non_hmac_tlvs_mut()[i], max_burst);
        }
    }

    /// Keep repaired BER padding after another extension resizes the reply.
    /// Changed lengths invalidate the forward count's denominator.
    pub fn finish_ber_padding(&mut self, original_len: Option<usize>) {
        if !self.has_ber {
            return;
        }
        if self.non_hmac_tlvs().iter().any(|t| {
            crate::ber::is_ber(t.tlv_type)
                && (t.flags.conformant_reflected
                    || t.is_unrecognized()
                    || t.is_malformed()
                    || t.is_integrity_failed())
        }) {
            return;
        }
        let pattern_idx = self
            .non_hmac_tlvs()
            .iter()
            .position(|t| t.tlv_type == TlvType::BerPattern);
        if pattern_idx.is_some_and(|i| self.non_hmac_tlvs()[i].value.is_empty()) {
            return;
        }
        let length = self
            .non_hmac_tlvs()
            .iter()
            .find(|t| t.tlv_type == TlvType::ExtraPadding)
            .map(|t| t.value.len());
        if length != original_len {
            Self::mark_ber_tlvs_nonconformant(self.non_hmac_tlvs_mut());
        }
        for index in 0..self.non_hmac_len {
            if self.non_hmac_tlvs()[index].tlv_type == TlvType::ExtraPadding {
                let (pattern, padding) = self.ber_padding_slices(index, pattern_idx);
                for (i, byte) in padding.iter_mut().enumerate() {
                    *byte = pattern[i % pattern.len()];
                }
            }
        }
    }

    fn ber_padding_slices(&mut self, padding: usize, pattern: Option<usize>) -> (&[u8], &mut [u8]) {
        let tlvs = self.non_hmac_tlvs_mut();
        match pattern {
            None => (BER_DEFAULT_PATTERN.as_slice(), &mut tlvs[padding].value),
            Some(pattern) if pattern < padding => {
                let (left, right) = tlvs.split_at_mut(padding);
                (&left[pattern].value, &mut right[0].value)
            }
            Some(pattern) => {
                let (left, right) = tlvs.split_at_mut(pattern);
                (&right[0].value, &mut left[padding].value)
            }
        }
    }

    #[cfg(test)]
    /// Reflect captured headers into Types 246/247 (ext-hdr-15 §§4.1–4.2, 6.1–6.2).
    /// Match by length and nonzero Requested prefix, then copy the tail while
    /// preserving Requested (8 bytes for 246; 4 for 247). Consume each match.
    /// No capture or match sets C without changing the value.
    /// `captured_fixed` is one IP header; use `process_reflected_headers_multi`
    /// for stacked headers. `captured_ext_headers` holds concatenated IPv6
    /// headers in wire order, with each header's Next Header byte.
    pub fn process_reflected_headers(
        &mut self,
        captured_fixed: Option<&[u8]>,
        captured_ext_headers: Option<&[u8]>,
    ) {
        let fixed_list: Option<Vec<Vec<u8>>> = captured_fixed.map(|b| {
            if b.is_empty() {
                Vec::new()
            } else {
                vec![b.to_vec()]
            }
        });
        self.process_reflected_headers_multi(fixed_list.as_deref(), captured_ext_headers);
    }

    /// Reflect multiple fixed IP headers in outer-to-inner order
    /// (ext-hdr-15 §6.2). None means the backend cannot capture IP headers.
    /// Each Type-247 TLV consumes the first matching unconsumed header:
    /// zero Requested matches by length; nonzero also matches its prefix.
    /// Repeated same-length requests therefore select successive headers.
    pub fn process_reflected_headers_multi(
        &mut self,
        captured_fixed: Option<&[Vec<u8>]>,
        captured_ext_headers: Option<&[u8]>,
    ) {
        Self::apply_reflected_headers(
            self.non_hmac_tlvs_mut(),
            captured_fixed,
            captured_ext_headers,
        );
    }

    /// Remove Types 246/247 until `base_len + self.wire_size() <= max_reply_bytes`
    /// (ext-hdr-15 §§4.2, 6.2). Remove 246 first to preserve §6.3 ordering;
    /// leave other types unchanged and repair wire indices. Return the count removed.
    /// In-place reflection does not grow these TLVs, but the reply MTU may differ
    /// from the request's. A zero limit disables trimming.
    pub fn trim_reflected_headers_to_size(
        &mut self,
        base_len: usize,
        max_reply_bytes: usize,
    ) -> usize {
        if max_reply_bytes == 0 {
            return 0;
        }
        let is_header = |t: &RawTlv| {
            matches!(
                t.tlv_type,
                TlvType::ReflectedFixedHdr | TlvType::ReflectedIpv6ExtHdr
            )
        };
        let mut removed = 0usize;
        while base_len + self.wire_size() > max_reply_bytes {
            let Some(idx) = self.non_hmac_tlvs().iter().rposition(is_header) else {
                break; // No header TLV left to drop; remaining oversize is out of scope.
            };
            self.remove_non_hmac(idx);

            removed += 1;
        }
        removed
    }

    fn apply_reflected_headers(
        tlvs: &mut [RawTlv],
        captured_fixed: Option<&[Vec<u8>]>,
        captured_ext_headers: Option<&[u8]>,
    ) {
        let is_header_tlv = |tlv: &RawTlv| {
            matches!(
                tlv.tlv_type,
                TlvType::ReflectedFixedHdr | TlvType::ReflectedIpv6ExtHdr
            )
        };
        // Most packets carry neither type; skip the record bookkeeping below.
        if !tlvs.iter().any(is_header_tlv) {
            return;
        }
        // ext-hdr-15 §6.3 requires Type 247 before Type 246.
        // If any 247 follows a 246, set C on all header TLVs and copy no data.
        let mut seen_ext = false;
        let mut out_of_order = false;
        for tlv in tlvs.iter().filter(|tlv| tlv.is_processable()) {
            match tlv.tlv_type {
                TlvType::ReflectedIpv6ExtHdr => seen_ext = true,
                TlvType::ReflectedFixedHdr if seen_ext => {
                    out_of_order = true;
                    break;
                }
                _ => {}
            }
        }
        if out_of_order {
            for tlv in tlvs.iter_mut().filter(|tlv| tlv.is_processable()) {
                if matches!(
                    tlv.tlv_type,
                    TlvType::ReflectedFixedHdr | TlvType::ReflectedIpv6ExtHdr
                ) {
                    tlv.set_conformant_reflected();
                }
            }
            return;
        }

        // Split the captured ext-header blob into individual records (wire
        // order) once. `None` means the backend cannot observe the IP layer.
        let ext_records: Option<Vec<&[u8]>> = captured_ext_headers.map(parse_ext_header_records);
        // Borrow the captured fixed-header list (outer→inner) as slices.
        let fixed_records: Option<Vec<&[u8]>> =
            captured_fixed.map(|list| list.iter().map(Vec::as_slice).collect());

        // Per-packet consumed sets for Type 246 (ext) and Type 247 (fixed)
        // first-fit-with-consumption pairing (§4.2/§6.2 rule 1 first-fit-by-length
        // reconciled with rule 3 outer-to-inner ordering). Each captured header is
        // reflected by at most one TLV. Pair each owner once; wire indices
        // observe the same filled payload.
        let mut consumed_ext: Vec<bool> = Vec::new();
        let mut consumed_fixed: Vec<bool> = Vec::new();
        for tlv in tlvs.iter_mut().filter(|tlv| tlv.is_processable()) {
            match tlv.tlv_type {
                TlvType::ReflectedFixedHdr => {
                    Self::apply_reflected_header::<4>(
                        tlv,
                        fixed_records.as_deref(),
                        &mut consumed_fixed,
                    );
                }
                // An extension header is a whole number of 8-octet units.
                TlvType::ReflectedIpv6ExtHdr if tlv.value.len() < 8 || tlv.value.len() % 8 != 0 => {
                    tlv.set_conformant_reflected();
                }
                TlvType::ReflectedIpv6ExtHdr => {
                    Self::apply_reflected_header::<8>(
                        tlv,
                        ext_records.as_deref(),
                        &mut consumed_ext,
                    );
                }
                _ => {}
            }
        }
    }

    /// Match a Type-247 (N=4) or Type-246 (N=8) request to the first unconsumed
    /// capture of the same length (ext-hdr-15 §§4.2, 6.2). Nonzero Requested
    /// also requires a prefix match. Consume the match so repeated requests
    /// select successive captures. No match sets C.
    fn apply_reflected_header<const N: usize>(
        tlv: &mut RawTlv,
        records: Option<&[&[u8]]>,
        consumed: &mut Vec<bool>,
    ) {
        let Some(records) = records else {
            // The backend cannot observe these headers.
            log_reflected_hdr_unsupported_once();
            tlv.set_conformant_reflected();
            return;
        };
        if consumed.len() < records.len() {
            consumed.resize(records.len(), false);
        }
        let len = tlv.value.len();
        let selector = Self::reflected_hdr_selector::<N>(&tlv.value);
        let found = records.iter().enumerate().position(|(i, header)| {
            !consumed[i]
                && header.len() == len
                && selector.is_none_or(|s| header.get(..N) == Some(&s[..]))
        });
        match found {
            Some(i) => {
                consumed[i] = true;
                Self::copy_reflected::<N>(&mut tlv.value, records[i]);
            }
            None => {
                if selector.is_some() && records.iter().any(|header| header.len() == len) {
                    log_reflected_hdr_selector_no_match_once();
                } else {
                    log_reflected_hdr_length_mismatch_once();
                }
                tlv.set_conformant_reflected();
            }
        }
    }

    /// Copies the whole matched header into the TLV value. A nonzero N-octet
    /// Requested selector already equals the header's first N octets; a zero
    /// one must be filled with them (ext-hdr-15 §4.2 and §6.2 rule 1). N is
    /// eight for Type 246 and four for Type 247.
    fn copy_reflected<const N: usize>(value: &mut [u8], header: &[u8]) {
        debug_assert_eq!(value.len(), header.len());
        debug_assert!(Self::reflected_hdr_selector::<N>(value)
            .is_none_or(|s| header.get(..N) == Some(&s[..])));
        value.copy_from_slice(header);
    }

    /// Return a nonzero N-octet Requested selector. All-zero selectors use
    /// ordered first-fit matching instead.
    fn reflected_hdr_selector<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
        let sel: [u8; N] = value.get(..N)?.try_into().ok()?;
        sel.iter().any(|&b| b != 0).then_some(sel)
    }

    /// Sets C on every IPv6 Extension Header Control sub-TLV in Type 12
    /// (draft-ietf-ippm-stamp-ext-hdr-15 §5.1).
    /// Used for unsupported reply-header attachment and duplicate requests;
    /// the latter require C on every offending copy.
    pub fn set_ipv6_ext_hdr_control_c_flag(&mut self) {
        Self::mark_ipv6_ext_hdr_control_c(self.non_hmac_tlvs_mut());
    }

    fn mark_ipv6_ext_hdr_control_c(tlvs: &mut [RawTlv]) {
        for tlv in tlvs {
            if tlv.tlv_type != TlvType::ReflectedControl || !tlv.is_processable() {
                continue;
            }
            let value = &mut tlv.value;
            if value.len() < REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE {
                continue;
            }
            // Sub-TLVs use the standard 4-byte STAMP header and begin after the
            // 8-octet fixed fields.
            let mut offset = REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE;
            while let Some(sub) = TlvSpan::at(value, offset) {
                if sub.tlv_type.to_byte() == REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL {
                    // Sub-TLV flags follow the STAMP TLV flag layout.
                    value[offset] |= TlvFlags::C;
                }
                offset = sub.end();
            }
        }
    }

    fn mark_ber_tlvs_nonconformant(tlvs: &mut [RawTlv]) {
        for tlv in tlvs.iter_mut().filter(|tlv| tlv.is_processable()) {
            if matches!(
                tlv.tlv_type,
                TlvType::BerPattern | TlvType::BerCount | TlvType::BerBurst
            ) {
                tlv.set_conformant_reflected();
            }
        }
    }

    fn write_ber_count(tlv: &mut RawTlv, count: u32) {
        if tlv.value.len() == BER_COUNT_TLV_VALUE_SIZE {
            tlv.value.copy_from_slice(&count.to_be_bytes());
        }
    }

    fn write_ber_burst(tlv: &mut RawTlv, burst: u32) {
        if tlv.value.len() == BER_BURST_TLV_VALUE_SIZE {
            tlv.value.copy_from_slice(&burst.to_be_bytes());
        }
    }

    /// Validates and updates Micro-session ID TLVs in a single slice.
    ///
    /// Returns `false` if a non-zero reflector ID doesn't match `refl_id`.
    fn apply_micro_session_id(tlvs: &mut [RawTlv], refl_id: u16) -> bool {
        for tlv in tlvs.iter_mut().filter(|tlv| tlv.is_processable()) {
            if tlv.tlv_type == TlvType::MicroSessionId {
                let Ok(msid) = MicroSessionIdTlv::from_raw(tlv) else {
                    continue;
                };

                if msid.reflector_micro_session_id != 0
                    && msid.reflector_micro_session_id != refl_id
                {
                    return false;
                }

                let updated = MicroSessionIdTlv::new(msid.sender_micro_session_id, refl_id);
                tlv.value = updated.to_raw().value;
            }
        }
        true
    }
}

/// Outcome of answering a single Location sub-TLV, used by the reflector to
/// decide whether to keep processing sub-TLVs (RFC 8972 §4: a malformed TLV
/// stops all further extension-TLV processing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocationSubOutcome {
    /// A generic request was answered with its specific sub-TLV.
    Answered,
    /// The type is not a generic request the reflector can act on; echoed
    /// with the U flag set.
    Unrecognized,
    /// The Length is invalid for the type, or the sub-TLV runs past the end
    /// of the value; marked with the M flag.
    Malformed,
}

/// Which RFC 8972 §4 flag disposition to stamp on a Location sub-TLV's Flags
/// octet. The reflector re-derives U/M/I from scratch (clearing the sender's
/// U=1), mirroring the outer-TLV `clear_reflector_flags` discipline.
#[derive(Debug, Clone, Copy)]
enum LocationSubFlag {
    /// Understood and answered: U=0, M=0, I=0.
    Answered,
    /// Not understood: U=1 (RFC 8972 §4 unrecognized-TLV rule).
    Unrecognized,
    /// Malformed: M=1 (RFC 8972 §4 malformed-TLV rule).
    Malformed,
}

/// Stamps the RFC 8972 §4 flag disposition onto a Location sub-TLV's Flags
/// octet (index 0 of `sub`). No-op on an empty slice.
fn set_sub_tlv_flag(sub: &mut [u8], flag: LocationSubFlag) {
    if let Some(flags) = sub.first_mut() {
        *flags = match flag {
            LocationSubFlag::Answered => 0x00,
            LocationSubFlag::Unrecognized => TlvFlags::U,
            LocationSubFlag::Malformed => TlvFlags::M,
        };
    }
}

/// Splits a captured IPv6 extension-header blob into individual records in
/// wire order. Each record begins at its own on-wire Next Header octet; the
/// record length is `(HdrExtLen + 1) * 8` octets (RFC 8200). Defensive: stops
/// on any short or inconsistent trailing bytes rather than panicking.
fn parse_ext_header_records(blob: &[u8]) -> Vec<&[u8]> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset + 2 <= blob.len() {
        let rec_len = (blob[offset + 1] as usize + 1) * 8;
        let Some(end) = offset.checked_add(rec_len) else {
            break;
        };
        if end > blob.len() {
            break;
        }
        records.push(&blob[offset..end]);
        offset = end;
    }
    records
}

/// Emits a one-time warning when the reflector receives an extension-header
/// reflection request (TLV 246/247) but the backend cannot observe raw IP
/// headers. Fired from `apply_reflected_header`.
fn log_reflected_hdr_unsupported_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed/IPv6 Ext Header TLV (Type 247/246) requested, but \
             this backend cannot see those headers; echoing with the C flag \
             (Conformance) per draft-ietf-ippm-stamp-ext-hdr-15 §4.1/§6.1. \
             The pnet backend sees both; the nix backend sees IPv6 extension \
             headers on Linux only."
        );
    }
}

/// Emits a one-time warning when a Reflected Fixed or IPv6 Extension Header
/// Data TLV (Type 247/246) has a Length that matches no captured header (e.g.
/// 20 bytes requested for an IPv6 packet). Per draft-ietf-ippm-stamp-ext-hdr-15
/// §4.1/§6.1 the reflector sets the C flag in that case rather than reflecting
/// a mismatched header.
fn log_reflected_hdr_length_mismatch_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed/IPv6 Ext Header TLV (Type 247/246) length matches no \
             received header (for a fixed header, perhaps the wrong address \
             family); echoing with the C flag (Conformance) per \
             draft-ietf-ippm-stamp-ext-hdr-15 §4.1/§6.1."
        );
    }
}

/// Emits a one-time warning when a Reflected Fixed/IPv6 Ext Header Data TLV
/// (Type 246/247) carries a non-zero Requested field that matches none of the
/// captured header(s). Per draft-ietf-ippm-stamp-ext-hdr-15 §4.1/§6.1 the
/// reflector then returns the TLV with the C flag (Conformance) set.
fn log_reflected_hdr_selector_no_match_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed/IPv6 Ext Header TLV (Type 246/247) Requested field matched \
             no captured header; echoing with the C flag (Conformance) per \
             draft-ietf-ippm-stamp-ext-hdr-15 §4.1/§6.1."
        );
    }
}

#[cfg(test)]
mod tests;
