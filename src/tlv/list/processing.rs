//! Reflector-side TLV mutation methods for TlvList.
//!
//! This submodule of `list` provides methods that the Session-Reflector uses
//! to update TLV fields in-place before reflecting a packet. Being a submodule
//! of `list`, it can access `TlvList`'s private fields directly.

use crate::tlv::core::{
    RawTlv, TlvType, ACCESS_REPORT_TLV_VALUE_SIZE, BER_BURST_TLV_VALUE_SIZE,
    BER_COUNT_TLV_VALUE_SIZE, COS_TLV_VALUE_SIZE, DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
    FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE, LOCATION_TLV_MIN_VALUE_SIZE,
    REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL, REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE,
    TIMESTAMP_INFO_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
};
use crate::tlv::{
    ClassOfServiceTlv, DestinationNodeAddressTlv, LocationSubType, MicroSessionIdTlv,
    PacketAddressInfo, ReflectedControlTlv, ReturnPathAction, ReturnPathTlv, SyncSource,
    TimestampMethod, TypedTlv, BER_DEFAULT_PATTERN,
};

use super::TlvList;

impl TlvList {
    /// Calls `f` on every TLV (in both `self.tlvs` and `self.wire_order_tlvs`)
    /// for which `pred` returns true.
    fn for_each_matching_tlv(
        &mut self,
        mut pred: impl FnMut(&RawTlv) -> bool,
        mut f: impl FnMut(&mut RawTlv),
    ) {
        for tlv in &mut self.tlvs {
            if pred(tlv) {
                f(tlv);
            }
        }
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order {
                if pred(tlv) {
                    f(tlv);
                }
            }
        }
    }

    /// Extracts the requested DSCP1/ECN1 from the first CoS TLV if present.
    ///
    /// Returns `Some((dscp1, ecn1))` if a CoS TLV is found and valid.
    #[must_use]
    pub fn get_cos_request(&self) -> Option<(u8, u8)> {
        for tlv in &self.tlvs {
            if tlv.tlv_type == TlvType::ClassOfService {
                if let Ok(cos) = ClassOfServiceTlv::from_raw(tlv) {
                    return Some((cos.dscp1, cos.ecn1));
                }
            }
        }
        None
    }

    /// Updates any Class of Service TLVs with the received DSCP/ECN values.
    ///
    /// Per RFC 8972 §4.4 (with verified erratum 8199) the Session-Reflector
    /// copies the received DSCP and ECN into DSCP2/EC2, and per
    /// draft-ietf-ippm-stamp-cos-ecn-01 §3.2 it reports via RPD whether the
    /// requested DSCP1 was used for the reply and via RPE whether the
    /// reply's ECN was set to EC1. This method only maintains the TLV's own
    /// bits; when `reply_ecn_applied` is false (RPE = 0b10, "unable"), -01
    /// additionally requires the reply's on-wire ECN bits be forced to
    /// 0b00 — that half of the rule is applied by the backends to the
    /// actual IP header, via `ClassOfServiceTlv::reply_wire_tos` /
    /// `crate::receiver::cos_unable_fallback_tos`.
    ///
    /// Updates bytes in-place to avoid allocation overhead. The CoS TLV
    /// layout (`| DSCP1 | DSCP2 |EC2|RPD|EC1|RPE| Reserved |`):
    /// - Byte 0: DSCP1 (6 bits, preserved) | DSCP2 bits 5:4 (updated)
    /// - Byte 1: DSCP2 bits 3:0 | EC2 (2 bits) | RPD (2 bits) - updated
    /// - Byte 2: EC1 (2 bits, preserved) | RPE (2 bits, updated) | Reserved
    /// - Byte 3: Reserved - preserved
    ///
    /// # Arguments
    /// * `received_dscp` - DSCP value received at reflector's ingress (6 bits, 0-63)
    /// * `received_ecn` - ECN value received at reflector's ingress (2 bits, 0-3)
    /// * `policy_rejected` - True if local policy rejected the requested DSCP1
    /// * `reply_ecn_applied` - True if the reply packet's ECN field is set to
    ///   EC1 (RPE = 0b11); false sets RPE = 0b10 ("unable")
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

        // Byte 2: keep EC1 (bits 7:6) and reserved bits 3:0, write RPE.
        let rpe = if reply_ecn_applied { 0b11 } else { 0b10 };
        value[2] = (value[2] & 0xCF) | (rpe << 4);
    }

    /// Updates Timestamp Information TLVs with the reflector's sync source and method.
    ///
    /// Per RFC 8972 §4.3, the Session-Reflector fills `sync_src_out` and `timestamp_out`
    /// (bytes 2-3 of the value) with its own clock information.
    pub fn update_timestamp_info_tlvs(&mut self, sync_src: SyncSource, ts_method: TimestampMethod) {
        let src_byte = sync_src.to_byte();
        let method_byte = ts_method.to_byte();
        self.for_each_matching_tlv(
            |tlv| {
                tlv.tlv_type == TlvType::TimestampInfo
                    && tlv.value.len() == TIMESTAMP_INFO_TLV_VALUE_SIZE
            },
            |tlv| {
                tlv.value[2] = src_byte;
                tlv.value[3] = method_byte;
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
    /// sub-TLVs for the source and destination IP addresses it observed.
    pub fn update_location_tlvs(&mut self, info: &PacketAddressInfo) {
        self.for_each_matching_tlv(
            |tlv| {
                tlv.tlv_type == TlvType::Location && tlv.value.len() >= LOCATION_TLV_MIN_VALUE_SIZE
            },
            |tlv| Self::update_location_value_in_place(&mut tlv.value, info),
        );
    }

    /// Updates a Location TLV value with the observed address information, in
    /// place, per RFC 8972 §4.2 / §4.2.2.
    ///
    /// The reflector fills the two-octet Destination Port and Source Port at
    /// the front of the value (§4.2), then walks the sender's request
    /// sub-TLVs and answers each *generic* request with its *specific*
    /// counterpart (§4.2.2): Source IP (7) → Source IPv4 (8)/IPv6 (9),
    /// Destination IP (4) → Destination IPv4 (5)/IPv6 (6), Source MAC (1) →
    /// Source EUI-48 (2)/EUI-64 (3).
    ///
    /// Because every generic→specific answer has the same size as the request
    /// (12 octets for the MAC family, 20 for the address family) and the
    /// transform is done in place, the Location TLV's Length is never changed —
    /// satisfying "the Session-Reflector ... MUST include in the reflected
    /// packet the Location TLV with a length equal to the Location TLV length
    /// in the received packet." Sub-TLVs the reflector does not recognize are
    /// left byte-for-byte as received with the U flag set (RFC 8972 §4); a
    /// sub-TLV whose Length is wrong for its type, or that runs past the end of
    /// the value, is marked with the M flag and stops further sub-TLV
    /// processing (§4). Any trailing octets that do not form a complete
    /// sub-TLV are left in place (they remain within the preserved Length),
    /// honouring "the Session-Reflector MAY leave some fields unreported by
    /// filling them with zeroes."
    fn update_location_value_in_place(value: &mut [u8], info: &PacketAddressInfo) {
        // Ports always fit: callers only invoke this for values that are
        // already >= LOCATION_TLV_MIN_VALUE_SIZE (4 octets).
        value[0..2].copy_from_slice(&info.dst_port.to_be_bytes());
        value[2..4].copy_from_slice(&info.src_port.to_be_bytes());

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
            if Self::answer_location_sub_tlv(&mut value[offset..end], info)
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
    fn answer_location_sub_tlv(sub: &mut [u8], info: &PacketAddressInfo) -> LocationSubOutcome {
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
                // §4.2.2: neither backend observes the received frame's source
                // MAC (nix = UDP socket, no L2; pnet does not thread it), so we
                // take the explicit "does not have the Source MAC Address"
                // branch: answer with Source EUI-64 (3), EUI-64 field zeroed.
                sub[1] = LocationSubType::SourceEui64.to_byte();
                sub[TLV_HEADER_SIZE..].fill(0);
                set_sub_tlv_flag(sub, LocationSubFlag::Answered);
                LocationSubOutcome::Answered
            }
            LocationSubType::DestinationIp => {
                Self::write_ip_sub_tlv_answer(sub, info.dst_addr, true);
                LocationSubOutcome::Answered
            }
            LocationSubType::SourceIp => {
                Self::write_ip_sub_tlv_answer(sub, info.src_addr, false);
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

    /// Updates Follow-Up Telemetry TLVs (RFC 8972 §4.7).
    ///
    /// `reflection` is `Some((seq, ts))` in the **stateful** reflector mode —
    /// the Session-Reflector fills in the Sequence Number and Follow-Up
    /// Timestamp from its previous reflection (§4.7-10) — and `None` in the
    /// **stateless** mode (RFC 8762 §4.2), where §4.7-7 mandates the Sequence
    /// Number and Follow-Up Timestamp fields be **zeroed**.
    ///
    /// Invalid-length FUT TLVs are also handled here per §4.7-6 (erratum 8339
    /// scope): a value whose length is not the mandated 16 octets has its
    /// present Sequence Number / Follow-Up Timestamp octets zeroed rather than
    /// left as received (the M flag is set separately by the length validator).
    pub fn update_follow_up_telemetry_tlvs(
        &mut self,
        reflection: Option<(u32, u64)>,
        mode: TimestampMethod,
    ) {
        let mode_byte = mode.to_byte();
        self.for_each_matching_tlv(
            |tlv| tlv.tlv_type == TlvType::FollowUpTelemetry,
            |tlv| {
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
                    // Stateless mode (§4.7-7) OR invalid length (§4.7-6): zero
                    // the Sequence Number and Follow-Up Timestamp fields (the
                    // first 12 octets), clamped to whatever the value holds.
                    _ => {
                        let end = tlv.value.len().min(12);
                        tlv.value[..end].fill(0);
                    }
                }
            },
        );
    }

    /// Discards Access Report TLVs (Type 6) whose Access ID is invalid, per
    /// RFC 8972 §4.6: "The value is one of the following: 1: 3GPP Network, 2:
    /// Non-3GPP Network. ... a TLV that contains values other than '1' or '2'
    /// MUST be discarded."
    ///
    /// The object of "discarded" is the *TLV*, not the whole packet. The
    /// reflector discards it by marking it unrecognized (U flag) — a
    /// Session-Sender then "MUST skip the processing of the TLV" (§4-17) — so
    /// the invalid report is never treated as valid, while the packet stays
    /// symmetric in size (RFC 8762 §4.3/§4.6) and the Access ID / Return Code
    /// bytes are still echoed unchanged (§4.6-8). This mirrors the U-flag
    /// treatment already used for a recognized TLV carrying an inapplicable
    /// value (see `process_destination_node_address`).
    ///
    /// Only well-formed (4-octet) Access Report TLVs are considered here; an
    /// invalid *length* is handled separately by the M-flag length validator.
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

    /// Processes Destination Node Address TLVs per RFC 9503 §4.
    ///
    /// Finds the first Destination Node Address TLV and checks if the address
    /// matches one of the reflector's local addresses. If not, sets the U-flag.
    ///
    /// Returns `true` if the address matched (or no such TLV was present).
    pub fn process_destination_node_address(&mut self, local_addrs: &[std::net::IpAddr]) -> bool {
        let mut matched = true;

        // Check in separated tlvs
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::DestinationNodeAddress {
                if let Ok(dna) = DestinationNodeAddressTlv::from_raw(tlv) {
                    if !local_addrs.contains(&dna.address) {
                        tlv.set_unrecognized();
                        matched = false;
                    }
                }
                break;
            }
        }

        // Also update wire-order TLVs if present
        if !matched {
            if let Some(ref mut wire_order) = self.wire_order_tlvs {
                for tlv in wire_order {
                    if tlv.tlv_type == TlvType::DestinationNodeAddress {
                        tlv.set_unrecognized();
                        break;
                    }
                }
            }
        }

        matched
    }

    /// Processes Return Path TLVs per RFC 9503 §5.
    ///
    /// Finds the first Return Path TLV, parses its sub-TLVs, and determines
    /// the appropriate action for the reflector.
    ///
    /// # Arguments
    /// * `sender_port` - The sender's UDP port (used for alternate address replies)
    /// * `allow_alternate` - Whether honouring a Return Address sub-TLV (replying
    ///   to a peer-chosen address) is permitted. When `false` (the default), a
    ///   Return Address sub-TLV is treated as unsupported: the U-flag is set and
    ///   the reply goes to the packet source. This prevents an open reflector
    ///   from being used as a traffic-redirection / reflection gadget aimed at
    ///   third parties (RFC 9503 Return Address is meant for controlled domains).
    pub fn process_return_path(
        &mut self,
        sender_port: u16,
        allow_alternate: bool,
    ) -> ReturnPathAction {
        // Find the first Return Path TLV
        let rp_idx = self
            .tlvs
            .iter()
            .position(|tlv| tlv.tlv_type == TlvType::ReturnPath);

        let Some(idx) = rp_idx else {
            return ReturnPathAction::Normal;
        };

        let Ok(rp) = ReturnPathTlv::from_raw(&self.tlvs[idx]) else {
            // Parse failed — set U-flag and return Normal
            self.tlvs[idx].set_unrecognized();
            if let Some(ref mut wire_order) = self.wire_order_tlvs {
                for tlv in wire_order.iter_mut() {
                    if tlv.tlv_type == TlvType::ReturnPath {
                        tlv.set_unrecognized();
                        break;
                    }
                }
            }
            return ReturnPathAction::Normal;
        };

        // Check for Control Code sub-TLV
        // RFC 9503: only bit 0 (reply-request) is meaningful; remaining bits are reserved and ignored.
        if let Some(cc) = rp.get_control_code() {
            return if cc & 1 == 0 {
                ReturnPathAction::SuppressReply
            } else {
                // Bit 0 = 1 requests a reply on the same incoming link.
                // On single-homed or directly-connected setups, a normal
                // sendto(src_addr) already egresses over the incoming link
                // and therefore satisfies the request. We cannot tell from
                // TLV-processing time whether that will be the case, so we
                // do not pre-emptively set the U-flag here — doing so would
                // falsely advertise "unsupported" for the common path. Per
                // RFC 9503 §4.1.1 the U-flag should be raised only when the
                // backend actually determines the request was not honoured;
                // that decision belongs in the send path, not the parser.
                ReturnPathAction::Normal
            };
        }

        // Check for Return Address sub-TLV
        if let Some(addr) = rp.get_return_address() {
            if allow_alternate {
                return ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(
                    addr,
                    sender_port,
                ));
            }
            // Redirection not permitted (default): signal "unsupported" via the
            // U-flag and reply normally to the packet source. Without this gate
            // an unauthenticated peer could direct the reply (and any Type-12
            // padding amplification) at an arbitrary victim.
            self.set_return_path_u_flag();
            return ReturnPathAction::Normal;
        }

        // SRv6 return path (RFC 9503 §5): hand the segment list to the send
        // path, which attempts best-effort SRH forwarding (RFC 8754) when
        // enabled and kernel-supported, or sets the U-flag on fallback. We do
        // NOT set the U-flag here — whether the request is honoured is decided
        // at send time, mirroring the Control Code reply-request handling above.
        if let Some(sids) = rp.get_srv6_sids() {
            return ReturnPathAction::Srv6Forward(sids);
        }

        // SR-MPLS cannot be forwarded from a userspace UDP socket: echo with
        // the U-flag set and reply normally.
        if rp.has_sr_mpls() {
            self.set_return_path_u_flag();
            return ReturnPathAction::UnsupportedSr;
        }

        // Empty or unrecognized sub-TLVs — set U-flag, return Normal
        self.set_return_path_u_flag();
        ReturnPathAction::Normal
    }

    /// Sets the U-flag on the Return Path TLV in both separated and wire-order lists.
    ///
    /// Public so the receiver can flag the Return Path TLV in the
    /// draft-ietf-ippm-asymmetrical-pkts-14 §4.3 conflict case (no-reply
    /// control code combined with a non-zero Reflected Test Packet Control
    /// TLV).
    pub fn set_return_path_u_flag(&mut self) {
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::ReturnPath {
                tlv.set_unrecognized();
                break;
            }
        }
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order.iter_mut() {
                if tlv.tlv_type == TlvType::ReturnPath {
                    tlv.set_unrecognized();
                    break;
                }
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
    /// Updates both `self.tlvs` and `self.wire_order_tlvs`.
    ///
    /// Returns `true` if all validations pass, `false` if a mismatch was found.
    pub fn update_micro_session_id_tlvs(&mut self, reflector_member_link_id: u16) -> bool {
        if !Self::apply_micro_session_id(&mut self.tlvs, reflector_member_link_id) {
            return false;
        }

        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            if !Self::apply_micro_session_id(wire_order, reflector_member_link_id) {
                return false;
            }
        }

        true
    }

    /// Returns the first Reflected Test Packet Control TLV request, if present.
    ///
    /// Per draft-ietf-ippm-asymmetrical-pkts §3, only the first occurrence is
    /// honoured; duplicates are ignored.
    #[must_use]
    pub fn get_reflected_control_request(&self) -> Option<ReflectedControlTlv> {
        for tlv in &self.tlvs {
            if tlv.tlv_type == TlvType::ReflectedControl {
                if let Ok(parsed) = ReflectedControlTlv::from_raw(tlv) {
                    return Some(parsed);
                }
            }
        }
        None
    }

    /// Marks the first Reflected Test Packet Control TLV with the U flag.
    /// Called when the reflector cannot honour some aspect of the request
    /// but still reflects the packet (e.g. the draft-ietf-ippm-
    /// asymmetrical-pkts-14 §4.3 conflict between a Return Path "no reply
    /// requested" control code and a non-zero Reflected Test Packet Control
    /// TLV); the U flag signals "this request was not honoured" without
    /// claiming success. The L2/L3 Address Group sub-TLV filters (§3.1.1/
    /// §3.1.2) do NOT use this path — a mismatch there drops the packet
    /// instead (see `l2_group_matches_any_local` / `l3_group_matches_any_local`
    /// in `receiver::mod`).
    pub fn set_reflected_control_u_flag(&mut self) {
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::ReflectedControl {
                tlv.set_unrecognized();
                break;
            }
        }
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order.iter_mut() {
                if tlv.tlv_type == TlvType::ReflectedControl {
                    tlv.set_unrecognized();
                    break;
                }
            }
        }
    }

    /// Marks the first Reflected Test Packet Control TLV with the C flag
    /// (Conformant Reflected Packet, draft-ietf-ippm-asymmetrical-pkts §3).
    /// Call this when the reflector cannot fully honour the request
    /// (MTU exceeded, rate/volume cap, or local policy).
    ///
    /// Updates both `self.tlvs` and `self.wire_order_tlvs` to keep the
    /// response consistent.
    pub fn set_reflected_control_c_flag(&mut self) {
        for tlv in &mut self.tlvs {
            if tlv.tlv_type == TlvType::ReflectedControl {
                tlv.set_conformant_reflected();
                break;
            }
        }
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order.iter_mut() {
                if tlv.tlv_type == TlvType::ReflectedControl {
                    tlv.set_conformant_reflected();
                    break;
                }
            }
        }
    }

    /// Processes BER TLVs per draft-gandhi-ippm-stamp-ber-05 §3.
    ///
    /// Computes the number of error bits and the longest consecutive error
    /// burst by XORing the received Extra Padding TLV (RFC 8972 Type 1)
    /// against the pattern carried in the Bit Pattern TLV (Type 240), then
    /// writes the results into the Bit Error Count (Type 241) and Max Burst
    /// (Type 242) TLVs.
    ///
    /// Per the draft:
    /// - Each of the three BER TLVs MAY appear at most once per packet.
    /// - The three TLVs MUST be paired with exactly one Extra Padding TLV.
    /// - If duplicates or a missing Extra Padding TLV are detected, the
    ///   offending BER TLVs are marked with the U-flag and no values are
    ///   computed.
    ///
    /// Operates on `self.tlvs`; wire-order mirroring is handled by the
    /// wire-order copy via `for_each_matching_tlv` where appropriate. This
    /// processing is a no-op when no BER TLVs are present.
    pub fn process_ber(&mut self) {
        // Locate indices in self.tlvs
        let mut padding_count = 0usize;
        let mut padding_idx: Option<usize> = None;
        let mut pattern_count = 0usize;
        let mut pattern_idx: Option<usize> = None;
        let mut count_count = 0usize;
        let mut count_idx: Option<usize> = None;
        let mut burst_count = 0usize;
        let mut burst_idx: Option<usize> = None;

        for (i, tlv) in self.tlvs.iter().enumerate() {
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

        // Draft §3: each BER TLV MAY appear only once. Mark duplicates U.
        let has_duplicate = pattern_count > 1 || count_count > 1 || burst_count > 1;

        // Draft §3: BER TLVs MUST be paired with an Extra Padding TLV.
        // Treat missing-or-duplicate Extra Padding as a protocol error too.
        let padding_invalid = padding_count != 1;

        if has_duplicate || padding_invalid {
            Self::mark_ber_tlvs_unrecognized(&mut self.tlvs);
            if let Some(ref mut wire_order) = self.wire_order_tlvs {
                Self::mark_ber_tlvs_unrecognized(wire_order);
            }
            return;
        }

        // Borrow padding/pattern immutably for the scan, then drop the borrows
        // before mutating count/burst TLVs further down.
        let (count, max_burst) = {
            let padding = self.tlvs[padding_idx.unwrap()].value.as_slice();
            let pattern = pattern_idx
                .map(|i| self.tlvs[i].value.as_slice())
                .filter(|v| !v.is_empty())
                .unwrap_or(BER_DEFAULT_PATTERN.as_slice());
            xor_popcount_and_max_burst(padding, pattern)
        };

        if let Some(i) = count_idx {
            Self::write_ber_count(&mut self.tlvs[i], count);
        }
        if let Some(i) = burst_idx {
            Self::write_ber_burst(&mut self.tlvs[i], max_burst);
        }

        // Mirror into wire-order slice if present.
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            for tlv in wire_order.iter_mut() {
                match tlv.tlv_type {
                    TlvType::BerCount if tlv.value.len() == BER_COUNT_TLV_VALUE_SIZE => {
                        Self::write_ber_count(tlv, count);
                    }
                    TlvType::BerBurst if tlv.value.len() == BER_BURST_TLV_VALUE_SIZE => {
                        Self::write_ber_burst(tlv, max_burst);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Processes Reflected IPv6 Extension Header Data (Type 246) and
    /// Reflected Fixed Header Data (Type 247) TLVs per
    /// draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 3.2, 5.1, 5.2.
    ///
    /// Each TLV value is `Requested(4) + Reflected(Length-4)`: the first 4
    /// octets are the Requested field — a disambiguation selector the
    /// reflector MUST leave exactly as received — and the reflected header's
    /// bytes from offset 4 onward go into the Reflected field. `Length` equals
    /// the full header size, so the header's own first 4 octets are never
    /// written into the reply value.
    ///
    /// Matching (§5.1/§5.2): candidate headers are filtered by length
    /// (`Length == header size`). A non-zero Requested field disambiguates
    /// same-length candidates by exact 4-octet match against the header's
    /// on-wire bytes; an all-zeros Requested field takes the first
    /// length-matching header. For multiple Type 246 TLVs, selection is
    /// **first-fit-with-consumption**: each matched captured header is consumed
    /// so no later TLV re-uses it. This reconciles the draft's two rules —
    /// §5.1's first-fit-by-length MUST and §3.1 rule 2's positional pairing —
    /// which the draft leaves in implicit tension; consumption yields §3.1
    /// ordering (successive same-length TLVs pair 1st↔1st, 2nd↔2nd) while still
    /// honouring §5.1 first-fit-by-length for a lone or shorter-than-first TLV.
    ///
    /// On failure — length mismatch, no data-plane access (`captured` is
    /// `None`), or no candidate matching the Requested field — the reflector
    /// sets the **C flag** (Conformance) on that TLV and leaves the value as
    /// received (§5.1/§5.2, per I-D.ietf-ippm-asymmetrical-pkts). The pre-11
    /// U-flag failure signalling is gone.
    ///
    /// `captured_fixed` supplies the IP fixed header (IPv4 20 bytes, IPv6
    /// 40 bytes). `captured_ext_headers` supplies IPv6 Hop-by-Hop/Destination
    /// Options headers concatenated verbatim as on the wire: each starts with
    /// its own Next Header octet (naming what follows), then HdrExtLen, then
    /// the option body.
    pub fn process_reflected_headers(
        &mut self,
        captured_fixed: Option<&[u8]>,
        captured_ext_headers: Option<&[u8]>,
    ) {
        Self::apply_reflected_headers(&mut self.tlvs, captured_fixed, captured_ext_headers);
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            Self::apply_reflected_headers(wire_order, captured_fixed, captured_ext_headers);
        }
    }

    fn apply_reflected_headers(
        tlvs: &mut [RawTlv],
        captured_fixed: Option<&[u8]>,
        captured_ext_headers: Option<&[u8]>,
    ) {
        // draft-ietf-ippm-stamp-ext-hdr-11 §3.3: the Reflected Fixed Header
        // Data (247) TLVs MUST precede the Reflected IPv6 Extension Header Data
        // (246) TLVs. "If ... TLVs are not received in this order, the Session-
        // Reflector MUST return these TLVs with the C flag ... set to 1 ...
        // without copying any data." Detect a 247 that appears after any 246
        // and, on violation, C-flag every header TLV and copy nothing.
        let mut seen_ext = false;
        let mut out_of_order = false;
        for tlv in tlvs.iter() {
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
            for tlv in tlvs.iter_mut() {
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

        // Per-packet consumed set for Type 246 first-fit-with-consumption
        // pairing (§5.1 first-fit-by-length reconciled with §3.1 rule 2
        // ordering). Each captured ext header is reflected by at most one TLV.
        // A fresh set per call means the `self.tlvs` and `wire_order_tlvs` views
        // are paired independently, exactly as the old `ext_pos` counter was.
        let mut consumed: Vec<bool> = Vec::new();
        for tlv in tlvs {
            match tlv.tlv_type {
                TlvType::ReflectedFixedHdr => Self::apply_reflected_fixed(tlv, captured_fixed),
                TlvType::ReflectedIpv6ExtHdr => {
                    Self::apply_reflected_ext(tlv, ext_records.as_deref(), &mut consumed);
                }
                _ => {}
            }
        }
    }

    /// Reflects a single Reflected Fixed Header Data TLV (Type 247) per -11
    /// §3.2/§5.2. There is a single captured IP fixed-header candidate.
    fn apply_reflected_fixed(tlv: &mut RawTlv, captured_fixed: Option<&[u8]>) {
        let value_len = tlv.value.len();
        let matched = match captured_fixed {
            Some(bytes) if !bytes.is_empty() => {
                if bytes.len() != value_len {
                    // (a) length mismatch with the captured header.
                    log_reflected_hdr_length_mismatch_once();
                    None
                } else if let Some(requested) = Self::reflected_hdr_selector(&tlv.value) {
                    // (c) a non-zero Requested field must match the header's
                    // first 4 on-wire octets.
                    if bytes.get(..4) == Some(&requested[..]) {
                        Some(bytes)
                    } else {
                        log_reflected_hdr_selector_no_match_once();
                        None
                    }
                } else {
                    // All-zeros Requested: the single fixed header matches.
                    Some(bytes)
                }
            }
            // (b) backend cannot observe the IP layer (nix UDP-socket backend).
            _ => {
                log_reflected_hdr_unsupported_once();
                None
            }
        };
        match matched {
            Some(header) => Self::copy_reflected(&mut tlv.value, header),
            None => tlv.set_conformant_reflected(),
        }
    }

    /// Reflects a single Reflected IPv6 Extension Header Data TLV (Type 246)
    /// per -11 §3.1/§5.1, using **first-fit-with-consumption** to reconcile the
    /// draft's two selection rules: §5.1 mandates ("MUST") matching the *first*
    /// length-matching extension header for an all-zeros Requested field, while
    /// §3.1 rule 2 requires *positional* pairing of successive Type 246 TLVs.
    /// The draft leaves this tension implicit; consuming each header as it is
    /// matched satisfies both — first-fit-by-length honours §5.1, and marking
    /// the header consumed makes a second TLV skip it, giving the §3.1 ordering.
    ///
    /// `consumed` is a shared per-packet set of already-reflected captured-header
    /// indices, threaded across every Type 246 TLV in one view (the caller uses
    /// a fresh set for each of the `tlvs` and `wire_order_tlvs` views, exactly as
    /// the old positional `ext_pos` counter was). A TLV that fails to match
    /// consumes nothing.
    fn apply_reflected_ext(
        tlv: &mut RawTlv,
        ext_records: Option<&[&[u8]]>,
        consumed: &mut Vec<bool>,
    ) {
        let value_len = tlv.value.len();
        let selected: Option<usize> = match ext_records {
            // (b) backend cannot observe the IP layer.
            None => {
                log_reflected_hdr_unsupported_once();
                None
            }
            Some(records) => {
                if consumed.len() < records.len() {
                    consumed.resize(records.len(), false);
                }
                if let Some(requested) = Self::reflected_hdr_selector(&tlv.value) {
                    // Non-zero Requested: first not-yet-consumed length-matching
                    // header whose on-wire first 4 octets equal the selector
                    // (§5.1). Consumption lets duplicate identical selectors pair
                    // with successive duplicate headers instead of both matching
                    // the first.
                    let m = records.iter().enumerate().position(|(i, r)| {
                        !consumed[i] && r.len() == value_len && r.get(..4) == Some(&requested[..])
                    });
                    if m.is_none() {
                        log_reflected_hdr_selector_no_match_once();
                    }
                    m
                } else {
                    // All-zeros Requested: first not-yet-consumed length-matching
                    // header (§5.1 first-fit-by-length; §3.1 rule 2 ordering
                    // falls out of consumption for multiple such TLVs).
                    records
                        .iter()
                        .enumerate()
                        .position(|(i, r)| !consumed[i] && r.len() == value_len)
                }
            }
        };
        match (selected, ext_records) {
            (Some(idx), Some(records)) => {
                consumed[idx] = true;
                Self::copy_reflected(&mut tlv.value, records[idx]);
            }
            _ => tlv.set_conformant_reflected(),
        }
    }

    /// Copies the Reflected portion (`header[4..]`) into `value[4..]`, leaving
    /// the Requested field (`value[..4]`) exactly as received, per
    /// draft-ietf-ippm-stamp-ext-hdr-11 §5.1/§5.2. Caller guarantees
    /// `value.len() == header.len()`.
    fn copy_reflected(value: &mut [u8], header: &[u8]) {
        debug_assert_eq!(value.len(), header.len());
        if value.len() >= 4 {
            value[4..].copy_from_slice(&header[4..]);
        }
    }

    /// Extracts the draft-ietf-ippm-stamp-ext-hdr-11 §5.1/§5.2 Requested
    /// selector from a TLV value: the first 4 bytes, but only when present and
    /// at least one is non-zero. `None` means "all-zeros Requested", i.e. match
    /// the first length-matching / positionally-corresponding header.
    fn reflected_hdr_selector(value: &[u8]) -> Option<[u8; 4]> {
        let sel: [u8; 4] = value.get(..4)?.try_into().ok()?;
        sel.iter().any(|&b| b != 0).then_some(sel)
    }

    /// Sets the C (Conformance) flag in the Sub-TLV Flags byte of every
    /// 'IPv6 Extension Header Control' sub-TLV (Type
    /// [`REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL`]) carried in the
    /// reflected 'Reflected Test Packet Control' TLV (Type 12), per
    /// draft-ietf-ippm-stamp-ext-hdr-11 §5.3.
    ///
    /// The caller uses this both for rule 4 (a single sub-TLV is present but
    /// the reflector cannot add matching IPv6 extension headers to its own
    /// reply — always the case here, since neither backend attaches reply
    /// headers) and for the cardinality rule (more than one such sub-TLV is
    /// present — the C flag is then set on *every* offending copy). Mutates the
    /// raw sub-TLV flag bytes in both `self.tlvs` and `self.wire_order_tlvs`.
    pub fn set_ipv6_ext_hdr_control_c_flag(&mut self) {
        Self::mark_ipv6_ext_hdr_control_c(&mut self.tlvs);
        if let Some(ref mut wire_order) = self.wire_order_tlvs {
            Self::mark_ipv6_ext_hdr_control_c(wire_order);
        }
    }

    fn mark_ipv6_ext_hdr_control_c(tlvs: &mut [RawTlv]) {
        for tlv in tlvs {
            if tlv.tlv_type != TlvType::ReflectedControl {
                continue;
            }
            let value = &mut tlv.value;
            if value.len() < REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE {
                continue;
            }
            // Sub-TLVs use the standard 4-byte STAMP header and begin after the
            // 8-octet fixed fields.
            let mut offset = REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE;
            while offset + TLV_HEADER_SIZE <= value.len() {
                let type_byte = value[offset + 1];
                let sub_len = u16::from_be_bytes([value[offset + 2], value[offset + 3]]) as usize;
                let Some(end) = (offset + TLV_HEADER_SIZE).checked_add(sub_len) else {
                    break;
                };
                if end > value.len() {
                    break;
                }
                if type_byte == REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL {
                    // C flag (bit 3, 0x10) in the Sub-TLV Flags byte, mirroring
                    // the STAMP TLV Flags procedure (RFC 8972).
                    value[offset] |= 0x10;
                }
                offset = end;
            }
        }
    }

    fn mark_ber_tlvs_unrecognized(tlvs: &mut [RawTlv]) {
        for tlv in tlvs {
            if matches!(
                tlv.tlv_type,
                TlvType::BerPattern | TlvType::BerCount | TlvType::BerBurst
            ) {
                tlv.set_unrecognized();
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
        for tlv in tlvs {
            if tlv.tlv_type == TlvType::MicroSessionId {
                let Ok(msid) = MicroSessionIdTlv::from_raw(tlv) else {
                    continue; // Malformed — skip (M-flag already set by parse_lenient)
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
            LocationSubFlag::Unrecognized => 0x80,
            LocationSubFlag::Malformed => 0x40,
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
/// headers. Fired from `apply_reflected_headers`.
fn log_reflected_hdr_unsupported_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed/IPv6 Ext Header TLV (Types 247/246) requested but \
             this backend cannot observe raw IP headers — echoing with the C flag \
             (Conformance) per draft-ietf-ippm-stamp-ext-hdr-11 §5.1/§5.2. \
             Rebuild with --features ttl-pnet to enable header reflection."
        );
    }
}

/// Emits a one-time warning when a Reflected Fixed Header Data TLV (Type 247)
/// arrives with a requested Length that doesn't match the captured IP
/// header size (e.g. 20 bytes requested for an IPv6 packet). Per
/// draft-ietf-ippm-stamp-ext-hdr-11 §5.2 the reflector sets the C flag in that
/// case rather than reflecting a mismatched header.
fn log_reflected_hdr_length_mismatch_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed Header Data TLV (Type 247) length does not match the \
             captured IP header (sender requested wrong address family?); echoing \
             with the C flag (Conformance) per draft-ietf-ippm-stamp-ext-hdr-11 §5.2."
        );
    }
}

/// Emits a one-time warning when a Reflected Fixed/IPv6 Ext Header Data TLV
/// (Type 246/247) carries a non-zero Requested field that matches none of the
/// captured header(s). Per draft-ietf-ippm-stamp-ext-hdr-11 §5.1/§5.2 the
/// reflector then returns the TLV with the C flag (Conformance) set.
fn log_reflected_hdr_selector_no_match_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed/IPv6 Ext Header TLV (Type 246/247) Requested field matched \
             no captured header — echoing with the C flag (Conformance) per \
             draft-ietf-ippm-stamp-ext-hdr-11 §5.1/§5.2."
        );
    }
}

/// XORs `padding` against `pattern` repeated, counts total error bits and the
/// longest consecutive run of `1` bits spanning byte boundaries. Runs are
/// counted across the whole padding buffer as a continuous bit stream.
///
/// Returns `(error_count, max_consecutive_error_bits)`.
fn xor_popcount_and_max_burst(padding: &[u8], pattern: &[u8]) -> (u32, u32) {
    if pattern.is_empty() {
        // Should never happen (caller filters empty pattern to default), but
        // be defensive: without a pattern we cannot compare.
        return (0, 0);
    }

    let mut count: u32 = 0;
    let mut current_burst: u32 = 0;
    let mut max_burst: u32 = 0;

    // Overflow is impossible for any realistic packet: a u32 counts up to 2^32
    // error bits, which would require a ~536 MB padding TLV. Use plain arithmetic.
    for (i, &byte) in padding.iter().enumerate() {
        let expected = pattern[i % pattern.len()];
        let err = byte ^ expected;
        count += err.count_ones();

        for bit in (0..8).rev() {
            if (err >> bit) & 1 == 1 {
                current_burst += 1;
                if current_burst > max_burst {
                    max_burst = current_burst;
                }
            } else {
                current_burst = 0;
            }
        }
    }

    (count, max_burst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;
    use crate::tlv::{
        AccessReportTlv, BerBurstTlv, BerCountTlv, BerPatternTlv, DirectMeasurementTlv,
        ExtraPaddingTlv, FollowUpTelemetryTlv, LocationTlv, ReflectedControlTlv, TimestampInfoTlv,
    };

    /// Builds a single-TLV list and runs the reflector clear pass on it,
    /// mimicking the production pipeline state at the point each
    /// `process_*` function would normally run.
    fn list_with_cleared(tlv: RawTlv) -> TlvList {
        let mut list = TlvList::new();
        list.push(tlv).unwrap();
        list.clear_reflector_flags();
        list
    }

    #[test]
    fn test_update_timestamp_info_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = TimestampInfoTlv::new(SyncSource::Ntp, TimestampMethod::SwLocal);
        list.push(sender_tlv.to_raw()).unwrap();

        list.update_timestamp_info_tlvs(SyncSource::Ptp, TimestampMethod::HwAssist);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = TimestampInfoTlv::from_raw(raw).unwrap();
        // In-fields should be preserved
        assert_eq!(parsed.sync_src_in, SyncSource::Ntp);
        assert_eq!(parsed.timestamp_in, TimestampMethod::SwLocal);
        // Out-fields should be updated
        assert_eq!(parsed.sync_src_out, SyncSource::Ptp);
        assert_eq!(parsed.timestamp_out, TimestampMethod::HwAssist);
    }

    #[test]
    fn test_update_timestamp_info_skips_wrong_size() {
        let mut list = TlvList::new();
        // Push a TimestampInfo with wrong size (3 bytes instead of 4)
        list.push(RawTlv::new(TlvType::TimestampInfo, vec![1, 2, 3]))
            .unwrap();

        list.update_timestamp_info_tlvs(SyncSource::Ptp, TimestampMethod::HwAssist);

        // Value should be unchanged since size didn't match
        assert_eq!(list.non_hmac_tlvs()[0].value, vec![1, 2, 3]);
    }

    #[test]
    fn test_update_direct_measurement_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = DirectMeasurementTlv::new(100);
        list.push(sender_tlv.to_raw()).unwrap();

        list.update_direct_measurement_tlvs(50, 49);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = DirectMeasurementTlv::from_raw(raw).unwrap();
        // Sender tx count preserved
        assert_eq!(parsed.sender_tx_count, 100);
        // Reflector counts filled
        assert_eq!(parsed.reflector_rx_count, 50);
        assert_eq!(parsed.reflector_tx_count, 49);
    }

    #[test]
    fn test_update_direct_measurement_skips_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::DirectMeasurement, vec![0; 8]))
            .unwrap();

        list.update_direct_measurement_tlvs(50, 49);

        // Value should be unchanged
        assert_eq!(list.non_hmac_tlvs()[0].value, vec![0; 8]);
    }

    #[test]
    fn test_reflector_answers_generic_source_ip_request_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};
        // Sender request per RFC 8972 §4.2/§4.2.1: ports(4 zero octets) +
        // one generic Source IP Address sub-TLV (Type 7) with the standard
        // 4-octet STAMP TLV header and a 16-octet zeroed value:
        //   [flags=0x80][type=7][length=0x0010][16 MBZ octets]
        let mut req = vec![0u8; 4];
        req.extend_from_slice(&[0x80, 7, 0x00, 0x10]);
        req.extend_from_slice(&[0u8; 16]);
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, req.clone()))
            .unwrap();
        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);
        let v = &list.non_hmac_tlvs()[0].value;
        assert_eq!(v.len(), req.len(), "Location TLV Length preserved (§4.2.2)");
        assert_eq!(&v[0..2], &862u16.to_be_bytes(), "dest port");
        assert_eq!(&v[2..4], &50000u16.to_be_bytes(), "src port");
        // Generic Source IP (7) answered as Source IPv4 (8) in place, U=0.
        assert_eq!(v[4], 0x00, "answered sub-TLV flags cleared (U=0)");
        assert_eq!(v[5], 8, "Source IP (7) answered as Source IPv4 (8)");
        assert_eq!(&v[6..8], &16u16.to_be_bytes(), "sub-TLV Length 16");
        assert_eq!(&v[8..12], &[10, 0, 0, 1], "source IPv4 copied");
        assert_eq!(&v[12..24], &[0u8; 12], "MBZ tail");
    }

    #[test]
    fn test_update_location_tlvs_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut list = TlvList::new();
        // RFC 8972 §4.2 request: ports + generic Source IP (7) and
        // Destination IP (4) sub-TLVs, each a 4-octet header + 16-octet MBZ
        // value.
        list.push(LocationTlv::request().to_raw()).unwrap();
        let original_len = list.non_hmac_tlvs()[0].value.len();

        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        assert_eq!(
            raw.value.len(),
            original_len,
            "Location TLV Length must be preserved (§4.2.2)"
        );
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.sub_tlvs.len(), 2);
        // Source IP (7) → Source IPv4 (8): 4-octet address + 12-octet MBZ.
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::SourceIpv4);
        assert!(
            !parsed.sub_tlvs[0].flags.unrecognized,
            "answered sub-TLV must clear U"
        );
        assert_eq!(&parsed.sub_tlvs[0].value[..4], &[10, 0, 0, 1]);
        assert_eq!(&parsed.sub_tlvs[0].value[4..], &[0u8; 12]);
        // Destination IP (4) → Destination IPv4 (5).
        assert_eq!(
            parsed.sub_tlvs[1].sub_type,
            LocationSubType::DestinationIpv4
        );
        assert_eq!(&parsed.sub_tlvs[1].value[..4], &[10, 0, 0, 2]);
        assert_eq!(&parsed.sub_tlvs[1].value[4..], &[0u8; 12]);
    }

    #[test]
    fn test_update_location_tlvs_ipv6() {
        use std::net::{IpAddr, Ipv6Addr};

        let mut list = TlvList::new();
        list.push(LocationTlv::request().to_raw()).unwrap();
        let original_len = list.non_hmac_tlvs()[0].value.len();

        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let info = PacketAddressInfo {
            src_addr: IpAddr::V6(src),
            src_port: 50000,
            dst_addr: IpAddr::V6(dst),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        assert_eq!(
            raw.value.len(),
            original_len,
            "Location TLV Length must be preserved (§4.2.2)"
        );
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.sub_tlvs.len(), 2);
        // Source IP (7) → Source IPv6 (9): full 16-octet address.
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::SourceIpv6);
        assert_eq!(parsed.sub_tlvs[0].value, src.octets().to_vec());
        // Destination IP (4) → Destination IPv6 (6).
        assert_eq!(
            parsed.sub_tlvs[1].sub_type,
            LocationSubType::DestinationIpv6
        );
        assert_eq!(parsed.sub_tlvs[1].value, dst.octets().to_vec());
    }

    #[test]
    fn test_update_location_source_mac_answered_as_eui64_zeroed() {
        // RFC 8972 §4.2.2: with no observed source MAC (UDP-socket
        // reflectors), a generic Source MAC (1) request MUST be answered with
        // Source EUI-64 (3) and the EUI-64 field zeroed.
        use std::net::{IpAddr, Ipv4Addr};
        let mut req = vec![0u8; 4];
        // Generic Source MAC: flags U=1, type 1, length 8, 8 MBZ octets.
        req.extend_from_slice(&[0x80, 1, 0x00, 0x08]);
        req.extend_from_slice(&[0u8; 8]);
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, req.clone()))
            .unwrap();
        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);
        let parsed = LocationTlv::from_raw(&list.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(parsed.sub_tlvs.len(), 1);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::SourceEui64);
        assert_eq!(parsed.sub_tlvs[0].value, vec![0u8; 8]);
        assert!(!parsed.sub_tlvs[0].flags.unrecognized);
    }

    #[test]
    fn test_update_location_unrecognized_sub_tlv_gets_u_flag() {
        // RFC 8972 §4: a sub-TLV whose type the reflector cannot act on is
        // copied verbatim with the U flag set.
        use std::net::{IpAddr, Ipv4Addr};
        let mut req = vec![0u8; 4];
        // Unknown sub-type 200 with a 4-octet value the reflector must not
        // touch.
        req.extend_from_slice(&[0x80, 200, 0x00, 0x04]);
        req.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, req.clone()))
            .unwrap();
        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);
        let raw = &list.non_hmac_tlvs()[0];
        assert_eq!(raw.value.len(), req.len(), "Length preserved");
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.sub_tlvs.len(), 1);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::Unknown(200));
        assert!(
            parsed.sub_tlvs[0].flags.unrecognized,
            "unrecognized sub-TLV must set U"
        );
        // Value copied verbatim.
        assert_eq!(parsed.sub_tlvs[0].value, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_update_location_malformed_sub_tlv_sets_m_and_stops() {
        // RFC 8972 §4: a recognized type carrying an invalid Length is
        // malformed — set M and stop processing further sub-TLVs.
        use std::net::{IpAddr, Ipv4Addr};
        let mut req = vec![0u8; 4];
        // Source IP (7) with a wrong Length of 4 (must be 16) → malformed.
        req.extend_from_slice(&[0x80, 7, 0x00, 0x04]);
        req.extend_from_slice(&[0u8; 4]);
        // A second, well-formed generic Source IP request that MUST NOT be
        // processed because processing stops at the malformed one.
        req.extend_from_slice(&[0x80, 7, 0x00, 0x10]);
        req.extend_from_slice(&[0u8; 16]);
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, req.clone()))
            .unwrap();
        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);
        let raw = &list.non_hmac_tlvs()[0];
        assert_eq!(raw.value.len(), req.len(), "Length preserved");
        // First sub-TLV (offset 4): M flag set.
        assert_eq!(raw.value[4], 0x40, "malformed sub-TLV → M flag");
        // Second sub-TLV (offset 12) left untouched (still the sender's U=1,
        // type 7 request — not answered).
        assert_eq!(
            raw.value[12], 0x80,
            "processing stopped: second sub-TLV untouched"
        );
        assert_eq!(raw.value[13], 7);
    }

    #[test]
    fn test_update_location_tlvs_ports_only_no_sub_tlvs() {
        // A sender that allocates only the ports (the minimum valid Location
        // TLV value, per LOCATION_TLV_MIN_VALUE_SIZE) makes no sub-TLV
        // request; the reflector fills the ports and answers nothing, without
        // growing the TLV (RFC 8972 §4.2.2).
        use std::net::{IpAddr, Ipv4Addr};

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, vec![0u8; 4]))
            .unwrap();

        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        assert_eq!(raw.value.len(), 4, "Location TLV Length must be preserved");
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert!(parsed.sub_tlvs.is_empty());
    }

    #[test]
    fn test_update_location_tlvs_preserves_sender_length_no_shrink() {
        // Cross-implementation testing observed a reflector answering a
        // 36-octet Location TLV request with a 16-octet Location TLV
        // reply. RFC 8972 §4.2.2: "The Session-Reflector that received an
        // extended STAMP packet with the Location TLV MUST include in the
        // reflected packet the Location TLV with a length equal to the
        // Location TLV length in the received packet." A request carrying a
        // generic Source IP (7, 20 octets) and Source MAC (1, 12 octets)
        // sub-TLV is 4 + 20 + 12 = 36 octets; answering both in place must
        // keep the Length at 36.
        use std::net::{IpAddr, Ipv4Addr};

        let mut req = vec![0u8; 4];
        req.extend_from_slice(&[0x80, 7, 0x00, 0x10]);
        req.extend_from_slice(&[0u8; 16]);
        req.extend_from_slice(&[0x80, 1, 0x00, 0x08]);
        req.extend_from_slice(&[0u8; 8]);
        assert_eq!(req.len(), 36);

        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::Location, req)).unwrap();

        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        assert_eq!(
            raw.value.len(),
            36,
            "reflector must not change the Location TLV Length (RFC 8972 §4.2.2)"
        );
        assert_eq!(&raw.value[0..2], &862u16.to_be_bytes());
        assert_eq!(&raw.value[2..4], &50000u16.to_be_bytes());
        // Both requests answered: Source IPv4 (8) then Source EUI-64 (3).
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.sub_tlvs.len(), 2);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::SourceIpv4);
        assert_eq!(parsed.sub_tlvs[1].sub_type, LocationSubType::SourceEui64);
    }

    #[test]
    fn test_update_follow_up_telemetry_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = FollowUpTelemetryTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

        // Stateful mode: report the previous reflection's seq/timestamp.
        list.update_follow_up_telemetry_tlvs(
            Some((42, 0xDEADBEEFCAFEBABE)),
            TimestampMethod::SwLocal,
        );

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = FollowUpTelemetryTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.follow_up_timestamp, 0xDEADBEEFCAFEBABE);
        assert_eq!(parsed.timestamp_mode, TimestampMethod::SwLocal);
    }

    #[test]
    fn test_update_follow_up_telemetry_stateless_zeroes_seq_and_timestamp() {
        // RFC 8972 §4.7-7: "If the Session-Reflector is in the stateless mode
        // ..., it MUST zero the Sequence Number and Follow-Up Timestamp
        // fields." A `None` reflection argument represents stateless mode.
        let mut list = TlvList::new();
        list.push(FollowUpTelemetryTlv::new().to_raw()).unwrap();

        // First populate as if stateful, then apply the stateless path.
        list.update_follow_up_telemetry_tlvs(Some((42, 0xDEADBEEF)), TimestampMethod::SwLocal);
        list.update_follow_up_telemetry_tlvs(None, TimestampMethod::SwLocal);

        let parsed = FollowUpTelemetryTlv::from_raw(&list.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(
            parsed.sequence_number, 0,
            "seq must be zeroed in stateless mode"
        );
        assert_eq!(
            parsed.follow_up_timestamp, 0,
            "timestamp must be zeroed in stateless mode"
        );
    }

    #[test]
    fn test_update_follow_up_telemetry_invalid_length_zeroed() {
        // RFC 8972 §4.7-6 (with erratum 8339 scope): "If the value of the
        // Length field is invalid, the Session-Reflector MUST zero the Sequence
        // Number and Follow-Up Timestamp fields ...". An 8-octet value is an
        // invalid length (must be 16); the present seq/timestamp octets MUST be
        // zeroed rather than left as received.
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::FollowUpTelemetry, vec![0xFF; 8]))
            .unwrap();

        list.update_follow_up_telemetry_tlvs(Some((42, 100)), TimestampMethod::SwLocal);

        assert_eq!(
            list.non_hmac_tlvs()[0].value,
            vec![0u8; 8],
            "invalid-length FUT value must be zeroed"
        );
    }

    #[test]
    fn test_access_report_valid_ids_not_flagged() {
        // RFC 8972 §4.6: Access ID values 1 (3GPP) and 2 (Non-3GPP) are valid.
        for id in [1u8, 2u8] {
            let mut list = list_with_cleared(AccessReportTlv::new(id, 1).to_raw());
            list.discard_invalid_access_report_tlvs();
            assert!(
                !list.non_hmac_tlvs()[0].is_unrecognized(),
                "Access ID {} is valid and must not be flagged",
                id
            );
        }
    }

    #[test]
    fn test_access_report_invalid_ids_discarded_with_u_flag() {
        // RFC 8972 §4.6: "a TLV that contains values other than '1' or '2' MUST
        // be discarded." The reflector discards the invalid Access Report TLV
        // by marking it unrecognized (U flag) — the sender then skips
        // processing it (§4-17) — while preserving symmetric packet size.
        for id in [0u8, 3u8, 15u8] {
            let mut list = list_with_cleared(AccessReportTlv::new(id, 1).to_raw());
            list.discard_invalid_access_report_tlvs();
            assert!(
                list.non_hmac_tlvs()[0].is_unrecognized(),
                "Access ID {} is invalid and must be discarded (U flag)",
                id
            );
        }
    }

    #[test]
    fn test_process_destination_node_address_match() {
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let mut list = list_with_cleared(DestinationNodeAddressTlv::new(addr).to_raw());

        let local_addrs = vec![addr];
        let matched = list.process_destination_node_address(&local_addrs);
        assert!(matched);
        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
    }

    #[test]
    fn test_process_destination_node_address_mismatch() {
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let tlv = DestinationNodeAddressTlv::new(addr);
        let mut list = TlvList::new();
        list.push(tlv.to_raw()).unwrap();

        let local_addrs = vec!["10.0.0.1".parse().unwrap()];
        let matched = list.process_destination_node_address(&local_addrs);
        assert!(!matched);
        assert!(list.non_hmac_tlvs()[0].is_unrecognized());
    }

    #[test]
    fn test_process_return_path_suppress() {
        let rp = ReturnPathTlv::with_control_code(0x0);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234, false);
        assert_eq!(action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_process_return_path_same_link_does_not_preemptively_flag_u() {
        // RFC 9503 §4.1.1: same-link request (bit 0 = 1). We cannot tell at
        // TLV-processing time whether the backend's sendto() will actually
        // egress over the incoming link — on single-homed hosts it trivially
        // does. Pre-emptively setting U-flag here would falsely mark those
        // responses "unsupported". The U-flag decision belongs in the send
        // path once the backend knows what happened.
        let mut list = list_with_cleared(ReturnPathTlv::with_control_code(0x1).to_raw());

        let action = list.process_return_path(1234, false);
        assert_eq!(action, ReturnPathAction::Normal);

        let echoed = list
            .non_hmac_tlvs()
            .iter()
            .find(|t| t.tlv_type == TlvType::ReturnPath)
            .expect("return path TLV kept in response");
        assert!(
            !echoed.is_unrecognized(),
            "same-link request must not pre-emptively set U-flag"
        );
    }

    #[test]
    fn test_process_return_path_cc_reserved_bits_suppress() {
        // RFC 9503: only bit 0 matters; reserved bits are ignored.
        // 0xFE has bit 0 clear → suppress.
        let rp = ReturnPathTlv::with_control_code(0xFE);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234, false);
        assert_eq!(action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_process_return_path_cc_reserved_bits_normal() {
        // RFC 9503: only bit 0 matters; reserved bits are ignored.
        // 0xFF has bit 0 set → same-link request; U-flag is not pre-set
        // since on single-homed paths the backend already satisfies it.
        let mut list = list_with_cleared(ReturnPathTlv::with_control_code(0xFF).to_raw());

        let action = list.process_return_path(1234, false);
        assert_eq!(action, ReturnPathAction::Normal);

        let echoed = list
            .non_hmac_tlvs()
            .iter()
            .find(|t| t.tlv_type == TlvType::ReturnPath)
            .expect("return path TLV kept in response");
        assert!(!echoed.is_unrecognized());
    }

    #[test]
    fn test_process_return_path_alternate_addr() {
        let addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let rp = ReturnPathTlv::with_return_address(addr);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        // allow_alternate = true: the operator opted in, so the reply is
        // directed to the requested address.
        let action = list.process_return_path(862, true);
        assert_eq!(
            action,
            ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(addr, 862))
        );
    }

    #[test]
    fn test_process_return_path_alternate_addr_denied_by_default() {
        // allow_alternate = false (the default): a Return Address sub-TLV must
        // NOT redirect the reply. The reflector echoes the TLV with the U-flag
        // and replies normally to the packet source. This blocks open-reflector
        // traffic-redirection / reflection aimed at arbitrary third parties.
        let addr: std::net::IpAddr = "10.0.0.5".parse().unwrap();
        let mut list = list_with_cleared(ReturnPathTlv::with_return_address(addr).to_raw());

        let action = list.process_return_path(862, false);
        assert_eq!(action, ReturnPathAction::Normal);

        let echoed = list
            .non_hmac_tlvs()
            .iter()
            .find(|t| t.tlv_type == TlvType::ReturnPath)
            .expect("return path TLV kept in response");
        assert!(
            echoed.is_unrecognized(),
            "denied alternate address must set the U-flag on the echoed TLV"
        );
    }

    #[test]
    fn test_process_return_path_sr_unsupported() {
        let rp = ReturnPathTlv::with_sr_mpls_labels(&[100, 200]);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(862, false);
        assert_eq!(action, ReturnPathAction::UnsupportedSr);
        assert!(list.non_hmac_tlvs()[0].is_unrecognized());
    }

    #[test]
    fn test_process_return_path_srv6_returns_segment_list_without_premature_u_flag() {
        let sids = [
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        ];
        let rp = ReturnPathTlv::with_srv6_sids(&sids);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();
        // Simulate the reflector pipeline, which clears the sender's U-flag
        // before semantic TLV processing runs.
        list.clear_reflector_flags();

        let action = list.process_return_path(862, false);
        assert_eq!(
            action,
            ReturnPathAction::Srv6Forward(vec![sids[0], sids[1]]),
            "SRv6 return path must surface the segment list for the send path"
        );
        // The U-flag decision is deferred to the send path (it depends on
        // kernel capability + the opt-in), so it must NOT be set here.
        assert!(
            !list.non_hmac_tlvs()[0].is_unrecognized(),
            "SRv6 must not be pre-flagged unrecognized during TLV processing"
        );
    }

    #[test]
    fn test_update_micro_session_id_tlvs_sets_reflector_id() {
        let msid = MicroSessionIdTlv::new(42, 0);
        let mut list = TlvList::new();
        list.push(msid.to_raw()).unwrap();

        let ok = list.update_micro_session_id_tlvs(99);
        assert!(ok);

        let parsed = MicroSessionIdTlv::from_raw(&list.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(parsed.sender_micro_session_id, 42);
        assert_eq!(parsed.reflector_micro_session_id, 99);
    }

    #[test]
    fn test_update_micro_session_id_tlvs_echoes_sender_id() {
        let msid = MicroSessionIdTlv::new(1234, 0);
        let mut list = TlvList::new();
        list.push(msid.to_raw()).unwrap();

        list.update_micro_session_id_tlvs(5678);

        let parsed = MicroSessionIdTlv::from_raw(&list.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(parsed.sender_micro_session_id, 1234);
    }

    #[test]
    fn test_update_micro_session_id_tlvs_validates_reflector_id() {
        // Non-zero reflector ID that does NOT match → should return false
        let msid = MicroSessionIdTlv::new(42, 50);
        let mut list = TlvList::new();
        list.push(msid.to_raw()).unwrap();

        let ok = list.update_micro_session_id_tlvs(99);
        assert!(!ok);
    }

    #[test]
    fn test_update_micro_session_id_tlvs_zero_reflector_id_accepted() {
        // Reflector ID 0 (unknown) should always pass
        let msid = MicroSessionIdTlv::new(42, 0);
        let mut list = TlvList::new();
        list.push(msid.to_raw()).unwrap();

        let ok = list.update_micro_session_id_tlvs(99);
        assert!(ok);
    }

    #[test]
    fn test_update_micro_session_id_tlvs_matching_reflector_id_accepted() {
        // Non-zero reflector ID that matches → should pass
        let msid = MicroSessionIdTlv::new(42, 99);
        let mut list = TlvList::new();
        list.push(msid.to_raw()).unwrap();

        let ok = list.update_micro_session_id_tlvs(99);
        assert!(ok);

        let parsed = MicroSessionIdTlv::from_raw(&list.non_hmac_tlvs()[0]).unwrap();
        assert_eq!(parsed.reflector_micro_session_id, 99);
    }

    // --- BER (draft-gandhi-ippm-stamp-ber) tests ---

    #[test]
    fn test_ber_xor_helper_no_errors() {
        // Padding exactly equals the repeated pattern → 0 errors.
        let padding = vec![0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00];
        let pattern = vec![0xFF, 0x00];
        let (count, burst) = xor_popcount_and_max_burst(&padding, &pattern);
        assert_eq!(count, 0);
        assert_eq!(burst, 0);
    }

    #[test]
    fn test_ber_xor_helper_all_ones_against_zeros() {
        // Padding all 1s, pattern all 0s → every bit an error.
        let padding = vec![0xFF, 0xFF];
        let pattern = vec![0x00];
        let (count, burst) = xor_popcount_and_max_burst(&padding, &pattern);
        assert_eq!(count, 16);
        assert_eq!(burst, 16); // all 16 bits form a single run
    }

    #[test]
    fn test_ber_xor_helper_burst_across_bytes() {
        // Errors spanning the byte boundary: 0x0F ^ 0x00 = 0x0F (4 errors at LSBs),
        // then 0xF0 ^ 0x00 = 0xF0 (4 errors at MSBs). Together they form an 8-bit run.
        let padding = vec![0x0F, 0xF0];
        let pattern = vec![0x00];
        let (count, burst) = xor_popcount_and_max_burst(&padding, &pattern);
        assert_eq!(count, 8);
        assert_eq!(burst, 8);
    }

    #[test]
    fn test_ber_xor_helper_isolated_bits() {
        // Padding: 0x55 (01010101), pattern 0x00 → 4 isolated error bits, max burst = 1.
        let padding = vec![0x55];
        let pattern = vec![0x00];
        let (count, burst) = xor_popcount_and_max_burst(&padding, &pattern);
        assert_eq!(count, 4);
        assert_eq!(burst, 1);
    }

    #[test]
    fn test_process_ber_happy_path() {
        let mut list = TlvList::new();
        // Padding differs from pattern on every bit of first byte.
        list.push(
            ExtraPaddingTlv {
                padding: vec![0xAA, 0x55],
            }
            .to_raw(),
        )
        .unwrap();
        list.push(BerPatternTlv::new(vec![0xAA, 0x55]).to_raw())
            .unwrap();
        list.push(BerCountTlv::default().to_raw()).unwrap();
        list.push(BerBurstTlv::default().to_raw()).unwrap();

        list.process_ber();

        // 0xAA ^ 0xAA = 0, 0x55 ^ 0x55 = 0, so 0 errors.
        let tlvs = list.non_hmac_tlvs();
        let count_tlv = tlvs
            .iter()
            .find(|t| t.tlv_type == TlvType::BerCount)
            .unwrap();
        assert_eq!(
            BerCountTlv::from_raw(count_tlv).unwrap().count,
            0,
            "identical padding and pattern → 0 errors"
        );
    }

    #[test]
    fn test_process_ber_computes_count_and_burst() {
        let mut list = TlvList::new();
        // Padding 0xFF, pattern 0x00 → 8 errors, max burst 8.
        list.push(
            ExtraPaddingTlv {
                padding: vec![0xFF],
            }
            .to_raw(),
        )
        .unwrap();
        list.push(BerPatternTlv::new(vec![0x00]).to_raw()).unwrap();
        list.push(BerCountTlv::default().to_raw()).unwrap();
        list.push(BerBurstTlv::default().to_raw()).unwrap();

        list.process_ber();

        let tlvs = list.non_hmac_tlvs();
        let count = BerCountTlv::from_raw(
            tlvs.iter()
                .find(|t| t.tlv_type == TlvType::BerCount)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(count.count, 8);
        let burst = BerBurstTlv::from_raw(
            tlvs.iter()
                .find(|t| t.tlv_type == TlvType::BerBurst)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(burst.max_burst, 8);
    }

    #[test]
    fn test_process_ber_uses_default_pattern_when_empty() {
        // No explicit Bit Pattern TLV; padding matches the 0xFF00 default.
        let mut list = TlvList::new();
        list.push(
            ExtraPaddingTlv {
                padding: vec![0xFF, 0x00, 0xFF, 0x00],
            }
            .to_raw(),
        )
        .unwrap();
        list.push(BerCountTlv::default().to_raw()).unwrap();
        list.push(BerBurstTlv::default().to_raw()).unwrap();

        list.process_ber();

        let tlvs = list.non_hmac_tlvs();
        let count = BerCountTlv::from_raw(
            tlvs.iter()
                .find(|t| t.tlv_type == TlvType::BerCount)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(count.count, 0);
    }

    #[test]
    fn test_process_ber_missing_extra_padding_flags_u() {
        // BER TLVs without a companion Extra Padding TLV → all three get U-flag.
        let mut list = TlvList::new();
        list.push(BerPatternTlv::new(vec![0xFF]).to_raw()).unwrap();
        list.push(BerCountTlv::default().to_raw()).unwrap();
        list.push(BerBurstTlv::default().to_raw()).unwrap();

        list.process_ber();

        for tlv in list.non_hmac_tlvs() {
            assert!(
                tlv.is_unrecognized(),
                "missing Extra Padding should mark all BER TLVs unrecognized"
            );
        }
    }

    #[test]
    fn test_process_ber_duplicate_count_tlvs_flag_u() {
        let mut list = TlvList::new();
        list.push(
            ExtraPaddingTlv {
                padding: vec![0xAA],
            }
            .to_raw(),
        )
        .unwrap();
        list.push(BerPatternTlv::new(vec![0xAA]).to_raw()).unwrap();
        list.push(BerCountTlv::default().to_raw()).unwrap();
        list.push(BerCountTlv::default().to_raw()).unwrap();

        list.process_ber();

        let tlvs = list.non_hmac_tlvs();
        let ber_tlvs: Vec<_> = tlvs
            .iter()
            .filter(|t| {
                matches!(
                    t.tlv_type,
                    TlvType::BerPattern | TlvType::BerCount | TlvType::BerBurst
                )
            })
            .collect();
        assert!(ber_tlvs.iter().all(|t| t.is_unrecognized()));
    }

    #[test]
    fn test_process_ber_no_ber_tlvs_noop() {
        // Packet without any BER TLVs — process_ber should be a no-op.
        let mut list = list_with_cleared(ExtraPaddingTlv::new_zeros(8).to_raw());

        list.process_ber();

        // No panics, no flags set.
        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
    }

    // --- Reflected Test Packet Control (draft-ietf-ippm-asymmetrical-pkts) tests ---

    #[test]
    fn test_get_reflected_control_request_returns_parsed_tlv() {
        let mut list = TlvList::new();
        list.push(ReflectedControlTlv::new(1500, 4, 1_000_000).to_raw())
            .unwrap();

        let req = list.get_reflected_control_request().unwrap();
        assert_eq!(req.length_of_reflected_packet, 1500);
        assert_eq!(req.number_of_reflected_packets, 4);
        assert_eq!(req.interval_nanoseconds, 1_000_000);
    }

    #[test]
    fn test_get_reflected_control_request_none_when_absent() {
        let mut list = TlvList::new();
        list.push(ExtraPaddingTlv::new_zeros(4).to_raw()).unwrap();

        assert!(list.get_reflected_control_request().is_none());
    }

    // --- Reflected Fixed/IPv6 Ext Header Data (draft-ietf-ippm-stamp-ext-hdr-11) tests ---

    #[test]
    fn test_reflected_fixed_hdr_populated_when_captured() {
        // -11 §5.2: Requested(4) preserved, Reflected = captured[4..].
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw());

        let captured: Vec<u8> = (10u8..30).collect(); // 20 distinct bytes
        list.process_reflected_headers(Some(&captured), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.tlv_type, TlvType::ReflectedFixedHdr);
        assert_eq!(
            &tlv.value[..4],
            &[0, 0, 0, 0],
            "Requested preserved (zeros)"
        );
        assert_eq!(&tlv.value[4..], &captured[4..], "Reflected = captured[4..]");
        assert!(!tlv.flags.conformant_reflected);
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_fixed_hdr_c_flag_when_backend_cant_capture() {
        // -11 §5.2 case (b): backend cannot observe IP layer → C flag, not U.
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw());

        // None = backend cannot observe IP layer (nix UDP-socket backend).
        list.process_reflected_headers(None, None);

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 20, "sender-advertised length is preserved");
        assert!(tlv.value.iter().all(|&b| b == 0), "value left as received");
        assert!(tlv.flags.conformant_reflected, "C flag set (-11)");
        assert!(!tlv.is_unrecognized(), "U flag must NOT be set under -11");
    }

    #[test]
    fn test_reflected_fixed_hdr_length_mismatch_sets_c_flag() {
        // -11 §5.2 case (a): the sender-advertised Length does not match the
        // captured header size (20-byte request but the packet is IPv6 with a
        // 40-byte fixed header) → C flag, value left as received.
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw());

        let ipv6_header = vec![0x60u8; 40];
        list.process_reflected_headers(Some(&ipv6_header), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 20, "sender-advertised length preserved");
        assert!(tlv.value.iter().all(|&b| b == 0), "value left as received");
        assert!(tlv.flags.conformant_reflected, "C flag on length mismatch");
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_fixed_hdr_ipv6_request_with_ipv6_capture_populated() {
        // 40-byte request + 40-byte captured header → Reflected = captured[4..].
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(40).to_raw());

        let captured: Vec<u8> = (0u8..40).collect();
        list.process_reflected_headers(Some(&captured), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(&tlv.value[..4], &[0, 0, 0, 0], "Requested preserved");
        assert_eq!(&tlv.value[4..], &captured[4..]);
        assert!(!tlv.flags.conformant_reflected);
    }

    #[test]
    fn test_reflected_fixed_hdr_selector_match_populates() {
        // -11 §5.2: a non-zero Requested field that matches the captured IP
        // header's first 4 octets → copy Reflected = captured[4..]. Here the
        // selector equals captured[..4], so the whole header is conveyed.
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut captured: Vec<u8> = (0u8..40).collect();
        captured[..4].copy_from_slice(&[0x60, 0x01, 0x02, 0x03]);

        let mut list = list_with_cleared(
            ReflectedFixedHdrTlv::request_with_selector(&[0x60, 0x01, 0x02, 0x03], 40).to_raw(),
        );
        list.process_reflected_headers(Some(&captured), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(
            &tlv.value[..4],
            &[0x60, 0x01, 0x02, 0x03],
            "Requested preserved"
        );
        assert_eq!(&tlv.value[4..], &captured[4..]);
        assert_eq!(
            tlv.value, captured,
            "selector == header[..4] → whole header"
        );
        assert!(!tlv.flags.conformant_reflected);
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_fixed_hdr_selector_mismatch_sets_c_flag() {
        // -11 §5.2 case (c): length matches but the Requested field does NOT
        // match the captured header → C flag, value (incl. Requested) preserved.
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut captured = vec![0u8; 40];
        captured[..4].copy_from_slice(&[0x60, 0x01, 0x02, 0x03]);

        let mut list = list_with_cleared(
            ReflectedFixedHdrTlv::request_with_selector(&[0x60, 0xFF, 0xFF, 0xFF], 40).to_raw(),
        );
        list.process_reflected_headers(Some(&captured), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 40, "advertised length preserved");
        assert_eq!(
            &tlv.value[..4],
            &[0x60, 0xFF, 0xFF, 0xFF],
            "Requested preserved on failure"
        );
        assert!(
            tlv.value[4..].iter().all(|&b| b == 0),
            "Reflected unchanged"
        );
        assert!(
            tlv.flags.conformant_reflected,
            "Requested mismatch → C flag"
        );
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_headers_out_of_order_sets_c_flag_no_copy() {
        // draft-ietf-ippm-stamp-ext-hdr-11 §3.3: Reflected Fixed Header Data
        // (247) TLVs MUST precede Reflected IPv6 Extension Header Data (246)
        // TLVs. "If ... TLVs are not received in this order, the Session-
        // Reflector MUST return these TLVs with the C flag ... set to 1 ...
        // without copying any data."
        use crate::tlv::{ReflectedFixedHdrTlv, ReflectedIpv6ExtHdrTlv};

        // Reversed order: 246 (ext hdr) BEFORE 247 (fixed hdr).
        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.push(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw())
            .unwrap();
        list.clear_reflector_flags();

        // Data that WOULD match if the TLVs were processed normally.
        let ext_blob = [0x00u8, 0x00, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        let fixed: Vec<u8> = (10u8..30).collect();
        list.process_reflected_headers(Some(&fixed), Some(&ext_blob));

        for tlv in list.non_hmac_tlvs() {
            assert!(
                tlv.flags.conformant_reflected,
                "out-of-order header TLV must get the C flag"
            );
            assert!(
                tlv.value.iter().all(|&b| b == 0),
                "out-of-order header TLV must not have data copied in"
            );
        }
    }

    #[test]
    fn test_reflected_headers_in_order_processed_normally() {
        // The complement of the §3.3 check: with 247 correctly before 246,
        // both TLVs are processed and copied normally (no false C flag).
        use crate::tlv::{ReflectedFixedHdrTlv, ReflectedIpv6ExtHdrTlv};

        let mut list = TlvList::new();
        list.push(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw())
            .unwrap();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.clear_reflector_flags();

        let ext_blob = [0x00u8, 0x00, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        let fixed: Vec<u8> = (10u8..30).collect();
        list.process_reflected_headers(Some(&fixed), Some(&ext_blob));

        let tlvs = list.non_hmac_tlvs();
        assert!(
            !tlvs[0].flags.conformant_reflected,
            "in-order 247 processed"
        );
        assert!(
            !tlvs[1].flags.conformant_reflected,
            "in-order 246 processed"
        );
        assert_eq!(&tlvs[0].value[4..], &fixed[4..], "247 reflected");
        assert_eq!(&tlvs[1].value[4..], &ext_blob[4..], "246 reflected");
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_populated_when_captured() {
        // -11 §5.1: Requested(4) preserved, Reflected = captured[4..].
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());

        // Destination Options header: NextHeader=60, HdrExtLen=0, 6 body bytes.
        let captured_ext = vec![60u8, 0u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        list.process_reflected_headers(Some(&[]), Some(&captured_ext));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(
            &tlv.value[..4],
            &[0, 0, 0, 0],
            "Requested preserved (zeros)"
        );
        assert_eq!(
            &tlv.value[4..],
            &captured_ext[4..],
            "Reflected = header[4..]"
        );
        assert!(!tlv.flags.conformant_reflected);
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_empty_capture_sets_c_flag() {
        // -11 §5.1: IPv4 path or IPv6 without ext headers — no header to
        // reflect, so the reflector "could not use it for reflecting any IPv6
        // extension header received" → C flag.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());

        list.process_reflected_headers(Some(&[0x45]), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 8, "advertised capacity preserved");
        assert!(
            tlv.flags.conformant_reflected,
            "no ext headers → C flag (-11)"
        );
        assert!(!tlv.is_unrecognized(), "U flag must NOT be set under -11");
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_c_flag_when_backend_cant_capture() {
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());

        list.process_reflected_headers(None, None);

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 8, "advertised capacity preserved");
        assert!(
            tlv.flags.conformant_reflected,
            "None capture → C flag (-11)"
        );
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_incomplete_capture_sets_c_flag() {
        // A blob shorter than one valid ext-header record (HdrExtLen=0 →
        // 8 octets, but only 4 present) yields no parseable record → C flag.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());

        let captured = vec![60u8, 0u8, 0xAA, 0xBB]; // 4 bytes < 8-byte record
        list.process_reflected_headers(Some(&[]), Some(&captured));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 8, "capacity preserved");
        assert!(tlv.flags.conformant_reflected, "no valid record → C flag");
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_length_smaller_than_record_sets_c_flag() {
        // A request Length (4) smaller than the minimum ext-header record
        // (8 octets) can never length-match → C flag. (No truncation under -11.)
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(4).to_raw());

        let captured = vec![60u8, 0u8, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        list.process_reflected_headers(Some(&[]), Some(&captured));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 4);
        assert!(tlv.flags.conformant_reflected, "length mismatch → C flag");
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_selector_matches_specific_header() {
        // -11 §5.1 disambiguation: two extension headers of the SAME length
        // (both 8 bytes), differing only in body. A non-zero Requested field
        // must pick the matching one. Here the selector equals rec_b's first 4
        // on-wire octets, so the whole rec_b (Requested + Reflected) is conveyed.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let rec_a = [0x3Cu8, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        let rec_b = [0x3Cu8, 0x00, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec_a);
        blob.extend_from_slice(&rec_b);

        // Selector = rec_b's first 4 on-wire bytes.
        let mut list = list_with_cleared(
            ReflectedIpv6ExtHdrTlv::request_with_selector(&[0x3C, 0x00, 0xB1, 0xB2], 8).to_raw(),
        );
        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(
            &tlv.value[..4],
            &[0x3C, 0x00, 0xB1, 0xB2],
            "Requested preserved"
        );
        assert_eq!(
            &tlv.value[4..],
            &rec_b[4..],
            "Reflected = matched header[4..]"
        );
        assert_eq!(
            tlv.value,
            rec_b.to_vec(),
            "selector == rec_b[..4] → whole rec_b"
        );
        assert!(!tlv.flags.conformant_reflected);
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_selector_no_match_sets_c_flag() {
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let blob = [0x3Cu8, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];

        let mut list = list_with_cleared(
            ReflectedIpv6ExtHdrTlv::request_with_selector(&[0x3C, 0x00, 0xFF, 0xFF], 8).to_raw(),
        );
        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value.len(), 8, "advertised capacity preserved");
        assert_eq!(
            &tlv.value[..4],
            &[0x3C, 0x00, 0xFF, 0xFF],
            "Requested preserved on failure"
        );
        assert!(
            tlv.flags.conformant_reflected,
            "no Requested match → C flag"
        );
        assert!(!tlv.is_unrecognized(), "U flag must NOT be set under -11");
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_selector_no_match_on_empty_capture_sets_c_flag() {
        // Non-zero Requested but no captured ext headers (IPv4 / no options):
        // the requested header isn't present → C flag.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(
            ReflectedIpv6ExtHdrTlv::request_with_selector(&[0x3C, 0x00, 0x01, 0x02], 8).to_raw(),
        );
        list.process_reflected_headers(Some(&[0x45]), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(tlv.flags.conformant_reflected);
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_zero_selector_does_not_concatenate() {
        // -11 removed the -08 "concatenate every captured header" behavior. A
        // 16-byte request against two 8-byte headers can no longer length-match
        // (the positionally-paired first header is 8 bytes) → C flag, proving
        // concat-all is gone.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let rec_a = [0x3Cu8, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        let rec_b = [0x00u8, 0x00, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec_a);
        blob.extend_from_slice(&rec_b);

        let mut list =
            list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(16).to_raw());
        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(
            tlv.flags.conformant_reflected,
            "16-byte request vs 8-byte header → length mismatch → C flag"
        );
    }

    #[test]
    fn test_reflected_headers_noop_when_no_tlvs() {
        // Packet with only Extra Padding — should not flag anything.
        let mut list = list_with_cleared(ExtraPaddingTlv::new_zeros(4).to_raw());

        list.process_reflected_headers(None, None);

        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
    }

    // --- draft-ietf-ippm-stamp-ext-hdr-11 semantics ---
    // -11 splits the value into Requested(4) + Reflected(Length-4). The
    // Requested field is left exactly as received; the Reflected field holds
    // only the matched header's bytes from offset 4 onward. Failure is
    // signalled with the C flag (Conformance), NOT the U flag, and the value
    // is left as received.

    #[test]
    fn test_v11_fixed_hdr_requested_preserved_reflected_is_offset_4() {
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw());

        // Bytes 0,1,2,...,19 so we can see exactly which land where.
        let captured: Vec<u8> = (0u8..20).collect();
        list.process_reflected_headers(Some(&captured), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(
            &tlv.value[..4],
            &[0, 0, 0, 0],
            "Requested field (value[..4]) preserved exactly as received"
        );
        assert_eq!(
            &tlv.value[4..],
            &captured[4..],
            "Reflected field = header[4..], header's own first 4 octets not copied"
        );
        assert!(!tlv.flags.conformant_reflected, "success → no C flag");
        assert!(!tlv.is_unrecognized(), "success → no U flag");
    }

    #[test]
    fn test_v11_fixed_hdr_none_capture_sets_c_flag_not_u() {
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw());

        list.process_reflected_headers(None, None);

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(
            tlv.flags.conformant_reflected,
            "None capture → C flag (-11)"
        );
        assert!(!tlv.is_unrecognized(), "must NOT set the U flag under -11");
        assert!(tlv.value.iter().all(|&b| b == 0), "value left as received");
    }

    #[test]
    fn test_v11_fixed_hdr_length_mismatch_sets_c_flag_not_u() {
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = list_with_cleared(ReflectedFixedHdrTlv::request_with_capacity(20).to_raw());

        let ipv6_header = vec![0x60u8; 40];
        list.process_reflected_headers(Some(&ipv6_header), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(
            tlv.flags.conformant_reflected,
            "length mismatch → C flag (-11)"
        );
        assert!(!tlv.is_unrecognized());
        assert_eq!(tlv.value.len(), 20, "advertised length preserved");
        assert!(tlv.value.iter().all(|&b| b == 0), "value left as received");
    }

    #[test]
    fn test_v11_ext_hdr_zero_selector_picks_first_length_match() {
        // Two extension headers of the SAME length (8 bytes). A zero Requested
        // field must pick the FIRST (positional) header, copy only its [4..].
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let rec_a = [0x3Cu8, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        let rec_b = [0x00u8, 0x00, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec_a);
        blob.extend_from_slice(&rec_b);

        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());
        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(
            &tlv.value[..4],
            &[0, 0, 0, 0],
            "Requested preserved (zeros)"
        );
        assert_eq!(&tlv.value[4..], &rec_a[4..], "first header's [4..] copied");
        assert!(!tlv.flags.conformant_reflected);
    }

    #[test]
    fn test_v11_ext_hdr_positional_pairing_two_tlvs_two_headers() {
        // 2 TLVs (both zero Requested, Length 8) ↔ 2 headers (8 bytes each),
        // paired in wire order: TLV[0] ↔ header[0], TLV[1] ↔ header[1].
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let rec0 = [0x3Cu8, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
        let rec1 = [0x00u8, 0x00, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec0);
        blob.extend_from_slice(&rec1);

        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.clear_reflector_flags();

        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlvs = list.non_hmac_tlvs();
        assert_eq!(&tlvs[0].value[4..], &rec0[4..], "1st TLV ↔ 1st header");
        assert_eq!(&tlvs[1].value[4..], &rec1[4..], "2nd TLV ↔ 2nd header");
        assert!(!tlvs[0].flags.conformant_reflected);
        assert!(!tlvs[1].flags.conformant_reflected);
    }

    #[test]
    fn test_v11_ext_hdr_no_selector_match_sets_c_flag_not_u() {
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let blob = [0x3Cu8, 0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6];
        let mut list = list_with_cleared(
            ReflectedIpv6ExtHdrTlv::request_with_selector(&[0x3C, 0x00, 0xFF, 0xFF], 8).to_raw(),
        );
        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(
            tlv.flags.conformant_reflected,
            "no Requested match → C flag"
        );
        assert!(!tlv.is_unrecognized(), "must NOT set U flag under -11");
        assert_eq!(
            &tlv.value[..4],
            &[0x3C, 0x00, 0xFF, 0xFF],
            "Requested preserved on failure"
        );
    }

    #[test]
    fn test_v11_ext_hdr_none_capture_sets_c_flag_not_u() {
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());

        list.process_reflected_headers(None, None);

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(
            tlv.flags.conformant_reflected,
            "None capture → C flag (-11)"
        );
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_v11_ext_hdr_empty_capture_sets_c_flag() {
        // A Reflected IPv6 Ext Hdr TLV but no ext headers received (IPv4 path or
        // IPv6 without options): the reflector "could not use it for reflecting
        // any IPv6 extension header received" → C flag (-11 §5.1).
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());

        list.process_reflected_headers(Some(&[0x45]), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(
            tlv.flags.conformant_reflected,
            "no ext headers → C flag (-11)"
        );
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_v11_ext_hdr_zero_selector_first_fit_skips_length_mismatch() {
        // Reviewer's exact failing scenario: a single zero-selector Length-8 TLV
        // against captured [16-byte HBH, 8-byte DestOpts]. Draft -11 §5.1
        // requires matching the FIRST IPv6 extension header of the MATCHING
        // LENGTH, so the 8-byte header must be reflected even though it is the
        // second header on the wire. The old positional selection C-flagged it
        // (the 16-byte header at position 0 failed the Length==8 filter).
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        // 16-byte HBH record: NextHeader=0x3C, HdrExtLen=1 → (1+1)*8 = 16 bytes.
        let mut rec16 = vec![0x3Cu8, 0x01];
        rec16.resize(16, 0xAA);
        // 8-byte DestOpts record: NextHeader=0x3C, HdrExtLen=0 → 8 bytes.
        let rec8 = [0x3Cu8, 0x00, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec16);
        blob.extend_from_slice(&rec8);

        let mut list = list_with_cleared(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw());
        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(
            &tlv.value[..4],
            &[0, 0, 0, 0],
            "Requested preserved (zeros)"
        );
        assert_eq!(
            &tlv.value[4..],
            &rec8[4..],
            "8-byte header reflected via first-fit-by-length (not the 16-byte first header)"
        );
        assert!(
            !tlv.flags.conformant_reflected,
            "first-fit by length matched → no C flag"
        );
    }

    #[test]
    fn test_v11_ext_hdr_zero_selector_first_fit_two_tlvs_reorder() {
        // Two zero-selector TLVs — Length 8 then Length 16 — against captured
        // [16-byte hdr, 8-byte hdr]. Expected outcome: first-fit-by-length WITH
        // CONSUMPTION pairs the Length-8 TLV to the 8-byte (2nd wire) header and
        // the Length-16 TLV to the 16-byte (1st wire) header, so BOTH reflect
        // even though the TLV order and the wire order disagree.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut rec16 = vec![0x3Cu8, 0x01];
        rec16.resize(16, 0xCC);
        let rec8 = [0x3Cu8, 0x00, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec16);
        blob.extend_from_slice(&rec8);

        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(16).to_raw())
            .unwrap();
        list.clear_reflector_flags();

        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlvs = list.non_hmac_tlvs();
        assert_eq!(
            &tlvs[0].value[4..],
            &rec8[4..],
            "Length-8 TLV ↔ 8-byte header (first-fit by length)"
        );
        assert_eq!(
            &tlvs[1].value[4..],
            &rec16[4..],
            "Length-16 TLV ↔ 16-byte header (first-fit by length)"
        );
        assert!(
            !tlvs[0].flags.conformant_reflected,
            "8-byte match → no C flag"
        );
        assert!(
            !tlvs[1].flags.conformant_reflected,
            "16-byte match → no C flag"
        );
    }

    #[test]
    fn test_v11_ext_hdr_zero_selector_same_length_pairs_in_order() {
        // Regression for §3.1 rule 2: two same-length (8-byte) zero-selector
        // TLVs against two same-length but DISTINGUISHABLE headers must pair in
        // wire order (1st↔1st, 2nd↔2nd). First-fit-with-consumption preserves
        // this: TLV[0] consumes header index 0, TLV[1] then finds index 1.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let rec0 = [0x3Cu8, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
        let rec1 = [0x00u8, 0x00, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec0);
        blob.extend_from_slice(&rec1);

        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw())
            .unwrap();
        list.clear_reflector_flags();

        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlvs = list.non_hmac_tlvs();
        assert_eq!(&tlvs[0].value[4..], &rec0[4..], "1st TLV ↔ 1st header");
        assert_eq!(&tlvs[1].value[4..], &rec1[4..], "2nd TLV ↔ 2nd header");
        assert!(!tlvs[0].flags.conformant_reflected);
        assert!(!tlvs[1].flags.conformant_reflected);
    }

    #[test]
    fn test_v11_ext_hdr_duplicate_nonzero_selector_consumes_successively() {
        // Two IDENTICAL non-zero Requested TLVs (same selector) against two
        // headers that share the same on-wire first 4 octets but differ in body.
        // With consumption, TLV[0] takes the 1st matching header and TLV[1]
        // takes the 2nd — both reflect DIFFERENT headers. The old
        // find()-without-consumption matched both TLVs to the first header.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let sel = [0x3Cu8, 0x00, 0xAA, 0xBB];
        let rec0 = [0x3Cu8, 0x00, 0xAA, 0xBB, 0x10, 0x11, 0x12, 0x13];
        let rec1 = [0x3Cu8, 0x00, 0xAA, 0xBB, 0x20, 0x21, 0x22, 0x23];
        let mut blob = Vec::new();
        blob.extend_from_slice(&rec0);
        blob.extend_from_slice(&rec1);

        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_selector(&sel, 8).to_raw())
            .unwrap();
        list.push(ReflectedIpv6ExtHdrTlv::request_with_selector(&sel, 8).to_raw())
            .unwrap();
        list.clear_reflector_flags();

        list.process_reflected_headers(Some(&[]), Some(&blob));

        let tlvs = list.non_hmac_tlvs();
        assert_eq!(
            tlvs[0].value, rec0,
            "1st duplicate TLV consumes the 1st matching header"
        );
        assert_eq!(
            tlvs[1].value, rec1,
            "2nd duplicate TLV consumes the 2nd matching header"
        );
        assert!(!tlvs[0].flags.conformant_reflected);
        assert!(!tlvs[1].flags.conformant_reflected);
    }

    #[test]
    fn test_set_reflected_control_c_flag() {
        let mut list = TlvList::new();
        list.push(ReflectedControlTlv::new(0, 2, 1_000).to_raw())
            .unwrap();

        assert!(!list.non_hmac_tlvs()[0].flags.conformant_reflected);

        list.set_reflected_control_c_flag();

        assert!(list.non_hmac_tlvs()[0].flags.conformant_reflected);
    }
}
