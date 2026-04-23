//! Reflector-side TLV mutation methods for TlvList.
//!
//! This submodule of `list` provides methods that the Session-Reflector uses
//! to update TLV fields in-place before reflecting a packet. Being a submodule
//! of `list`, it can access `TlvList`'s private fields directly.

use crate::tlv::core::{
    RawTlv, TlvType, BER_BURST_TLV_VALUE_SIZE, BER_COUNT_TLV_VALUE_SIZE, COS_TLV_VALUE_SIZE,
    DIRECT_MEASUREMENT_TLV_VALUE_SIZE, FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE,
    LOCATION_TLV_MIN_VALUE_SIZE, TIMESTAMP_INFO_TLV_VALUE_SIZE,
};
use crate::tlv::{
    ClassOfServiceTlv, DestinationNodeAddressTlv, LocationSubTlv, LocationSubType,
    MicroSessionIdTlv, PacketAddressInfo, ReflectedControlTlv, ReturnPathAction, ReturnPathTlv,
    SyncSource, TimestampMethod, TypedTlv, BER_DEFAULT_PATTERN,
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
    /// Per RFC 8972 §5.2, the Session-Reflector fills in DSCP2 and ECN2 fields
    /// with the values received at its ingress before reflecting the packet.
    ///
    /// Updates bytes in-place to avoid allocation overhead. The CoS TLV layout:
    /// - Byte 0: DSCP1 (6 bits) | ECN1 (2 bits) - preserved
    /// - Byte 1: DSCP2 (6 bits) | ECN2 (2 bits) - updated
    /// - Byte 2: RP (2 bits) | Reserved (6 bits) - RP updated if policy_rejected
    /// - Byte 3: Reserved - preserved
    ///
    /// # Arguments
    /// * `received_dscp` - DSCP value received at reflector's ingress (6 bits, 0-63)
    /// * `received_ecn` - ECN value received at reflector's ingress (2 bits, 0-3)
    /// * `policy_rejected` - True if local policy rejected the requested DSCP1
    pub fn update_cos_tlvs(&mut self, received_dscp: u8, received_ecn: u8, policy_rejected: bool) {
        self.for_each_matching_tlv(
            |tlv| tlv.tlv_type == TlvType::ClassOfService && tlv.value.len() == COS_TLV_VALUE_SIZE,
            |tlv| {
                Self::update_cos_value_in_place(
                    &mut tlv.value,
                    received_dscp,
                    received_ecn,
                    policy_rejected,
                );
            },
        );
    }

    /// Updates CoS TLV value bytes in-place.
    ///
    /// Modifies DSCP2/ECN2/RP fields without allocating a new value buffer.
    /// Assumes value is exactly `COS_TLV_VALUE_SIZE` (4) bytes.
    #[inline]
    fn update_cos_value_in_place(
        value: &mut [u8],
        received_dscp: u8,
        received_ecn: u8,
        policy_rejected: bool,
    ) {
        // Byte 1: DSCP2 (6 bits) | ECN2 (2 bits)
        value[1] = ((received_dscp & 0x3F) << 2) | (received_ecn & 0x03);

        // Byte 2: RP (2 bits) | Reserved (6 bits) - preserve reserved bits
        let rp_bits = if policy_rejected { 0x40 } else { 0x00 }; // RP=1 in bits 7-6
        value[2] = rp_bits | (value[2] & 0x3F);
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

    /// Updates Location TLV value with address information.
    ///
    /// Replaces the entire value with ports and address sub-TLVs.
    fn update_location_value_in_place(value: &mut Vec<u8>, info: &PacketAddressInfo) {
        value.clear();
        // Dest port and src port
        value.extend_from_slice(&info.dst_port.to_be_bytes());
        value.extend_from_slice(&info.src_port.to_be_bytes());
        // Add source address sub-TLV
        match info.src_addr {
            std::net::IpAddr::V4(addr) => {
                LocationSubTlv::new(LocationSubType::Ipv4Src, addr.octets().to_vec())
                    .write_to(value);
            }
            std::net::IpAddr::V6(addr) => {
                LocationSubTlv::new(LocationSubType::Ipv6Src, addr.octets().to_vec())
                    .write_to(value);
            }
        }
        // Add destination address sub-TLV
        match info.dst_addr {
            std::net::IpAddr::V4(addr) => {
                LocationSubTlv::new(LocationSubType::Ipv4Dst, addr.octets().to_vec())
                    .write_to(value);
            }
            std::net::IpAddr::V6(addr) => {
                LocationSubTlv::new(LocationSubType::Ipv6Dst, addr.octets().to_vec())
                    .write_to(value);
            }
        }
    }

    /// Updates Follow-Up Telemetry TLVs with the last reflection data.
    ///
    /// Per RFC 8972 §4.7, the Session-Reflector fills in the sequence number
    /// and timestamp from its previous reflection.
    pub fn update_follow_up_telemetry_tlvs(
        &mut self,
        last_seq: u32,
        last_ts: u64,
        mode: TimestampMethod,
    ) {
        let seq_bytes = last_seq.to_be_bytes();
        let ts_bytes = last_ts.to_be_bytes();
        let mode_byte = mode.to_byte();
        self.for_each_matching_tlv(
            |tlv| {
                tlv.tlv_type == TlvType::FollowUpTelemetry
                    && tlv.value.len() == FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE
            },
            |tlv| {
                tlv.value[0..4].copy_from_slice(&seq_bytes);
                tlv.value[4..12].copy_from_slice(&ts_bytes);
                tlv.value[12] = mode_byte;
                tlv.value[13..16].fill(0); // Reserved
            },
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
    pub fn process_return_path(&mut self, sender_port: u16) -> ReturnPathAction {
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
            return ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(
                addr,
                sender_port,
            ));
        }

        // Check for SR-MPLS or SRv6 — unsupported in userspace
        if rp.has_sr_mpls() || rp.has_srv6() {
            self.set_return_path_u_flag();
            return ReturnPathAction::UnsupportedSr;
        }

        // Empty or unrecognized sub-TLVs — set U-flag, return Normal
        self.set_return_path_u_flag();
        ReturnPathAction::Normal
    }

    /// Sets the U-flag on the Return Path TLV in both separated and wire-order lists.
    fn set_return_path_u_flag(&mut self) {
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
    /// draft-ietf-ippm-stamp-ext-hdr.
    ///
    /// When `captured` is `Some`, the reflector copies the captured bytes
    /// into each matching TLV's Value. When `captured` is `None`, the
    /// backend cannot observe raw IP headers — the TLVs are echoed empty
    /// with the U-flag set per RFC 8972 §4.2.
    ///
    /// `captured_fixed` supplies the IP fixed header (IPv4 20 bytes, IPv6
    /// 40 bytes). `captured_ext_headers` supplies concatenated IPv6
    /// Hop-by-Hop/Destination Options, each prefixed with NextHeader and
    /// HdrLen bytes exactly as on the wire.
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
        for tlv in tlvs {
            match tlv.tlv_type {
                TlvType::ReflectedFixedHdr => match captured_fixed {
                    Some(bytes) if !bytes.is_empty() => {
                        tlv.value = bytes.to_vec();
                    }
                    _ => {
                        tlv.value.clear();
                        tlv.set_unrecognized();
                        log_reflected_hdr_unsupported_once();
                    }
                },
                TlvType::ReflectedIpv6ExtHdr => match captured_ext_headers {
                    // Empty ext_headers is legitimate for an IPv4 packet or an
                    // IPv6 packet without Hop-by-Hop/Destination options. Only
                    // set U-flag when the backend cannot observe the IP layer
                    // at all (captured_ext_headers is None).
                    Some(bytes) => {
                        tlv.value = bytes.to_vec();
                    }
                    None => {
                        tlv.value.clear();
                        tlv.set_unrecognized();
                        log_reflected_hdr_unsupported_once();
                    }
                },
                _ => {}
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

/// Emits a one-time warning when the reflector receives an extension-header
/// reflection request (TLV 246/247) but the backend cannot observe raw IP
/// headers. Fired from `apply_reflected_headers`.
fn log_reflected_hdr_unsupported_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if !LOGGED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "Reflected Fixed/IPv6 Ext Header TLV (Types 247/246) requested but \
             this backend cannot observe raw IP headers — echoing with U-flag. \
             Rebuild with --features ttl-pnet to enable draft-ietf-ippm-stamp-ext-hdr reflection."
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
        BerBurstTlv, BerCountTlv, BerPatternTlv, DirectMeasurementTlv, ExtraPaddingTlv,
        FollowUpTelemetryTlv, LocationTlv, ReflectedControlTlv, TimestampInfoTlv,
    };

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
    fn test_update_location_tlvs_ipv4() {
        use std::net::{IpAddr, Ipv4Addr};

        let mut list = TlvList::new();
        let sender_tlv = LocationTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

        let info = PacketAddressInfo {
            src_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 50000,
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: 862,
        };
        list.update_location_tlvs(&info);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.sub_tlvs.len(), 2);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::Ipv4Src);
        assert_eq!(parsed.sub_tlvs[0].value, vec![10, 0, 0, 1]);
        assert_eq!(parsed.sub_tlvs[1].sub_type, LocationSubType::Ipv4Dst);
        assert_eq!(parsed.sub_tlvs[1].value, vec![10, 0, 0, 2]);
    }

    #[test]
    fn test_update_location_tlvs_ipv6() {
        use std::net::{IpAddr, Ipv6Addr};

        let mut list = TlvList::new();
        let sender_tlv = LocationTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

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
        let parsed = LocationTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.dest_port, 862);
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.sub_tlvs.len(), 2);
        assert_eq!(parsed.sub_tlvs[0].sub_type, LocationSubType::Ipv6Src);
        assert_eq!(parsed.sub_tlvs[0].value, src.octets().to_vec());
        assert_eq!(parsed.sub_tlvs[1].sub_type, LocationSubType::Ipv6Dst);
        assert_eq!(parsed.sub_tlvs[1].value, dst.octets().to_vec());
    }

    #[test]
    fn test_update_follow_up_telemetry_tlvs() {
        let mut list = TlvList::new();
        let sender_tlv = FollowUpTelemetryTlv::new();
        list.push(sender_tlv.to_raw()).unwrap();

        list.update_follow_up_telemetry_tlvs(42, 0xDEADBEEFCAFEBABE, TimestampMethod::SwLocal);

        let raw = &list.non_hmac_tlvs()[0];
        let parsed = FollowUpTelemetryTlv::from_raw(raw).unwrap();
        assert_eq!(parsed.sequence_number, 42);
        assert_eq!(parsed.follow_up_timestamp, 0xDEADBEEFCAFEBABE);
        assert_eq!(parsed.timestamp_mode, TimestampMethod::SwLocal);
    }

    #[test]
    fn test_update_follow_up_telemetry_skips_wrong_size() {
        let mut list = TlvList::new();
        list.push(RawTlv::new(TlvType::FollowUpTelemetry, vec![0; 8]))
            .unwrap();

        list.update_follow_up_telemetry_tlvs(42, 100, TimestampMethod::SwLocal);

        // Value should be unchanged
        assert_eq!(list.non_hmac_tlvs()[0].value, vec![0; 8]);
    }

    #[test]
    fn test_process_destination_node_address_match() {
        let addr: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let tlv = DestinationNodeAddressTlv::new(addr);
        let mut list = TlvList::new();
        list.push(tlv.to_raw()).unwrap();

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

        let action = list.process_return_path(1234);
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
        let rp = ReturnPathTlv::with_control_code(0x1);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
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

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::SuppressReply);
    }

    #[test]
    fn test_process_return_path_cc_reserved_bits_normal() {
        // RFC 9503: only bit 0 matters; reserved bits are ignored.
        // 0xFF has bit 0 set → same-link request; U-flag is not pre-set
        // since on single-homed paths the backend already satisfies it.
        let rp = ReturnPathTlv::with_control_code(0xFF);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
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

        let action = list.process_return_path(862);
        assert_eq!(
            action,
            ReturnPathAction::AlternateAddress(std::net::SocketAddr::new(addr, 862))
        );
    }

    #[test]
    fn test_process_return_path_sr_unsupported() {
        let rp = ReturnPathTlv::with_sr_mpls_labels(&[100, 200]);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(862);
        assert_eq!(action, ReturnPathAction::UnsupportedSr);
        assert!(list.non_hmac_tlvs()[0].is_unrecognized());
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
        let mut list = TlvList::new();
        list.push(ExtraPaddingTlv::new_zeros(8).to_raw()).unwrap();

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

    // --- Reflected Fixed/IPv6 Ext Header Data (draft-ippm-stamp-ext-hdr) tests ---

    #[test]
    fn test_reflected_fixed_hdr_populated_when_captured() {
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = TlvList::new();
        list.push(ReflectedFixedHdrTlv::request().to_raw()).unwrap();

        let mut captured = vec![0u8; 20];
        captured[0] = 0x45; // IPv4 version + IHL
        captured[1] = 0x00; // TOS
        list.process_reflected_headers(Some(&captured), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.tlv_type, TlvType::ReflectedFixedHdr);
        assert_eq!(tlv.value, captured);
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_fixed_hdr_u_flag_when_backend_cant_capture() {
        use crate::tlv::ReflectedFixedHdrTlv;
        let mut list = TlvList::new();
        list.push(ReflectedFixedHdrTlv::request().to_raw()).unwrap();

        // None = backend cannot observe IP layer (nix UDP-socket backend).
        list.process_reflected_headers(None, None);

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(tlv.value.is_empty(), "value must be cleared on U-flag path");
        assert!(tlv.is_unrecognized(), "U-flag must be set when backend cannot capture");
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_populated_when_captured() {
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request().to_raw())
            .unwrap();

        // Fake Hop-by-Hop header: NextHeader=60 (Destination Opts), HdrExtLen=0, 6 bytes body.
        let captured_ext = vec![60u8, 0u8, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00];
        list.process_reflected_headers(Some(&[]), Some(&captured_ext));

        let tlv = &list.non_hmac_tlvs()[0];
        assert_eq!(tlv.value, captured_ext);
        assert!(!tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_empty_capture_is_not_u_flag() {
        // An IPv4 packet or an IPv6 packet without ext headers produces an
        // empty captured_ext_headers slice — that's legitimate, not "backend
        // can't observe". U-flag stays clear.
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request().to_raw())
            .unwrap();

        list.process_reflected_headers(Some(&[0x45]), Some(&[]));

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(tlv.value.is_empty());
        assert!(
            !tlv.is_unrecognized(),
            "empty ext-header list on IPv4 packet must not set U-flag"
        );
    }

    #[test]
    fn test_reflected_ipv6_ext_hdr_u_flag_when_backend_cant_capture() {
        use crate::tlv::ReflectedIpv6ExtHdrTlv;
        let mut list = TlvList::new();
        list.push(ReflectedIpv6ExtHdrTlv::request().to_raw())
            .unwrap();

        list.process_reflected_headers(None, None);

        let tlv = &list.non_hmac_tlvs()[0];
        assert!(tlv.value.is_empty());
        assert!(tlv.is_unrecognized());
    }

    #[test]
    fn test_reflected_headers_noop_when_no_tlvs() {
        // Packet with only Extra Padding — should not flag anything.
        let mut list = TlvList::new();
        list.push(ExtraPaddingTlv::new_zeros(4).to_raw()).unwrap();

        list.process_reflected_headers(None, None);

        assert!(!list.non_hmac_tlvs()[0].is_unrecognized());
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
