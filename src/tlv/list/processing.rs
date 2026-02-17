//! Reflector-side TLV mutation methods for TlvList.
//!
//! This submodule of `list` provides methods that the Session-Reflector uses
//! to update TLV fields in-place before reflecting a packet. Being a submodule
//! of `list`, it can access `TlvList`'s private fields directly.

use crate::tlv::core::{
    RawTlv, TlvType, COS_TLV_VALUE_SIZE, DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
    FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE, LOCATION_TLV_MIN_VALUE_SIZE, TIMESTAMP_INFO_TLV_VALUE_SIZE,
};
use crate::tlv::{
    ClassOfServiceTlv, DestinationNodeAddressTlv, LocationSubTlv, LocationSubType,
    MicroSessionIdTlv, PacketAddressInfo, ReturnPathAction, ReturnPathTlv, SyncSource,
    TimestampMethod, TypedTlv,
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
                ReturnPathAction::Normal // Same-link = normal for userspace UDP
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;
    use crate::tlv::{DirectMeasurementTlv, FollowUpTelemetryTlv, LocationTlv, TimestampInfoTlv};

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
    fn test_process_return_path_normal() {
        let rp = ReturnPathTlv::with_control_code(0x1);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::Normal);
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
        // 0xFF has bit 0 set → normal reply.
        let rp = ReturnPathTlv::with_control_code(0xFF);
        let mut list = TlvList::new();
        list.push(rp.to_raw()).unwrap();

        let action = list.process_return_path(1234);
        assert_eq!(action, ReturnPathAction::Normal);
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
}
