use super::*;

#[test]
fn test_wire_format_sizes_match_rfc() {
    // Verify wire format sizes match RFC 8762 requirements
    let unauth = PacketUnauthenticated {
        sequence_number: 0,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    assert_eq!(unauth.to_bytes().len(), 44);

    let reflected_unauth = ReflectedPacketUnauthenticated {
        sequence_number: 0,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        receive_timestamp: 0,
        sess_sender_seq_number: 0,
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz2: [0; 2],
        sess_sender_ttl: 0,
        mbz3: [0; 3],
    };
    assert_eq!(reflected_unauth.to_bytes().len(), 44);

    let auth = PacketAuthenticated {
        sequence_number: 0,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    assert_eq!(auth.to_bytes().len(), 112);

    let reflected_auth = ReflectedPacketAuthenticated {
        sequence_number: 0,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz1: [0; 4],
        receive_timestamp: 0,
        mbz2: [0; 8],
        sess_sender_seq_number: 0,
        mbz3: [0; 12],
        sess_sender_timestamp: 0,
        sess_sender_err_estimate: 0,
        mbz4: [0; 6],
        sess_sender_ttl: 0,
        mbz5: [0; 15],
        hmac: [0; 16],
    };
    assert_eq!(reflected_auth.to_bytes().len(), 112);
}

#[test]
fn test_packet_unauthenticated_serialization() {
    let packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz: [0; 28],
    };
    let serialized = packet.to_bytes();
    let deserialized = PacketUnauthenticated::from_bytes(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

#[test]
fn test_reflected_packet_unauthenticated_serialization() {
    let packet = ReflectedPacketUnauthenticated {
        sequence_number: 1,
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        receive_timestamp: 987654321,
        sess_sender_seq_number: 2,
        sess_sender_timestamp: 123456789,
        sess_sender_err_estimate: 100,
        mbz2: [0; 2],
        sess_sender_ttl: 64,
        mbz3: [0; 3],
    };
    let serialized = packet.to_bytes();
    let deserialized = ReflectedPacketUnauthenticated::from_bytes(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

#[test]
fn test_packet_authenticated_serialization() {
    let packet = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    let serialized = packet.to_bytes();
    let deserialized = PacketAuthenticated::from_bytes(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

#[test]
fn test_reflected_packet_authenticated_serialization() {
    let packet = ReflectedPacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 123456789,
        error_estimate: 100,
        ssid: 0,
        mbz1: [0; 4],
        receive_timestamp: 987654321,
        mbz2: [0; 8],
        sess_sender_seq_number: 2,
        mbz3: [0; 12],
        sess_sender_timestamp: 123456789,
        sess_sender_err_estimate: 100,
        mbz4: [0; 6],
        sess_sender_ttl: 64,
        mbz5: [0; 15],
        hmac: [0; 16],
    };
    let serialized = packet.to_bytes();
    let deserialized = ReflectedPacketAuthenticated::from_bytes(&serialized).unwrap();
    assert_eq!(packet, deserialized);
}

#[test]
fn test_packet_unauthenticated_buffer_too_small() {
    let small_buffer = [0u8; 43];
    let result = PacketUnauthenticated::from_bytes(&small_buffer);
    assert!(result.is_err());
}

#[test]
fn test_packet_authenticated_buffer_too_small() {
    let small_buffer = [0u8; 111];
    let result = PacketAuthenticated::from_bytes(&small_buffer);
    assert!(result.is_err());
}

#[test]
fn test_reflected_unauth_buffer_too_small() {
    let small_buffer = [0u8; 43];
    let result = ReflectedPacketUnauthenticated::from_bytes(&small_buffer);
    assert!(result.is_err());
}

#[test]
fn test_reflected_auth_buffer_too_small() {
    let small_buffer = [0u8; 111];
    let result = ReflectedPacketAuthenticated::from_bytes(&small_buffer);
    assert!(result.is_err());
}

#[test]
fn test_packet_field_values_preserved() {
    // Test specific field values are correctly preserved
    let packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 0xDEADBEEFCAFEBABE,
        error_estimate: 0xABCD,
        ssid: 0xBEEF,
        mbz: [0x42; 28],
    };
    let serialized = packet.to_bytes();
    let deserialized = PacketUnauthenticated::from_bytes(&serialized).unwrap();

    assert_eq!(deserialized.sequence_number, 0x12345678);
    assert_eq!(deserialized.timestamp, 0xDEADBEEFCAFEBABE);
    assert_eq!(deserialized.error_estimate, 0xABCD);
    assert_eq!(deserialized.ssid, 0xBEEF);
    assert_eq!(deserialized.mbz, [0x42; 28]);
}

#[test]
fn test_reflected_packet_echoed_fields() {
    // Verify reflected packet can store echoed sender fields
    let packet = ReflectedPacketUnauthenticated {
        sequence_number: 100,
        timestamp: 200,
        error_estimate: 300,
        ssid: 0x11,
        receive_timestamp: 400,
        sess_sender_seq_number: 500,
        sess_sender_timestamp: 600,
        sess_sender_err_estimate: 700,
        mbz2: [0; 2],
        sess_sender_ttl: 64,
        mbz3: [0; 3],
    };
    let serialized = packet.to_bytes();
    let deserialized = ReflectedPacketUnauthenticated::from_bytes(&serialized).unwrap();

    // Verify echoed fields
    assert_eq!(deserialized.sess_sender_seq_number, 500);
    assert_eq!(deserialized.sess_sender_timestamp, 600);
    assert_eq!(deserialized.sess_sender_err_estimate, 700);
    assert_eq!(deserialized.ssid, 0x11);
    assert_eq!(deserialized.sess_sender_ttl, 64);

    // RFC 8972 §3 Figure 2: the SSID appears once. The two octets after
    // the Session-Sender Error Estimate are MBZ, and a peer that verifies
    // MBZ (RFC 8762 §4.6) drops the reply if they are not.
    assert_eq!(&serialized[38..40], &[0, 0], "octets 38-39 must stay MBZ");
    assert_eq!(deserialized.mbz2, [0; 2]);
}

#[test]
fn test_buffer_larger_than_needed() {
    // Create a packet and serialize it
    let packet = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 2,
        error_estimate: 3,
        ssid: 0,
        mbz: [0; 28],
    };
    let mut bytes = packet.to_bytes().to_vec();

    // Add extra bytes at the end
    bytes.extend_from_slice(&[0xff; 100]);

    // Should still deserialize correctly (reads only what it needs)
    let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();
    assert_eq!(packet, restored);
}

#[test]
fn test_big_endian_wire_format() {
    // Test that sequence number is serialized in big-endian
    let packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let bytes = packet.to_bytes();

    // Big-endian: most significant byte first
    assert_eq!(bytes[0], 0x12);
    assert_eq!(bytes[1], 0x34);
    assert_eq!(bytes[2], 0x56);
    assert_eq!(bytes[3], 0x78);
}

#[test]
fn test_timestamp_big_endian() {
    let packet = PacketUnauthenticated {
        sequence_number: 0,
        timestamp: 0x0102030405060708,
        error_estimate: 0,
        ssid: 0,
        mbz: [0; 28],
    };
    let bytes = packet.to_bytes();

    // Timestamp starts at offset 4
    assert_eq!(bytes[4], 0x01);
    assert_eq!(bytes[5], 0x02);
    assert_eq!(bytes[6], 0x03);
    assert_eq!(bytes[7], 0x04);
    assert_eq!(bytes[8], 0x05);
    assert_eq!(bytes[9], 0x06);
    assert_eq!(bytes[10], 0x07);
    assert_eq!(bytes[11], 0x08);
}

#[test]
fn test_error_estimate_big_endian() {
    let packet = PacketUnauthenticated {
        sequence_number: 0,
        timestamp: 0,
        error_estimate: 0xABCD,
        ssid: 0,
        mbz: [0; 28],
    };
    let bytes = packet.to_bytes();

    // Error estimate starts at offset 12
    assert_eq!(bytes[12], 0xAB);
    assert_eq!(bytes[13], 0xCD);
}

#[test]
fn test_ssid_at_correct_offset_unauth() {
    // RFC 8972 §3: SSID occupies bytes 14-15 immediately after Error Estimate.
    let packet = PacketUnauthenticated {
        sequence_number: 0,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0x1234,
        mbz: [0; 28],
    };
    let bytes = packet.to_bytes();
    assert_eq!(bytes[14], 0x12);
    assert_eq!(bytes[15], 0x34);
}

#[test]
fn test_ssid_at_correct_offset_auth() {
    // RFC 8972 §3: SSID occupies bytes 26-27 in authenticated test packet.
    let packet = PacketAuthenticated {
        sequence_number: 0,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid: 0xABCD,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    let bytes = packet.to_bytes();
    assert_eq!(bytes[26], 0xAB);
    assert_eq!(bytes[27], 0xCD);
}

#[test]
fn test_mbz_bytes_at_correct_offset() {
    let mbz_pattern = [0x42u8; 28];
    let packet = PacketUnauthenticated {
        sequence_number: 0,
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz: mbz_pattern,
    };
    let bytes = packet.to_bytes();

    // MBZ starts at offset 16 (after 14-byte header + 2-byte SSID)
    for i in 0..28 {
        assert_eq!(bytes[16 + i], 0x42);
    }
}

#[test]
fn test_hmac_at_correct_offset_auth() {
    let hmac_pattern = [0xAB; 16];
    let packet = PacketAuthenticated {
        sequence_number: 0,
        mbz0: [0; 12],
        timestamp: 0,
        error_estimate: 0,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: hmac_pattern,
    };
    let bytes = packet.to_bytes();

    // HMAC starts at offset 96 (4+12+8+2+2+30+32+6)
    for i in 0..16 {
        assert_eq!(bytes[96 + i], 0xAB);
    }
}

#[test]
fn test_sequence_number_boundary_values() {
    for seq in [0u32, 1, u32::MAX / 2, u32::MAX - 1, u32::MAX] {
        let packet = PacketUnauthenticated {
            sequence_number: seq,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            mbz: [0; 28],
        };

        let bytes = packet.to_bytes();
        let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();

        assert_eq!(
            restored.sequence_number, seq,
            "Sequence number {} should roundtrip correctly",
            seq
        );
    }
}

#[test]
fn test_timestamp_boundary_values() {
    for ts in [0u64, 1, u64::MAX / 2, u64::MAX - 1, u64::MAX] {
        let packet = PacketUnauthenticated {
            sequence_number: 0,
            timestamp: ts,
            error_estimate: 0,
            ssid: 0,
            mbz: [0; 28],
        };

        let bytes = packet.to_bytes();
        let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();

        assert_eq!(
            restored.timestamp, ts,
            "Timestamp {} should roundtrip correctly",
            ts
        );
    }
}

#[test]
fn test_error_estimate_boundary_values() {
    for ee in [0u16, 1, u16::MAX / 2, u16::MAX - 1, u16::MAX] {
        let packet = PacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0,
            error_estimate: ee,
            ssid: 0,
            mbz: [0; 28],
        };

        let bytes = packet.to_bytes();
        let restored = PacketUnauthenticated::from_bytes(&bytes).unwrap();

        assert_eq!(
            restored.error_estimate, ee,
            "Error estimate {} should roundtrip correctly",
            ee
        );
    }
}

#[test]
fn test_ttl_boundary_values() {
    for ttl in [0u8, 1, 64, 128, 255] {
        let packet = ReflectedPacketUnauthenticated {
            sequence_number: 0,
            timestamp: 0,
            error_estimate: 0,
            ssid: 0,
            receive_timestamp: 0,
            sess_sender_seq_number: 0,
            sess_sender_timestamp: 0,
            sess_sender_err_estimate: 0,
            mbz2: [0; 2],
            sess_sender_ttl: ttl,
            mbz3: [0; 3],
        };

        let bytes = packet.to_bytes();
        let restored = ReflectedPacketUnauthenticated::from_bytes(&bytes).unwrap();

        assert_eq!(
            restored.sess_sender_ttl, ttl,
            "TTL {} should roundtrip correctly",
            ttl
        );
    }
}

#[test]
fn test_from_bytes_lenient_unauth_full_packet() {
    let packet = PacketUnauthenticated {
        sequence_number: 0x12345678,
        timestamp: 0xDEADBEEFCAFEBABE,
        error_estimate: 0xABCD,
        ssid: 0x9876,
        mbz: [0x42; 28],
    };
    let bytes = packet.to_bytes();

    let restored = PacketUnauthenticated::from_bytes_lenient(&bytes);
    assert_eq!(packet, restored);
}

#[test]
fn test_from_bytes_lenient_unauth_short_packet() {
    // Only first 20 bytes provided (seq + timestamp + error_estimate + ssid + 4 bytes mbz)
    let mut short_buf = [0u8; 20];
    short_buf[0..4].copy_from_slice(&0x12345678u32.to_be_bytes()); // seq
    short_buf[4..12].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_be_bytes()); // timestamp
    short_buf[12..14].copy_from_slice(&0xABCDu16.to_be_bytes()); // error_estimate
    short_buf[14..16].copy_from_slice(&0x1122u16.to_be_bytes()); // ssid
    short_buf[16..20].copy_from_slice(&[0x42; 4]); // partial mbz

    let restored = PacketUnauthenticated::from_bytes_lenient(&short_buf);

    assert_eq!(restored.sequence_number, 0x12345678);
    assert_eq!(restored.timestamp, 0xDEADBEEFCAFEBABE);
    assert_eq!(restored.error_estimate, 0xABCD);
    assert_eq!(restored.ssid, 0x1122);
    // First 4 bytes should be 0x42, rest zero-filled
    assert_eq!(restored.mbz[0..4], [0x42; 4]);
    assert_eq!(restored.mbz[4..28], [0; 24]);
}

#[test]
fn test_from_bytes_lenient_unauth_empty_packet() {
    let empty: [u8; 0] = [];
    let restored = PacketUnauthenticated::from_bytes_lenient(&empty);

    assert_eq!(restored.sequence_number, 0);
    assert_eq!(restored.timestamp, 0);
    assert_eq!(restored.error_estimate, 0);
    assert_eq!(restored.ssid, 0);
    assert_eq!(restored.mbz, [0; 28]);
}

#[test]
fn test_from_bytes_lenient_auth_full_packet() {
    let packet = PacketAuthenticated {
        sequence_number: 0x12345678,
        mbz0: [0x11; 12],
        timestamp: 0xDEADBEEFCAFEBABE,
        error_estimate: 0xABCD,
        ssid: 0x9988,
        mbz1a: [0x22; 30],
        mbz1b: [0x33; 32],
        mbz1c: [0x44; 6],
        hmac: [0x55; 16],
    };
    let bytes = packet.to_bytes();

    let restored = PacketAuthenticated::from_bytes_lenient(&bytes);
    assert_eq!(packet, restored);
}

#[test]
fn test_from_bytes_lenient_auth_short_packet() {
    // Only 30 bytes provided: seq(4) + mbz0(12) + timestamp(8) + error_estimate(2) + ssid(2) + 2 bytes mbz1a
    let mut short_buf = [0u8; 30];
    short_buf[0..4].copy_from_slice(&0x12345678u32.to_be_bytes()); // seq
    short_buf[4..16].copy_from_slice(&[0x11; 12]); // mbz0
    short_buf[16..24].copy_from_slice(&0xDEADBEEFCAFEBABEu64.to_be_bytes()); // timestamp
    short_buf[24..26].copy_from_slice(&0xABCDu16.to_be_bytes()); // error_estimate
    short_buf[26..28].copy_from_slice(&0x4321u16.to_be_bytes()); // ssid
    short_buf[28..30].copy_from_slice(&[0x22; 2]); // partial mbz1a

    let restored = PacketAuthenticated::from_bytes_lenient(&short_buf);

    assert_eq!(restored.sequence_number, 0x12345678);
    assert_eq!(restored.mbz0, [0x11; 12]);
    assert_eq!(restored.timestamp, 0xDEADBEEFCAFEBABE);
    assert_eq!(restored.error_estimate, 0xABCD);
    assert_eq!(restored.ssid, 0x4321);
    // First 2 bytes of mbz1a should be 0x22, rest zero-filled
    assert_eq!(restored.mbz1a[0..2], [0x22; 2]);
    assert_eq!(restored.mbz1a[2..30], [0; 28]);
    assert_eq!(restored.mbz1b, [0; 32]);
    assert_eq!(restored.mbz1c, [0; 6]);
    assert_eq!(restored.hmac, [0; 16]);
}

// Extended packet tests

#[test]
fn test_extended_packet_unauth_new() {
    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };
    let ext = ExtendedPacketUnauthenticated::new(base);

    assert_eq!(ext.base.sequence_number, 1);
    assert!(!ext.has_tlvs());
}

#[test]
fn test_extended_packet_unauth_with_tlvs() {
    use crate::tlv::{RawTlv, TlvType};

    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0, 0, 0, 0]))
        .unwrap();

    let ext = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs);

    assert!(ext.has_tlvs());
    assert_eq!(ext.tlvs.len(), 1);
}

#[test]
fn test_extended_packet_unauth_to_bytes() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let base = PacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz: [0; 28],
    };

    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0xAA; 4]))
        .unwrap();

    let ext = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs);
    let bytes = ext.to_bytes();

    // 44 base + 4 header + 4 value = 52
    assert_eq!(bytes.len(), 44 + TLV_HEADER_SIZE + 4);
    assert_eq!(ext.wire_size(), bytes.len());
}

#[test]
fn test_extended_packet_unauth_from_bytes() {
    use crate::tlv::{RawTlv, TlvType};

    let base = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 12345,
        error_estimate: 100,
        ssid: 0,
        mbz: [0; 28],
    };

    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![1, 2, 3, 4]))
        .unwrap();

    let original = ExtendedPacketUnauthenticated::with_tlvs(base, tlvs);
    let bytes = original.to_bytes();

    let parsed = ExtendedPacketUnauthenticated::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.base.sequence_number, 42);
    assert_eq!(parsed.tlvs.len(), 1);
}

#[test]
fn test_extended_packet_unauth_from_bytes_no_tlvs() {
    let base = PacketUnauthenticated {
        sequence_number: 42,
        timestamp: 12345,
        error_estimate: 100,
        ssid: 0,
        mbz: [0; 28],
    };
    let bytes = base.to_bytes();

    let parsed = ExtendedPacketUnauthenticated::from_bytes(&bytes).unwrap();

    assert_eq!(parsed.base.sequence_number, 42);
    assert!(!parsed.has_tlvs());
}

#[test]
fn test_extended_packet_auth_new() {
    let base = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0; 16],
    };
    let ext = ExtendedPacketAuthenticated::new(base);

    assert_eq!(ext.base.sequence_number, 1);
    assert!(!ext.has_tlvs());
}

#[test]
fn test_extended_packet_auth_to_bytes() {
    use crate::tlv::{RawTlv, TlvType, TLV_HEADER_SIZE};

    let base = PacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1a: [0; 30],
        mbz1b: [0; 32],
        mbz1c: [0; 6],
        hmac: [0xAB; 16],
    };

    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 8]))
        .unwrap();

    let ext = ExtendedPacketAuthenticated::with_tlvs(base, tlvs);
    let bytes = ext.to_bytes();

    // 112 base + 4 header + 8 value = 124
    assert_eq!(bytes.len(), 112 + TLV_HEADER_SIZE + 8);
}

#[test]
fn test_extended_reflected_packet_unauth() {
    use crate::tlv::{RawTlv, TlvType};

    let base = ReflectedPacketUnauthenticated {
        sequence_number: 1,
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        receive_timestamp: 50,
        sess_sender_seq_number: 1,
        sess_sender_timestamp: 30,
        sess_sender_err_estimate: 5,
        mbz2: [0; 2],
        sess_sender_ttl: 64,
        mbz3: [0; 3],
    };

    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
        .unwrap();

    let ext = ExtendedReflectedPacketUnauthenticated::with_tlvs(base, tlvs);
    let bytes = ext.to_bytes();

    assert_eq!(bytes.len(), ext.wire_size());
}

#[test]
fn test_extended_reflected_packet_auth() {
    use crate::tlv::{RawTlv, TlvType};

    let base = ReflectedPacketAuthenticated {
        sequence_number: 1,
        mbz0: [0; 12],
        timestamp: 100,
        error_estimate: 10,
        ssid: 0,
        mbz1: [0; 4],
        receive_timestamp: 50,
        mbz2: [0; 8],
        sess_sender_seq_number: 1,
        mbz3: [0; 12],
        sess_sender_timestamp: 30,
        sess_sender_err_estimate: 5,
        mbz4: [0; 6],
        sess_sender_ttl: 64,
        mbz5: [0; 15],
        hmac: [0; 16],
    };

    let mut tlvs = TlvList::new();
    tlvs.push(RawTlv::new(TlvType::ExtraPadding, vec![0; 4]))
        .unwrap();
    tlvs.push(RawTlv::new(TlvType::Hmac, vec![0xFF; 16]))
        .unwrap();

    let ext = ExtendedReflectedPacketAuthenticated::with_tlvs(base, tlvs);
    let bytes = ext.to_bytes();

    assert_eq!(bytes.len(), ext.wire_size());
}
