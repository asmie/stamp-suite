use super::*;
use proptest::prelude::*;

const VECTORS: &str = include_str!("../../../tests/fixtures/residual-ber/values.json");

#[test]
fn independent_successor_vectors_preserve_counters_patterns_and_opaque_sub_tlvs() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let pattern_type = vectors["pattern_type"].as_u64().unwrap() as u8;
    for vector in vectors["valid"].as_array().unwrap() {
        let bytes = hex::decode(vector["value_hex"].as_str().unwrap()).unwrap();
        let value = ResidualBerValue::decode_value(&bytes).unwrap();
        assert_eq!(u64::from(value.count), vector["count"].as_u64().unwrap());
        assert_eq!(
            u64::from(value.max_burst),
            vector["max_burst"].as_u64().unwrap()
        );
        let pattern = value
            .explicit_pattern(pattern_type)
            .unwrap()
            .map(hex::encode);
        assert_eq!(
            pattern.as_deref(),
            vector["pattern_hex"].as_str(),
            "{vector}"
        );
        let mut encoded = Vec::new();
        value.encode_value(&mut encoded).unwrap();
        assert_eq!(encoded, bytes, "{vector}");
    }
}

#[test]
fn independent_negative_vectors_distinguish_framing_and_pattern_errors() {
    let vectors: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let pattern_type = vectors["pattern_type"].as_u64().unwrap() as u8;
    for vector in vectors["invalid"].as_array().unwrap() {
        let bytes = hex::decode(vector["value_hex"].as_str().unwrap()).unwrap();
        let decoded = ResidualBerValue::decode_value(&bytes);
        let error = match decoded {
            Err(error) => error,
            Ok(value) => value.explicit_pattern(pattern_type).unwrap_err(),
        };
        match error {
            ResidualBerError::ShortValue { length } => {
                assert_eq!(vector["error"], "short_value");
                assert_eq!(length, bytes.len());
            }
            ResidualBerError::ShortSubTlvHeader { offset } => {
                assert_eq!(vector["error"], "short_header");
                assert_eq!(offset as u64, vector["offset"].as_u64().unwrap());
            }
            ResidualBerError::TruncatedSubTlv { offset, .. } => {
                assert_eq!(vector["error"], "truncated_sub_tlv");
                assert_eq!(offset as u64, vector["offset"].as_u64().unwrap());
            }
            ResidualBerError::ShortPattern { index, .. } => {
                assert_eq!(vector["error"], "short_pattern");
                assert_eq!(index as u64, vector["index"].as_u64().unwrap());
            }
            ResidualBerError::DuplicatePattern => assert_eq!(vector["error"], "duplicate_pattern"),
            other => panic!("unexpected error {other:?} for {vector}"),
        }
    }
}

#[test]
fn requests_zero_counters_and_separate_pattern_absence_from_empty() {
    let default = ResidualBerValue::request(240, None).unwrap();
    assert_eq!(default, ResidualBerValue::default());
    assert_eq!(default.explicit_pattern(240).unwrap(), None);
    assert_eq!(RESIDUAL_BER_DEFAULT_PATTERN, [0xff, 0, 0xff, 0]);
    for size in 0..RESIDUAL_BER_MIN_PATTERN_SIZE {
        assert!(matches!(
            ResidualBerValue::request(240, Some(&vec![0xaa; size])),
            Err(ResidualBerError::ShortPattern { .. })
        ));
    }
    // Revision 01 requires at least four bytes, not a multiple of four.
    let explicit = ResidualBerValue::request(240, Some(&[1, 2, 3, 4, 5])).unwrap();
    assert_eq!(explicit.count, 0);
    assert_eq!(explicit.max_burst, 0);
    assert_eq!(explicit.sub_tlvs[0].flags, TlvFlags::U);
    assert_eq!(
        explicit.explicit_pattern(240).unwrap(),
        Some([1, 2, 3, 4, 5].as_slice())
    );
    assert_eq!(explicit.explicit_pattern(241).unwrap(), None);
}

#[test]
fn codec_does_not_acknowledge_an_unregistered_endpoint_type() {
    use crate::tlv::{TlvList, TlvType};
    // This is a test-local experimental outer type, not a proposed allocation.
    let wire = [TlvFlags::U, 250, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut list = TlvList::parse(&wire).unwrap();
    assert!(list.apply_reflector_flags(None, &[0; 4], &wire));
    let raw = &list.non_hmac_tlvs()[0];
    assert_eq!(raw.tlv_type, TlvType::Unknown(250));
    assert!(raw.is_unrecognized());
    assert_eq!(raw.value, [0; 8]);
}

#[test]
fn draft_listed_peer_captures_are_older_than_the_successor_layout() {
    let captures: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/residual-ber/teaparty-592558a.json"
    ))
    .unwrap();
    let records = captures["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    for record in records {
        let packet = hex::decode(record["packet_hex"].as_str().unwrap()).unwrap();
        let list = crate::tlv::TlvList::parse(&packet[44..]).unwrap();
        let fields: Vec<_> = list
            .iter()
            .map(|tlv| (tlv.tlv_type.to_byte(), tlv.value.as_slice()))
            .collect();
        assert_eq!(
            fields.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            [1, 9, 10]
        );
        assert_eq!(fields[0].1, RESIDUAL_BER_DEFAULT_PATTERN.repeat(16));
        assert_eq!(fields[1].1, [0; 4]);
        assert_eq!(fields[2].1, RESIDUAL_BER_DEFAULT_PATTERN);
        assert!(matches!(
            ResidualBerValue::decode_value(fields[1].1),
            Err(ResidualBerError::ShortValue { length: 4 })
        ));
        assert_eq!(
            list.iter().nth(1).unwrap().tlv_type,
            crate::tlv::TlvType::DestinationNodeAddress
        );
        assert_eq!(
            list.iter().nth(2).unwrap().tlv_type,
            crate::tlv::TlvType::ReturnPath
        );
    }
}

#[test]
fn aggregate_length_limit_is_checked_before_writing() {
    let maximum_pattern = usize::from(u16::MAX) - RESIDUAL_BER_FIXED_VALUE_SIZE - TLV_HEADER_SIZE;
    let mut value = ResidualBerValue::request(240, Some(&vec![0x55; maximum_pattern])).unwrap();
    let mut encoded = Vec::new();
    value.encode_value(&mut encoded).unwrap();
    assert_eq!(encoded.len(), usize::from(u16::MAX));
    assert_eq!(ResidualBerValue::decode_value(&encoded).unwrap(), value);
    assert_eq!(
        ResidualBerValue::request(240, Some(&vec![0; maximum_pattern + 1])),
        Err(ResidualBerError::ValueTooLong)
    );
    value.sub_tlvs[0].value.push(0);
    let mut out = vec![1, 2, 3];
    assert_eq!(
        value.encode_value(&mut out),
        Err(ResidualBerError::ValueTooLong)
    );
    assert_eq!(out, [1, 2, 3]);
    value.sub_tlvs[0].value = vec![0; usize::from(u16::MAX) + 1];
    assert_eq!(
        value.encode_value(&mut out),
        Err(ResidualBerError::ValueTooLong)
    );
    assert_eq!(out, [1, 2, 3]);
    assert_eq!(
        ResidualBerValue::decode_value(&value.sub_tlvs[0].value),
        Err(ResidualBerError::ValueTooLong)
    );
    // Each child fits individually, but the parent's aggregate does not.
    value.sub_tlvs = (0..2)
        .map(|kind| ResidualBerSubTlv {
            flags: 0,
            kind,
            value: vec![0; 32764],
        })
        .collect();
    assert_eq!(
        value.encode_value(&mut out),
        Err(ResidualBerError::ValueTooLong)
    );
    assert_eq!(out, [1, 2, 3]);
}

proptest! {
    #[test]
    fn arbitrary_input_is_bounded_and_decodes_losslessly(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(value) = ResidualBerValue::decode_value(&bytes) {
            let _ = value.explicit_pattern(240);
            let mut out = Vec::new();
            value.encode_value(&mut out).unwrap();
            prop_assert_eq!(out, bytes);
        }
    }

    #[test]
    fn generated_nested_values_round_trip(
        count in any::<u32>(), burst in any::<u32>(),
        subs in prop::collection::vec((any::<u8>(), any::<u8>(), prop::collection::vec(any::<u8>(), 0..128)), 0..16)
    ) {
        let value = ResidualBerValue {
            count, max_burst: burst,
            sub_tlvs: subs.into_iter().map(|(flags, kind, value)| ResidualBerSubTlv { flags, kind, value }).collect(),
        };
        let mut out = Vec::new();
        value.encode_value(&mut out).unwrap();
        prop_assert_eq!(ResidualBerValue::decode_value(&out).unwrap(), value);
    }
}
