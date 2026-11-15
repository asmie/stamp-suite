use super::*;
use crate::sender::validate::validate_reflected_tlvs;
use crate::{crypto::HmacKey, tlv::TlvList};

fn decode(bytes: &[u8], key: Option<&HmacKey>) -> Option<CosObservation> {
    let (tlvs, _) = TlvList::parse_lenient(bytes);
    let mut data = vec![0; 44];
    data.extend_from_slice(bytes);
    validate_reflected_tlvs(&tlvs, &data, 44, key, None, None, &mut None, false, false)
        .unwrap()
        .cos
}

#[test]
fn ecn_retains_wire_fields_and_limits_reverse_comparison() {
    // Independent wire bytes: all EC1/EC2/RPE/RPD/C combinations, all
    // requested and received codepoints, and missing/invalid IP metadata.
    for requested in 0..4 {
        for ec1 in 0..4 {
            for ec2 in 0..4 {
                for rpe in 0..4 {
                    for rpd in 0..4 {
                        for c in [false, true] {
                            let wire = [
                                if c { 0x10 } else { 0 },
                                4,
                                0,
                                4,
                                0xb9,
                                0x40 | (ec2 << 2) | rpd,
                                (ec1 << 6) | (rpe << 4),
                                0,
                            ];
                            let cos = decode(&wire, None).unwrap();
                            assert_eq!(cos.value.dscp1, 46);
                            assert_eq!(cos.value.dscp2, 20);
                            for reply in [None, Some(0), Some(1), Some(2), Some(3), Some(4)] {
                                let mut summary = EcnSummary::new(requested, Some(requested));
                                summary.record(Some(cos), reply);
                                assert_eq!(summary.received_ec2[usize::from(ec2)], 1);
                                assert_eq!(summary.echoed_ec1[usize::from(ec1)], 1);
                                assert_eq!(summary.rpe[usize::from(rpe)], 1);
                                assert_eq!(summary.rpd[usize::from(rpd)], 1);
                                assert_eq!(summary.conformant_reflected, u64::from(c));
                                let comparable = rpe == 3
                                    && !c
                                    && ec1 == requested
                                    && matches!(reply, Some(0..=3));
                                assert_eq!(summary.reverse_comparable, u64::from(comparable));
                                assert_eq!(summary.reverse_unknown, u64::from(!comparable));
                                assert_eq!(summary.usable_cos, 1);
                                assert_eq!(summary.unavailable_cos, 0);
                                assert_eq!(
                                    summary.reply_ip_ecn.iter().sum::<u64>()
                                        + summary.unavailable_reply_ip_ecn,
                                    1
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn ecn_observations_require_unambiguous_reachable_integrity_checked_cos() {
    let good = [0, 4, 0, 4, 0, 12, 0xb0, 0];
    assert!(decode(&good, None).is_some());
    for flag in [0x80, 0x40, 0x20] {
        let mut bad = good;
        bad[0] = flag;
        assert!(decode(&bad, None).is_none());
    }
    for prefix in [
        vec![0x40, 0xfe, 0, 0],
        vec![0x20, 0xfe, 0, 0],
        good.to_vec(),
    ] {
        let mut bytes = prefix;
        bytes.extend(good);
        assert!(decode(&bytes, None).is_none());
    }
    let mut duplicate = good.to_vec();
    duplicate.extend([0x80, 4, 0, 4, 0, 0, 0, 0]);
    assert!(decode(&duplicate, None).is_none());
    assert!(decode(&[0, 4, 0, 3, 0, 0, 0], None).is_none());
    assert!(decode(&[], None).is_none());
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    assert!(
        decode(&good, Some(&key)).is_none(),
        "missing optional HMAC is not measurement evidence"
    );
    let mut signed = TlvList::parse(&good).unwrap();
    signed.set_hmac(&key, &[0; 4]);
    let mut bytes = signed.to_bytes();
    bytes[8] = 0; // reflected HMAC has U cleared
    assert!(decode(&bytes, Some(&key)).is_some());
    assert!(decode(&bytes, None).is_none(), "unverified signature");
    *bytes.last_mut().unwrap() ^= 1;
    assert!(decode(&bytes, Some(&key)).is_none(), "invalid signature");
}

#[test]
fn missing_cos_does_not_hide_observed_ip_ce_or_claim_path_support() {
    let mut summary = EcnSummary::new(2, None);
    summary.record(None, Some(3));
    summary.record(None, None);
    assert_eq!(summary.replies, 2);
    assert_eq!(summary.unavailable_cos, 2);
    assert_eq!(summary.reply_ip_ecn, [0, 0, 0, 1]);
    assert_eq!(summary.unavailable_reply_ip_ecn, 1);
    assert_eq!(summary.reverse_unknown, 2);
    assert_eq!(summary.reverse_comparable, 0);
    assert_eq!(summary.configured_egress_ecn, None);
}
