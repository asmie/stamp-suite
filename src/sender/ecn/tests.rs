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
                                assert_direction_totals(&summary);
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

fn assert_direction_totals(summary: &EcnSummary) {
    for direction in [&summary.forward, &summary.reverse] {
        assert_eq!(direction.comparable + direction.unknown, summary.replies);
        assert_eq!(
            direction.transitions.iter().flatten().sum::<u64>(),
            direction.comparable
        );
        assert_eq!(
            direction.unchanged + direction.bleaching + direction.ce_marked + direction.remarked,
            direction.comparable
        );
        let reasons = serde_json::to_value(&direction.unknown_reasons).unwrap();
        assert_eq!(
            reasons
                .as_object()
                .unwrap()
                .values()
                .map(|v| v.as_u64().unwrap())
                .sum::<u64>(),
            direction.unknown
        );
    }
    assert_eq!(summary.reverse_comparable, summary.reverse.comparable);
    assert_eq!(summary.reverse_unknown, summary.reverse.unknown);
}

#[test]
fn ecn_directional_classification_covers_every_codepoint_pair() {
    // Golden table in [baseline][observation] order. CE->CE is unchanged;
    // Not-ECT->CE is remarking, not evidence of ECT congestion marking.
    let expected = [
        ["unchanged", "remarked", "remarked", "remarked"],
        ["bleaching", "unchanged", "remarked", "ce_marked"],
        ["bleaching", "remarked", "unchanged", "ce_marked"],
        ["bleaching", "remarked", "remarked", "unchanged"],
    ];
    for baseline in 0..4u8 {
        for observed in 0..4u8 {
            let cos = decode(
                &[0, 4, 0, 4, 0, observed << 2, (baseline << 6) | 0x30, 0],
                None,
            );
            let mut summary = EcnSummary::new(baseline, Some(baseline));
            summary.record(cos, Some(observed));
            for direction in [&summary.forward, &summary.reverse] {
                let json = serde_json::to_value(direction).unwrap();
                assert_eq!(
                    json[expected[usize::from(baseline)][usize::from(observed)]],
                    1
                );
                assert_eq!(
                    direction.transitions[usize::from(baseline)][usize::from(observed)],
                    1
                );
                assert_eq!(direction.ce_observed, u64::from(observed == 3));
            }
            assert_direction_totals(&summary);
        }
    }
}

#[test]
fn ecn_unknown_reasons_are_exclusive_and_do_not_fabricate_transitions() {
    // Overlapping failures pin priority: C, RPE, request mismatch, then IP.
    for (flags, ec1, rpe, ip, reason) in [
        (0x10, 1, 0, None, "conformant_reflected"),
        (0, 1, 3, None, "request_mismatch"),
        (0, 1, 0, None, "legacy_or_unconfirmed"),
        (0, 2, 1, None, "reserved_rpe"),
        (0, 2, 2, Some(0), "reflector_unable"),
        (0, 2, 3, None, "reply_ip_unavailable"),
        (0, 2, 3, Some(4), "reply_ip_unavailable"),
    ] {
        let cos = decode(&[flags, 4, 0, 4, 0, 0, (ec1 << 6) | (rpe << 4), 0], None);
        let mut summary = EcnSummary::new(2, Some(2));
        summary.record(cos, ip);
        assert_eq!(
            summary.forward.bleaching, 1,
            "reverse flags do not invalidate ingress EC2"
        );
        assert_eq!(summary.reverse.comparable, 0);
        assert_eq!(
            serde_json::to_value(&summary.reverse.unknown_reasons).unwrap()[reason],
            1
        );
        assert_direction_totals(&summary);
    }
    let mut summary = EcnSummary::new(2, None);
    summary.record(None, Some(3));
    assert_eq!(summary.forward.unknown_reasons.cos_unavailable, 1);
    assert_eq!(summary.reverse.unknown_reasons.cos_unavailable, 1);
    summary.record(decode(&[0, 4, 0, 4, 0, 0, 0xb0, 0], None), Some(3));
    assert_eq!(summary.forward.unknown_reasons.local_marking_unavailable, 1);
    assert_eq!(summary.forward.comparable, 0);
    assert_eq!(summary.reverse.ce_marked, 1);
    assert_direction_totals(&summary);
}

#[test]
fn ecn_forward_baseline_is_local_marking_and_reverse_pairs_stay_per_reply() {
    let cos = decode(&[0, 4, 0, 4, 0, 4, 0x70, 0], None);
    let mut summary = EcnSummary::new(1, Some(2));
    summary.record(cos, Some(1));
    assert_eq!(summary.forward.transitions[2][1], 1);
    assert_eq!(summary.forward.remarked, 1);
    assert_eq!(summary.reverse.unchanged, 1);
    assert_direction_totals(&summary);

    // Same marginal CoS/IP counts; only the eligible pair changes.
    let applied = decode(&[0, 4, 0, 4, 0, 8, 0xb0, 0], None);
    let refused = decode(&[0, 4, 0, 4, 0, 8, 0xa0, 0], None);
    let mut first = EcnSummary::new(2, Some(2));
    first.record(applied, Some(0));
    first.record(refused, Some(3));
    let mut second = EcnSummary::new(2, Some(2));
    second.record(refused, Some(0)); // reverse order also must not affect pairing
    second.record(applied, Some(3));
    assert_eq!(first.reply_ip_ecn, second.reply_ip_ecn);
    assert_eq!(first.rpe, second.rpe);
    assert_eq!(first.received_ec2, second.received_ec2);
    assert_eq!(first.reverse.bleaching, 1);
    assert_eq!(first.reverse.ce_marked, 0);
    assert_eq!(second.reverse.bleaching, 0);
    assert_eq!(second.reverse.ce_marked, 1);
    for summary in [&first, &second] {
        assert_eq!(summary.reverse.unknown_reasons.reflector_unable, 1);
        assert_direction_totals(summary);
    }
}
