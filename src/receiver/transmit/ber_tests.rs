use super::*;
use crate::{
    crypto::HmacKey,
    tlv::{
        BerBurstTlv, BerCountTlv, BerPatternTlv, ExtraPaddingTlv, TlvFlags, TlvList, TlvType,
        TypedTlv,
    },
};

#[test]
fn ber_route_budget_keeps_whole_patterns_and_resigns_c_metadata() {
    let key = HmacKey::new(vec![0xab; 16]).unwrap();
    for base in [44, 112] {
        let mut list = TlvList::new();
        for mut t in [
            BerPatternTlv::new(vec![1, 2, 3]).to_raw(),
            BerCountTlv::new(6).to_raw(),
            BerBurstTlv::new(3).to_raw(),
            ExtraPaddingTlv {
                padding: [1, 2, 3].repeat(534),
            }
            .to_raw(),
        ] {
            t.flags = TlvFlags::default();
            list.push(t).unwrap();
        }
        list.set_hmac_response(&key, &[0; 4]);
        let mut data = vec![0; base];
        data.extend_from_slice(&list.to_bytes());
        assert!(has_ber(&data, base));
        let mut invalid = data.clone();
        invalid[base] |= 0x20;
        assert!(
            !has_ber(&invalid, base),
            "I-flagged failure echoes stay opaque"
        );

        assert!(!fit_reply(&mut data, base, 1500, false).unwrap());
        assert!(data.len() <= 1500);
        sign_tlvs(&mut data, base, &key);
        let list = TlvList::parse(&data[base..]).unwrap();
        assert!(list.verify_hmac(&key, &data[..4], &data[base..]).is_ok());
        for t in list.non_hmac_tlvs() {
            if crate::ber::is_ber(t.tlv_type) {
                assert!(t.flags.conformant_reflected);
            }
            if t.tlv_type == TlvType::ExtraPadding {
                assert!(!t.value.is_empty());
                assert_eq!(t.value, [1, 2, 3].repeat(t.value.len() / 3));
            }
        }
        assert!(fit_reply(&mut data, base, base + 10, false).is_err());
    }
}
