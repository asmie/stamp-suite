//! Destination policy retained across reply routing and marking retries.
use crate::{
    cos_policy::{DscpSelection, DscpSet},
    tlv::{TlvFlags, TlvList, TlvSpan, TlvType, COS_TLV_VALUE_SIZE},
};

/// Immutable CoS policy snapshot for this request's two possible destinations.
#[derive(Debug)]
pub struct CosReplyPolicy {
    requested: u8,
    ecn: u8,
    ecn_permitted: bool,
    primary: DscpSet,
    source: DscpSet,
    // Usually empty. Preserve original peer C separately from a locally
    // generated third-DSCP C so route retries can remove only our own flag.
    original_c: Vec<bool>,
}

impl CosReplyPolicy {
    pub(super) fn new(
        requested: u8,
        primary: DscpSet,
        source: DscpSet,
        ecn: u8,
        ecn_permitted: bool,
        tlvs: &TlvList,
    ) -> Self {
        let cos = || {
            tlvs.non_hmac_tlvs().iter().filter(|t| {
                t.tlv_type == TlvType::ClassOfService
                    && t.is_processable()
                    && t.value.len() == COS_TLV_VALUE_SIZE
            })
        };
        let original_c = if cos().any(|t| t.flags.conformant_reflected) {
            cos().map(|t| t.flags.conformant_reflected).collect()
        } else {
            Vec::new()
        };
        Self {
            requested,
            ecn,
            ecn_permitted,
            primary,
            source,
            original_c,
        }
    }

    pub(super) fn allowed(&self, to_source: bool) -> DscpSet {
        if to_source {
            self.source
        } else {
            self.primary
        }
    }

    pub(super) fn select(
        &self,
        to_source: bool,
        received: u8,
        marking_failed: bool,
    ) -> Option<DscpSelection> {
        let allowed = self.allowed(to_source);
        // Prefer the received marking on a capability retry only if admitted.
        // Otherwise retain an admitted DSCP1, or the policy's third value.
        let requested = if marking_failed && allowed.contains(received) {
            None
        } else {
            Some(self.requested)
        };
        allowed.select(requested, received)
    }

    pub(super) fn ecn(&self, marking_failed: bool, unavailable: bool) -> (u8, u8) {
        if unavailable {
            (0, 1)
        } else if marking_failed || !self.ecn_permitted {
            (0, 2)
        } else {
            (self.ecn, 3)
        }
    }

    pub(super) fn apply(&self, data: &mut [u8], base: usize, selection: DscpSelection, rpe: u8) {
        let mut pos = base;
        let mut index = 0;
        while let Some(tlv) = TlvSpan::at(data, pos) {
            if tlv.flags.malformed {
                break;
            }
            if tlv.tlv_type == TlvType::ClassOfService
                && tlv.len == COS_TLV_VALUE_SIZE
                && tlv.flags.processed()
            {
                let value = tlv.value_start();
                data[value + 1] = (data[value + 1] & 0xfc) | u8::from(selection.rejected);
                data[value + 2] = (data[value + 2] & 0xcf) | (rpe << 4);
                let c =
                    selection.third_value || self.original_c.get(index).copied().unwrap_or(false);
                data[tlv.start] =
                    (data[tlv.start] & !TlvFlags::C) | if c { TlvFlags::C } else { 0 };
                index += 1;
            }
            pos = tlv.end();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dscp_edits_preserve_opaque_values_and_independent_c_per_tlv() {
        for opaque in [TlvFlags::U, TlvFlags::I, TlvFlags::M] {
            let mut data = vec![opaque, 4, 0, 4, 184, 0xac, 0xb0, 0];
            data.extend([TlvFlags::C, 4, 0, 4, 184, 0xac, 0xb0, 0]);
            data.extend([0, 4, 0, 4, 184, 0xac, 0xb0, 0]);
            let original = data.clone();
            let list = TlvList::parse(&data).unwrap();
            let policy = CosReplyPolicy::new(46, DscpSet::all(), DscpSet::all(), 2, true, &list);
            let third = DscpSet::parse("34").unwrap().select(Some(46), 10).unwrap();
            policy.apply(&mut data, 0, third, 2);
            assert_eq!(&data[..8], &original[..8]);
            if opaque == TlvFlags::M {
                assert_eq!(data, original);
                continue;
            }
            assert_eq!(data[8], TlvFlags::C);
            assert_eq!(data[16], TlvFlags::C);
            let requested = DscpSet::all().select(Some(46), 10).unwrap();
            policy.apply(&mut data, 0, requested, 3);
            assert_eq!(data, original, "remove only locally generated C on retry");
        }
    }
}
