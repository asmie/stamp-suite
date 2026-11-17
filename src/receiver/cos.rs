//! Destination policy retained across reply routing and marking retries.
use crate::{
    cos_policy::{DscpSelection, DscpSet},
    tlv::{TlvFlags, TlvSpan, TlvType, COS_TLV_VALUE_SIZE},
};

/// Immutable CoS policy snapshot for this request's two possible destinations.
#[derive(Debug)]
pub struct CosReplyPolicy {
    requested: u8,
    ecn: u8,
    ecn_permitted: bool,
    primary: DscpSet,
    source: DscpSet,
}

impl CosReplyPolicy {
    pub(super) fn new(
        requested: u8,
        primary: DscpSet,
        source: DscpSet,
        ecn: u8,
        ecn_permitted: bool,
    ) -> Self {
        Self {
            requested,
            ecn,
            ecn_permitted,
            primary,
            source,
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

    /// Writes RPD, RPE and C for the selected DSCP into every processed CoS
    /// TLV. Incoming-flag normalization cleared any C the peer sent, so C
    /// here means only a local third-value fallback, and a route retry that
    /// selects the requested DSCP again clears it.
    pub(super) fn apply(&self, data: &mut [u8], base: usize, selection: DscpSelection, rpe: u8) {
        let mut pos = base;
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
                let c = if selection.third_value {
                    TlvFlags::C
                } else {
                    0
                };
                data[tlv.start] = (data[tlv.start] & !TlvFlags::C) | c;
            }
            pos = tlv.end();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dscp_edits_skip_opaque_values_and_set_c_only_for_a_third_value() {
        for opaque in [TlvFlags::U, TlvFlags::I, TlvFlags::M] {
            let mut data = vec![opaque, 4, 0, 4, 184, 0xac, 0xb0, 0];
            data.extend([0, 4, 0, 4, 184, 0xac, 0xb0, 0]);
            data.extend([0, 4, 0, 4, 184, 0xac, 0xb0, 0]);
            let original = data.clone();
            let policy = CosReplyPolicy::new(46, DscpSet::all(), DscpSet::all(), 2, true);
            let third = DscpSet::parse("34").unwrap().select(Some(46), 10).unwrap();
            policy.apply(&mut data, 0, third, 2);
            assert_eq!(&data[..8], &original[..8], "opaque TLV changed");
            if opaque == TlvFlags::M {
                // Processing stops at a malformed TLV.
                assert_eq!(data, original);
                continue;
            }
            for start in [8, 16] {
                assert_eq!(data[start], TlvFlags::C);
                assert_eq!(data[start + 5], 0xad, "RPD=01");
                assert_eq!(data[start + 6], 0xa0, "RPE=10");
            }
            let requested = DscpSet::all().select(Some(46), 10).unwrap();
            policy.apply(&mut data, 0, requested, 3);
            assert_eq!(data[8], 0, "a route retry clears the local C");
            assert_eq!(data[16], 0);
        }
    }
}
