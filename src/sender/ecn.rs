//! Bounded ECN observations from admitted, distinct reply copies.

use super::telemetry::CosObservation;

/// ECN observations; array indexes are the two-bit wire codepoints.
/// Raw histograms remain separate from the paired directional diagnostics.
#[derive(Clone, Debug, serde::Serialize)]
pub struct EcnSummary {
    pub requested_ecn: u8,
    /// Socket marking accepted by the OS, not proof of actual wire marking.
    pub configured_egress_ecn: Option<u8>,
    pub replies: u64,
    pub usable_cos: u64,
    pub unavailable_cos: u64,
    pub received_ec2: [u64; 4],
    pub echoed_ec1: [u64; 4],
    pub rpe: [u64; 4],
    pub rpd: [u64; 4],
    pub conformant_reflected: u64,
    pub reply_ip_ecn: [u64; 4],
    pub unavailable_reply_ip_ecn: u64,
    /// Both integrity-usable CoS and IP metadata exist, EC1 matches the request,
    /// RPE=11 and C=0. This is eligibility, not a claim of an unchanged path.
    pub reverse_comparable: u64,
    pub reverse_unknown: u64,
    /// Local socket marking compared with validated reflector ingress EC2.
    pub forward: EcnDirectionSummary,
    /// Validated, applied EC1 compared with this reply's own IP ECN.
    pub reverse: EcnDirectionSummary,
}

/// Mutually exclusive diagnostic outcomes for one direction. Comparisons
/// describe endpoint evidence and cannot locate or prove a network fault.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct EcnDirectionSummary {
    pub comparable: u64,
    pub unknown: u64,
    pub unchanged: u64,
    /// Nonzero ECN changed to Not-ECT, including CE erasure to Not-ECT.
    pub bleaching: u64,
    /// ECT(1) or ECT(0) changed to CE. A request already using CE is excluded.
    pub ce_marked: u64,
    /// All remaining unequal pairs, including Not-ECT to CE and ECT swaps.
    pub remarked: u64,
    /// Comparable observations ending in CE; overlaps outcome categories.
    pub ce_observed: u64,
    /// Rows are baseline codepoints, columns are observed codepoints (0..3).
    pub transitions: [[u64; 4]; 4],
    pub unknown_reasons: EcnUnknownSummary,
}

/// One primary reason per unknown comparison, in the documented priority order.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct EcnUnknownSummary {
    pub cos_unavailable: u64,
    pub local_marking_unavailable: u64,
    pub conformant_reflected: u64,
    pub request_mismatch: u64,
    pub legacy_or_unconfirmed: u64,
    /// RPE=1: the reflector could apply neither EC1 nor Not-ECT (draft-ietf-bpm-stamp-cos-ecn-00).
    pub reflector_marking_unavailable: u64,
    /// RPE=2 cannot distinguish policy refusal from platform limitations.
    pub reflector_unable: u64,
    pub reply_ip_unavailable: u64,
}

enum UnknownReason {
    CosUnavailable,
    LocalMarkingUnavailable,
    ConformantReflected,
    RequestMismatch,
    LegacyOrUnconfirmed,
    ReflectorMarkingUnavailable,
    ReflectorUnable,
    ReplyIpUnavailable,
}

impl EcnDirectionSummary {
    fn record(&mut self, pair: Result<(u8, u8), UnknownReason>) {
        let (baseline, observed) = match pair {
            Ok(pair) => pair,
            Err(reason) => {
                self.unknown += 1;
                let reasons = &mut self.unknown_reasons;
                let count = match reason {
                    UnknownReason::CosUnavailable => &mut reasons.cos_unavailable,
                    UnknownReason::LocalMarkingUnavailable => {
                        &mut reasons.local_marking_unavailable
                    }
                    UnknownReason::ConformantReflected => &mut reasons.conformant_reflected,
                    UnknownReason::RequestMismatch => &mut reasons.request_mismatch,
                    UnknownReason::LegacyOrUnconfirmed => &mut reasons.legacy_or_unconfirmed,
                    UnknownReason::ReflectorMarkingUnavailable => {
                        &mut reasons.reflector_marking_unavailable
                    }
                    UnknownReason::ReflectorUnable => &mut reasons.reflector_unable,
                    UnknownReason::ReplyIpUnavailable => &mut reasons.reply_ip_unavailable,
                };
                *count += 1;
                return;
            }
        };
        self.comparable += 1;
        self.transitions[usize::from(baseline)][usize::from(observed)] += 1;
        self.ce_observed += u64::from(observed == 3);
        if baseline == observed {
            self.unchanged += 1;
        } else if observed == 0 {
            self.bleaching += 1;
        } else if matches!(baseline, 1 | 2) && observed == 3 {
            self.ce_marked += 1;
        } else {
            self.remarked += 1;
        }
    }
}

impl EcnSummary {
    pub(crate) fn new(requested_ecn: u8, configured_egress_ecn: Option<u8>) -> Self {
        Self {
            requested_ecn,
            configured_egress_ecn,
            replies: 0,
            usable_cos: 0,
            unavailable_cos: 0,
            received_ec2: [0; 4],
            echoed_ec1: [0; 4],
            rpe: [0; 4],
            rpd: [0; 4],
            conformant_reflected: 0,
            reply_ip_ecn: [0; 4],
            unavailable_reply_ip_ecn: 0,
            reverse_comparable: 0,
            reverse_unknown: 0,
            forward: EcnDirectionSummary::default(),
            reverse: EcnDirectionSummary::default(),
        }
    }

    pub(super) fn record(&mut self, cos: Option<CosObservation>, reply_ecn: Option<u8>) {
        self.replies += 1;
        let reply_ecn = reply_ecn.filter(|&v| v < 4);
        if let Some(ecn) = reply_ecn {
            self.reply_ip_ecn[usize::from(ecn)] += 1;
        } else {
            self.unavailable_reply_ip_ecn += 1;
        }
        let mut forward = Err(UnknownReason::CosUnavailable);
        let mut reverse = Err(UnknownReason::CosUnavailable);
        if let Some(observation) = cos {
            let cos = observation.value;
            self.usable_cos += 1;
            self.received_ec2[usize::from(cos.ecn2)] += 1;
            self.echoed_ec1[usize::from(cos.ecn1)] += 1;
            self.rpe[usize::from(cos.rpe)] += 1;
            self.rpd[usize::from(cos.rpd)] += 1;
            self.conformant_reflected += u64::from(observation.conformant_reflected);
            // C/RPE describe reverse marking, not the reflector's ingress EC2.
            forward = self
                .configured_egress_ecn
                .filter(|&v| v < 4)
                .map(|baseline| (baseline, cos.ecn2))
                .ok_or(UnknownReason::LocalMarkingUnavailable);
            reverse = if observation.conformant_reflected {
                Err(UnknownReason::ConformantReflected)
            } else {
                match cos.rpe {
                    0 => Err(UnknownReason::LegacyOrUnconfirmed),
                    1 => Err(UnknownReason::ReflectorMarkingUnavailable),
                    2 => Err(UnknownReason::ReflectorUnable),
                    _ if cos.ecn1 != self.requested_ecn => Err(UnknownReason::RequestMismatch),
                    _ => reply_ecn
                        .map(|observed| (cos.ecn1, observed))
                        .ok_or(UnknownReason::ReplyIpUnavailable),
                }
            };
        } else {
            self.unavailable_cos += 1;
        }
        self.forward.record(forward);
        self.reverse.record(reverse);
        self.reverse_comparable = self.reverse.comparable;
        self.reverse_unknown = self.reverse.unknown;
    }
}

#[cfg(test)]
mod tests;
