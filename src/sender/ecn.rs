//! Bounded ECN observations from admitted, distinct reply copies.

use super::telemetry::CosObservation;

/// Raw ECN observations; array indexes are the two-bit wire codepoints.
/// Histograms are marginal counts, not paired path transformations.
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
        let mut comparable = false;
        if let Some(observation) = cos {
            let cos = observation.value;
            self.usable_cos += 1;
            self.received_ec2[usize::from(cos.ecn2)] += 1;
            self.echoed_ec1[usize::from(cos.ecn1)] += 1;
            self.rpe[usize::from(cos.rpe)] += 1;
            self.rpd[usize::from(cos.rpd)] += 1;
            self.conformant_reflected += u64::from(observation.conformant_reflected);
            comparable = reply_ecn.is_some()
                && cos.rpe == 3
                && cos.ecn1 == self.requested_ecn
                && !observation.conformant_reflected;
        } else {
            self.unavailable_cos += 1;
        }
        self.reverse_comparable += u64::from(comparable);
        self.reverse_unknown += u64::from(!comparable);
    }
}

#[cfg(test)]
mod tests;
