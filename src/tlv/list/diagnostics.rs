//! Observe preserved C provenance without decoding protected child values.

use super::TlvList;
use crate::tlv::core::REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL;
use crate::tlv::framing::child_region_offset;
use crate::tlv::{TlvConformanceErrors, TlvConformanceReason, TlvSpan, TlvType};

impl TlvList {
    /// The fixed prefixes identify child headers even when their values are
    /// opaque. Visit complete frames up to the first incomplete child only.
    /// Unknown container formats and all child values remain uninterpreted.
    pub(crate) fn preserved_peer_c_errors(
        &self,
        generated_reply_controls: bool,
    ) -> TlvConformanceErrors {
        let mut report = TlvConformanceErrors::default();
        let mut first_control = true;
        for parent in self.non_hmac_tlvs() {
            let Some(offset) = child_region_offset(parent.tlv_type) else {
                continue;
            };
            let local_control = if parent.tlv_type == TlvType::ReflectedControl {
                let first = std::mem::take(&mut first_control);
                // The setter visits processable parents before the first one
                // can receive U for disabled/replayed/conflicting handling.
                generated_reply_controls
                    && (parent.is_processable()
                        || (first
                            && parent.flags.unrecognized
                            && !parent.flags.malformed
                            && !parent.flags.integrity_failed))
            } else {
                false
            };
            let mut pos = offset;
            while let Some(child) = TlvSpan::at(&parent.value, pos) {
                // This is the sole local child-C generator. Other C bits in
                // defined child headers were retained from the peer. Prefer
                // the known local cause even if the peer also supplied C.
                let generated = local_control
                    && child.tlv_type.to_byte() == REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL
                    && child.len == 0;
                if child.flags.conformant_reflected && !generated {
                    report.insert(TlvConformanceReason::PeerCPreserved);
                    return report;
                }
                pos = child.end();
            }
        }
        report
    }
}
