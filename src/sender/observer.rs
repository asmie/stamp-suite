//! Live sender events for Prometheus metrics, the SNMP sub-agent and
//! library callers.

use std::sync::Arc;

/// Receives sender events as they happen. Every method does nothing by
/// default, so an observer implements only what it reports.
pub trait SenderObserver: Send + Sync {
    fn probe_sent(&self) {}
    fn reply_received(&self, _rtt_ns: u64) {}
    fn probes_lost(&self, _count: u32) {}
    /// A reply failed base-packet HMAC verification and was discarded.
    fn hmac_failed(&self) {}
    /// A reply was discarded by TLV validation.
    fn reply_rejected(&self) {}
    /// U, M and I flag counts of an accepted reply's TLVs.
    fn tlv_flags(&self, _unrecognized: usize, _malformed: usize, _integrity_failed: usize) {}
}

/// The observers of one sender run.
#[derive(Clone, Default)]
pub struct SenderObservers(Vec<Arc<dyn SenderObserver>>);

impl SenderObservers {
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, observer: Arc<dyn SenderObserver>) {
        self.0.push(observer);
    }

    pub(super) fn probe_sent(&self) {
        self.0.iter().for_each(|o| o.probe_sent());
    }

    pub(super) fn reply_received(&self, rtt_ns: u64) {
        self.0.iter().for_each(|o| o.reply_received(rtt_ns));
    }

    pub(super) fn probes_lost(&self, count: u32) {
        if count > 0 {
            self.0.iter().for_each(|o| o.probes_lost(count));
        }
    }

    pub(super) fn hmac_failed(&self) {
        self.0.iter().for_each(|o| o.hmac_failed());
    }

    pub(super) fn reply_rejected(&self) {
        self.0.iter().for_each(|o| o.reply_rejected());
    }

    pub(super) fn tlv_flags(&self, flags: &super::FlagCounts) {
        self.0.iter().for_each(|o| {
            o.tlv_flags(flags.unrecognized, flags.malformed, flags.integrity_failed);
        });
    }
}
