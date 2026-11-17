//! Reply budget, burst scheduling and shutdown drain.

use super::*;

/// A slot covers processing, channel handoff, queued deadlines and the active
/// send. Keeping it through every copy bounds combined work in both backends.
pub(in crate::receiver) struct ReplyBudget {
    pub(super) limit: usize,
    pub(super) used: AtomicUsize,
    pub(super) counters: Arc<ReflectorCounters>,
}

impl ReplyBudget {
    pub fn new(limit: usize, counters: Arc<ReflectorCounters>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            counters,
        })
    }

    /// `fetch_update` is deprecated on current toolchains and its
    /// replacement is newer than the MSRV, so the CAS loop is spelled out.
    pub(super) fn try_take_slot(&self) -> bool {
        let mut used = self.used.load(Ordering::Acquire);
        while used < self.limit {
            match self.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => used = actual,
            }
        }
        false
    }

    pub fn reserve(self: &Arc<Self>) -> Option<ReplyReservation> {
        if !self.try_take_slot() {
            self.counters
                .reply_queue_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.counters.record_drop("queue_full");
            return None;
        }
        Some(ReplyReservation(Arc::clone(self)))
    }

    pub fn is_empty(&self) -> bool {
        self.used.load(Ordering::Acquire) == 0
    }
}

pub(in crate::receiver) struct ReplyReservation(Arc<ReplyBudget>);
impl ReplyReservation {
    pub fn attach(self, transmission: Transmission) -> QueuedTransmission {
        QueuedTransmission {
            transmission,
            reservation: self,
        }
    }
}
impl Drop for ReplyReservation {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(in crate::receiver) struct QueuedTransmission {
    pub transmission: Transmission,
    pub(super) reservation: ReplyReservation,
}
impl Drop for QueuedTransmission {
    fn drop(&mut self) {
        if self.transmission.remaining > 0 {
            let counters = &self.reservation.0.counters;
            counters
                .queued_replies_cancelled
                .fetch_add(u64::from(self.transmission.remaining), Ordering::Relaxed);
            counters.record_drop("cancelled");
        }
    }
}

/// A shutdown deadline is set once and cannot be extended by later signals.
#[derive(Default)]
pub(in crate::receiver) struct ShutdownDrain {
    pub(super) deadline: Option<Instant>,
}
impl ShutdownDrain {
    pub fn begin(&mut self, now: Instant, grace: Duration) {
        self.deadline.get_or_insert(now + grace);
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn finished(&self, now: Instant, empty: bool) -> bool {
        self.deadline
            .is_some_and(|deadline| empty || now >= deadline)
    }
}

pub(super) struct Pending {
    pub(super) at: Instant,
    pub(super) order: u64,
    pub(super) transmission: QueuedTransmission,
}
impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.order == other.order
    }
}
impl Eq for Pending {}
impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl Ord for Pending {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.order.cmp(&self.order))
    }
}

#[derive(Default)]
pub(in crate::receiver) struct ReplyQueue {
    pub(super) pending: BinaryHeap<Pending>,
    pub(super) order: u64,
}
impl ReplyQueue {
    pub fn deadline(&self) -> Option<Instant> {
        self.pending.peek().map(|p| p.at)
    }
    pub fn push_at(&mut self, transmission: QueuedTransmission, at: Instant) {
        self.order = self.order.wrapping_add(1);
        self.pending.push(Pending {
            at,
            order: self.order,
            transmission,
        });
    }
    pub fn schedule_next(&mut self, transmission: QueuedTransmission) {
        if transmission.transmission.remaining > 0 {
            let at = Instant::now() + transmission.transmission.interval;
            self.push_at(transmission, at);
        }
    }
    pub fn pop_due(&mut self) -> Option<QueuedTransmission> {
        if self.deadline().is_some_and(|at| at <= Instant::now()) {
            self.pending.pop().map(|p| p.transmission)
        } else {
            None
        }
    }
}
