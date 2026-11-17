//! Probes awaiting a reply, with the indexes that age and retire them.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    time::{Duration, Instant},
};

use super::PendingPacket;

/// What inserting a probe displaced. Each displaced probe counts as lost.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Displaced {
    /// An unanswered probe with the same sequence number (after wrap).
    pub sequence_reused: bool,
    /// The oldest probe, to keep a bounded table within its limit.
    pub limit_reached: bool,
}

/// Unanswered probes by sequence number.
///
/// With a limit (`--max-pending-probes`), probes are aged by the ordinal of
/// their successful send, which keeps the order right across timestamp ties
/// and sequence wrap, and the oldest is retired when the table is full.
/// Without one, a send-ordered deadline queue expires probes after the reply
/// timeout; answered probes are skipped lazily. Removing a probe through this
/// type keeps every index in step with the probes.
pub(super) struct PendingTable {
    probes: HashMap<u32, PendingPacket>,
    /// Zero for unlimited.
    limit: usize,
    /// Bounded mode: send ordinal to `(send time, sequence)`.
    order: BTreeMap<u64, (Instant, u32)>,
    /// Bounded mode: sequence to its send ordinal.
    ordinals: HashMap<u32, u64>,
    /// Unbounded mode with a timeout: `(deadline, sequence)` in send order.
    deadlines: VecDeque<(Instant, u32)>,
    high_watermark: usize,
}

impl PendingTable {
    pub(super) fn new(limit: u32) -> Self {
        Self {
            probes: HashMap::new(),
            limit: limit as usize,
            order: BTreeMap::new(),
            ordinals: HashMap::new(),
            deadlines: VecDeque::new(),
            high_watermark: 0,
        }
    }

    fn bounded(&self) -> bool {
        self.limit != 0
    }

    /// Records a probe sent with send ordinal `ordinal` under reply timeout
    /// `timeout` (zero for none) and reports which older probes it displaced.
    pub(super) fn insert(
        &mut self,
        seq: u32,
        probe: PendingPacket,
        ordinal: u64,
        timeout: Duration,
    ) -> Displaced {
        // A reused sequence cannot represent both generations; the older
        // probe is retired rather than silently dropped from loss accounting.
        let mut displaced = Displaced {
            sequence_reused: self.remove(&seq).is_some(),
            limit_reached: false,
        };
        if self.bounded() {
            if self.probes.len() >= self.limit {
                let (_, (oldest_time, oldest_seq)) =
                    self.order.pop_first().expect("indexed pending probe");
                let oldest = self
                    .probes
                    .remove(&oldest_seq)
                    .expect("indexed pending probe");
                debug_assert_eq!(oldest.send_time, oldest_time);
                self.ordinals.remove(&oldest_seq);
                displaced.limit_reached = true;
            }
            self.order.insert(ordinal, (probe.send_time, seq));
            self.ordinals.insert(seq, ordinal);
        } else if !timeout.is_zero() {
            self.deadlines.push_back((probe.send_time + timeout, seq));
        }
        self.probes.insert(seq, probe);
        self.high_watermark = self.high_watermark.max(self.probes.len());
        displaced
    }

    /// Removes an answered or retired probe.
    pub(super) fn remove(&mut self, seq: &u32) -> Option<PendingPacket> {
        let probe = self.probes.remove(seq)?;
        if let Some(ordinal) = self.ordinals.remove(seq) {
            self.order.remove(&ordinal).expect("indexed pending probe");
        }
        Some(probe)
    }

    /// Removes the probes whose reply `timeout` has passed by `now` and
    /// returns how many. Both indexes are in send order, so this stops at the
    /// first probe still within its timeout.
    pub(super) fn expire(&mut self, now: Instant, timeout: Duration) -> u32 {
        let mut lost = 0;
        if timeout.is_zero() {
            return lost;
        }
        if self.bounded() {
            while let Some((_, &(sent, seq))) = self.order.first_key_value() {
                if sent + timeout > now {
                    break;
                }
                self.remove(&seq).expect("indexed pending probe");
                lost += 1;
            }
            return lost;
        }
        while let Some(&(deadline, seq)) = self.deadlines.front() {
            if deadline > now {
                break;
            }
            self.deadlines.pop_front();
            // Answered probes, and older generations of a reused sequence,
            // are skipped here rather than searched for on removal.
            if self
                .probes
                .get(&seq)
                .is_some_and(|p| p.send_time + timeout == deadline)
            {
                self.probes.remove(&seq);
                lost += 1;
            }
        }
        lost
    }

    pub(super) fn get(&self, seq: &u32) -> Option<&PendingPacket> {
        self.probes.get(seq)
    }

    /// For kernel TX timestamps, which correct a probe's T1 after the send.
    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    pub(super) fn get_mut(&mut self, seq: &u32) -> Option<&mut PendingPacket> {
        self.probes.get_mut(seq)
    }

    pub(super) fn contains_key(&self, seq: &u32) -> bool {
        self.probes.contains_key(seq)
    }

    pub(super) fn len(&self) -> usize {
        self.probes.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    /// The most probes held at once during the run.
    pub(super) fn high_watermark(&self) -> usize {
        self.high_watermark
    }
}

#[cfg(test)]
impl PendingTable {
    /// An unlimited table without expiry holding `probes`.
    pub(super) fn from_probes(probes: impl IntoIterator<Item = (u32, PendingPacket)>) -> Self {
        let mut table = Self::new(0);
        for (seq, probe) in probes {
            table.insert_probe(seq, probe);
        }
        table
    }

    /// Inserts into an unlimited table, where the send ordinal is unused.
    pub(super) fn insert_probe(&mut self, seq: u32, probe: PendingPacket) {
        self.insert(seq, probe, 0, Duration::ZERO);
    }

    /// Bounded-mode index sizes, which must always equal `len()`.
    pub(super) fn index_lens(&self) -> (usize, usize) {
        (self.order.len(), self.ordinals.len())
    }

    pub(super) fn deadline_len(&self) -> usize {
        self.deadlines.len()
    }

    /// Sequence number of the oldest probe in bounded mode.
    pub(super) fn oldest_seq(&self) -> Option<u32> {
        self.order.first_key_value().map(|(_, &(_, seq))| seq)
    }

    /// Send ordinal of the newest probe in bounded mode.
    pub(super) fn newest_ordinal(&self) -> Option<u64> {
        self.order.last_key_value().map(|(&ordinal, _)| ordinal)
    }
}

#[cfg(test)]
impl std::ops::Index<&u32> for PendingTable {
    type Output = PendingPacket;

    fn index(&self, seq: &u32) -> &PendingPacket {
        &self.probes[seq]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn probe(send_time: Instant) -> PendingPacket {
        PendingPacket {
            send_time,
            send_timestamp: 0,
            wire_timestamp: 0,
            ber_padding: None,
        }
    }

    #[test]
    fn bounded_table_retires_oldest_and_keeps_indexes_in_step() {
        let start = Instant::now();
        let mut table = PendingTable::new(2);
        assert_eq!(
            table.insert(1, probe(start), 1, SECOND),
            Displaced::default()
        );
        assert_eq!(
            table.insert(2, probe(start), 2, SECOND),
            Displaced::default()
        );
        let displaced = table.insert(3, probe(start), 3, SECOND);
        assert!(displaced.limit_reached && !displaced.sequence_reused);
        assert!(!table.contains_key(&1));
        assert_eq!(table.oldest_seq(), Some(2));
        assert!(table.remove(&2).is_some());
        assert_eq!(table.index_lens(), (table.len(), table.len()));
        // Reusing a live sequence retires its older generation.
        let displaced = table.insert(3, probe(start), 4, SECOND);
        assert!(displaced.sequence_reused && !displaced.limit_reached);
        assert_eq!(table.newest_ordinal(), Some(4));
        assert_eq!(table.index_lens(), (1, 1));
        assert_eq!(table.high_watermark(), 2);
        assert_eq!(table.expire(start + Duration::from_secs(1), SECOND), 1);
        assert!(table.is_empty());
        assert_eq!(table.index_lens(), (0, 0));
    }

    #[test]
    fn unbounded_table_expires_in_send_order_and_skips_answered_probes() {
        let start = Instant::now();
        let mut table = PendingTable::new(0);
        for seq in 0..3 {
            table.insert(
                seq,
                probe(start + Duration::from_millis(u64::from(seq))),
                0,
                SECOND,
            );
        }
        assert!(table.remove(&0).is_some());
        assert_eq!(table.index_lens(), (0, 0));
        assert_eq!(table.deadline_len(), 3);
        assert_eq!(table.expire(start + Duration::from_millis(1000), SECOND), 0);
        assert_eq!(table.expire(start + Duration::from_millis(1001), SECOND), 1);
        assert_eq!(table.expire(start + Duration::from_secs(5), SECOND), 1);
        assert!(table.is_empty() && table.deadline_len() == 0);

        // Without a timeout nothing is queued or expired.
        let mut forever = PendingTable::new(0);
        forever.insert(1, probe(start), 0, Duration::ZERO);
        assert_eq!(forever.deadline_len(), 0);
        assert_eq!(
            forever.expire(start + Duration::from_secs(3600), Duration::ZERO),
            0
        );
        assert_eq!(forever.len(), 1);
    }
}
