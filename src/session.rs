pub use crate::session_identity::{SessionAdmission, SessionKey};
use crate::tlv::TimestampMethod;

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

/// Sequence-number classification for replay detection
/// (draft-ietf-ippm-asymmetrical-pkts-14 §5). A valid HMAC does not rule out replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Ahead of every sequence number seen so far (the normal case), or the
    /// first packet of the session.
    New,
    /// Behind the high-water mark but not seen before — a late or reordered
    /// packet, which is ordinary on a real network and not an attack signal.
    Reordered,
    /// Already seen: a duplicate or a replay.
    Replay,
    /// So far behind the high-water mark that the window no longer remembers
    /// whether it was seen. Reported separately rather than guessed at.
    OutOfWindow,
}

/// Number of sequence numbers below the high-water mark the replay window
/// remembers. 31 rather than 32 so the window bitmap and an "initialized"
/// marker share one `u64` with the high-water mark, keeping the whole check a
/// single compare-and-swap.
pub const REPLAY_WINDOW: u32 = 31;

/// Bit 31 of the packed low half: set once the session has seen any packet.
/// Without it, the all-zero state would be ambiguous between "nothing seen
/// yet" and "sequence number 0 seen".
const REPLAY_INITIALIZED: u32 = 1 << 31;

/// Mask of the window bitmap proper (bits 0..=30 → offsets 1..=31).
const REPLAY_BITMAP_MASK: u32 = REPLAY_INITIALIZED - 1;

/// Represents a STAMP measurement session.
///
/// A session tracks the session identifier, maintains an atomic counter
/// for generating unique sequence numbers, and tracks packet counters
/// for Direct Measurement and Follow-Up Telemetry TLV support.
pub struct Session {
    /// Unique identifier for this session.
    sess_id: u32,
    /// Atomic counter for generating sequential packet numbers.
    curr_seq: AtomicU32,
    /// Total packets received in this session (for Direct Measurement TLV).
    packets_received: AtomicU32,
    /// Total packets transmitted in this session (for Direct Measurement TLV).
    packets_transmitted: AtomicU32,
    /// Coherent sequence/timestamp/provenance record for Follow-Up Telemetry.
    last_reflection: RwLock<(u32, u64, TimestampMethod)>,
    /// Replay-detection window for *received* sequence numbers
    /// (draft-ietf-ippm-asymmetrical-pkts-14 §5). Distinct from `curr_seq`,
    /// which is this reflector's own outgoing generator.
    ///
    /// Packed so the whole update is one compare-and-swap:
    /// bits 63..32 hold the highest sequence number seen, bit 31 marks the
    /// session as initialized, and bits 30..0 are a bitmap where bit `n` means
    /// "sequence number `high - (n + 1)` has been seen".
    replay_state: AtomicU64,
    /// Serializes retirement against a datagram currently being transmitted.
    /// An expired session cannot send queued replies after its identity restarts.
    active: RwLock<bool>,
}

impl Session {
    /// Creates a new session with the given identifier.
    ///
    /// The sequence number counter is initialized to 0.
    pub fn new(id: u32) -> Session {
        Session {
            sess_id: id,
            curr_seq: AtomicU32::new(0),
            packets_received: AtomicU32::new(0),
            packets_transmitted: AtomicU32::new(0),
            last_reflection: RwLock::new((0, 0, TimestampMethod::SwLocal)),
            replay_state: AtomicU64::new(0),
            active: RwLock::new(true),
        }
    }

    /// Keep this guard through the send and its counter/telemetry updates.
    pub(crate) fn transmission_guard(&self) -> Option<std::sync::RwLockReadGuard<'_, bool>> {
        let guard = self.active.read().unwrap_or_else(|e| e.into_inner());
        if *guard {
            Some(guard)
        } else {
            None
        }
    }

    fn retire(&self) {
        *self.active.write().unwrap_or_else(|e| e.into_inner()) = false;
    }

    /// Classifies and records `seq` (draft-ietf-ippm-asymmetrical-pkts-14 §5).
    /// The caller decides whether to drop it; reordering and sender restarts can
    /// also produce non-New verdicts.
    ///
    /// Wrapping differences below 2^31 count as ahead; larger differences count
    /// as behind. Compare-and-swap retries prevent lost concurrent updates.
    pub fn check_replay(&self, seq: u32) -> ReplayVerdict {
        loop {
            let packed = self.replay_state.load(Ordering::Relaxed);
            let (verdict, next) = Self::replay_step(packed, seq);
            let Some(next) = next else {
                return verdict;
            };
            if self
                .replay_state
                .compare_exchange_weak(packed, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return verdict;
            }
        }
    }

    /// Classifies `seq` without advancing the replay window.
    /// The receive pipeline classifies verified packets before response assembly
    /// and commits them afterward.
    pub fn classify_replay(&self, seq: u32) -> ReplayVerdict {
        Self::replay_step(self.replay_state.load(Ordering::Relaxed), seq).0
    }

    /// Mutating half of [`Self::check_replay`]: records `seq` in the window.
    /// Backends call this only after the packet passed verification and was
    /// answered, so the window holds nothing an attacker could plant.
    pub fn commit_replay(&self, seq: u32) {
        loop {
            let packed = self.replay_state.load(Ordering::Relaxed);
            let (_, next) = Self::replay_step(packed, seq);
            let Some(next) = next else {
                return; // Already recorded (replay / out of window) — no update.
            };
            if self
                .replay_state
                .compare_exchange_weak(packed, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// One classification step against a packed window state: the verdict for
    /// `seq`, and the successor state when recording it would change anything
    /// (`None` for replays and out-of-window packets, which never update).
    fn replay_step(packed: u64, seq: u32) -> (ReplayVerdict, Option<u64>) {
        let low = packed as u32;

        if low & REPLAY_INITIALIZED == 0 {
            // First packet on this session.
            return (
                ReplayVerdict::New,
                Some(((seq as u64) << 32) | u64::from(REPLAY_INITIALIZED)),
            );
        }

        let high = (packed >> 32) as u32;
        let bitmap = low & REPLAY_BITMAP_MASK;

        if seq == high {
            // The high-water mark itself, seen a second time.
            return (ReplayVerdict::Replay, None);
        }

        let ahead = seq.wrapping_sub(high);
        if ahead < 1 << 31 {
            // Advancing: every remembered offset moves further back by
            // `ahead`, and the old high-water mark becomes offset
            // `ahead` (bit `ahead - 1`) if the window still reaches it.
            let shifted = if ahead >= 32 {
                0
            } else {
                (bitmap << ahead) & REPLAY_BITMAP_MASK
            };
            let old_high_bit = if ahead <= REPLAY_WINDOW {
                1u32 << (ahead - 1)
            } else {
                0
            };
            let next_low = REPLAY_INITIALIZED | shifted | old_high_bit;
            (
                ReplayVerdict::New,
                Some(((seq as u64) << 32) | u64::from(next_low)),
            )
        } else {
            let behind = high.wrapping_sub(seq);
            if behind > REPLAY_WINDOW {
                return (ReplayVerdict::OutOfWindow, None);
            }
            let bit = 1u32 << (behind - 1);
            if bitmap & bit != 0 {
                return (ReplayVerdict::Replay, None);
            }
            let next_low = REPLAY_INITIALIZED | bitmap | bit;
            (
                ReplayVerdict::Reordered,
                Some(((high as u64) << 32) | u64::from(next_low)),
            )
        }
    }

    /// Returns the session identifier.
    pub fn get_id(&self) -> u32 {
        self.sess_id
    }

    /// Generates and returns the next sequence number for this session.
    ///
    /// This method is thread-safe and atomically increments the counter.
    pub fn generate_sequence_number(&self) -> u32 {
        self.curr_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Records a received packet for this session.
    pub fn record_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a transmitted packet for this session.
    pub fn record_transmitted(&self) {
        self.packets_transmitted.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the total count of received packets.
    pub fn get_received_count(&self) -> u32 {
        self.packets_received.load(Ordering::Relaxed)
    }

    /// Returns the total count of transmitted packets.
    pub fn get_transmitted_count(&self) -> u32 {
        self.packets_transmitted.load(Ordering::Relaxed)
    }

    /// Records a software-generated transmit timestamp for the new reflection.
    pub fn record_reflection(&self, seq: u32, timestamp: u64) {
        *self
            .last_reflection
            .write()
            .unwrap_or_else(|e| e.into_inner()) = (seq, timestamp, TimestampMethod::SwLocal);
    }

    /// Returns a consistent sequence/timestamp snapshot.
    pub fn get_last_reflection(&self) -> (u32, u64) {
        let (seq, timestamp, _) = self.get_last_reflection_with_method();
        (seq, timestamp)
    }

    /// Returns the timestamp and the method that actually produced it together.
    pub fn get_last_reflection_with_method(&self) -> (u32, u64, TimestampMethod) {
        *self
            .last_reflection
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Applies a software timestamp correction (compatibility helper).
    pub fn correct_reflection_timestamp(&self, seq: u32, timestamp: u64) -> bool {
        self.correct_reflection_timestamp_with_method(seq, timestamp, TimestampMethod::SwLocal)
    }

    /// Corrects only the matching reflection, atomically updating its timestamp
    /// and provenance. A later software report cannot downgrade a hardware one.
    pub fn correct_reflection_timestamp_with_method(
        &self,
        seq: u32,
        timestamp: u64,
        method: TimestampMethod,
    ) -> bool {
        let mut record = self
            .last_reflection
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if record.0 != seq
            || (record.2 == TimestampMethod::HwAssist && method != TimestampMethod::HwAssist)
        {
            return false;
        }
        *record = (seq, timestamp, method);
        true
    }
}

/// Entry in the session manager tracking a session and its activity.
struct SessionEntry {
    /// The session for this client.
    session: Arc<Session>,
    /// Last time this session was used.
    last_active: Instant,
}

/// Maintains independent state for each complete STAMP session identity.
pub struct SessionManager {
    #[cfg(test)]
    pub(crate) admission_checks: AtomicUsize,
    #[cfg(test)]
    pub(crate) acquisitions: AtomicUsize,
    /// Map from complete identity to runtime state.
    sessions: RwLock<HashMap<SessionKey, SessionEntry>>,
    admission: SessionAdmission,
    provisioned: HashSet<SessionKey>,
    /// Counter for generating unique session IDs.
    next_session_id: AtomicU32,
    /// Optional timeout after which inactive sessions may be cleaned up.
    session_timeout: Option<Duration>,
    /// Maximum number of sessions to prevent unbounded growth; 0 means
    /// unlimited. Runtime-adjustable via the control plane.
    max_sessions: AtomicUsize,
    /// When true, new identities are rejected; existing sessions continue.
    /// Changes are serialized with session creation by the table write lock.
    draining: AtomicBool,
    /// Suppresses repeated capacity warnings while the table is full.
    /// Cleared by `cleanup_stale_sessions` when capacity becomes available.
    saturated: AtomicBool,
}

/// One immutable provisioning decision, bound to its manager and full identity.
/// Consuming it still checks the current cap/drain state under the table lock.
/// It neither allocates nor pins a runtime session and is not an authentication
/// credential: the receiver must validate the packet before calling `acquire`.
pub(crate) struct SessionAdmissionPermit<'a> {
    manager: &'a SessionManager,
    key: SessionKey,
}

impl SessionAdmissionPermit<'_> {
    pub(crate) fn acquire(self) -> Option<Arc<Session>> {
        self.manager.get_or_create_admitted(self.key)
    }
}

impl SessionManager {
    /// Creates a new session manager with an optional timeout and session limit.
    ///
    /// If `session_timeout` is `Some`, sessions that have been inactive
    /// for longer than the timeout may be cleaned up via `cleanup_stale_sessions()`.
    /// If `max_sessions` is `Some`, new sessions will be rejected once the limit is reached.
    pub fn new(session_timeout: Option<Duration>, max_sessions: Option<usize>) -> Self {
        Self::with_admission(
            session_timeout,
            max_sessions,
            SessionAdmission::Permissive,
            HashSet::new(),
        )
    }

    pub fn with_admission(
        session_timeout: Option<Duration>,
        max_sessions: Option<usize>,
        admission: SessionAdmission,
        provisioned: HashSet<SessionKey>,
    ) -> Self {
        SessionManager {
            #[cfg(test)]
            admission_checks: AtomicUsize::new(0),
            #[cfg(test)]
            acquisitions: AtomicUsize::new(0),
            admission,
            provisioned,
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU32::new(0),
            session_timeout,
            max_sessions: AtomicUsize::new(max_sessions.unwrap_or(0)),
            draining: AtomicBool::new(false),
            saturated: AtomicBool::new(false),
        }
    }

    /// Admission is independent of runtime state: expiry never removes provisioning.
    pub fn admits(&self, key: &SessionKey) -> bool {
        #[cfg(test)]
        self.admission_checks.fetch_add(1, Ordering::Relaxed);
        self.admission == SessionAdmission::Permissive || self.provisioned.contains(key)
    }

    /// Check immutable provisioning once without touching the runtime table.
    /// The permit cannot be transferred to another manager or session key.
    pub(crate) fn admit(&self, key: SessionKey) -> Option<SessionAdmissionPermit<'_>> {
        self.admits(&key)
            .then_some(SessionAdmissionPermit { manager: self, key })
    }

    pub fn admission(&self) -> SessionAdmission {
        self.admission
    }

    pub fn provisioned_count(&self) -> usize {
        self.provisioned.len()
    }

    /// Expire exactly one matching runtime entry, refusing an ambiguous client.
    /// The optional internal session ID is the ID returned by the control API.
    pub fn expire_matching(
        &self,
        client: SocketAddr,
        session_id: Option<u32>,
    ) -> Result<bool, &'static str> {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let mut matches = sessions.iter().filter(|(key, entry)| {
            key.client == client && session_id.is_none_or(|id| entry.session.get_id() == id)
        });
        let key = matches.next().map(|(key, _)| *key);
        if matches.next().is_some() {
            return Err("multiple sessions for client; specify session_id");
        }
        let removed = key.and_then(|key| sessions.remove(&key));
        if let Some(entry) = &removed {
            entry.session.retire();
            self.note_table_shrunk(sessions.len());
        }
        Ok(removed.is_some())
    }

    /// Returns true when a new entry must not be stored: the table is at
    /// its cap (logs the one-shot saturation warning) or the reflector is
    /// draining.
    fn reject_new_entry(&self, current_len: usize, client: SocketAddr) -> bool {
        let cap = self.max_sessions.load(Ordering::Relaxed);
        if cap != 0 && current_len >= cap {
            self.note_saturated(cap, client);
            return true;
        }
        self.draining.load(Ordering::Relaxed)
    }

    /// Removes the session for `client`. Returns true if it existed.
    pub fn expire_session(&self, client: impl Into<SessionKey>) -> bool {
        let client = client.into();
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let removed = sessions.remove(&client);
        if let Some(entry) = &removed {
            entry.session.retire();
            self.note_table_shrunk(sessions.len());
        }
        removed.is_some()
    }

    /// Enables or disables drain mode (see `draining`).
    pub fn set_draining(&self, draining: bool) {
        let _sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        self.draining.store(draining, Ordering::Relaxed);
    }

    /// True while drain mode is active.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Sets the session-table cap; 0 means unlimited. Existing entries are
    /// never evicted by a smaller cap; only new admission is restricted.
    pub fn set_max_sessions(&self, cap: usize) {
        let _sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        self.max_sessions.store(cap, Ordering::Relaxed);
        self.saturated.store(false, Ordering::Relaxed);
    }

    fn note_table_shrunk(&self, len: usize) {
        let cap = self.max_sessions.load(Ordering::Relaxed);
        if cap == 0 || len < cap {
            self.saturated.store(false, Ordering::Relaxed);
        }
        #[cfg(feature = "metrics")]
        crate::metrics::reflector_metrics::set_active_sessions(len);
    }

    /// Current session-table cap; 0 means unlimited.
    #[must_use]
    pub fn max_sessions(&self) -> usize {
        self.max_sessions.load(Ordering::Relaxed)
    }

    /// Logs the "session table at cap" warning at most once per saturation
    /// episode. Per-client rejections are logged at debug to avoid a
    /// flood-driven log-amplification DoS.
    fn note_saturated(&self, max: usize, client: SocketAddr) {
        if !self.saturated.swap(true, Ordering::Relaxed) {
            log::warn!(
                "Session table reached its cap ({max}); new sessions are rejected \
                 until entries expire or the cap increases. Existing sessions continue."
            );
        }
        log::debug!("Session limit reached, rejecting new client {client}");
    }

    /// Generates and returns the next sequence number for a client's session.
    ///
    /// Creates a new session if one doesn't exist for the client.
    /// Also updates the last_active time in a single lock acquisition.
    pub fn generate_sequence_number(&self, client: impl Into<SessionKey>) -> Option<u32> {
        self.get_session_and_seq(client).map(|(seq, _session)| seq)
    }

    /// Returns the session for a client without generating a sequence number.
    ///
    /// Creates a new session if one doesn't exist. This is useful for accessing
    /// session state (counters, last reflection) without consuming a sequence number.
    /// Returns `None` on provisioning, capacity, or drain rejection. No temporary
    /// session is created, and rejection does not consume an internal session ID.
    pub fn get_or_create_session(&self, client: impl Into<SessionKey>) -> Option<Arc<Session>> {
        self.admit(client.into())?.acquire()
    }

    fn get_or_create_admitted(&self, client: SessionKey) -> Option<Arc<Session>> {
        #[cfg(test)]
        self.acquisitions.fetch_add(1, Ordering::Relaxed);
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let count = sessions.len();
        match sessions.entry(client) {
            Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                entry.last_active = Instant::now();
                Some(Arc::clone(&entry.session))
            }
            Entry::Vacant(vacant) => {
                if self.reject_new_entry(count, client.client) {
                    return None;
                }
                let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
                let session = Arc::new(Session::new(session_id));
                vacant.insert(SessionEntry {
                    session: Arc::clone(&session),
                    last_active: Instant::now(),
                });
                log::debug!("Created new session {} for client {}", session_id, client);

                #[cfg(feature = "metrics")]
                {
                    crate::metrics::reflector_metrics::record_session_created();
                    crate::metrics::reflector_metrics::set_active_sessions(count + 1);
                }

                Some(session)
            }
        }
    }

    /// Returns the session for a client only if it already exists, without
    /// creating one or refreshing its activity time. Used by the kernel
    /// TX-timestamp drain to apply late corrections without resurrecting
    /// expired sessions.
    pub fn get_session(&self, client: impl Into<SessionKey>) -> Option<Arc<Session>> {
        let client = client.into();
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions.get(&client).map(|e| Arc::clone(&e.session))
    }

    /// Gets the session for a client and generates the next sequence number.
    ///
    /// Returns both the sequence number and an Arc to the session, allowing the
    /// caller to access session state (e.g., packet counters for Direct Measurement TLV).
    /// Creates a new session if one doesn't exist for the client.
    /// Returns `None` if new-session admission is denied or concurrent expiry
    /// retires the acquired session before sequence allocation.
    pub fn get_session_and_seq(
        &self,
        client: impl Into<SessionKey>,
    ) -> Option<(u32, Arc<Session>)> {
        let session = self.get_or_create_session(client)?;
        let active = session.transmission_guard()?;
        let seq = session.generate_sequence_number();
        drop(active);
        Some((seq, session))
    }

    /// Removes sessions that have been inactive longer than the timeout.
    ///
    /// Returns the number of sessions removed.
    /// Does nothing if no timeout was configured.
    pub fn cleanup_stale_sessions(&self) -> usize {
        let timeout = match self.session_timeout {
            Some(t) => t,
            None => return 0,
        };

        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let before_count = sessions.len();

        sessions.retain(|addr, entry| {
            let keep = now.duration_since(entry.last_active) < timeout;
            if !keep {
                entry.session.retire();
                log::debug!("Removing stale session for client {}", addr);
            }
            keep
        });

        let removed = before_count - sessions.len();
        if removed > 0 {
            log::info!("Cleaned up {} stale sessions", removed);

            self.note_table_shrunk(sessions.len());
        }

        removed
    }

    /// Returns the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Returns a summary of all sessions: (client_addr, packets_received, packets_transmitted).
    pub fn session_summaries(&self) -> Vec<(SocketAddr, u32, u32)> {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions
            .iter()
            .map(|(addr, entry)| {
                (
                    addr.client,
                    entry.session.get_received_count(),
                    entry.session.get_transmitted_count(),
                )
            })
            .collect()
    }

    pub fn session_summaries_by_key(&self) -> Vec<(SessionKey, u32, u32)> {
        self.sessions
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(key, entry)| {
                (
                    *key,
                    entry.session.get_received_count(),
                    entry.session.get_transmitted_count(),
                )
            })
            .collect()
    }

    /// Returns an extended summary of all sessions for SNMP reporting.
    pub fn session_summaries_extended(&self) -> Vec<SessionSummary> {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions
            .iter()
            .map(|(addr, entry)| {
                let (last_seq, _ts) = entry.session.get_last_reflection();
                SessionSummary {
                    key: *addr,
                    client_addr: addr.client,
                    session_id: entry.session.get_id(),
                    packets_received: entry.session.get_received_count(),
                    packets_transmitted: entry.session.get_transmitted_count(),
                    last_reflected_seq: last_seq,
                    last_active: entry.last_active,
                }
            })
            .collect()
    }
}

/// Extended session summary for SNMP reporting.
pub struct SessionSummary {
    pub key: SessionKey,
    /// Client address (IP:port).
    pub client_addr: SocketAddr,
    /// Session identifier.
    pub session_id: u32,
    /// Total packets received.
    pub packets_received: u32,
    /// Total packets transmitted.
    pub packets_transmitted: u32,
    /// Last reflected sequence number.
    pub last_reflected_seq: u32,
    /// Timestamp of last activity.
    pub last_active: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn admission_permit_observes_later_cap_drain_and_expiry_changes() {
        let first = SessionKey::from("127.0.0.1:1001".parse::<SocketAddr>().unwrap());
        let second = SessionKey::from("127.0.0.1:1002".parse::<SocketAddr>().unwrap());
        let denied = SessionKey::from("127.0.0.1:1003".parse::<SocketAddr>().unwrap());
        let manager = SessionManager::with_admission(
            None,
            None,
            SessionAdmission::Provisioned,
            [first, second].into_iter().collect(),
        );
        assert!(manager.admit(denied).is_none());
        let pending = manager.admit(second).unwrap();
        assert_eq!(
            manager.session_count(),
            0,
            "a permit must not allocate state"
        );
        let existing = manager.get_or_create_session(first).unwrap();
        manager.set_max_sessions(1);
        assert!(pending.acquire().is_none(), "a later cap must apply");
        assert_eq!(manager.next_session_id.load(Ordering::Relaxed), 1);

        manager.set_max_sessions(0);
        let pending = manager.admit(second).unwrap();
        let known = manager.admit(first).unwrap();
        manager.set_draining(true);
        assert!(pending.acquire().is_none(), "a later drain must apply");
        assert!(Arc::ptr_eq(&known.acquire().unwrap(), &existing));
        assert_eq!(manager.next_session_id.load(Ordering::Relaxed), 1);

        let pending = manager.admit(first).unwrap();
        manager
            .expire_matching(first.client, Some(existing.get_id()))
            .unwrap();
        assert!(
            pending.acquire().is_none(),
            "expiry during drain cannot recreate state"
        );
        assert!(existing.transmission_guard().is_none());
        manager.set_draining(false);
        let replacement = manager.admit(first).unwrap().acquire().unwrap();
        assert!(!Arc::ptr_eq(&existing, &replacement));
        assert_eq!(replacement.get_id(), 1);
        assert_eq!(replacement.generate_sequence_number(), 0);
    }

    #[test]
    fn complete_identity_isolates_all_runtime_state() {
        for (source, destination) in [
            ("127.0.0.1:4000", "127.0.0.1:862"),
            ("[::1]:4000", "[::1]:862"),
        ] {
            let base: SessionKey = format!("42,{source},{destination}").parse().unwrap();
            let mut other_destination = base;
            other_destination.local.set_port(863);
            let keys = [
                base,
                SessionKey { ssid: 43, ..base },
                other_destination,
                SessionKey {
                    sender_micro_session_id: Some(1),
                    ..base
                },
                SessionKey {
                    sender_micro_session_id: Some(2),
                    ..base
                },
            ];
            let manager = SessionManager::new(None, None);
            for key in keys {
                let (seq, session) = manager.get_session_and_seq(key).unwrap();
                assert_eq!(seq, 0);
                assert_eq!(session.get_received_count(), 0);
                assert_eq!(session.get_transmitted_count(), 0);
                assert_eq!(session.check_replay(100), ReplayVerdict::New);
                assert_eq!(session.get_last_reflection().0, 0);
                session.record_received();
                session.record_transmitted();
                session.record_reflection(100, 123);
            }
            assert_eq!(manager.session_count(), 5);
            for key in keys {
                assert_eq!(manager.generate_sequence_number(key).unwrap(), 1);
                let session = manager.get_session(key).unwrap();
                assert_eq!(session.check_replay(100), ReplayVerdict::Replay);
                assert_eq!(session.get_received_count(), 1);
                assert_eq!(session.get_transmitted_count(), 1);
                assert_eq!(session.get_last_reflection(), (100, 123));
            }
            assert!(manager.expire_matching(base.client, None).is_err());
            let id = manager.get_session(base).unwrap().get_id();
            assert_eq!(manager.expire_matching(base.client, Some(id)), Ok(true));
            assert!(manager.get_session(base).is_none());
            assert_eq!(manager.session_count(), 4);
        }
    }

    #[test]
    fn provisioning_survives_runtime_expiry_and_denies_other_identities() {
        let key: SessionKey = "42,127.0.0.1:4000,127.0.0.1:862,1".parse().unwrap();
        let manager = SessionManager::with_admission(
            Some(Duration::ZERO),
            None,
            SessionAdmission::Provisioned,
            HashSet::from([key]),
        );
        assert!(manager.admits(&key));
        assert!(!manager.admits(&SessionKey { ssid: 43, ..key }));
        assert!(!manager.admits(&SessionKey {
            sender_micro_session_id: None,
            ..key
        }));
        manager.get_or_create_session(key).unwrap();
        assert_eq!(manager.cleanup_stale_sessions(), 1);
        assert!(manager.admits(&key));
        assert_eq!(manager.provisioned_count(), 1);
        manager.get_or_create_session(key).unwrap();
        assert!(manager.expire_session(key));
        assert!(manager.admits(&key));
    }

    // -----------------------------------------------------------------------
    // Replay detection (draft-ietf-ippm-asymmetrical-pkts-14 §5)

    #[test]
    fn test_replay_first_packet_is_new() {
        let s = Session::new(1);
        assert_eq!(s.check_replay(0), ReplayVerdict::New);

        // Sequence number 0 must be *remembered*, which is why the packed
        // state carries an explicit initialized marker: an all-zero state
        // would otherwise look like "nothing seen yet".
        assert_eq!(s.check_replay(0), ReplayVerdict::Replay);
    }

    #[test]
    fn test_replay_monotonic_run_is_all_new() {
        let s = Session::new(1);
        for seq in 0..1000u32 {
            assert_eq!(
                s.check_replay(seq),
                ReplayVerdict::New,
                "in-order seq {seq} must be New"
            );
        }
    }

    #[test]
    fn test_replay_immediate_duplicate_detected() {
        let s = Session::new(1);
        assert_eq!(s.check_replay(10), ReplayVerdict::New);
        assert_eq!(s.check_replay(10), ReplayVerdict::Replay);
        // And still detected after the window has moved on a little.
        assert_eq!(s.check_replay(11), ReplayVerdict::New);
        assert_eq!(s.check_replay(10), ReplayVerdict::Replay);
    }

    #[test]
    fn test_replay_reordered_then_duplicate() {
        let s = Session::new(1);
        assert_eq!(s.check_replay(100), ReplayVerdict::New);
        // 98 is behind the high-water mark and unseen: late, not a replay.
        assert_eq!(s.check_replay(98), ReplayVerdict::Reordered);
        // The same late packet again *is* a replay.
        assert_eq!(s.check_replay(98), ReplayVerdict::Replay);
        // A different late one is still just reordered.
        assert_eq!(s.check_replay(99), ReplayVerdict::Reordered);
    }

    #[test]
    fn test_replay_window_edge_and_beyond() {
        let s = Session::new(1);
        assert_eq!(s.check_replay(1000), ReplayVerdict::New);

        // The furthest offset the window remembers.
        let edge = 1000 - REPLAY_WINDOW;
        assert_eq!(s.check_replay(edge), ReplayVerdict::Reordered);
        assert_eq!(s.check_replay(edge), ReplayVerdict::Replay);

        // One past the window: honestly reported as unknown rather than
        // guessed at in either direction.
        assert_eq!(s.check_replay(edge - 1), ReplayVerdict::OutOfWindow);
        assert_eq!(s.check_replay(edge - 1), ReplayVerdict::OutOfWindow);
    }

    #[test]
    fn test_replay_large_forward_jump_clears_the_window() {
        let s = Session::new(1);
        assert_eq!(s.check_replay(5), ReplayVerdict::New);
        assert_eq!(s.check_replay(4), ReplayVerdict::Reordered);
        // Jumping far ahead pushes every remembered offset out of range.
        assert_eq!(s.check_replay(10_000), ReplayVerdict::New);
        // 4 and 5 are now ancient history, not replays.
        assert_eq!(s.check_replay(4), ReplayVerdict::OutOfWindow);
        assert_eq!(s.check_replay(9_999), ReplayVerdict::Reordered);
    }

    #[test]
    fn test_classify_replay_is_read_only_commit_advances() {
        let s = Session::new(1);
        // Classification never advances the window — repeated classification
        // of the same unseen sequence number stays New.
        assert_eq!(s.classify_replay(5), ReplayVerdict::New);
        assert_eq!(s.classify_replay(5), ReplayVerdict::New);

        s.commit_replay(5);
        assert_eq!(s.classify_replay(5), ReplayVerdict::Replay);
        // Committing an already-recorded sequence number is a no-op.
        s.commit_replay(5);
        assert_eq!(s.classify_replay(5), ReplayVerdict::Replay);

        // A late unseen packet classifies as Reordered until committed.
        assert_eq!(s.classify_replay(4), ReplayVerdict::Reordered);
        assert_eq!(s.classify_replay(4), ReplayVerdict::Reordered);
        s.commit_replay(4);
        assert_eq!(s.classify_replay(4), ReplayVerdict::Replay);

        // classify+commit agrees with the atomic check_replay.
        assert_eq!(s.check_replay(6), ReplayVerdict::New);
        assert_eq!(s.classify_replay(6), ReplayVerdict::Replay);
    }

    #[test]
    fn test_replay_advance_preserves_remembered_offsets() {
        let s = Session::new(1);
        assert_eq!(s.check_replay(50), ReplayVerdict::New);
        assert_eq!(s.check_replay(48), ReplayVerdict::Reordered);
        // Advance by 3: offset of 48 becomes 5, still inside the window.
        assert_eq!(s.check_replay(53), ReplayVerdict::New);
        assert_eq!(
            s.check_replay(48),
            ReplayVerdict::Replay,
            "a remembered offset must survive the window shifting"
        );
        assert_eq!(
            s.check_replay(50),
            ReplayVerdict::Replay,
            "the previous high-water mark must be remembered after advancing"
        );
    }

    #[test]
    fn test_replay_survives_sequence_wraparound() {
        let s = Session::new(1);
        let near_max = u32::MAX - 2;
        assert_eq!(s.check_replay(near_max), ReplayVerdict::New);
        assert_eq!(s.check_replay(u32::MAX - 1), ReplayVerdict::New);
        assert_eq!(s.check_replay(u32::MAX), ReplayVerdict::New);
        // Wrapping past the end keeps advancing, not looking like a 4-billion
        // step backwards.
        assert_eq!(s.check_replay(0), ReplayVerdict::New);
        assert_eq!(s.check_replay(1), ReplayVerdict::New);
        // And the pre-wrap values are still remembered as seen.
        assert_eq!(s.check_replay(u32::MAX), ReplayVerdict::Replay);
        assert_eq!(s.check_replay(near_max), ReplayVerdict::Replay);
    }

    #[test]
    fn test_replay_is_per_session_not_global() {
        let a = Session::new(1);
        let b = Session::new(2);
        assert_eq!(a.check_replay(7), ReplayVerdict::New);
        assert_eq!(
            b.check_replay(7),
            ReplayVerdict::New,
            "each session tracks its own sender's numbering"
        );
    }

    #[test]
    fn test_replay_concurrent_updates_lose_nothing() {
        // Every distinct sequence number is offered exactly once from several
        // threads: none may be reported as a replay, because none is one.
        let s = Arc::new(Session::new(1));
        let mut handles = Vec::new();
        for t in 0..4u32 {
            let s = Arc::clone(&s);
            handles.push(thread::spawn(move || {
                let mut replays = 0;
                for i in 0..250u32 {
                    if s.check_replay(t * 250 + i) == ReplayVerdict::Replay {
                        replays += 1;
                    }
                }
                replays
            }));
        }
        let total: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total, 0,
            "no distinct sequence number may be called a replay"
        );
    }

    #[test]
    fn test_expire_session() {
        let mgr = SessionManager::new(None, None);
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        mgr.get_or_create_session(addr).unwrap();
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.expire_session(addr));
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.expire_session(addr), "second expire returns false");
    }

    #[test]
    fn test_draining_blocks_new_sessions_only() {
        let mgr = SessionManager::new(None, None);
        let known: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let new_client: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        mgr.get_or_create_session(known).unwrap();

        mgr.set_draining(true);
        assert!(mgr.is_draining());
        assert!(mgr.get_or_create_session(new_client).is_none());
        assert_eq!(mgr.session_count(), 1, "draining: new clients rejected");
        // Existing client still tracked.
        mgr.get_or_create_session(known).unwrap();
        assert_eq!(mgr.session_count(), 1);

        mgr.set_draining(false);
        mgr.get_or_create_session(new_client).unwrap();
        assert_eq!(mgr.session_count(), 2);
    }

    #[test]
    fn test_set_max_sessions_at_runtime() {
        let mgr = SessionManager::new(None, Some(2));
        assert_eq!(mgr.max_sessions(), 2);
        mgr.set_max_sessions(1);
        assert_eq!(mgr.max_sessions(), 1);
        mgr.get_or_create_session("10.0.0.1:1".parse::<SocketAddr>().unwrap())
            .unwrap();
        assert!(mgr
            .get_or_create_session("10.0.0.2:2".parse::<SocketAddr>().unwrap())
            .is_none());
        assert_eq!(mgr.session_count(), 1, "cap applies to new creations");
    }

    #[test]
    fn test_correct_reflection_timestamp_only_for_matching_seq() {
        let session = Session::new(1);
        session.record_reflection(42, 1000);

        // Matching seq → timestamp replaced (kernel TX timestamp arrived).
        assert!(session.correct_reflection_timestamp(42, 2000));
        assert_eq!(session.get_last_reflection(), (42, 2000));

        // A newer reflection was recorded since → stale correction dropped.
        session.record_reflection(43, 3000);
        assert!(!session.correct_reflection_timestamp(42, 9999));
        assert_eq!(session.get_last_reflection(), (43, 3000));
    }

    #[test]
    fn test_get_session_returns_only_existing() {
        let mgr = SessionManager::new(None, None);
        let addr: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        assert!(mgr.get_session(addr).is_none());
        mgr.get_or_create_session(addr).unwrap();
        assert!(mgr.get_session(addr).is_some());
        assert_eq!(mgr.session_count(), 1, "get_session must not create");
    }

    #[test]
    fn test_sequence_number_starts_at_zero() {
        let session = Session::new(1);
        assert_eq!(session.generate_sequence_number(), 0);
    }

    #[test]
    fn test_sequence_number_many_increments() {
        let session = Session::new(1);
        for i in 0..1000 {
            assert_eq!(session.generate_sequence_number(), i);
        }
    }

    #[test]
    fn test_session_thread_safety() {
        let session = Arc::new(Session::new(1));
        let mut handles = vec![];

        // Spawn 10 threads, each generating 100 sequence numbers
        for _ in 0..10 {
            let session_clone = Arc::clone(&session);
            handles.push(thread::spawn(move || {
                let mut nums = Vec::new();
                for _ in 0..100 {
                    nums.push(session_clone.generate_sequence_number());
                }
                nums
            }));
        }

        // Collect all sequence numbers
        let mut all_nums: Vec<u32> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();

        // Sort and verify no duplicates (all unique)
        all_nums.sort();
        let unique_count = all_nums.len();
        all_nums.dedup();
        assert_eq!(
            all_nums.len(),
            unique_count,
            "Duplicate sequence numbers found"
        );

        // Should have exactly 1000 unique numbers (0-999)
        assert_eq!(all_nums.len(), 1000);
        assert_eq!(*all_nums.first().unwrap(), 0);
        assert_eq!(*all_nums.last().unwrap(), 999);
    }

    #[test]
    fn test_multiple_sessions_independent() {
        let session1 = Session::new(1);
        let session2 = Session::new(2);

        // Generate some numbers from session1
        assert_eq!(session1.generate_sequence_number(), 0);
        assert_eq!(session1.generate_sequence_number(), 1);

        // Session2 should start fresh
        assert_eq!(session2.generate_sequence_number(), 0);

        // Continue session1
        assert_eq!(session1.generate_sequence_number(), 2);
    }

    // SessionManager tests

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_session_manager_creates_sessions() {
        let manager = SessionManager::new(None, None);

        let client1 = make_addr(10001);
        let client2 = make_addr(10002);

        // First call creates a session
        let seq1 = manager.generate_sequence_number(client1).unwrap();
        assert_eq!(seq1, 0);
        assert_eq!(manager.session_count(), 1);

        // Second call to same client reuses session
        let seq2 = manager.generate_sequence_number(client1).unwrap();
        assert_eq!(seq2, 1);
        assert_eq!(manager.session_count(), 1);

        // Different client gets its own session
        let seq3 = manager.generate_sequence_number(client2).unwrap();
        assert_eq!(seq3, 0);
        assert_eq!(manager.session_count(), 2);
    }

    #[test]
    fn test_session_manager_independent_sequences() {
        let manager = SessionManager::new(None, None);

        let client1 = make_addr(10001);
        let client2 = make_addr(10002);

        // Interleave requests from two clients
        assert_eq!(manager.generate_sequence_number(client1).unwrap(), 0);
        assert_eq!(manager.generate_sequence_number(client2).unwrap(), 0);
        assert_eq!(manager.generate_sequence_number(client1).unwrap(), 1);
        assert_eq!(manager.generate_sequence_number(client1).unwrap(), 2);
        assert_eq!(manager.generate_sequence_number(client2).unwrap(), 1);
        assert_eq!(manager.generate_sequence_number(client1).unwrap(), 3);
        assert_eq!(manager.generate_sequence_number(client2).unwrap(), 2);
    }

    #[test]
    fn test_session_manager_thread_safety() {
        let manager = Arc::new(SessionManager::new(None, None));
        let mut handles = vec![];

        // 5 threads, each simulating a different client
        for i in 0..5 {
            let manager_clone = Arc::clone(&manager);
            handles.push(thread::spawn(move || {
                let client = make_addr(10001 + i);
                let mut nums = Vec::new();
                for _ in 0..100 {
                    nums.push(manager_clone.generate_sequence_number(client).unwrap());
                }
                nums
            }));
        }

        // Each thread should get sequence 0-99
        for handle in handles {
            let nums = handle.join().unwrap();
            assert_eq!(nums.len(), 100);
            // Should be sequential within each client
            for (i, &n) in nums.iter().enumerate() {
                assert_eq!(n, i as u32);
            }
        }

        // Should have 5 sessions
        assert_eq!(manager.session_count(), 5);
    }

    #[test]
    fn test_session_manager_cleanup_no_timeout() {
        let manager = SessionManager::new(None, None);
        let client = make_addr(10001);

        manager.generate_sequence_number(client).unwrap();
        assert_eq!(manager.session_count(), 1);

        // Without timeout, cleanup does nothing
        assert_eq!(manager.cleanup_stale_sessions(), 0);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_cleanup_with_timeout() {
        // Use a short but reasonable timeout for testing
        // 50ms timeout with 100ms sleep provides 2x margin for slow/loaded systems
        let manager = SessionManager::new(Some(Duration::from_millis(50)), None);
        let client = make_addr(10001);

        manager.generate_sequence_number(client).unwrap();
        assert_eq!(manager.session_count(), 1);

        // Wait for timeout (2x the timeout duration for reliability)
        thread::sleep(Duration::from_millis(100));

        // Cleanup should remove the stale session
        assert_eq!(manager.cleanup_stale_sessions(), 1);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_cleanup_keeps_active() {
        let manager = SessionManager::new(Some(Duration::from_secs(300)), None);
        let client = make_addr(10001);

        manager.generate_sequence_number(client).unwrap();

        // Session is still active, should not be cleaned up
        assert_eq!(manager.cleanup_stale_sessions(), 0);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn lowering_cap_preserves_existing_sessions_and_rejection_has_no_state() {
        let manager = SessionManager::new(None, Some(2));
        let first = manager.get_or_create_session(make_addr(1)).unwrap();
        let second = manager.get_or_create_session(make_addr(2)).unwrap();
        first.record_received();
        first.record_reflection(12, 345);
        first.commit_replay(99);
        assert_eq!(manager.generate_sequence_number(make_addr(1)), Some(0));
        manager.set_max_sessions(1);
        for _ in 0..3 {
            assert!(manager.get_or_create_session(make_addr(3)).is_none());
        }
        assert_eq!(
            manager.session_count(),
            2,
            "lowering the cap must not evict"
        );
        assert_eq!(manager.next_session_id.load(Ordering::Relaxed), 2);
        assert!(Arc::ptr_eq(
            &first,
            &manager.get_or_create_session(make_addr(1)).unwrap()
        ));
        assert!(Arc::ptr_eq(
            &second,
            &manager.get_or_create_session(make_addr(2)).unwrap()
        ));
        assert_eq!(manager.generate_sequence_number(make_addr(1)), Some(1));
        assert_eq!(first.get_received_count(), 1);
        assert_eq!(first.get_last_reflection(), (12, 345));
        assert_eq!(first.classify_replay(99), ReplayVerdict::Replay);
        manager.expire_session(make_addr(2));
        assert!(manager.get_or_create_session(make_addr(3)).is_none());
        manager.expire_session(make_addr(1));
        assert!(!manager.saturated.load(Ordering::Relaxed));
        let replacement = manager.get_or_create_session(make_addr(3)).unwrap();
        assert_eq!(replacement.get_id(), 2);
    }

    #[test]
    fn concurrent_admission_never_exceeds_capacity() {
        let manager = Arc::new(SessionManager::new(None, Some(4)));
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let threads: Vec<_> = (0..16)
            .map(|i| {
                let manager = Arc::clone(&manager);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    manager.get_or_create_session(make_addr(i + 1)).is_some()
                })
            })
            .collect();
        let admitted = threads
            .into_iter()
            .map(|t| usize::from(t.join().unwrap()))
            .sum::<usize>();
        assert_eq!(admitted, 4);
        assert_eq!(manager.session_count(), 4);
        manager.set_draining(true);
        manager.set_max_sessions(0);
        assert!(manager.get_or_create_session(make_addr(100)).is_none());
    }

    #[test]
    fn provisioned_capacity_and_restart_preserve_admission_but_reset_runtime() {
        let key: SessionKey = "42,127.0.0.1:4000,127.0.0.1:862,1".parse().unwrap();
        let other = SessionKey { ssid: 43, ..key };
        let manager = SessionManager::with_admission(
            Some(Duration::ZERO),
            Some(1),
            SessionAdmission::Provisioned,
            HashSet::from([key, other]),
        );
        let first = manager.get_or_create_session(key).unwrap();
        first.record_received();
        first.record_reflection(3, 100);
        first.commit_replay(7);
        assert!(manager.get_or_create_session(other).is_none());
        assert!(manager
            .get_or_create_session(SessionKey { ssid: 99, ..key })
            .is_none());
        assert_eq!(manager.cleanup_stale_sessions(), 1);
        assert!(first.transmission_guard().is_none());
        let restarted = manager.get_or_create_session(key).unwrap();
        assert_ne!(first.get_id(), restarted.get_id());
        assert_eq!(restarted.generate_sequence_number(), 0);
        assert_eq!(restarted.get_received_count(), 0);
        assert_eq!(restarted.get_last_reflection(), (0, 0));
        assert_eq!(restarted.classify_replay(7), ReplayVerdict::New);
        assert_eq!(manager.provisioned_count(), 2);
        assert_eq!(
            manager.expire_matching(key.client, Some(restarted.get_id())),
            Ok(true)
        );
        assert!(restarted.transmission_guard().is_none());
        assert!(manager.get_or_create_session(other).is_some());
    }

    #[test]
    fn test_session_manager_enforces_max_sessions_cap() {
        // Cap of 2: preserve the first two identities and reject a third.
        let manager = SessionManager::new(None, Some(2));
        manager.generate_sequence_number(make_addr(1)).unwrap();
        manager.generate_sequence_number(make_addr(2)).unwrap();
        assert_eq!(manager.session_count(), 2);

        assert!(manager.get_or_create_session(make_addr(3)).is_none());
        assert!(manager.get_session_and_seq(make_addr(3)).is_none());
        assert!(manager.generate_sequence_number(make_addr(3)).is_none());
        assert_eq!(
            manager.session_count(),
            2,
            "table must not grow past the cap"
        );

        // Existing clients are still served from the table.
        manager.generate_sequence_number(make_addr(1)).unwrap();
        assert_eq!(manager.session_count(), 2);
    }

    #[test]
    fn test_session_cap_reopens_after_cleanup_frees_space() {
        let manager = SessionManager::new(Some(Duration::from_millis(50)), Some(1));
        manager.generate_sequence_number(make_addr(1)).unwrap();
        assert_eq!(manager.session_count(), 1);
        // Over cap now — second client is not stored.
        assert!(manager.generate_sequence_number(make_addr(2)).is_none());
        assert_eq!(manager.session_count(), 1);

        // Let the first entry go stale and clean it up.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(manager.cleanup_stale_sessions(), 1);
        assert_eq!(manager.session_count(), 0);

        // Space freed → a new client is tracked again.
        manager.generate_sequence_number(make_addr(3)).unwrap();
        assert_eq!(manager.session_count(), 1);
    }
    #[test]
    fn reflection_method_tracks_actual_reports_without_stale_downgrades() {
        let session = Session::new(0);
        session.record_reflection(7, 100);
        assert_eq!(
            session.get_last_reflection_with_method(),
            (7, 100, TimestampMethod::SwLocal)
        );
        assert!(session.correct_reflection_timestamp_with_method(7, 110, TimestampMethod::SwLocal));
        assert!(session.correct_reflection_timestamp_with_method(
            7,
            120,
            TimestampMethod::HwAssist
        ));
        assert!(!session.correct_reflection_timestamp_with_method(
            7,
            115,
            TimestampMethod::SwLocal
        ));
        assert_eq!(
            session.get_last_reflection_with_method(),
            (7, 120, TimestampMethod::HwAssist)
        );
        session.record_reflection(8, 200);
        assert!(!session.correct_reflection_timestamp_with_method(
            7,
            130,
            TimestampMethod::HwAssist
        ));
        assert_eq!(
            session.get_last_reflection_with_method(),
            (8, 200, TimestampMethod::SwLocal)
        );
    }
}
