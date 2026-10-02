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
/// (RFC 10052 §5). A valid HMAC does not rule out replay.
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
    /// (RFC 10052 §5). Distinct from `curr_seq`,
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

    #[cfg(test)]
    /// Classifies and records `seq` (RFC 10052 §5).
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

    /// Returns the next sequence number without consuming it. A stateful
    /// reflector consumes it only after a successful send, so failed sends
    /// leave no gap (RFC 8762 §4.3.1 counts transmitted packets). Callers
    /// must be the session's only sender.
    pub fn peek_sequence_number(&self) -> u32 {
        self.curr_seq.load(Ordering::Relaxed)
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

    #[cfg(test)]
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
    /// Last use, in nanoseconds since the manager's `epoch`. Atomic so the
    /// per-packet refresh needs only the table's read lock.
    last_active: AtomicU64,
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
    /// Reference point for `SessionEntry::last_active`.
    epoch: Instant,
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
            epoch: Instant::now(),
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

    #[cfg(test)]
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

    #[cfg(test)]
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

    fn now_ns(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn last_active(&self, entry: &SessionEntry) -> Instant {
        self.epoch + Duration::from_nanos(entry.last_active.load(Ordering::Relaxed))
    }

    fn get_or_create_admitted(&self, client: SessionKey) -> Option<Arc<Session>> {
        #[cfg(test)]
        self.acquisitions.fetch_add(1, Ordering::Relaxed);
        // Known sessions need only the read lock.
        {
            let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = sessions.get(&client) {
                entry.last_active.store(self.now_ns(), Ordering::Relaxed);
                return Some(Arc::clone(&entry.session));
            }
        }
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let count = sessions.len();
        match sessions.entry(client) {
            // Created by another thread between the two locks.
            Entry::Occupied(occupied) => {
                let entry = occupied.get();
                entry.last_active.store(self.now_ns(), Ordering::Relaxed);
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
                    last_active: AtomicU64::new(self.now_ns()),
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

    #[cfg(test)]
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
            let keep = now.duration_since(self.last_active(entry)) < timeout;
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
                    last_active: self.last_active(entry),
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
mod tests;
