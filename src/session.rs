use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

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
    /// Sequence number of the last reflected packet (for Follow-Up Telemetry TLV).
    last_reflected_seq: AtomicU32,
    /// Timestamp of the last reflected packet (for Follow-Up Telemetry TLV).
    last_reflected_timestamp: AtomicU64,
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
            last_reflected_seq: AtomicU32::new(0),
            last_reflected_timestamp: AtomicU64::new(0),
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

    /// Records a reflection with the given sequence number and timestamp.
    pub fn record_reflection(&self, seq: u32, timestamp: u64) {
        self.last_reflected_seq.store(seq, Ordering::Relaxed);
        self.last_reflected_timestamp
            .store(timestamp, Ordering::Relaxed);
    }

    /// Returns the last reflection's sequence number and timestamp.
    pub fn get_last_reflection(&self) -> (u32, u64) {
        (
            self.last_reflected_seq.load(Ordering::Relaxed),
            self.last_reflected_timestamp.load(Ordering::Relaxed),
        )
    }

    /// Replaces the recorded TX timestamp of the last reflection when `seq`
    /// still matches — used when a kernel transmit timestamp for that reply
    /// arrives from the socket error queue after the fact (feature
    /// "hwtstamp"). Returns false (and changes nothing) when a newer
    /// reflection has been recorded since.
    pub fn correct_reflection_timestamp(&self, seq: u32, timestamp: u64) -> bool {
        if self.last_reflected_seq.load(Ordering::Relaxed) == seq {
            self.last_reflected_timestamp
                .store(timestamp, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

/// Entry in the session manager tracking a session and its activity.
struct SessionEntry {
    /// The session for this client.
    session: Arc<Session>,
    /// Last time this session was used.
    last_active: Instant,
}

/// Manages multiple sessions, one per client (IP:port).
///
/// Used in multi-session reflector mode (RFC 8972) where each client
/// gets its own independent sequence counter.
pub struct SessionManager {
    /// Map from client address to session entry.
    sessions: RwLock<HashMap<SocketAddr, SessionEntry>>,
    /// Counter for generating unique session IDs.
    next_session_id: AtomicU32,
    /// Optional timeout after which inactive sessions may be cleaned up.
    session_timeout: Option<Duration>,
    /// Optional maximum number of sessions to prevent unbounded growth.
    max_sessions: Option<usize>,
    /// True while the table is at its cap. Used to log the "cap reached"
    /// warning exactly once per saturation episode instead of once per
    /// rejected client — otherwise a flood would turn the log into its own
    /// amplification DoS. Reset by `cleanup_stale_sessions` once the table
    /// drops back below the cap.
    saturated: AtomicBool,
}

impl SessionManager {
    /// Creates a new session manager with an optional timeout and session limit.
    ///
    /// If `session_timeout` is `Some`, sessions that have been inactive
    /// for longer than the timeout may be cleaned up via `cleanup_stale_sessions()`.
    /// If `max_sessions` is `Some`, new sessions will be rejected once the limit is reached.
    pub fn new(session_timeout: Option<Duration>, max_sessions: Option<usize>) -> Self {
        SessionManager {
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU32::new(0),
            session_timeout,
            max_sessions,
            saturated: AtomicBool::new(false),
        }
    }

    /// Logs the "session table at cap" warning at most once per saturation
    /// episode. Per-client rejections are logged at debug to avoid a
    /// flood-driven log-amplification DoS.
    fn note_saturated(&self, max: usize, client: SocketAddr) {
        if !self.saturated.swap(true, Ordering::Relaxed) {
            log::warn!(
                "Session table reached its cap ({max}); new clients are still \
                 answered but not tracked until stale entries expire. Raise \
                 --max-sessions if this is legitimate load."
            );
        }
        log::debug!("Session limit reached, not tracking new client {client}");
    }

    /// Generates and returns the next sequence number for a client's session.
    ///
    /// Creates a new session if one doesn't exist for the client.
    /// Also updates the last_active time in a single lock acquisition.
    pub fn generate_sequence_number(&self, client: SocketAddr) -> u32 {
        let (seq, _session) = self.get_session_and_seq(client);
        seq
    }

    /// Returns the session for a client without generating a sequence number.
    ///
    /// Creates a new session if one doesn't exist. This is useful for accessing
    /// session state (counters, last reflection) without consuming a sequence number.
    pub fn get_or_create_session(&self, client: SocketAddr) -> Arc<Session> {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());

        if let Some(entry) = sessions.get_mut(&client) {
            entry.last_active = Instant::now();
            Arc::clone(&entry.session)
        } else {
            if let Some(max) = self.max_sessions {
                if sessions.len() >= max {
                    self.note_saturated(max, client);
                    // Return a temporary session that won't be stored
                    return Arc::new(Session::new(u32::MAX));
                }
            }
            let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            let session = Arc::new(Session::new(session_id));
            sessions.insert(
                client,
                SessionEntry {
                    session: Arc::clone(&session),
                    last_active: Instant::now(),
                },
            );
            log::debug!("Created new session {} for client {}", session_id, client);

            #[cfg(feature = "metrics")]
            {
                crate::metrics::reflector_metrics::record_session_created();
                crate::metrics::reflector_metrics::set_active_sessions(sessions.len());
            }

            session
        }
    }

    /// Returns the session for a client only if it already exists, without
    /// creating one or refreshing its activity time. Used by the kernel
    /// TX-timestamp drain to apply late corrections without resurrecting
    /// expired sessions.
    pub fn get_session(&self, client: SocketAddr) -> Option<Arc<Session>> {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions.get(&client).map(|e| Arc::clone(&e.session))
    }

    /// Gets the session for a client and generates the next sequence number.
    ///
    /// Returns both the sequence number and an Arc to the session, allowing the
    /// caller to access session state (e.g., packet counters for Direct Measurement TLV).
    /// Creates a new session if one doesn't exist for the client.
    pub fn get_session_and_seq(&self, client: SocketAddr) -> (u32, Arc<Session>) {
        // Take write lock once for both session lookup and activity update
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());

        let session = if let Some(entry) = sessions.get_mut(&client) {
            // Existing session - update activity and return
            entry.last_active = Instant::now();
            Arc::clone(&entry.session)
        } else {
            if let Some(max) = self.max_sessions {
                if sessions.len() >= max {
                    self.note_saturated(max, client);
                    // Return a temporary session that won't be stored
                    let session = Arc::new(Session::new(u32::MAX));
                    return (0, session);
                }
            }
            // Create new session
            let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            let session = Arc::new(Session::new(session_id));
            sessions.insert(
                client,
                SessionEntry {
                    session: Arc::clone(&session),
                    last_active: Instant::now(),
                },
            );
            log::debug!("Created new session {} for client {}", session_id, client);

            // Record session creation metrics
            #[cfg(feature = "metrics")]
            {
                crate::metrics::reflector_metrics::record_session_created();
                crate::metrics::reflector_metrics::set_active_sessions(sessions.len());
            }

            session
        };

        // Release lock before generating sequence number
        drop(sessions);
        let seq = session.generate_sequence_number();
        (seq, session)
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
                log::debug!("Removing stale session for client {}", addr);
            }
            keep
        });

        let removed = before_count - sessions.len();
        if removed > 0 {
            log::info!("Cleaned up {} stale sessions", removed);

            // Update active sessions gauge after cleanup
            #[cfg(feature = "metrics")]
            crate::metrics::reflector_metrics::set_active_sessions(sessions.len());
        }

        // Re-arm the one-shot "cap reached" warning once we drop back below the
        // cap, so a later saturation episode is reported again.
        if let Some(max) = self.max_sessions {
            if sessions.len() < max {
                self.saturated.store(false, Ordering::Relaxed);
            }
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
                    *addr,
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
                    client_addr: *addr,
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
        mgr.get_or_create_session(addr);
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
        let seq1 = manager.generate_sequence_number(client1);
        assert_eq!(seq1, 0);
        assert_eq!(manager.session_count(), 1);

        // Second call to same client reuses session
        let seq2 = manager.generate_sequence_number(client1);
        assert_eq!(seq2, 1);
        assert_eq!(manager.session_count(), 1);

        // Different client gets its own session
        let seq3 = manager.generate_sequence_number(client2);
        assert_eq!(seq3, 0);
        assert_eq!(manager.session_count(), 2);
    }

    #[test]
    fn test_session_manager_independent_sequences() {
        let manager = SessionManager::new(None, None);

        let client1 = make_addr(10001);
        let client2 = make_addr(10002);

        // Interleave requests from two clients
        assert_eq!(manager.generate_sequence_number(client1), 0);
        assert_eq!(manager.generate_sequence_number(client2), 0);
        assert_eq!(manager.generate_sequence_number(client1), 1);
        assert_eq!(manager.generate_sequence_number(client1), 2);
        assert_eq!(manager.generate_sequence_number(client2), 1);
        assert_eq!(manager.generate_sequence_number(client1), 3);
        assert_eq!(manager.generate_sequence_number(client2), 2);
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
                    nums.push(manager_clone.generate_sequence_number(client));
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

        manager.generate_sequence_number(client);
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

        manager.generate_sequence_number(client);
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

        manager.generate_sequence_number(client);

        // Session is still active, should not be cleaned up
        assert_eq!(manager.cleanup_stale_sessions(), 0);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_enforces_max_sessions_cap() {
        // Cap of 2: the first two distinct clients are tracked; a third is
        // still answered (returns a session) but NOT stored, so an
        // unauthenticated flood cannot grow the table without bound.
        let manager = SessionManager::new(None, Some(2));
        manager.generate_sequence_number(make_addr(1));
        manager.generate_sequence_number(make_addr(2));
        assert_eq!(manager.session_count(), 2);

        // Third distinct client: over the cap → transient, unstored session.
        let s = manager.get_or_create_session(make_addr(3));
        assert_eq!(
            s.get_id(),
            u32::MAX,
            "over-cap client must get a transient (unstored) session"
        );
        assert_eq!(
            manager.session_count(),
            2,
            "table must not grow past the cap"
        );

        // Existing clients are still served from the table.
        manager.generate_sequence_number(make_addr(1));
        assert_eq!(manager.session_count(), 2);
    }

    #[test]
    fn test_session_cap_reopens_after_cleanup_frees_space() {
        let manager = SessionManager::new(Some(Duration::from_millis(50)), Some(1));
        manager.generate_sequence_number(make_addr(1));
        assert_eq!(manager.session_count(), 1);
        // Over cap now — second client is not stored.
        manager.generate_sequence_number(make_addr(2));
        assert_eq!(manager.session_count(), 1);

        // Let the first entry go stale and clean it up.
        thread::sleep(Duration::from_millis(100));
        assert_eq!(manager.cleanup_stale_sessions(), 1);
        assert_eq!(manager.session_count(), 0);

        // Space freed → a new client is tracked again.
        manager.generate_sequence_number(make_addr(3));
        assert_eq!(manager.session_count(), 1);
    }
}
