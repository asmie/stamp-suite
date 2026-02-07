use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

/// Represents a STAMP measurement session.
///
/// A session tracks the session identifier and maintains an atomic counter
/// for generating unique sequence numbers for each packet.
pub struct Session {
    /// Unique identifier for this session.
    sess_id: u32,
    /// Atomic counter for generating sequential packet numbers.
    curr_seq: AtomicU32,
}

impl Session {
    /// Creates a new session with the given identifier.
    ///
    /// The sequence number counter is initialized to 0.
    pub fn new(id: u32) -> Session {
        Session {
            sess_id: id,
            curr_seq: AtomicU32::new(0),
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
}

impl SessionManager {
    /// Creates a new session manager with an optional timeout.
    ///
    /// If `session_timeout` is `Some`, sessions that have been inactive
    /// for longer than the timeout may be cleaned up via `cleanup_stale_sessions()`.
    pub fn new(session_timeout: Option<Duration>) -> Self {
        SessionManager {
            sessions: RwLock::new(HashMap::new()),
            next_session_id: AtomicU32::new(0),
            session_timeout,
        }
    }

    /// Gets the session for a client, creating a new one if necessary.
    ///
    /// Also updates the last active time for the session.
    pub fn get_or_create_session(&self, client: SocketAddr) -> Arc<Session> {
        // Try read lock first for the common case (session exists)
        {
            let sessions = self.sessions.read().unwrap();
            if let Some(entry) = sessions.get(&client) {
                return Arc::clone(&entry.session);
            }
        }

        // Need to create a new session - acquire write lock
        let mut sessions = self.sessions.write().unwrap();

        // Double-check after acquiring write lock (another thread may have created it)
        if let Some(entry) = sessions.get_mut(&client) {
            entry.last_active = Instant::now();
            return Arc::clone(&entry.session);
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
        session
    }

    /// Generates and returns the next sequence number for a client's session.
    ///
    /// Creates a new session if one doesn't exist for the client.
    pub fn generate_sequence_number(&self, client: SocketAddr) -> u32 {
        let session = self.get_or_create_session(client);

        // Update last_active time
        if let Ok(mut sessions) = self.sessions.write() {
            if let Some(entry) = sessions.get_mut(&client) {
                entry.last_active = Instant::now();
            }
        }

        session.generate_sequence_number()
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

        let mut sessions = self.sessions.write().unwrap();
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
        }
        removed
    }

    /// Returns the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::thread;

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
        let manager = SessionManager::new(None);

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
        let manager = SessionManager::new(None);

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
    fn test_session_manager_get_or_create() {
        let manager = SessionManager::new(None);
        let client = make_addr(10001);

        // Get or create returns same session
        let session1 = manager.get_or_create_session(client);
        let session2 = manager.get_or_create_session(client);

        assert_eq!(session1.get_id(), session2.get_id());
        assert_eq!(Arc::strong_count(&session1), 3); // manager + session1 + session2
    }

    #[test]
    fn test_session_manager_thread_safety() {
        let manager = Arc::new(SessionManager::new(None));
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
        let manager = SessionManager::new(None);
        let client = make_addr(10001);

        manager.generate_sequence_number(client);
        assert_eq!(manager.session_count(), 1);

        // Without timeout, cleanup does nothing
        assert_eq!(manager.cleanup_stale_sessions(), 0);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_cleanup_with_timeout() {
        // Use a very short timeout for testing
        let manager = SessionManager::new(Some(Duration::from_millis(1)));
        let client = make_addr(10001);

        manager.generate_sequence_number(client);
        assert_eq!(manager.session_count(), 1);

        // Wait for timeout
        thread::sleep(Duration::from_millis(10));

        // Cleanup should remove the stale session
        assert_eq!(manager.cleanup_stale_sessions(), 1);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_cleanup_keeps_active() {
        let manager = SessionManager::new(Some(Duration::from_secs(300)));
        let client = make_addr(10001);

        manager.generate_sequence_number(client);

        // Session is still active, should not be cleaned up
        assert_eq!(manager.cleanup_stale_sessions(), 0);
        assert_eq!(manager.session_count(), 1);
    }
}
