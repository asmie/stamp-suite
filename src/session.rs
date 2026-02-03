use std::sync::atomic::{AtomicU32, Ordering};

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

#[cfg(test)]
mod tests {
    use super::*;
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
}
