use std::sync::atomic::{AtomicU32, Ordering};

pub struct Session {
    sess_id: u32,
    curr_seq: AtomicU32,
}

impl Session {
    pub fn new(id: u32) -> Session {
        Session {
            sess_id: id,
            curr_seq: AtomicU32::new(0),
        }
    }

    pub fn get_id(&self) -> u32 {
        self.sess_id
    }

    pub fn generate_sequence_number(&self) -> u32 {
        self.curr_seq.fetch_add(1, Ordering::Relaxed)
    }
}
