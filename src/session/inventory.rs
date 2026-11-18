//! Bounded session inventory for the optional control plane.

use std::{collections::BTreeMap, io, ops::Bound::Excluded, ops::Bound::Included};

use super::*;

/// Largest supported page, also enforced for direct library callers.
pub const MAX_SESSION_PAGE_SIZE: usize = 500;

pub(super) struct InventoryIndex {
    nonce: [u8; 16],
    last_id: u64,
    pub(super) entries: BTreeMap<u64, SessionKey>,
}

impl InventoryIndex {
    // The caller holds the table write lock, so its survivors are authoritative,
    // including busy retiring reservations. Keep their original ordinals and
    // leave the manager nonce/creation boundary unchanged.
    pub(super) fn remove_expired(
        &mut self,
        removed: &[u64],
        total_removed: usize,
        survivors: &HashMap<SessionKey, SessionEntry>,
    ) -> Option<BTreeMap<u64, SessionKey>> {
        if survivors.len() <= total_removed / 3 {
            // Rebuild only when at least three quarters of the table disappeared.
            // Return the detached tree for destruction outside the table lock.
            let retained = survivors
                .iter()
                .map(|(key, entry)| (entry.inventory_id, *key))
                .collect();
            Some(std::mem::replace(&mut self.entries, retained))
        } else {
            for id in removed {
                self.entries.remove(id);
            }
            None
        }
    }
}

/// A live page within a fixed creation boundary, not a snapshot of counters.
pub struct SessionPage {
    pub items: Vec<SessionSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPageError {
    InvalidLimit,
    InvalidCursor,
    ExpiredCursor,
    NotEnabled,
}

impl std::fmt::Display for SessionPageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "limit must be between 1 and 500",
            Self::InvalidCursor => "invalid session cursor",
            Self::ExpiredCursor => {
                "session cursor belongs to a different manager; restart the walk"
            }
            Self::NotEnabled => "session inventory index is not enabled",
        })
    }
}

impl std::error::Error for SessionPageError {}

impl SessionManager {
    /// Enable bounded inventory before serving control requests. This one-time
    /// O(n) registration holds the table write lock and retains an ordered key
    /// index. Repeated calls preserve existing cursors. Managers without a
    /// control server need not enable it.
    pub fn enable_session_inventory(&self) -> io::Result<()> {
        if self.inventory_enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let mut inventory = self.inventory.write().unwrap_or_else(|e| e.into_inner());
        if inventory.is_some() {
            return Ok(());
        }
        let mut index = InventoryIndex {
            nonce,
            last_id: 0,
            entries: BTreeMap::new(),
        };
        for (key, entry) in sessions.iter_mut() {
            // A live table cannot contain more than u64::MAX entries on the
            // supported 32/64-bit targets. ID zero denotes an unindexed entry.
            index.last_id += 1;
            entry.inventory_id = index.last_id;
            index.entries.insert(index.last_id, *key);
        }
        *inventory = Some(index);
        self.inventory_enabled.store(true, Ordering::Release);
        Ok(())
    }

    // The caller holds the table write lock. Refuse ordinal exhaustion before
    // allocating a session or consuming its independently wrapping u32 ID.
    pub(super) fn insert_inventory_entry(&self, key: SessionKey) -> Option<u64> {
        if !self.inventory_enabled.load(Ordering::Acquire) {
            return Some(0);
        }
        let mut inventory = self.inventory.write().unwrap_or_else(|e| e.into_inner());
        let index = inventory.as_mut().expect("enabled inventory index");
        index.last_id = index.last_id.checked_add(1)?;
        index.entries.insert(index.last_id, key);
        Some(index.last_id)
    }

    // Only actual table removals reach here; retiring reservations stay indexed.
    pub(super) fn remove_inventory_entry(&self, id: u64) {
        if id != 0 {
            self.inventory
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .as_mut()
                .expect("indexed session")
                .entries
                .remove(&id);
        }
    }

    /// Collect at most `limit` summaries and inspect at most one extra index
    /// entry. Traversal costs O(log n + limit), including hashed table lookups;
    /// response storage is O(limit). No full-table scan or cached snapshot is
    /// created here. Per-session metadata locks may still wait for updates.
    ///
    /// The cursor belongs to this manager's lifetime. New entries after the
    /// first page's boundary are excluded, deletions are skipped, and counters
    /// reflect each page's read time. Existing entries registered at enable time
    /// have an unspecified but stable order; later entries follow creation order.
    pub fn session_summaries_page(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<SessionPage, SessionPageError> {
        if !(1..=MAX_SESSION_PAGE_SIZE).contains(&limit) {
            return Err(SessionPageError::InvalidLimit);
        }
        let decoded = cursor.map(decode_cursor).transpose()?;
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        let inventory = self.inventory.read().unwrap_or_else(|e| e.into_inner());
        let index = inventory.as_ref().ok_or(SessionPageError::NotEnabled)?;
        let (upper, after) = match decoded {
            Some((nonce, upper, after)) => {
                if nonce != index.nonce {
                    return Err(SessionPageError::ExpiredCursor);
                }
                if upper > index.last_id || after == 0 || after >= upper {
                    return Err(SessionPageError::InvalidCursor);
                }
                (upper, after)
            }
            None => (index.last_id, 0),
        };
        // An empty manager has upper == after == 0; BTreeMap accepts that
        // empty (Excluded, Included) range.
        let mut range = index.entries.range((Excluded(after), Included(upper)));
        // Grown on demand rather than sized from the caller's `limit`: a page
        // holds at most MAX_SESSION_PAGE_SIZE rows, so this costs a few
        // reallocations at most, and no request-derived value sizes memory.
        let mut items = Vec::new();
        let mut last = after;
        for (id, key) in range.by_ref().take(limit) {
            let entry = sessions.get(key).expect("inventory entry in session table");
            items.push(self.summarize(*key, entry));
            last = *id;
        }
        let next_cursor = range
            .next()
            .map(|_| format!("v1-{}-{upper:016x}-{last:016x}", hex::encode(index.nonce)));
        Ok(SessionPage { items, next_cursor })
    }
}

fn decode_cursor(cursor: &str) -> Result<([u8; 16], u64, u64), SessionPageError> {
    let invalid = SessionPageError::InvalidCursor;
    // Check ASCII and fixed delimiters before slicing; even adversarial UTF-8
    // cannot panic or request an allocation proportional to the input length.
    let bytes = cursor.as_bytes();
    if bytes.len() != 69
        || !cursor.starts_with("v1-")
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !bytes[3..35].iter().all(u8::is_ascii_hexdigit)
        || !bytes[36..52].iter().all(u8::is_ascii_hexdigit)
        || !bytes[53..69].iter().all(u8::is_ascii_hexdigit)
    {
        return Err(invalid);
    }
    let mut nonce = [0; 16];
    hex::decode_to_slice(&cursor[3..35], &mut nonce).map_err(|_| invalid)?;
    let upper = u64::from_str_radix(&cursor[36..52], 16).map_err(|_| invalid)?;
    let after = u64::from_str_radix(&cursor[53..69], 16).map_err(|_| invalid)?;
    Ok((nonce, upper, after))
}

#[cfg(test)]
mod tests;
