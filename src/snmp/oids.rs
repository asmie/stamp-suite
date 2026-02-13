//! OID constants for the STAMP-SUITE-MIB.
//!
//! Enterprise OID: 1.3.6.1.4.1.99999 (placeholder PEN).

use super::agentx::Oid;

/// Base enterprise OID: .1.3.6.1.4.1.99999
const BASE: &[u32] = &[1, 3, 6, 1, 4, 1, 99999];

/// Root of the STAMP-SUITE-MIB subtree, used for AgentX registration.
pub fn stamp_suite_root() -> Oid {
    Oid::from_slice(BASE)
}

// -- Reflector Config (.1.1.1.1.*) --

fn refl_config(leaf: u32) -> Oid {
    let mut v = BASE.to_vec();
    v.extend_from_slice(&[1, 1, 1, leaf, 0]); // .0 for scalar instance
    Oid(v)
}

pub fn stamp_refl_admin_status() -> Oid {
    refl_config(1)
}
pub fn stamp_refl_listen_addr() -> Oid {
    refl_config(2)
}
pub fn stamp_refl_listen_port() -> Oid {
    refl_config(3)
}
pub fn stamp_refl_auth_mode() -> Oid {
    refl_config(4)
}
pub fn stamp_refl_tlv_mode() -> Oid {
    refl_config(5)
}
pub fn stamp_refl_stateful() -> Oid {
    refl_config(6)
}
pub fn stamp_refl_session_timeout() -> Oid {
    refl_config(7)
}

// -- Reflector Stats (.1.1.2.*) --

fn refl_stats(leaf: u32) -> Oid {
    let mut v = BASE.to_vec();
    v.extend_from_slice(&[1, 1, 2, leaf, 0]);
    Oid(v)
}

pub fn stamp_refl_pkts_received() -> Oid {
    refl_stats(1)
}
pub fn stamp_refl_pkts_reflected() -> Oid {
    refl_stats(2)
}
pub fn stamp_refl_pkts_dropped() -> Oid {
    refl_stats(3)
}
pub fn stamp_refl_active_sessions() -> Oid {
    refl_stats(4)
}
pub fn stamp_refl_uptime() -> Oid {
    refl_stats(5)
}

// -- Reflector Session Table (.1.1.3.1.*) --

/// Build a session table entry OID: `.1.3.6.1.4.1.99999.1.1.3.1.{column}.{index}`
pub fn stamp_refl_session_entry(column: u32, index: u32) -> Oid {
    let mut v = BASE.to_vec();
    v.extend_from_slice(&[1, 1, 3, 1, column, index]);
    Oid(v)
}

/// Session table entry prefix (for GetNext walking): .1.3.6.1.4.1.99999.1.1.3.1
pub fn stamp_refl_session_table_prefix() -> Oid {
    let mut v = BASE.to_vec();
    v.extend_from_slice(&[1, 1, 3, 1]);
    Oid(v)
}

/// Number of columns in the session table.
pub const SESSION_TABLE_COLUMNS: u32 = 7;

// -- Sender Config (.1.2.1.*) --

fn sender_config(leaf: u32) -> Oid {
    let mut v = BASE.to_vec();
    v.extend_from_slice(&[1, 2, 1, leaf, 0]);
    Oid(v)
}

pub fn stamp_send_remote_addr() -> Oid {
    sender_config(1)
}
pub fn stamp_send_remote_port() -> Oid {
    sender_config(2)
}
pub fn stamp_send_local_port() -> Oid {
    sender_config(3)
}
pub fn stamp_send_pkt_count() -> Oid {
    sender_config(4)
}
pub fn stamp_send_delay() -> Oid {
    sender_config(5)
}
pub fn stamp_send_auth_mode() -> Oid {
    sender_config(6)
}

// -- Sender Stats (.1.2.2.*) --

fn sender_stats(leaf: u32) -> Oid {
    let mut v = BASE.to_vec();
    v.extend_from_slice(&[1, 2, 2, leaf, 0]);
    Oid(v)
}

pub fn stamp_send_pkts_sent() -> Oid {
    sender_stats(1)
}
pub fn stamp_send_pkts_recv() -> Oid {
    sender_stats(2)
}
pub fn stamp_send_pkts_lost() -> Oid {
    sender_stats(3)
}
pub fn stamp_send_rtt_min() -> Oid {
    sender_stats(4)
}
pub fn stamp_send_rtt_max() -> Oid {
    sender_stats(5)
}
pub fn stamp_send_rtt_avg() -> Oid {
    sender_stats(6)
}
pub fn stamp_send_jitter() -> Oid {
    sender_stats(7)
}
pub fn stamp_send_loss_pct() -> Oid {
    sender_stats(8)
}

/// Returns all scalar OIDs in sorted order (for GetNext walking).
///
/// This includes all scalar objects from both reflector and sender subtrees.
/// Session table OIDs are handled dynamically.
pub fn all_scalar_oids() -> Vec<Oid> {
    vec![
        // Reflector Config
        stamp_refl_admin_status(),
        stamp_refl_listen_addr(),
        stamp_refl_listen_port(),
        stamp_refl_auth_mode(),
        stamp_refl_tlv_mode(),
        stamp_refl_stateful(),
        stamp_refl_session_timeout(),
        // Reflector Stats
        stamp_refl_pkts_received(),
        stamp_refl_pkts_reflected(),
        stamp_refl_pkts_dropped(),
        stamp_refl_active_sessions(),
        stamp_refl_uptime(),
        // Sender Config
        stamp_send_remote_addr(),
        stamp_send_remote_port(),
        stamp_send_local_port(),
        stamp_send_pkt_count(),
        stamp_send_delay(),
        stamp_send_auth_mode(),
        // Sender Stats
        stamp_send_pkts_sent(),
        stamp_send_pkts_recv(),
        stamp_send_pkts_lost(),
        stamp_send_rtt_min(),
        stamp_send_rtt_max(),
        stamp_send_rtt_avg(),
        stamp_send_jitter(),
        stamp_send_loss_pct(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_oids_sorted() {
        let oids = all_scalar_oids();
        for i in 1..oids.len() {
            assert!(
                oids[i - 1] < oids[i],
                "OIDs not sorted at index {}: {} >= {}",
                i,
                oids[i - 1],
                oids[i]
            );
        }
    }

    #[test]
    fn test_session_entry_oid() {
        let oid = stamp_refl_session_entry(2, 5);
        // Should be .1.3.6.1.4.1.99999.1.1.3.1.2.5
        assert_eq!(oid.0, vec![1, 3, 6, 1, 4, 1, 99999, 1, 1, 3, 1, 2, 5]);
    }

    #[test]
    fn test_all_oids_under_root() {
        let root = stamp_suite_root();
        for oid in all_scalar_oids() {
            assert!(
                oid.starts_with(&root),
                "OID {} not under root {}",
                oid,
                root
            );
        }
    }

    #[test]
    fn test_session_table_prefix() {
        let prefix = stamp_refl_session_table_prefix();
        let entry = stamp_refl_session_entry(1, 1);
        assert!(entry.starts_with(&prefix));
    }
}
