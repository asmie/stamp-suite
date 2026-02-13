//! SNMP MIB handler implementing the STAMP-SUITE-MIB.
//!
//! Maps OID requests to reads from the shared SNMP state.

use std::{net::IpAddr, sync::Arc};

use std::sync::atomic::Ordering;

use super::{
    agentx::{MibHandler, Oid, VarBind, VarBindValue},
    oids,
    state::SnmpState,
};

/// MIB handler that serves the STAMP-SUITE-MIB from shared runtime state.
pub struct StampMibHandler {
    state: Arc<SnmpState>,
}

impl StampMibHandler {
    pub fn new(state: Arc<SnmpState>) -> Self {
        StampMibHandler { state }
    }

    /// Looks up a scalar OID and returns its value.
    fn get_scalar(&self, oid: &Oid) -> Option<VarBindValue> {
        // Reflector Config
        if *oid == oids::stamp_refl_admin_status() {
            let val = if self.state.config.is_reflector { 1 } else { 2 };
            return Some(VarBindValue::Integer(val));
        }
        if *oid == oids::stamp_refl_listen_addr() {
            return Some(VarBindValue::OctetString(ip_to_octets(
                self.state.config.listen_addr,
            )));
        }
        if *oid == oids::stamp_refl_listen_port() {
            return Some(VarBindValue::Gauge32(self.state.config.listen_port as u32));
        }
        if *oid == oids::stamp_refl_auth_mode() {
            let val = if self.state.config.auth_mode == "A" {
                2
            } else {
                1
            };
            return Some(VarBindValue::Integer(val));
        }
        if *oid == oids::stamp_refl_tlv_mode() {
            let val = match self.state.config.tlv_mode {
                crate::configuration::TlvHandlingMode::Echo => 1,
                crate::configuration::TlvHandlingMode::Ignore => 2,
            };
            return Some(VarBindValue::Integer(val));
        }
        if *oid == oids::stamp_refl_stateful() {
            let val = if self.state.config.stateful_reflector {
                1 // TruthValue: true
            } else {
                2 // TruthValue: false
            };
            return Some(VarBindValue::Integer(val));
        }
        if *oid == oids::stamp_refl_session_timeout() {
            return Some(VarBindValue::Gauge32(
                self.state.config.session_timeout as u32,
            ));
        }

        // Reflector Stats
        if *oid == oids::stamp_refl_pkts_received() {
            let val = self
                .state
                .reflector_counters
                .as_ref()
                .map(|c| c.packets_received.load(Ordering::Relaxed))
                .unwrap_or(0);
            return Some(VarBindValue::Counter64(val));
        }
        if *oid == oids::stamp_refl_pkts_reflected() {
            let val = self
                .state
                .reflector_counters
                .as_ref()
                .map(|c| c.packets_reflected.load(Ordering::Relaxed))
                .unwrap_or(0);
            return Some(VarBindValue::Counter64(val));
        }
        if *oid == oids::stamp_refl_pkts_dropped() {
            let val = self
                .state
                .reflector_counters
                .as_ref()
                .map(|c| c.packets_dropped.load(Ordering::Relaxed))
                .unwrap_or(0);
            return Some(VarBindValue::Counter64(val));
        }
        if *oid == oids::stamp_refl_active_sessions() {
            let val = self
                .state
                .session_manager
                .as_ref()
                .map(|sm| sm.session_count())
                .unwrap_or(0);
            return Some(VarBindValue::Gauge32(val as u32));
        }
        if *oid == oids::stamp_refl_uptime() {
            let elapsed = self.state.start_time.elapsed();
            // TimeTicks is in hundredths of a second
            let ticks = (elapsed.as_millis() / 10) as u32;
            return Some(VarBindValue::TimeTicks(ticks));
        }

        // Sender Config
        if *oid == oids::stamp_send_remote_addr() {
            return Some(VarBindValue::OctetString(ip_to_octets(
                self.state.config.remote_addr,
            )));
        }
        if *oid == oids::stamp_send_remote_port() {
            return Some(VarBindValue::Gauge32(self.state.config.remote_port as u32));
        }
        if *oid == oids::stamp_send_local_port() {
            return Some(VarBindValue::Gauge32(self.state.config.listen_port as u32));
        }
        if *oid == oids::stamp_send_pkt_count() {
            return Some(VarBindValue::Gauge32(self.state.config.packet_count as u32));
        }
        if *oid == oids::stamp_send_delay() {
            return Some(VarBindValue::Gauge32(self.state.config.send_delay as u32));
        }
        if *oid == oids::stamp_send_auth_mode() {
            let val = if self.state.config.auth_mode == "A" {
                2
            } else {
                1
            };
            return Some(VarBindValue::Integer(val));
        }

        // Sender Stats
        if let Some(ref stats) = self.state.sender_stats {
            if *oid == oids::stamp_send_pkts_sent() {
                return Some(VarBindValue::Counter32(
                    stats.packets_sent.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_pkts_recv() {
                return Some(VarBindValue::Counter32(
                    stats.packets_received.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_pkts_lost() {
                return Some(VarBindValue::Counter32(
                    stats.packets_lost.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_rtt_min() {
                return Some(VarBindValue::Gauge32(
                    stats.rtt_min_us.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_rtt_max() {
                return Some(VarBindValue::Gauge32(
                    stats.rtt_max_us.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_rtt_avg() {
                return Some(VarBindValue::Gauge32(
                    stats.rtt_avg_us.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_jitter() {
                return Some(VarBindValue::Gauge32(
                    stats.jitter_us.load(Ordering::Relaxed),
                ));
            }
            if *oid == oids::stamp_send_loss_pct() {
                return Some(VarBindValue::Gauge32(
                    stats.loss_pct_x100.load(Ordering::Relaxed),
                ));
            }
        } else {
            // No sender stats — return 0 for sender stat OIDs
            let sender_stat_oids = [
                oids::stamp_send_pkts_sent(),
                oids::stamp_send_pkts_recv(),
                oids::stamp_send_pkts_lost(),
            ];
            if sender_stat_oids.contains(oid) {
                return Some(VarBindValue::Counter32(0));
            }
            let sender_gauge_oids = [
                oids::stamp_send_rtt_min(),
                oids::stamp_send_rtt_max(),
                oids::stamp_send_rtt_avg(),
                oids::stamp_send_jitter(),
                oids::stamp_send_loss_pct(),
            ];
            if sender_gauge_oids.contains(oid) {
                return Some(VarBindValue::Gauge32(0));
            }
        }

        None
    }

    /// Looks up a session table entry OID and returns its value.
    fn get_session_entry(&self, oid: &Oid) -> Option<VarBindValue> {
        let prefix = oids::stamp_refl_session_table_prefix();
        if !oid.starts_with(&prefix) || oid.len() != prefix.len() + 2 {
            return None;
        }

        let column = oid.0[prefix.len()];
        let index = oid.0[prefix.len() + 1];

        let sm = self.state.session_manager.as_ref()?;
        let summaries = sm.session_summaries_extended();

        // Find the session with matching index (session_id)
        let session = summaries.iter().find(|s| s.session_id == index)?;

        match column {
            1 => Some(VarBindValue::Gauge32(session.session_id)),
            2 => Some(VarBindValue::OctetString(ip_to_octets(
                session.client_addr.ip(),
            ))),
            3 => Some(VarBindValue::Gauge32(session.client_addr.port() as u32)),
            4 => Some(VarBindValue::Counter32(session.packets_received)),
            5 => Some(VarBindValue::Counter32(session.packets_transmitted)),
            6 => Some(VarBindValue::Gauge32(session.last_reflected_seq)),
            7 => {
                let elapsed = session.last_active.elapsed();
                let ticks = (elapsed.as_millis() / 10) as u32;
                Some(VarBindValue::TimeTicks(ticks))
            }
            _ => None,
        }
    }

    /// Builds the full sorted list of valid OIDs, including dynamic session table entries.
    fn all_valid_oids(&self) -> Vec<Oid> {
        let mut oids_list = oids::all_scalar_oids();

        // Add session table entries (sorted by column, then index)
        if let Some(ref sm) = self.state.session_manager {
            let summaries = sm.session_summaries_extended();
            let mut indices: Vec<u32> = summaries.iter().map(|s| s.session_id).collect();
            indices.sort();

            for col in 1..=oids::SESSION_TABLE_COLUMNS {
                for &idx in &indices {
                    oids_list.push(oids::stamp_refl_session_entry(col, idx));
                }
            }
        }

        // The list is already sorted because:
        // - Scalar OIDs are pre-sorted
        // - Session table OIDs come after reflector stats (numerically)
        //   but BEFORE sender OIDs. We need to re-sort.
        oids_list.sort();
        oids_list
    }
}

impl MibHandler for StampMibHandler {
    fn get(&self, oid: &Oid) -> VarBind {
        // Try scalar lookup
        if let Some(value) = self.get_scalar(oid) {
            return VarBind {
                oid: oid.clone(),
                value,
            };
        }

        // Try session table lookup
        if let Some(value) = self.get_session_entry(oid) {
            return VarBind {
                oid: oid.clone(),
                value,
            };
        }

        // Unknown OID
        VarBind {
            oid: oid.clone(),
            value: VarBindValue::NoSuchObject,
        }
    }

    fn get_next(&self, oid: &Oid, end: &Oid) -> VarBind {
        let all = self.all_valid_oids();

        // Find the first OID strictly greater than the requested one
        for candidate in &all {
            if candidate > oid {
                // Check if within range (end OID is exclusive upper bound)
                if !end.is_empty() && candidate >= end {
                    break;
                }
                return self.get(candidate);
            }
        }

        VarBind {
            oid: oid.clone(),
            value: VarBindValue::EndOfMibView,
        }
    }
}

/// Converts an IP address to SNMP InetAddress octets.
fn ip_to_octets(addr: IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::TlvHandlingMode;
    use crate::receiver::ReflectorCounters;
    use crate::session::SessionManager;
    use crate::snmp::state::{SenderSnmpStats, SnmpConfig, SnmpState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;

    fn make_test_state(is_reflector: bool) -> Arc<SnmpState> {
        let counters = Arc::new(ReflectorCounters::new());
        let session_manager = Arc::new(SessionManager::new(None));
        let sender_stats = Arc::new(SenderSnmpStats::new());

        Arc::new(SnmpState {
            config: SnmpConfig {
                is_reflector,
                listen_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                listen_port: 862,
                remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote_port: 862,
                auth_mode: "O".to_string(),
                tlv_mode: TlvHandlingMode::Echo,
                stateful_reflector: false,
                session_timeout: 300,
                packet_count: 1000,
                send_delay: 1000,
            },
            reflector_counters: Some(counters),
            session_manager: Some(session_manager),
            start_time: Instant::now(),
            sender_stats: Some(sender_stats),
        })
    }

    #[test]
    fn test_get_scalar_admin_status() {
        let state = make_test_state(true);
        let handler = StampMibHandler::new(state);
        let vb = handler.get(&oids::stamp_refl_admin_status());
        match vb.value {
            VarBindValue::Integer(v) => assert_eq!(v, 1), // enabled
            _ => panic!("Expected Integer"),
        }
    }

    #[test]
    fn test_get_scalar_admin_status_disabled() {
        let state = make_test_state(false);
        let handler = StampMibHandler::new(state);
        let vb = handler.get(&oids::stamp_refl_admin_status());
        match vb.value {
            VarBindValue::Integer(v) => assert_eq!(v, 2), // disabled
            _ => panic!("Expected Integer"),
        }
    }

    #[test]
    fn test_get_unknown_oid() {
        let state = make_test_state(true);
        let handler = StampMibHandler::new(state);
        let unknown = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999, 99, 99]);
        let vb = handler.get(&unknown);
        assert!(matches!(vb.value, VarBindValue::NoSuchObject));
    }

    #[test]
    fn test_get_reflector_stats_counters() {
        let state = make_test_state(true);
        // Simulate some packets
        state
            .reflector_counters
            .as_ref()
            .unwrap()
            .packets_received
            .store(42, Ordering::Relaxed);
        state
            .reflector_counters
            .as_ref()
            .unwrap()
            .packets_reflected
            .store(40, Ordering::Relaxed);
        state
            .reflector_counters
            .as_ref()
            .unwrap()
            .packets_dropped
            .store(2, Ordering::Relaxed);

        let handler = StampMibHandler::new(state);

        match handler.get(&oids::stamp_refl_pkts_received()).value {
            VarBindValue::Counter64(v) => assert_eq!(v, 42),
            _ => panic!("Expected Counter64"),
        }
        match handler.get(&oids::stamp_refl_pkts_reflected()).value {
            VarBindValue::Counter64(v) => assert_eq!(v, 40),
            _ => panic!("Expected Counter64"),
        }
        match handler.get(&oids::stamp_refl_pkts_dropped()).value {
            VarBindValue::Counter64(v) => assert_eq!(v, 2),
            _ => panic!("Expected Counter64"),
        }
    }

    #[test]
    fn test_get_sender_stats() {
        let state = make_test_state(false);
        state
            .sender_stats
            .as_ref()
            .unwrap()
            .packets_sent
            .store(100, Ordering::Relaxed);
        state
            .sender_stats
            .as_ref()
            .unwrap()
            .rtt_avg_us
            .store(500, Ordering::Relaxed);

        let handler = StampMibHandler::new(state);

        match handler.get(&oids::stamp_send_pkts_sent()).value {
            VarBindValue::Counter32(v) => assert_eq!(v, 100),
            _ => panic!("Expected Counter32"),
        }
        match handler.get(&oids::stamp_send_rtt_avg()).value {
            VarBindValue::Gauge32(v) => assert_eq!(v, 500),
            _ => panic!("Expected Gauge32"),
        }
    }

    #[test]
    fn test_get_next_walks_scalars() {
        let state = make_test_state(true);
        let handler = StampMibHandler::new(state);
        let root = oids::stamp_suite_root();
        let end = Oid(vec![]); // no bound

        // First get_next from root should return first scalar
        let vb = handler.get_next(&root, &end);
        assert_eq!(vb.oid, oids::stamp_refl_admin_status());
    }

    #[test]
    fn test_get_next_end_of_mib() {
        let state = make_test_state(true);
        let handler = StampMibHandler::new(state);
        // Past the last OID
        let past_end = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 100000]);
        let end = Oid(vec![]);

        let vb = handler.get_next(&past_end, &end);
        assert!(matches!(vb.value, VarBindValue::EndOfMibView));
    }

    #[test]
    fn test_get_next_session_table() {
        let state = make_test_state(true);
        // Create a session
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
        state
            .session_manager
            .as_ref()
            .unwrap()
            .get_or_create_session(client);

        let handler = StampMibHandler::new(state);

        // Get the session table prefix - walking from here should find entries
        let prefix = oids::stamp_refl_session_table_prefix();
        let end = Oid(vec![]);
        let vb = handler.get_next(&prefix, &end);

        // Should be the first column (index) of the first session (id=0)
        assert_eq!(vb.oid, oids::stamp_refl_session_entry(1, 0));
    }

    #[test]
    fn test_get_listen_addr_ipv4() {
        let state = make_test_state(true);
        let handler = StampMibHandler::new(state);
        let vb = handler.get(&oids::stamp_refl_listen_addr());
        match vb.value {
            VarBindValue::OctetString(v) => assert_eq!(v, vec![0, 0, 0, 0]),
            _ => panic!("Expected OctetString"),
        }
    }

    #[test]
    fn test_get_active_sessions() {
        let state = make_test_state(true);
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
        state
            .session_manager
            .as_ref()
            .unwrap()
            .get_or_create_session(client);

        let handler = StampMibHandler::new(state);
        match handler.get(&oids::stamp_refl_active_sessions()).value {
            VarBindValue::Gauge32(v) => assert_eq!(v, 1),
            _ => panic!("Expected Gauge32"),
        }
    }
}
