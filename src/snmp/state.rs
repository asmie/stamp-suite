//! Shared state types for SNMP sub-agent.
//!
//! These types bridge between the STAMP runtime (receiver/sender) and
//! the SNMP handler, providing thread-safe access to operational data.

use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::{configuration::TlvHandlingMode, receiver::ReflectorCounters, session::SessionManager};

/// Shared state exposed to the SNMP handler.
pub struct SnmpState {
    /// Configuration snapshot (immutable after startup).
    pub config: SnmpConfig,
    /// Reflector counters (shared with receiver backends). None in sender mode.
    pub reflector_counters: Option<Arc<ReflectorCounters>>,
    /// Session manager (shared with receiver backends). None in sender mode.
    pub session_manager: Option<Arc<SessionManager>>,
    /// Start time of the application (for uptime calculation).
    pub start_time: Instant,
    /// Sender statistics (updated atomically during run). None in reflector mode.
    pub sender_stats: Option<Arc<SenderSnmpStats>>,
}

/// Configuration snapshot for SNMP reporting.
pub struct SnmpConfig {
    pub is_reflector: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub auth_mode: String,
    pub tlv_mode: TlvHandlingMode,
    pub stateful_reflector: bool,
    pub session_timeout: u64,
    pub packet_count: u16,
    pub send_delay: u16,
}

/// Sender statistics exposed via SNMP, updated atomically.
///
/// Counters are updated live during the sender run (inc_sent, inc_received,
/// record_rtt) so that SNMP polling sees current values. A final
/// `update_from_snapshot` call at the end sets definitive results.
pub struct SenderSnmpStats {
    pub packets_sent: AtomicU32,
    pub packets_received: AtomicU32,
    pub packets_lost: AtomicU32,
    pub rtt_min_us: AtomicU32,
    pub rtt_max_us: AtomicU32,
    pub rtt_avg_us: AtomicU32,
    pub jitter_us: AtomicU32,
    /// Loss percentage × 100 (e.g. 250 = 2.50%).
    pub loss_pct_x100: AtomicU32,
    /// Running RTT sum in microseconds (internal, for live average computation).
    rtt_sum_us: AtomicU64,
    /// Last observed RTT in microseconds (internal, for jitter computation).
    last_rtt_us: AtomicU32,
}

impl SenderSnmpStats {
    pub fn new() -> Self {
        SenderSnmpStats {
            packets_sent: AtomicU32::new(0),
            packets_received: AtomicU32::new(0),
            packets_lost: AtomicU32::new(0),
            rtt_min_us: AtomicU32::new(0),
            rtt_max_us: AtomicU32::new(0),
            rtt_avg_us: AtomicU32::new(0),
            jitter_us: AtomicU32::new(0),
            loss_pct_x100: AtomicU32::new(0),
            rtt_sum_us: AtomicU64::new(0),
            last_rtt_us: AtomicU32::new(0),
        }
    }

    /// Updates statistics from a completed sender run.
    pub fn update_from_snapshot(&self, snap: SenderStatsSnapshot) {
        self.packets_sent.store(snap.sent, Ordering::Relaxed);
        self.packets_received
            .store(snap.received, Ordering::Relaxed);
        self.packets_lost.store(snap.lost, Ordering::Relaxed);
        self.rtt_min_us.store(snap.rtt_min_us, Ordering::Relaxed);
        self.rtt_max_us.store(snap.rtt_max_us, Ordering::Relaxed);
        self.rtt_avg_us.store(snap.rtt_avg_us, Ordering::Relaxed);
        self.jitter_us.store(snap.jitter_us, Ordering::Relaxed);
        self.loss_pct_x100
            .store(snap.loss_pct_x100, Ordering::Relaxed);
    }

    /// Increments the packets_sent counter.
    pub fn inc_sent(&self) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the packets_received counter.
    pub fn inc_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments the packets_lost counter.
    pub fn inc_lost(&self) {
        self.packets_lost.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a single RTT sample, updating min/max/avg/jitter live.
    ///
    /// Call this after `inc_received()` so that `packets_received` is current
    /// for the average computation.
    pub fn record_rtt(&self, rtt_us: u32) {
        // Update min (0 means no samples yet)
        let current_min = self.rtt_min_us.load(Ordering::Relaxed);
        if current_min == 0 || rtt_us < current_min {
            self.rtt_min_us.store(rtt_us, Ordering::Relaxed);
        }

        // Update max
        let current_max = self.rtt_max_us.load(Ordering::Relaxed);
        if rtt_us > current_max {
            self.rtt_max_us.store(rtt_us, Ordering::Relaxed);
        }

        // Update running average
        let new_sum = self.rtt_sum_us.fetch_add(rtt_us as u64, Ordering::Relaxed) + rtt_us as u64;
        let count = self.packets_received.load(Ordering::Relaxed) as u64;
        if count > 0 {
            self.rtt_avg_us
                .store((new_sum / count) as u32, Ordering::Relaxed);
        }

        // Update jitter (RFC 3550 §A.8: J += (|D| - J) / 16)
        let last = self.last_rtt_us.swap(rtt_us, Ordering::Relaxed);
        if last != 0 {
            let diff = rtt_us.abs_diff(last);
            let j = self.jitter_us.load(Ordering::Relaxed);
            let new_j = if j == 0 {
                diff
            } else {
                ((j as i64) + ((diff as i64 - j as i64) / 16)) as u32
            };
            self.jitter_us.store(new_j, Ordering::Relaxed);
        }
    }
}

/// Snapshot of sender statistics for atomic update.
pub struct SenderStatsSnapshot {
    pub sent: u32,
    pub received: u32,
    pub lost: u32,
    pub rtt_min_us: u32,
    pub rtt_max_us: u32,
    pub rtt_avg_us: u32,
    pub jitter_us: u32,
    pub loss_pct_x100: u32,
}

impl Default for SenderSnmpStats {
    fn default() -> Self {
        Self::new()
    }
}
