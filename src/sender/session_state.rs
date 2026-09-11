//! Draft ext-hdr-13 §7.1 sender state notifications.
use std::{
    collections::{HashSet, VecDeque},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Idle,
    Active,
    Failed,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Summary {
    pub state: State,
    pub loss_threshold: u16,
    pub consecutive_losses: u32,
    pub active_notifications: u64,
    pub failed_notifications: u64,
    pub idle_notifications: u64,
}

struct Probe {
    seq: u32,
    deadline: Instant,
}

pub(super) struct Monitor {
    summary: Summary,
    timeout: Duration,
    transmitting: bool,
    probes: VecDeque<Probe>,
    received: HashSet<u32>,
}

impl Monitor {
    pub(super) fn new(threshold: u16, timeout: Duration) -> Self {
        Self {
            summary: Summary {
                loss_threshold: threshold.max(1),
                ..Summary::default()
            },
            timeout,
            transmitting: false,
            probes: VecDeque::new(),
            received: HashSet::new(),
        }
    }
    pub(super) fn sent(&mut self, seq: u32, now: Instant) {
        self.transmitting = true;
        if !self.timeout.is_zero() {
            self.probes.push_back(Probe {
                seq,
                deadline: now + self.timeout,
            });
            self.received.insert(seq);
        }
    }
    pub(super) fn reply(&mut self, seq: u32, _now: Instant) {
        if !self.transmitting {
            return;
        }
        // A validated reply ends the preceding loss run. Earlier unanswered
        // probes can still count as packet loss, but cannot trigger a new
        // session failure after this newer probe has established connectivity.
        if self.received.contains(&seq) {
            while let Some(probe) = self.probes.pop_front() {
                self.received.remove(&probe.seq);
                if probe.seq == seq {
                    break;
                }
            }
        }
        self.summary.consecutive_losses = 0;
        self.transition(State::Active);
    }
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.probes.front().map(|p| p.deadline)
    }
    pub(super) fn advance(&mut self, now: Instant) {
        while self.probes.front().is_some_and(|p| p.deadline <= now) {
            let probe = self.probes.pop_front().unwrap();
            self.received.remove(&probe.seq);
            if self.summary.state != State::Idle {
                self.summary.consecutive_losses = self.summary.consecutive_losses.saturating_add(1);
                if self.summary.consecutive_losses >= u32::from(self.summary.loss_threshold) {
                    self.transition(State::Failed);
                }
            }
        }
    }
    pub(super) fn idle(&mut self) {
        let notify_idle = self.transmitting && self.summary.state == State::Idle;
        self.transmitting = false;
        self.probes.clear();
        self.received.clear();
        if notify_idle {
            self.summary.idle_notifications += 1;
            tracing::info!(target: "stamp_suite::session_state", state = ?State::Idle, "STAMP session state changed");
        } else {
            self.transition(State::Idle);
        }
    }
    fn transition(&mut self, state: State) {
        if self.summary.state == state {
            return;
        }
        self.summary.state = state;
        match state {
            State::Active => {
                self.summary.active_notifications += 1;
                self.summary.consecutive_losses = 0;
            }
            State::Failed => self.summary.failed_notifications += 1,
            State::Idle => {
                self.summary.idle_notifications += 1;
                self.summary.consecutive_losses = 0;
            }
        }
        tracing::info!(target: "stamp_suite::session_state", state = ?state,
            loss_threshold = self.summary.loss_threshold, "STAMP session state changed");
    }
    pub(super) fn summary(&self) -> Summary {
        self.summary.clone()
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.idle();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_failure_recovery_idle_and_no_repeated_notifications() {
        let now = Instant::now();
        let timeout = Duration::from_secs(1);
        let mut m = Monitor::new(2, timeout);
        m.sent(1, now);
        m.advance(now + timeout);
        assert_eq!(m.summary.state, State::Idle); // No established connectivity yet.
        m.sent(2, now + timeout);
        m.reply(2, now + timeout);
        m.sent(3, now + timeout);
        m.sent(4, now + timeout);
        m.sent(5, now + timeout);
        m.advance(now + timeout * 2);
        assert_eq!(m.summary.failed_notifications, 1);
        m.reply(5, now + timeout * 3);
        assert_eq!(m.summary.active_notifications, 2);
        m.idle();
        m.reply(5, now + timeout * 4);
        assert_eq!(m.summary.state, State::Idle);
        assert_eq!(m.summary.idle_notifications, 1);
    }
    #[test]
    fn successful_probe_separates_losses_even_when_reordered() {
        let now = Instant::now();
        let timeout = Duration::from_secs(1);
        let mut m = Monitor::new(2, timeout);
        m.sent(0, now);
        m.reply(0, now);
        for n in 1..=3 {
            m.sent(n, now);
        }
        m.reply(2, now);
        m.advance(now + timeout);
        assert_eq!(m.summary.failed_notifications, 0);
        assert_eq!(m.summary.consecutive_losses, 1);
    }
}
