//! Access Report retransmission state machine (RFC 8972 §4.6).

use super::*;

/// RFC 8972 §4.6 default timer, also used by `--access-report-timeout`.
pub(crate) const DEFAULT_ACCESS_REPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// RFC 8972 §4.6 default retry budget, also used by `--access-report-retries`.
pub(crate) const DEFAULT_ACCESS_REPORT_RETRIES: u32 = 4;

/// Access Report retransmission state (RFC 8972 §4.6).
///
/// The send loop checks [`Self::due`], calls [`Self::record_sent`] after a successful
/// send, and calls [`Self::acknowledge`] on a valid echo. Expiry requests a
/// retransmission until the retry limit; acknowledgment disarms the timer.
/// No separate task or timer is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AccessReportRetransmitState {
    expected_report: AccessReportTlv,
    pub(super) timeout: Duration,
    pub(super) max_retries: u32,
    pub(super) phase: AccessReportPhase,
    pub(super) retransmissions: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AccessReportPhase {
    /// The Access Report TLV has not been sent yet.
    NotStarted,
    /// Sent (or retransmitted) and awaiting the reflected echo before
    /// `deadline`. `attempt` is 0 for the original send, 1..=`max_retries`
    /// for the Nth retransmission.
    Armed { attempt: u32, deadline: Instant },
    /// The reflector's echo was received before the retry budget was
    /// exhausted; nothing further is sent.
    Acknowledged,
    /// No retries remain. Access Report transmission stops; measurement
    /// continues (RFC 8972 §4.6).
    Aborted,
}

impl AccessReportRetransmitState {
    /// Creates an unarmed state machine with the configured timer and retry
    /// budget (RFC 8972 §4.6).
    pub(super) fn new(
        timeout: Duration,
        max_retries: u32,
        expected_report: AccessReportTlv,
    ) -> Self {
        Self {
            expected_report,
            timeout,
            max_retries,
            phase: AccessReportPhase::NotStarted,
            retransmissions: 0,
        }
    }

    /// Determines whether the next probe should carry the report. Planning a
    /// send does not arm its timer or consume retry budget. Exhaustion after
    /// the last successful attempt still terminates the exchange on expiry.
    pub(super) fn due(&mut self, now: Instant) -> bool {
        match self.phase {
            AccessReportPhase::NotStarted => true,
            AccessReportPhase::Armed { attempt, deadline } if now >= deadline => {
                if attempt < self.max_retries {
                    true
                } else {
                    self.phase = AccessReportPhase::Aborted;
                    false
                }
            }
            _ => false,
        }
    }

    /// Records a successfully sent report that was due. Call only after the
    /// complete datagram was accepted by the transport; failed sends leave the
    /// original deadline and retry budget unchanged.
    pub(super) fn record_sent(&mut self, now: Instant) -> bool {
        if !self.due(now) {
            return false;
        }
        let attempt = match self.phase {
            AccessReportPhase::NotStarted => 0,
            AccessReportPhase::Armed { attempt, .. } => {
                self.retransmissions += 1;
                attempt + 1
            }
            _ => return false,
        };
        self.phase = AccessReportPhase::Armed {
            attempt,
            deadline: now + self.timeout,
        };
        true
    }

    /// Postpones a due retransmission whose datagram was not sent by one timer
    /// period, without spending retry budget. Otherwise the expired deadline
    /// keeps the report due, and every wait would retry at once until the
    /// send-error budget ends the run. An unsent original report needs no
    /// delay: the next scheduled probe carries it.
    pub(super) fn defer(&mut self, now: Instant) {
        if let AccessReportPhase::Armed { deadline, .. } = &mut self.phase {
            if now >= *deadline {
                *deadline = now + self.timeout;
            }
        }
    }

    /// Disarms an armed timer only when the usable echo matches the report
    /// being delivered (RFC 8972 §4.6). Decoding has already ignored Reserved
    /// bits; Access ID and Return Code must both match. Other states are unchanged.
    pub(super) fn acknowledge(&mut self, report: AccessReportTlv) {
        if report == self.expected_report && matches!(self.phase, AccessReportPhase::Armed { .. }) {
            self.phase = AccessReportPhase::Acknowledged;
        }
    }

    /// The current delivery outcome, for reporting in the sender's stats
    /// summary. `NotStarted` and `Armed` both surface as `Pending`: in
    /// neither case has delivery been confirmed.
    pub(super) fn outcome(&self) -> AccessReportOutcome {
        match self.phase {
            AccessReportPhase::Acknowledged => AccessReportOutcome::Acknowledged,
            AccessReportPhase::Aborted => AccessReportOutcome::Aborted,
            AccessReportPhase::NotStarted | AccessReportPhase::Armed { .. } => {
                AccessReportOutcome::Pending
            }
        }
    }

    /// Number of retransmissions actually performed so far.
    pub(super) fn retransmissions(&self) -> u32 {
        self.retransmissions
    }

    /// Whether the original report was sent. Prevents the post-loop wait from
    /// starting an exchange that no probe began.
    pub(super) fn has_started(&self) -> bool {
        !matches!(self.phase, AccessReportPhase::NotStarted)
    }

    /// Whether the procedure is acknowledged or aborted, ending its wait
    /// and retransmission work (RFC 8972 §4.6).
    pub(super) fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            AccessReportPhase::Acknowledged | AccessReportPhase::Aborted
        )
    }

    /// The current retransmission deadline, if still `Armed`. Lets a caller
    /// that just called [`Self::due`] and got `false` back (not due yet)
    /// know how long to sleep before checking `due` again, instead of busy
    /// polling.
    pub(super) fn armed_deadline(&self) -> Option<Instant> {
        match self.phase {
            AccessReportPhase::Armed { deadline, .. } => Some(deadline),
            AccessReportPhase::NotStarted
            | AccessReportPhase::Acknowledged
            | AccessReportPhase::Aborted => None,
        }
    }

    /// Builds the [`AccessReportSummary`] for [`StatsSnapshot::with_access_report`].
    pub(super) fn summary(&self) -> AccessReportSummary {
        AccessReportSummary {
            outcome: self.outcome(),
            retransmissions: self.retransmissions(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defer_postpones_only_an_expired_attempt_and_keeps_its_budget() {
        let now = Instant::now();
        let timeout = Duration::from_secs(3);
        let mut state = AccessReportRetransmitState::new(timeout, 1, AccessReportTlv::new(1, 1));
        state.defer(now);
        assert_eq!(state.phase, AccessReportPhase::NotStarted);

        state.record_sent(now);
        let armed = state.phase;
        state.defer(now + Duration::from_secs(1));
        assert_eq!(state.phase, armed, "a pending timer is left alone");

        let failed_at = now + timeout;
        assert!(state.due(failed_at));
        state.defer(failed_at);
        assert_eq!(
            state.phase,
            AccessReportPhase::Armed {
                attempt: 0,
                deadline: failed_at + timeout,
            }
        );
        assert!(!state.due(failed_at));
        assert!(state.due(failed_at + timeout));
        assert_eq!(state.retransmissions(), 0);
    }

    #[test]
    fn acknowledgement_requires_both_original_report_fields() {
        let now = Instant::now();
        for expected in [AccessReportTlv::new(1, 1), AccessReportTlv::new(2, 255)] {
            for id in 0..=15 {
                for code in 0..=255 {
                    let mut state =
                        AccessReportRetransmitState::new(Duration::from_secs(1), 1, expected);
                    state.record_sent(now);
                    let deadline = state.armed_deadline();
                    let received = AccessReportTlv::new(id, code);
                    state.acknowledge(received);
                    if received == expected {
                        assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);
                        assert!(!state.record_sent(now + Duration::from_secs(1)));
                    } else {
                        assert_eq!(state.outcome(), AccessReportOutcome::Pending);
                        assert_eq!(state.armed_deadline(), deadline);
                        assert_eq!(state.retransmissions(), 0);
                        assert!(state.record_sent(now + Duration::from_secs(1)));
                        assert_eq!(state.retransmissions(), 1);
                        state.acknowledge(expected);
                        assert_eq!(state.outcome(), AccessReportOutcome::Acknowledged);
                    }
                }
            }
        }
    }
}
