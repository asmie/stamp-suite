//! Access Report retransmission state machine (RFC 8972 §4.6).

use super::*;

/// RFC 8972 §4.6 default retransmission timer value: "The default value of
/// the retransmission timer for the Access Report TLV SHOULD be three
/// seconds." Single source of truth for both the state machine's own tests
/// and the `--access-report-timeout` CLI default (`configuration.rs`).
pub(crate) const DEFAULT_ACCESS_REPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// RFC 8972 §4.6 default retry budget: "This retransmission SHOULD be
/// repeated up to four times before the procedure is aborted." Single
/// source of truth for both the state machine's own tests and the
/// `--access-report-retries` CLI default (`configuration.rs`).
pub(crate) const DEFAULT_ACCESS_REPORT_RETRIES: u32 = 4;

/// Access Report retransmission state (RFC 8972 §4.6).
///
/// The send loop supplies time to [`Self::tick`] and calls [`Self::acknowledge`]
/// on a valid echo. Expiry requests a retransmission until the retry limit;
/// acknowledgment disarms the timer. No separate task or timer is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AccessReportRetransmitState {
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
    /// The retry budget was exhausted without an acknowledgment; the
    /// procedure is aborted and nothing further is sent (RFC 8972 §4.6:
    /// "...before the procedure is aborted"). The measurement itself is
    /// unaffected — only this sub-feature gives up.
    Aborted,
}

impl AccessReportRetransmitState {
    /// Creates a fresh, not-yet-armed state machine using the given
    /// retransmission timer and retry budget (RFC 8972 §4.6: "An
    /// implementation MUST provide control of the retransmission timer
    /// value and the number of retransmissions").
    pub(super) fn new(timeout: Duration, max_retries: u32) -> Self {
        Self {
            timeout,
            max_retries,
            phase: AccessReportPhase::NotStarted,
            retransmissions: 0,
        }
    }

    /// Advances retransmission state before each send-loop iteration.
    /// Returns `true` for the initial send or an expired retry; `false` while
    /// waiting or after acknowledgment/abort.
    pub(super) fn tick(&mut self, now: Instant) -> bool {
        match self.phase {
            AccessReportPhase::NotStarted => {
                self.phase = AccessReportPhase::Armed {
                    attempt: 0,
                    deadline: now + self.timeout,
                };
                true
            }
            AccessReportPhase::Armed { attempt, deadline } => {
                if now < deadline {
                    false
                } else if attempt < self.max_retries {
                    self.retransmissions += 1;
                    self.phase = AccessReportPhase::Armed {
                        attempt: attempt + 1,
                        deadline: now + self.timeout,
                    };
                    true
                } else {
                    self.phase = AccessReportPhase::Aborted;
                    false
                }
            }
            AccessReportPhase::Acknowledged | AccessReportPhase::Aborted => false,
        }
    }

    /// Disarms an armed timer on a reflected Access Report echo (RFC 8972 §4.6).
    /// Other states are unchanged.
    pub(super) fn acknowledge(&mut self) {
        if matches!(self.phase, AccessReportPhase::Armed { .. }) {
            self.phase = AccessReportPhase::Acknowledged;
        }
    }

    /// The current delivery outcome, for reporting in the sender's stats
    /// summary. `NotStarted`/`Armed` both surface as `Pending` — from the
    /// caller's perspective the report has not (yet) been confirmed
    /// delivered either way.
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
    /// that just called [`Self::tick`] and got `false` back (not due yet)
    /// know how long to sleep before calling `tick` again, instead of busy
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
