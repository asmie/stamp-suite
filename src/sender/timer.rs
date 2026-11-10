//! Keep Windows waits precise while a sender is active.

const PERIOD_MS: u32 = 1;

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
}

/// Every successful request must have its own matching release, including
/// when several senders overlap or a run is cancelled/dropped.
pub(super) struct TimerResolution {
    active: bool,
}

impl TimerResolution {
    pub(super) fn request() -> Self {
        // SAFETY: The WinMM API takes an integer period and has no pointer or
        // thread-affinity requirements. Drop matches each successful request.
        let result = unsafe { timeBeginPeriod(PERIOD_MS) };
        if result != 0 {
            log::warn!(
                "Cannot request 1 ms Windows timer resolution (MMRESULT {result}); \
                 probe pacing may be less accurate"
            );
        }
        Self {
            active: result == 0,
        }
    }
}

impl Drop for TimerResolution {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: This releases exactly the successful request owned by
            // this guard, using the same period, on every exit path.
            let result = unsafe { timeEndPeriod(PERIOD_MS) };
            if result != 0 {
                log::warn!("Cannot release Windows timer resolution (MMRESULT {result})");
            }
        }
    }
}
