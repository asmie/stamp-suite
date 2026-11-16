//! Keep Windows waits precise while a sender is active.

use std::sync::Mutex;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessInformation, ProcessPowerThrottling, SetProcessInformation,
    PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
    PROCESS_POWER_THROTTLING_STATE,
};

const PERIOD_MS: u32 = 1;
const TIMER_POLICY: u32 = PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;

// Unlike WinMM requests, process policy is not reference counted by Windows.
// Keep it in force until the last of our overlapping senders has finished.
static POLICY: Mutex<Policy> = Mutex::new(Policy {
    users: 0,
    previous: None,
});

struct Policy {
    users: usize,
    previous: Option<PROCESS_POWER_THROTTLING_STATE>,
}

fn read_policy() -> std::io::Result<PROCESS_POWER_THROTTLING_STATE> {
    let mut state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ..Default::default()
    };
    // SAFETY: The pseudo handle is valid for this process, and the writable
    // structure has the version and size required by this information class.
    let result = unsafe {
        GetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (&mut state as *mut PROCESS_POWER_THROTTLING_STATE).cast(),
            std::mem::size_of_val(&state) as u32,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(state)
    }
}

fn write_policy(state: &PROCESS_POWER_THROTTLING_STATE) -> std::io::Result<()> {
    // SAFETY: The API synchronously reads a correctly sized structure. The
    // caller preserves unrelated fields and changes only this process.
    let result = unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            (state as *const PROCESS_POWER_THROTTLING_STATE).cast(),
            std::mem::size_of_val(state) as u32,
        )
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn acquire_policy() -> std::io::Result<()> {
    let mut policy = POLICY.lock().unwrap_or_else(|p| p.into_inner());
    if policy.users == 0 {
        let previous = read_policy()?;
        let active = PROCESS_POWER_THROTTLING_STATE {
            ControlMask: previous.ControlMask | TIMER_POLICY,
            StateMask: previous.StateMask & !TIMER_POLICY,
            ..previous
        };
        // Windows 11 may otherwise ignore timeBeginPeriod for hidden processes.
        // Explicitly honor it without changing CPU power-throttling policy.
        write_policy(&active)?;
        policy.previous = Some(previous);
    }
    policy.users += 1;
    Ok(())
}

fn release_policy() -> std::io::Result<()> {
    let mut policy = POLICY.lock().unwrap_or_else(|p| p.into_inner());
    policy.users -= 1;
    if policy.users == 0 {
        if let Some(previous) = policy.previous.take() {
            // Re-read to retain unrelated changes made while senders ran.
            let current = read_policy()?;
            write_policy(&PROCESS_POWER_THROTTLING_STATE {
                ControlMask: (current.ControlMask & !TIMER_POLICY)
                    | (previous.ControlMask & TIMER_POLICY),
                StateMask: (current.StateMask & !TIMER_POLICY)
                    | (previous.StateMask & TIMER_POLICY),
                ..current
            })?;
        }
    }
    Ok(())
}

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
}

/// Every successful request must have its own matching release, including
/// when several senders overlap or a run is cancelled/dropped.
pub(super) struct TimerResolution {
    active: bool,
    policy_active: bool,
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
        let active = result == 0;
        let policy_active = active
            && match acquire_policy() {
                Ok(()) => true,
                Err(error) => {
                    // Older Windows versions may not support this policy.
                    // Retain the WinMM request as a best-effort fallback.
                    log::warn!(
                        "Cannot make Windows honor sender timer resolution: {error}; \
                         probe pacing may be less accurate"
                    );
                    false
                }
            };
        Self {
            active,
            policy_active,
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
        if self.policy_active {
            if let Err(error) = release_policy() {
                log::warn!("Cannot restore Windows timer-resolution policy: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests;
