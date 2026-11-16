use super::TimerResolution;
use std::process::Command;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessInformation, ProcessPowerThrottling, SetProcessInformation,
    PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION, PROCESS_POWER_THROTTLING_STATE,
};

fn read_policy() -> PROCESS_POWER_THROTTLING_STATE {
    let mut state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ..Default::default()
    };
    // SAFETY: The current-process pseudo handle and correctly sized writable
    // structure remain valid throughout this synchronous call.
    assert_ne!(
        unsafe {
            GetProcessInformation(
                GetCurrentProcess(),
                ProcessPowerThrottling,
                (&mut state as *mut PROCESS_POWER_THROTTLING_STATE).cast(),
                std::mem::size_of_val(&state) as u32,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    state
}

fn write_policy(state: &PROCESS_POWER_THROTTLING_STATE) {
    // SAFETY: The API reads this correctly sized structure synchronously and
    // changes only this disposable test process, never the host's policy.
    assert_ne!(
        unsafe {
            SetProcessInformation(
                GetCurrentProcess(),
                ProcessPowerThrottling,
                (state as *const PROCESS_POWER_THROTTLING_STATE).cast(),
                std::mem::size_of_val(state) as u32,
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

fn assert_policy(expected: &PROCESS_POWER_THROTTLING_STATE) {
    let actual = read_policy();
    assert_eq!(actual.ControlMask, expected.ControlMask);
    assert_eq!(actual.StateMask, expected.StateMask);
}

#[test]
fn timer_policy_is_scoped_to_overlapping_senders_and_cancelled_tasks() {
    const CHILD: &str = "STAMP_TIMER_POLICY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Timer policy is process-wide. Do not disturb other senders running
        // concurrently in the library test process.
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sender::timer::tests::timer_policy_is_scoped_to_overlapping_senders_and_cancelled_tasks",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let timer = PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION;
    let cpu = PROCESS_POWER_THROTTLING_EXECUTION_SPEED;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (control, state) in [(0, 0), (timer, 0), (timer, timer)] {
        let original = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: control,
            StateMask: state,
        };
        write_policy(&original);
        assert_policy(&original);
        let first = TimerResolution::request();
        assert!(first.active);
        let mut active = PROCESS_POWER_THROTTLING_STATE {
            ControlMask: control | timer,
            StateMask: state & !timer,
            ..original
        };
        assert_policy(&active);
        let second = TimerResolution::request();
        assert!(second.active);
        drop(first);
        assert_policy(&active);
        // A change to a different process policy while a sender is active
        // must survive restoring the timer policy.
        active.ControlMask |= cpu;
        write_policy(&active);
        drop(second);
        let restored = PROCESS_POWER_THROTTLING_STATE {
            ControlMask: original.ControlMask | cpu,
            ..original
        };
        assert_policy(&restored);
        runtime.block_on(async {
            let (ready, wait) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let guard = TimerResolution::request();
                assert!(guard.active);
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(guard);
            });
            wait.await.unwrap();
            assert_policy(&active);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        });
        assert_policy(&restored);
    }
}
