use super::SendTimeline;
use std::time::Duration;
use tokio::time::Instant;

fn start() -> Instant {
    // Only the arbitrary origin is read from the clock. Every decision below
    // uses supplied instants; elapsed wall time and timer precision are irrelevant.
    Instant::from_std(std::time::Instant::now())
}

fn millis(values: &[u64]) -> Vec<Duration> {
    values.iter().copied().map(Duration::from_millis).collect()
}

fn trace(
    count: u32,
    duration: Option<u32>,
    gap: Duration,
    work: Duration,
) -> (Vec<Duration>, Duration) {
    let start = start();
    let mut now = start;
    let mut timeline = SendTimeline::new(start, count, duration);
    let mut probes = Vec::new();
    // A broken termination decision must fail rather than hang the test.
    for _ in 0..20 {
        if !timeline.can_send(probes.len() as u64, || now) {
            return (probes, now.duration_since(start));
        }
        probes.push(now.duration_since(start));
        now += work;
        let wait = timeline.after_probe(gap, || now);
        now = now.max(wait.deadline);
    }
    panic!("synthetic run did not stop within its expected probe budget");
}

#[test]
fn finite_count_starts_immediately_and_preserves_the_last_gap() {
    let (probes, elapsed) = trace(5, None, Duration::from_millis(10), Duration::from_millis(2));
    assert_eq!(probes, millis(&[0, 10, 20, 30, 40]));
    assert_eq!(elapsed, Duration::from_millis(50));
}

#[test]
fn duration_stops_unlimited_and_larger_counts_and_clamps_the_last_wait() {
    for count in [0, 1000] {
        let (probes, elapsed) = trace(
            count,
            Some(1),
            Duration::from_millis(300),
            Duration::from_millis(20),
        );
        assert_eq!(probes, millis(&[0, 300, 600, 900]));
        assert_eq!(elapsed, Duration::from_secs(1));
    }
}

#[test]
fn earlier_count_limit_does_not_wait_out_the_duration() {
    let (probes, elapsed) = trace(3, Some(1), Duration::from_millis(100), Duration::ZERO);
    assert_eq!(probes, millis(&[0, 100, 200]));
    assert_eq!(elapsed, Duration::from_millis(300));
}

#[test]
fn a_probe_in_flight_can_finish_after_duration_but_no_new_probe_starts() {
    let (probes, elapsed) = trace(
        0,
        Some(1),
        Duration::from_millis(10),
        Duration::from_millis(1100),
    );
    assert_eq!(probes, millis(&[0]));
    assert_eq!(elapsed, Duration::from_millis(1100));
}

#[test]
fn duration_boundary_is_exclusive_to_the_nanosecond() {
    let start = start();
    let timeline = SendTimeline::new(start, 0, Some(1));
    assert!(timeline.can_send(0, || start));
    assert!(timeline.can_send(0, || start + Duration::from_nanos(999_999_999)));
    assert!(!timeline.can_send(0, || start + Duration::from_secs(1)));
    assert!(!timeline.can_send(0, || start + Duration::from_nanos(1_000_000_001)));
}

#[test]
fn count_limits_use_the_full_sent_counter_and_zero_means_unlimited() {
    let start = start();
    let finite = SendTimeline::new(start, u32::MAX, Some(1));
    assert!(finite.can_send(u64::from(u32::MAX) - 1, || start));
    assert!(!finite.can_send(u64::from(u32::MAX), || panic!(
        "count should stop before consulting time"
    )));
    assert!(!finite.can_send(u64::MAX, || panic!("sent counter must not wrap to u32")));
    let unlimited = SendTimeline::new(start, 0, None);
    assert!(unlimited.can_send(u64::MAX, || panic!("no duration needs no clock")));
}

#[test]
fn catch_up_retains_exactly_two_milliseconds_but_resets_above_it() {
    for (completed_ns, first_deadline_ns, next_deadline_ns) in [
        (11_999_999, 10_000_000, 20_000_000),
        (12_000_000, 10_000_000, 20_000_000),
        (12_000_001, 12_000_001, 22_000_001),
        (1_000_000_000, 1_000_000_000, 1_010_000_000),
    ] {
        let start = start();
        let mut timeline = SendTimeline::new(start, 0, None);
        let now = start + Duration::from_nanos(completed_ns);
        let first = timeline.after_probe(Duration::from_millis(10), || now);
        assert_eq!(
            first.deadline,
            start + Duration::from_nanos(first_deadline_ns)
        );
        let next = timeline.after_probe(Duration::from_millis(10), || now);
        assert_eq!(
            next.deadline,
            start + Duration::from_nanos(next_deadline_ns)
        );
    }
}

#[test]
fn changing_intervals_keep_the_timeline_without_processing_drift() {
    let start = start();
    let mut timeline = SendTimeline::new(start, 0, None);
    for (gap_ms, completed_ms, deadline_ms) in [(10, 2, 10), (30, 12, 40), (5, 42, 45)] {
        let wait = timeline.after_probe(Duration::from_millis(gap_ms), || {
            start + Duration::from_millis(completed_ms)
        });
        assert_eq!(wait.deadline, start + Duration::from_millis(deadline_ms));
    }
}

#[test]
fn spin_threshold_uses_the_drawn_gap_even_when_duration_clamps_the_wait() {
    let start = start();
    for (gap_ns, spin) in [
        (0, true),
        (999_999, true),
        (1_000_000, false),
        (1_000_001, false),
    ] {
        let mut timeline = SendTimeline::new(start, 0, None);
        let gap = Duration::from_nanos(gap_ns);
        let wait = timeline.after_probe(gap, || start);
        assert_eq!(wait.deadline, start + gap);
        assert_eq!(wait.spin, spin);
    }
    let mut timeline = SendTimeline::new(start, 0, Some(1));
    let wait = timeline.after_probe(Duration::from_secs(2), || {
        start + Duration::from_micros(999_500)
    });
    assert_eq!(wait.deadline, start + Duration::from_secs(1));
    assert!(
        !wait.spin,
        "a short remaining duration does not change the gap's spin policy"
    );
}

#[test]
fn ce_extends_pending_deadline_and_recovery_cannot_shorten_it() {
    let start = start();
    let mut timeline = SendTimeline::new(start, 0, None);
    let mut interval = Duration::from_millis(20);
    let mut gap = interval;
    timeline.after_probe(gap, || start);
    // Repeated observations at the same limit do not repeatedly extend the
    // wait. Clean feedback cannot cancel a backoff already scheduled.
    for (current_ms, due_ms) in [(40, 40), (40, 40), (30, 40), (80, 80), (20, 80)] {
        let wait = timeline.back_off(&mut gap, &mut interval, Duration::from_millis(current_ms));
        assert_eq!(wait.deadline, start + Duration::from_millis(due_ms));
    }
    // The following probe continues from the corrected timeline, using the
    // recovered controller interval without catching up to the old deadline.
    let wait = timeline.after_probe(Duration::from_millis(20), || {
        start + Duration::from_millis(81)
    });
    assert_eq!(wait.deadline, start + Duration::from_millis(100));
}

#[test]
fn ce_scales_the_existing_poisson_draw_without_resampling() {
    use super::Schedule;
    use crate::configuration::SendSchedule;
    let start = start();
    let mut actual = Schedule::with_seed(SendSchedule::Poisson, 42);
    let mut expected = Schedule::with_seed(SendSchedule::Poisson, 42);
    let base = Duration::from_millis(20);
    for _ in 0..100 {
        let mut timeline = SendTimeline::new(start, 0, None);
        let original = expected.next_gap(base);
        let mut gap = actual.next_gap(base);
        let mut interval = base;
        timeline.after_probe(gap, || start);
        for factor in [2, 4, 8] {
            let wait = timeline.back_off(&mut gap, &mut interval, base * factor);
            assert_eq!(wait.deadline, start + original * factor);
        }
    }
}

#[test]
fn backoff_leaves_spin_wait_when_zero_or_sub_millisecond_gap_grows() {
    let start = start();
    for base in [Duration::ZERO, Duration::from_micros(500)] {
        let mut timeline = SendTimeline::new(start, 0, None);
        let mut interval = base;
        let mut gap = base;
        assert!(timeline.after_probe(gap, || start).spin);
        let wait = timeline.back_off(&mut gap, &mut interval, Duration::from_millis(2));
        assert!(!wait.spin);
        assert_eq!(wait.deadline, start + Duration::from_millis(2));
    }
}

#[test]
fn duration_limit_still_clamps_a_backed_off_deadline() {
    let start = start();
    let mut timeline = SendTimeline::new(start, 0, Some(1));
    let mut interval = Duration::from_millis(500);
    let mut gap = interval;
    timeline.after_probe(gap, || start);
    let wait = timeline.back_off(&mut gap, &mut interval, Duration::from_secs(2));
    assert_eq!(wait.deadline, start + Duration::from_secs(1));
    assert!(!timeline.can_send(1, || wait.deadline));
}

#[test]
fn ce_extends_from_the_reset_timeline_after_a_large_send_delay() {
    let start = start();
    let mut timeline = SendTimeline::new(start, 0, None);
    let mut interval = Duration::from_millis(20);
    let mut gap = interval;
    let completed = start + Duration::from_millis(100);
    assert_eq!(timeline.after_probe(gap, || completed).deadline, completed);
    let wait = timeline.back_off(&mut gap, &mut interval, Duration::from_millis(40));
    assert_eq!(wait.deadline, completed + Duration::from_millis(20));
}

#[test]
fn small_backoff_steps_accumulate_against_the_original_poisson_draw() {
    let start = start();
    let mut timeline = SendTimeline::new(start, 0, None);
    let mut interval = Duration::from_micros(1);
    let mut gap = Duration::from_nanos(100);
    timeline.after_probe(gap, || start);
    for nanos in 1001..=2000 {
        timeline.back_off(&mut gap, &mut interval, Duration::from_nanos(nanos));
    }
    assert_eq!(gap, Duration::from_nanos(200));
    assert_eq!(
        timeline.after_probe(Duration::ZERO, || start).deadline,
        start + Duration::from_nanos(200)
    );
}

#[test]
fn near_unity_controller_backoff_scales_each_new_draw_from_its_own_base() {
    use crate::rate_control::{AimdController, AimdParams};
    let start = start();
    let mut timeline = SendTimeline::new(start, 0, None);
    let mut controller = AimdController::new(AimdParams {
        base_interval: Duration::from_micros(1),
        max_interval: Duration::from_micros(3),
        backoff_factor: 1.0001,
        recovery_step: Duration::from_nanos(1),
    });
    let mut due = start;
    for (draw_ns, expected_ns) in [(100, 200), (300, 450)] {
        let mut gap = Duration::from_nanos(draw_ns);
        let mut interval = controller.current_interval();
        let mut wait = timeline.after_probe(gap, || due);
        for _ in 0..1000 {
            controller.on_ce_observed();
            wait = timeline.back_off(&mut gap, &mut interval, controller.current_interval());
        }
        assert_eq!(gap, Duration::from_nanos(expected_ns));
        due += gap;
        assert_eq!(wait.deadline, due);
    }
}

proptest::proptest! {
    #[test]
    fn backoff_deadline_depends_on_peak_not_feedback_partition(
        base_ns in 0u64..2_000_000,
        drawn_ns in 0u64..2_000_000,
        steps in proptest::collection::vec(0u64..2_000_000, 0..40),
        capped in proptest::bool::ANY,
        delayed in proptest::bool::ANY,
    ) {
        let start = start();
        let stop = capped.then_some(1);
        let completed = start + if delayed { Duration::from_millis(5) } else { Duration::ZERO };
        let original = if base_ns == 0 { Duration::ZERO } else { Duration::from_nanos(drawn_ns) };
        let base = Duration::from_nanos(base_ns);
        let peak = Duration::from_nanos(base_ns + steps.iter().copied().max().unwrap_or(0));
        let mut repeated = SendTimeline::new(start, 0, stop);
        let mut once = SendTimeline::new(start, 0, stop);
        let mut repeated_gap = original;
        let mut once_gap = original;
        let mut repeated_interval = base;
        let mut once_interval = base;
        let mut observed = repeated.after_probe(original, || completed);
        once.after_probe(original, || completed);
        for step in steps {
            observed = repeated.back_off(&mut repeated_gap, &mut repeated_interval,
                Duration::from_nanos(base_ns + step));
        }
        let expected = once.back_off(&mut once_gap, &mut once_interval, peak);
        proptest::prop_assert_eq!(observed.deadline, expected.deadline);
        proptest::prop_assert_eq!(observed.spin, expected.spin);
        proptest::prop_assert_eq!(repeated_gap, once_gap);
        proptest::prop_assert_eq!(repeated_interval, once_interval);
    }
}
