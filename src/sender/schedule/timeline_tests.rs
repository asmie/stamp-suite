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
