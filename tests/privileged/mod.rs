//! Shared policy: optional local probes may skip; a required wire run must fail.
pub fn unavailable(scenario: &str, reason: &str) {
    assert!(
        std::env::var("STAMP_REQUIRE_PRIVILEGED").as_deref() != Ok("1"),
        "[privileged] required scenario {scenario} could not run: {reason}"
    );
    eprintln!("[privileged] SKIP {scenario}: {reason}");
}
