use crate::configuration::ClockFormat;

/// Offset in seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: i64 = 2208988800;

/// Returns the current UTC timestamp in the requested STAMP clock format.
///
/// ```
/// use stamp_suite::configuration::ClockFormat;
/// use stamp_suite::time::generate_timestamp;
/// let timestamp = generate_timestamp(ClockFormat::NTP);
/// ```
pub fn generate_timestamp(cs: ClockFormat) -> u64 {
    let (secs, nanos) = unix_now();
    timestamp_from_parts(secs, nanos, cs)
}

/// The system clock as Unix seconds and nanoseconds. A clock set before 1970
/// reads as the epoch.
#[must_use]
pub(crate) fn unix_now() -> (i64, u32) {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    (
        i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX),
        since_epoch.subsec_nanos(),
    )
}

/// Decodes a wire timestamp to nanoseconds since the Unix epoch.
///
/// The 32-bit seconds word is unfolded to the era nearest
/// `reference_unix_seconds` (within about 68 years). The reference must use the
/// same timescale as the timestamp. PTP's seconds are treated as UTC here;
/// callers must remove a known remote UTC offset. The Z bit specifies encoding,
/// not synchronization or a UTC offset. Returns `None` for an invalid PTP
/// nanoseconds word (>= one second).
#[must_use]
pub(crate) fn timestamp_to_unix_nanos(
    value: u64,
    format: ClockFormat,
    reference_unix_seconds: i64,
) -> Option<i128> {
    let fraction = value as u32;
    let (epoch_offset, nanos) = match format {
        ClockFormat::NTP => (
            i128::from(NTP_UNIX_OFFSET),
            (u64::from(fraction) * 1_000_000_000) >> 32,
        ),
        ClockFormat::PTP if fraction < 1_000_000_000 => (0, u64::from(fraction)),
        ClockFormat::PTP => return None,
    };
    let reference = i128::from(reference_unix_seconds);
    let seconds = i128::from(value >> 32) - epoch_offset;
    let era = 1i128 << 32;
    let delta = (seconds - reference + era / 2).rem_euclid(era) - era / 2;
    Some((reference + delta) * 1_000_000_000 + i128::from(nanos))
}

/// Converts a raw `(seconds, nanoseconds)` pair into the STAMP wire format.
///
/// The pair can be a kernel `timespec` from an `SCM_TIMESTAMPING` control
/// message. `secs` is seconds since the Unix epoch (CLOCK_REALTIME domain);
/// [`generate_timestamp`] uses this function, so kernel and userspace
/// timestamps remain directly subtractable.
#[must_use]
pub(crate) fn timestamp_from_parts(secs: i64, nanos: u32, cs: ClockFormat) -> u64 {
    match cs {
        ClockFormat::NTP => {
            let ntp_secs = (secs + NTP_UNIX_OFFSET) as u32;
            let fraction = ((nanos as u64) << 32) / 1_000_000_000;
            ((ntp_secs as u64) << 32) | fraction
        }
        ClockFormat::PTP => ((secs as u64) << 32) | nanos as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_decode_unfolds_both_formats_near_reference() {
        for seconds in [
            -2_208_988_801,
            -1,
            0,
            2_085_978_495,
            2_085_978_496,
            4_294_967_295,
            4_294_967_296,
            8_589_934_592,
        ] {
            for format in [ClockFormat::NTP, ClockFormat::PTP] {
                for nanos in [0, 1, 500_000_000, 999_999_999] {
                    let wire = timestamp_from_parts(seconds, nanos, format);
                    let expected = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
                    for pivot in [seconds - 60, seconds, seconds + 60] {
                        let actual = timestamp_to_unix_nanos(wire, format, pivot).unwrap();
                        assert!(
                            (actual - expected).abs() <= 1,
                            "{format:?} {seconds}.{nanos} reference={pivot}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unix_decode_validates_ptp_fraction_without_restricting_ntp() {
        for fraction in [1_000_000_000u64, u32::MAX as u64] {
            assert_eq!(timestamp_to_unix_nanos(fraction, ClockFormat::PTP, 0), None);
            assert!(timestamp_to_unix_nanos(fraction, ClockFormat::NTP, 0).is_some());
        }
    }

    #[test]
    fn ntp_conversion() {
        const TEST_CASES: &[(i64, u32)] = &[(1_525_987, 0), (0, 0), (2_584_229, 151_000_000)];

        for &(secs, nanos) in TEST_CASES {
            let test_val = timestamp_from_parts(secs, nanos, ClockFormat::NTP);

            let expected_secs = secs + NTP_UNIX_OFFSET;
            let actual_secs = (test_val >> 32) as i64;
            assert_eq!(actual_secs, expected_secs, "Mismatch in seconds field");

            // Verify fractional part: convert NTP fraction back to nanoseconds
            let ntp_frac = test_val as u32;
            let actual_nanos = ((ntp_frac as u64) * 1_000_000_000 / (1u64 << 32)) as u32;
            // Allow 1 nanosecond tolerance due to rounding in NTP fractional conversion.
            // NTP uses 2^32 fractions per second (~0.23ns resolution).
            assert!(
                (nanos as i64 - actual_nanos as i64).abs() <= 1,
                "Mismatch in fractional nanos: expected {}, got {}",
                nanos,
                actual_nanos
            );
        }
    }

    #[test]
    fn ptp_conversion() {
        fn assert_conversion(secs: i64, nanos: u32) {
            let ptp_val = timestamp_from_parts(secs, nanos, ClockFormat::PTP);
            assert_eq!(secs, (ptp_val >> 32) as i64);
            assert_eq!(nanos, ptp_val as u32);
        }

        assert_conversion(1_525_987, 0);
        assert_conversion(0, 0);
        assert_conversion(2_584_229, 25_003_600);
    }

    #[test]
    fn generated_timestamp_tracks_the_system_clock() {
        let (secs, _) = unix_now();
        for format in [ClockFormat::NTP, ClockFormat::PTP] {
            let decoded =
                timestamp_to_unix_nanos(generate_timestamp(format), format, secs).unwrap();
            assert!((decoded / 1_000_000_000 - i128::from(secs)).abs() <= 1);
        }
    }

    #[test]
    fn test_ntp_timestamp_at_unix_epoch() {
        let ntp_ts = timestamp_from_parts(0, 0, ClockFormat::NTP);
        let ntp_secs = ntp_ts >> 32;
        // At Unix epoch, NTP seconds should equal the offset
        assert_eq!(ntp_secs as i64, NTP_UNIX_OFFSET);
    }

    #[test]
    fn test_ptp_timestamp_at_unix_epoch() {
        let ptp_ts = timestamp_from_parts(0, 0, ClockFormat::PTP);
        // At Unix epoch, PTP timestamp should be 0
        assert_eq!(ptp_ts, 0);
    }
}
