use chrono::{DateTime, Utc};

use crate::configuration::ClockFormat;

/// Offset in seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: i64 = 2208988800;

/// Generates timestamp with specified clock format.
///
/// generate_timestamp generates timestamp of the current date and time not taking into account
/// any timezones. Timestamp is generated for UTC.
///
/// ```
/// use stamp_suite::configuration::ClockFormat;
/// use stamp_suite::time::generate_timestamp;
/// let timestamp = generate_timestamp(ClockFormat::NTP);
/// println!("Timestamp is {}", timestamp);
/// ```
pub fn generate_timestamp(cs: ClockFormat) -> u64 {
    let now = Utc::now();

    match cs {
        ClockFormat::NTP => convert_dt_to_ntp(now),
        ClockFormat::PTP => convert_dt_to_ptp(now),
    }
}

/// Converts a wire STAMP timestamp back to nanoseconds since its clock epoch
/// (NTP: 1900-01-01, PTP: 1970-01-01), so two timestamps of the **same**
/// format and era can be subtracted. Use [`timestamp_to_unix_nanos`] for
/// cross-format comparisons or comparisons spanning a seconds-word wrap. The upper 32 bits are
/// whole seconds in both formats; the lower 32 bits are an NTP binary fraction
/// or PTP nanoseconds respectively. Returns `u128` to keep the
/// `seconds * 10^9` product exact for the full 32-bit seconds range.
#[must_use]
pub fn timestamp_to_nanos(value: u64, cs: ClockFormat) -> u128 {
    let secs = u128::from(value >> 32);
    let frac = u128::from(value & 0xFFFF_FFFF);
    let subsec_nanos = match cs {
        // NTP fraction → nanoseconds: frac * 10^9 / 2^32.
        ClockFormat::NTP => (frac * 1_000_000_000) >> 32,
        // PTP lower word already holds nanoseconds.
        ClockFormat::PTP => frac,
    };
    secs * 1_000_000_000 + subsec_nanos
}

/// Decode a wire timestamp onto the Unix epoch, unfolding the 32-bit seconds
/// word to the era nearest `reference_unix_seconds` (within about 68 years).
/// The reference must use the same timescale as the timestamp. PTP's seconds
/// are treated as UTC here; callers must remove a known remote UTC offset.
/// The Z bit specifies encoding, not synchronization or a UTC offset.
/// Returns None for an invalid PTP nanoseconds word (>= one second).
#[must_use]
pub fn timestamp_to_unix_nanos(
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

/// Converts a raw `(seconds, nanoseconds)` pair — e.g. a kernel `timespec`
/// from an `SCM_TIMESTAMPING` control message — into the STAMP wire format.
/// `secs` is seconds since the Unix epoch (CLOCK_REALTIME domain); the
/// arithmetic is identical to [`generate_timestamp`]'s, so kernel and
/// userspace timestamps remain directly subtractable.
#[must_use]
pub fn timestamp_from_parts(secs: i64, nanos: u32, cs: ClockFormat) -> u64 {
    match cs {
        ClockFormat::NTP => {
            let ntp_secs = (secs + NTP_UNIX_OFFSET) as u32;
            let fraction = ((nanos as u64) << 32) / 1_000_000_000;
            ((ntp_secs as u64) << 32) | fraction
        }
        ClockFormat::PTP => ((secs as u64) << 32) | nanos as u64,
    }
}

fn convert_dt_to_ntp(date: DateTime<Utc>) -> u64 {
    let secs = (date.timestamp() + NTP_UNIX_OFFSET) as u32;
    // NTP fraction: nanoseconds * 2^32 / 10^9
    // Use nanoseconds for better precision than microseconds
    let fraction = ((date.timestamp_subsec_nanos() as u64) << 32) / 1_000_000_000;

    ((secs as u64) << 32) | fraction
}

fn convert_dt_to_ptp(date: DateTime<Utc>) -> u64 {
    // Cast to u64 first to avoid signed shift issues with pre-epoch timestamps
    // For pre-epoch (negative) timestamps, the upper 32 bits will wrap correctly
    let secs = date.timestamp() as u64;
    let nanos = date.timestamp_subsec_nanos() as u64;
    (secs << 32) | nanos
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::convert_dt_to_ntp;

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
    fn convert_dt_to_ntp_test() {
        use chrono::{DateTime, Utc};

        const TEST_CASES: &[(i64, u32)] = &[(1_525_987, 0), (0, 0), (2_584_229, 151_000_000)];

        for &(secs, nanos) in TEST_CASES {
            let sample = DateTime::<Utc>::from_timestamp(secs, nanos).expect("Invalid timestamp");
            let test_val = convert_dt_to_ntp(sample);

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
    fn convert_dt_to_ptp_test() {
        use chrono::Utc;

        fn assert_conversion(secs: i64, nanos: u32) {
            let datetime =
                chrono::DateTime::<Utc>::from_timestamp(secs, nanos).expect("Invalid timestamp");
            let ptp_val = convert_dt_to_ptp(datetime);
            assert_eq!(secs, (ptp_val >> 32) as i64);
            assert_eq!(nanos, ptp_val as u32);
        }

        assert_conversion(1_525_987, 0);
        assert_conversion(0, 0);
        assert_conversion(2_584_229, 25_003_600);
    }

    #[test]
    fn timestamp_to_nanos_ptp_exact() {
        // PTP packs (secs << 32) | nanos directly.
        let v = (5u64 << 32) | 250_000_000;
        assert_eq!(timestamp_to_nanos(v, ClockFormat::PTP), 5_250_000_000);
    }

    #[test]
    fn timestamp_to_nanos_ntp_half_second() {
        // NTP fraction 2^31 == 0.5 s.
        let v = (1u64 << 32) | (1u64 << 31);
        assert_eq!(timestamp_to_nanos(v, ClockFormat::NTP), 1_500_000_000);
    }

    #[test]
    fn timestamp_to_nanos_round_trips_ptp_generate() {
        let dt = DateTime::<Utc>::from_timestamp(2_584_229, 25_003_600).unwrap();
        let ptp = convert_dt_to_ptp(dt);
        assert_eq!(
            timestamp_to_nanos(ptp, ClockFormat::PTP),
            2_584_229_025_003_600
        );
    }

    #[test]
    fn timestamp_to_nanos_ntp_round_trips_within_tolerance() {
        // A timestamp from convert_dt_to_ntp converts back to ns-since-NTP-epoch
        // within the ~0.23 ns NTP fractional resolution.
        let dt = DateTime::<Utc>::from_timestamp(2_584_229, 151_000_000).unwrap();
        let ntp = convert_dt_to_ntp(dt);
        let expected = (2_584_229u128 + NTP_UNIX_OFFSET as u128) * 1_000_000_000 + 151_000_000;
        let got = timestamp_to_nanos(ntp, ClockFormat::NTP);
        assert!(
            (got as i128 - expected as i128).abs() <= 1,
            "expected ~{expected} ns, got {got}"
        );
    }

    #[test]
    fn timestamp_from_parts_matches_chrono_converters() {
        // A kernel timespec converted via timestamp_from_parts must yield
        // exactly the same wire value as the chrono-based converters for
        // the same instant — kernel and userspace timestamps stay
        // subtractable on the wire.
        for &(secs, nanos) in &[(0i64, 0u32), (1_525_987, 0), (2_584_229, 151_000_000)] {
            let dt = DateTime::<Utc>::from_timestamp(secs, nanos).unwrap();
            assert_eq!(
                timestamp_from_parts(secs, nanos, ClockFormat::NTP),
                convert_dt_to_ntp(dt),
                "NTP mismatch at {secs}.{nanos}"
            );
            assert_eq!(
                timestamp_from_parts(secs, nanos, ClockFormat::PTP),
                convert_dt_to_ptp(dt),
                "PTP mismatch at {secs}.{nanos}"
            );
        }
    }

    #[test]
    fn test_ntp_timestamp_at_unix_epoch() {
        let unix_epoch = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let ntp_ts = convert_dt_to_ntp(unix_epoch);
        let ntp_secs = ntp_ts >> 32;
        // At Unix epoch, NTP seconds should equal the offset
        assert_eq!(ntp_secs as i64, NTP_UNIX_OFFSET);
    }

    #[test]
    fn test_ptp_timestamp_at_unix_epoch() {
        let unix_epoch = DateTime::<Utc>::from_timestamp(0, 0).unwrap();
        let ptp_ts = convert_dt_to_ptp(unix_epoch);
        // At Unix epoch, PTP timestamp should be 0
        assert_eq!(ptp_ts, 0);
    }
}
