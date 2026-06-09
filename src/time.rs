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
/// format can be subtracted to obtain a one-way delay. The upper 32 bits are
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
