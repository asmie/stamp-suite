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
