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
    let fraction = ((date.timestamp_subsec_micros() as u64) * u32::MAX as u64 / 1000000) as u32;

    ((secs as u64) << 32) | fraction as u64
}

fn convert_dt_to_ptp(date: DateTime<Utc>) -> u64 {
    ((date.timestamp() << 32) as u64) | (date.timestamp_subsec_nanos() as u64)
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

            let ntp_frac = test_val as u32;
            let expected_micros = sample.timestamp_subsec_micros();
            let actual_micros = ((ntp_frac as u64) * 1_000_000 / (1u64 << 32)) as u32;
            assert!(
                (expected_micros as i32 - actual_micros as i32).abs() <= 1,
                "Mismatch in fractional micros: expected {}, got {}",
                expected_micros,
                actual_micros
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

    #[test]
    fn test_timestamps_are_monotonic() {
        // Generate multiple timestamps and verify they're non-decreasing
        let mut prev_ntp = 0u64;
        let mut prev_ptp = 0u64;

        for _ in 0..100 {
            let ntp = generate_timestamp(ClockFormat::NTP);
            let ptp = generate_timestamp(ClockFormat::PTP);

            assert!(ntp >= prev_ntp, "NTP timestamps should be monotonic");
            assert!(ptp >= prev_ptp, "PTP timestamps should be monotonic");

            prev_ntp = ntp;
            prev_ptp = ptp;
        }
    }
}
