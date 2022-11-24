use crate::configuration::ClockFormat;
use chrono::{DateTime, Utc};

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
    use chrono::{DateTime, NaiveDateTime, Utc};

    #[test]
    fn convert_dt_to_ntp_test() {
        let mut sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1525987, 0), Utc);
        let mut test_val = convert_dt_to_ntp(sample);
        assert_eq!(
            sample.timestamp(),
            (test_val >> 32) as i64 - NTP_UNIX_OFFSET
        );
        assert_eq!(
            sample.timestamp_subsec_micros(),
            (test_val as u32) / u32::MAX * 1000
        );

        sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        test_val = convert_dt_to_ntp(sample);
        assert_eq!(
            sample.timestamp(),
            (test_val >> 32) as i64 - NTP_UNIX_OFFSET
        );
        assert_eq!(
            sample.timestamp_subsec_micros(),
            (test_val as u32) / u32::MAX * 1000
        );

        sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(2584229, 151000000), Utc);
        test_val = convert_dt_to_ntp(sample);
        assert_eq!(
            sample.timestamp(),
            (test_val >> 32) as i64 - NTP_UNIX_OFFSET
        );
        assert_eq!(
            sample.timestamp_subsec_micros(),
            ((test_val as u32) as u64 * 1000000u64 / u32::MAX as u64) as u32 + 1
        );
    }

    #[test]
    fn convert_dt_to_ptp_test() {
        let mut sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1525987, 0), Utc);
        let mut test_val = convert_dt_to_ptp(sample);
        assert_eq!(sample.timestamp(), (test_val >> 32) as i64);
        assert_eq!(sample.timestamp_subsec_nanos(), test_val as u32);

        sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
        test_val = convert_dt_to_ptp(sample);
        assert_eq!(sample.timestamp(), (test_val >> 32) as i64);
        assert_eq!(sample.timestamp_subsec_nanos(), test_val as u32);

        sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(2584229, 25003600), Utc);
        test_val = convert_dt_to_ptp(sample);
        assert_eq!(sample.timestamp(), (test_val >> 32) as i64);
        assert_eq!(sample.timestamp_subsec_nanos(), test_val as u32);
    }
}
