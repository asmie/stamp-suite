use std::alloc::System;
use crate::configuration::ClockFormat;
use chrono::{Date, DateTime, Timelike, Utc};

const NTP_UNIX_OFFSET : i64 = 2208988800;

pub fn generate_timestamp(cs : ClockFormat) -> u64 {
    let now = Utc::now();

    match cs {
        ClockFormat::NTP => convert_dt_to_ntp(now),
        ClockFormat::PTP => convert_dt_to_ptp(now)
    }
}

fn convert_dt_to_ntp(date : DateTime<Utc>) -> u64 {
    let secs = (date.timestamp() + NTP_UNIX_OFFSET) as u32;
    let fraction = date.timestamp_subsec_millis() / u32::MAX / 1000;

    ((secs as u64) << 32) | fraction as u64
}

fn convert_dt_to_ptp(date : DateTime<Utc>) -> u64 {
    ((date.timestamp() << 32) as u64) | (date.timestamp_subsec_nanos() as u64)
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc, NaiveDateTime};
    use crate::time::convert_dt_to_ntp;
    use super::*;

    #[test]
    fn convert_dt_to_ntp_test() {
        let sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1525987, 0), Utc);
        let test_val = convert_dt_to_ntp(sample);

        assert_eq!(sample.timestamp(), (test_val >> 32) as i64 - NTP_UNIX_OFFSET);
    }

    #[test]
    fn convert_dt_to_ptp_test() {
        let sample = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1525987, 0), Utc);
        let test_val = convert_dt_to_ptp(sample);

        assert_eq!(sample.timestamp(), (test_val >> 32) as i64);
    }
}