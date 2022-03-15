use std::alloc::System;
use crate::configuration::ClockSource;
use chrono::Utc;

const NTP_UNIX_OFFSET : u64 = 2208988800;

pub fn generate_timestamp(cs : ClockSource) -> u64 {
    match cs {
        ClockSource::NTP => generate_ntp_time(),
        ClockSource::PTP => generate_ptp_time()
    }
}

fn generate_ntp_time() -> u64 {
    let now = Utc::now();

    now.timestamp() as u64
}

fn generate_ptp_time() -> u64 {
    let now = Utc::now();

    now.timestamp() as u64
}