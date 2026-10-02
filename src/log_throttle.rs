//! Throttled diagnostics for events a remote peer can trigger on every packet.
//!
//! An unthrottled warning per bad packet turns a packet flood into a log
//! flood. Each call site counts its own occurrences and reports the 1st,
//! 10th, 100th, ... one; the rest go to `debug` (or are dropped for stderr).

use std::sync::atomic::{AtomicU64, Ordering};

/// Occurrence counter for one call site.
pub struct Throttle(AtomicU64);

impl Throttle {
    /// A counter with no recorded occurrences.
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Records one occurrence. Returns its ordinal when it should be reported.
    pub fn hit(&self) -> Option<u64> {
        let n = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        is_power_of_ten(n).then_some(n)
    }
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new()
    }
}

fn is_power_of_ten(mut n: u64) -> bool {
    while n >= 10 && n % 10 == 0 {
        n /= 10;
    }
    n == 1
}

/// `log::warn!` on the 1st, 10th, 100th, ... occurrence at this call site,
/// `log::debug!` otherwise.
#[macro_export]
#[doc(hidden)]
macro_rules! warn_throttled {
    ($($arg:tt)+) => {{
        static THROTTLE: $crate::log_throttle::Throttle = $crate::log_throttle::Throttle::new();
        match THROTTLE.hit() {
            Some(1) => log::warn!($($arg)+),
            Some(n) => log::warn!("{} ({n} occurrences)", format_args!($($arg)+)),
            None => log::debug!($($arg)+),
        }
    }};
}

/// `eprintln!` on the 1st, 10th, 100th, ... occurrence at this call site.
#[macro_export]
#[doc(hidden)]
macro_rules! eprintln_throttled {
    ($($arg:tt)+) => {{
        static THROTTLE: $crate::log_throttle::Throttle = $crate::log_throttle::Throttle::new();
        match THROTTLE.hit() {
            Some(1) => eprintln!($($arg)+),
            Some(n) => eprintln!("{} ({n} occurrences)", format_args!($($arg)+)),
            None => {}
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_powers_of_ten_only() {
        let throttle = Throttle::new();
        let reported: Vec<u64> = (0..1000).filter_map(|_| throttle.hit()).collect();
        assert_eq!(reported, [1, 10, 100, 1000]);
    }
}
