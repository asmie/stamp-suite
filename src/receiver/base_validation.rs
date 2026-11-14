//! Optional base-field admission checks, before runtime session mutation.
//! RFC 8762 §4.2.1 selects NTP/PTP via Error Estimate Z. RFC 4656 §4.1.2
//! forbids a zero multiplier; RFC 8877 §4.3 bounds truncated PTP nanoseconds.

pub(super) fn validate(timestamp: u64, estimate: u16) -> Result<(), &'static str> {
    if estimate & 0xff == 0 {
        return Err("zero Error Estimate multiplier");
    }
    if estimate & 0x4000 != 0 && timestamp as u32 >= 1_000_000_000 {
        return Err("PTP nanoseconds outside 0..1000000000");
    }
    // All 64-bit NTP encodings are representable. No reference clock,
    // freshness or monotonicity requirement can be inferred from the wire.
    Ok(())
}

#[cfg(test)]
mod tests;
