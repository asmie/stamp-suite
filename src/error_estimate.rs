//! Error estimate encoding/decoding for STAMP timestamps (RFC 8762 Section 4.2).
//!
//! The error estimate is a 16-bit field that indicates the estimated error of the
//! timestamp. The format is: S (1 bit) | Z (1 bit) | Scale (6 bits) | Multiplier (8 bits)
//!
//! - S (bit 15): Synchronization flag. 1 = clock is synchronized.
//! - Z (bit 14): Timestamp format flag. 0 = NTP format, 1 = PTP format.
//! - Scale (bits 13-8): Scale factor (0-63).
//! - Multiplier (bits 7-0): Multiplier value (0-255).
//!
//! The error in seconds is calculated as: Multiplier × 2^(-32) × 2^Scale

use thiserror::Error;

use crate::clock_format::ClockFormat;

/// Error estimate for STAMP timestamps (RFC 8762 Section 4.2).
///
/// 16-bit format: S (1 bit) | Z (1 bit) | Scale (6 bits) | Multiplier (8 bits)
/// - S = Synchronization flag (1 = synchronized)
/// - Z = Timestamp format (0 = NTP, 1 = PTP)
/// - Error = Multiplier × 2^(-32) × 2^Scale seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ErrorEstimate {
    /// Synchronization bit (S). When set to 1, indicates the clock is synchronized.
    pub synchronized: bool,
    /// Timestamp format bit (Z). When 0, NTP format is used. When 1, PTP format is used.
    pub z_flag: bool,
    /// Scale factor (0-63). Used in the error calculation as 2^Scale.
    pub scale: u8,
    /// Multiplier (0-255). The base value for error calculation.
    pub multiplier: u8,
}

/// Errors that can occur when creating or parsing an ErrorEstimate.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ErrorEstimateError {
    /// Scale value exceeds the maximum of 63.
    #[error("Scale value {0} exceeds maximum of 63")]
    ScaleOutOfRange(u8),
}

impl ErrorEstimate {
    /// Creates a new ErrorEstimate with validation.
    ///
    /// # Arguments
    /// * `synchronized` - Whether the clock is synchronized (S bit)
    /// * `z_flag` - Timestamp format flag (Z bit): false = NTP, true = PTP
    /// * `scale` - Scale factor (must be 0-63)
    /// * `multiplier` - Multiplier value (0-255)
    ///
    /// # Errors
    /// Returns `ErrorEstimateError::ScaleOutOfRange` if scale > 63.
    pub fn new(
        synchronized: bool,
        z_flag: bool,
        scale: u8,
        multiplier: u8,
    ) -> Result<Self, ErrorEstimateError> {
        if scale > 63 {
            return Err(ErrorEstimateError::ScaleOutOfRange(scale));
        }
        Ok(Self {
            synchronized,
            z_flag,
            scale,
            multiplier,
        })
    }

    /// Creates a new ErrorEstimate using a ClockFormat to determine the Z flag.
    ///
    /// # Arguments
    /// * `synchronized` - Whether the clock is synchronized (S bit)
    /// * `clock_format` - Clock format (NTP or PTP), determines the Z flag
    /// * `scale` - Scale factor (must be 0-63)
    /// * `multiplier` - Multiplier value (0-255)
    ///
    /// # Errors
    /// Returns `ErrorEstimateError::ScaleOutOfRange` if scale > 63.
    pub fn with_clock_format(
        synchronized: bool,
        clock_format: ClockFormat,
        scale: u8,
        multiplier: u8,
    ) -> Result<Self, ErrorEstimateError> {
        let z_flag = clock_format == ClockFormat::PTP;
        Self::new(synchronized, z_flag, scale, multiplier)
    }

    /// Creates a default unsynchronized error estimate with NTP format.
    ///
    /// Returns an error estimate with S=0, Z=0 (NTP), Scale=0, Multiplier=1.
    /// This represents a small but non-zero error for unsynchronized clocks.
    #[must_use]
    pub fn unsynchronized() -> Self {
        Self {
            synchronized: false,
            z_flag: false,
            scale: 0,
            multiplier: 1,
        }
    }

    /// Creates a default unsynchronized error estimate with the specified clock format.
    ///
    /// Returns an error estimate with S=0, Z based on clock_format, Scale=0, Multiplier=1.
    #[must_use]
    pub fn unsynchronized_with_format(clock_format: ClockFormat) -> Self {
        Self {
            synchronized: false,
            z_flag: clock_format == ClockFormat::PTP,
            scale: 0,
            multiplier: 1,
        }
    }

    /// Returns the clock format based on the Z flag.
    #[must_use]
    pub fn clock_format(&self) -> ClockFormat {
        if self.z_flag {
            ClockFormat::PTP
        } else {
            ClockFormat::NTP
        }
    }

    /// Decodes an ErrorEstimate from its 16-bit wire format.
    ///
    /// Wire format (RFC 8762):
    /// - Bit 15: S (synchronization) bit
    /// - Bit 14: Z (timestamp format) bit - 0 = NTP, 1 = PTP
    /// - Bits 13-8: Scale (6 bits)
    /// - Bits 7-0: Multiplier (8 bits)
    #[must_use]
    pub fn from_wire(value: u16) -> Self {
        let synchronized = (value & 0x8000) != 0;
        let z_flag = (value & 0x4000) != 0;
        let scale = ((value >> 8) & 0x3F) as u8;
        let multiplier = (value & 0xFF) as u8;

        Self {
            synchronized,
            z_flag,
            scale,
            multiplier,
        }
    }

    /// Encodes the ErrorEstimate to its 16-bit wire format.
    ///
    /// Wire format (RFC 8762):
    /// - Bit 15: S (synchronization) bit
    /// - Bit 14: Z (timestamp format) bit - 0 = NTP, 1 = PTP
    /// - Bits 13-8: Scale (6 bits, masked to ensure validity)
    /// - Bits 7-0: Multiplier (8 bits)
    #[must_use]
    pub fn to_wire(&self) -> u16 {
        let s_bit = if self.synchronized { 0x8000u16 } else { 0 };
        let z_bit = if self.z_flag { 0x4000u16 } else { 0 };
        let scale_bits = ((self.scale as u16) & 0x3F) << 8;
        let multiplier_bits = self.multiplier as u16;

        s_bit | z_bit | scale_bits | multiplier_bits
    }

    /// Calculates the error in seconds.
    ///
    /// The formula is: Multiplier × 2^(-32) × 2^Scale = Multiplier × 2^(Scale - 32)
    #[must_use]
    pub fn error_seconds(&self) -> f64 {
        let exponent = (self.scale as i32) - 32;
        (self.multiplier as f64) * 2.0_f64.powi(exponent)
    }
}

impl From<u16> for ErrorEstimate {
    fn from(value: u16) -> Self {
        Self::from_wire(value)
    }
}

impl From<ErrorEstimate> for u16 {
    fn from(estimate: ErrorEstimate) -> Self {
        estimate.to_wire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_format_roundtrip() {
        // Test various combinations
        let test_cases = [
            (true, false, 0, 0),    // S=1, Z=0 (NTP)
            (false, false, 0, 1),   // S=0, Z=0 (NTP)
            (true, true, 63, 255),  // S=1, Z=1 (PTP), max scale/multiplier
            (false, true, 32, 128), // S=0, Z=1 (PTP)
            (true, false, 10, 100), // S=1, Z=0 (NTP)
        ];

        for (sync, z, scale, mult) in test_cases {
            let original = ErrorEstimate::new(sync, z, scale, mult).unwrap();
            let wire = original.to_wire();
            let decoded = ErrorEstimate::from_wire(wire);
            assert_eq!(
                original, decoded,
                "Roundtrip failed for ({}, {}, {}, {})",
                sync, z, scale, mult
            );
        }
    }

    #[test]
    fn test_sync_bit() {
        // S=1 should set bit 15
        let synced = ErrorEstimate::new(true, false, 0, 0).unwrap();
        assert_eq!(synced.to_wire() & 0x8000, 0x8000);

        // S=0 should clear bit 15
        let unsynced = ErrorEstimate::new(false, false, 0, 0).unwrap();
        assert_eq!(unsynced.to_wire() & 0x8000, 0);
    }

    #[test]
    fn test_z_flag_bit() {
        // Z=1 (PTP) should set bit 14
        let ptp = ErrorEstimate::new(false, true, 0, 0).unwrap();
        assert_eq!(ptp.to_wire() & 0x4000, 0x4000);

        // Z=0 (NTP) should clear bit 14
        let ntp = ErrorEstimate::new(false, false, 0, 0).unwrap();
        assert_eq!(ntp.to_wire() & 0x4000, 0);
    }

    #[test]
    fn test_scale_range() {
        // Scale 0-63 should be valid
        for scale in 0..=63 {
            assert!(ErrorEstimate::new(false, false, scale, 1).is_ok());
        }

        // Scale > 63 should fail
        let result = ErrorEstimate::new(false, false, 64, 1);
        assert!(matches!(
            result,
            Err(ErrorEstimateError::ScaleOutOfRange(64))
        ));

        let result = ErrorEstimate::new(false, false, 255, 1);
        assert!(matches!(
            result,
            Err(ErrorEstimateError::ScaleOutOfRange(255))
        ));
    }

    #[test]
    fn test_error_calculation() {
        // Test: Multiplier=1, Scale=32 -> 1 * 2^(32-32) = 1 * 2^0 = 1 second
        let estimate = ErrorEstimate::new(false, false, 32, 1).unwrap();
        assert!((estimate.error_seconds() - 1.0).abs() < 1e-10);

        // Test: Multiplier=1, Scale=0 -> 1 * 2^(0-32) = 1 * 2^-32 ≈ 2.33e-10
        let estimate = ErrorEstimate::new(false, false, 0, 1).unwrap();
        let expected = 2.0_f64.powi(-32);
        assert!((estimate.error_seconds() - expected).abs() < 1e-15);

        // Test: Multiplier=100, Scale=10 -> 100 * 2^(10-32) = 100 * 2^-22
        let estimate = ErrorEstimate::new(false, false, 10, 100).unwrap();
        let expected = 100.0 * 2.0_f64.powi(-22);
        assert!((estimate.error_seconds() - expected).abs() < 1e-15);
    }

    #[test]
    fn test_unsynchronized_default() {
        let estimate = ErrorEstimate::unsynchronized();
        assert!(!estimate.synchronized);
        assert!(!estimate.z_flag);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 1);
    }

    #[test]
    fn test_unsynchronized_with_format() {
        let ntp = ErrorEstimate::unsynchronized_with_format(ClockFormat::NTP);
        assert!(!ntp.synchronized);
        assert!(!ntp.z_flag);
        assert_eq!(ntp.clock_format(), ClockFormat::NTP);

        let ptp = ErrorEstimate::unsynchronized_with_format(ClockFormat::PTP);
        assert!(!ptp.synchronized);
        assert!(ptp.z_flag);
        assert_eq!(ptp.clock_format(), ClockFormat::PTP);
    }

    #[test]
    fn test_with_clock_format() {
        let ntp = ErrorEstimate::with_clock_format(true, ClockFormat::NTP, 10, 50).unwrap();
        assert!(ntp.synchronized);
        assert!(!ntp.z_flag);
        assert_eq!(ntp.scale, 10);
        assert_eq!(ntp.multiplier, 50);

        let ptp = ErrorEstimate::with_clock_format(false, ClockFormat::PTP, 20, 100).unwrap();
        assert!(!ptp.synchronized);
        assert!(ptp.z_flag);
        assert_eq!(ptp.scale, 20);
        assert_eq!(ptp.multiplier, 100);
    }

    #[test]
    fn test_clock_format_method() {
        let ntp = ErrorEstimate::new(false, false, 0, 0).unwrap();
        assert_eq!(ntp.clock_format(), ClockFormat::NTP);

        let ptp = ErrorEstimate::new(false, true, 0, 0).unwrap();
        assert_eq!(ptp.clock_format(), ClockFormat::PTP);
    }

    #[test]
    fn test_default_trait() {
        let estimate = ErrorEstimate::default();
        assert!(!estimate.synchronized);
        assert!(!estimate.z_flag);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);
    }

    #[test]
    fn test_from_u16() {
        let value: u16 = 0xCA64; // S=1, Z=1 (PTP), Scale=0x0A (10), Multiplier=0x64 (100)
        let estimate: ErrorEstimate = value.into();
        assert!(estimate.synchronized);
        assert!(estimate.z_flag);
        assert_eq!(estimate.scale, 10);
        assert_eq!(estimate.multiplier, 100);
    }

    #[test]
    fn test_into_u16() {
        let estimate = ErrorEstimate::new(true, true, 10, 100).unwrap();
        let value: u16 = estimate.into();
        assert_eq!(value, 0xCA64); // S=1, Z=1, Scale=10, Multiplier=100
    }

    #[test]
    fn test_wire_format_specific_values() {
        // Test specific wire format values
        // 0x0000: S=0, Z=0, Scale=0, Mult=0
        let estimate = ErrorEstimate::from_wire(0x0000);
        assert!(!estimate.synchronized);
        assert!(!estimate.z_flag);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);

        // 0xFFFF: S=1, Z=1, Scale=63 (0x3F), Mult=255
        let estimate = ErrorEstimate::from_wire(0xFFFF);
        assert!(estimate.synchronized);
        assert!(estimate.z_flag);
        assert_eq!(estimate.scale, 63);
        assert_eq!(estimate.multiplier, 255);

        // 0x8000: S=1, Z=0, Scale=0, Mult=0
        let estimate = ErrorEstimate::from_wire(0x8000);
        assert!(estimate.synchronized);
        assert!(!estimate.z_flag);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);

        // 0x4000: S=0, Z=1, Scale=0, Mult=0
        let estimate = ErrorEstimate::from_wire(0x4000);
        assert!(!estimate.synchronized);
        assert!(estimate.z_flag);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);
    }

    #[test]
    fn test_ntp_wire_format_backward_compat() {
        // Old format without Z flag: S=1, Scale=10, Multiplier=100 -> 0x8A64
        // New format with Z=0: S=1, Z=0, Scale=10, Multiplier=100 -> 0x8A64
        // The values should be the same for NTP (Z=0)
        let estimate = ErrorEstimate::new(true, false, 10, 100).unwrap();
        assert_eq!(estimate.to_wire(), 0x8A64);
    }
}
