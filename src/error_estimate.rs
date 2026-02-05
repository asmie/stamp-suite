//! Error estimate encoding/decoding for STAMP timestamps (RFC 8762 Section 4.2).
//!
//! The error estimate is a 16-bit field that indicates the estimated error of the
//! timestamp. The format is: S (1 bit) | Scale (6 bits) | Multiplier (8 bits)
//!
//! The error in seconds is calculated as: Multiplier × 2^(-32) × 2^Scale

use thiserror::Error;

/// Error estimate for STAMP timestamps (RFC 8762 Section 4.2).
///
/// 16-bit format: S (1 bit) | Scale (6 bits) | Multiplier (8 bits)
/// Error = Multiplier × 2^(-32) × 2^Scale seconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ErrorEstimate {
    /// Synchronization bit (S). When set to 1, indicates the clock is synchronized.
    pub synchronized: bool,
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
    /// * `scale` - Scale factor (must be 0-63)
    /// * `multiplier` - Multiplier value (0-255)
    ///
    /// # Errors
    /// Returns `ErrorEstimateError::ScaleOutOfRange` if scale > 63.
    pub fn new(synchronized: bool, scale: u8, multiplier: u8) -> Result<Self, ErrorEstimateError> {
        if scale > 63 {
            return Err(ErrorEstimateError::ScaleOutOfRange(scale));
        }
        Ok(Self {
            synchronized,
            scale,
            multiplier,
        })
    }

    /// Creates a default unsynchronized error estimate.
    ///
    /// Returns an error estimate with S=0, Scale=0, Multiplier=1.
    /// This represents a small but non-zero error for unsynchronized clocks.
    #[must_use]
    pub fn unsynchronized() -> Self {
        Self {
            synchronized: false,
            scale: 0,
            multiplier: 1,
        }
    }

    /// Decodes an ErrorEstimate from its 16-bit wire format.
    ///
    /// Wire format:
    /// - Bit 15: S (synchronization) bit
    /// - Bits 14-9: Scale (6 bits) - NOTE: The original plan had this wrong
    /// - Bits 8-0: Multiplier (8 bits) - NOTE: This should be 9 bits based on RFC
    ///
    /// Actually per RFC 8762: bit 15 = S, bits 14-8 = Scale (7 bits but we use 6), bits 7-0 = Multiplier
    /// Let's use: bit 15 = S, bits 14-8 = Scale (6 bits in 14-9), bits 7-0 = Multiplier (8 bits)
    #[must_use]
    pub fn from_wire(value: u16) -> Self {
        let synchronized = (value & 0x8000) != 0;
        let scale = ((value >> 8) & 0x3F) as u8;
        let multiplier = (value & 0xFF) as u8;

        Self {
            synchronized,
            scale,
            multiplier,
        }
    }

    /// Encodes the ErrorEstimate to its 16-bit wire format.
    ///
    /// Wire format:
    /// - Bit 15: S (synchronization) bit
    /// - Bits 14-8: Scale (6 bits, masked to ensure validity)
    /// - Bits 7-0: Multiplier (8 bits)
    #[must_use]
    pub fn to_wire(&self) -> u16 {
        let s_bit = if self.synchronized { 0x8000u16 } else { 0 };
        let scale_bits = ((self.scale as u16) & 0x3F) << 8;
        let multiplier_bits = self.multiplier as u16;

        s_bit | scale_bits | multiplier_bits
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
            (true, 0, 0),
            (false, 0, 1),
            (true, 63, 255),
            (false, 32, 128),
            (true, 10, 100),
        ];

        for (sync, scale, mult) in test_cases {
            let original = ErrorEstimate::new(sync, scale, mult).unwrap();
            let wire = original.to_wire();
            let decoded = ErrorEstimate::from_wire(wire);
            assert_eq!(
                original, decoded,
                "Roundtrip failed for ({}, {}, {})",
                sync, scale, mult
            );
        }
    }

    #[test]
    fn test_sync_bit() {
        // S=1 should set bit 15
        let synced = ErrorEstimate::new(true, 0, 0).unwrap();
        assert_eq!(synced.to_wire() & 0x8000, 0x8000);

        // S=0 should clear bit 15
        let unsynced = ErrorEstimate::new(false, 0, 0).unwrap();
        assert_eq!(unsynced.to_wire() & 0x8000, 0);
    }

    #[test]
    fn test_scale_range() {
        // Scale 0-63 should be valid
        for scale in 0..=63 {
            assert!(ErrorEstimate::new(false, scale, 1).is_ok());
        }

        // Scale > 63 should fail
        let result = ErrorEstimate::new(false, 64, 1);
        assert!(matches!(
            result,
            Err(ErrorEstimateError::ScaleOutOfRange(64))
        ));

        let result = ErrorEstimate::new(false, 255, 1);
        assert!(matches!(
            result,
            Err(ErrorEstimateError::ScaleOutOfRange(255))
        ));
    }

    #[test]
    fn test_error_calculation() {
        // Test: Multiplier=1, Scale=32 -> 1 * 2^(32-32) = 1 * 2^0 = 1 second
        let estimate = ErrorEstimate::new(false, 32, 1).unwrap();
        assert!((estimate.error_seconds() - 1.0).abs() < 1e-10);

        // Test: Multiplier=1, Scale=0 -> 1 * 2^(0-32) = 1 * 2^-32 ≈ 2.33e-10
        let estimate = ErrorEstimate::new(false, 0, 1).unwrap();
        let expected = 2.0_f64.powi(-32);
        assert!((estimate.error_seconds() - expected).abs() < 1e-15);

        // Test: Multiplier=100, Scale=10 -> 100 * 2^(10-32) = 100 * 2^-22
        let estimate = ErrorEstimate::new(false, 10, 100).unwrap();
        let expected = 100.0 * 2.0_f64.powi(-22);
        assert!((estimate.error_seconds() - expected).abs() < 1e-15);
    }

    #[test]
    fn test_unsynchronized_default() {
        let estimate = ErrorEstimate::unsynchronized();
        assert!(!estimate.synchronized);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 1);
    }

    #[test]
    fn test_default_trait() {
        let estimate = ErrorEstimate::default();
        assert!(!estimate.synchronized);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);
    }

    #[test]
    fn test_from_u16() {
        let value: u16 = 0x8A64; // S=1, Scale=0x0A (10), Multiplier=0x64 (100)
        let estimate: ErrorEstimate = value.into();
        assert!(estimate.synchronized);
        assert_eq!(estimate.scale, 10);
        assert_eq!(estimate.multiplier, 100);
    }

    #[test]
    fn test_into_u16() {
        let estimate = ErrorEstimate::new(true, 10, 100).unwrap();
        let value: u16 = estimate.into();
        assert_eq!(value, 0x8A64);
    }

    #[test]
    fn test_wire_format_specific_values() {
        // Test specific wire format values
        // 0x0000: S=0, Scale=0, Mult=0
        let estimate = ErrorEstimate::from_wire(0x0000);
        assert!(!estimate.synchronized);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);

        // 0xFFFF: S=1, Scale=63 (0x3F), Mult=255
        let estimate = ErrorEstimate::from_wire(0xFFFF);
        assert!(estimate.synchronized);
        assert_eq!(estimate.scale, 63);
        assert_eq!(estimate.multiplier, 255);

        // 0x8000: S=1, Scale=0, Mult=0
        let estimate = ErrorEstimate::from_wire(0x8000);
        assert!(estimate.synchronized);
        assert_eq!(estimate.scale, 0);
        assert_eq!(estimate.multiplier, 0);
    }
}
