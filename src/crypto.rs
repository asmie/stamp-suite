//! HMAC cryptographic operations for STAMP packet authentication.
//!
//! This module provides HMAC-SHA256 computation and verification for
//! authenticated STAMP packets as defined in RFC 8762.

use std::{fs, path::Path};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Minimum key length in bytes for HMAC operations.
pub const MIN_KEY_LENGTH: usize = 16;

/// HMAC output length (truncated to 16 bytes per RFC 8762).
pub const HMAC_OUTPUT_LENGTH: usize = 16;

/// Errors that can occur during HMAC operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum HmacError {
    /// The provided key is too short.
    #[error("Key length {0} is less than minimum required {MIN_KEY_LENGTH} bytes")]
    KeyTooShort(usize),

    /// Invalid hexadecimal string.
    #[error("Invalid hex string: {0}")]
    InvalidHex(String),

    /// Failed to read key from file.
    #[error("Failed to read key file: {0}")]
    FileReadError(String),
}

/// HMAC key for STAMP authentication.
///
/// Wraps a key and provides methods for computing and verifying
/// HMAC-SHA256 truncated to 16 bytes.
#[derive(Clone)]
pub struct HmacKey(Vec<u8>);

impl HmacKey {
    /// Creates a new HmacKey from raw bytes.
    ///
    /// # Arguments
    /// * `key` - The raw key bytes (must be at least 16 bytes)
    ///
    /// # Errors
    /// Returns `HmacError::KeyTooShort` if key is less than 16 bytes.
    pub fn new(key: Vec<u8>) -> Result<Self, HmacError> {
        if key.len() < MIN_KEY_LENGTH {
            return Err(HmacError::KeyTooShort(key.len()));
        }
        Ok(Self(key))
    }

    /// Creates a new HmacKey from a hexadecimal string.
    ///
    /// # Arguments
    /// * `hex_str` - Hexadecimal string representing the key
    ///
    /// # Errors
    /// Returns `HmacError::InvalidHex` if the string is not valid hex.
    /// Returns `HmacError::KeyTooShort` if the decoded key is less than 16 bytes.
    pub fn from_hex(hex_str: &str) -> Result<Self, HmacError> {
        let key = hex::decode(hex_str).map_err(|e| HmacError::InvalidHex(e.to_string()))?;
        Self::new(key)
    }

    /// Creates a new HmacKey by reading from a file.
    ///
    /// The file should contain the key as raw bytes or hex-encoded text.
    /// If the file content starts with valid hex characters and has even length,
    /// it's treated as hex. Otherwise, it's treated as raw bytes.
    ///
    /// # Arguments
    /// * `path` - Path to the key file
    ///
    /// # Errors
    /// Returns `HmacError::FileReadError` if the file cannot be read.
    /// Returns `HmacError::KeyTooShort` if the key is less than 16 bytes.
    pub fn from_file(path: &Path) -> Result<Self, HmacError> {
        let content =
            fs::read_to_string(path).map_err(|e| HmacError::FileReadError(e.to_string()))?;

        let trimmed = content.trim();

        // Try to parse as hex first
        if let Ok(key) = Self::from_hex(trimmed) {
            return Ok(key);
        }

        // Fall back to raw bytes
        let raw_bytes = fs::read(path).map_err(|e| HmacError::FileReadError(e.to_string()))?;

        Self::new(raw_bytes)
    }

    /// Computes HMAC-SHA256 truncated to 16 bytes.
    ///
    /// # Arguments
    /// * `data` - The data to authenticate
    ///
    /// # Returns
    /// A 16-byte array containing the truncated HMAC.
    #[must_use]
    pub fn compute(&self, data: &[u8]) -> [u8; HMAC_OUTPUT_LENGTH] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("HMAC can take key of any size");
        mac.update(data);
        let result = mac.finalize();
        let full_hmac = result.into_bytes();

        // Truncate to 16 bytes
        let mut truncated = [0u8; HMAC_OUTPUT_LENGTH];
        truncated.copy_from_slice(&full_hmac[..HMAC_OUTPUT_LENGTH]);
        truncated
    }

    /// Verifies an HMAC using constant-time comparison.
    ///
    /// # Arguments
    /// * `data` - The data that was authenticated
    /// * `expected` - The expected 16-byte HMAC value
    ///
    /// # Returns
    /// `true` if the HMAC is valid, `false` otherwise.
    #[must_use]
    pub fn verify(&self, data: &[u8], expected: &[u8; HMAC_OUTPUT_LENGTH]) -> bool {
        let computed = self.compute(data);
        // Constant-time comparison to prevent timing attacks
        constant_time_compare(&computed, expected)
    }

    /// Returns the key length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the key is empty (should never happen after construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Performs constant-time comparison of two byte slices.
///
/// This prevents timing attacks by always comparing all bytes.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Computes HMAC for packet data up to the HMAC field offset.
///
/// # Arguments
/// * `key` - The HMAC key
/// * `packet_bytes` - The full packet bytes
/// * `hmac_offset` - The byte offset where the HMAC field begins
///
/// # Returns
/// A 16-byte array containing the truncated HMAC.
#[must_use]
pub fn compute_packet_hmac(
    key: &HmacKey,
    packet_bytes: &[u8],
    hmac_offset: usize,
) -> [u8; HMAC_OUTPUT_LENGTH] {
    let data = if hmac_offset <= packet_bytes.len() {
        &packet_bytes[..hmac_offset]
    } else {
        packet_bytes
    };
    key.compute(data)
}

/// Verifies the HMAC of a packet.
///
/// # Arguments
/// * `key` - The HMAC key
/// * `packet_bytes` - The full packet bytes
/// * `hmac_offset` - The byte offset where the HMAC field begins
/// * `expected` - The expected HMAC value from the packet
///
/// # Returns
/// `true` if the HMAC is valid, `false` otherwise.
#[must_use]
pub fn verify_packet_hmac(
    key: &HmacKey,
    packet_bytes: &[u8],
    hmac_offset: usize,
    expected: &[u8; HMAC_OUTPUT_LENGTH],
) -> bool {
    let data = if hmac_offset <= packet_bytes.len() {
        &packet_bytes[..hmac_offset]
    } else {
        packet_bytes
    };
    key.verify(data, expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_deterministic() {
        let key = HmacKey::new(vec![0u8; 32]).unwrap();
        let data = b"test data";

        let hmac1 = key.compute(data);
        let hmac2 = key.compute(data);

        assert_eq!(hmac1, hmac2);
    }

    #[test]
    fn test_verify_correct_key() {
        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        let data = b"important message";

        let hmac = key.compute(data);
        assert!(key.verify(data, &hmac));
    }

    #[test]
    fn test_verify_wrong_key() {
        let key1 = HmacKey::new(vec![0xab; 32]).unwrap();
        let key2 = HmacKey::new(vec![0xcd; 32]).unwrap();
        let data = b"important message";

        let hmac = key1.compute(data);
        assert!(!key2.verify(data, &hmac));
    }

    #[test]
    fn test_verify_wrong_data() {
        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        let data1 = b"message one";
        let data2 = b"message two";

        let hmac = key.compute(data1);
        assert!(!key.verify(data2, &hmac));
    }

    #[test]
    fn test_key_from_hex() {
        let hex_key = "0123456789abcdef0123456789abcdef";
        let key = HmacKey::from_hex(hex_key).unwrap();

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_key_from_hex_uppercase() {
        let hex_key = "0123456789ABCDEF0123456789ABCDEF";
        let key = HmacKey::from_hex(hex_key).unwrap();

        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_key_from_hex_invalid() {
        let invalid_hex = "not_valid_hex!";
        let result = HmacKey::from_hex(invalid_hex);

        assert!(matches!(result, Err(HmacError::InvalidHex(_))));
    }

    #[test]
    fn test_key_minimum_length() {
        // 15 bytes should fail
        let result = HmacKey::new(vec![0u8; 15]);
        assert!(matches!(result, Err(HmacError::KeyTooShort(15))));

        // 16 bytes should succeed
        let result = HmacKey::new(vec![0u8; 16]);
        assert!(result.is_ok());

        // Hex key too short (14 hex chars = 7 bytes)
        let result = HmacKey::from_hex("0123456789abcd");
        assert!(matches!(result, Err(HmacError::KeyTooShort(7))));
    }

    #[test]
    fn test_verify_packet_hmac() {
        let key = HmacKey::new(vec![0xab; 32]).unwrap();
        let packet = vec![0u8; 112];

        let hmac = compute_packet_hmac(&key, &packet, 96);
        assert!(verify_packet_hmac(&key, &packet, 96, &hmac));
    }

    #[test]
    fn test_constant_time_compare() {
        // Note: This test verifies correctness only. The constant-time property
        // (resistance to timing attacks) cannot be reliably tested in a unit test
        // and must be verified by code inspection or specialized timing analysis tools.
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5]; // Different at last byte
        let d = [1, 2, 3]; // Different length
        let e = [5, 2, 3, 4]; // Different at first byte

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
        assert!(!constant_time_compare(&a, &d));
        assert!(!constant_time_compare(&a, &e));
        assert!(!constant_time_compare(&[], &[1]));
        assert!(constant_time_compare(&[], &[]));
    }

    #[test]
    fn test_different_inputs_different_hmacs() {
        let key = HmacKey::new(vec![0xab; 32]).unwrap();

        let hmac1 = key.compute(b"data1");
        let hmac2 = key.compute(b"data2");

        assert_ne!(hmac1, hmac2);
    }

    #[test]
    fn test_key_len() {
        let key = HmacKey::new(vec![0u8; 32]).unwrap();
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());
    }
}
