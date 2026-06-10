//! HMAC cryptographic operations for STAMP packet authentication.
//!
//! This module provides HMAC-SHA256 computation and verification for
//! authenticated STAMP packets as defined in RFC 8762.

use std::{collections::HashMap, fs, path::Path};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize;

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

    /// Key file or directory has insecure (group/other-accessible) permissions.
    #[error(
        "Key path {path} has insecure permissions (mode {mode:04o}): {detail}. \
         Refusing to use it — restrict it to the owner (key files: chmod 0400; \
         key directory: chmod 0700, or 0750 if group read is required)"
    )]
    InsecurePermissions {
        /// The offending path.
        path: String,
        /// The file mode (low 9 bits).
        mode: u32,
        /// Human-readable description of what is wrong.
        detail: &'static str,
    },
}

/// HMAC key for STAMP authentication.
///
/// Wraps a key and provides methods for computing and verifying
/// HMAC-SHA256 truncated to 16 bytes.
pub struct HmacKey(Vec<u8>);

impl Clone for HmacKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Drop for HmacKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

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
    /// If the file content is valid UTF-8 and parses as hex, it's treated as hex.
    /// Otherwise, it's treated as raw bytes.
    ///
    /// On Unix the key file's permissions are checked on the *opened file
    /// descriptor* (`fstat`), not via a second path lookup. This closes the
    /// TOCTOU window between the check and the read, and — because it inspects
    /// the mode of the exact inode the bytes are read from — also rejects a key
    /// whose (possibly symlinked) target is group- or other-accessible. Any
    /// group/other access bit (`0o077`) is rejected, because a key readable by
    /// anyone but the owner is an exposed secret.
    ///
    /// `O_NOFOLLOW` is deliberately *not* used: secret-injection setups
    /// (Kubernetes secret mounts, systemd credentials) commonly expose the key
    /// file as a symlink, and the `fstat`-on-fd check already validates the
    /// real target's permissions.
    ///
    /// # Arguments
    /// * `path` - Path to the key file
    ///
    /// # Errors
    /// Returns `HmacError::FileReadError` if the file cannot be read.
    /// Returns `HmacError::InsecurePermissions` if the file is group/other
    /// accessible (Unix only).
    /// Returns `HmacError::KeyTooShort` if the key is less than 16 bytes.
    pub fn from_file(path: &Path) -> Result<Self, HmacError> {
        use std::io::Read;

        let mut file = fs::File::open(path).map_err(|e| HmacError::FileReadError(e.to_string()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = file
                .metadata()
                .map_err(|e| HmacError::FileReadError(e.to_string()))?;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(HmacError::InsecurePermissions {
                    path: path.display().to_string(),
                    mode: mode & 0o777,
                    detail: "key file is accessible by group or other",
                });
            }
        }

        let mut raw_bytes = Vec::new();
        file.read_to_end(&mut raw_bytes)
            .map_err(|e| HmacError::FileReadError(e.to_string()))?;

        // Try to parse as hex if it's valid UTF-8
        if let Ok(content) = std::str::from_utf8(&raw_bytes) {
            let trimmed = content.trim();
            if let Ok(key) = Self::from_hex(trimmed) {
                return Ok(key);
            }
        }

        // Fall back to raw bytes
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

/// A set of HMAC keys, optionally keyed by SSID (RFC 8972 §4.1 Session
/// Sender Identifier). Lets a single reflector serve multiple senders
/// without sharing a single key across all of them — useful for
/// multi-tenant deployments and key rotation.
///
/// Lookup order in `for_ssid(s)`:
/// 1. Per-SSID entry for `s` (if present).
/// 2. The `default` key (if set).
/// 3. `None`.
///
/// A receiver configured only with `--hmac-key` / `--hmac-key-file`
/// produces a set with `default: Some(_)` and an empty per-SSID map,
/// which preserves the existing single-key behaviour for SSID 0 and any
/// other SSID.
#[derive(Default)]
pub struct HmacKeySet {
    default: Option<HmacKey>,
    per_ssid: HashMap<u16, HmacKey>,
}

impl HmacKeySet {
    /// Creates an empty key set (no keys at all). Callers should add a
    /// default and/or per-SSID entries before use.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps a single key as the default. Used when the operator passes
    /// `--hmac-key` / `--hmac-key-file` and no `--hmac-key-dir`.
    #[must_use]
    pub fn with_default(key: HmacKey) -> Self {
        Self {
            default: Some(key),
            per_ssid: HashMap::new(),
        }
    }

    /// Inserts (or replaces) the per-SSID key for `ssid`.
    pub fn insert(&mut self, ssid: u16, key: HmacKey) {
        self.per_ssid.insert(ssid, key);
    }

    /// Sets the fallback key used when no per-SSID entry matches.
    pub fn set_default(&mut self, key: HmacKey) {
        self.default = Some(key);
    }

    /// Returns true when no keys are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.default.is_none() && self.per_ssid.is_empty()
    }

    /// Returns the key to use for the given SSID, falling back to the
    /// default if no per-SSID entry exists.
    #[must_use]
    pub fn for_ssid(&self, ssid: u16) -> Option<&HmacKey> {
        self.per_ssid.get(&ssid).or(self.default.as_ref())
    }

    /// Builds a key set by reading every regular file in `dir`. File
    /// names are interpreted as the SSID (hex; trailing `.key` /
    /// `.bin` extensions stripped). A file named `default.key` becomes
    /// the fallback key for SSIDs without an explicit entry.
    ///
    /// File contents follow the same hex-or-bytes contract as
    /// `HmacKey::from_file`.
    ///
    /// # Errors
    /// Returns `HmacError::FileReadError` if the directory cannot be
    /// listed; per-file decode errors (including a key file with insecure
    /// permissions) are logged and skipped so one bad file doesn't take down
    /// the whole reflector.
    /// Returns `HmacError::InsecurePermissions` if the directory itself is
    /// writable by group or other (Unix only) — that would let another user
    /// inject or replace key files.
    pub fn from_dir(dir: &Path) -> Result<Self, HmacError> {
        // The directory may be group-readable (the recommended layout is
        // `0750 root:stamp`), but it must not be group/other *writable*, or an
        // attacker could drop in or replace per-SSID key files.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata =
                fs::metadata(dir).map_err(|e| HmacError::FileReadError(e.to_string()))?;
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(HmacError::InsecurePermissions {
                    path: dir.display().to_string(),
                    mode: mode & 0o777,
                    detail: "key directory is writable by group or other",
                });
            }
        }

        let entries = fs::read_dir(dir).map_err(|e| HmacError::FileReadError(e.to_string()))?;
        let mut set = HmacKeySet::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let key = match HmacKey::from_file(&path) {
                Ok(k) => k,
                Err(e) => {
                    log::warn!("Skipping HMAC key file {:?}: {}", path.display(), e);
                    continue;
                }
            };
            if stem.eq_ignore_ascii_case("default") {
                set.default = Some(key);
                continue;
            }
            match u16::from_str_radix(stem, 16) {
                Ok(ssid) => {
                    set.insert(ssid, key);
                }
                Err(_) => {
                    log::warn!(
                        "Skipping HMAC key file {:?}: filename stem {:?} is \
                         not a hex u16 SSID or 'default'",
                        path.display(),
                        stem
                    );
                }
            }
        }
        Ok(set)
    }
}

/// Performs constant-time comparison of two byte slices.
///
/// Uses the `subtle` crate for audited constant-time semantics.
/// This prevents timing attacks by always comparing all bytes in constant time.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Extracts the authenticated portion of a packet (data before the HMAC field).
#[inline]
fn authenticated_data(packet_bytes: &[u8], hmac_offset: usize) -> &[u8] {
    if hmac_offset <= packet_bytes.len() {
        &packet_bytes[..hmac_offset]
    } else {
        packet_bytes
    }
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
    key.compute(authenticated_data(packet_bytes, hmac_offset))
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
    key.verify(authenticated_data(packet_bytes, hmac_offset), expected)
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

    // -----------------------------------------------------------------------
    // B6: HmacKeySet — per-SSID HMAC keys.

    #[test]
    fn test_keyset_empty_returns_none() {
        let set = HmacKeySet::new();
        assert!(set.is_empty());
        assert!(set.for_ssid(0).is_none());
        assert!(set.for_ssid(1234).is_none());
    }

    #[test]
    fn test_keyset_default_only_returns_default_for_all_ssids() {
        let set = HmacKeySet::with_default(HmacKey::new(vec![0xAA; 16]).unwrap());
        assert!(!set.is_empty());
        let k1 = set.for_ssid(0).expect("default returned for SSID 0");
        let k2 = set
            .for_ssid(0xFFFF)
            .expect("default returned for SSID 0xFFFF");
        // Same bytes — same key.
        assert_eq!(k1.compute(b"x"), k2.compute(b"x"));
    }

    #[test]
    fn test_keyset_per_ssid_overrides_default() {
        let mut set = HmacKeySet::with_default(HmacKey::new(vec![0xAA; 16]).unwrap());
        set.insert(42, HmacKey::new(vec![0xBB; 16]).unwrap());

        // SSID 42 → BB key; SSID 0 → AA default.
        let k_default = set.for_ssid(0).unwrap().compute(b"x");
        let k_42 = set.for_ssid(42).unwrap().compute(b"x");
        let k_99 = set.for_ssid(99).unwrap().compute(b"x");
        assert_ne!(k_default, k_42, "per-SSID key must differ from default");
        assert_eq!(k_default, k_99, "fallback to default for unknown SSID");
    }

    #[test]
    fn test_keyset_unknown_ssid_falls_back_to_default() {
        let mut set = HmacKeySet::new();
        set.insert(7, HmacKey::new(vec![0xCC; 16]).unwrap());

        // No default → unknown SSIDs return None.
        assert!(set.for_ssid(0).is_none());
        assert!(set.for_ssid(99).is_none());
        assert!(set.for_ssid(7).is_some());

        // Add default → unknown SSIDs now resolve.
        set.set_default(HmacKey::new(vec![0xDD; 16]).unwrap());
        assert!(set.for_ssid(0).is_some());
        assert!(set.for_ssid(99).is_some());
    }

    /// Test helper: write `content` to `dir/name` with owner-only (0600)
    /// permissions on Unix so `HmacKey::from_file`'s permission check accepts it.
    fn write_key_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
        use std::io::Write;
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[test]
    fn test_keyset_from_dir_round_trip() {
        let dir = tempfile::tempdir().expect("create tempdir");

        // Write three keys: one default + two per-SSID (owner-only perms).
        write_key_file(
            dir.path(),
            "default.key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_key_file(dir.path(), "002a.key", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); // SSID 42
        write_key_file(dir.path(), "ffff.key", "cccccccccccccccccccccccccccccccc"); // SSID 65535
                                                                                    // Unparseable file — must be skipped, not fatal.
        write_key_file(dir.path(), "notes.txt", "this is a comment file");

        let set = HmacKeySet::from_dir(dir.path()).expect("load");
        assert!(set.for_ssid(42).is_some());
        assert!(set.for_ssid(0xFFFF).is_some());
        assert!(set.for_ssid(0).is_some(), "default key resolves SSID 0");
        // Per-SSID and default must differ.
        let default_digest = set.for_ssid(0).unwrap().compute(b"x");
        let ssid42_digest = set.for_ssid(42).unwrap().compute(b"x");
        assert_ne!(default_digest, ssid42_digest);
    }

    #[cfg(unix)]
    #[test]
    fn test_from_file_accepts_owner_only_key() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = write_key_file(dir.path(), "k.key", "00112233445566778899aabbccddeeff");
        assert!(HmacKey::from_file(&path).is_ok(), "0600 key must load");
    }

    #[cfg(unix)]
    #[test]
    fn test_from_file_rejects_group_or_other_accessible_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = write_key_file(dir.path(), "k.key", "00112233445566778899aabbccddeeff");

        // Group-readable (0640) must be rejected, not merely warned.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            matches!(
                HmacKey::from_file(&path),
                Err(HmacError::InsecurePermissions { .. })
            ),
            "group-readable key file must be rejected"
        );

        // World-readable (0604) likewise.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o604)).unwrap();
        assert!(matches!(
            HmacKey::from_file(&path),
            Err(HmacError::InsecurePermissions { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_from_dir_rejects_group_or_other_writable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("create tempdir");
        write_key_file(
            dir.path(),
            "default.key",
            "00112233445566778899aabbccddeeff",
        );

        // Group-writable directory → key injection risk → rejected.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let result = HmacKeySet::from_dir(dir.path());
        // Restore a sane mode so the tempdir can be cleaned up.
        let _ = std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700));
        assert!(
            matches!(result, Err(HmacError::InsecurePermissions { .. })),
            "group/other-writable key dir must be rejected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_from_dir_allows_group_readable_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("create tempdir");
        write_key_file(
            dir.path(),
            "default.key",
            "00112233445566778899aabbccddeeff",
        );

        // Group-readable but not writable (0750, the recommended layout) is OK.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let result = HmacKeySet::from_dir(dir.path());
        let _ = std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700));
        assert!(result.is_ok(), "0750 key dir must be accepted");
    }
}
