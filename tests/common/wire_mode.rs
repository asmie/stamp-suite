//! The three request layouts the wire tests cover: open mode, open mode with
//! a key (signed TLVs), and authenticated mode. Offsets are written out here
//! from RFC 8762 §4.2 and §4.3 and RFC 8972 §3, independently of
//! stamp-suite's packet module. Users also include `common/wire_hmac.rs`.
#![allow(dead_code)] // Each integration target uses a different helper subset.

use crate::wire_hmac;

/// The test key, as bytes and as the `--hmac-key` argument.
pub const KEY: [u8; 16] = [0xab; 16];
pub const KEY_HEX: &str = "abababababababababababababababab";

/// Unauthenticated and authenticated base packet sizes.
const OPEN_BASE: usize = 44;
const AUTH_BASE: usize = 112;
/// Start of the base-packet HMAC in authenticated mode.
const AUTH_HMAC: usize = 96;

/// The discriminants number the modes in evidence file names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Unauthenticated packets and no key.
    Open = 0,
    /// Unauthenticated packets; TLVs carry an HMAC TLV (RFC 8972 §4.8).
    Keyed = 1,
    /// Authenticated packets, with an HMAC TLV when TLVs are present.
    Authenticated = 2,
}

impl Mode {
    pub const ALL: [Mode; 3] = [Mode::Open, Mode::Keyed, Mode::Authenticated];

    /// The reflector has a key: HMAC TLVs are added and checked.
    pub fn keyed(self) -> bool {
        self != Mode::Open
    }

    pub fn authenticated(self) -> bool {
        self == Mode::Authenticated
    }

    /// Base packet size; TLVs start here.
    pub fn base(self) -> usize {
        if self.authenticated() {
            AUTH_BASE
        } else {
            OPEN_BASE
        }
    }

    /// Error Estimate in a Session-Sender packet.
    pub fn error_estimate(self) -> usize {
        if self.authenticated() {
            24
        } else {
            12
        }
    }

    /// Timestamp in either packet.
    pub fn timestamp(self) -> usize {
        if self.authenticated() {
            16
        } else {
            4
        }
    }

    /// Session-Sender Identifier in either packet (RFC 8972 §3).
    pub fn ssid(self) -> usize {
        if self.authenticated() {
            26
        } else {
            14
        }
    }

    /// Session-Sender Sequence Number echoed in a reflected packet.
    pub fn sender_sequence(self) -> usize {
        if self.authenticated() {
            48
        } else {
            24
        }
    }

    /// Session-Sender Timestamp echoed in a reflected packet.
    pub fn sender_timestamp(self) -> usize {
        if self.authenticated() {
            64
        } else {
            28
        }
    }

    /// Session-Sender TTL/Hop Limit in a reflected packet.
    pub fn sender_ttl(self) -> usize {
        if self.authenticated() {
            80
        } else {
            40
        }
    }

    /// Command-line arguments that select this mode, for either role.
    pub fn key_args(self) -> &'static [&'static str] {
        match self {
            Mode::Open => &[],
            Mode::Keyed => &["--hmac-key", KEY_HEX],
            Mode::Authenticated => &["--hmac-key", KEY_HEX, "--auth-mode", "A"],
        }
    }

    /// A Session-Sender base packet with `sequence` and an Error Estimate
    /// multiplier of one, unsigned.
    pub fn request(self, sequence: u32) -> Vec<u8> {
        let mut bytes = vec![0; self.base()];
        bytes[..4].copy_from_slice(&sequence.to_be_bytes());
        bytes[self.error_estimate() + 1] = 1;
        bytes
    }

    /// HMAC TLV value over the sequence number and the TLVs from the base
    /// to the end of `packet` (RFC 8972 §4.8).
    pub fn tlv_digest(self, packet: &[u8]) -> [u8; 16] {
        let mut covered = packet[..4].to_vec();
        covered.extend_from_slice(&packet[self.base()..]);
        wire_hmac::digest(&KEY, &covered)
    }

    /// Appends a Session-Sender HMAC TLV (U flag set) in keyed modes.
    pub fn append_hmac_tlv(self, packet: &mut Vec<u8>) {
        if self.keyed() {
            let digest = self.tlv_digest(packet);
            packet.extend_from_slice(&[0x80, 8, 0, 16]);
            packet.extend_from_slice(&digest);
        }
    }

    /// Writes the base-packet HMAC in authenticated mode (RFC 8762 §4.2.2).
    pub fn seal(self, packet: &mut [u8]) {
        if self.authenticated() {
            let digest = wire_hmac::digest(&KEY, &packet[..AUTH_HMAC]);
            packet[AUTH_HMAC..AUTH_BASE].copy_from_slice(&digest);
        }
    }

    /// Checks the base-packet HMAC in authenticated mode.
    pub fn assert_sealed(self, packet: &[u8]) {
        if self.authenticated() {
            assert_eq!(
                &packet[AUTH_HMAC..AUTH_BASE],
                &wire_hmac::digest(&KEY, &packet[..AUTH_HMAC]),
                "{self:?}: base-packet HMAC"
            );
        }
    }

    /// Checks, in keyed modes, that `packet` ends with a reflected HMAC TLV
    /// (no flags) over everything before it.
    pub fn assert_hmac_tlv(self, packet: &[u8]) {
        if self.keyed() {
            let pos = packet.len() - 20;
            assert_eq!(&packet[pos..pos + 4], &[0, 8, 0, 16], "{self:?}: HMAC TLV");
            assert_eq!(
                &packet[pos + 4..],
                &self.tlv_digest(&packet[..pos]),
                "{self:?}: HMAC TLV value"
            );
        }
    }
}
