//! Sender and reflector packet layouts (RFC 8762 and RFC 8972).
//!
//! Each base packet's layout is declared once with `wire_packet!`, which
//! generates the struct, its big-endian `to_bytes`/`from_bytes` and the
//! lenient parsers, and checks at compile time that the fields tile the packet.
//! [`Extended`](crate::packets::Extended) adds the TLVs that follow a base
//! packet.

use thiserror::Error;

use crate::tlv::{TlvError, TlvList};

/// Receive-buffer capacity for the 16-bit UDP length limit (IPv4 allows 65507
/// payload bytes). Accommodates padded probes without datagram truncation.
pub(crate) const MAX_UDP_PAYLOAD: usize = 65535;

/// Size of an unauthenticated base packet in both directions
/// (RFC 8762 §4.2.1, §4.3.1).
pub const UNAUTH_BASE_SIZE: usize = 44;

/// Size of an authenticated base packet in both directions
/// (RFC 8762 §4.2.2, §4.3.2).
pub const AUTH_BASE_SIZE: usize = 112;

/// Offset of the HMAC field in authenticated packets of either direction.
/// The HMAC covers the octets before it (RFC 8762 §4.4).
pub const AUTH_HMAC_OFFSET: usize = 96;

/// Offset of the SSID field in unauthenticated packets (RFC 8972 §3).
pub(crate) const UNAUTH_SSID_OFFSET: usize = 14;

/// Offset of the SSID field in authenticated packets (RFC 8972 §3).
pub(crate) const AUTH_SSID_OFFSET: usize = 26;

/// Errors that can occur during packet parsing or processing.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// Buffer is too small for the packet type.
    #[error("Buffer too small: expected at least {expected} bytes, got {actual}")]
    BufferTooSmall { expected: usize, actual: usize },

    /// TLV parsing or validation error.
    #[error("TLV error: {0}")]
    TlvError(#[from] TlvError),
}

// ============================================================================
// Wire format parsing helpers
// ============================================================================

/// Checks that buffer has at least `expected` bytes.
#[inline]
fn check_size(buf: &[u8], expected: usize) -> Result<(), PacketError> {
    if buf.len() < expected {
        Err(PacketError::BufferTooSmall {
            expected,
            actual: buf.len(),
        })
    } else {
        Ok(())
    }
}

/// A fixed-width big-endian wire field.
trait WireField: Sized {
    const SIZE: usize;
    /// Writes the field at the start of `buf`.
    fn put(&self, buf: &mut [u8]);
    /// Reads the field from the start of `buf`.
    fn get(buf: &[u8]) -> Self;
}

macro_rules! wire_int {
    ($($ty:ty),*) => {$(
        impl WireField for $ty {
            const SIZE: usize = std::mem::size_of::<$ty>();
            fn put(&self, buf: &mut [u8]) {
                buf[..Self::SIZE].copy_from_slice(&self.to_be_bytes());
            }
            fn get(buf: &[u8]) -> Self {
                // `wire_packet!` passes a slice of at least SIZE bytes.
                Self::from_be_bytes(buf[..Self::SIZE].try_into().unwrap())
            }
        }
    )*};
}
wire_int!(u8, u16, u32, u64);

impl<const N: usize> WireField for [u8; N] {
    const SIZE: usize = N;
    fn put(&self, buf: &mut [u8]) {
        buf[..N].copy_from_slice(self);
    }
    fn get(buf: &[u8]) -> Self {
        buf[..N].try_into().unwrap()
    }
}

/// A fixed-size STAMP base packet. [`Extended`] is generic over it.
///
/// The packet types also have inherent `to_bytes`/`from_bytes` methods, so
/// callers that name a concrete type need not import this trait.
pub trait BasePacket: Sized + Copy {
    /// Wire size in octets.
    const SIZE: usize;
    /// The serialized packet, `[u8; SIZE]`.
    type Bytes: AsRef<[u8]> + AsMut<[u8]>;

    /// Serializes the packet in big-endian wire format.
    fn to_wire(&self) -> Self::Bytes;

    /// Parses a packet; fails if `buf` is shorter than `SIZE`.
    ///
    /// # Errors
    /// Returns [`PacketError::BufferTooSmall`] for a short buffer.
    fn from_wire(buf: &[u8]) -> Result<Self, PacketError>;

    /// Parses a packet, zero-filling missing octets (RFC 8762 §4.6), and
    /// returns the zero-filled buffer the fields were read from. HMAC
    /// verification uses that buffer.
    fn from_wire_lenient(buf: &[u8]) -> (Self, Self::Bytes);
}

/// Declares a base packet: the struct, its wire codec, and a compile-time
/// check that each field starts where the previous one ends and that the
/// fields fill exactly `$size` octets.
macro_rules! wire_packet {
    (
        $(#[$meta:meta])*
        pub struct $name:ident ($size:expr) {
            $( $(#[$fmeta:meta])* $field:ident: $ty:ty = $at:expr, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub struct $name {
            $( $(#[$fmeta])* pub $field: $ty, )*
        }

        const _: () = {
            let mut at = 0;
            $( assert!($at == at, "field offset does not follow the previous field"); at += <$ty as WireField>::SIZE; )*
            assert!(at == $size, "fields do not fill the packet");
        };

        impl BasePacket for $name {
            const SIZE: usize = $size;
            type Bytes = [u8; $size];

            fn to_wire(&self) -> [u8; $size] {
                let mut buf = [0u8; $size];
                $( self.$field.put(&mut buf[$at..]); )*
                buf
            }

            fn from_wire(buf: &[u8]) -> Result<Self, PacketError> {
                check_size(buf, $size)?;
                Ok(Self { $( $field: <$ty as WireField>::get(&buf[$at..]), )* })
            }

            fn from_wire_lenient(buf: &[u8]) -> (Self, [u8; $size]) {
                let mut padded = [0u8; $size];
                let len = buf.len().min($size);
                padded[..len].copy_from_slice(&buf[..len]);
                let packet = Self { $( $field: <$ty as WireField>::get(&padded[$at..]), )* };
                (packet, padded)
            }
        }

        impl $name {
            /// Serializes the packet in big-endian wire format.
            #[must_use]
            pub fn to_bytes(&self) -> [u8; $size] {
                self.to_wire()
            }

            /// Parses a packet from big-endian wire format.
            ///
            /// # Errors
            /// Returns [`PacketError::BufferTooSmall`] if `buf` is shorter
            /// than the packet.
            pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
                Self::from_wire(buf)
            }

            /// Parses a packet, zero-filling missing octets (RFC 8762 §4.6
            /// short-packet handling for TWAMP Light peers).
            #[must_use]
            pub fn from_bytes_lenient(buf: &[u8]) -> Self {
                Self::from_wire_lenient(buf).0
            }

            /// Like [`Self::from_bytes_lenient`], also returning the
            /// zero-filled buffer the fields were read from.
            #[must_use]
            pub fn from_bytes_lenient_with_canonical(buf: &[u8]) -> (Self, [u8; $size]) {
                Self::from_wire_lenient(buf)
            }
        }
    };
}

wire_packet! {
    /// Unauthenticated STAMP test packet sent by the Session-Sender.
    ///
    /// This is the basic packet format without HMAC authentication (44 bytes).
    /// See RFC 8762 §4.2.1, with the RFC 8972 §3 SSID extension occupying
    /// the two octets immediately following Error Estimate.
    ///
    /// Wire format:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Sequence Number                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                          Timestamp                           |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Error Estimate        |             SSID              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// |                         MBZ (28 octets)                       |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub struct PacketUnauthenticated (UNAUTH_BASE_SIZE) {
        /// Packet sequence number for ordering and loss detection.
        sequence_number: u32 = 0,
        /// Timestamp when the packet was sent (NTP or PTP format).
        timestamp: u64 = 4,
        /// Error estimate for the timestamp.
        error_estimate: u16 = 12,
        /// Session-Sender Identifier per RFC 8972 §3 (0 if unused).
        ssid: u16 = 14,
        /// Must Be Zero.
        mbz: [u8; 28] = 16,
    }
}

wire_packet! {
    /// Unauthenticated STAMP reflected packet sent by the Session-Reflector.
    ///
    /// Contains the original sender information plus reflector timestamps (44 bytes).
    /// See RFC 8762 §4.3.1, with the RFC 8972 §3 SSID in the two octets after
    /// Error Estimate.
    ///
    /// Wire format:
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        Sequence Number                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                          Timestamp                           |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Error Estimate        |             SSID              |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                       Receive Timestamp                       |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  Session-Sender Seq Number                    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                  Session-Sender Timestamp                     |
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | Session-Sender Error Estimate |           MBZ                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Ses-Sender TTL |                      MBZ                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    pub struct ReflectedPacketUnauthenticated (UNAUTH_BASE_SIZE) {
        /// Reflector's sequence number.
        sequence_number: u32 = 0,
        /// Timestamp when the reflector sent the response.
        timestamp: u64 = 4,
        /// Reflector's error estimate.
        error_estimate: u16 = 12,
        /// Session-Sender Identifier echoed/asserted by reflector (RFC 8972 §3).
        ssid: u16 = 14,
        /// Timestamp when the reflector received the test packet.
        receive_timestamp: u64 = 16,
        /// Original sender's sequence number (echoed back).
        sess_sender_seq_number: u32 = 24,
        /// Original sender's timestamp (echoed back).
        sess_sender_timestamp: u64 = 28,
        /// Original sender's error estimate (echoed back).
        sess_sender_err_estimate: u16 = 36,
        /// Must Be Zero (RFC 8762 §4.3.1). The reply SSID is only at octets
        /// 14-15 (RFC 8972 §3 Figure 2).
        mbz2: [u8; 2] = 38,
        /// TTL/Hop Limit of the received test packet.
        sess_sender_ttl: u8 = 40,
        /// Must Be Zero.
        mbz3: [u8; 3] = 41,
    }
}

wire_packet! {
    /// Authenticated STAMP test packet sent by the Session-Sender.
    ///
    /// Includes HMAC for integrity verification (112 bytes).
    /// See RFC 8762 §4.2.2, with the RFC 8972 §3 SSID extension occupying
    /// the two octets immediately following Error Estimate.
    pub struct PacketAuthenticated (AUTH_BASE_SIZE) {
        /// Packet sequence number for ordering and loss detection.
        sequence_number: u32 = 0,
        /// Must Be Zero.
        mbz0: [u8; 12] = 4,
        /// Timestamp when the packet was sent (NTP or PTP format).
        timestamp: u64 = 16,
        /// Error estimate for the timestamp.
        error_estimate: u16 = 24,
        /// Session-Sender Identifier per RFC 8972 §3 (0 if unused).
        ssid: u16 = 26,
        /// Must Be Zero.
        mbz1: [u8; 68] = 28,
        /// HMAC over octets 0-95 (RFC 8762 §4.4).
        hmac: [u8; 16] = 96,
    }
}

wire_packet! {
    /// Authenticated STAMP reflected packet sent by the Session-Reflector.
    ///
    /// Contains the original sender information plus reflector timestamps with HMAC (112 bytes).
    /// See RFC 8762 §4.3.2, with the RFC 8972 §3 SSID in the two octets after
    /// Error Estimate.
    pub struct ReflectedPacketAuthenticated (AUTH_BASE_SIZE) {
        /// Reflector's sequence number.
        sequence_number: u32 = 0,
        /// Must Be Zero.
        mbz0: [u8; 12] = 4,
        /// Timestamp when the reflector sent the response.
        timestamp: u64 = 16,
        /// Reflector's error estimate.
        error_estimate: u16 = 24,
        /// Session-Sender Identifier echoed/asserted by reflector (RFC 8972 §3).
        ssid: u16 = 26,
        /// Must Be Zero.
        mbz1: [u8; 4] = 28,
        /// Timestamp when the reflector received the test packet.
        receive_timestamp: u64 = 32,
        /// Must Be Zero.
        mbz2: [u8; 8] = 40,
        /// Original sender's sequence number (echoed back).
        sess_sender_seq_number: u32 = 48,
        /// Must Be Zero.
        mbz3: [u8; 12] = 52,
        /// Original sender's timestamp (echoed back).
        sess_sender_timestamp: u64 = 64,
        /// Original sender's error estimate (echoed back).
        sess_sender_err_estimate: u16 = 72,
        /// Must Be Zero (octets 74-79). RFC 8972 §3 places the SSID once per
        /// reflected packet, at octets 26-27.
        mbz4: [u8; 6] = 74,
        /// TTL/Hop Limit of the received test packet.
        sess_sender_ttl: u8 = 80,
        /// Must Be Zero.
        mbz5: [u8; 15] = 81,
        /// HMAC over octets 0-95 (RFC 8762 §4.4).
        hmac: [u8; 16] = 96,
    }
}

/// A base packet followed by RFC 8972 TLVs. The base packet's own HMAC (in
/// authenticated mode) covers only the base packet; TLV integrity uses the
/// HMAC TLV (RFC 8972 §4.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extended<B> {
    /// The base packet.
    pub base: B,
    /// TLVs following the base packet.
    pub tlvs: TlvList,
}

/// Unauthenticated Session-Sender test packet with TLVs.
pub type ExtendedPacketUnauthenticated = Extended<PacketUnauthenticated>;
/// Unauthenticated reflected packet with TLVs.
pub type ExtendedReflectedPacketUnauthenticated = Extended<ReflectedPacketUnauthenticated>;
/// Authenticated Session-Sender test packet with TLVs.
pub type ExtendedPacketAuthenticated = Extended<PacketAuthenticated>;
/// Authenticated reflected packet with TLVs.
pub type ExtendedReflectedPacketAuthenticated = Extended<ReflectedPacketAuthenticated>;

impl<B: BasePacket> Extended<B> {
    /// Base packet size in octets.
    pub const BASE_SIZE: usize = B::SIZE;

    /// A packet with no TLVs.
    #[must_use]
    pub fn new(base: B) -> Self {
        Self {
            base,
            tlvs: TlvList::new(),
        }
    }

    /// A packet with the given TLVs.
    #[must_use]
    pub fn with_tlvs(base: B, tlvs: TlvList) -> Self {
        Self { base, tlvs }
    }

    /// Parses a complete base packet and a well-formed TLV list.
    ///
    /// # Errors
    /// Returns an error if the base packet is short or a TLV is malformed.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, PacketError> {
        let base = B::from_wire(buf)?;
        let tlvs = if buf.len() > B::SIZE {
            TlvList::parse(&buf[B::SIZE..])?
        } else {
            TlvList::new()
        };
        Ok(Self { base, tlvs })
    }

    /// Parses leniently: a short base packet is zero-filled (RFC 8762 §4.6)
    /// and malformed TLVs are kept with the M flag instead of failing.
    /// Also returns the zero-filled base packet, which HMAC verification uses.
    #[must_use]
    pub fn from_bytes_lenient(buf: &[u8]) -> (Self, B::Bytes) {
        let (base, canonical) = B::from_wire_lenient(buf);
        let tlvs = if buf.len() > B::SIZE {
            TlvList::parse_lenient(&buf[B::SIZE..]).0
        } else {
            TlvList::new()
        };
        (Self { base, tlvs }, canonical)
    }

    /// Serializes the base packet followed by the TLVs.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.wire_size());
        buf.extend_from_slice(self.base.to_wire().as_ref());
        self.tlvs.write_to(&mut buf);
        buf
    }

    /// Total wire size in octets.
    #[must_use]
    pub fn wire_size(&self) -> usize {
        B::SIZE + self.tlvs.wire_size()
    }

    /// Whether any TLVs follow the base packet.
    #[must_use]
    pub fn has_tlvs(&self) -> bool {
        !self.tlvs.is_empty()
    }
}

#[cfg(test)]
mod tests;
