//! Reply source-address pinning (RFC 9503 §3).
//!
//! A matching Destination Node Address TLV selects the reply source. Linux
//! applies it through per-packet ancillary data in
//! `receiver::transmit::send_datagram`, including on wildcard binds where
//! route-based selection may choose another address. Unsupported platforms
//! and failed sends fall back to kernel source selection.

/// Whether this build can pin a reply's source address.
///
/// `IP_PKTINFO`/`IPV6_PKTINFO` as *outgoing* ancillary data is a Linux
/// interface. Darwin has no equivalent that sets the source of an individual
/// datagram on an unconnected socket, so callers there keep the kernel's choice.
#[must_use]
pub const fn supported() -> bool {
    cfg!(target_os = "linux")
}
