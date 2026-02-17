//! Destination Node Address TLV (Type 9) per RFC 9503 §4.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::tlv::core::{TlvError, TlvType, DEST_NODE_ADDR_IPV4_SIZE, DEST_NODE_ADDR_IPV6_SIZE};
use crate::tlv::traits::TypedTlv;

/// Destination Node Address TLV (Type 9) per RFC 9503 §4.
///
/// The Session-Sender includes this TLV to specify the intended reflector address.
/// The Session-Reflector checks if the address matches one of its local addresses
/// and sets the U-flag if it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationNodeAddressTlv {
    /// The intended destination address.
    pub address: IpAddr,
}

impl DestinationNodeAddressTlv {
    /// Creates a new Destination Node Address TLV.
    #[must_use]
    pub fn new(address: IpAddr) -> Self {
        Self { address }
    }
}

impl TypedTlv for DestinationNodeAddressTlv {
    const TYPE: TlvType = TlvType::DestinationNodeAddress;

    fn decode_value(value: &[u8]) -> Result<Self, TlvError> {
        match value.len() {
            DEST_NODE_ADDR_IPV4_SIZE => {
                let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
                Ok(Self {
                    address: IpAddr::V4(addr),
                })
            }
            DEST_NODE_ADDR_IPV6_SIZE => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(value);
                let addr = Ipv6Addr::from(octets);
                Ok(Self {
                    address: IpAddr::V6(addr),
                })
            }
            other => Err(TlvError::InvalidDestinationNodeAddressLength(other)),
        }
    }

    fn encode_value(&self, out: &mut Vec<u8>) {
        match self.address {
            IpAddr::V4(addr) => out.extend_from_slice(&addr.octets()),
            IpAddr::V6(addr) => out.extend_from_slice(&addr.octets()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::core::RawTlv;

    #[test]
    fn test_destination_node_address_ipv4_roundtrip() {
        let original = DestinationNodeAddressTlv::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::DestinationNodeAddress);
        assert_eq!(raw.value.len(), DEST_NODE_ADDR_IPV4_SIZE);
        let parsed = DestinationNodeAddressTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_destination_node_address_ipv6_roundtrip() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let original = DestinationNodeAddressTlv::new(IpAddr::V6(addr));
        let raw = original.to_raw();
        assert_eq!(raw.tlv_type, TlvType::DestinationNodeAddress);
        assert_eq!(raw.value.len(), DEST_NODE_ADDR_IPV6_SIZE);
        let parsed = DestinationNodeAddressTlv::from_raw(&raw).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_destination_node_address_invalid_length() {
        let raw = RawTlv::new(TlvType::DestinationNodeAddress, vec![0u8; 8]);
        let result = DestinationNodeAddressTlv::from_raw(&raw);
        assert!(matches!(
            result,
            Err(TlvError::InvalidDestinationNodeAddressLength(8))
        ));
    }
}
