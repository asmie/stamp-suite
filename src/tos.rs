//! The IPv4 TOS / IPv6 Traffic Class octet: DSCP in the upper six bits and
//! ECN in the lower two (RFC 2474 §3, RFC 3168 §5).

/// One TOS / Traffic Class octet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tos(pub u8);

impl Tos {
    /// Packs DSCP and ECN. Bits outside their fields are dropped.
    #[must_use]
    pub const fn new(dscp: u8, ecn: u8) -> Self {
        Self(((dscp & 0x3F) << 2) | (ecn & 0x03))
    }

    #[must_use]
    pub const fn dscp(self) -> u8 {
        self.0 >> 2
    }

    #[must_use]
    pub const fn ecn(self) -> u8 {
        self.0 & 0x03
    }

    /// The same DSCP with ECN cleared (Not-ECT).
    #[must_use]
    pub const fn without_ecn(self) -> Self {
        Self(self.0 & !0x03)
    }
}

#[cfg(test)]
mod tests {
    use super::Tos;

    #[test]
    fn packs_and_splits_dscp_and_ecn() {
        let tos = Tos::new(46, 2);
        assert_eq!(tos.0, 0xBA);
        assert_eq!((tos.dscp(), tos.ecn()), (46, 2));
        assert_eq!(tos.without_ecn(), Tos::new(46, 0));
        assert_eq!(Tos::new(0xFF, 0xFF), Tos(0xFF));
    }
}
