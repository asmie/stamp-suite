//! Fixed-cardinality diagnostics for locally generated non-BER C conditions.

/// A processed Type 12 condition that caused a reflected C flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlvConformanceReason {
    Type12CountLimit,
    Type12IntervalLimit,
    Type12SizeLimit,
    Type12RateLimit,
    Type12VolumeLimit,
    Type12RouteMtu,
    Type12PaddingUnencodable,
}

impl TlvConformanceReason {
    pub const ALL: [Self; 7] = [
        Self::Type12CountLimit,
        Self::Type12IntervalLimit,
        Self::Type12SizeLimit,
        Self::Type12RateLimit,
        Self::Type12VolumeLimit,
        Self::Type12RouteMtu,
        Self::Type12PaddingUnencodable,
    ];

    /// A fixed counter label, without any peer-supplied value.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Type12CountLimit => "type12_count_limit",
            Self::Type12IntervalLimit => "type12_interval_limit",
            Self::Type12SizeLimit => "type12_size_limit",
            Self::Type12RateLimit => "type12_rate_limit",
            Self::Type12VolumeLimit => "type12_volume_limit",
            Self::Type12RouteMtu => "type12_route_mtu",
            Self::Type12PaddingUnencodable => "type12_padding_unencodable",
        }
    }
}

/// At most one occurrence of each processed condition per reflected datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlvConformanceErrors(u32);

impl TlvConformanceErrors {
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
    pub fn contains(self, reason: TlvConformanceReason) -> bool {
        self.0 & (1 << reason as u8) != 0
    }
    pub(crate) fn insert(&mut self, reason: TlvConformanceReason) {
        self.0 |= 1 << reason as u8;
    }
    pub(crate) fn merge(&mut self, other: Self) {
        self.0 |= other.0;
    }
    pub fn iter(self) -> impl Iterator<Item = TlvConformanceReason> {
        TlvConformanceReason::ALL
            .into_iter()
            .filter(move |r| self.contains(*r))
    }
}
