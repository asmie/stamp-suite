//! Fixed-cardinality reasons for locally generated BER C flags.

/// A local reason for returning BER metadata with the C flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BerConformanceReason {
    MissingPadding,
    DuplicatePadding,
    DuplicateBer,
    ShortBerValue,
    DuplicatePattern,
    PaddingMisaligned,
    PaddingResized,
}

impl BerConformanceReason {
    pub const ALL: [Self; 7] = [
        Self::MissingPadding,
        Self::DuplicatePadding,
        Self::DuplicateBer,
        Self::ShortBerValue,
        Self::DuplicatePattern,
        Self::PaddingMisaligned,
        Self::PaddingResized,
    ];

    /// Stable counter label; never contains peer-supplied data.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MissingPadding => "missing_padding",
            Self::DuplicatePadding => "duplicate_padding",
            Self::DuplicateBer => "duplicate_ber",
            Self::ShortBerValue => "short_ber_value",
            Self::DuplicatePattern => "duplicate_pattern",
            Self::PaddingMisaligned => "padding_misaligned",
            Self::PaddingResized => "padding_resized",
        }
    }
}

/// At most one occurrence of each reason per reflected datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BerConformanceErrors(u8);

impl BerConformanceErrors {
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn contains(self, reason: BerConformanceReason) -> bool {
        self.0 & (1 << reason as u8) != 0
    }

    pub(crate) fn insert(&mut self, reason: BerConformanceReason) {
        self.0 |= 1 << reason as u8;
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.0 |= other.0;
    }

    pub fn iter(self) -> impl Iterator<Item = BerConformanceReason> {
        BerConformanceReason::ALL
            .into_iter()
            .filter(move |r| self.contains(*r))
    }
}
