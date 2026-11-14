//! Fixed-cardinality diagnostics for locally generated non-BER C conditions.

/// A locally processed non-BER condition that caused a reflected C flag.
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
    HeaderOrder,
    HeaderFixedPolicy,
    HeaderIpv6Policy,
    HeaderIpv6Length,
    HeaderCaptureUnavailable,
    HeaderSelectorAmbiguous,
    HeaderSelectorNoMatch,
    HeaderLengthUnavailable,
    CosMarkingUnavailable,
    ReplyHeaderUnsupported,
    ReplyHeaderDuplicate,
}

impl TlvConformanceReason {
    pub const ALL: [Self; 18] = [
        Self::Type12CountLimit,
        Self::Type12IntervalLimit,
        Self::Type12SizeLimit,
        Self::Type12RateLimit,
        Self::Type12VolumeLimit,
        Self::Type12RouteMtu,
        Self::Type12PaddingUnencodable,
        Self::HeaderOrder,
        Self::HeaderFixedPolicy,
        Self::HeaderIpv6Policy,
        Self::HeaderIpv6Length,
        Self::HeaderCaptureUnavailable,
        Self::HeaderSelectorAmbiguous,
        Self::HeaderSelectorNoMatch,
        Self::HeaderLengthUnavailable,
        Self::CosMarkingUnavailable,
        Self::ReplyHeaderUnsupported,
        Self::ReplyHeaderDuplicate,
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
            Self::HeaderOrder => "header_order",
            Self::HeaderFixedPolicy => "header_fixed_policy",
            Self::HeaderIpv6Policy => "header_ipv6_policy",
            Self::HeaderIpv6Length => "header_ipv6_length",
            Self::HeaderCaptureUnavailable => "header_capture_unavailable",
            Self::HeaderSelectorAmbiguous => "header_selector_ambiguous",
            Self::HeaderSelectorNoMatch => "header_selector_no_match",
            Self::HeaderLengthUnavailable => "header_length_unavailable",
            Self::CosMarkingUnavailable => "cos_marking_unavailable",
            Self::ReplyHeaderUnsupported => "reply_header_unsupported",
            Self::ReplyHeaderDuplicate => "reply_header_duplicate",
        }
    }
}

/// At most one occurrence of each processed condition per reflected datagram.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlvConformanceErrors {
    bits: u32,
    // One-based first processed-header ordinal for each header reason. Size
    // trimming removes a suffix of processed headers. Keeping the first
    // occurrence is sufficient to know whether a reason survives, even when
    // several headers have it. Storage is fixed; no packet bytes are retained.
    first_header: [usize; 8],
}

impl TlvConformanceErrors {
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }
    pub fn contains(&self, reason: TlvConformanceReason) -> bool {
        self.bits & (1 << reason as u8) != 0
    }
    pub(crate) fn insert(&mut self, reason: TlvConformanceReason) {
        self.bits |= 1 << reason as u8;
    }
    pub(crate) fn merge(&mut self, other: Self) {
        self.bits |= other.bits;
        if other.has_header_reasons() {
            for (first, other) in self.first_header.iter_mut().zip(other.first_header) {
                if other != 0 && (*first == 0 || other < *first) {
                    *first = other;
                }
            }
        }
    }
    /// Record a C reason at the ordinal among processed Type 246/247 TLVs.
    pub(crate) fn insert_header(&mut self, reason: TlvConformanceReason, ordinal: usize) {
        let index = reason as usize - TlvConformanceReason::HeaderOrder as usize;
        let first = &mut self.first_header[index];
        let required = ordinal + 1;
        if *first == 0 || required < *first {
            *first = required;
        }
        self.insert(reason);
    }

    pub(crate) fn has_header_reasons(&self) -> bool {
        const HEADER_MASK: u32 = ((1 << 8) - 1) << TlvConformanceReason::HeaderOrder as u8;
        self.bits & HEADER_MASK != 0
    }

    /// Retain reasons represented by a surviving prefix of processed headers.
    pub(crate) fn retain_headers(&mut self, count: usize) {
        for (index, required) in self.first_header.iter().enumerate() {
            if *required > count {
                self.bits &= !(1 << (index + TlvConformanceReason::HeaderOrder as usize));
            }
        }
    }

    pub fn iter(self) -> impl Iterator<Item = TlvConformanceReason> {
        TlvConformanceReason::ALL
            .into_iter()
            .filter(move |r| self.contains(*r))
    }
}
