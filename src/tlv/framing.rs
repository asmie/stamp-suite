//! Allocation-free framing inspection, separate from TLV response policy.

use super::core::{
    TlvSpan, TlvType, LOCATION_TLV_MIN_VALUE_SIZE, REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE,
    TIMESTAMP_INFO_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
};
use super::RESIDUAL_BER_FIXED_VALUE_SIZE;

/// Structural failure in a TLV region. Type-specific value validation is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvFramingErrorKind {
    /// Fewer than four bytes remain for the next header.
    IncompleteHeader { available: usize },
    /// The header's declared value does not fit in its containing region.
    IncompleteValue { declared: usize, available: usize },
}

/// First structural failure, with offsets relative to the supplied TLV buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("TLV framing failure at {offset}, parent {parent:?}: {kind:?}")]
pub struct TlvFramingError {
    pub offset: usize,
    /// `Some` for a known container's child, `None` for a top-level failure.
    pub parent: Option<usize>,
    pub kind: TlvFramingErrorKind,
}

/// Walk complete frames without copying values. Emit one error, then stop.
///
/// Flag bits and type-specific value rules do not affect the walk. Unlike the
/// legacy list parser, a one-to-three-byte trailing fragment is reported.
#[derive(Debug, Clone)]
pub struct TlvFrames<'a> {
    bytes: &'a [u8],
    offset: usize,
    failed: bool,
}

impl<'a> TlvFrames<'a> {
    /// Walk from `start` to the end of `bytes`. Starting at or beyond the end
    /// yields no frames, matching a loop over [`TlvSpan::at`]. Bound a child
    /// region by slicing `bytes` at its parent's end before constructing this.
    #[must_use]
    pub fn new(bytes: &'a [u8], start: usize) -> Self {
        Self {
            bytes,
            offset: start,
            failed: false,
        }
    }
}

impl Iterator for TlvFrames<'_> {
    type Item = Result<TlvSpan, TlvFramingError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset >= self.bytes.len() {
            return None;
        }
        let available = self.bytes.len() - self.offset;
        if let Some(span) = TlvSpan::at(self.bytes, self.offset) {
            self.offset = span.end();
            return Some(Ok(span));
        }
        let kind = if available < TLV_HEADER_SIZE {
            TlvFramingErrorKind::IncompleteHeader { available }
        } else {
            let declared = usize::from(u16::from_be_bytes([
                self.bytes[self.offset + 2],
                self.bytes[self.offset + 3],
            ]));
            TlvFramingErrorKind::IncompleteValue {
                declared,
                available: available - TLV_HEADER_SIZE,
            }
        };
        self.failed = true;
        Some(Err(TlvFramingError {
            offset: self.offset,
            parent: None,
            kind,
        }))
    }
}

impl std::iter::FusedIterator for TlvFrames<'_> {}

/// Offset of the child TLV region inside a known container's value, after its
/// fixed prefix: Location (4), Timestamp Information (4), Return Path (0),
/// Reflected Control (8) and Residual BER (8). Other types have no children.
#[must_use]
pub fn child_region_offset(kind: TlvType) -> Option<usize> {
    match kind {
        TlvType::Location => Some(LOCATION_TLV_MIN_VALUE_SIZE),
        TlvType::TimestampInfo => Some(TIMESTAMP_INFO_TLV_VALUE_SIZE),
        TlvType::ReturnPath => Some(0),
        TlvType::ReflectedControl => Some(REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE),
        TlvType::ResidualBer => Some(RESIDUAL_BER_FIXED_VALUE_SIZE),
        _ => None,
    }
}

/// Check complete outer frames and child frames in known container layouts.
///
/// Known child regions start at [`child_region_offset`]. Child values,
/// unknown layouts, padding and digests remain opaque;
/// child type numbers never cause recursive interpretation of their values.
///
/// A complete outer value shorter than its fixed prefix has no inspectable
/// child region and is left to semantic validation. This checker also does not
/// verify HMACs, flag rules, cardinality or known value lengths. It scans past
/// M/I/U flags without processing values, so callers must choose when to invoke
/// it. Success is framing evidence, not an admission or integrity verdict.
///
/// Work is linear in the input length with constant storage and nesting depth.
/// No receiver reply/discard policy is implied.
///
/// # Errors
/// Returns the first incomplete frame in encounter order, including the owning
/// parent offset for a child failure. Outer offsets precede their child offsets.
pub fn check_tlv_framing(bytes: &[u8]) -> Result<(), TlvFramingError> {
    for parent in TlvFrames::new(bytes, 0) {
        let parent = parent?;
        let Some(prefix) = child_region_offset(parent.tlv_type) else {
            continue;
        };
        if parent.len < prefix {
            continue;
        }
        for child in TlvFrames::new(&bytes[..parent.end()], parent.value_start() + prefix) {
            if let Err(mut error) = child {
                error.parent = Some(parent.start);
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
