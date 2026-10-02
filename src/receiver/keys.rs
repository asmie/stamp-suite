//! Per-packet HMAC key selection.

use super::*;

/// Resolves the packet's key from `ctx.hmac_key_set`, including its default.
/// Uses `ctx.hmac_key` only when no keyset is configured.
pub(super) fn resolve_hmac_key<'a>(ctx: &'a ProcessingContext, ssid: u16) -> Option<&'a HmacKey> {
    if let Some(set) = ctx.hmac_key_set {
        return set.for_ssid(ssid);
    }
    ctx.hmac_key
}
