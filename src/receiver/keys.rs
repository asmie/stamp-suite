//! HMAC key loading for the reflector and per-packet key selection.

use super::*;

/// Whether any HMAC key source was configured, including a directory.
///
/// Check this alongside the loaded key/keyset: load failure must not silently
/// turn a keyed reflector into an open one.
#[must_use]
pub fn hmac_key_source_configured(conf: &Configuration) -> bool {
    conf.hmac_key.is_some() || conf.hmac_key_file.is_some() || conf.hmac_key_dir.is_some()
}

/// Whether a single-key source was configured for [`load_hmac_key`].
/// Excludes reflector-only `--hmac-key-dir`.
#[must_use]
pub fn single_hmac_key_source_configured(conf: &Configuration) -> bool {
    conf.hmac_key.is_some() || conf.hmac_key_file.is_some()
}

pub fn load_hmac_key(conf: &Configuration) -> Option<HmacKey> {
    if let Some(ref hex_key) = conf.hmac_key {
        match HmacKey::from_hex(hex_key.as_str()) {
            Ok(key) => return Some(key),
            Err(e) => {
                log::error!("Failed to parse HMAC key: {}", e);
                return None;
            }
        }
    }

    if let Some(ref path) = conf.hmac_key_file {
        match HmacKey::from_file(path) {
            Ok(key) => return Some(key),
            Err(e) => {
                log::error!("Failed to load HMAC key from file: {}", e);
                return None;
            }
        }
    }

    None
}

/// Loads a keyset from the configured key, key file, or key directory.
/// Single keys populate the default; directories supply per-SSID entries and
/// an optional `default.key`. Returns `None` when no keyset can be loaded.
pub fn load_hmac_key_set(conf: &Configuration) -> Option<crate::crypto::HmacKeySet> {
    use crate::crypto::HmacKeySet;

    if let Some(ref dir) = conf.hmac_key_dir {
        match HmacKeySet::from_dir(dir) {
            Ok(set) => {
                if set.is_empty() {
                    log::error!(
                        "HMAC key directory {:?} contained no usable keys",
                        dir.display()
                    );
                    return None;
                }
                return Some(set);
            }
            Err(e) => {
                log::error!(
                    "Failed to load HMAC key directory {:?}: {}",
                    dir.display(),
                    e
                );
                return None;
            }
        }
    }

    load_hmac_key(conf).map(HmacKeySet::with_default)
}

/// Resolves the packet's key from `ctx.hmac_key_set`, including its default.
/// Uses `ctx.hmac_key` only when no keyset is configured.
pub(super) fn resolve_hmac_key<'a>(ctx: &'a ProcessingContext, ssid: u16) -> Option<&'a HmacKey> {
    if let Some(set) = ctx.hmac_key_set {
        return set.for_ssid(ssid);
    }
    ctx.hmac_key
}
