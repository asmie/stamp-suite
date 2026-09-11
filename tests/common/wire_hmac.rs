//! Test-only digest oracle. Callers supply raw coverage bytes independently of
//! stamp-suite's packet parsing, key selection and HMAC coverage helpers.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub fn digest(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes()[..16].try_into().unwrap()
}
