#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::tlv::ResidualBerValue;

// Successor value framing must be lossless, including unknown/invalid pattern
// sub-TLVs. Semantic errors are separate from structural decoding failures.
fuzz_target!(|data: &[u8]| {
    if let Ok(value) = ResidualBerValue::decode_value(data) {
        let _ = value.explicit_pattern(240); // fixture-local sub-TLV codepoint
        let mut out = Vec::new();
        value.encode_value(&mut out).unwrap();
        assert_eq!(out, data);
    }
});
