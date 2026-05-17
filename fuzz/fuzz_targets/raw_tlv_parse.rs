#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::tlv::RawTlv;

fuzz_target!(|data: &[u8]| {
    let _ = RawTlv::parse(data);
});
