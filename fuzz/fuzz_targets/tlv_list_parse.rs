#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::tlv::TlvList;

fuzz_target!(|data: &[u8]| {
    let _ = TlvList::parse(data);
});
