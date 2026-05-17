#![no_main]

use libfuzzer_sys::fuzz_target;
use stamp_suite::snmp::agentx;

fuzz_target!(|data: &[u8]| {
    let _ = agentx::decode_oid(data);
    let _ = agentx::decode_search_range(data);
});
