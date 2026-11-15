//! Optional public test artifacts: raw-IP pcap plus endpoint report/rule counters.
use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub struct Evidence {
    path: PathBuf,
    capture: File,
}

impl Evidence {
    pub fn new(ipv6: bool, mode: u8, name: &str) -> Option<Self> {
        let directory = PathBuf::from(std::env::var_os("STAMP_ECN_CAPTURE_DIR")?);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("ipv{}-mode{mode}-{name}", if ipv6 { 6 } else { 4 }));
        let mut capture = File::create(path.with_extension("pcap")).unwrap();
        // Classic little-endian pcap, microsecond timestamps, LINKTYPE_RAW=101.
        capture.write_all(&0xa1b2c3d4u32.to_le_bytes()).unwrap();
        capture.write_all(&2u16.to_le_bytes()).unwrap();
        capture.write_all(&4u16.to_le_bytes()).unwrap();
        for value in [0u32, 0, 4096, 101] {
            capture.write_all(&value.to_le_bytes()).unwrap();
        }
        Some(Self { path, capture })
    }

    pub fn packet(&mut self, bytes: &[u8]) {
        // Userspace dequeue time only; these captures are not timing evidence.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        for value in [
            now.as_secs() as u32,
            now.subsec_micros(),
            bytes.len() as u32,
            bytes.len() as u32,
        ] {
            self.capture.write_all(&value.to_le_bytes()).unwrap();
        }
        self.capture.write_all(bytes).unwrap();
    }

    pub fn finish(mut self, report: &serde_json::Value, rules: &serde_json::Value) {
        self.capture.flush().unwrap();
        let file = File::create(self.path.with_extension("json")).unwrap();
        serde_json::to_writer_pretty(
            file,
            &serde_json::json!({"report": report, "nftables": rules}),
        )
        .unwrap();
    }
}
