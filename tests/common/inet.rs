//! Independent Internet checksums and kernel UDP counters for raw-packet tests.
#![allow(dead_code)] // Each integration target uses a different helper subset.

/// RFC 1071 Internet checksum: the complemented one's-complement sum of
/// 16-bit words. An odd final byte is padded with zero. A buffer that already
/// contains its own correct checksum sums to zero.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| (u32::from(pair[0]) << 8) | u32::from(*pair.get(1).unwrap_or(&0)))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The UDP checksum field for a pseudo-header plus segment. A computed zero
/// is sent as all ones, since zero means "no checksum" (RFC 768).
pub fn udp_checksum(pseudo_header_and_segment: &[u8]) -> u16 {
    match checksum(pseudo_header_and_segment) {
        0 => u16::MAX,
        sum => sum,
    }
}

/// Linux `Udp: InCsumErrors` from `/proc/net/snmp`, for the current network
/// namespace.
#[cfg(target_os = "linux")]
pub fn udp_checksum_errors() -> u64 {
    let stats = std::fs::read_to_string("/proc/net/snmp").unwrap();
    let mut udp = stats.lines().filter_map(|line| line.strip_prefix("Udp: "));
    let index = udp
        .next()
        .unwrap()
        .split_whitespace()
        .position(|name| name == "InCsumErrors")
        .unwrap();
    udp.next()
        .unwrap()
        .split_whitespace()
        .nth(index)
        .unwrap()
        .parse()
        .unwrap()
}
