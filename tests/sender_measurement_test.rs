//! Independent wire peer verifies sender summaries and final burst draining.
#[path = "common/child.rs"]
mod child;
#[path = "common/wire_hmac.rs"]
mod wire_hmac;
#[path = "common/wire_mode.rs"]
mod wire_mode;
use child::ChildProcess;
use std::{
    net::UdpSocket,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wire_mode::Mode;

struct Sender(ChildProcess);
impl Sender {
    fn start(peer: &UdpSocket, auth: bool, count: u32, copies: u16) -> Self {
        Self::start_profile(peer, auth, count, copies, true, &[])
    }
    fn start_profile(
        peer: &UdpSocket,
        auth: bool,
        count: u32,
        copies: u16,
        extensions: bool,
        extra: &[&str],
    ) -> Self {
        let ip = peer.local_addr().unwrap().ip().to_string();
        let mut command = Command::new(env!("CARGO_BIN_EXE_stamp-suite"));
        command
            .args([
                "--remote-addr",
                &ip,
                "--remote-port",
                &peer.local_addr().unwrap().port().to_string(),
                "--local-addr",
                &ip,
                "--local-port",
                "0",
                "--count",
                &count.to_string(),
                "--hwtstamp",
                "off",
                "--output-format",
                "json",
                "--reflected-control-count",
                &copies.to_string(),
            ])
            .env_remove("STAMP_HMAC_KEY")
            .env("RUST_LOG", "off")
            .env("TOKIO_WORKER_THREADS", "2");
        if !extra.contains(&"--timeout") {
            command.args(["--timeout", "1"]);
        }
        if !extra.contains(&"--send-delay") {
            command.args(["--send-delay", "20"]);
        }
        if extensions {
            command.args(["--direct-measurement", "--follow-up-telemetry"]);
        }
        command.args(extra);
        if auth {
            command.args([
                "--auth-mode",
                "A",
                "--hmac-key",
                "ABABABABABABABABABABABABABABABAB",
            ]);
        }
        Self(ChildProcess::spawn(&mut command))
    }
    fn finish(self) -> serde_json::Value {
        let output = self.0.finish(Duration::from_secs(5));
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}
fn ptp_now() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (now.as_secs() << 32) | u64::from(now.subsec_nanos())
}
fn sign(parts: &[&[u8]]) -> [u8; 16] {
    wire_hmac::digest(&[0xAB; 16], &parts.concat())
}
fn reply(
    request: &[u8],
    auth: bool,
    reflected: u32,
    dm: [u32; 3],
    previous: Option<(u32, u64)>,
) -> (Vec<u8>, u64) {
    let base = if auth { 112 } else { 44 };
    let (ts, err, rx, seq, echo, echo_err, ttl) = if auth {
        (16, 24, 32, 48, 64, 72, 80)
    } else {
        (4, 12, 16, 24, 28, 36, 40)
    };
    let t3 = ptp_now();
    let mut bytes = vec![0; base];
    bytes[..4].copy_from_slice(&reflected.to_be_bytes());
    bytes[ts..ts + 8].copy_from_slice(&t3.to_be_bytes());
    bytes[err..err + 2].copy_from_slice(&0x4001u16.to_be_bytes());
    bytes[err + 2..err + 4].copy_from_slice(&request[err + 2..err + 4]);
    bytes[rx..rx + 8].copy_from_slice(&t3.to_be_bytes());
    bytes[seq..seq + 4].copy_from_slice(&request[..4]);
    bytes[echo..echo + 8].copy_from_slice(&request[ts..ts + 8]);
    bytes[echo_err..echo_err + 2].copy_from_slice(&request[err..err + 2]);
    bytes[ttl] = 64;
    bytes.extend_from_slice(&[0, 5, 0, 12]);
    for n in dm {
        bytes.extend_from_slice(&n.to_be_bytes());
    }
    bytes.extend_from_slice(&[0, 7, 0, 16]);
    let (previous_seq, previous_ts) = previous.unwrap_or((0, 0));
    bytes.extend_from_slice(&previous_seq.to_be_bytes());
    bytes.extend_from_slice(&previous_ts.to_be_bytes());
    bytes.extend_from_slice(&[2, 0, 0, 0]);
    if auth {
        let digest = sign(&[&bytes[..4], &bytes[base..]]);
        bytes.extend_from_slice(&[0, 8, 0, 16]);
        bytes.extend_from_slice(&digest);
        let digest = sign(&[&bytes[..96]]);
        bytes[96..112].copy_from_slice(&digest);
    }
    (bytes, t3)
}

fn reply_with_extensions(request: &[u8], auth: bool, tail: &[u8]) -> Vec<u8> {
    let (mut bytes, _) = reply(request, auth, 10, [1, 1, 1], None);
    let base = if auth { 112 } else { 44 };
    bytes.truncate(base);
    bytes.extend_from_slice(tail);
    if auth {
        let digest = sign(&[&bytes[..4], &bytes[base..]]);
        bytes.extend_from_slice(&[0, 8, 0, 16]);
        bytes.extend_from_slice(&digest);
        let digest = sign(&[&bytes[..96]]);
        bytes[96..112].copy_from_slice(&digest);
    }
    bytes
}

#[test]
fn base_only_sender_validates_returned_extensions() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let sender = Sender::start_profile(&peer, auth, 1, 1, false, &[]);
            let mut request = [0; 2048];
            let (len, source) = peer.recv_from(&mut request).unwrap();
            assert_eq!(
                len,
                if auth { 112 } else { 44 },
                "request must really be base-only"
            );
            let reply = reply_with_extensions(&request[..len], auth, &[0, 1, 0, 4, 1, 2, 3, 4]);
            peer.send_to(&reply, source).unwrap();
            let stats = sender.finish();
            assert_eq!(stats["packets_received"], 1);
            let validation = &stats["measurements"]["tlv_validation"];
            assert_eq!(
                validation["evaluated_replies"], 1,
                "{ip} auth={auth}: {stats}"
            );
            assert_eq!(validation["by_type"]["1"]["observed"], 1);
            if auth {
                assert_eq!(validation["hmac"]["verified"], 1);
            }
        }
    }
}

#[test]
fn sender_validates_unused_tlv_lengths_before_later_measurements() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for extensions in [true, false] {
                for (kind, value_len, flags) in
                    [(4, 8usize, 0u8), (4, 4, 0x40), (3, 5, 0), (3, 9, 0)]
                {
                    let peer = UdpSocket::bind((ip, 0)).unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let sender = Sender::start_profile(&peer, auth, 1, 1, extensions, &[]);
                    let mut request = [0; 2048];
                    let (len, source) = peer.recv_from(&mut request).unwrap();
                    // Unused CoS/Timestamp Info still validate their lengths.
                    // Invalid length/child framing or peer M must stop later DM;
                    // signatures cover the original bytes in either case.
                    let mut tail = vec![flags, kind, 0, value_len as u8];
                    tail.extend(std::iter::repeat_n(0, value_len));
                    tail.extend_from_slice(&[0, 5, 0, 12]);
                    for value in [1u32, 2, 3] {
                        tail.extend_from_slice(&value.to_be_bytes());
                    }
                    peer.send_to(&reply_with_extensions(&request[..len], auth, &tail), source)
                        .unwrap();
                    let stats = sender.finish();
                    assert_eq!(
                        stats["packets_received"], 1,
                        "base RTT is independently usable"
                    );
                    assert_eq!(
                        stats["measurements"]["direct_measurement"]["observations"], 0,
                        "{ip} auth={auth} ext={extensions}: {stats}"
                    );
                    let validation = &stats["measurements"]["tlv_validation"];
                    assert_eq!(validation["flags"]["malformed"], 1);
                    assert_eq!(
                        validation["by_type"][kind.to_string()]["flags"]["malformed"],
                        1
                    );
                    if auth {
                        assert_eq!(
                            validation["hmac"]["verified"], 1,
                            "verify original wire bytes"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn sender_stops_at_malformed_location_children_but_ignores_child_i() {
    let cases = [
        (vec![0, 0, 0, 0, 0x80], 0),                   // incomplete child header
        (vec![0, 0, 0, 0, 0, 7, 0, 4, 1, 2, 3, 4], 0), // known wrong length
        ([vec![0, 0, 0, 0, 0x40, 7, 0, 16], vec![0; 16]].concat(), 0),
        ([vec![0, 0, 0, 0, 0x20, 7, 0, 16], vec![0; 16]].concat(), 1),
    ];
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for (location, observations) in &cases {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let sender = Sender::start_profile(&peer, auth, 1, 1, true, &[]);
                let mut request = [0; 2048];
                let (len, source) = peer.recv_from(&mut request).unwrap();
                let mut tail = vec![0, 2];
                tail.extend_from_slice(&(location.len() as u16).to_be_bytes());
                tail.extend_from_slice(location);
                tail.extend_from_slice(&[0, 5, 0, 12]);
                for value in [1u32, 2, 3] {
                    tail.extend_from_slice(&value.to_be_bytes());
                }
                peer.send_to(&reply_with_extensions(&request[..len], auth, &tail), source)
                    .unwrap();
                let stats = sender.finish();
                assert_eq!(stats["packets_received"], 1);
                assert_eq!(
                    stats["measurements"]["direct_measurement"]["observations"], *observations,
                    "{ip} auth={auth} location={location:?}"
                );
                let validation = &stats["measurements"]["tlv_validation"];
                assert_eq!(
                    validation["flags"]["malformed"],
                    u64::from(*observations == 0)
                );
                if auth {
                    assert_eq!(validation["hmac"]["verified"], 1);
                }
            }
        }
    }
}

#[test]
fn sender_validates_return_path_children_before_consuming_extension_values() {
    let cases = [
        (0, vec![0x80], 1, 0, 1, 0),
        (0, vec![0, 2, 0, 1, 0xaa], 1, 0, 1, 0),
        (0, vec![0x40, 1, 0, 4, 0, 0, 0, 1], 1, 0, 1, 0),
        (0, vec![0x20, 1, 0, 4, 0, 0, 0, 1], 0, 1, 0, 0),
        (0x80, vec![0x20, 1, 0, 4, 0, 0, 0, 1], 0, 0, 1, 1),
        (0, vec![0, 1, 0, 4, 0, 0, 0, 1, 0x40, 8, 0, 0], 1, 0, 1, 0),
        (0, vec![0, 1, 0, 4, 0, 0, 0, 1, 0x80, 4, 0, 0], 0, 0, 1, 1),
    ];
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for (flags, value, malformed, integrity, before, after) in &cases {
                for dm_first in [false, true] {
                    let peer = UdpSocket::bind((ip, 0)).unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let sender = Sender::start_profile(&peer, auth, 1, 1, true, &[]);
                    let mut request = [0; 2048];
                    let (len, source) = peer.recv_from(&mut request).unwrap();
                    let mut dm = vec![0, 5, 0, 12];
                    for n in [1u32, 2, 3] {
                        dm.extend_from_slice(&n.to_be_bytes());
                    }
                    let mut path = vec![*flags, 10, 0, value.len() as u8];
                    path.extend_from_slice(value);
                    let tail = if dm_first {
                        [dm, path].concat()
                    } else {
                        [path, dm].concat()
                    };
                    peer.send_to(&reply_with_extensions(&request[..len], auth, &tail), source)
                        .unwrap();
                    let stats = sender.finish();
                    assert_eq!(stats["packets_received"], 1, "base RTT remains usable");
                    assert_eq!(
                        stats["measurements"]["direct_measurement"]["observations"],
                        if dm_first { *before } else { *after },
                        "{ip} auth={auth} value={value:?}: {stats}"
                    );
                    let validation = &stats["measurements"]["tlv_validation"];
                    assert_eq!(validation["flags"]["malformed"], *malformed);
                    assert_eq!(validation["flags"]["integrity_failed"], *integrity);
                    if auth {
                        assert_eq!(validation["hmac"]["verified"], 1);
                    }
                }
            }
        }
    }
}

#[test]
fn sender_origins_rfc8972_tlvs_with_u_set_and_m_i_clear() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let auth = mode.authenticated();
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut extra = vec![
                "--extra-padding",
                "260",
                "--location",
                "--timestamp-info",
                "--cos",
                "--direct-measurement",
                "--access-report",
                "1",
                "--follow-up-telemetry",
            ];
            if mode == Mode::Keyed {
                extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
            }
            let sender = Sender::start_profile(&peer, auth, 1, 1, false, &extra);
            let mut request = [0; 2048];
            let (length, source) = peer.recv_from(&mut request).unwrap();
            let request = &request[..length];
            let base = if auth { 112 } else { 44 };
            if auth {
                assert_eq!(&request[96..112], &sign(&[&request[..96]]));
            }
            let mut pos = base;
            let mut kinds = vec![];
            let mut echo = vec![];
            while pos < request.len() {
                assert!(pos + 4 <= request.len());
                let size = u16::from_be_bytes([request[pos + 2], request[pos + 3]]) as usize;
                assert!(pos + 4 + size <= request.len());
                assert_eq!(request[pos], 0x80, "all sender U/M/I and reserved bits");
                let kind = request[pos + 1];
                kinds.push(kind);
                if kind == 1 {
                    assert_eq!(&request[pos + 2..pos + 4], &[1, 4], "260-byte value length");
                    // The sender fills padding from its own pseudorandom
                    // generator (RFC 8972 §4.1), never leaving it zeroed.
                    let padding = &request[pos + 4..pos + 4 + size];
                    assert!(padding.iter().any(|&b| b != 0), "padding is not generated");
                }
                if kind == 2 {
                    let mut expected = vec![0; 4];
                    expected.extend_from_slice(&[0x80, 7, 0, 16]);
                    expected.extend_from_slice(&[0; 16]);
                    expected.extend_from_slice(&[0x80, 4, 0, 16]);
                    expected.extend_from_slice(&[0; 16]);
                    assert_eq!(size, 44);
                    assert_eq!(&request[pos + 4..pos + 4 + size], expected);
                }
                if kind == 5 {
                    assert_eq!(size, 12);
                    assert_eq!(
                        &request[pos + 4..pos + 4 + size],
                        &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]
                    );
                }
                if kind == 3 {
                    assert_eq!(&request[pos + 4..pos + 4 + size], &[0; 4]);
                }
                if kind == 6 {
                    assert_eq!(&request[pos + 4..pos + 4 + size], &[0x10, 1, 0, 0]);
                }
                if kind == 7 {
                    assert_eq!(&request[pos + 4..pos + 4 + size], &[0; 16]);
                }
                if kind == 8 {
                    assert_eq!(size, 16);
                    assert_eq!(pos + 4 + size, request.len());
                    assert_eq!(
                        &request[pos + 4..],
                        &sign(&[&request[..4], &request[base..pos]])
                    );
                } else {
                    echo.push(0); // recognized response TLV, clear U/M/I
                    echo.extend_from_slice(&request[pos + 1..pos + 4 + size]);
                }
                pos += 4 + size;
            }
            kinds.sort_unstable();
            assert_eq!(
                kinds,
                if mode == Mode::Open {
                    (1..=7).collect::<Vec<_>>()
                } else {
                    (1..=8).collect()
                }
            );
            let mut response = reply_with_extensions(request, auth, &echo);
            if mode == Mode::Keyed {
                let digest = sign(&[&response[..4], &response[base..]]);
                response.extend_from_slice(&[0, 8, 0, 16]);
                response.extend_from_slice(&digest);
            }
            peer.send_to(&response, source).unwrap();
            let stats = sender.finish();
            assert_eq!(stats["packets_received"], 1);
            assert_eq!(stats["access_report"]["outcome"], "acknowledged");
        }
    }
}

#[test]
fn sender_direct_measurement_counts_actual_probes_and_zeroes_peer_fields() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let auth = mode.authenticated();
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut extra = vec!["--timestamp-info"];
            if mode == Mode::Keyed {
                extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
            }
            let sender = Sender::start_profile(&peer, auth, 3, 1, true, &extra);
            for probe in 1..=3u32 {
                let mut request = [0; 2048];
                let (length, source) = peer.recv_from(&mut request).unwrap();
                let request = &request[..length];
                let base = if auth { 112 } else { 44 };
                if auth {
                    assert_eq!(&request[96..112], &sign(&[&request[..96]]));
                }
                let mut pos = base;
                let mut found_dm = false;
                while pos < request.len() {
                    assert!(pos + 4 <= request.len());
                    let size = u16::from_be_bytes([request[pos + 2], request[pos + 3]]) as usize;
                    assert!(pos + 4 + size <= request.len());
                    let value = &request[pos + 4..pos + 4 + size];
                    match request[pos + 1] {
                        3 => assert_eq!(value, &[0; 4]),
                        5 => {
                            found_dm = true;
                            assert_eq!(size, 12);
                            assert_eq!(&value[..4], &probe.to_be_bytes());
                            assert_eq!(&value[4..], &[0; 8]);
                        }
                        7 => assert_eq!(value, &[0; 16]),
                        8 => {
                            assert_eq!(pos + 20, request.len());
                            assert_eq!(value, sign(&[&request[..4], &request[base..pos]]));
                        }
                        _ => (),
                    }
                    pos += 4 + size;
                }
                assert!(found_dm);
                peer.send_to(
                    &reply_with_extensions(request, auth, &[0, 1, 0, 4, 1, 2, 3, 4]),
                    source,
                )
                .unwrap();
            }
            assert_eq!(sender.finish()["packets_received"], 3);
        }
    }
}
#[test]
fn sender_cos_fields_and_automatic_ect_response_reach_the_wire() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            for (include_cos, ecn) in [(false, 0u8), (true, 0), (true, 1), (true, 2), (true, 3)] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let ecn_text = ecn.to_string();
                let mut extra = vec!["--dscp", "46", "--ecn", &ecn_text];
                if include_cos {
                    extra.push("--cos");
                }
                if mode == Mode::Keyed {
                    extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
                }
                let auth = mode.authenticated();
                let sender = Sender::start_profile(&peer, auth, 1, 1, false, &extra);
                let mut request = [0; 2048];
                let (length, source) = peer.recv_from(&mut request).unwrap();
                let request = &request[..length];
                let base = if auth { 112 } else { 44 };
                if auth {
                    assert_eq!(&request[96..112], &sign(&[&request[..96]]));
                }
                let mut pos = base;
                let mut found = false;
                while pos < request.len() {
                    assert!(pos + 4 <= request.len());
                    let size = u16::from_be_bytes([request[pos + 2], request[pos + 3]]) as usize;
                    assert!(pos + 4 + size <= request.len());
                    if request[pos + 1] == 4 {
                        assert!(!found, "one originated CoS TLV");
                        found = true;
                        assert_eq!(&request[pos..pos + 4], &[0x80, 4, 0, 4]);
                        assert_eq!(&request[pos + 4..pos + 4 + size], &[184, 0, ecn << 6, 0]);
                    }
                    if request[pos + 1] == 8 {
                        assert_eq!(pos + 20, request.len());
                        assert_eq!(
                            &request[pos + 4..],
                            &sign(&[&request[..4], &request[base..pos]])
                        );
                    }
                    pos += 4 + size;
                }
                assert_eq!(found, include_cos);
                // A valid independently signed forward-path CE report.
                let mut response = reply_with_extensions(
                    request,
                    auth,
                    &[0, 4, 0, 4, 184, 12, (ecn << 6) | 0x30, 0],
                );
                if mode == Mode::Keyed {
                    let digest = sign(&[&response[..4], &response[base..]]);
                    response.extend_from_slice(&[0, 8, 0, 16]);
                    response.extend_from_slice(&digest);
                }
                peer.send_to(&response, source).unwrap();
                let stats = sender.finish();
                assert_eq!(stats["packets_received"], 1);
                let active = include_cos && matches!(ecn, 1 | 2);
                assert_eq!(stats["congestion"].is_object(), active);
                if active {
                    assert_eq!(stats["congestion"]["ce_replies"], 1);
                    assert_eq!(stats["congestion"]["backoffs_applied"], 1);
                    assert!(
                        stats["congestion"]["current_interval_ms"].as_f64().unwrap()
                            > stats["congestion"]["base_interval_ms"].as_f64().unwrap()
                    );
                }
            }
        }
    }
}

fn peer(auth: bool) -> UdpSocket {
    let socket = UdpSocket::bind((if auth { "::1" } else { "127.0.0.1" }, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}
fn burst(auth: bool) {
    let peer = peer(auth);
    let sender = Sender::start(&peer, auth, 1, 3);
    let mut request = [0; 2048];
    let (len, source) = peer.recv_from(&mut request).unwrap();
    let mut previous = None;
    for n in 0..3 {
        let (bytes, timestamp) = reply(&request[..len], auth, 10 + n, [1, 1, n], previous);
        peer.send_to(&bytes, source).unwrap();
        if n == 0 {
            peer.send_to(&bytes, source).unwrap();
        }
        previous = Some((10 + n, timestamp));
        // Copies arrive after the main send loop and the first response.
        std::thread::sleep(Duration::from_millis(60));
    }
    let stats = sender.finish();
    assert_eq!(stats["packets_received"], 1, "{stats}");
    let m = &stats["measurements"];
    for (name, value) in [
        ("unique_replies", 3),
        ("additional_replies", 2),
        ("duplicate_replies", 1),
        ("unobserved_requested_replies", 0),
    ] {
        assert_eq!(m[name], value, "{stats}");
    }
    assert_eq!(m["reply_rtt"]["samples"], 3);
    assert_eq!(m["direct_measurement"]["forward_missing"], 0);
    assert_eq!(m["direct_measurement"]["reverse_missing"], 0);
    assert_eq!(m["follow_up"]["matched"], 2, "{stats}");
    assert!(
        m["follow_up"]["reverse_delay"]["avg_ms"]
            .as_f64()
            .unwrap()
            .abs()
            < 1000.0
    );
}
fn loss(auth: bool) {
    let peer = peer(auth);
    let sender = Sender::start(&peer, auth, 4, 1);
    let mut request = [0; 2048];
    let mut previous = None;
    for n in 0..4 {
        let (len, source) = peer.recv_from(&mut request).unwrap();
        assert_eq!(u32::from_be_bytes(request[..4].try_into().unwrap()), n);
        if n == 1 {
            continue;
        } // Model one request absent from reflector's in-profile count.
        let tx = if n == 0 { 0 } else { n - 1 + u32::from(n == 3) };
        let rx = if n == 0 { 1 } else { n };
        let (bytes, timestamp) = reply(&request[..len], auth, 10 + tx, [n + 1, rx, tx], previous);
        peer.send_to(&bytes, source).unwrap();
        previous = Some((10 + tx, timestamp));
    }
    let stats = sender.finish();
    assert_eq!(stats["packets_received"], 3, "{stats}");
    assert_eq!(stats["packets_lost"], 1);
    let m = &stats["measurements"]["direct_measurement"];
    assert_eq!(m["sender_packets"], 3, "{stats}");
    assert_eq!(m["reflector_received"], 2);
    assert_eq!(m["forward_missing"], 1);
    assert_eq!(m["reflector_transmitted"], 3);
    assert_eq!(m["replies_received"], 2);
    assert_eq!(m["reverse_missing"], 1);
}
#[test]
fn ipv4_open_burst_and_duplicate() {
    burst(false);
}

#[test]
fn sender_matches_every_echoed_timestamp_octet_before_consuming_a_probe() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for extensions in [false, true] {
                for clock in ["NTP", "PTP"] {
                    let peer = UdpSocket::bind((ip, 0)).unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                    let sender = Sender::start_profile(
                        &peer,
                        auth,
                        1,
                        1,
                        extensions,
                        &[
                            "--clock-source",
                            clock,
                            "--ssid",
                            "42",
                            "--on-zero-ssid",
                            "stop",
                        ],
                    );
                    let mut request = [0; 2048];
                    let (size, source) = peer.recv_from(&mut request).unwrap();
                    let request = &request[..size];
                    let (timestamp, ssid, base) = if auth { (16, 26, 112) } else { (4, 14, 44) };
                    assert!(request.len() >= base);
                    let transmit = |input: &[u8]| {
                        let (mut packet, _) = reply(input, auth, 10, [1, 1, 1], None);
                        if !extensions {
                            packet.truncate(base);
                        }
                        peer.send_to(&packet, source).unwrap();
                    };
                    let mut unknown = request.to_vec();
                    unknown[..4].copy_from_slice(&99u32.to_be_bytes());
                    unknown[ssid..ssid + 2].fill(0);
                    transmit(&unknown);
                    for byte in 0..8 {
                        let mut wrong = request.to_vec();
                        wrong[timestamp + byte] ^= 1;
                        // If the stale echo gets past identity validation,
                        // zero-SSID stop would end the run before the good one.
                        wrong[ssid..ssid + 2].fill(0);
                        transmit(&wrong);
                    }
                    transmit(request);
                    let stats = sender.finish();
                    assert_eq!(
                        stats["packets_received"], 1,
                        "{ip} auth={auth} ext={extensions} {clock}: {stats}"
                    );
                    assert_eq!(stats["packets_lost"], 0);
                    assert_eq!(stats["measurements"]["mismatched_replies"], 8);
                    assert_eq!(stats["measurements"]["unknown_replies"], 1);
                    assert_eq!(stats["measurements"]["unique_replies"], 1);
                }
            }
        }
    }
}
#[test]
fn ipv6_authenticated_burst_and_duplicate() {
    burst(true);
}
#[test]
fn ipv4_open_directional_counter_window() {
    loss(false);
}
#[test]
fn ipv6_authenticated_directional_counter_window() {
    loss(true);
}

#[test]
fn sender_holds_ecn_backoff_until_usable_non_ce_feedback_returns() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            for case in ["clean", "missing", "bad_hmac", "duplicate"] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut extra = vec!["--cos", "--ecn", "2", "--ecn-recovery-step", "10"];
                if mode == Mode::Keyed {
                    extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
                }
                let auth = mode.authenticated();
                let sender = Sender::start_profile(&peer, auth, 3, 1, false, &extra);
                for index in 0..3 {
                    let mut request = [0; 2048];
                    let (length, source) = peer.recv_from(&mut request).unwrap();
                    // Independent CoS bytes: CE first, then test feedback, then
                    // usable non-CE. Each response matches an actual sent probe.
                    let mut tail = vec![0, 4, 0, 4, 0, if index == 0 { 12 } else { 8 }, 0xb0, 0];
                    if index == 1 {
                        if case == "missing" {
                            tail.clear();
                        }
                        if case == "duplicate" {
                            tail.extend_from_within(..);
                        }
                    }
                    let mut response = reply_with_extensions(&request[..length], auth, &tail);
                    let base = if auth { 112 } else { 44 };
                    if !auth && (mode == Mode::Keyed || (index == 1 && case == "bad_hmac")) {
                        let digest = sign(&[&response[..4], &response[base..]]);
                        response.extend_from_slice(&[0, 8, 0, 16]);
                        response.extend_from_slice(&digest);
                    }
                    if index == 1 && case == "bad_hmac" {
                        *response.last_mut().unwrap() ^= 1;
                    }
                    peer.send_to(&response, source).unwrap();
                }
                let stats = sender.finish();
                assert_eq!(
                    stats["packets_received"], 3,
                    "{ip} mode={mode:?} case={case}"
                );
                assert_eq!(stats["congestion"]["ce_replies"], 1);
                assert_eq!(stats["congestion"]["backoffs_applied"], 1);
                assert_eq!(
                    stats["congestion"]["current_interval_ms"].as_f64().unwrap(),
                    if case == "clean" { 20.0 } else { 30.0 },
                    "{ip} mode={mode:?} case={case}"
                );
            }
        }
    }
}

#[test]
fn near_unity_ce_factors_do_not_stall_sender_backoff() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            for (delay, factor, base_ms) in [
                ("1us", "1.0001", 0.001),
                ("100", "1.0000000000000002", 100.0),
            ] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut extra = vec![
                    "--cos",
                    "--ecn",
                    "2",
                    "--send-delay",
                    delay,
                    "--ecn-backoff-factor",
                    factor,
                ];
                if mode == Mode::Keyed {
                    extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
                }
                let auth = mode.authenticated();
                let sender = Sender::start_profile(&peer, auth, 1, 1, false, &extra);
                let mut request = [0; 2048];
                let (length, source) = peer.recv_from(&mut request).unwrap();
                let mut response =
                    reply_with_extensions(&request[..length], auth, &[0, 4, 0, 4, 0, 12, 0xb0, 0]);
                if mode == Mode::Keyed {
                    let digest = sign(&[&response[..4], &response[44..]]);
                    response.extend_from_slice(&[0, 8, 0, 16]);
                    response.extend_from_slice(&digest);
                }
                peer.send_to(&response, source).unwrap();
                let stats = sender.finish();
                assert_eq!(stats["packets_received"], 1);
                assert_eq!(stats["congestion"]["ce_replies"], 1);
                assert_eq!(stats["congestion"]["backoffs_applied"], 1);
                let interval = stats["congestion"]["current_interval_ms"].as_f64().unwrap();
                assert!(
                    (interval - base_ms - 0.000001).abs() < 1e-12,
                    "{ip} mode={mode:?} factor={factor}: {interval}"
                );
            }
        }
    }
}

#[test]
fn incomplete_retry_bursts_keep_the_send_based_timeout_after_ack_or_abort() {
    // The reply window is --timeout (3 s) from the retry's send. A window
    // restarted by the late ACK (1.5 s) or by exhaustion (the 2 s report
    // timer) would end at 4.5 s or later. Bounds of [2.8 s, 3.9 s) leave 900 ms
    // for process scheduling and exit under CI load and still catch a restart.
    const WINDOW: Duration = Duration::from_secs(3);
    for acknowledge in [true, false] {
        let peer = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let sender = Sender::start_profile(
            &peer,
            false,
            1,
            3,
            false,
            &[
                "--timeout",
                "3",
                "--access-report",
                "1",
                "--access-report-timeout",
                "2",
                "--access-report-retries",
                "1",
            ],
        );
        let mut request = [0; 2048];
        let (length, source) = peer.recv_from(&mut request).unwrap();
        // All initial copies arrive, but report delivery remains unconfirmed.
        for _ in 0..3 {
            peer.send_to(
                &reply_with_extensions(&request[..length], false, &[]),
                source,
            )
            .unwrap();
        }
        let (length, _) = peer.recv_from(&mut request).unwrap();
        let retry_received = Instant::now();
        let tail = if acknowledge {
            // A later ACK, before the report timer expires, must not start a
            // fresh reply window.
            std::thread::sleep(Duration::from_millis(1500));
            &[0, 6, 0, 4, 0x10, 1, 0, 0][..]
        } else {
            // Delivery has exhausted its two-second timer, but a valid base
            // reply can still arrive within the retry's reply window.
            std::thread::sleep(Duration::from_millis(2300));
            &[][..]
        };
        peer.send_to(
            &reply_with_extensions(&request[..length], false, tail),
            source,
        )
        .unwrap();
        let stats = sender.finish();
        let elapsed = retry_received.elapsed();
        assert!(
            elapsed >= WINDOW - Duration::from_millis(200),
            "reply window ended early: {elapsed:?}"
        );
        assert!(
            elapsed < WINDOW + Duration::from_millis(900),
            "reply window was restarted: {elapsed:?}"
        );
        assert_eq!(stats["packets_sent"], 2);
        assert_eq!(stats["packets_received"], 2);
        assert_eq!(stats["packets_lost"], 0);
        assert_eq!(
            stats["access_report"]["outcome"],
            if acknowledge {
                "acknowledged"
            } else {
                "aborted"
            }
        );
        assert_eq!(stats["access_report"]["retransmissions"], 1);
        assert_eq!(stats["measurements"]["unique_replies"], 4);
        assert_eq!(stats["measurements"]["unobserved_requested_replies"], 2);
    }
}

#[test]
fn access_report_acknowledgement_keeps_later_retry_burst_copies() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            for retry_during_drain in [false, true] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                // The report timer equals --timeout, so the retry is sent as the
                // original drain window ends. Two seconds leave the late copies
                // below ample time to arrive within the retry's reply window.
                let mut extra = vec![
                    "--timeout",
                    "2",
                    "--access-report",
                    "2",
                    "--access-return-code",
                    "255",
                    "--access-report-timeout",
                    "2",
                    "--access-report-retries",
                    "1",
                ];
                if mode == Mode::Keyed {
                    extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
                }
                let auth = mode.authenticated();
                let sender = Sender::start_profile(&peer, auth, 1, 3, false, &extra);
                let encode = |request: &[u8], tail: &[u8]| {
                    let mut response = reply_with_extensions(request, auth, tail);
                    if mode == Mode::Keyed && !tail.is_empty() {
                        let digest = sign(&[&response[..4], &response[44..]]);
                        response.extend_from_slice(&[0, 8, 0, 16]);
                        response.extend_from_slice(&digest);
                    }
                    response
                };
                let mut buffer = [0; 2048];
                let (length, source) = peer.recv_from(&mut buffer).unwrap();
                let original = buffer[..length].to_vec();
                // Complete the initial burst to enter report completion early,
                // or hold one copy so the retry occurs near the drain deadline.
                for _ in 0..if retry_during_drain { 2 } else { 3 } {
                    peer.send_to(&encode(&original, &[]), source).unwrap();
                }
                let (length, _) = peer.recv_from(&mut buffer).unwrap();
                let retry = buffer[..length].to_vec();
                let base = if auth { 112 } else { 44 };
                let mut offset = base;
                let mut copies = None;
                let mut reports = 0;
                while offset < length {
                    let size =
                        usize::from(u16::from_be_bytes([retry[offset + 2], retry[offset + 3]]));
                    let end = offset + 4 + size;
                    assert!(end <= length);
                    match retry[offset + 1] {
                        6 => {
                            reports += 1;
                            assert_eq!(&retry[offset + 4..end], &[0x20, 255, 0, 0]);
                        }
                        12 => {
                            copies = Some(u32::from_be_bytes(
                                retry[offset + 4..offset + 8].try_into().unwrap(),
                            ))
                        }
                        _ => (),
                    }
                    offset = end;
                }
                assert_eq!(reports, 1);
                assert_eq!(copies, Some(3));
                let acknowledgement = encode(&retry, &[0, 6, 0, 4, 0x20, 255, 0, 0]);
                peer.send_to(&acknowledgement, source).unwrap();
                peer.send_to(&acknowledgement, source).unwrap(); // exact duplicate

                // The sender must remain alive for later distinct burst copies,
                // after both the acknowledgement and the original drain window.
                std::thread::sleep(Duration::from_millis(150));
                if retry_during_drain {
                    peer.send_to(&encode(&original, &[]), source).unwrap();
                }
                for _ in 0..2 {
                    peer.send_to(&encode(&retry, &[]), source).unwrap();
                }
                let stats = sender.finish();
                assert_eq!(stats["packets_sent"], 2);
                assert_eq!(stats["packets_received"], 2);
                assert_eq!(stats["packets_lost"], 0);
                assert_eq!(stats["access_report"]["outcome"], "acknowledged");
                assert_eq!(stats["access_report"]["retransmissions"], 1);
                let measurements = &stats["measurements"];
                assert_eq!(
                    measurements["unique_replies"], 6,
                    "{ip} mode={mode:?} drain={retry_during_drain}: {stats}"
                );
                assert_eq!(measurements["additional_replies"], 4);
                assert_eq!(measurements["duplicate_replies"], 1);
                assert_eq!(measurements["unobserved_requested_replies"], 0);
                assert_eq!(measurements["reply_rtt"]["samples"], 6);
            }
        }
    }
}

#[test]
fn access_report_retries_during_pacing_preserve_scheduled_count_and_duration() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut extra = vec![
                "--send-delay",
                "4000",
                "--duration",
                "5",
                "--access-report",
                "2",
                "--access-return-code",
                "255",
                "--access-report-timeout",
                "1",
                "--access-report-retries",
                "2",
            ];
            if mode == Mode::Keyed {
                extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
            }
            let auth = mode.authenticated();
            let sender = Sender::start_profile(&peer, auth, 2, 1, false, &extra);
            let mut buffer = [0; 2048];
            let (length, source) = peer.recv_from(&mut buffer).unwrap();
            let started = Instant::now();
            let base = if auth { 112 } else { 44 };
            let report = [0x80, 6, 0, 4, 0x20, 255, 0, 0];
            assert_eq!(&buffer[base..base + 8], &report);
            let send = |request: &[u8], tail: &[u8]| {
                let mut response = reply_with_extensions(request, auth, tail);
                if mode == Mode::Keyed && !tail.is_empty() {
                    let digest = sign(&[&response[..4], &response[44..]]);
                    response.extend_from_slice(&[0, 8, 0, 16]);
                    response.extend_from_slice(&digest);
                }
                peer.send_to(&response, source).unwrap();
            };
            // Accept the original RTT without acknowledging report delivery.
            send(&buffer[..length], &[]);
            let first_seq = buffer[..4].to_vec();
            let (length, retry_source) = peer
                .recv_from(&mut buffer)
                .expect("report retry must precede the four-second probe deadline");
            assert_eq!(retry_source, source);
            assert!(started.elapsed() >= Duration::from_millis(800));
            assert_ne!(&buffer[..4], &first_seq);
            assert_eq!(&buffer[base..base + 8], &report);
            send(&buffer[..length], &[0, 6, 0, 4, 0x20, 255, 0, 0]);
            let retry_seq = buffer[..4].to_vec();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let (length, _) = peer
                .recv_from(&mut buffer)
                .expect("a timer retry must not consume the second scheduled probe");
            assert!(started.elapsed() >= Duration::from_millis(3800));
            assert_ne!(&buffer[..4], &retry_seq);
            let mut offset = base;
            while offset < length {
                let size =
                    usize::from(u16::from_be_bytes([buffer[offset + 2], buffer[offset + 3]]));
                assert_ne!(
                    buffer[offset + 1],
                    6,
                    "acknowledged report must not be resent"
                );
                offset += 4 + size;
            }
            assert_eq!(offset, length);
            send(&buffer[..length], &[]);
            let stats = sender.finish();
            // The duration caps the final scheduled wait (otherwise 8 seconds).
            assert!(started.elapsed() < Duration::from_secs(7));
            assert_eq!(stats["packets_sent"], 3, "{ip} mode={mode:?}");
            assert_eq!(stats["packets_received"], 3);
            assert_eq!(stats["packets_lost"], 0);
            assert_eq!(stats["access_report"]["outcome"], "acknowledged");
            assert_eq!(stats["access_report"]["retransmissions"], 1);
        }
    }
}

#[test]
fn access_report_retries_during_final_reply_drain() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut extra = vec![
                "--timeout",
                "10",
                "--access-report",
                "2",
                "--access-return-code",
                "255",
                "--access-report-timeout",
                "1",
                "--access-report-retries",
                "2",
            ];
            if mode == Mode::Keyed {
                extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
            }
            let auth = mode.authenticated();
            let sender = Sender::start_profile(&peer, auth, 1, 1, false, &extra);
            let mut buffer = [0; 2048];
            let (length, source) = peer.recv_from(&mut buffer).unwrap();
            let first = buffer[..length].to_vec();
            let base = if auth { 112 } else { 44 };
            let report = [0x80, 6, 0, 4, 0x20, 255, 0, 0];
            assert_eq!(&first[base..base + 8], &report);
            let started = Instant::now();
            let (length, retry_source) = peer
                .recv_from(&mut buffer)
                .expect("Access Report retry must not wait for the ten-second reply drain");
            assert_eq!(retry_source, source);
            assert!(started.elapsed() >= Duration::from_millis(800));
            assert_eq!(&buffer[base..base + 8], &report);
            assert_ne!(&first[..4], &buffer[..4], "retry needs a fresh sequence");
            let send = |request: &[u8], tail: &[u8]| {
                let mut response = reply_with_extensions(request, auth, tail);
                if mode == Mode::Keyed && !tail.is_empty() {
                    let digest = sign(&[&response[..4], &response[44..]]);
                    response.extend_from_slice(&[0, 8, 0, 16]);
                    response.extend_from_slice(&digest);
                }
                peer.send_to(&response, source).unwrap();
            };
            send(&buffer[..length], &[0, 6, 0, 4, 0x20, 255, 0, 0]);
            // Keep the original probe pending beyond the next retry deadline.
            // Acknowledging the retry must disarm its timer during the drain.
            peer.set_read_timeout(Some(Duration::from_millis(1500)))
                .unwrap();
            let error = peer.recv_from(&mut buffer).unwrap_err();
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
            send(&first, &[]);
            let stats = sender.finish();
            assert_eq!(stats["packets_sent"], 2, "{ip} mode={mode:?}");
            assert_eq!(stats["packets_received"], 2);
            assert_eq!(stats["packets_lost"], 0);
            assert_eq!(stats["access_report"]["outcome"], "acknowledged");
            assert_eq!(stats["access_report"]["retransmissions"], 1);
        }
    }
}

#[test]
fn access_report_retries_until_one_matching_unambiguous_echo() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let (id, code) = match mode {
                Mode::Open => (1u8, 1u8),
                Mode::Keyed => (2, 255),
                Mode::Authenticated => (2, 0),
            };
            let (id_text, code_text) = (id.to_string(), code.to_string());
            let mut extra = vec![
                "--access-report",
                &id_text,
                "--access-return-code",
                &code_text,
                "--access-report-timeout",
                "1",
                "--access-report-retries",
                "1",
            ];
            if mode == Mode::Keyed {
                extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
            }
            let auth = mode.authenticated();
            let sender = Sender::start_profile(&peer, auth, 1, 1, false, &extra);
            let mut request = [0; 2048];
            let (length, source) = peer.recv_from(&mut request).unwrap();
            let base = if auth { 112 } else { 44 };
            let originated = [0x80, 6, 0, 4, id << 4, code, 0, 0];
            assert_eq!(&request[base..base + 8], &originated);
            let send = |request: &[u8], tail: &[u8]| {
                let mut response = reply_with_extensions(request, auth, tail);
                if mode == Mode::Keyed {
                    let digest = sign(&[&response[..4], &response[44..]]);
                    response.extend_from_slice(&[0, 8, 0, 16]);
                    response.extend_from_slice(&digest);
                }
                peer.send_to(&response, source).unwrap();
            };
            // All base replies and signatures are valid. None confirms the
            // single report sent by this session.
            for value in [
                [(3 - id) << 4, code, 0, 0],
                [id << 4, code ^ 1, 0, 0],
                [0, code, 0, 0],
                [0xf0, code, 0, 0],
            ] {
                let mut tail = vec![0, 6, 0, 4];
                tail.extend_from_slice(&value);
                send(&request[..length], &tail);
            }
            // A matching first report must not hide a conflicting duplicate,
            // including a second instance carrying the U flag.
            for flags in [0, 0x80] {
                send(
                    &request[..length],
                    &[
                        0,
                        6,
                        0,
                        4,
                        id << 4,
                        code,
                        0,
                        0,
                        flags,
                        6,
                        0,
                        4,
                        (3 - id) << 4,
                        code,
                        0,
                        0,
                    ],
                );
            }
            let (length, _) = peer
                .recv_from(&mut request)
                .expect("a mismatched report must not cancel the retry");
            assert_eq!(&request[base..base + 8], &originated);
            // Reserved bits and bytes must still be ignored on a matching echo.
            send(
                &request[..length],
                &[0, 6, 0, 4, (id << 4) | 0x0f, code, 0xff, 0xff],
            );
            let stats = sender.finish();
            assert_eq!(stats["packets_sent"], 2, "{ip} mode={mode:?}");
            assert_eq!(stats["packets_received"], 2);
            assert_eq!(stats["packets_lost"], 0);
            assert_eq!(stats["access_report"]["outcome"], "acknowledged");
            assert_eq!(stats["access_report"]["retransmissions"], 1);
        }
    }
}

#[test]
fn sender_applies_ce_backoff_to_the_already_scheduled_probe() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in Mode::ALL {
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            // The CE reply must be processed before the already scheduled
            // second probe is due (400 ms), which leaves ample time on loaded
            // CI hosts. Backoff then moves that probe to 2 s after the first.
            let mut extra = vec![
                "--cos",
                "--ecn",
                "2",
                "--send-delay",
                "400",
                "--ecn-backoff-factor",
                "5",
            ];
            if mode == Mode::Keyed {
                extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
            }
            let auth = mode.authenticated();
            let sender = Sender::start_profile(&peer, auth, 2, 1, false, &extra);
            let mut request = [0; 2048];
            let (length, source) = peer.recv_from(&mut request).unwrap();
            let first = Instant::now();
            let mut response =
                reply_with_extensions(&request[..length], auth, &[0, 4, 0, 4, 0, 12, 0xb0, 0]);
            if mode == Mode::Keyed {
                let digest = sign(&[&response[..4], &response[44..]]);
                response.extend_from_slice(&[0, 8, 0, 16]);
                response.extend_from_slice(&digest);
            }
            peer.send_to(&response, source).unwrap();
            let (length, source) = peer.recv_from(&mut request).unwrap();
            let gap = first.elapsed();
            // Wide margin for process/socket scheduling, but well beyond the
            // stale 400 ms deadline. Exact timing is covered by timeline tests.
            assert!(
                gap >= Duration::from_millis(1500),
                "{ip} mode={mode:?}: {gap:?}"
            );
            peer.send_to(
                &reply_with_extensions(&request[..length], auth, &[]),
                source,
            )
            .unwrap();
            let stats = sender.finish();
            assert_eq!(stats["packets_received"], 2);
            assert_eq!(stats["congestion"]["ce_replies"], 1);
            assert_eq!(stats["congestion"]["current_interval_ms"], 2000.0);
        }
    }
}

#[test]
fn zero_ssid_stop_interrupts_a_long_probe_wait_after_identity_validation() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for extensions in [false, true] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut extra = vec![
                    "--send-delay",
                    "10s",
                    "--ssid",
                    "42",
                    "--on-zero-ssid",
                    "stop",
                ];
                if extensions {
                    extra.extend(["--access-report", "1"]);
                }
                let sender = Sender::start_profile(&peer, auth, 10, 1, extensions, &extra);
                let mut request = [0; 2048];
                let (length, source) = peer.recv_from(&mut request).unwrap();
                let mut zero_ssid = request[..length].to_vec();
                let (timestamp, ssid) = if auth { (16, 26) } else { (4, 14) };
                zero_ssid[ssid..ssid + 2].fill(0);
                let transmit = |input: &[u8]| {
                    peer.send_to(&reply_with_extensions(input, auth, &[]), source)
                        .unwrap();
                };
                // Neither an unknown sequence nor a stale timestamp may stop
                // the run, even when the reply has a valid base HMAC.
                let mut unknown = zero_ssid.clone();
                unknown[..4].copy_from_slice(&99u32.to_be_bytes());
                transmit(&unknown);
                let mut stale = zero_ssid.clone();
                stale[timestamp] ^= 1;
                transmit(&stale);
                let started = Instant::now();
                transmit(&zero_ssid);
                let stats = sender.finish();
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "{ip} auth={auth} ext={extensions}"
                );
                assert_eq!(stats["packets_sent"], 1);
                assert_eq!(stats["packets_received"], 0);
                assert_eq!(stats["packets_lost"], 1);
                assert_eq!(stats["measurements"]["unknown_replies"], 1);
                assert_eq!(stats["measurements"]["mismatched_replies"], 1);
                if extensions {
                    assert_eq!(stats["access_report"]["retransmissions"], 0);
                    assert_eq!(stats["access_report"]["outcome"], "pending");
                }
            }
        }
    }
}

#[test]
fn zero_ssid_continue_keeps_sending_and_accepts_the_next_matching_reply() {
    for ip in ["127.0.0.1", "::1"] {
        for auth in [false, true] {
            for extensions in [false, true] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let sender = Sender::start_profile(
                    &peer,
                    auth,
                    2,
                    1,
                    extensions,
                    &[
                        "--send-delay",
                        "100",
                        "--ssid",
                        "42",
                        "--on-zero-ssid",
                        "continue",
                    ],
                );
                for index in 0..2 {
                    let mut request = [0; 2048];
                    let (length, source) = peer.recv_from(&mut request).unwrap();
                    let ssid = if auth { 26 } else { 14 };
                    assert_eq!(&request[ssid..ssid + 2], &42u16.to_be_bytes());
                    if index == 0 {
                        request[ssid..ssid + 2].fill(0);
                    }
                    peer.send_to(
                        &reply_with_extensions(&request[..length], auth, &[]),
                        source,
                    )
                    .unwrap();
                }
                let stats = sender.finish();
                assert_eq!(stats["packets_sent"], 2);
                assert_eq!(stats["packets_received"], 2);
                assert_eq!(stats["packets_lost"], 0);
            }
        }
    }
}
