//! Independent wire peer verifies sender summaries and final burst draining.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    net::UdpSocket,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Sender(Option<Child>);
impl Drop for Sender {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
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
                "--send-delay",
                "20",
                "--timeout",
                "1",
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
        Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ))
    }
    fn finish(mut self) -> serde_json::Value {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "sender failed to exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = self.0.take().unwrap().wait_with_output().unwrap();
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
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0xAB; 16]).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes()[..16].try_into().unwrap()
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
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
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
fn sender_origins_rfc8972_tlvs_with_u_set_and_m_i_clear() {
    for ip in ["127.0.0.1", "::1"] {
        for mode in 0..3 {
            let auth = mode == 2;
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
            if mode == 1 {
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
                if mode == 0 {
                    (1..=7).collect::<Vec<_>>()
                } else {
                    (1..=8).collect()
                }
            );
            let mut response = reply_with_extensions(request, auth, &echo);
            if mode == 1 {
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
        for mode in 0..3 {
            let auth = mode == 2;
            let peer = UdpSocket::bind((ip, 0)).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let mut extra = vec!["--timestamp-info"];
            if mode == 1 {
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
        for mode in 0..3 {
            for (include_cos, ecn) in [(false, 0u8), (true, 0), (true, 1), (true, 2), (true, 3)] {
                let peer = UdpSocket::bind((ip, 0)).unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let ecn_text = ecn.to_string();
                let mut extra = vec!["--dscp", "46", "--ecn", &ecn_text];
                if include_cos {
                    extra.push("--cos");
                }
                if mode == 1 {
                    extra.extend(["--hmac-key", "ABABABABABABABABABABABABABABABAB"]);
                }
                let auth = mode == 2;
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
                if mode == 1 {
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
