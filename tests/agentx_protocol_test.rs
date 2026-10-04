//! Independent AgentX master wire fixtures; no production encoders/decoders.
#![cfg(all(unix, feature = "snmp"))]
use stamp_suite::shutdown::CancellationToken;
use stamp_suite::snmp::agentx::{AgentXSession, MibHandler, Oid, VarBind, VarBindValue};
use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    thread,
    time::Duration,
};

struct Mib;
impl MibHandler for Mib {
    fn get(&self, oid: &Oid) -> VarBind {
        let value = if [
            vec![1, 1],
            vec![1, 2],
            vec![1, 3],
            vec![2, 1],
            vec![2, 2],
            vec![2, 3],
        ]
        .contains(&oid.0)
        {
            VarBindValue::Integer(*oid.0.last().unwrap() as i32)
        } else {
            VarBindValue::NoSuchInstance
        };
        VarBind {
            oid: oid.clone(),
            value,
        }
    }
    fn get_next(&self, oid: &Oid, end: &Oid) -> VarBind {
        for next in [
            vec![1, 1],
            vec![1, 2],
            vec![1, 3],
            vec![2, 1],
            vec![2, 2],
            vec![2, 3],
        ] {
            if next > oid.0 && (end.is_empty() || next < end.0) {
                return self.get(&Oid(next));
            }
        }
        VarBind {
            oid: oid.clone(),
            value: VarBindValue::EndOfMibView,
        }
    }
}
fn oid(subs: &[u32], include: bool) -> Vec<u8> {
    let mut data = vec![subs.len() as u8, 0, u8::from(include), 0];
    for sub in subs {
        data.extend_from_slice(&sub.to_be_bytes());
    }
    data
}
fn range(start: &[u32], include: bool, end: &[u32]) -> Vec<u8> {
    [oid(start, include), oid(end, false)].concat()
}
fn pdu(kind: u8, session: u32, transaction: u32, packet: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![1, kind, 0x10, 0];
    for n in [session, transaction, packet, payload.len() as u32] {
        data.extend_from_slice(&n.to_be_bytes());
    }
    data.extend_from_slice(payload);
    data
}
fn read_pdu(stream: &mut UnixStream) -> (Vec<u8>, Vec<u8>) {
    let mut header = vec![0; 20];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(header[0], 1);
    assert_eq!(header[2] & 0x10, 0x10);
    let len = u32::from_be_bytes(header[16..20].try_into().unwrap()) as usize;
    assert!(len <= 1_048_576);
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).unwrap();
    (header, payload)
}
struct Peer {
    stream: UnixStream,
    cancel: CancellationToken,
    worker: Option<thread::JoinHandle<Result<(), String>>>,
    _dir: tempfile::TempDir,
}
impl Peer {
    fn start() -> Self {
        Self::start_with_echo(false)
    }

    fn start_with_echo(echo: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master");
        let listener = UnixListener::bind(&path).unwrap();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let worker = thread::spawn(move || {
            let mut session = AgentXSession::connect(path.to_str().unwrap(), "wire fixture")
                .map_err(|e| e.to_string())?;
            session.register(&Oid(vec![1])).map_err(|e| e.to_string())?;
            session.run_loop(&Mib, &stop).map_err(|e| e.to_string())
        });
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        for kind in [1, 3] {
            let (h, body) = read_pdu(&mut stream);
            assert_eq!(h[1], kind);
            let id = u32::from_be_bytes(h[12..16].try_into().unwrap());
            let mut payload = vec![0; 8];
            if echo {
                payload.extend([0, if kind == 1 { 4 } else { 5 }, 0, 0]);
                if kind == 1 {
                    // Net-SNMP canonicalizes the null Open OID to 0.0.
                    payload.extend([2, 0, 0, 0]);
                    payload.extend([0; 8]);
                    payload.extend(&body[8..]);
                } else {
                    payload.extend(&body[4..]);
                }
            }
            stream.write_all(&pdu(18, 42, 0, id, &payload)).unwrap();
        }
        Self {
            stream,
            cancel,
            worker: Some(worker),
            _dir: dir,
        }
    }
    fn request(&mut self, kind: u8, payload: &[u8]) -> Vec<u8> {
        let request = pdu(kind, 42, 7, 11, payload);
        self.stream.write_all(&request).unwrap();
        self.response(&request)
    }
    fn response(&mut self, request: &[u8]) -> Vec<u8> {
        let (h, payload) = read_pdu(&mut self.stream);
        assert_eq!(h[1], 18);
        assert_eq!(&h[4..16], &request[4..16]);
        assert!(payload.len() >= 8);
        assert_eq!(&payload[4..8], &[0; 4]);
        payload[8..].to_vec()
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn net_snmp_echoed_administrative_bindings_register_and_serve() {
    let mut peer = Peer::start_with_echo(true);
    let payload = range(&[1, 1], false, &[]);
    let response = peer.request(5, &payload);
    assert_eq!(bindings(&response), vec![(2, vec![1, 1])]);
    assert_eq!(&response[response.len() - 4..], &1u32.to_be_bytes());
}
fn bindings(mut data: &[u8]) -> Vec<(u16, Vec<u32>)> {
    let mut result = vec![];
    while !data.is_empty() {
        let kind = u16::from_be_bytes(data[..2].try_into().unwrap());
        assert_eq!(&data[2..4], &[0; 2]);
        let n = data[4] as usize;
        let mut name = if data[5] == 0 {
            vec![]
        } else {
            vec![1, 3, 6, 1, data[5] as u32]
        };
        for chunk in data[8..8 + 4 * n].chunks_exact(4) {
            name.push(u32::from_be_bytes(chunk.try_into().unwrap()));
        }
        let len = 8
            + 4 * n
            + match kind {
                2 => 4,
                130 => 0,
                _ => panic!("unexpected varbind {kind}"),
            };
        result.push((kind, name));
        data = &data[len..];
    }
    result
}
fn bulk(n: u16, m: u16, ranges: &[Vec<u8>]) -> Vec<u8> {
    let mut data = [n.to_be_bytes(), m.to_be_bytes()].concat();
    for r in ranges {
        data.extend_from_slice(r);
    }
    data
}
#[test]
fn bulk_repetitions_are_interleaved() {
    let mut peer = Peer::start();
    let body = bulk(
        0,
        2,
        &[range(&[1, 0], false, &[2]), range(&[2, 0], false, &[])],
    );
    assert_eq!(
        bindings(&peer.request(7, &body)),
        vec![
            (2, vec![1, 1]),
            (2, vec![2, 1]),
            (2, vec![1, 2]),
            (2, vec![2, 2])
        ]
    );
}
#[test]
fn bulk_keeps_exhausted_ranges_until_all_end() {
    let mut peer = Peer::start();
    let body = bulk(
        0,
        9,
        &[range(&[1, 1], false, &[1, 3]), range(&[2, 0], false, &[])],
    );
    assert_eq!(
        bindings(&peer.request(7, &body)),
        vec![
            (2, vec![1, 2]),
            (2, vec![2, 1]),
            (130, vec![1, 2]),
            (2, vec![2, 2]),
            (130, vec![1, 2]),
            (2, vec![2, 3]),
            (130, vec![1, 2]),
            (130, vec![2, 3])
        ]
    );
}
#[test]
fn inclusive_starts_apply_once_with_exclusive_ends() {
    let mut peer = Peer::start();
    let ranges = [range(&[1, 1], true, &[1, 3]), range(&[2, 1], true, &[2, 3])];
    assert_eq!(
        bindings(&peer.request(6, &ranges.concat())),
        vec![(2, vec![1, 1]), (2, vec![2, 1])]
    );
    assert_eq!(
        bindings(&peer.request(7, &bulk(1, 3, &ranges))),
        vec![
            (2, vec![1, 1]),
            (2, vec![2, 1]),
            (2, vec![2, 2]),
            (130, vec![2, 2])
        ]
    );
    assert_eq!(
        bindings(&peer.request(6, &range(&[1, 1], true, &[1, 1]))),
        vec![(130, vec![1, 1])]
    );
}
#[test]
fn bulk_zero_repetitions_and_all_non_repeaters() {
    let mut peer = Peer::start();
    let ranges = [range(&[1, 0], false, &[2]), range(&[2, 0], false, &[])];
    assert!(peer.request(7, &bulk(0, 0, &ranges)).is_empty());
    assert_eq!(
        bindings(&peer.request(7, &bulk(1, 0, &ranges))),
        vec![(2, vec![1, 1])]
    );
    assert_eq!(
        bindings(&peer.request(7, &bulk(10, 0, &ranges))),
        vec![(2, vec![1, 1]), (2, vec![2, 1])]
    );
}
#[test]
fn fragmented_header_and_payload_survive_timeout_ticks() {
    let mut peer = Peer::start();
    let request = pdu(7, 42, 19, 23, &bulk(0, 1, &[range(&[1, 0], false, &[2])]));
    peer.stream.write_all(&request[..7]).unwrap();
    thread::sleep(Duration::from_millis(1250));
    peer.stream.write_all(&request[7..23]).unwrap();
    thread::sleep(Duration::from_millis(1250));
    peer.stream.write_all(&request[23..]).unwrap();
    assert_eq!(bindings(&peer.response(&request)), vec![(2, vec![1, 1])]);
    // The following frame must still start at the correct byte.
    assert_eq!(
        bindings(&peer.request(5, &range(&[2, 2], false, &[]))),
        vec![(2, vec![2, 2])]
    );
}
#[test]
fn master_close_receives_correlated_success_before_exit() {
    let mut peer = Peer::start();
    assert!(peer.request(2, &[1, 0, 0, 0]).is_empty());
    assert!(peer.worker.take().unwrap().join().unwrap().is_ok());
}

#[test]
fn coalesced_frames_and_initially_exhausted_range_keep_positions() {
    let mut peer = Peer::start();
    let body = bulk(0, 2, &[range(&[9], false, &[]), range(&[2, 0], false, &[])]);
    let first = pdu(7, 42, 31, 51, &body);
    let second = pdu(5, 42, 32, 52, &range(&[1, 3], false, &[]));
    peer.stream
        .write_all(&[first.clone(), second.clone()].concat())
        .unwrap();
    assert_eq!(
        bindings(&peer.response(&first)),
        vec![
            (130, vec![9]),
            (2, vec![2, 1]),
            (130, vec![9]),
            (2, vec![2, 2])
        ]
    );
    assert_eq!(bindings(&peer.response(&second)), vec![(2, vec![1, 3])]);
}

#[test]
fn cancellation_during_partial_frame_closes_transport_promptly() {
    let mut peer = Peer::start();
    peer.stream.write_all(&[1, 7, 0x10, 0, 0, 0, 0]).unwrap();
    // Ensure the peer has time to read the partial header, then cancel
    // during its next read. It must not wait to complete a bogus Close response.
    thread::sleep(Duration::from_millis(100));
    let start = std::time::Instant::now();
    peer.cancel.cancel();
    assert!(peer.worker.take().unwrap().join().unwrap().is_ok());
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(peer.stream.read(&mut [0; 20]).unwrap(), 0);
}

#[test]
fn range_limit_returns_an_error_without_losing_session_framing() {
    let mut peer = Peer::start();
    for kind in [5, 6, 7] {
        let ranges = vec![range(&[1, 0], false, &[2]); 257];
        let body = if kind == 7 {
            bulk(0, 2, &ranges)
        } else {
            ranges.concat()
        };
        let request = pdu(kind, 42, 70, 80, &body);
        peer.stream.write_all(&request).unwrap();
        let (header, body) = read_pdu(&mut peer.stream);
        assert_eq!(&header[4..16], &request[4..16]);
        assert_eq!(&body[4..], &[0, 5, 1, 1]); // genErr, SearchRange index 257
    }
    assert_eq!(
        bindings(&peer.request(5, &range(&[1, 2], false, &[]))),
        vec![(2, vec![1, 2])]
    );
}

#[test]
fn cancellation_closes_the_session_with_reason_shutdown() {
    let mut peer = Peer::start();
    peer.cancel.cancel();
    // Close-PDU (type 2) whose first payload octet is reasonShutdown (5),
    // RFC 2741 §6.2.2.
    let (h, payload) = read_pdu(&mut peer.stream);
    assert_eq!(h[1], 2);
    assert_eq!(payload[0], 5);
    let id = u32::from_be_bytes(h[12..16].try_into().unwrap());
    peer.stream.write_all(&pdu(18, 42, 0, id, &[0; 8])).unwrap();
    assert!(peer.worker.take().unwrap().join().unwrap().is_ok());
}

#[test]
fn administrative_responses_require_valid_layout_status_and_correlation() {
    for stage in [1, 3] {
        for fault in [
            "short",
            "error",
            "packet",
            "type",
            "index",
            "session",
            "trailing",
            "echo-oid",
            "echo-value",
            "echo-short",
        ] {
            if stage == 1 && fault == "session" {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("master");
            let listener = UnixListener::bind(&path).unwrap();
            let worker = thread::spawn(move || {
                let mut session =
                    AgentXSession::connect(path.to_str().unwrap(), "invalid responses")?;
                session.register(&Oid(vec![1]))
            });
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            for kind in [1, 3] {
                let (h, body) = read_pdu(&mut stream);
                assert_eq!(h[1], kind);
                let mut packet = u32::from_be_bytes(h[12..16].try_into().unwrap());
                let mut session = 42;
                let mut response_kind = 18;
                let mut payload = vec![0; 8];
                if kind == stage {
                    match fault {
                        "short" => payload.truncate(4),
                        "error" => payload[5] = 5,
                        "packet" => packet += 1,
                        "type" => response_kind = 7,
                        "index" => payload[7] = 1,
                        "session" => session += 1,
                        "trailing" => payload.extend([0; 8]),
                        "echo-oid" | "echo-value" | "echo-short" => {
                            payload.extend([0, if kind == 1 { 4 } else { 5 }, 0, 0]);
                            if kind == 1 {
                                payload.extend(oid(&[0, 0], false));
                                payload.extend(&body[8..]);
                            } else {
                                payload.extend(&body[4..]);
                            }
                            match fault {
                                "echo-oid" => payload[19] ^= 1,
                                "echo-value" if kind == 1 => payload[28] ^= 1,
                                "echo-value" => payload.extend([0; 4]),
                                "echo-short" => {
                                    payload.pop();
                                }
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                stream
                    .write_all(&pdu(response_kind, session, 0, packet, &payload))
                    .unwrap();
                if kind == stage {
                    break;
                }
            }
            assert!(
                worker.join().unwrap().is_err(),
                "accepted {fault} in stage {stage}"
            );
        }
    }
}

fn little_pdu(kind: u8, session: u32, transaction: u32, packet: u32, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![1, kind, 0, 0];
    for n in [session, transaction, packet, payload.len() as u32] {
        data.extend(n.to_le_bytes());
    }
    data.extend(payload);
    data
}

fn little_range(start: &[u32], include: bool, end: &[u32]) -> Vec<u8> {
    let mut bytes = vec![];
    for (oid, included) in [(start, include), (end, false)] {
        bytes.extend([oid.len() as u8, 0, u8::from(included), 0]);
        for sub in oid {
            bytes.extend(sub.to_le_bytes());
        }
    }
    bytes
}

#[test]
fn little_endian_handshake_and_each_search_operation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("master");
    let listener = UnixListener::bind(&path).unwrap();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let worker = thread::spawn(move || {
        let mut session = AgentXSession::connect(path.to_str().unwrap(), "little endian").unwrap();
        session.register(&Oid(vec![1])).unwrap();
        session.run_loop(&Mib, &stop).unwrap();
    });
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    for kind in [1, 3] {
        let (h, _) = read_pdu(&mut stream);
        assert_eq!(h[1], kind);
        let id = u32::from_be_bytes(h[12..16].try_into().unwrap());
        // Administrative transaction IDs are not defined by AgentX.
        stream
            .write_all(&little_pdu(18, 42, 1234, id, &[0; 8]))
            .unwrap();
    }
    for kind in [5, 6, 7] {
        let mut payload = if kind == 7 { vec![0, 0, 2, 0] } else { vec![] };
        payload.extend(little_range(&[1, 1], true, &[2, 1]));
        stream
            .write_all(&little_pdu(kind, 42, 0x12345678, 0xabcdef01, &payload))
            .unwrap();
        let (h, response) = read_pdu(&mut stream);
        assert_eq!(u32::from_be_bytes(h[8..12].try_into().unwrap()), 0x12345678);
        assert_eq!(
            u32::from_be_bytes(h[12..16].try_into().unwrap()),
            0xabcdef01
        );
        assert_eq!(&response[4..8], &[0; 4]);
        let expected = if kind == 7 {
            vec![(2, vec![1, 1]), (2, vec![1, 2])]
        } else {
            vec![(2, vec![1, 1])]
        };
        assert_eq!(bindings(&response[8..]), expected);
    }
    cancel.cancel();
    worker.join().unwrap();
}

#[test]
fn silent_handshake_is_cancellable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("master");
    let listener = UnixListener::bind(&path).unwrap();
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    let worker = thread::spawn(move || {
        AgentXSession::connect_cancellable(path.to_str().unwrap(), "cancel", stop)
    });
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let (h, _) = read_pdu(&mut stream);
    assert_eq!(h[1], 1);
    let start = std::time::Instant::now();
    cancel.cancel();
    assert!(worker.join().unwrap().is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
}
