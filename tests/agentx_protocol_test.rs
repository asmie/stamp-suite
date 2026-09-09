//! Independent AgentX master wire fixtures; no production encoders/decoders.
#![cfg(all(unix, feature = "snmp"))]
use stamp_suite::snmp::agentx::{AgentXSession, MibHandler, Oid, VarBind, VarBindValue};
use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
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
    cancel: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<Result<(), String>>>,
    _dir: tempfile::TempDir,
}
impl Peer {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master");
        let listener = UnixListener::bind(&path).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
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
            let (h, _) = read_pdu(&mut stream);
            assert_eq!(h[1], kind);
            let id = u32::from_be_bytes(h[12..16].try_into().unwrap());
            stream.write_all(&pdu(18, 42, 0, id, &[0; 8])).unwrap();
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
        self.cancel.store(true, Ordering::Relaxed);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
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
    peer.cancel.store(true, Ordering::Relaxed);
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
