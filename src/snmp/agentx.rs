//! Minimal AgentX sub-agent implementation per RFC 2741.
//!
//! Implements only the sub-agent side: Open, Register, Close, and handling
//! of Get/GetNext/GetBulk request PDUs from the master agent.

use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

// --- PDU type constants (RFC 2741 §6.1) ---

const AGENTX_OPEN_PDU: u8 = 1;
const AGENTX_CLOSE_PDU: u8 = 2;
const AGENTX_REGISTER_PDU: u8 = 3;
const AGENTX_RESPONSE_PDU: u8 = 18;
const AGENTX_GET_PDU: u8 = 5;
const AGENTX_GETNEXT_PDU: u8 = 6;
const AGENTX_GETBULK_PDU: u8 = 7;

// Close reasons (RFC 2741 §6.2.6)
const REASON_SHUTDOWN: u8 = 1;

// AgentX protocol version
const AGENTX_VERSION: u8 = 1;

// --- VarBind type constants (RFC 2741 §5.4) ---

const VARBIND_INTEGER: u16 = 2;
const VARBIND_OCTET_STRING: u16 = 4;
const VARBIND_COUNTER32: u16 = 65;
const VARBIND_GAUGE32: u16 = 66;
const VARBIND_TIMETICKS: u16 = 67;
const VARBIND_COUNTER64: u16 = 70;
const VARBIND_NO_SUCH_OBJECT: u16 = 128;
const VARBIND_NO_SUCH_INSTANCE: u16 = 129;
const VARBIND_END_OF_MIB_VIEW: u16 = 130;

// --- Error types ---

/// Errors that can occur during AgentX protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum AgentXError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("Master agent returned error: res_error={0}")]
    ResponseError(u16),
    #[error("Unexpected PDU type: {0}")]
    UnexpectedPdu(u8),
}

// --- Core types ---

/// An SNMP Object Identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    /// Creates a new OID from a slice of sub-identifiers.
    pub fn from_slice(subs: &[u32]) -> Self {
        Oid(subs.to_vec())
    }

    /// Returns true if this OID starts with `prefix`.
    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.len() >= prefix.0.len() && self.0[..prefix.0.len()] == prefix.0[..]
    }

    /// Returns the number of sub-identifiers.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the OID has no sub-identifiers.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = self.0.iter().map(|s| s.to_string()).collect();
        write!(f, ".{}", parts.join("."))
    }
}

/// An SNMP variable binding value.
#[derive(Clone, Debug)]
pub enum VarBindValue {
    Integer(i32),
    OctetString(Vec<u8>),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

/// A variable binding (OID + value).
#[derive(Clone, Debug)]
pub struct VarBind {
    pub oid: Oid,
    pub value: VarBindValue,
}

// --- PDU header ---

/// Decoded AgentX PDU header (20 bytes).
#[derive(Debug)]
pub struct PduHeader {
    pub version: u8,
    pub pdu_type: u8,
    pub flags: u8,
    pub session_id: u32,
    pub transaction_id: u32,
    pub packet_id: u32,
    pub payload_length: u32,
}

/// PDU header size in bytes.
pub const PDU_HEADER_SIZE: usize = 20;

// --- Encoding functions ---

/// Encodes a complete AgentX PDU (header + payload).
pub fn encode_pdu(
    pdu_type: u8,
    flags: u8,
    session_id: u32,
    transaction_id: u32,
    packet_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PDU_HEADER_SIZE + payload.len());
    buf.push(AGENTX_VERSION);
    buf.push(pdu_type);
    buf.push(flags);
    buf.push(0); // reserved
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&transaction_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decodes an AgentX PDU header from a 20-byte buffer.
pub fn decode_header(buf: &[u8]) -> Result<PduHeader, AgentXError> {
    if buf.len() < PDU_HEADER_SIZE {
        return Err(AgentXError::Protocol(format!(
            "Header too short: {} bytes",
            buf.len()
        )));
    }
    Ok(PduHeader {
        version: buf[0],
        pdu_type: buf[1],
        flags: buf[2],
        session_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        transaction_id: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        packet_id: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
        payload_length: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
    })
}

/// Encodes an OID per RFC 2741 §5.1.
///
/// Format: n_subid(4) + prefix(1) + include(1) + reserved(2) + sub-identifiers(4 each).
/// If the OID starts with 1.3.6.1 the prefix optimization is used.
pub fn encode_oid(oid: &Oid, include: bool) -> Vec<u8> {
    let subs = &oid.0;

    // Check for internet prefix optimization (1.3.6.1.x)
    let (prefix_byte, start_idx) =
        if subs.len() >= 5 && subs[0] == 1 && subs[1] == 3 && subs[2] == 6 && subs[3] == 1 {
            let fifth = subs[4];
            if fifth <= 255 {
                (fifth as u8, 5)
            } else {
                (0u8, 0)
            }
        } else {
            (0u8, 0)
        };

    let n_subid = (subs.len() - start_idx) as u32;
    let mut buf = Vec::with_capacity(4 + (n_subid as usize) * 4);
    buf.extend_from_slice(&n_subid.to_be_bytes());
    buf.push(prefix_byte);
    buf.push(if include { 1 } else { 0 });
    buf.push(0); // reserved
    buf.push(0); // reserved

    for &sub in &subs[start_idx..] {
        buf.extend_from_slice(&sub.to_be_bytes());
    }
    buf
}

/// Decodes an OID from a buffer. Returns the decoded OID and the number of bytes consumed.
pub fn decode_oid(buf: &[u8]) -> Result<(Oid, bool, usize), AgentXError> {
    if buf.len() < 4 {
        return Err(AgentXError::Protocol("OID header too short".to_string()));
    }

    let n_subid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let prefix = buf[4];
    let include = buf[5] != 0;

    let expected_len = 8 + n_subid * 4;
    if buf.len() < expected_len {
        return Err(AgentXError::Protocol(format!(
            "OID buffer too short: need {} have {}",
            expected_len,
            buf.len()
        )));
    }

    let mut subs = Vec::with_capacity(if prefix > 0 { 5 + n_subid } else { n_subid });

    if prefix > 0 {
        subs.extend_from_slice(&[1, 3, 6, 1, prefix as u32]);
    }

    let mut offset = 8;
    for _ in 0..n_subid {
        subs.push(u32::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]));
        offset += 4;
    }

    Ok((Oid(subs), include, expected_len))
}

/// Encodes a VarBind per RFC 2741 §5.4.
pub fn encode_varbind(vb: &VarBind) -> Vec<u8> {
    let mut buf = Vec::new();

    match &vb.value {
        VarBindValue::Integer(v) => {
            buf.extend_from_slice(&VARBIND_INTEGER.to_be_bytes());
            buf.extend_from_slice(&[0, 0]); // reserved
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
            buf.extend_from_slice(&(*v as u32).to_be_bytes());
        }
        VarBindValue::OctetString(v) => {
            buf.extend_from_slice(&VARBIND_OCTET_STRING.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
            // Octet string: length(4) + data + padding to 4-byte boundary
            buf.extend_from_slice(&(v.len() as u32).to_be_bytes());
            buf.extend_from_slice(v);
            let pad = (4 - (v.len() % 4)) % 4;
            buf.extend(std::iter::repeat_n(0u8, pad));
        }
        VarBindValue::Counter32(v) => {
            buf.extend_from_slice(&VARBIND_COUNTER32.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
            buf.extend_from_slice(&v.to_be_bytes());
        }
        VarBindValue::Gauge32(v) => {
            buf.extend_from_slice(&VARBIND_GAUGE32.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
            buf.extend_from_slice(&v.to_be_bytes());
        }
        VarBindValue::TimeTicks(v) => {
            buf.extend_from_slice(&VARBIND_TIMETICKS.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
            buf.extend_from_slice(&v.to_be_bytes());
        }
        VarBindValue::Counter64(v) => {
            buf.extend_from_slice(&VARBIND_COUNTER64.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
            buf.extend_from_slice(&v.to_be_bytes());
        }
        VarBindValue::NoSuchObject => {
            buf.extend_from_slice(&VARBIND_NO_SUCH_OBJECT.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
        }
        VarBindValue::NoSuchInstance => {
            buf.extend_from_slice(&VARBIND_NO_SUCH_INSTANCE.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
        }
        VarBindValue::EndOfMibView => {
            buf.extend_from_slice(&VARBIND_END_OF_MIB_VIEW.to_be_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&encode_oid(&vb.oid, false));
        }
    }

    buf
}

/// Decodes a SearchRange from a buffer per RFC 2741 §5.2.
/// Returns (start_oid, end_oid, bytes_consumed).
pub fn decode_search_range(buf: &[u8]) -> Result<(Oid, Oid, usize), AgentXError> {
    let (start_oid, include, start_len) = decode_oid(buf)?;
    let (end_oid, _end_include, end_len) = decode_oid(&buf[start_len..])?;

    // The include flag is part of the start OID encoding
    let _ = include;

    Ok((start_oid, end_oid, start_len + end_len))
}

/// Encodes an octet string per RFC 2741 §5.3.
fn encode_octet_string(s: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + s.len() + 3);
    buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
    buf.extend_from_slice(s);
    let pad = (4 - (s.len() % 4)) % 4;
    buf.extend(std::iter::repeat_n(0u8, pad));
    buf
}

// --- MibHandler trait ---

/// Trait for handling SNMP requests dispatched by the AgentX session.
pub trait MibHandler: Send + Sync {
    /// Handle a GET request. Return a VarBind for the requested OID.
    fn get(&self, oid: &Oid) -> VarBind;

    /// Handle a GETNEXT request. Return the next VarBind after the given OID.
    fn get_next(&self, oid: &Oid, end: &Oid) -> VarBind;
}

// --- AgentX Session ---

/// An AgentX sub-agent session connected to a master agent.
pub struct AgentXSession {
    stream: UnixStream,
    session_id: u32,
    packet_id: AtomicU32,
}

impl AgentXSession {
    /// Connects to the master agent via a Unix socket and opens a session.
    pub fn connect(path: &str, description: &str) -> Result<Self, AgentXError> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;

        let mut session = AgentXSession {
            stream,
            session_id: 0,
            packet_id: AtomicU32::new(1),
        };

        session.open(description)?;
        Ok(session)
    }

    fn next_packet_id(&self) -> u32 {
        self.packet_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends an Open PDU (RFC 2741 §6.2.1) and reads the Response.
    fn open(&mut self, description: &str) -> Result<(), AgentXError> {
        let pid = self.next_packet_id();

        // Open PDU payload: timeout(1) + reserved(3) + id(oid, null) + description(octet string)
        let mut payload = Vec::new();
        payload.push(30); // timeout: 30 seconds
        payload.extend_from_slice(&[0, 0, 0]); // reserved
                                               // Null OID for sub-agent ID
        payload.extend_from_slice(&encode_oid(&Oid(vec![]), false));
        // Description as octet string
        payload.extend_from_slice(&encode_octet_string(description.as_bytes()));

        let pdu = encode_pdu(AGENTX_OPEN_PDU, 0, 0, 0, pid, &payload);
        self.stream.write_all(&pdu)?;

        let (header, _payload) = self.read_response()?;
        if header.pdu_type != AGENTX_RESPONSE_PDU {
            return Err(AgentXError::UnexpectedPdu(header.pdu_type));
        }
        self.session_id = header.session_id;
        log::info!("AgentX session opened (session_id={})", self.session_id);
        Ok(())
    }

    /// Registers an OID subtree with the master agent (RFC 2741 §6.2.3).
    pub fn register(&mut self, subtree: &Oid) -> Result<(), AgentXError> {
        let pid = self.next_packet_id();

        // Register PDU payload: timeout(1) + priority(1) + range_subid(1) + reserved(1) + subtree(oid)
        let mut payload = vec![30, 127, 0, 0]; // timeout, priority, range_subid, reserved
        payload.extend_from_slice(&encode_oid(subtree, false));

        let pdu = encode_pdu(AGENTX_REGISTER_PDU, 0, self.session_id, 0, pid, &payload);
        self.stream.write_all(&pdu)?;

        let (header, response_payload) = self.read_response()?;
        if header.pdu_type != AGENTX_RESPONSE_PDU {
            return Err(AgentXError::UnexpectedPdu(header.pdu_type));
        }

        // Check res.error in response payload
        if response_payload.len() >= 8 {
            let res_error = u16::from_be_bytes([response_payload[4], response_payload[5]]);
            if res_error != 0 {
                return Err(AgentXError::ResponseError(res_error));
            }
        }

        log::info!("Registered OID subtree {}", subtree);
        Ok(())
    }

    /// Sends a Close PDU (RFC 2741 §6.2.2).
    pub fn close(&mut self) -> Result<(), AgentXError> {
        let pid = self.next_packet_id();
        let payload = [REASON_SHUTDOWN, 0, 0, 0];
        let pdu = encode_pdu(AGENTX_CLOSE_PDU, 0, self.session_id, 0, pid, &payload);
        self.stream.write_all(&pdu)?;
        // Best-effort read of response
        let _ = self.read_response();
        log::info!("AgentX session closed");
        Ok(())
    }

    /// Reads a complete PDU (header + payload) from the stream.
    fn read_response(&mut self) -> Result<(PduHeader, Vec<u8>), AgentXError> {
        let mut header_buf = [0u8; PDU_HEADER_SIZE];
        self.stream.read_exact(&mut header_buf)?;
        let header = decode_header(&header_buf)?;

        let mut payload = vec![0u8; header.payload_length as usize];
        if !payload.is_empty() {
            self.stream.read_exact(&mut payload)?;
        }

        Ok((header, payload))
    }

    /// Runs the AgentX event loop, dispatching requests to the handler.
    ///
    /// This blocks until the connection is closed or an error occurs.
    /// Call from `spawn_blocking`.
    pub fn run_loop(
        &mut self,
        handler: &dyn MibHandler,
        cancel: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<(), AgentXError> {
        // Set a shorter read timeout so we can check for cancellation
        self.stream.set_read_timeout(Some(Duration::from_secs(1)))?;

        loop {
            if cancel.load(Ordering::Relaxed) {
                let _ = self.close();
                return Ok(());
            }

            let mut header_buf = [0u8; PDU_HEADER_SIZE];
            match self.stream.read_exact(&mut header_buf) {
                Ok(()) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(AgentXError::Io(e)),
            }

            let header = decode_header(&header_buf)?;
            let mut payload = vec![0u8; header.payload_length as usize];
            if !payload.is_empty() {
                self.stream.read_exact(&mut payload)?;
            }

            match header.pdu_type {
                AGENTX_GET_PDU => {
                    let response = self.handle_get(&header, &payload, handler)?;
                    self.stream.write_all(&response)?;
                }
                AGENTX_GETNEXT_PDU => {
                    let response = self.handle_get_next(&header, &payload, handler)?;
                    self.stream.write_all(&response)?;
                }
                AGENTX_GETBULK_PDU => {
                    let response = self.handle_get_bulk(&header, &payload, handler)?;
                    self.stream.write_all(&response)?;
                }
                AGENTX_CLOSE_PDU => {
                    log::info!("Master agent closed session");
                    return Ok(());
                }
                other => {
                    log::warn!("Ignoring unknown PDU type {}", other);
                }
            }
        }
    }

    /// Handles a Get PDU by looking up each requested OID.
    fn handle_get(
        &self,
        header: &PduHeader,
        payload: &[u8],
        handler: &dyn MibHandler,
    ) -> Result<Vec<u8>, AgentXError> {
        let mut varbinds_buf = Vec::new();
        let mut offset = 0;

        // Parse SearchRanges and resolve each
        while offset < payload.len() {
            let (start_oid, _end_oid, consumed) = decode_search_range(&payload[offset..])?;
            offset += consumed;

            let vb = handler.get(&start_oid);
            varbinds_buf.extend_from_slice(&encode_varbind(&vb));
        }

        Ok(self.build_response(header, &varbinds_buf))
    }

    /// Handles a GetNext PDU.
    fn handle_get_next(
        &self,
        header: &PduHeader,
        payload: &[u8],
        handler: &dyn MibHandler,
    ) -> Result<Vec<u8>, AgentXError> {
        let mut varbinds_buf = Vec::new();
        let mut offset = 0;

        while offset < payload.len() {
            let (start_oid, end_oid, consumed) = decode_search_range(&payload[offset..])?;
            offset += consumed;

            let vb = handler.get_next(&start_oid, &end_oid);
            varbinds_buf.extend_from_slice(&encode_varbind(&vb));
        }

        Ok(self.build_response(header, &varbinds_buf))
    }

    /// Handles a GetBulk PDU (simplified — treats as multiple GetNext).
    fn handle_get_bulk(
        &self,
        header: &PduHeader,
        payload: &[u8],
        handler: &dyn MibHandler,
    ) -> Result<Vec<u8>, AgentXError> {
        if payload.len() < 4 {
            return Err(AgentXError::Protocol(
                "GetBulk payload too short".to_string(),
            ));
        }

        let non_repeaters = u16::from_be_bytes([payload[0], payload[1]]) as usize;
        let max_repetitions = u16::from_be_bytes([payload[2], payload[3]]) as usize;

        let mut varbinds_buf = Vec::new();
        let mut ranges = Vec::new();
        let mut offset = 4;

        // Parse all search ranges
        while offset < payload.len() {
            let (start_oid, end_oid, consumed) = decode_search_range(&payload[offset..])?;
            offset += consumed;
            ranges.push((start_oid, end_oid));
        }

        // Process non-repeaters (single GetNext each)
        for range in ranges.iter().take(non_repeaters.min(ranges.len())) {
            let vb = handler.get_next(&range.0, &range.1);
            varbinds_buf.extend_from_slice(&encode_varbind(&vb));
        }

        // Process repeaters
        for range in ranges.iter().skip(non_repeaters) {
            let mut current_oid = range.0.clone();
            for _ in 0..max_repetitions {
                let vb = handler.get_next(&current_oid, &range.1);
                let is_end = matches!(vb.value, VarBindValue::EndOfMibView);
                varbinds_buf.extend_from_slice(&encode_varbind(&vb));
                if is_end {
                    break;
                }
                current_oid = vb.oid;
            }
        }

        Ok(self.build_response(header, &varbinds_buf))
    }

    /// Builds a Response PDU with the given varbinds.
    fn build_response(&self, request_header: &PduHeader, varbinds: &[u8]) -> Vec<u8> {
        // Response payload: sysUpTime(4) + res.error(2) + res.index(2) + varbinds
        let mut response_payload = Vec::with_capacity(8 + varbinds.len());
        response_payload.extend_from_slice(&[0, 0, 0, 0]); // sysUpTime (unused by sub-agent)
        response_payload.extend_from_slice(&[0, 0]); // res.error = noError
        response_payload.extend_from_slice(&[0, 0]); // res.index
        response_payload.extend_from_slice(varbinds);

        encode_pdu(
            AGENTX_RESPONSE_PDU,
            0,
            request_header.session_id,
            request_header.transaction_id,
            request_header.packet_id,
            &response_payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_encode_decode_roundtrip_internet() {
        // OID under internet prefix: 1.3.6.1.4.1.99999
        let oid = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999]);
        let encoded = encode_oid(&oid, false);
        let (decoded, include, consumed) = decode_oid(&encoded).unwrap();
        assert_eq!(decoded, oid);
        assert!(!include);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_oid_encode_decode_roundtrip_short() {
        // OID without internet prefix
        let oid = Oid::from_slice(&[1, 2, 3]);
        let encoded = encode_oid(&oid, true);
        let (decoded, include, consumed) = decode_oid(&encoded).unwrap();
        assert_eq!(decoded, oid);
        assert!(include);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_oid_encode_decode_empty() {
        let oid = Oid(vec![]);
        let encoded = encode_oid(&oid, false);
        let (decoded, _include, _consumed) = decode_oid(&encoded).unwrap();
        assert_eq!(decoded, oid);
    }

    #[test]
    fn test_pdu_header_encode_decode() {
        let pdu = encode_pdu(AGENTX_GET_PDU, 0, 42, 7, 99, &[1, 2, 3, 4]);
        let header = decode_header(&pdu).unwrap();
        assert_eq!(header.version, AGENTX_VERSION);
        assert_eq!(header.pdu_type, AGENTX_GET_PDU);
        assert_eq!(header.session_id, 42);
        assert_eq!(header.transaction_id, 7);
        assert_eq!(header.packet_id, 99);
        assert_eq!(header.payload_length, 4);
    }

    #[test]
    fn test_varbind_encode_integer() {
        let vb = VarBind {
            oid: Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 1, 1]),
            value: VarBindValue::Integer(42),
        };
        let encoded = encode_varbind(&vb);
        // Should have type(2) + reserved(2) + encoded_oid + value(4)
        assert!(encoded.len() > 8);
        // Type should be INTEGER
        assert_eq!(
            u16::from_be_bytes([encoded[0], encoded[1]]),
            VARBIND_INTEGER
        );
    }

    #[test]
    fn test_varbind_encode_counter64() {
        let vb = VarBind {
            oid: Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999, 1, 1, 2, 1]),
            value: VarBindValue::Counter64(123456789),
        };
        let encoded = encode_varbind(&vb);
        assert_eq!(
            u16::from_be_bytes([encoded[0], encoded[1]]),
            VARBIND_COUNTER64
        );
    }

    #[test]
    fn test_varbind_encode_octet_string() {
        let vb = VarBind {
            oid: Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999]),
            value: VarBindValue::OctetString(b"hello".to_vec()),
        };
        let encoded = encode_varbind(&vb);
        assert_eq!(
            u16::from_be_bytes([encoded[0], encoded[1]]),
            VARBIND_OCTET_STRING
        );
    }

    #[test]
    fn test_varbind_encode_no_such_object() {
        let vb = VarBind {
            oid: Oid::from_slice(&[1, 3, 6, 1, 99]),
            value: VarBindValue::NoSuchObject,
        };
        let encoded = encode_varbind(&vb);
        assert_eq!(
            u16::from_be_bytes([encoded[0], encoded[1]]),
            VARBIND_NO_SUCH_OBJECT
        );
    }

    #[test]
    fn test_varbind_encode_end_of_mib_view() {
        let vb = VarBind {
            oid: Oid::from_slice(&[1, 3, 6, 1, 99]),
            value: VarBindValue::EndOfMibView,
        };
        let encoded = encode_varbind(&vb);
        assert_eq!(
            u16::from_be_bytes([encoded[0], encoded[1]]),
            VARBIND_END_OF_MIB_VIEW
        );
    }

    #[test]
    fn test_search_range_decode() {
        let start = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999]);
        let end = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 100000]);

        let mut buf = Vec::new();
        buf.extend_from_slice(&encode_oid(&start, false));
        buf.extend_from_slice(&encode_oid(&end, false));

        let (decoded_start, decoded_end, consumed) = decode_search_range(&buf).unwrap();
        assert_eq!(decoded_start, start);
        assert_eq!(decoded_end, end);
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_oid_starts_with() {
        let parent = Oid::from_slice(&[1, 3, 6, 1, 4]);
        let child = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999]);
        let other = Oid::from_slice(&[1, 3, 6, 2, 1]);

        assert!(child.starts_with(&parent));
        assert!(!other.starts_with(&parent));
        assert!(parent.starts_with(&parent)); // equal is a prefix
    }

    #[test]
    fn test_oid_display() {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999]);
        assert_eq!(format!("{}", oid), ".1.3.6.1.4.1.99999");
    }

    #[test]
    fn test_oid_ordering() {
        let a = Oid::from_slice(&[1, 3, 6, 1, 4, 1]);
        let b = Oid::from_slice(&[1, 3, 6, 1, 4, 2]);
        let c = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 0]);
        assert!(a < b);
        assert!(a < c); // a is prefix of c, so a < c
    }

    #[test]
    fn test_oid_prefix_optimization() {
        // OID .1.3.6.1.4 should use prefix byte 4
        let oid = Oid::from_slice(&[1, 3, 6, 1, 4, 1, 99999]);
        let encoded = encode_oid(&oid, false);
        // n_subid should be 2 (only sub-ids after the prefix: 1, 99999)
        let n_subid = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(n_subid, 2);
        // prefix byte
        assert_eq!(encoded[4], 4);
    }
}
