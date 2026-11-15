//! Many stateful identities on one UDP tuple, separate from warm-up SSID 7.
use serde::Serialize;
use stamp_suite::{
    crypto::HmacKey,
    packets::{ReflectedPacketAuthenticated, ReflectedPacketUnauthenticated},
};
use std::process::Command;

const WARMUP_SSID: u16 = 7;

#[derive(Clone, Copy)]
pub(super) struct Profile {
    count: u16,
}

impl Profile {
    pub(super) fn new(count: u16, scheduled: u64) -> Result<Self, &'static str> {
        if !(1..=65534).contains(&count) {
            return Err("sessions must be 1–65534 (SSID 7 is reserved for warm-up)");
        }
        if scheduled < u64::from(count) {
            return Err("scheduled probes must cover every requested session at least once");
        }
        Ok(Self { count })
    }

    fn ssid(&self, sequence: u32) -> u16 {
        if sequence == 0 {
            return WARMUP_SSID;
        }
        let ordinal = ((sequence - 1) % u32::from(self.count)) as u16 + 1;
        ordinal + u16::from(ordinal >= WARMUP_SSID)
    }

    pub(super) fn configure(&self, command: &mut Command) {
        // Two warm-up tuples plus the measured identities fit without cap or
        // expiry interference. This workload measures creation and reuse.
        command.args([
            "--session-timeout",
            "0",
            "--max-sessions",
            &(u32::from(self.count) + 2).to_string(),
        ]);
    }

    pub(super) fn request(&self, sequence: u32, timestamp: u64, key: Option<&HmacKey>) -> Vec<u8> {
        let mut bytes = vec![0; if key.is_some() { 112 } else { 44 }];
        let offset = if key.is_some() { 16 } else { 4 };
        bytes[..4].copy_from_slice(&sequence.to_be_bytes());
        bytes[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
        bytes[offset + 8..offset + 10].copy_from_slice(&1u16.to_be_bytes());
        bytes[offset + 10..offset + 12].copy_from_slice(&self.ssid(sequence).to_be_bytes());
        if let Some(key) = key {
            let digest = key.compute(&bytes[..96]);
            bytes[96..112].copy_from_slice(&digest);
        }
        bytes
    }

    pub(super) fn response(
        &self,
        bytes: &[u8],
        timestamp: u64,
        key: Option<&HmacKey>,
    ) -> Option<u32> {
        let (sequence, echoed, estimate, ssid) = if let Some(key) = key {
            if bytes.len() != 112 {
                return None;
            }
            let reply = ReflectedPacketAuthenticated::from_bytes(bytes).ok()?;
            if !key.verify(&bytes[..96], &reply.hmac) {
                return None;
            }
            (
                reply.sess_sender_seq_number,
                reply.sess_sender_timestamp,
                reply.sess_sender_err_estimate,
                reply.ssid,
            )
        } else {
            if bytes.len() != 44 {
                return None;
            }
            let reply = ReflectedPacketUnauthenticated::from_bytes(bytes).ok()?;
            (
                reply.sess_sender_seq_number,
                reply.sess_sender_timestamp,
                reply.sess_sender_err_estimate,
                reply.ssid,
            )
        };
        (echoed == timestamp && estimate == 1 && ssid == self.ssid(sequence)).then_some(sequence)
    }

    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "configured_sessions": self.count,
            "identity": "one_udp_tuple_distinct_nonzero_ssids",
            "reserved_warmup_ssid": WARMUP_SSID,
            "warmup_sessions": 2,
            "reflector_max_sessions": u32::from(self.count) + 2,
            "reflector_session_timeout_seconds": 0,
            "includes_initial_creation": true,
        })
    }
}

pub(super) struct Replies {
    received: Vec<u32>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(super) struct Summary {
    pub(super) configured_sessions: usize,
    pub(super) offered_sessions: usize,
    pub(super) sessions_with_replies: usize,
    pub(super) fully_replied_sessions: usize,
    pub(super) partially_replied_sessions: usize,
    pub(super) unreplied_sessions: usize,
    pub(super) unique_replies: u64,
    pub(super) missing_replies: u64,
    pub(super) min_received_per_offered_session: u32,
    pub(super) max_received_per_offered_session: u32,
}

impl Replies {
    pub(super) fn new(profile: &Profile) -> Self {
        Self {
            received: vec![0; usize::from(profile.count)],
        }
    }

    // Called only after global sequence admission/deduplication.
    pub(super) fn record(&mut self, sequence: u32) -> Result<(), &'static str> {
        let sequence = sequence
            .checked_sub(1)
            .ok_or("warm-up is not a measured session reply")?;
        let index = sequence as usize % self.received.len();
        let slot = &mut self.received[index];
        *slot = slot.checked_add(1).ok_or("session reply count overflow")?;
        Ok(())
    }

    pub(super) fn summary(&self, sent: u32) -> Result<Summary, &'static str> {
        let mut result = Summary {
            configured_sessions: self.received.len(),
            offered_sessions: (sent as usize).min(self.received.len()),
            sessions_with_replies: 0,
            fully_replied_sessions: 0,
            partially_replied_sessions: 0,
            unreplied_sessions: 0,
            unique_replies: 0,
            missing_replies: 0,
            min_received_per_offered_session: u32::MAX,
            max_received_per_offered_session: 0,
        };
        for (index, &received) in self.received.iter().enumerate() {
            let expected = sent / self.received.len() as u32
                + u32::from(index < sent as usize % self.received.len());
            if received > expected {
                return Err("session replies exceed offered probes");
            }
            if expected == 0 {
                continue;
            }
            result.unique_replies += u64::from(received);
            result.missing_replies += u64::from(expected - received);
            result.sessions_with_replies += usize::from(received > 0);
            result.fully_replied_sessions += usize::from(received == expected);
            result.partially_replied_sessions += usize::from(received > 0 && received < expected);
            result.unreplied_sessions += usize::from(received == 0);
            result.min_received_per_offered_session =
                result.min_received_per_offered_session.min(received);
            result.max_received_per_offered_session =
                result.max_received_per_offered_session.max(received);
        }
        if result.offered_sessions == 0 {
            result.min_received_per_offered_session = 0;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const STAMP: u64 = 0xedde_1234_5678_0000;

    fn reply(sequence: u32, ssid: u16, key: Option<&HmacKey>) -> Vec<u8> {
        let mut bytes = vec![0; if key.is_some() { 112 } else { 44 }];
        let (seq, echo, estimate, identity) = if key.is_some() {
            (48, 64, 72, 26)
        } else {
            (24, 28, 36, 14)
        };
        bytes[seq..seq + 4].copy_from_slice(&sequence.to_be_bytes());
        bytes[echo..echo + 8].copy_from_slice(&STAMP.to_be_bytes());
        bytes[estimate..estimate + 2].copy_from_slice(&1u16.to_be_bytes());
        bytes[identity..identity + 2].copy_from_slice(&ssid.to_be_bytes());
        if let Some(key) = key {
            let digest = key.compute(&bytes[..96]);
            bytes[96..112].copy_from_slice(&digest);
        }
        bytes
    }

    #[test]
    fn identities_are_bounded_cycle_and_exclude_warmup() {
        for count in [1, 6, 7, 1024, 65534] {
            let profile = Profile::new(count, 100_000).unwrap();
            let mut ids = std::collections::HashSet::new();
            assert_eq!(profile.ssid(0), 7);
            for seq in 1..=u32::from(count) {
                let id = profile.ssid(seq);
                assert!(id != 0 && id != 7);
                assert!(ids.insert(id));
                assert_eq!(id, profile.ssid(seq + u32::from(count)));
            }
            assert_eq!(ids.len(), usize::from(count));
        }
        assert_eq!(Profile::new(65534, 65534).unwrap().ssid(65534), 65535);
        assert!(Profile::new(0, 100).is_err());
        assert!(Profile::new(65535, 65535).is_err());
        assert!(Profile::new(100, 99).is_err());
    }

    #[test]
    fn requests_and_replies_bind_identity_and_signature_to_global_sequence() {
        let profile = Profile::new(8, 100).unwrap();
        let key = HmacKey::new(vec![0xab; 16]).unwrap();
        for key in [None, Some(&key)] {
            for (seq, ssid) in [
                (0u32, 7u16),
                (1, 1),
                (6, 6),
                (7, 8),
                (8, 9),
                (9, 1),
                (16, 9),
            ] {
                let request = profile.request(seq, STAMP, key);
                let (identity, timestamp) = if key.is_some() { (26, 16) } else { (14, 4) };
                assert_eq!(&request[..4], &seq.to_be_bytes());
                assert_eq!(&request[identity..identity + 2], &ssid.to_be_bytes());
                assert_eq!(&request[timestamp..timestamp + 8], &STAMP.to_be_bytes());
                if let Some(key) = key {
                    assert_eq!(&request[96..], &key.compute(&request[..96]));
                }
                let bytes = reply(seq, ssid, key);
                assert_eq!(profile.response(&bytes, STAMP, key), Some(seq));
                for wrong in [0, ssid.wrapping_add(1)] {
                    assert_eq!(profile.response(&reply(seq, wrong, key), STAMP, key), None);
                }
                assert_eq!(profile.response(&bytes, STAMP + 1, key), None);
                assert_eq!(
                    profile.response(&bytes[..bytes.len() - 1], STAMP, key),
                    None
                );
                assert_eq!(
                    profile.response(&[bytes.as_slice(), &[0]].concat(), STAMP, key),
                    None
                );
                if let Some(key) = key {
                    let mut bad = bytes;
                    bad[111] ^= 1;
                    assert_eq!(profile.response(&bad, STAMP, Some(key)), None);
                }
            }
        }
    }

    #[test]
    fn per_session_loss_accounts_for_partial_cycles_and_missing_identities() {
        let profile = Profile::new(3, 100).unwrap();
        let mut replies = Replies::new(&profile);
        assert!(replies.record(0).is_err());
        assert_eq!(replies.summary(0).unwrap().offered_sessions, 0);
        // Seven sends: A gets 1/4/7, B gets 2/5, C gets 3/6. C never replies.
        for seq in [5, 7, 1, 4] {
            replies.record(seq).unwrap();
        }
        assert_eq!(
            replies.summary(7).unwrap(),
            Summary {
                configured_sessions: 3,
                offered_sessions: 3,
                sessions_with_replies: 2,
                fully_replied_sessions: 1,
                partially_replied_sessions: 1,
                unreplied_sessions: 1,
                unique_replies: 4,
                missing_replies: 3,
                min_received_per_offered_session: 0,
                max_received_per_offered_session: 3,
            }
        );
        assert!(replies.summary(2).is_err());
        let mut small = Replies::new(&profile);
        small.record(1).unwrap();
        let summary = small.summary(2).unwrap();
        assert_eq!(summary.offered_sessions, 2);
        assert_eq!(summary.unreplied_sessions, 1);
        assert_eq!(summary.missing_replies, 1);
    }
}
