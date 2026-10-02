//! Sequence-number replay classification for reflected sessions
//! (RFC 10052 §5).

use super::*;

/// Classifies and counts replay-window results after base parsing and HMAC
/// verification (RFC 10052 §5).
///
/// Reads the sequence from the first four bytes in either layout
/// (RFC 8762 §4.2/§4.3). Does not advance the window; [`commit_replay`] runs
/// after response assembly. Type-12 requests with a non-New verdict get one
/// U-flagged reply; `--drop-replayed` can suppress other duplicates.
/// Log individual events at debug level to avoid replay-driven log floods.
pub(crate) fn evaluate_replay(
    session: &crate::session::Session,
    data: &[u8],
    counters: &ReflectorCounters,
) -> crate::session::ReplayVerdict {
    use crate::session::ReplayVerdict;

    if data.len() < 4 {
        // Too short to carry a complete wire Sequence Number. Strict parsing
        // rejects this upstream; lenient zero-fill remains supported.
        return ReplayVerdict::New;
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    let verdict = session.classify_replay(seq);
    match verdict {
        ReplayVerdict::Replay => {
            counters
                .packets_replayed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!(
                "replayed sequence number {seq} on session {}",
                session.get_id()
            );
        }
        ReplayVerdict::Reordered | ReplayVerdict::OutOfWindow => {
            counters
                .packets_reordered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            log::debug!(
                "out-of-order sequence number {seq} ({verdict:?}) on session {}",
                session.get_id()
            );
        }
        ReplayVerdict::New => {}
    }
    verdict
}

/// Records a *verified* packet's Sequence Number in its session's replay
/// window — the mutating counterpart of [`evaluate_replay`]. The shared live
/// pipeline calls this after response assembly. Base parsing and configured
/// HMAC verification have already succeeded; rejected authenticated-mode
/// packets cannot advance the anti-replay state.
pub(crate) fn commit_replay(session: &crate::session::Session, data: &[u8]) {
    if data.len() < 4 {
        return;
    }
    let seq = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    session.commit_replay(seq);
}
