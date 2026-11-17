//! Reflected packet assembly (RFC 8762 §4.3) with TLV handling (RFC 8972).

use super::*;

/// Assembles an unauthenticated reflected packet from a received test packet.
///
/// `rcvt` is the receive timestamp, `ttl` the request's TTL/Hop Limit and
/// `reflector_error_estimate` the reflector's own estimate in wire format.
/// `reflector_seq` replaces the echoed Sequence Number in stateful mode
/// (RFC 8762 §4.3.1).
pub fn assemble_unauth_answer(
    packet: &PacketUnauthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
) -> ReflectedPacketUnauthenticated {
    // RFC 8972 §3 Figure 2: the reflected packet carries the Session-Sender
    // Identifier once, in the two octets after the reflector's own Error
    // Estimate. The run after the Session-Sender Error Estimate stays MBZ.
    ReflectedPacketUnauthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        mbz2: [0; 2],
        sess_sender_ttl: ttl,
        sequence_number: reflector_seq.unwrap_or(packet.sequence_number),
        error_estimate: reflector_error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        ssid: packet.ssid,
        mbz3: [0; 3],
    }
}

/// Assembles an unauthenticated reflected packet with symmetric size (RFC 8762 §4.3).
///
/// The 44-byte base is followed by a copy of `original_data` beyond its first
/// 44 bytes, so the reply matches the request's length.
pub(crate) fn assemble_unauth_answer_symmetric(
    packet: &PacketUnauthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
) -> Vec<u8> {
    let base = assemble_unauth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        reflector_seq,
    );
    let mut response = base.to_bytes().to_vec();

    // Copy any content beyond the base packet (RFC 8762 §4.3).
    if let Some(tail) = original_data.get(UNAUTH_BASE_SIZE..) {
        response.extend_from_slice(tail);
    }

    response
}

/// Assembles an authenticated reflected packet from a received test packet.
///
/// Parameters match [`assemble_unauth_answer`]; `hmac_key`, when present,
/// signs the base packet (RFC 8762 §4.4).
pub fn assemble_auth_answer(
    packet: &PacketAuthenticated,
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
) -> ReflectedPacketAuthenticated {
    let mut response = ReflectedPacketAuthenticated {
        sess_sender_timestamp: packet.timestamp,
        sess_sender_err_estimate: packet.error_estimate,
        sess_sender_seq_number: packet.sequence_number,
        sess_sender_ttl: ttl,
        sequence_number: reflector_seq.unwrap_or(packet.sequence_number),
        error_estimate: reflector_error_estimate,
        timestamp: generate_timestamp(cs),
        receive_timestamp: rcvt,
        ssid: packet.ssid,
        mbz0: [0u8; 12],
        mbz1: [0u8; 4],
        mbz2: [0u8; 8],
        mbz3: [0u8; 12],
        mbz4: [0u8; 6],
        mbz5: [0u8; 15],
        hmac: [0u8; 16],
    };

    if let Some(key) = hmac_key {
        let bytes = response.to_bytes();
        response.hmac = compute_packet_hmac(key, &bytes, AUTH_HMAC_OFFSET);
    }

    response
}

/// Assembles an authenticated reflected packet with symmetric size (RFC 8762 §4.3).
///
/// The 112-byte base is followed by a copy of `original_data` beyond its
/// first 112 bytes, outside the base HMAC's coverage.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_auth_answer_symmetric(
    packet: &PacketAuthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
) -> Vec<u8> {
    let base = assemble_auth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        hmac_key,
        reflector_seq,
    );
    let mut response = base.to_bytes().to_vec();

    // Copy any content beyond the base packet (RFC 8762 §4.3).
    if let Some(tail) = original_data.get(AUTH_BASE_SIZE..) {
        response.extend_from_slice(tail);
    }

    response
}

/// Assembles an unauthenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet. `tlv_hmac_key` signs the
/// reply's TLVs; `verify_incoming_hmac` checks the request's TLV HMAC with it.
/// Unauthenticated mode does not require an HMAC TLV to be present.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_unauth_answer_with_tlvs(
    packet: &PacketUnauthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    reflector_seq: Option<u32>,
    tlv_mode: TlvHandlingMode,
    tlv_hmac_key: Option<&HmacKey>,
    verify_incoming_hmac: bool,
    ctx: &ProcessingContext,
) -> StampResponse {
    let base = assemble_unauth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        reflector_seq,
    );
    assemble_tlv_reply(
        &base.to_bytes(),
        original_data,
        tlv_mode,
        TlvVerification {
            key: tlv_hmac_key,
            verify: verify_incoming_hmac,
            require_hmac_tlv: false,
        },
        ctx,
    )
}

/// Assembles an authenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet. With verification on,
/// authenticated mode also requires an HMAC TLV unless the request carries
/// only Extra Padding.
#[allow(clippy::too_many_arguments)]
pub(crate) fn assemble_auth_answer_with_tlvs(
    packet: &PacketAuthenticated,
    original_data: &[u8],
    cs: ClockFormat,
    rcvt: u64,
    ttl: u8,
    reflector_error_estimate: u16,
    hmac_key: Option<&HmacKey>,
    reflector_seq: Option<u32>,
    tlv_mode: TlvHandlingMode,
    tlv_hmac_key: Option<&HmacKey>,
    verify_incoming_hmac: bool,
    ctx: &ProcessingContext,
) -> StampResponse {
    let base = assemble_auth_answer(
        packet,
        cs,
        rcvt,
        ttl,
        reflector_error_estimate,
        hmac_key,
        reflector_seq,
    );
    assemble_tlv_reply(
        &base.to_bytes(),
        original_data,
        tlv_mode,
        TlvVerification {
            key: tlv_hmac_key,
            verify: verify_incoming_hmac,
            require_hmac_tlv: verify_incoming_hmac,
        },
        ctx,
    )
}

/// How the request's TLV HMAC is checked (RFC 8972 §4.8).
struct TlvVerification<'a> {
    /// Signs the reply's TLVs, and verifies the request's when `verify` is set.
    key: Option<&'a HmacKey>,
    verify: bool,
    /// Treat a missing HMAC TLV as an integrity failure.
    require_hmac_tlv: bool,
}

/// Appends the request's TLVs to an assembled base packet and processes them.
/// The base HMAC, when present, covers only the base, so the TLVs and any
/// copied tail never affect it.
fn assemble_tlv_reply(
    base_bytes: &[u8],
    original_data: &[u8],
    tlv_mode: TlvHandlingMode,
    verification: TlvVerification,
    ctx: &ProcessingContext,
) -> StampResponse {
    let base_size = base_bytes.len();
    // Each queued response owns its output buffer; reserve the incoming size
    // and a possible generated TLV HMAC before appending the chain.
    let capacity =
        original_data
            .len()
            .max(base_size)
            .saturating_add(if verification.key.is_some() {
                TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE
            } else {
                0
            });
    let mut response = Vec::with_capacity(capacity);
    response.extend_from_slice(base_bytes);
    let Some(tlv_data) = original_data.get(base_size..).filter(|d| !d.is_empty()) else {
        return StampResponse::new(response);
    };
    if tlv_mode == TlvHandlingMode::Ignore {
        // Act as a reflector without TLV support: copy the content beyond
        // the base packet unprocessed (RFC 8762 §4.3, RFC 8972 §4).
        response.extend_from_slice(tlv_data);
        return StampResponse::new(response);
    }

    // One lenient pass handles valid and malformed TLVs alike.
    let (mut tlvs, _) = TlvList::parse_lenient(tlv_data);
    // Bytes the parser left alone: an all-zero tail or 1-3 octets too short
    // for a TLV header.
    let unparsed_tail = &tlv_data[tlvs.wire_size().min(tlv_data.len())..];

    // RFC 8972 §4.8: the TLV HMAC covers the Sequence Number (first 4 bytes)
    // and the TLVs. Apply the reflector's U, M and I flags; on an HMAC failure
    // the TLVs are echoed with I set, not dropped.
    let verify_key = verification.key.filter(|_| verification.verify);
    let hmac_ok = tlvs.apply_reflector_flags_strict(
        verify_key,
        &original_data[..4],
        tlv_data,
        verification.require_hmac_tlv,
    );
    let mut response_info = StampResponse::new(Vec::new());
    // This C is generated by local length validation before HMAC admission.
    // Preserve its cause even when verification sets I.
    response_info
        .ber_conformance
        .merge(tlvs.short_ber_conformance_errors());

    #[cfg(feature = "metrics")]
    if ctx.metrics_enabled {
        let (u_count, m_count, i_count) = tlvs.count_error_flags();
        crate::metrics::reflector_metrics::record_tlv_errors(u_count, m_count, i_count);
    }

    // On HMAC failure only echo, with I set (RFC 8972 §4.8). With a malformed
    // TLV, process the TLVs before it; the flags already mark it M and the
    // rest U (RFC 8972 §4).
    if hmac_ok && tlvs.allows_processing() {
        let Some(result) =
            apply_semantic_tlv_processing(&mut tlvs, ctx, verification.key, base_bytes)
        else {
            return StampResponse {
                return_path_action: ReturnPathAction::SuppressReply,
                ..StampResponse::new(response)
            };
        };
        response_info.cos_request = result.cos_request;
        response_info.cos_reply_policy = result.cos_reply_policy;
        response_info.return_path_action = result.return_path_action;
        response_info.reflected_control = result.reflected_control;
        response_info.reply_source = result.reply_source;
        response_info.tlv_hmac_generated = result.tlv_hmac_generated;
        response_info.tlv_processed = true;
        response_info.ber_conformance.merge(result.ber_conformance);
        response_info.tlv_conformance.merge(result.tlv_conformance);
    } else {
        // Observe only bounded child headers in known container layouts; this
        // neither validates nor mutates opaque values.
        response_info
            .tlv_conformance
            .merge(tlvs.preserved_peer_c_errors(false));
    }

    tlvs.write_to(&mut response);

    // Preserve only the received unparsed tail (RFC 8762 §4.3/§4.6). Do not
    // refill removed header TLVs with raw zeros: after an HMAC those would be
    // unframed non-padding TLVs. The header size limit intentionally permits a
    // shorter reply. Skip when Type 12 controls the reply length (RFC 10052
    // §3). The tail lies outside both HMACs.
    if response_info.reflected_control.is_none() && response.len() < original_data.len() {
        let take = unparsed_tail
            .len()
            .min(original_data.len() - response.len());
        response.extend_from_slice(&unparsed_tail[..take]);
    }
    response_info.data = response;
    response_info
}
