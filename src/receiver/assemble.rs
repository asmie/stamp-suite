//! Reflected packet assembly (RFC 8762 §4.3) with TLV handling (RFC 8972).

use super::*;

/// Assembles an unauthenticated reflected packet from a received test packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
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

/// Assembles an unauthenticated reflected packet with symmetric size (RFC 8762 Section 4.3).
///
/// Preserves the original packet length by padding with zeros beyond the base 44 bytes.
/// Per RFC 8762 Section 4.2.1, extra octets SHOULD be filled with zeros.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data (used only for length)
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
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
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
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

    // Compute HMAC if key is provided
    if let Some(key) = hmac_key {
        let bytes = response.to_bytes();
        response.hmac = compute_packet_hmac(key, &bytes, AUTH_HMAC_OFFSET);
    }

    response
}

/// Assembles an authenticated reflected packet with symmetric size (RFC 8762 Section 4.3).
///
/// Preserves the original packet length by padding with zeros beyond the base 112 bytes.
/// Per RFC 8762 Section 4.2.1, extra octets SHOULD be filled with zeros.
///
/// # Arguments
/// * `packet` - The received authenticated test packet
/// * `original_data` - The original received packet data (used only for length)
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `hmac_key` - Optional HMAC key for computing the response HMAC
/// * `reflector_seq` - Optional independent reflector sequence number (RFC 8972 stateful mode)
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
/// set on ALL TLVs rather than dropping the packet.
///
/// # Arguments
/// * `packet` - The received unauthenticated test packet
/// * `original_data` - The original received packet data
/// * `cs` - Clock format to use for timestamps
/// * `rcvt` - Receive timestamp when the packet was received
/// * `ttl` - TTL/Hop Limit value from the received packet's IP header
/// * `reflector_error_estimate` - The reflector's own error estimate in wire format
/// * `reflector_seq` - Optional independent reflector sequence number
/// * `tlv_mode` - How to handle TLV extensions
/// * `tlv_hmac_key` - Optional HMAC key for TLV HMAC computation in response
/// * `verify_incoming_hmac` - Whether to verify incoming TLV HMAC (sets I-flag on failure)
/// * `received_dscp` - DSCP value received from IP header (for CoS TLV)
/// * `received_ecn` - ECN value received from IP header (for CoS TLV)
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
    let base_bytes = base.to_bytes();
    // Each queued response owns its output buffer; reserve the incoming size
    // and a possible generated TLV HMAC before appending the chain.
    let capacity = original_data
        .len()
        .max(base_bytes.len())
        .saturating_add(if tlv_hmac_key.is_some() { 20 } else { 0 });
    let mut response = Vec::with_capacity(capacity);
    response.extend_from_slice(&base_bytes);
    let mut cos_request: Option<(u8, u8)> = None;
    let mut return_path_action = ReturnPathAction::Normal;
    let mut reflected_control: Option<ReflectedControlBehavior> = None;
    let mut reply_source: Option<std::net::IpAddr> = None;
    let mut tlv_hmac_generated = false;

    // Handle TLVs based on mode
    match tlv_mode {
        TlvHandlingMode::Ignore => {
            // Act as a reflector without TLV support: copy the content
            // beyond the base packet unprocessed (RFC 8762 §4.3, RFC 8972 §4).
            if let Some(tail) = original_data.get(UNAUTH_BASE_SIZE..) {
                response.extend_from_slice(tail);
            }
        }
        TlvHandlingMode::Echo => {
            // Parse and echo TLVs from incoming packet
            if original_data.len() > UNAUTH_BASE_SIZE {
                let tlv_data = &original_data[UNAUTH_BASE_SIZE..];

                // One lenient pass handles valid and malformed TLVs alike.
                let (mut tlvs, _) = TlvList::parse_lenient(tlv_data);
                // Bytes the parser left alone: an all-zero tail or 1-3 octets
                // too short for a TLV header.
                let unparsed_tail = &tlv_data[tlvs.wire_size().min(tlv_data.len())..];

                // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + TLVs
                let incoming_seq_bytes = &original_data[..4];

                // Apply reflector-side flag updates per RFC 8972:
                // - U-flag for unrecognized types
                // - I-flag on ALL TLVs if HMAC verification fails (only if verify_incoming_hmac)
                // Per RFC 8972 §4.8: on failure, TLVs are echoed with I-flag set (not dropped)
                // Note: Unauthenticated mode does not require HMAC TLV presence
                let verify_key = if verify_incoming_hmac {
                    tlv_hmac_key
                } else {
                    None
                };
                let hmac_ok = tlvs.apply_reflector_flags(verify_key, incoming_seq_bytes, tlv_data);

                // Record TLV error metrics
                #[cfg(feature = "metrics")]
                if ctx.metrics_enabled {
                    let (u_count, m_count, i_count) = tlvs.count_error_flags();
                    crate::metrics::reflector_metrics::record_tlv_errors(u_count, m_count, i_count);
                }

                // On HMAC failure only echo, with I set (RFC 8972 §4.8). With a
                // malformed TLV, process the TLVs before it; the flags already
                // mark it M and the rest U (RFC 8972 §4).
                if hmac_ok && tlvs.allows_processing() {
                    match apply_semantic_tlv_processing(&mut tlvs, ctx, tlv_hmac_key, &base_bytes) {
                        Some(result) => {
                            cos_request = result.cos_request;
                            return_path_action = result.return_path_action;
                            reflected_control = result.reflected_control;
                            reply_source = result.reply_source;
                            tlv_hmac_generated = result.tlv_hmac_generated;
                        }
                        None => {
                            return StampResponse {
                                data: response,
                                cos_request: None,
                                return_path_action: ReturnPathAction::SuppressReply,
                                reflected_control: None,
                                reply_source: None,
                                tlv_hmac_generated: false,
                            };
                        }
                    }
                }

                tlvs.write_to(&mut response);

                // Copy the unparsed tail after the TLVs so the reply keeps the
                // request's size and bytes (RFC 8762 §4.3/§4.6). It follows the
                // HMAC, outside its coverage. Never truncate a longer reply, and
                // skip when Type 12 controls the reply length
                // (RFC 10052 §3).
                if reflected_control.is_none() && response.len() < original_data.len() {
                    let take = unparsed_tail
                        .len()
                        .min(original_data.len() - response.len());
                    response.extend_from_slice(&unparsed_tail[..take]);
                    response.resize(original_data.len(), 0);
                }
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
        reflected_control,
        reply_source,
        tlv_hmac_generated,
    }
}

/// Assembles an authenticated reflected packet with TLV handling (RFC 8972).
///
/// Per RFC 8972 §4.8, on HMAC verification failure, TLVs are echoed with I-flag
/// set on ALL TLVs rather than dropping the packet.
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
    let base_bytes = base.to_bytes();
    // Each queued response owns its output buffer; reserve the incoming size
    // and a possible generated TLV HMAC before appending the chain.
    let capacity = original_data
        .len()
        .max(base_bytes.len())
        .saturating_add(if tlv_hmac_key.is_some() { 20 } else { 0 });
    let mut response = Vec::with_capacity(capacity);
    response.extend_from_slice(&base_bytes);
    let mut cos_request: Option<(u8, u8)> = None;
    let mut return_path_action = ReturnPathAction::Normal;
    let mut reflected_control: Option<ReflectedControlBehavior> = None;
    let mut reply_source: Option<std::net::IpAddr> = None;
    let mut tlv_hmac_generated = false;

    // Handle TLVs based on mode
    match tlv_mode {
        TlvHandlingMode::Ignore => {
            // See the unauthenticated path. The base HMAC covers octets
            // 0-95 only, so the copied tail does not affect it.
            if let Some(tail) = original_data.get(AUTH_BASE_SIZE..) {
                response.extend_from_slice(tail);
            }
        }
        TlvHandlingMode::Echo => {
            // Parse and echo TLVs from incoming packet
            if original_data.len() > AUTH_BASE_SIZE {
                let tlv_data = &original_data[AUTH_BASE_SIZE..];

                // One lenient pass handles valid and malformed TLVs alike.
                let (mut tlvs, _) = TlvList::parse_lenient(tlv_data);
                // Bytes the parser left alone: an all-zero tail or 1-3 octets
                // too short for a TLV header.
                let unparsed_tail = &tlv_data[tlvs.wire_size().min(tlv_data.len())..];

                // Per RFC 8972 §4.8: HMAC covers Sequence Number (first 4 bytes) + TLVs
                let incoming_seq_bytes = &original_data[..4];

                // Apply reflector-side flag updates per RFC 8972:
                // - U-flag for unrecognized types
                // - I-flag on ALL TLVs if HMAC verification fails (only if verify_incoming_hmac)
                // Per RFC 8972 §4.8: on failure, TLVs are echoed with I-flag set (not dropped)
                // For strict RFC 8972 authenticated mode: require HMAC TLV (unless only Extra Padding)
                let verify_key = if verify_incoming_hmac {
                    tlv_hmac_key
                } else {
                    None
                };
                let require_hmac_tlv = verify_incoming_hmac;
                let hmac_ok = tlvs.apply_reflector_flags_strict(
                    verify_key,
                    incoming_seq_bytes,
                    tlv_data,
                    require_hmac_tlv,
                );

                // Record TLV error metrics
                #[cfg(feature = "metrics")]
                if ctx.metrics_enabled {
                    let (u_count, m_count, i_count) = tlvs.count_error_flags();
                    crate::metrics::reflector_metrics::record_tlv_errors(u_count, m_count, i_count);
                }

                // On HMAC failure only echo, with I set (RFC 8972 §4.8). With a
                // malformed TLV, process the TLVs before it; the flags already
                // mark it M and the rest U (RFC 8972 §4).
                if hmac_ok && tlvs.allows_processing() {
                    match apply_semantic_tlv_processing(&mut tlvs, ctx, tlv_hmac_key, &base_bytes) {
                        Some(result) => {
                            cos_request = result.cos_request;
                            return_path_action = result.return_path_action;
                            reflected_control = result.reflected_control;
                            reply_source = result.reply_source;
                            tlv_hmac_generated = result.tlv_hmac_generated;
                        }
                        None => {
                            return StampResponse {
                                data: response,
                                cos_request: None,
                                return_path_action: ReturnPathAction::SuppressReply,
                                reflected_control: None,
                                reply_source: None,
                                tlv_hmac_generated: false,
                            };
                        }
                    }
                }

                tlvs.write_to(&mut response);

                // See the unauthenticated path. The tail follows the base
                // HMAC field and the TLV HMAC, outside both coverages.
                if reflected_control.is_none() && response.len() < original_data.len() {
                    let take = unparsed_tail
                        .len()
                        .min(original_data.len() - response.len());
                    response.extend_from_slice(&unparsed_tail[..take]);
                    response.resize(original_data.len(), 0);
                }
            }
        }
    }

    StampResponse {
        data: response,
        cos_request,
        return_path_action,
        reflected_control,
        reply_source,
        tlv_hmac_generated,
    }
}
