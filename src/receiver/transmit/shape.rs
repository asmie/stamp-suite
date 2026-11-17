//! Fitting a reply to its payload budget, send-time telemetry and signing.

use super::*;

/// Inspect the shaped output rather than classifying an opaque incoming C flag.
pub(super) fn has_control_c(data: &[u8], base: usize) -> bool {
    let mut pos = base;
    while let Some(tlv) = TlvSpan::at(data, pos) {
        if tlv.tlv_type == TlvType::ReflectedControl
            && tlv.flags.processed()
            && tlv.flags.conformant_reflected
        {
            return true;
        }
        pos = tlv.end();
    }
    false
}

pub(super) fn is_reflected_header(tlv: &TlvSpan) -> bool {
    matches!(
        tlv.tlv_type,
        TlvType::ReflectedIpv6ExtHdr | TlvType::ReflectedFixedHdr
    )
}

/// True when the reply is a complete, well-formed TLV chain that includes a
/// processed Type 246/247 TLV.
pub(super) fn has_reflected_headers(data: &[u8], base: usize) -> bool {
    let mut pos = base;
    let mut found = false;
    while let Some(tlv) = TlvSpan::at(data, pos) {
        if tlv.flags.malformed {
            return false;
        }
        found |= is_reflected_header(&tlv) && tlv.flags.processed();
        pos = tlv.end();
    }
    found && pos == data.len()
}

/// True when the reply is a complete TLV chain, without M or I flags, that
/// carries a processed BER TLV.
pub(super) fn has_ber(data: &[u8], base: usize) -> bool {
    let mut pos = base;
    let mut found = false;
    while let Some(tlv) = TlvSpan::at(data, pos) {
        if tlv.flags.malformed || tlv.flags.integrity_failed {
            return false;
        }
        found |= crate::ber::is_ber(tlv.tlv_type) && !tlv.flags.unrecognized;
        pos = tlv.end();
    }
    found && pos == data.len()
}

#[cfg(test)]
pub(super) fn fit_reply_for_test(
    data: &mut Vec<u8>,
    base: usize,
    cap: usize,
    controlled: bool,
) -> io::Result<bool> {
    fit_reply(data, base, cap, controlled, &mut Default::default())
}

/// Preserve complete mandatory TLVs and the final HMAC. Only padding and
/// reflected header TLVs may be removed. Return true to terminate a burst.
pub(super) fn fit_reply(
    data: &mut Vec<u8>,
    base: usize,
    cap: usize,
    controlled: bool,
    reasons: &mut crate::ber::BerConformanceErrors,
) -> io::Result<bool> {
    if data.len() <= cap {
        return Ok(false);
    }
    let cannot_fit = || reply_too_large("mandatory reply fields exceed payload budget");
    if base > cap {
        return Err(cannot_fit());
    }
    // Header-reflection packets follow ext-hdr-26 §7.2: remove complete
    // reflected-header TLVs before considering any other resizing policy.
    let ber = has_ber(data, base);
    if ber && !has_reflected_headers(data, base) {
        return fit_ber_reply(data, base, cap, controlled, reasons);
    }
    // Every byte after the base must belong to a well-formed TLV.
    let mut pos = base;
    let mut tlvs = Vec::new();
    while pos < data.len() {
        let tlv = TlvSpan::at(data, pos).ok_or_else(cannot_fit)?;
        if tlv.flags.malformed {
            return Err(cannot_fit());
        }
        if !controlled || ber || tlv.tlv_type != TlvType::ExtraPadding {
            tlvs.push((tlv, data[tlv.start..tlv.end()].to_vec()));
        }
        pos = tlv.end();
    }
    let mut size = base + tlvs.iter().map(|(_, bytes)| bytes.len()).sum::<usize>();
    while size > cap {
        let Some(index) = tlvs
            .iter()
            .rposition(|(tlv, _)| is_reflected_header(tlv) && tlv.flags.processed())
        else {
            // After exhausting optional headers, use BER-specific padding:
            // whole repetitions for standalone replies, or an exact-budget
            // pattern prefix plus C for controlled replies.
            if ber {
                data.truncate(base);
                for (_, bytes) in tlvs {
                    data.extend_from_slice(&bytes);
                }
                return fit_reply(data, base, cap, controlled, reasons);
            }
            return Err(cannot_fit());
        };
        size -= tlvs.remove(index).1.len();
    }
    if controlled && ber {
        data.truncate(base);
        for (_, bytes) in tlvs {
            data.extend_from_slice(&bytes);
        }
        return fit_ber_reply(data, base, cap, true, reasons);
    }
    if controlled {
        // RFC 10052 §3: a reply clamped to the MTU carries C.
        if let Some((_, control)) = tlvs
            .iter_mut()
            .find(|(tlv, _)| tlv.tlv_type == TlvType::ReflectedControl && tlv.flags.processed())
        {
            control[0] |= TlvFlags::C;
        }
    }
    if controlled && !ber {
        let padding = cap - size;
        if padding >= TLV_HEADER_SIZE {
            let pad = crate::tlv::ExtraPaddingTlv::new_zeros(padding - TLV_HEADER_SIZE);
            let mut raw = crate::tlv::TypedTlv::to_raw(&pad);
            raw.flags = TlvFlags::default();
            let index = tlvs
                .iter()
                .position(|(tlv, _)| tlv.tlv_type.is_hmac())
                .unwrap_or(tlvs.len());
            let bytes = raw.to_bytes();
            let span = TlvSpan::at(&bytes, 0).expect("serialized padding TLV");
            tlvs.insert(index, (span, bytes));
        }
        // A 1..3-octet remainder cannot encode a TLV; send the shorter valid
        // packet with C=1, never a malformed tail or an over-MTU packet.

        // The clamp resized the padding after semantic processing, so the
        // BER forward count no longer describes it.
        for (tlv, bytes) in &mut tlvs {
            if crate::ber::is_ber(tlv.tlv_type) {
                bytes[0] |= TlvFlags::C;
                if !tlv.flags.integrity_failed && !tlv.flags.unrecognized {
                    reasons.insert(crate::ber::BerConformanceReason::PaddingResized);
                }
            }
        }
    }
    data.truncate(base);
    for (_, bytes) in tlvs {
        data.extend_from_slice(&bytes);
    }
    Ok(controlled)
}

pub(super) fn fit_ber_reply(
    data: &mut Vec<u8>,
    base: usize,
    cap: usize,
    controlled: bool,
    reasons: &mut crate::ber::BerConformanceErrors,
) -> io::Result<bool> {
    let cannot_fit = || reply_too_large("BER fields exceed payload budget");
    let list = crate::tlv::TlvList::parse(&data[base..]).map_err(|_| cannot_fit())?;
    let mut tlvs: Vec<_> = list.iter().cloned().collect();
    let resized = if controlled {
        let pads: Vec<_> = tlvs
            .iter()
            .enumerate()
            .filter(|(_, t)| t.tlv_type == TlvType::ExtraPadding)
            .map(|(i, _)| i)
            .collect();
        if pads.len() != 1 {
            return Err(cannot_fit());
        }
        let pad = pads[0];
        let old_len = tlvs[pad].value.len();
        let fixed = base
            + tlvs
                .iter()
                .map(crate::tlv::RawTlv::wire_size)
                .sum::<usize>()
            - old_len;
        let new_len = cap.checked_sub(fixed).ok_or_else(cannot_fit)?;
        tlvs[pad].value.resize(new_len, 0);
        crate::ber::repair_reflected_padding(&mut tlvs)?;
        old_len != new_len
    } else {
        crate::ber::fit_padding(&mut tlvs, cap, base).map_err(|_| cannot_fit())?
    };
    let mut fitted = crate::tlv::TlvList::new();
    for mut tlv in tlvs {
        if resized && crate::ber::is_ber(tlv.tlv_type) {
            tlv.set_conformant_reflected();
            reasons.insert(crate::ber::BerConformanceReason::PaddingResized);
        }
        if controlled && tlv.tlv_type == TlvType::ReflectedControl && tlv.is_processable() {
            tlv.set_conformant_reflected();
        }
        fitted.push(tlv).map_err(|_| cannot_fit())?;
    }
    data.truncate(base);
    data.extend_from_slice(&fitted.to_bytes());
    Ok(controlled)
}

/// Refreshes send-time Direct Measurement counters and Follow-Up Telemetry
/// in TLVs the reflector processed. Processing stopped at the first malformed
/// TLV (RFC 8972 §4), so the walk stops there too.
pub(super) fn refresh_telemetry(data: &mut [u8], base: usize, session: &Session, stateful: bool) {
    let mut pos = base;
    while let Some(tlv) = TlvSpan::at(data, pos) {
        if tlv.flags.malformed {
            break;
        }
        if tlv.flags.processed() {
            let value = &mut data[tlv.value()];
            match (tlv.tlv_type, tlv.len) {
                (TlvType::DirectMeasurement, DIRECT_MEASUREMENT_TLV_VALUE_SIZE) => {
                    value[4..8].copy_from_slice(&session.get_received_count().to_be_bytes());
                    value[8..12].copy_from_slice(&session.get_transmitted_count().to_be_bytes());
                }
                (TlvType::FollowUpTelemetry, FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE) if stateful => {
                    let (seq, ts, method) = session.get_last_reflection_with_method();
                    value[..4].copy_from_slice(&seq.to_be_bytes());
                    value[4..12].copy_from_slice(&ts.to_be_bytes());
                    value[12] = method.to_byte();
                }
                (TlvType::FollowUpTelemetry, FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE) => {
                    value[..12].fill(0)
                }
                _ => {}
            }
        }
        pos = tlv.end();
    }
}

/// Re-signs the TLV HMAC that assembly generated. Assembly puts it after all
/// TLVs, possibly followed by symmetric zero padding. Callers check
/// `StampResponse::tlv_hmac_generated`; echoed HMACs must stay unchanged.
pub(super) fn sign_tlvs(data: &mut [u8], base: usize, key: &HmacKey) {
    const HMAC_TLV_SIZE: usize = TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE;
    if data.len() < base + HMAC_TLV_SIZE {
        return;
    }
    // RFC 8972 §4.8: the HMAC covers the base Sequence Number and every
    // TLV before the HMAC TLV.
    let sign = |data: &mut [u8], hmac_at: usize| {
        let digest = key.compute_parts([&data[..4], &data[base..hmac_at]]);
        data[hmac_at + TLV_HEADER_SIZE..hmac_at + HMAC_TLV_SIZE].copy_from_slice(&digest);
    };
    // BER replies may carry nonzero Extra Padding after the HMAC. Walk
    // structural frames even past semantic M: assembly owns this generated
    // HMAC, and a well-framed error TLV still belongs in its signed prefix.
    let mut pos = base;
    while let Some(tlv) = TlvSpan::at(data, pos) {
        if tlv.tlv_type.is_hmac() && tlv.len == HMAC_TLV_VALUE_SIZE {
            sign(data, tlv.start);
            return;
        }
        pos = tlv.end();
    }
    // Otherwise the HMAC is the last TLV, followed only by zero padding. Match
    // its header after the flags byte: type, then the u16 length 16.
    let hmac_type = TlvType::Hmac.to_byte();
    let header_tail = [hmac_type, 0, HMAC_TLV_VALUE_SIZE as u8];
    for pos in (base..=data.len() - HMAC_TLV_SIZE).rev() {
        if data[pos + 1..pos + TLV_HEADER_SIZE] == header_tail
            && data[pos + HMAC_TLV_SIZE..].iter().all(|b| *b == 0)
        {
            sign(data, pos);
            return;
        }
    }
}
