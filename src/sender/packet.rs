//! Test packet and request TLV construction for the sender.

use super::*;

/// Removes Reflected Fixed/IPv6 Extension Header TLVs (Types 247/246) from
/// `extra_tlvs` until the assembled packet fits within `mtu`
/// (draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§6.2: "one or more ... TLVs MUST be
/// removed to avoid violating the path MTU limit"). `fixed_overhead` is every
/// on-wire byte outside `extra_tlvs` (IP + attached ext headers + UDP + STAMP
/// base + the per-packet HMAC/DM/Access TLVs). Type-246 TLVs are removed before
/// Type-247: they come last in the ext-hdr-15 §6.3 order, so trimming from the
/// tail keeps the survivors ordered. Only these two TLV types are ever removed.
///
/// Returns how many TLVs were removed.
pub(super) fn enforce_egress_mtu(
    extra_tlvs: &mut Vec<RawTlv>,
    mtu: usize,
    fixed_overhead: usize,
) -> usize {
    let wire = |tlvs: &[RawTlv]| -> usize {
        tlvs.iter()
            .map(|t| crate::tlv::TLV_HEADER_SIZE + t.value.len())
            .sum()
    };
    let is_header_tlv = |t: &RawTlv| {
        matches!(
            t.tlv_type,
            TlvType::ReflectedIpv6ExtHdr | TlvType::ReflectedFixedHdr
        )
    };
    let mut removed = 0usize;
    while fixed_overhead + wire(extra_tlvs) > mtu {
        let Some(idx) = extra_tlvs.iter().rposition(is_header_tlv) else {
            break; // No header TLV left; other oversize is not this rule's concern.
        };
        extra_tlvs.remove(idx);
        removed += 1;
    }
    removed
}

pub(super) fn log_header_trim(removed: usize, mtu: usize) {
    if removed > 0 {
        log::warn!(
            "Removed {removed} Reflected Fixed/IPv6 Ext Header TLV(s) (Type 246/247) to keep the \
             test packet within the {mtu}-byte MTU (draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§6.2)"
        );
    }
}

/// Builds the wire bytes of one deliberately malformed TLV, used by the
/// `--malformed` conformance-testing switch to exercise a reflector's
/// malformed-TLV handling (RFC 8972 §4). The TLV is appended after the packet's
/// regular content; the sender does not otherwise rely on or parse it.
pub(super) fn malformed_tlv_bytes(mode: MalformedMode) -> Vec<u8> {
    // Flags, Type, Length(hi), Length(lo), then Value.
    const U_FLAG: u8 = crate::tlv::TlvFlags::U;
    let padding_type = TlvType::ExtraPadding.to_byte();
    match mode {
        // Structurally valid (length matches the 4 value octets) but with
        // reserved flag bits set: `U_FLAG | 0x07` lights the three lowest
        // reserved bits while still asserting U as a sender must.
        MalformedMode::BadFlags => vec![U_FLAG | 0x07, padding_type, 0x00, 0x04, 0, 0, 0, 0],
        // Length field claims 0xFFFF octets but only four follow, so the
        // declared length overruns the packet (RFC 8972 §4: M flag).
        MalformedMode::BadLength => vec![U_FLAG, padding_type, 0xFF, 0xFF, 0, 0, 0, 0],
    }
}

/// Builds a Micro-session ID TLV with the sender's member-link ID.
/// Writes the known `reflector_id`, or zero when unknown (RFC 9534 §3.2).
pub(super) fn micro_session_request_tlv(sender_id: u16, reflector_id: Option<u16>) -> RawTlv {
    MicroSessionIdTlv::new(sender_id, reflector_id.unwrap_or(0)).to_raw()
}

/// Builds the Reflected Test Packet Control TLV (RFC 10052 §3) when needed.
///
/// It is needed when the configuration requests asymmetric replies
/// (count > 1) and/or attaches an IPv6 Extension Header Control sub-TLV
/// (draft-ietf-ippm-stamp-ext-hdr-15 §5.1). Returns `None` for plain
/// symmetric measurements so trivial sessions are not amplified.
pub(super) fn build_reflected_control_tlv(
    length: u16,
    count: u16,
    interval_ns: u32,
    no_ext_hdr: bool,
) -> Option<ReflectedControlTlv> {
    if count <= 1 && !no_ext_hdr {
        return None;
    }
    if no_ext_hdr {
        // Presence-only IPv6 Extension Header Control sub-TLV:
        // flags=0, type (experimental stand-in for TBA3), length=0.
        Some(ReflectedControlTlv::with_sub_tlvs(
            length,
            count,
            interval_ns,
            vec![
                0x00,
                crate::tlv::REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL,
                0x00,
                0x00,
            ],
        ))
    } else {
        Some(ReflectedControlTlv::new(length, count, interval_ns))
    }
}

/// Builds the control TLV with the current AIMD-scaled interval
/// (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
///
/// `SenderRun::build_probe` calls this for every probe, including Access
/// Report retries, when `scale_reflected_control` is active, since
/// `extra_tlvs` omits the static TLV.
pub(super) fn scaled_reflected_control_tlv(
    length: u16,
    count: u16,
    interval_ns: u32,
    no_ext_hdr: bool,
    scale: f64,
) -> Option<RawTlv> {
    let scaled_ns = ((interval_ns as f64) * scale)
        .round()
        .clamp(0.0, u32::MAX as f64) as u32;
    build_reflected_control_tlv(length, count, scaled_ns, no_ext_hdr).map(|c| c.to_raw())
}

/// Builds the Reflected Fixed / IPv6 Extension Header request TLVs
/// (draft-ietf-ippm-stamp-ext-hdr-15 §4.2, §6.2) for the outgoing packet,
/// honoring the optional Requested-field selectors (§4.1, §6.1). Assumes `conf`
/// has passed `validate()` (so any selector decodes and fits); a stray decode
/// error degrades to the zero-filled request rather than panicking.
pub(super) fn reflected_header_request_tlvs(conf: &Configuration) -> Vec<RawTlv> {
    let mut out = Vec::new();

    // draft-ietf-ippm-stamp-ext-hdr-15 §6.3: the Reflected Fixed Header Data
    // (Type 247) TLVs MUST be added before the Reflected IPv6 Extension Header
    // Data (Type 246) TLVs, so emit every 247 first.
    let fixed_family_len = if conf.remote_ip().is_ipv4() {
        IPV4_FIXED_HEADER_SIZE
    } else {
        IPV6_FIXED_HEADER_SIZE
    };
    let fixed_specs = conf.fixed_hdr_requests();
    // §6.2: each occurrence adds a Type-247 TLV of the family's header length,
    // in header order; the reflector pairs them with its outer-to-inner
    // capture (rule 3). The backward-compatible standalone
    // `--reflected-fixed-hdr-selector` applies only to the single-header form.
    let single_fixed = fixed_specs.len() == 1;
    for spec in &fixed_specs {
        let selector = spec.selector.clone().or_else(|| {
            single_fixed
                .then(|| selector_bytes(conf.reflected_fixed_hdr_selector.as_deref()))
                .flatten()
        });
        let tlv = match selector {
            Some(sel) => ReflectedFixedHdrTlv::request_with_selector(&sel, fixed_family_len),
            None => ReflectedFixedHdrTlv::request_with_capacity(fixed_family_len),
        };
        out.push(tlv.to_raw());
    }
    if !fixed_specs.is_empty() {
        log::info!(
            "Reflected Fixed Header TLV(s) (Type 247) requested: {} header(s), {} bytes each",
            fixed_specs.len(),
            fixed_family_len
        );
    }

    // draft-ietf-ippm-stamp-ext-hdr-15 §4.2: for every real IPv6 extension
    // header the sender attaches (`--attach-ext-hdr`), emit a matching Type-246
    // request TLV so the reflector copies it back. The attached headers appear
    // on the wire before any externally-supplied ones, and each carries an
    // all-zeros Requested field: the header's first on-wire octet (Next Header)
    // is assigned by the kernel and cannot be predicted here, so positional
    // pairing (§4.2 rule 3), not a selector, disambiguates them.
    // IPv6 extension headers do not exist for IPv4, so attach-derived request
    // TLVs are emitted only for IPv6 destinations (matching the send-path gate).
    let attach_specs = if conf.remote_ip().is_ipv6() {
        conf.attach_ext_hdrs()
    } else {
        Vec::new()
    };
    if conf.reflected_ipv6_ext_hdr.is_empty() {
        for attach in &attach_specs {
            out.push(ReflectedIpv6ExtHdrTlv::request_with_capacity(attach.bytes.len()).to_raw());
        }
    }
    if !attach_specs.is_empty() {
        log::info!(
            "Attaching {} real IPv6 extension header(s) with matching Type-246 request TLV(s) \
             (draft-ietf-ippm-stamp-ext-hdr-15 §4.2)",
            attach_specs.len()
        );
    }

    // Explicit `--reflected-ipv6-ext-hdr` request TLVs (§4.2: in header order,
    // each Length matching its header). The standalone
    // `--reflected-ipv6-ext-hdr-selector` applies only to the single-header form.
    let ext_specs = conf.ext_hdr_requests();
    let single_ext = ext_specs.len() == 1;
    for spec in &ext_specs {
        let selector = spec.selector.clone().or_else(|| {
            single_ext
                .then(|| selector_bytes(conf.reflected_ipv6_ext_hdr_selector.as_deref()))
                .flatten()
        });
        let tlv = match selector {
            Some(sel) => {
                let cap = spec.length.max(sel.len());
                ReflectedIpv6ExtHdrTlv::request_with_selector(&sel, cap)
            }
            None => ReflectedIpv6ExtHdrTlv::request_with_capacity(spec.length),
        };
        out.push(tlv.to_raw());
    }
    if !ext_specs.is_empty() {
        log::info!(
            "Reflected IPv6 Ext Header TLV(s) (Type 246) requested: {} header(s)",
            ext_specs.len()
        );
    }

    out
}

/// Decodes a validated selector string to bytes; `None` when absent or (post-
/// `validate()`, which should not happen) unparseable.
pub(super) fn selector_bytes(sel: Option<&str>) -> Option<Vec<u8>> {
    sel.and_then(|s| decode_selector(s).ok())
}

/// Creates a new unauthenticated STAMP test packet with the specified error estimate.
///
/// `error_estimate` is in wire format. The caller should set the sequence
/// number and timestamp before sending.
pub fn assemble_unauth_packet(error_estimate: u16) -> PacketUnauthenticated {
    PacketUnauthenticated {
        timestamp: 0,
        ssid: 0,
        mbz: [0u8; 28],
        error_estimate,
        sequence_number: 0,
    }
}

/// Creates a new authenticated STAMP test packet with the specified error estimate.
///
/// `error_estimate` is in wire format. The caller should set the sequence
/// number and timestamp before sending, then call `finalize_auth_packet` to
/// compute and set the HMAC.
pub fn assemble_auth_packet(error_estimate: u16) -> PacketAuthenticated {
    PacketAuthenticated {
        timestamp: 0,
        mbz0: [0u8; 12],
        error_estimate,
        ssid: 0,
        sequence_number: 0,
        hmac: [0u8; 16],
        mbz1a: [0u8; 30],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
    }
}

/// Computes and sets the base HMAC after all other packet fields are finalized.
pub(crate) fn finalize_auth_packet(packet: &mut PacketAuthenticated, key: &HmacKey) {
    let bytes = packet.to_bytes();
    packet.hmac = compute_packet_hmac(key, &bytes, AUTH_HMAC_OFFSET);
}

/// Appends `groups` of TLVs to `out` in order, followed by an HMAC TLV when
/// `tlv_hmac_key` is set (RFC 8972 §4.8). The HMAC covers the Sequence Number
/// and the TLVs before it. When the probe carries BER TLVs, Extra Padding goes
/// after the HMAC and outside its coverage, so residual bit errors can be
/// measured. The layout matches a `TlvList` built from the same TLVs and
/// signed with `set_hmac`, without copying the TLVs into one.
pub(super) fn write_probe_tlvs(
    out: &mut Vec<u8>,
    sequence_number: u32,
    groups: &[&[RawTlv]],
    tlv_hmac_key: Option<&HmacKey>,
) {
    let tlvs = || groups.iter().flat_map(|group| group.iter());
    let padding_last = tlv_hmac_key.is_some() && tlvs().any(|tlv| crate::ber::is_ber(tlv.tlv_type));
    let covered = |tlv: &&RawTlv| !(padding_last && tlv.tlv_type == TlvType::ExtraPadding);
    let mut signer = tlv_hmac_key.map(|key| {
        let mut signer = key.signer();
        signer.update(&sequence_number.to_be_bytes());
        signer
    });
    for tlv in tlvs().filter(covered) {
        tlv.write_to(out);
        if let Some(signer) = signer.as_mut() {
            signer.update(&tlv.wire_header());
            signer.update(&tlv.value);
        }
    }
    if let Some(signer) = signer {
        RawTlv::new(TlvType::Hmac, signer.finish().to_vec()).write_to(out);
    }
    for tlv in tlvs().filter(|tlv| !covered(tlv)) {
        tlv.write_to(out);
    }
}

/// Builds an unauthenticated STAMP packet with TLV extensions.
///
/// `error_estimate` is in wire format; a `None` SSID is sent as zero. With
/// `tlv_hmac_key`, an HMAC TLV (RFC 8972 §4.8) follows `extra_tlvs`.
pub fn build_unauth_packet_with_tlvs(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    ssid: Option<u16>,
    extra_tlvs: &[RawTlv],
    tlv_hmac_key: Option<&HmacKey>,
) -> Vec<u8> {
    let base = PacketUnauthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz: [0u8; 28],
    };
    let mut out = base.to_bytes().to_vec();
    write_probe_tlvs(&mut out, sequence_number, &[extra_tlvs], tlv_hmac_key);
    out
}

/// Builds an authenticated STAMP packet with TLV extensions.
///
/// `base_hmac_key` signs the base packet; `tlv_hmac_key`, which may be the
/// same key, adds an HMAC TLV (RFC 8972 §4.8) after `extra_tlvs`.
/// `error_estimate` is in wire format; a `None` SSID is sent as zero.
pub fn build_auth_packet_with_tlvs(
    sequence_number: u32,
    timestamp: u64,
    error_estimate: u16,
    base_hmac_key: &HmacKey,
    ssid: Option<u16>,
    extra_tlvs: &[RawTlv],
    tlv_hmac_key: Option<&HmacKey>,
) -> Vec<u8> {
    let mut base = PacketAuthenticated {
        sequence_number,
        timestamp,
        error_estimate,
        ssid: ssid.unwrap_or(0),
        mbz0: [0u8; 12],
        mbz1a: [0u8; 30],
        mbz1b: [0u8; 32],
        mbz1c: [0u8; 6],
        hmac: [0u8; 16],
    };
    finalize_auth_packet(&mut base, base_hmac_key);
    let mut out = base.to_bytes().to_vec();
    write_probe_tlvs(&mut out, sequence_number, &[extra_tlvs], tlv_hmac_key);
    out
}
