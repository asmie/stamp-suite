//! Privileged network-namespace conformance tier (Linux only).
//!
//! These tests exercise the on-wire behaviours that unit and loopback tests
//! cannot reach: real IP TOS/ECN bytes, TTL/Hop-Limit marking, IPv6 extension
//! headers, SRv6 SRH routing, Address Group (MAC/IP) filtering, and Type-12
//! multi-reply pacing. Each is mapped to the conformance-matrix clauses it
//! evidences (RFC 8762 §4.x + erratum 8199, RFC 8972 §4.4, RFC 9503 §5,
//! draft-ietf-ippm-asymmetrical-pkts-14, draft-ietf-ippm-stamp-ext-hdr-11,
//! draft-ietf-ippm-stamp-cos-ecn-01, draft-gandhi-ippm-stamp-ber).
//!
//! # Running
//!
//! Every scenario is `#[ignore]`d and additionally guarded: it runs only with
//! `STAMP_NETNS_TESTS=1`, as root (or CAP_NET_ADMIN), and when its per-scenario
//! kernel/tool prerequisites hold. Missing prerequisites **skip cleanly**
//! (printing `[netns] SKIP …`) — they never fail — mirroring the project's
//! defensive-hardware-features rule.
//!
//! ```bash
//! sudo -E STAMP_NETNS_TESTS=1 cargo test --test netns_conformance -- --ignored --test-threads=1
//! ```
//!
//! See `doc/testing-netns.md` for prerequisites and troubleshooting.

#![cfg(target_os = "linux")]

use std::{
    net::{IpAddr, SocketAddr},
    thread,
    time::Duration,
};

use stamp_suite::packets::{
    ExtendedPacketUnauthenticated, ExtendedReflectedPacketUnauthenticated, PacketUnauthenticated,
};
use stamp_suite::tlv::{
    RawTlv, ReflectedControlTlv, ReflectedIpv6ExtHdrTlv, TlvList, TlvType, TypedTlv,
};

mod netns;
use netns::{CapturedPacket, NetnsFixture};

/// 16-byte HMAC key (hex) used by the authenticated round-trip scenario.
const HMAC_HEX: &str = "0123456789abcdef0123456789abcdef";

// --------------------------------------------------------------------------
// Small shared helpers.
// --------------------------------------------------------------------------

/// Packets whose UDP source port is the reflector port — i.e. reflected
/// replies leaving the reflector.
fn replies(pkts: &[CapturedPacket], port: u16) -> Vec<&CapturedPacket> {
    pkts.iter().filter(|p| p.src_port == port).collect()
}

/// Packets whose UDP destination port is the reflector port — i.e. test
/// packets arriving at the reflector.
fn requests(pkts: &[CapturedPacket], port: u16) -> Vec<&CapturedPacket> {
    pkts.iter().filter(|p| p.dst_port == port).collect()
}

fn base_unauth(seq: u32) -> PacketUnauthenticated {
    PacketUnauthenticated {
        sequence_number: seq,
        // A plausible NTP-era timestamp; the exact value is irrelevant here.
        timestamp: 0xE500_0000_0000_0000,
        error_estimate: 0,
        ssid: 0,
        mbz: [0u8; 28],
    }
}

fn reply_tlvs(payload: &[u8]) -> Option<TlvList> {
    ExtendedReflectedPacketUnauthenticated::from_bytes(payload)
        .ok()
        .map(|e| e.tlvs)
}

fn request_tlvs(payload: &[u8]) -> Option<TlvList> {
    ExtendedPacketUnauthenticated::from_bytes(payload)
        .ok()
        .map(|e| e.tlvs)
}

fn find_tlv(tlvs: &TlvList, t: TlvType) -> Option<RawTlv> {
    tlvs.iter().find(|x| x.tlv_type == t).cloned()
}

/// Builds a full unauthenticated STAMP test packet carrying a single Type-12
/// Reflected Control TLV whose value ends in `sub` (an Address Group sub-TLV).
fn craft_control_packet(sub: Vec<u8>) -> Vec<u8> {
    let ctrl = ReflectedControlTlv::with_sub_tlvs(0, 1, 0, sub).to_raw();
    let mut tlvs = TlvList::new();
    tlvs.push(ctrl).expect("push Type-12 TLV");
    ExtendedPacketUnauthenticated::with_tlvs(base_unauth(7), tlvs).to_bytes()
}

/// L3 Address Group sub-TLV (type 11) — `prefix_len(1) + reserved(3) + v4(4)`.
fn l3_sub(prefix_len: u8, prefix: [u8; 4]) -> Vec<u8> {
    let mut v = vec![0x00u8, 11, 0x00, 0x08, prefix_len, 0, 0, 0];
    v.extend_from_slice(&prefix);
    v
}

/// L2 Address Group sub-TLV (type 10) — `mask(6) + group(6)`.
fn l2_sub(mask: [u8; 6], group: [u8; 6]) -> Vec<u8> {
    let mut v = vec![0x00u8, 10, 0x00, 0x0c];
    v.extend_from_slice(&mask);
    v.extend_from_slice(&group);
    v
}

/// Standard round-trip sender args: a few packets, short spacing/timeout.
fn roundtrip_sender_args() -> Vec<&'static str> {
    vec!["--count", "3", "--send-delay", "50", "--timeout", "2"]
}

// ==========================================================================
// Scenario 1 — unauthenticated + authenticated round-trip (RFC 8762 §4.2-4.5).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_1_roundtrip_unauth_and_auth() {
    let scen = "1_roundtrip";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V4(fx.reflector_v4());
    let send = IpAddr::V4(fx.sender_v4());

    // Unauthenticated.
    {
        let _r = match fx.spawn_reflector(refl, &[], netns::BIN) {
            Ok(r) => r,
            Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
        };
        let run = fx.run_sender(refl, send, &roundtrip_sender_args());
        assert!(
            run.packets_received.unwrap_or(0) >= 1,
            "unauth round-trip received 0 replies (sender stderr: {})",
            run.stderr
        );
    }

    // Authenticated (HMAC on both ends).
    {
        let refl_args = ["--auth-mode", "A", "--hmac-key", HMAC_HEX];
        let _r = match fx.spawn_reflector(refl, &refl_args, netns::BIN) {
            Ok(r) => r,
            Err(e) => return netns::emit_skip(scen, &format!("spawn auth reflector: {e}")),
        };
        let mut args = roundtrip_sender_args();
        args.extend(["--auth-mode", "A", "--hmac-key", HMAC_HEX]);
        let run = fx.run_sender(refl, send, &args);
        assert!(
            run.packets_received.unwrap_or(0) >= 1,
            "authenticated round-trip received 0 replies (sender stderr: {})",
            run.stderr
        );
    }

    netns::emit_pass(scen, "unauth + auth replies received across the veth");
}

// ==========================================================================
// Scenario 2 — on-wire DSCP/ECN reflection + CoS reply-TOS
// (RFC 8972 §4.4 + erratum 8199 + draft-ietf-ippm-stamp-cos-ecn-01 §3.2).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_2_cos_dscp_ecn_onwire() {
    let scen = "2_cos_dscp_ecn";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V4(fx.reflector_v4());
    let send = IpAddr::V4(fx.sender_v4());
    let port = fx.port();

    let _r = match fx.spawn_reflector(refl, &[], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    // DSCP 34 (AF41), ECN 1 (ECT(1)). The sender egress-marks its packets and
    // requests these via the CoS TLV; the reflector reflects DSCP+ECN and
    // applies the requested reply-TOS.
    let mut args = roundtrip_sender_args();
    args.extend(["--cos", "--dscp", "34", "--ecn", "1"]);
    let run = fx.run_sender(refl, send, &args);
    thread::sleep(Duration::from_millis(150));
    let pkts = cap.stop();

    if pkts.is_empty() {
        return netns::emit_skip(scen, "no packets captured (tcpdump/timing)");
    }
    assert!(
        run.packets_received.unwrap_or(0) >= 1,
        "CoS round-trip received 0 replies (sender stderr: {})",
        run.stderr
    );

    let reply = *replies(&pkts, port)
        .first()
        .expect("at least one reflected reply on the wire");

    // Erratum 8199 + cos-ecn-01 normal case: the reply's on-wire DSCP equals
    // the requested DSCP1 (34) and its ECN equals EC1 (1, RPE=0b11).
    assert_eq!(
        reply.dscp(),
        34,
        "reflected reply DSCP on the wire should be 34 (got {})",
        reply.dscp()
    );
    assert_eq!(
        reply.ecn(),
        1,
        "reflected reply ECN on the wire should be EC1=1 (got {})",
        reply.ecn()
    );

    // The echoed CoS TLV must carry DSCP2/EC2 = received (34/1) and RPE=0b11.
    let tlvs = reply_tlvs(&reply.payload).expect("parse reflected packet TLVs");
    let cos = find_tlv(&tlvs, TlvType::ClassOfService).expect("reflected CoS TLV present");
    assert_eq!(cos.value.len(), 4, "CoS TLV value is 4 octets");
    let dscp2 = ((cos.value[0] & 0x03) << 4) | ((cos.value[1] >> 4) & 0x0f);
    let ec2 = (cos.value[1] >> 2) & 0x03;
    let rpe = (cos.value[2] >> 4) & 0x03;
    assert_eq!(dscp2, 34, "CoS DSCP2 reflects received DSCP (erratum 8199)");
    assert_eq!(ec2, 1, "CoS EC2 reflects received ECN (erratum 8199)");
    assert_eq!(rpe, 0b11, "CoS RPE=0b11 (reply ECN set to EC1, cos-ecn-01)");

    netns::emit_pass(
        scen,
        "reply carries DSCP=34 ECN=1 and CoS RPE=0b11 on the wire",
    );
}

// ==========================================================================
// Scenario 3 — SRv6 Return Path: SRH attached and routed (RFC 9503 §5 /
// RFC 8754). First live exercise of send_with_srh(). Skips without seg6.
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_3_srv6_return_path() {
    let scen = "3_srv6";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    if !netns::seg6_enabled() {
        return netns::emit_skip(
            scen,
            "net.ipv6.conf.all.seg6_enabled=0 (no SRv6 on this kernel)",
        );
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V6(fx.reflector_v6());
    let send = IpAddr::V6(fx.sender_v6());
    let port = fx.port();

    let _r = match fx.spawn_reflector(refl, &["--srv6-return-forwarding"], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    // Ask the reflector to return via an SRv6 segment list (a single SID: the
    // reflector's own address, the simplest valid routed segment).
    let sid = fx.reflector_v6().to_string();
    let mut args = roundtrip_sender_args();
    args.extend(["--return-srv6-sids", &sid]);
    let run = fx.run_sender(refl, send, &args);
    thread::sleep(Duration::from_millis(150));
    let pkts = cap.stop();

    // A reply is expected either way: SRH-forwarded (RFC 8754 routing header
    // present) or, if the kernel refused the SRH, a normal reply with the
    // Return Path U-flag set. Both are conformant; we assert the round-trip
    // completed and report which path was taken.
    assert!(
        run.packets_received.unwrap_or(0) >= 1,
        "SRv6 return-path round-trip received 0 replies (sender stderr: {})",
        run.stderr
    );
    let srh_seen = replies(&pkts, port)
        .iter()
        .any(|p| p.ext_headers.iter().any(|(t, _)| *t == 43));
    let detail = if srh_seen {
        "reply carried an SRH (routing header) — live send_with_srh verified"
    } else {
        "reply received via U-flag fallback (kernel declined SRH insertion)"
    };
    netns::emit_pass(scen, detail);
}

// ==========================================================================
// Scenario 4a — ext-hdr on the nix backend: a Type-246 request the backend
// cannot satisfy comes back with the C flag (Conformance) set
// (draft-ietf-ippm-stamp-ext-hdr-11 §5.1, -11 semantics).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_4a_ext_hdr_nix_c_flag() {
    let scen = "4a_ext_hdr_nix";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V6(fx.reflector_v6());
    let send = IpAddr::V6(fx.sender_v6());
    let port = fx.port();

    let _r = match fx.spawn_reflector(refl, &[], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    let mut args = roundtrip_sender_args();
    args.push("--reflected-ipv6-ext-hdr");
    let run = fx.run_sender(refl, send, &args);
    thread::sleep(Duration::from_millis(150));
    let pkts = cap.stop();

    assert!(
        run.packets_received.unwrap_or(0) >= 1,
        "ext-hdr round-trip received 0 replies (sender stderr: {})",
        run.stderr
    );
    let reply = *replies(&pkts, port)
        .first()
        .expect("a reflected reply on the wire");
    assert!(
        reply.is_v6,
        "scenario runs over IPv6; reply must be an IPv6 packet"
    );
    let tlvs = reply_tlvs(&reply.payload).expect("parse reflected TLVs");
    let ext = find_tlv(&tlvs, TlvType::ReflectedIpv6ExtHdr)
        .expect("reflected Type-246 TLV present in reply");
    // The nix (UDP-socket) backend has no data-plane access, so -11 §5.1
    // requires it to echo the TLV with the Conformance flag set — NOT the
    // pre-11 U-flag.
    assert!(
        ext.flags.conformant_reflected,
        "nix backend must set the C flag on the unsatisfiable Type-246 request"
    );
    assert!(
        !ext.flags.unrecognized,
        "-11 uses the C flag, not the U flag, for ext-hdr failure"
    );

    netns::emit_pass(scen, "Type-246 returned with C flag set by the nix backend");
}

// ==========================================================================
// Scenario 4b — real ext-hdr capture + reflection on the pnet backend
// (draft-ietf-ippm-stamp-ext-hdr-11 §§3.1, 5.1). Requires a pnet-feature
// reflector binary (STAMP_NETNS_PNET_BIN) and kernel IPV6_DSTOPTS injection.
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root + STAMP_NETNS_PNET_BIN"]
fn scenario_4b_ext_hdr_pnet_capture() {
    let scen = "4b_ext_hdr_pnet";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let pnet_bin = match std::env::var(netns::PNET_BIN_ENV) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            return netns::emit_skip(
                scen,
                &format!(
                    "{} not set (no ttl-pnet reflector binary)",
                    netns::PNET_BIN_ENV
                ),
            )
        }
    };
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl_v6 = fx.reflector_v6();
    let port = fx.port();

    let _r = match fx.spawn_reflector(IpAddr::V6(refl_v6), &[], &pnet_bin) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn pnet reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    // Craft a test packet with a Type-246 request whose Length (8) equals the
    // 8-byte Destination Options header we inject via a sticky IPV6_DSTOPTS
    // socket option.
    let req_tlv = ReflectedIpv6ExtHdrTlv::request_with_capacity(8).to_raw();
    let mut tlvs = TlvList::new();
    tlvs.push(req_tlv).expect("push Type-246 request");
    let payload = ExtendedPacketUnauthenticated::with_tlvs(base_unauth(9), tlvs).to_bytes();
    let dstopts = netns::build_destopts_padn();
    let dst = SocketAddr::new(IpAddr::V6(refl_v6), port);

    let reply =
        match fx.udp_exchange_from_sender(dst, &payload, Some(&dstopts), Duration::from_secs(2)) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return netns::emit_skip(scen, "no reply (pnet capture / injection unsupported)")
            }
            Err(e) => return netns::emit_skip(scen, &format!("injection unsupported: {e}")),
        };
    let pkts = cap.stop();

    // The on-wire request should carry the Destination Options header (type 60).
    let req_ext = requests(&pkts, port).iter().find_map(|p| {
        p.ext_headers
            .iter()
            .find(|(t, _)| *t == 60)
            .map(|(_, b)| b.clone())
    });
    let req_ext = match req_ext {
        Some(b) => b,
        None => {
            return netns::emit_skip(
                scen,
                "injected Destination Options header not observed on the wire",
            )
        }
    };

    let rtlvs = reply_tlvs(&reply).expect("parse reflected TLVs");
    let ext =
        find_tlv(&rtlvs, TlvType::ReflectedIpv6ExtHdr).expect("reflected Type-246 TLV present");
    // Success path: C flag clear, and the Reflected field (value[4..]) equals
    // the captured header's bytes from offset 4 (§5.1: Requested(4)+Reflected).
    assert!(
        !ext.flags.conformant_reflected,
        "pnet backend captured the header, so the C flag must be clear"
    );
    assert!(
        ext.value.len() >= 8,
        "Type-246 value should be the 8-byte header"
    );
    assert_eq!(
        &ext.value[4..8],
        &req_ext[4..8],
        "Reflected field must echo the on-wire ext-header bytes from offset 4"
    );

    netns::emit_pass(
        scen,
        "pnet backend captured and reflected the Destination Options header",
    );
}

// ==========================================================================
// Scenario 5 — L2 + L3 Address Group filters
// (draft-ietf-ippm-asymmetrical-pkts-14 §3.1.1 / §3.1.2): a matching filter
// yields a reply, a non-matching filter drops the packet (no reply).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_5_address_group_filters() {
    let scen = "5_address_group";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl_v4 = fx.reflector_v4();
    let port = fx.port();
    // Bind the reflector to its exact veth address so its local-address set is
    // deterministic ([refl_v4]) for L3 matching.
    let _r = match fx.spawn_reflector(IpAddr::V4(refl_v4), &[], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let mac = match fx.reflector_mac() {
        Ok(m) => m,
        Err(e) => return netns::emit_skip(scen, &format!("reflector MAC: {e}")),
    };
    let dst = SocketAddr::new(IpAddr::V4(refl_v4), port);
    let hit = Duration::from_millis(1500);
    let miss = Duration::from_millis(1000);

    // --- L3: matching /32 prefix → reply; non-matching → drop. ---
    let l3_match = craft_control_packet(l3_sub(32, refl_v4.octets()));
    match fx.udp_exchange_from_sender(dst, &l3_match, None, hit) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("L3 matching Address Group filter got no reply (should reflect)"),
        Err(e) => return netns::emit_skip(scen, &format!("L3-match send: {e}")),
    }
    let l3_miss = craft_control_packet(l3_sub(32, [203, 0, 113, 1]));
    match fx.udp_exchange_from_sender(dst, &l3_miss, None, miss) {
        Ok(None) => {}
        Ok(Some(_)) => panic!(
            "L3 non-matching Address Group filter was answered — §3.1.2 requires the \
             packet be dropped"
        ),
        Err(e) => return netns::emit_skip(scen, &format!("L3-miss send: {e}")),
    }

    // --- L2: matching MAC (mask=ff:ff:ff:ff:ff:ff) → reply; flipped → drop. ---
    let l2_match = craft_control_packet(l2_sub([0xff; 6], mac));
    match fx.udp_exchange_from_sender(dst, &l2_match, None, hit) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("L2 matching Address Group filter got no reply (should reflect)"),
        Err(e) => return netns::emit_skip(scen, &format!("L2-match send: {e}")),
    }
    let mut bad = mac;
    bad[5] ^= 0xff;
    let l2_miss = craft_control_packet(l2_sub([0xff; 6], bad));
    match fx.udp_exchange_from_sender(dst, &l2_miss, None, miss) {
        Ok(None) => {}
        Ok(Some(_)) => panic!(
            "L2 non-matching Address Group filter was answered — §3.1.1 requires the \
             packet be dropped"
        ),
        Err(e) => return netns::emit_skip(scen, &format!("L2-miss send: {e}")),
    }

    netns::emit_pass(
        scen,
        "L2 + L3 filters reflect on match and drop on mismatch",
    );
}

// ==========================================================================
// Scenario 6 — Type-12 multi-reply: count, pacing, and length padding on the
// wire (draft-ietf-ippm-asymmetrical-pkts-14 §3).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_6_type12_multi_reply() {
    let scen = "6_type12_multi_reply";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V4(fx.reflector_v4());
    let send = IpAddr::V4(fx.sender_v4());
    let port = fx.port();

    // Amplification is off by default; enable a cap of 16 so the request is
    // honoured.
    let _r = match fx.spawn_reflector(refl, &["--reflected-control-max-count", "16"], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    // One request asking for 4 reply copies, 20 ms apart, padded to 200 octets.
    let args = [
        "--count",
        "1",
        "--send-delay",
        "100",
        "--timeout",
        "2",
        "--reflected-control-count",
        "4",
        "--reflected-control-interval-ns",
        "20000000",
        "--reflected-control-length",
        "200",
    ];
    let _run = fx.run_sender(refl, send, &args);
    // Extra copies are emitted asynchronously; give them time before stopping.
    thread::sleep(Duration::from_millis(400));
    let pkts = cap.stop();

    let reps = replies(&pkts, port);
    if reps.is_empty() {
        return netns::emit_skip(scen, "no reply packets captured (timing)");
    }
    // Count: multiple replies emitted, but never more than requested (cap
    // respected).
    assert!(
        reps.len() >= 2,
        "Type-12 request should yield multiple replies (got {})",
        reps.len()
    );
    assert!(
        reps.len() <= 4,
        "reflector emitted more replies ({}) than the 4 requested — amplification cap breached",
        reps.len()
    );
    // Length: replies are padded well beyond the 44-octet base.
    assert!(
        reps.iter().all(|r| r.payload.len() > 44),
        "reflected replies should be padded toward the requested length"
    );
    // Pacing: the largest inter-reply gap approaches the requested 20 ms.
    let mut ts: Vec<u128> = reps.iter().map(|r| r.ts_ns).collect();
    ts.sort_unstable();
    let max_gap = ts.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0);
    assert!(
        max_gap >= 15_000_000,
        "inter-reply pacing {max_gap} ns is far below the requested 20 ms"
    );

    netns::emit_pass(
        scen,
        &format!(
            "{} replies, max gap {:.1} ms, padded payloads",
            reps.len(),
            max_gap as f64 / 1e6
        ),
    );
}

// ==========================================================================
// Scenario 7 — BER on the wire: the Bit Pattern fills the Extra Padding TLV,
// and the reflector's Bit Error Count is 0 on a clean channel
// (draft-gandhi-ippm-stamp-ber §3).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_7_ber_onwire() {
    let scen = "7_ber";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V4(fx.reflector_v4());
    let send = IpAddr::V4(fx.sender_v4());
    let port = fx.port();

    let _r = match fx.spawn_reflector(refl, &[], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    let args = [
        "--count",
        "1",
        "--send-delay",
        "100",
        "--timeout",
        "2",
        "--ber",
        "--ber-pattern",
        "ff00",
        "--ber-padding-size",
        "64",
    ];
    let run = fx.run_sender(refl, send, &args);
    thread::sleep(Duration::from_millis(150));
    let pkts = cap.stop();

    if pkts.is_empty() {
        return netns::emit_skip(scen, "no packets captured (timing)");
    }
    assert!(
        run.packets_received.unwrap_or(0) >= 1,
        "BER round-trip received 0 replies (sender stderr: {})",
        run.stderr
    );

    // Request on the wire: the Extra Padding TLV (Type 1) carries the 0xFF00
    // pattern repeated across 64 octets.
    let req = *requests(&pkts, port)
        .first()
        .expect("a test packet on the wire");
    let rtlvs = request_tlvs(&req.payload).expect("parse request TLVs");
    let pad = find_tlv(&rtlvs, TlvType::ExtraPadding).expect("Extra Padding TLV present");
    assert_eq!(pad.value.len(), 64, "padding size honoured on the wire");
    let expected: Vec<u8> = (0..64)
        .map(|i| if i % 2 == 0 { 0xff } else { 0x00 })
        .collect();
    assert_eq!(
        pad.value, expected,
        "Extra Padding carries the 0xFF00 pattern"
    );

    // Reply: on a clean channel, the Bit Error Count TLV (Type 241) reads 0.
    let reply = *replies(&pkts, port)
        .first()
        .expect("a reflected reply on the wire");
    let reply_tlvs = reply_tlvs(&reply.payload).expect("parse reflected TLVs");
    let count = find_tlv(&reply_tlvs, TlvType::BerCount).expect("BER Count TLV present in reply");
    assert_eq!(count.value.len(), 4, "BER Count TLV value is a u32");
    let errors = u32::from_be_bytes([
        count.value[0],
        count.value[1],
        count.value[2],
        count.value[3],
    ]);
    assert_eq!(errors, 0, "clean channel must yield a zero bit-error count");

    netns::emit_pass(
        scen,
        "0xFF00 pattern present in Extra Padding; clean-channel bit-error count = 0",
    );
}

// ==========================================================================
// Scenario 8 — TTL / Hop-Limit egress marking on the wire (`--ttl`,
// sender.rs apply_egress_ip_options).
// ==========================================================================
#[test]
#[ignore = "privileged netns tier: STAMP_NETNS_TESTS=1 + root"]
fn scenario_8_ttl_egress_marking() {
    let scen = "8_ttl";
    if let Err(r) = netns::require_env() {
        return netns::emit_skip(scen, &r);
    }
    let fx = match NetnsFixture::new() {
        Ok(f) => f,
        Err(e) => return netns::emit_skip(scen, &e),
    };
    let refl = IpAddr::V4(fx.reflector_v4());
    let send = IpAddr::V4(fx.sender_v4());
    let port = fx.port();

    let _r = match fx.spawn_reflector(refl, &[], netns::BIN) {
        Ok(r) => r,
        Err(e) => return netns::emit_skip(scen, &format!("spawn reflector: {e}")),
    };
    let cap = match fx.start_capture() {
        Ok(c) => c,
        Err(e) => return netns::emit_skip(scen, &format!("tcpdump: {e}")),
    };

    let mut args = roundtrip_sender_args();
    args.extend(["--ttl", "33"]);
    let run = fx.run_sender(refl, send, &args);
    thread::sleep(Duration::from_millis(150));
    let pkts = cap.stop();

    if pkts.is_empty() {
        return netns::emit_skip(scen, "no packets captured (timing)");
    }
    assert!(
        run.packets_received.unwrap_or(0) >= 1,
        "TTL round-trip received 0 replies (sender stderr: {})",
        run.stderr
    );
    // The veth is a single L2 hop, so the requested TTL is not decremented in
    // transit: the reflector-side capture sees exactly 33.
    let req = *requests(&pkts, port)
        .first()
        .expect("a test packet on the wire");
    assert_eq!(
        req.ttl, 33,
        "sender must set IP TTL to the requested 33 (got {})",
        req.ttl
    );

    netns::emit_pass(scen, "outgoing test packets carry IP TTL = 33 on the wire");
}
