//! Receiver implementation using pnet for raw packet capture with real TTL.
//!
//! Requires raw socket capabilities (root/CAP_NET_RAW on Linux).
//!
//! Uses `spawn_blocking` to run the blocking packet capture loop on a dedicated
//! thread, preventing starvation of the async runtime.

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering as AtomicOrdering},
    time::{Duration, Instant},
};

use pnet::{
    datalink::{self, Channel::Ethernet, Config, DataLinkReceiver, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        udp::UdpPacket,
        Packet,
    },
    util::MacAddr,
};

use std::sync::Arc;

use crate::{
    clock_format::ClockFormat,
    configuration::{is_auth, Configuration, TlvHandlingMode},
    crypto::HmacKey,
    error_estimate::ErrorEstimate,
    session::SessionManager,
};

use crate::tlv::ReturnPathAction;

use super::{
    cos_unable_fallback_tos, hmac_key_source_configured, load_hmac_key, print_reflector_stats,
    process_stamp_packet_isolated, recompute_response_tlv_hmac, set_cos_policy_rejected,
    set_return_path_u_flag_in_response, should_apply_fallback_tos, ProcessingContext,
    ReceiverSharedState, ReflectorCounters, AUTH_BASE_SIZE, UNAUTH_BASE_SIZE,
};

/// Context for sending STAMP responses in pnet mode.
struct PnetSendContext {
    send_socket_v4: std::net::UdpSocket,
    send_socket_v6: Option<std::net::UdpSocket>,
    /// Cached TOS value for IPv4 socket to avoid redundant setsockopt calls.
    last_tos_v4: std::cell::Cell<u8>,
    /// Cached TOS value for IPv6 socket to avoid redundant setsockopt calls.
    last_tos_v6: std::cell::Cell<u8>,
}

/// Configuration extracted for the blocking capture loop.
/// This allows us to move owned data into the spawn_blocking closure.
struct CaptureConfig {
    local_port: u16,
    clock_source: ClockFormat,
    use_auth: bool,
    error_estimate_wire: u16,
    hmac_key: Option<HmacKey>,
    /// Per-SSID key set (B6), shared with the control plane which may
    /// mutate it at runtime. When populated it overrides `hmac_key` and the
    /// reflector resolves the per-packet key via the incoming SSID.
    hmac_keys: Arc<std::sync::RwLock<Option<crate::crypto::HmacKeySet>>>,
    session_manager: Arc<SessionManager>,
    /// Whether stateful per-client sequence numbering is enabled.
    stateful_reflector: bool,
    tlv_mode: TlvHandlingMode,
    require_hmac: bool,
    verify_tlv_hmac: bool,
    strict_packets: bool,
    cleanup_interval: Option<Duration>,
    #[cfg(feature = "metrics")]
    metrics_enabled: bool,
    /// Shutdown flag set by signal handler.
    shutdown: Arc<AtomicBool>,
    /// Aggregate packet counters for reporting.
    counters: Arc<ReflectorCounters>,
    /// Local addresses for Destination Node Address TLV matching (RFC 9503 §4).
    /// RFC 8972 §4.2.2 Location field-disclosure policy.
    location_disclosure: crate::tlv::LocationDisclosure,
    /// Suppress the reply to a replayed Sequence Number
    /// (draft-ietf-ippm-asymmetrical-pkts-14 §5, `--drop-replayed`).
    drop_replayed: bool,
    /// DSCP/ECN admission policy (RFC 8972 §4.4/§6, cos-ecn-01 §3.2).
    cos_policy: crate::cos_policy::CosAdmissionPolicy,
    local_addresses: Vec<IpAddr>,
    /// Local MAC addresses for the Reflected Test Packet Control TLV's L2
    /// Address Group sub-TLV matching (draft-ietf-ippm-asymmetrical-pkts-14
    /// §3.1.1).
    local_macs: Vec<[u8; 6]>,
    /// Reflector member link ID for Micro-session ID TLV (RFC 9534 §3.2).
    reflector_member_link_id: Option<u16>,
    /// Whether to honour a Return Path "Return Address" sub-TLV (RFC 9503 §5).
    /// Off by default to prevent third-party traffic redirection.
    return_path_allow_alternate: bool,
    /// Per-source rate limiter (always constructed; rate 0 = unlimited,
    /// runtime-adjustable via the control plane).
    rate_limiter: Arc<super::RateLimiter>,
    /// Runtime-adjustable reflector caps (Reflected Test Packet Control
    /// TLV limits, draft-ietf-ippm-asymmetrical-pkts-14 §3).
    caps: Arc<super::RuntimeCaps>,
}

/// Interface properties needed for macOS special handling.
/// Extracted from NetworkInterface since it's not Send.
struct InterfaceProps {
    is_up: bool,
    is_broadcast: bool,
    is_loopback: bool,
    is_point_to_point: bool,
}

/// Runs the STAMP Session Reflector using pnet for raw packet capture.
///
/// Captures packets at the datalink layer to extract the real TTL value.
/// Requires elevated privileges (root or CAP_NET_RAW on Linux).
///
/// The blocking packet capture loop runs in a dedicated thread via `spawn_blocking`
/// to prevent starvation of the async runtime (e.g., metrics server).
pub async fn run_receiver(
    conf: &Configuration,
    shared: &ReceiverSharedState,
) -> Result<(), crate::StartupError> {
    let interface_ip_match =
        |iface: &NetworkInterface| iface.ips.iter().any(|ip| ip.ip() == conf.local_addr);

    // Find the network interface with the provided local IP address
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_ip_match);

    let interface = match interface {
        Some(iface) => iface,
        None => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::new(format!(
                "No interface found with IP address {}",
                conf.local_addr
            )));
        }
    };

    // Extract interface properties for macOS special handling (NetworkInterface is not Send)
    let iface_props = InterfaceProps {
        is_up: interface.is_up(),
        is_broadcast: interface.is_broadcast(),
        is_loopback: interface.is_loopback(),
        is_point_to_point: interface.is_point_to_point(),
    };

    // Configure read timeout for periodic cleanup during idle periods.
    // Use half the session timeout (min 1s) to allow cleanup of stale counter sessions.
    let read_timeout = if conf.session_timeout > 0 {
        Some(Duration::from_secs((conf.session_timeout / 2).max(1)))
    } else {
        None
    };
    let config = Config {
        read_timeout,
        ..Default::default()
    };

    // Create a channel to receive on
    let (_, rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::new(format!(
                "Unhandled channel type for interface {}",
                interface.name
            )));
        }
        Err(e) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::new(format!(
                "Unable to create capture channel on {}: {e}",
                interface.name
            )));
        }
    };

    // We need UDP sockets to send responses - one for each address family
    // since pnet captures at the datalink layer and may see both IPv4 and IPv6 packets
    let local_addr: SocketAddr = (conf.local_addr, conf.local_port).into();
    let send_socket_v4 = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::new(format!(
                "Cannot bind IPv4 send socket: {e}"
            )));
        }
    };
    let send_socket_v6 = std::net::UdpSocket::bind("[::]:0").ok(); // Optional, may fail if IPv6 unavailable

    // Check if authenticated mode is used
    let use_auth = is_auth(conf.auth_mode);

    // Load HMAC keys (B6: prefer the multi-key set path; fall back to a
    // single legacy key if --hmac-key-dir is not set).
    let keyset_configured = shared
        .hmac_keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .is_some();
    let hmac_key = if !keyset_configured {
        load_hmac_key(conf)
    } else {
        None
    };

    // Validate: authenticated mode requires some HMAC key (single or set).
    if use_auth && hmac_key.is_none() && !keyset_configured {
        shared.capture_alive.store(false, AtomicOrdering::Relaxed);
        return Err(crate::StartupError::new(
            "Authenticated mode (-A A) requires --hmac-key, --hmac-key-file, or --hmac-key-dir",
        ));
    }

    // See the matching check in the nix backend: a key source that failed to
    // load must not degrade into running without one.
    if hmac_key.is_none() && !keyset_configured && hmac_key_source_configured(conf) {
        shared.capture_alive.store(false, AtomicOrdering::Relaxed);
        return Err(crate::StartupError::new(
            "an HMAC key source was configured (--hmac-key, --hmac-key-file or \
             --hmac-key-dir) but no usable key could be loaded; see the error above. \
             Refusing to run without the key that was asked for",
        ));
    }

    // Build error estimate from configuration with Z flag set based on clock source
    let error_estimate = ErrorEstimate::with_clock_format(
        conf.clock_synchronized,
        conf.clock_source,
        conf.error_scale,
        conf.error_multiplier,
    )
    .unwrap_or_else(|_| ErrorEstimate::unsynchronized_with_format(conf.clock_source));
    let error_estimate_wire = error_estimate.to_wire();

    if hmac_key.is_some() {
        log::info!("HMAC authentication enabled");
    }

    let session_manager = Arc::clone(&shared.session_manager);

    if conf.stateful_reflector {
        log::info!("Stateful reflector mode enabled (RFC 8972)");
    }

    let send_ctx = PnetSendContext {
        send_socket_v4,
        send_socket_v6,
        last_tos_v4: std::cell::Cell::new(0),
        last_tos_v6: std::cell::Cell::new(0),
    };

    if conf.tlv_mode != TlvHandlingMode::Ignore {
        log::info!("TLV handling mode: {:?}", conf.tlv_mode);
    }

    println!(
        "STAMP Reflector listening on {} (pnet mode, real TTL)",
        local_addr
    );

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = conf
        .session_timeout
        .checked_div(2)
        .map(|t| Duration::from_secs(t.max(1)));

    let shutdown = Arc::new(AtomicBool::new(false));
    let counters = Arc::clone(&shared.counters);
    let start_time = shared.start_time;
    let output_format = conf.output_format;

    // Build local addresses for Destination Node Address TLV matching (RFC 9503 §4).
    let local_addresses = super::build_local_addresses(conf.local_addr);

    // Build local MAC addresses for the Reflected Test Packet Control TLV's
    // L2 Address Group sub-TLV matching (draft-ietf-ippm-asymmetrical-pkts-14
    // §3.1.1). Unlike `local_addresses`, this always enumerates every
    // interface's hardware address regardless of the bind address.
    let local_macs = super::build_local_macs();

    // Build capture config with all values needed by the blocking loop
    let capture_config = CaptureConfig {
        local_port: conf.local_port,
        clock_source: conf.clock_source,
        use_auth,
        error_estimate_wire,
        hmac_key,
        hmac_keys: Arc::clone(&shared.hmac_keys),
        session_manager: Arc::clone(&session_manager),
        stateful_reflector: conf.stateful_reflector,
        tlv_mode: conf.tlv_mode,
        require_hmac: conf.require_hmac,
        verify_tlv_hmac: conf.verify_tlv_hmac,
        strict_packets: conf.strict_packets,
        cleanup_interval,
        #[cfg(feature = "metrics")]
        metrics_enabled: conf.metrics,
        shutdown: Arc::clone(&shutdown),
        counters: Arc::clone(&counters),
        local_addresses,
        // RFC 8972 §4.2.2 Location field-disclosure policy; `validate()`
        // already rejected a bad list at startup.
        location_disclosure: conf.location_disclosure().unwrap_or_default(),
        drop_replayed: conf.drop_replayed,
        cos_policy: conf
            .cos_admission_policy()
            .unwrap_or_else(|_| crate::cos_policy::CosAdmissionPolicy::permit_all()),
        local_macs,
        reflector_member_link_id: conf.reflector_member_link_id,
        return_path_allow_alternate: conf.return_path_allow_alternate,
        rate_limiter: Arc::clone(&shared.rate_limiter),
        caps: Arc::clone(&shared.caps),
    };

    // Spawn async task that funnels both Ctrl+C and the control plane's
    // shutdown request (POST /v1/shutdown) into the capture loop's
    // existing shutdown flag.
    let shutdown_flag = Arc::clone(&shutdown);
    let control_shutdown = Arc::clone(&shared.shutdown_requested);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = tick.tick() => {
                    if control_shutdown.load(AtomicOrdering::Relaxed) {
                        log::info!("shutdown requested via control plane");
                        break;
                    }
                }
            }
        }
        shutdown_flag.store(true, AtomicOrdering::Relaxed);
    });

    // Spawn the blocking packet capture loop on a dedicated thread.
    // This prevents starvation of the async runtime which may be running
    // other tasks like the metrics HTTP server.
    let capture_alive_for_loop = Arc::clone(&shared.capture_alive);
    let result = tokio::task::spawn_blocking(move || {
        run_capture_loop(rx, capture_config, send_ctx, iface_props);
    })
    .await;

    // The capture thread should normally return cleanly on shutdown flag.
    // A panic propagated through the JoinHandle (`result == Err`) means an
    // unhandled invariant fired; surface it to logs and to the readiness flag
    // so systemd / external monitors can react. We still return cleanly so
    // the process exits with a normal status — systemd will restart us per
    // unit configuration.
    if let Err(e) = result {
        log::error!("Capture thread terminated abnormally: {}", e);
        capture_alive_for_loop.store(false, AtomicOrdering::Relaxed);
    }

    // Print reflector stats on shutdown
    print_reflector_stats(&counters, &session_manager, start_time, output_format);
}

/// The blocking packet capture loop, run on a dedicated thread.
fn run_capture_loop(
    mut rx: Box<dyn DataLinkReceiver>,
    config: CaptureConfig,
    send_ctx: PnetSendContext,
    iface_props: InterfaceProps,
) {
    let mut last_cleanup = Instant::now();
    let mut buf = [0u8; 1600];

    loop {
        // Check shutdown flag
        if config.shutdown.load(AtomicOrdering::Relaxed) {
            break;
        }

        // Periodic session cleanup check
        if let Some(interval) = config.cleanup_interval {
            if last_cleanup.elapsed() >= interval {
                let removed = config.session_manager.cleanup_stale_sessions();
                if removed > 0 {
                    log::debug!("Session cleanup: removed {} stale sessions", removed);
                }
                last_cleanup = Instant::now();
            }
        }

        let mut fake_ethernet_frame = MutableEthernetPacket::new(&mut buf[..]).unwrap();
        match rx.next() {
            Ok(packet) => {
                let payload_offset;
                if cfg!(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos"
                )) && iface_props.is_up
                    && !iface_props.is_broadcast
                    && (iface_props.is_loopback || iface_props.is_point_to_point)
                {
                    if iface_props.is_loopback {
                        payload_offset = 14;
                    } else {
                        payload_offset = 0;
                    }
                    if packet.len() > payload_offset {
                        let Some(ip_header) = Ipv4Packet::new(&packet[payload_offset..]) else {
                            continue; // Malformed packet, skip
                        };
                        let version = ip_header.get_version();
                        if version == 4 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv4);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_packet(&fake_ethernet_frame.to_immutable(), &config, &send_ctx);
                            continue;
                        } else if version == 6 {
                            fake_ethernet_frame.set_destination(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_source(MacAddr(0, 0, 0, 0, 0, 0));
                            fake_ethernet_frame.set_ethertype(EtherTypes::Ipv6);
                            fake_ethernet_frame.set_payload(&packet[payload_offset..]);
                            handle_packet(&fake_ethernet_frame.to_immutable(), &config, &send_ctx);
                            continue;
                        }
                    }
                }
                let Some(ethernet) = EthernetPacket::new(packet) else {
                    continue; // Malformed frame, skip
                };
                handle_packet(&ethernet, &config, &send_ctx);
            }
            Err(e) => {
                // Timeout errors are expected when read_timeout is set - just continue to run cleanup
                if e.kind() != std::io::ErrorKind::TimedOut
                    && e.kind() != std::io::ErrorKind::WouldBlock
                {
                    log::warn!("Capture receive failed: {}", e);
                }
            }
        }
    }
}

/// IP protocol numbers for the two IP-in-IP tunnel encapsulations.
const PROTO_IPV4_IN_IP: u8 = 4;
const PROTO_IPV6_IN_IP: u8 = 41;
/// Cap on IP-in-IP nesting we descend, to bound work on adversarial packets.
const MAX_IP_TUNNEL_DEPTH: usize = 4;

fn handle_packet(ethernet: &EthernetPacket, config: &CaptureConfig, send_ctx: &PnetSendContext) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                // Capture the raw 20-byte IPv4 fixed header for Reflected Fixed
                // Header Data TLV (Type 247). IHL * 4 gives the total IPv4 header
                // length (including options); the draft reflects only the fixed
                // 20-byte header, so clamp to that.
                let ipv4_bytes = header.packet();
                let fixed_len = std::cmp::min(ipv4_bytes.len(), crate::tlv::IPV4_FIXED_HEADER_SIZE);
                let mut fixed_headers = vec![ipv4_bytes[..fixed_len].to_vec()];
                let mut ext_headers: Vec<u8> = Vec::new();
                // Descend any IP-in-IP tunnel (§3.2 rule 2: multiple stacked IP
                // headers) to reach the innermost UDP datagram.
                let (final_proto, upper) = descend_ip_tunnel(
                    header.get_next_level_protocol().0,
                    header.payload(),
                    &mut fixed_headers,
                    &mut ext_headers,
                );
                if final_proto == IpNextHeaderProtocols::Udp.0 {
                    if let Some(udp) = UdpPacket::new(upper) {
                        if udp.get_destination() == config.local_port {
                            let captured = super::CapturedHeaders {
                                fixed_headers,
                                ipv6_ext_headers: ext_headers,
                            };
                            let pkt = PacketMeta {
                                src: SocketAddr::new(
                                    IpAddr::V4(header.get_source()),
                                    udp.get_source(),
                                ),
                                dst_addr: IpAddr::V4(header.get_destination()),
                                ttl: header.get_ttl(),
                                dscp: header.get_dscp(),
                                ecn: header.get_ecn(),
                                captured,
                            };
                            handle_stamp_packet(udp.payload(), &pkt, config, send_ctx);
                        }
                    }
                }
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(header) = Ipv6Packet::new(ethernet.payload()) {
                // Capture the 40-byte IPv6 fixed header and any Hop-by-Hop /
                // Destination Options / Routing (incl. SRH) / Fragment extension
                // headers for TLV Types 247/246.
                let ipv6_bytes = header.packet();
                let fixed_len = std::cmp::min(ipv6_bytes.len(), crate::tlv::IPV6_FIXED_HEADER_SIZE);
                let mut fixed_headers = vec![ipv6_bytes[..fixed_len].to_vec()];
                let (mut ext_headers, final_next, payload_offset) =
                    extract_ipv6_ext_headers(&header);
                // Descend any IP-in-IP tunnel after the outer ext-header chain.
                let (final_proto, upper) = descend_ip_tunnel(
                    final_next.0,
                    &ipv6_bytes[payload_offset.min(ipv6_bytes.len())..],
                    &mut fixed_headers,
                    &mut ext_headers,
                );

                if final_proto == IpNextHeaderProtocols::Udp.0 {
                    if let Some(udp) = UdpPacket::new(upper) {
                        if udp.get_destination() == config.local_port {
                            let traffic_class = header.get_traffic_class();
                            let captured = super::CapturedHeaders {
                                fixed_headers,
                                ipv6_ext_headers: ext_headers,
                            };
                            let pkt = PacketMeta {
                                src: SocketAddr::new(
                                    IpAddr::V6(header.get_source()),
                                    udp.get_source(),
                                ),
                                dst_addr: IpAddr::V6(header.get_destination()),
                                ttl: header.get_hop_limit(),
                                dscp: (traffic_class >> 2) & 0x3F,
                                ecn: traffic_class & 0x03,
                                captured,
                            };
                            handle_stamp_packet(udp.payload(), &pkt, config, send_ctx);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// Descends an IP-in-IP tunnel chain (draft-ietf-ippm-stamp-ext-hdr-11 §3.2
/// rule 2): while `proto` names an encapsulated IPv4 (protocol 4) or IPv6
/// (protocol 41) header inside `bytes`, capture that inner header's fixed part
/// into `fixed_headers` (outer→inner) and, for IPv6, append its extension
/// headers to `ext_headers`, then advance to the encapsulated payload. Returns
/// the first non-tunnel protocol number and the remaining upper-layer bytes
/// (e.g. the UDP datagram). Bounded by [`MAX_IP_TUNNEL_DEPTH`].
fn descend_ip_tunnel<'a>(
    mut proto: u8,
    mut bytes: &'a [u8],
    fixed_headers: &mut Vec<Vec<u8>>,
    ext_headers: &mut Vec<u8>,
) -> (u8, &'a [u8]) {
    for _ in 0..MAX_IP_TUNNEL_DEPTH {
        match proto {
            PROTO_IPV4_IN_IP => {
                let Some(inner) = Ipv4Packet::new(bytes) else {
                    break;
                };
                let inner_bytes = inner.packet();
                let flen = std::cmp::min(inner_bytes.len(), crate::tlv::IPV4_FIXED_HEADER_SIZE);
                if flen < crate::tlv::IPV4_FIXED_HEADER_SIZE {
                    break;
                }
                fixed_headers.push(inner_bytes[..flen].to_vec());
                proto = inner.get_next_level_protocol().0;
                // Advance past the full inner IPv4 header (IHL words).
                let ihl = (inner.get_header_length() as usize) * 4;
                let advance = ihl.max(crate::tlv::IPV4_FIXED_HEADER_SIZE).min(bytes.len());
                bytes = &bytes[advance..];
            }
            PROTO_IPV6_IN_IP => {
                let Some(inner) = Ipv6Packet::new(bytes) else {
                    break;
                };
                let inner_bytes = inner.packet();
                let flen = std::cmp::min(inner_bytes.len(), crate::tlv::IPV6_FIXED_HEADER_SIZE);
                if flen < crate::tlv::IPV6_FIXED_HEADER_SIZE {
                    break;
                }
                fixed_headers.push(inner_bytes[..flen].to_vec());
                let (inner_ext, inner_next, inner_off) = extract_ipv6_ext_headers(&inner);
                ext_headers.extend_from_slice(&inner_ext);
                proto = inner_next.0;
                bytes = &bytes[inner_off.min(bytes.len())..];
            }
            _ => break,
        }
    }
    (proto, bytes)
}

/// Walks the IPv6 extension-header chain after the 40-byte fixed header,
/// returning:
/// - the extension-header bytes concatenated **verbatim as on the wire**: each
///   record starts with its own Next Header octet (naming what follows), then
///   HdrExtLen, then the header body — per draft-ietf-ippm-stamp-ext-hdr-11
///   §3.1/§5.1 (the reflector's first-4-byte Requested selector matches these
///   on-wire octets);
/// - the final NextHeader protocol number (UDP if the chain leads to UDP);
/// - the byte offset into the full IPv6 packet where the upper-layer payload
///   (e.g. UDP) begins.
///
/// Recognised (and captured) headers, per RFC 8200 and §3.1's own examples
/// ("Routing Header for IPv6 including Segment Routing Header"): Hop-by-Hop (0),
/// Routing (43, incl. SRH type 4), Fragment (44), and Destination Options (60).
/// Routing/HBH/DestOpts carry the generic `[Next Header][Hdr Ext Len]` container
/// (length `(HdrExtLen + 1) * 8`); Fragment is a fixed 8-octet header whose
/// second octet is Reserved, not a length. The walk **terminates** at the
/// Authentication Header (51) and Encapsulating Security Payload (50): AH's
/// length is expressed in a different unit and ESP's contents are encrypted, so
/// neither can be reflected meaningfully — the reflector then finds no
/// length-matching candidate and correctly signals the C flag (§5.1-E). It also
/// terminates at any upper-layer protocol (e.g. UDP).
fn extract_ipv6_ext_headers(
    header: &Ipv6Packet,
) -> (Vec<u8>, pnet::packet::ip::IpNextHeaderProtocol, usize) {
    use pnet::packet::ip::IpNextHeaderProtocol;

    let (out, final_next, walked) =
        walk_ipv6_ext_header_chain(header.payload(), header.get_next_header().0);
    (
        out,
        IpNextHeaderProtocol(final_next),
        // 40-byte fixed header + walked extension-header bytes.
        40 + walked,
    )
}

const HOP_BY_HOP: u8 = 0;
const ESP: u8 = 50;
const AUTH_HEADER: u8 = 51;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DESTINATION_OPTS: u8 = 60;

/// Returns the on-wire length in octets of the extension header of type
/// `hdr_type` whose bytes begin at `rec`, or `None` if `hdr_type` is not a
/// captured extension header (upper-layer protocol, AH, ESP, …) or `rec` is too
/// short to determine the length.
fn ext_header_len(hdr_type: u8, rec: &[u8]) -> Option<usize> {
    match hdr_type {
        // Generic option/routing container: length = (Hdr Ext Len + 1) * 8.
        HOP_BY_HOP | DESTINATION_OPTS | ROUTING => {
            let hdr_ext_len = *rec.get(1)? as usize;
            Some((hdr_ext_len + 1) * 8)
        }
        // Fragment header is always exactly 8 octets (RFC 8200 §4.5); its
        // second octet is Reserved, not a length field.
        FRAGMENT => Some(8),
        // AH's length is in a different unit and ESP's payload is encrypted, so
        // neither can be reflected — the walk terminates here (§5.1-E C-flag).
        AUTH_HEADER | ESP => None,
        // Upper-layer protocol (e.g. UDP) or anything else: not an ext header.
        _ => None,
    }
}

/// Pure core of [`extract_ipv6_ext_headers`], operating on the IPv6 payload
/// bytes and the fixed header's Next Header value. Returns the captured
/// extension-header bytes (verbatim), the final Next Header value, and the
/// number of payload bytes consumed by the walked headers.
fn walk_ipv6_ext_header_chain(payload: &[u8], first_next: u8) -> (Vec<u8>, u8, usize) {
    let mut this_header_type = first_next;
    let mut offset = 0usize;
    let mut out = Vec::new();

    loop {
        let rec = &payload[offset.min(payload.len())..];
        let Some(len) = ext_header_len(this_header_type, rec) else {
            break; // Upper-layer protocol, AH, ESP, or unrecognised → stop.
        };
        // Need at least 2 bytes for the Next Header + Hdr Ext Len fields and
        // the full declared length to be present.
        if rec.len() < 2 || rec.len() < len || len == 0 {
            break;
        }
        // This header's own Next Header field (byte 0) names the FOLLOWING
        // header. Emit the header verbatim.
        let this_next = rec[0];
        out.extend_from_slice(&rec[..len]);
        this_header_type = this_next;
        offset += len;
    }

    (out, this_header_type, offset)
}

/// Sets the IP TOS (Type of Service) / IPv6 Traffic Class on a socket.
///
/// This controls the DSCP/ECN bits in outgoing packets for CoS TLV support (RFC 8972 §5.2).
#[cfg(unix)]
fn set_socket_tos(socket: &std::net::UdpSocket, tos: u8, is_ipv6: bool) -> std::io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let tos_val: libc::c_int = tos as libc::c_int;
    let (level, opt) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
    } else {
        (libc::IPPROTO_IP, libc::IP_TOS)
    };

    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &tos_val as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Sets the IP TOS (Type of Service) / IPv6 Traffic Class on a socket.
///
/// Windows implementation using Winsock2 `setsockopt`.
#[cfg(windows)]
fn set_socket_tos(socket: &std::net::UdpSocket, tos: u8, is_ipv6: bool) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    #[link(name = "ws2_32")]
    extern "system" {
        fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    }

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_TOS: i32 = 3;
    const IPV6_TCLASS: i32 = 39;

    let raw_socket = socket.as_raw_socket() as usize;
    let tos_val: i32 = tos as i32;
    let (level, opt) = if is_ipv6 {
        (IPPROTO_IPV6, IPV6_TCLASS)
    } else {
        (IPPROTO_IP, IP_TOS)
    };

    let result = unsafe {
        setsockopt(
            raw_socket,
            level,
            opt,
            &tos_val as *const i32 as *const u8,
            std::mem::size_of::<i32>() as i32,
        )
    };
    if result != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Per-packet metadata extracted from IP/UDP headers.
struct PacketMeta {
    src: SocketAddr,
    dst_addr: IpAddr,
    ttl: u8,
    dscp: u8,
    ecn: u8,
    /// Raw IP-layer bytes for draft-ietf-ippm-stamp-ext-hdr TLV reflection
    /// (Types 246/247). Captured at the datalink layer; always available
    /// when using this backend.
    captured: super::CapturedHeaders,
}

fn handle_stamp_packet(
    data: &[u8],
    pkt: &PacketMeta,
    config: &CaptureConfig,
    send_ctx: &PnetSendContext,
) {
    // Rate limit check: drop packet if source exceeds the per-client
    // token bucket. Distinct counter so operators can tell rate-limit
    // drops from parse/HMAC failures.
    if !config.rate_limiter.allow(pkt.src.ip()) {
        log::debug!("Rate-limited packet from {}", pkt.src);
        config
            .counters
            .packets_rate_limited
            .fetch_add(1, AtomicOrdering::Relaxed);
        config
            .counters
            .packets_dropped
            .fetch_add(1, AtomicOrdering::Relaxed);
        return;
    }

    config
        .counters
        .packets_received
        .fetch_add(1, AtomicOrdering::Relaxed);

    // Get session counters for Direct Measurement and Follow-Up Telemetry.
    // Always tracked per-client, independent of --stateful-reflector.
    let counter_session = config.session_manager.get_or_create_session(pkt.src);
    counter_session.record_received();

    // draft-ietf-ippm-asymmetrical-pkts-14 §5: classify the received Sequence
    // Number against this session's replay window. Detection is unconditional
    // and counted; `--drop-replayed` decides whether a duplicate is answered.
    let replay_verdict = super::evaluate_replay(&counter_session, data, &config.counters);
    if config.drop_replayed && replay_verdict == crate::session::ReplayVerdict::Replay {
        config
            .counters
            .packets_dropped
            .fetch_add(1, AtomicOrdering::Relaxed);
        return;
    }

    let reflector_rx_count = Some(counter_session.get_received_count());
    let reflector_tx_count = Some(counter_session.get_transmitted_count());
    let last_reflection = Some(counter_session.get_last_reflection());

    // Build packet address info for Location TLV.
    // dst_addr comes from the parsed IP header, so it's always the real
    // destination even when bound to a wildcard address.
    let packet_addr_info = Some(crate::tlv::PacketAddressInfo {
        src_addr: pkt.src.ip(),
        src_port: pkt.src.port(),
        dst_addr: pkt.dst_addr,
        dst_port: config.local_port,
    });

    // Panic-isolated: a panic in processing must not unwind out of the capture
    // task and stop the reflector. On panic the packet is dropped (None).
    // The keyset read guard is scoped to this block (the capture loop is
    // synchronous, but tight scoping keeps writer latency low).
    let response_opt = {
        let keys_guard = config.hmac_keys.read().unwrap_or_else(|e| e.into_inner());
        let ctx = ProcessingContext {
            clock_source: config.clock_source,
            error_estimate_wire: config.error_estimate_wire,
            hmac_key: config.hmac_key.as_ref(),
            hmac_key_set: keys_guard.as_ref(),
            require_hmac: config.require_hmac,
            session_manager: if config.stateful_reflector {
                Some(&config.session_manager)
            } else {
                None
            },
            stateful_reflector: config.stateful_reflector,
            tlv_mode: config.tlv_mode,
            verify_tlv_hmac: config.verify_tlv_hmac,
            strict_packets: config.strict_packets,
            #[cfg(feature = "metrics")]
            metrics_enabled: config.metrics_enabled,
            received_dscp: pkt.dscp,
            received_ecn: pkt.ecn,
            reflector_rx_count,
            reflector_tx_count,
            packet_addr_info,
            last_reflection,
            location_disclosure: config.location_disclosure,
            cos_policy: &config.cos_policy,
            local_addresses: &config.local_addresses,
            local_macs: &config.local_macs,
            sender_port: pkt.src.port(),
            return_path_allow_alternate: config.return_path_allow_alternate,
            reflector_member_link_id: config.reflector_member_link_id,
            captured_headers: Some(&pkt.captured),
            reflected_control_max_count: config
                .caps
                .reflected_control_max_count
                .load(AtomicOrdering::Relaxed),
            reflected_control_max_size: config
                .caps
                .reflected_control_max_size
                .load(AtomicOrdering::Relaxed),
            reflected_control_min_interval_ns: config
                .caps
                .reflected_control_min_interval_ns
                .load(AtomicOrdering::Relaxed),
            rx_timestamp: None,
            rx_method: crate::tlv::TimestampMethod::SwLocal,
            tx_method: crate::tlv::TimestampMethod::SwLocal,
        };
        process_stamp_packet_isolated(data, pkt.src, pkt.ttl, config.use_auth, &ctx)
    };
    if let Some(mut response) = response_opt {
        // The packet survived parse + HMAC verification — only now may it
        // advance the session's anti-replay window.
        super::commit_replay(&counter_session, data);

        // Handle Return Path action (RFC 9503 §5)
        let send_target = match &response.return_path_action {
            ReturnPathAction::SuppressReply => {
                log::debug!("Return Path: suppressing reply to {}", pkt.src);
                config
                    .counters
                    .packets_dropped
                    .fetch_add(1, AtomicOrdering::Relaxed);
                return;
            }
            ReturnPathAction::AlternateAddress(addr) => *addr,
            ReturnPathAction::Normal
            | ReturnPathAction::UnsupportedSr
            | ReturnPathAction::Srv6Forward(_) => pkt.src,
        };

        // The pnet/raw backend cannot insert an SRv6 Segment Routing Header, so
        // an SRv6 return path is treated as unsupported: set the Return Path
        // U-flag (RFC 8972 §4.2) and reply over the normal path. (SRv6 SRH
        // insertion is implemented only on the Linux `nix` UDP-socket backend.)
        if matches!(
            response.return_path_action,
            ReturnPathAction::Srv6Forward(_)
        ) {
            let base_size = if config.use_auth {
                AUTH_BASE_SIZE
            } else {
                UNAUTH_BASE_SIZE
            };
            if set_return_path_u_flag_in_response(&mut response.data, base_size) {
                if let Some(ref key) = config.hmac_key {
                    recompute_response_tlv_hmac(&mut response.data, base_size, key);
                }
            }
        }

        // Determine TOS value: use CoS TLV request if present, otherwise default (0).
        let (tos, has_cos_request) = match response.cos_request {
            Some((dscp, ecn)) => (((dscp & 0x3F) << 2) | (ecn & 0x03), true),
            None => (0u8, false),
        };

        let is_ipv6 = send_target.is_ipv6();

        let last_tos_cache = if is_ipv6 {
            &send_ctx.last_tos_v6
        } else {
            &send_ctx.last_tos_v4
        };

        // Only call setsockopt if TOS value changed (reduces syscall overhead under load).
        // Skip if the target socket is unavailable — try_send will fail and the
        // alternate-address fallback path handles it (sets U-flag, retries on original src).
        let tos_socket: Option<&std::net::UdpSocket> = if is_ipv6 {
            send_ctx.send_socket_v6.as_ref()
        } else {
            Some(&send_ctx.send_socket_v4)
        };
        if tos != last_tos_cache.get() {
            if let Some(socket) = tos_socket {
                match set_socket_tos(socket, tos, is_ipv6) {
                    Ok(()) => {
                        last_tos_cache.set(tos);
                    }
                    Err(e) => {
                        if has_cos_request {
                            log::debug!("Failed to set IP_TOS/IPV6_TCLASS to {}: {}", tos, e);
                            // Set RP flag in CoS TLV to indicate policy rejection (RFC 8972 §5.2)
                            let base_size = if config.use_auth {
                                AUTH_BASE_SIZE
                            } else {
                                UNAUTH_BASE_SIZE
                            };
                            if set_cos_policy_rejected(&mut response.data, base_size) {
                                // RP mutation invalidates the TLV HMAC — recompute
                                if let Some(ref key) = config.hmac_key {
                                    recompute_response_tlv_hmac(&mut response.data, base_size, key);
                                }
                            }

                            // draft-ietf-ippm-stamp-cos-ecn-01 §3.2 MUST: even
                            // though the requested DSCP1/EC1 TOS could not be
                            // applied, best-effort re-apply with the reply's
                            // ECN bits forced to 0b00 (Not-ECT) rather than
                            // leaving the previous, possibly non-zero, ECN
                            // value on the wire.
                            let fallback_tos = cos_unable_fallback_tos(pkt.dscp);
                            if should_apply_fallback_tos(tos, fallback_tos, last_tos_cache.get()) {
                                match set_socket_tos(socket, fallback_tos, is_ipv6) {
                                    Ok(()) => last_tos_cache.set(fallback_tos),
                                    Err(e2) => log::debug!(
                                        "cos-ecn-01 zero-ECN fallback TOS {} also failed: {}",
                                        fallback_tos,
                                        e2
                                    ),
                                }
                            }
                        }
                        // Don't update cache further on failure - retry next time
                    }
                }
            }
        }

        // Helper: send to the given target using the correct address-family
        // socket, pinning the reply's IP source address when a Destination Node
        // Address TLV matched one of ours (RFC 9503 §3). Pinning is best-effort
        // and Linux-only; any failure falls through to an ordinary send, which
        // is still a correct reply from the kernel's choice of source. Both
        // backends do this identically so the §3 SHOULD does not depend on
        // which one is in use.
        // Only the Unix pinning path below reads this.
        #[cfg(unix)]
        let reply_source = response.reply_source;
        let try_send = |data: &[u8], target: SocketAddr| -> Result<usize, std::io::Error> {
            let socket = match target {
                SocketAddr::V4(_) => Some(&send_ctx.send_socket_v4),
                SocketAddr::V6(_) => send_ctx.send_socket_v6.as_ref(),
            };
            let Some(socket) = socket else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "IPv6 socket unavailable",
                ));
            };
            // The whole attempt is inside one `cfg(unix)` block: on Windows
            // `reply_source::send_from` does not exist (no `std::os::fd`), so
            // there is nothing here to bind `source` for either.
            #[cfg(unix)]
            if let Some(source) = reply_source {
                if crate::reply_source::supported() {
                    use std::os::fd::AsRawFd;
                    match crate::reply_source::send_from(socket.as_raw_fd(), data, target, source) {
                        Ok(sent) => return Ok(sent),
                        Err(e) => log::debug!(
                            "could not pin reply source to {source} \
                             (RFC 9503 §3): {e}; using the OS's choice"
                        ),
                    }
                }
            }
            socket.send_to(data, target)
        };

        let sent_ok = match try_send(&response.data, send_target) {
            Ok(_) => true,
            Err(e) if send_target != pkt.src => {
                // Alternate-address send failed — set U-flag on Return Path TLV
                // and fall back to original source (RFC 9503 §5).
                log::debug!(
                    "Return Path: alternate send to {} failed ({}), falling back to {}",
                    send_target,
                    e,
                    pkt.src
                );
                let base_size = if config.use_auth {
                    AUTH_BASE_SIZE
                } else {
                    UNAUTH_BASE_SIZE
                };
                if set_return_path_u_flag_in_response(&mut response.data, base_size) {
                    if let Some(ref key) = config.hmac_key {
                        recompute_response_tlv_hmac(&mut response.data, base_size, key);
                    }
                }
                match try_send(&response.data, pkt.src) {
                    Ok(_) => true,
                    Err(e2) => {
                        log::warn!("Failed to send response to {}: {}", pkt.src, e2);
                        false
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to send response to {}: {}", send_target, e);
                false
            }
        };

        if sent_ok {
            config
                .counters
                .packets_reflected
                .fetch_add(1, AtomicOrdering::Relaxed);
            // Record transmission for Direct Measurement and Follow-Up Telemetry.
            // Always tracked per-client, independent of --stateful-reflector.
            let session = config.session_manager.get_or_create_session(pkt.src);
            session.record_transmitted();
            if response.data.len() >= 4 {
                let reflected_seq = u32::from_be_bytes([
                    response.data[0],
                    response.data[1],
                    response.data[2],
                    response.data[3],
                ]);
                let send_ts = crate::time::generate_timestamp(config.clock_source);
                session.record_reflection(reflected_seq, send_ts);
            }

            // Reflected Test Packet Control multi-send
            // (draft-ietf-ippm-asymmetrical-pkts §3). Inline blocking sleep —
            // the pnet backend runs packet capture on a dedicated blocking
            // thread, so this delays subsequent packets. Cap and clamp were
            // applied upstream in receiver::mod::apply_semantic_tlv_processing.
            if let Some(behavior) = response.reflected_control {
                if behavior.extra_copies > 0 {
                    let interval = std::time::Duration::from_nanos(behavior.interval_ns as u64);
                    for _ in 0..behavior.extra_copies {
                        std::thread::sleep(interval);
                        // Each extra send consumes one rate-limit token;
                        // bucket exhaustion breaks the loop early so a
                        // sender's asymmetric burst cannot exceed its
                        // per-client budget.
                        if !config.rate_limiter.allow(pkt.src.ip()) {
                            config
                                .counters
                                .packets_rate_limited
                                .fetch_add(1, AtomicOrdering::Relaxed);
                            config
                                .counters
                                .packets_dropped
                                .fetch_add(1, AtomicOrdering::Relaxed);
                            break;
                        }
                        match try_send(&response.data, send_target) {
                            Ok(_) => {
                                config
                                    .counters
                                    .packets_reflected
                                    .fetch_add(1, AtomicOrdering::Relaxed);
                            }
                            Err(e) => {
                                log::debug!("Reflected Control extra send failed: {}", e);
                                config
                                    .counters
                                    .packets_dropped
                                    .fetch_add(1, AtomicOrdering::Relaxed);
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            config
                .counters
                .packets_dropped
                .fetch_add(1, AtomicOrdering::Relaxed);
        }
    }
}

// `build_local_addresses` now lives in `receiver::mod` and is shared between
// backends (see [`super::build_local_addresses`]).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::create_shared_state;
    use clap::Parser;

    /// draft-ietf-ippm-stamp-ext-hdr-11 §3.1/§5.1: captured extension headers
    /// must be stored verbatim as on the wire — byte 0 is the header's OWN Next
    /// Header field (naming what follows), NOT the header's own type (which is
    /// carried in the preceding Next Header pointer). This is what the
    /// reflector's first-4-byte Requested selector matches against.
    #[test]
    fn extract_ipv6_ext_headers_stores_records_verbatim_on_wire() {
        // 40-byte IPv6 fixed header + one 8-byte Hop-by-Hop Options header.
        let mut buf = vec![0u8; 48];
        buf[0] = 0x60; // Version 6
        buf[4] = 0x00; // Payload Length hi
        buf[5] = 0x08; // Payload Length = 8 (the HBH header)
        buf[6] = 0; // Next Header = 0 (Hop-by-Hop Options) — names the HBH header
        buf[7] = 64; // Hop Limit
                     // Hop-by-Hop Options header (on the wire, at offset 40):
        buf[40] = 17; // its OWN Next Header = 17 (UDP) — names what follows
        buf[41] = 0; // HdrExtLen = 0 → (0 + 1) * 8 = 8 octets
        buf[42..48].copy_from_slice(&[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6]);

        let pkt = Ipv6Packet::new(&buf).expect("valid IPv6 packet");
        let (records, final_next, payload_offset) = extract_ipv6_ext_headers(&pkt);

        assert_eq!(
            records,
            vec![17, 0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6],
            "record byte 0 must be the header's own Next Header field (17=UDP), \
             not the header's type (0=HBH)"
        );
        assert_eq!(final_next.0, 17, "chain terminates at UDP");
        assert_eq!(payload_offset, 48, "40-byte fixed + 8-byte HBH");
    }

    /// draft-ietf-ippm-stamp-ext-hdr-11 §3.1 rule 2 / §3.1's example list:
    /// the walk must traverse and capture a Routing Header (type 43, incl. the
    /// Segment Routing Header / routing type 4) in the chain, in order, and
    /// continue to the upper layer.
    #[test]
    fn walk_captures_routing_header_including_srh() {
        // Chain: fixed(next=HBH) → HBH(8, next=Routing) → SRH(16, next=UDP).
        // SRH is a Routing Header with Routing Type 4.
        let mut payload = Vec::new();
        // HBH: next=Routing(43), HdrExtLen=0 ⇒ 8 octets.
        payload.extend_from_slice(&[43, 0, 0x01, 0x04, 0, 0, 0, 0]);
        // SRH (Routing): next=UDP(17), HdrExtLen=1 ⇒ 16 octets; routing type 4.
        payload.extend_from_slice(&[17, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (out, final_next, walked) = walk_ipv6_ext_header_chain(&payload, HOP_BY_HOP);
        assert_eq!(walked, 24, "8-byte HBH + 16-byte SRH walked");
        assert_eq!(final_next, 17, "chain terminates at UDP");
        // Two records captured verbatim, in order.
        assert_eq!(&out[..8], &payload[..8], "HBH captured first");
        assert_eq!(
            &out[8..24],
            &payload[8..24],
            "SRH captured second, in order"
        );
        assert_eq!(out[8], 17, "SRH record byte 0 is its own Next Header (UDP)");
        assert_eq!(out[10], 4, "SRH routing type 4 preserved verbatim");
    }

    /// A Fragment header (type 44) is a fixed 8 octets; its second byte is
    /// Reserved, not a Hdr Ext Len, so the walk must not treat it as a length.
    #[test]
    fn walk_captures_fragment_header_as_fixed_eight_octets() {
        // Fragment header: next=UDP(17), Reserved byte = 0xAB (must be ignored
        // for length purposes), then 6 more octets = 8 total.
        let payload = [17u8, 0xAB, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44];
        let (out, final_next, walked) = walk_ipv6_ext_header_chain(&payload, FRAGMENT);
        assert_eq!(walked, 8, "Fragment header is always 8 octets");
        assert_eq!(final_next, 17, "terminates at UDP");
        assert_eq!(out, payload.to_vec(), "captured verbatim");
    }

    /// The walk terminates at AH (51) and ESP (50): those cannot be reflected,
    /// so they are neither captured nor walked past.
    #[test]
    fn walk_terminates_at_ah_and_esp() {
        // fixed(next=AH) → nothing captured, final_next = AH.
        let ah_payload = [0u8; 16];
        let (out, final_next, walked) = walk_ipv6_ext_header_chain(&ah_payload, AUTH_HEADER);
        assert!(out.is_empty(), "AH is not captured");
        assert_eq!(final_next, AUTH_HEADER);
        assert_eq!(walked, 0);

        let (out, final_next, walked) = walk_ipv6_ext_header_chain(&ah_payload, ESP);
        assert!(out.is_empty(), "ESP is not captured");
        assert_eq!(final_next, ESP);
        assert_eq!(walked, 0);
    }

    /// `run_receiver` must return cleanly (not panic) when the configured
    /// local address is not bound to any interface, and the shared
    /// `capture_alive` flag must transition to `false` so an external
    /// readiness probe can observe the dead capture.
    ///
    /// 192.0.2.1 is in TEST-NET-1 (RFC 5737) and is not bound to any
    /// real interface under normal conditions.
    #[tokio::test]
    async fn run_receiver_clears_capture_alive_on_missing_interface() {
        let conf = Configuration::parse_from([
            "stamp-suite",
            "--remote-addr",
            "127.0.0.1",
            "--local-addr",
            "192.0.2.1",
            "--is-reflector",
        ]);
        let shared = create_shared_state(&conf);

        assert!(shared.capture_alive.load(AtomicOrdering::Relaxed));

        // run_receiver fails immediately when no interface matches, and that
        // failure must be reported (not a clean exit) so main can exit non-zero.
        let err = run_receiver(&conf, &shared)
            .await
            .expect_err("a missing capture interface is a startup failure");
        assert!(
            err.to_string().contains("No interface found"),
            "unexpected startup error: {err}"
        );

        assert!(
            !shared.capture_alive.load(AtomicOrdering::Relaxed),
            "capture_alive must clear when capture cannot start"
        );
    }
}
