//! Receiver implementation using pnet for raw packet capture with real TTL.
//!
//! Requires raw socket capabilities (root/CAP_NET_RAW on Linux).
//!
//! Uses `spawn_blocking` to run the blocking packet capture loop on a dedicated
//! thread, preventing starvation of the async runtime.

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::Ordering as AtomicOrdering,
    time::{Duration, Instant},
};

use pnet::{
    datalink::{self, Channel::Ethernet, Config, DataLinkReceiver, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        ipv6::Ipv6Packet,
        udp::UdpPacket,
        Packet,
    },
};

use std::sync::Arc;

use crate::{configuration::Configuration, shutdown::CancellationToken};

use super::{
    ingest::{ReceivedPacket, ReflectorCore, ReflectorSettings},
    print_reflector_stats,
    transmit::{DatagramSender, QueuedTransmission, ReplyBudget, ReplyQueue, ShutdownDrain},
    ReceiverSharedState, ReflectorCounters,
};

/// Context for sending STAMP responses in pnet mode.
struct PnetSendContext {
    send_socket_v4: std::net::UdpSocket,
    send_socket_v6: Option<std::net::UdpSocket>,
}

/// Everything the blocking capture loop owns.
struct CaptureConfig {
    core: ReflectorCore,
    interface_index: u32,
    queue_capacity: usize,
    shutdown_grace: Duration,
    local_port: u16,
    cleanup_interval: Option<Duration>,
    /// Child of the process shutdown token; also cancelled when the
    /// capture or transmit side stops.
    shutdown: CancellationToken,
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
    // Bind one reply socket per address family to the STAMP port.
    // Connected senders discard replies from other source ports. Raw capture
    // does not bind a receive socket, so the STAMP port is available.
    let local_addr: SocketAddr = conf.local_socket_addr();
    let send_bind_v4: SocketAddr = match conf.local_addr {
        std::net::IpAddr::V4(v4) => (v4, conf.local_port).into(),
        // Captured IPv4 traffic still needs an IPv4 reply socket when the
        // reflector was pointed at an IPv6 (or wildcard) address.
        std::net::IpAddr::V6(_) => (std::net::Ipv4Addr::UNSPECIFIED, conf.local_port).into(),
    };
    let send_socket_v4 = match std::net::UdpSocket::bind(send_bind_v4) {
        Ok(s) => s,
        Err(e) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::io(
                format!("Cannot bind to address {send_bind_v4} (IPv4 send socket)"),
                e,
            ));
        }
    };
    let send_bind_v6: SocketAddr = match conf.local_addr {
        std::net::IpAddr::V6(_) => conf.local_socket_addr(),
        std::net::IpAddr::V4(_) => (std::net::Ipv6Addr::UNSPECIFIED, conf.local_port).into(),
    };
    // Optional: IPv6 may be unavailable, or the port may already be taken by
    // the v4 socket above on a dual-stack bind. Losing it only costs IPv6
    // replies, which the v4 path cannot serve anyway.
    let send_socket_v6 = std::net::UdpSocket::bind(send_bind_v6).ok();
    for socket in std::iter::once(&send_socket_v4).chain(send_socket_v6.iter()) {
        crate::net_policy::set_hops(socket)
            .map_err(|e| crate::StartupError::io("Cannot set reply TTL/Hop Limit 255", e))?;
        if let Some(name) = conf.interface.as_deref() {
            crate::net_policy::bind_to_interface(socket, name).map_err(|e| {
                crate::StartupError::io(format!("Cannot bind to interface {name}"), e)
            })?;
        }
        socket
            .set_nonblocking(true)
            .map_err(|e| crate::StartupError::io("Cannot make reply socket nonblocking", e))?;
    }

    // Key and policy errors are reported before capture-driver discovery.
    let settings = match ReflectorSettings::from_config(conf, shared, false) {
        Ok(settings) => settings,
        Err(e) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(e);
        }
    };

    // Interface discovery can itself depend on capture-driver availability.
    // Report ordinary socket and key failures before consulting that driver.
    // `--interface` selects the capture interface by name; the local
    // address, unless it is a wildcard, must still be one of its addresses.
    let interface_ip_match = |iface: &NetworkInterface| {
        let has_addr = (conf.interface.is_some() && conf.local_addr.is_unspecified())
            || iface.ips.iter().any(|ip| ip.ip() == conf.local_addr);
        conf.interface
            .as_deref()
            .is_none_or(|name| iface.name == name)
            && (conf.local_scope_id == 0 || iface.index == conf.local_scope_id)
            && has_addr
    };

    // Find the network interface with the provided local IP address
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_ip_match);

    let interface = match interface {
        Some(iface) => iface,
        None => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::config(
                match conf.interface.as_deref() {
                    Some(name) => {
                        format!("No interface {name} with IP address {}", conf.local_addr)
                    }
                    None => format!("No interface found with IP address {}", conf.local_addr),
                },
            ));
        }
    };

    // Extract interface properties for macOS special handling (NetworkInterface is not Send)
    let iface_props = InterfaceProps {
        is_up: interface.is_up(),
        is_broadcast: interface.is_broadcast(),
        is_loopback: interface.is_loopback(),
        is_point_to_point: interface.is_point_to_point(),
    };

    // Validate keys and bind ordinary sockets before opening privileged capture.
    // Bound shutdown polling independently of session expiry, including timeout=0.
    let read_timeout = Some(Duration::from_millis(100));
    let config = Config {
        read_timeout,
        #[cfg(target_os = "linux")]
        socket_fd: incoming_only_capture_socket(),
        ..Default::default()
    };

    // Create a channel to receive on
    let (_, rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::config(format!(
                "Unhandled channel type for interface {}",
                interface.name
            )));
        }
        Err(e) => {
            shared.capture_alive.store(false, AtomicOrdering::Relaxed);
            return Err(crate::StartupError::io(
                format!("Unable to create capture channel on {}", interface.name),
                e,
            ));
        }
    };

    let session_manager = Arc::clone(&shared.session_manager);

    let send_ctx = PnetSendContext {
        send_socket_v4,
        send_socket_v6,
    };

    log::info!(
        "STAMP Reflector listening on {} (pnet mode, real TTL)",
        local_addr
    );

    // Session cleanup interval: run at half the timeout period, minimum 1 second
    // When session_timeout is 0, checked_div returns None, disabling cleanup
    let cleanup_interval = conf
        .session_timeout
        .checked_div(2)
        .map(|t| Duration::from_secs(t.max(1)));

    let shutdown = shared.shutdown.child_token();
    let counters = Arc::clone(&shared.counters);
    let start_time = shared.start_time;
    let output_format = conf.output_format;

    let capture_config = CaptureConfig {
        core: ReflectorCore::new(settings, shared, conf.reflector_queue_capacity as usize),
        interface_index: interface.index,
        queue_capacity: conf.reflector_queue_capacity as usize,
        shutdown_grace: Duration::from_millis(u64::from(conf.reflector_shutdown_grace_ms)),
        local_port: conf.local_port,
        cleanup_interval,
        shutdown: shutdown.clone(),
    };

    // Dropping this future (an aborted task) also stops capture and sending.
    let _stop_on_drop = shutdown.drop_guard();

    // Spawn the blocking packet capture loop on a dedicated thread.
    // This prevents starvation of the async runtime which may be running
    // other tasks like the metrics HTTP server.
    let capture_alive_for_loop = Arc::clone(&shared.capture_alive);
    let result = tokio::task::spawn_blocking(move || {
        run_capture_loop(rx, capture_config, send_ctx, iface_props);
    })
    .await;

    // Report capture-task panics and clear readiness so monitors can detect
    // capture failure.
    if let Err(e) = result {
        log::error!("Capture thread terminated abnormally: {}", e);
        capture_alive_for_loop.store(false, AtomicOrdering::Relaxed);
    }

    // Print reflector stats on shutdown
    print_reflector_stats(&counters, &session_manager, start_time, output_format);
    // Reaching here is a normal shutdown (ctrl-c or the control plane), not a
    // startup failure — those return Err above and make main exit non-zero.
    Ok(())
}

struct TransmitWorker {
    handle: Option<std::thread::JoinHandle<()>>,
    shutdown: CancellationToken,
}
impl TransmitWorker {
    fn join(&mut self) {
        if self
            .handle
            .take()
            .is_some_and(|worker| worker.join().is_err())
        {
            log::error!("reflector transmission worker panicked");
        }
    }
}
impl Drop for TransmitWorker {
    fn drop(&mut self) {
        self.shutdown.cancel();
        self.join();
    }
}

/// The blocking packet capture loop, run on a dedicated thread.
fn run_capture_loop(
    mut rx: Box<dyn DataLinkReceiver>,
    config: CaptureConfig,
    send_ctx: PnetSendContext,
    iface_props: InterfaceProps,
) {
    let (transmitter, receiver) = std::sync::mpsc::sync_channel(config.queue_capacity);
    let tx_counters = Arc::clone(&config.core.counters);
    let tx_limiter = Arc::clone(&config.core.rate_limiter);
    let tx_shutdown = config.shutdown.clone();
    let tx_budget = Arc::clone(&config.core.budget);
    let grace = config.shutdown_grace;
    let worker = std::thread::spawn(move || {
        // A transmit worker that exits for any reason also stops capture.
        let _stop = tx_shutdown.clone().drop_guard();
        run_transmit_loop(
            receiver,
            send_ctx,
            &tx_counters,
            &tx_limiter,
            &tx_shutdown,
            &tx_budget,
            grace,
        )
    });
    let mut worker = TransmitWorker {
        handle: Some(worker),
        shutdown: config.shutdown.clone(),
    };
    let mut last_cleanup = Instant::now();

    loop {
        if config.shutdown.is_cancelled() {
            break;
        }

        // Periodic session cleanup check
        if let Some(interval) = config.cleanup_interval {
            if last_cleanup.elapsed() >= interval {
                let removed = config.core.session_manager.cleanup_stale_sessions();
                if removed > 0 {
                    log::debug!("Session cleanup: removed {} stale sessions", removed);
                }
                last_cleanup = Instant::now();
            }
        }

        match rx.next() {
            Ok(packet) => {
                // Loopback and point-to-point interfaces on Apple platforms
                // deliver IP packets without an Ethernet header.
                if cfg!(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos"
                )) && iface_props.is_up
                    && !iface_props.is_broadcast
                    && (iface_props.is_loopback || iface_props.is_point_to_point)
                {
                    let payload_offset = if iface_props.is_loopback { 14 } else { 0 };
                    if let Some(ip) = packet.get(payload_offset..).filter(|ip| !ip.is_empty()) {
                        let version = ip[0] >> 4;
                        if version == 4 || version == 6 {
                            handle_ip_packet(ip, version, None, &config, &transmitter);
                            continue;
                        }
                    }
                }
                let Some(ethernet) = EthernetPacket::new(packet) else {
                    continue; // Malformed frame, skip
                };
                handle_packet(&ethernet, &config, &transmitter);
            }
            Err(e) => {
                // Timeout errors are expected when read_timeout is set - just continue to run cleanup
                if e.kind() != std::io::ErrorKind::TimedOut
                    && e.kind() != std::io::ErrorKind::WouldBlock
                {
                    crate::warn_throttled!("Capture receive failed: {}", e);
                }
            }
        }
    }
    drop(transmitter);
    worker.join();
}

/// Opens the AF_PACKET socket for capture with outgoing frames ignored.
///
/// Linux shows a loopback datagram to packet sockets twice, once leaving and
/// once arriving, so without this a request sent over `lo` is reflected
/// twice. `PACKET_IGNORE_OUTGOING` needs Linux 4.20; on older kernels the
/// duplicate remains. Returns `None` if the socket cannot be created, letting
/// pnet open its own and report the error. pnet takes ownership of the fd.
#[cfg(target_os = "linux")]
fn incoming_only_capture_socket() -> Option<i32> {
    use nix::libc;
    let protocol = i32::from((libc::ETH_P_ALL as u16).to_be());
    // SAFETY: socket(2) with constant arguments; the result is checked.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        return None;
    }
    let one: libc::c_int = 1;
    // SAFETY: `fd` is a valid socket and `one` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_IGNORE_OUTGOING,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc < 0 {
        log::warn!(
            "PACKET_IGNORE_OUTGOING unavailable ({}); loopback requests may be reflected twice",
            std::io::Error::last_os_error()
        );
    }
    Some(fd)
}

/// IP protocol numbers for the two IP-in-IP tunnel encapsulations.
const PROTO_IPV4_IN_IP: u8 = 4;
const PROTO_IPV6_IN_IP: u8 = 41;
/// Cap on IP-in-IP nesting we descend, to bound work on adversarial packets.
const MAX_IP_TUNNEL_DEPTH: usize = 4;

fn handle_packet(
    ethernet: &EthernetPacket,
    config: &CaptureConfig,
    transmitter: &std::sync::mpsc::SyncSender<QueuedTransmission>,
) {
    let version = match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => 4,
        EtherTypes::Ipv6 => 6,
        _ => return,
    };
    let src_mac = ethernet.get_source().octets();
    handle_ip_packet(
        ethernet.payload(),
        version,
        Some(src_mac),
        config,
        transmitter,
    );
}

fn handle_ip_packet(
    ip: &[u8],
    version: u8,
    src_mac: Option<[u8; 6]>,
    config: &CaptureConfig,
    transmitter: &std::sync::mpsc::SyncSender<QueuedTransmission>,
) {
    let Some((udp, mut pkt)) = checked_udp(ip, version) else {
        return;
    };
    if udp.get_destination() != config.local_port {
        return;
    }
    pkt.src =
        crate::net_scope::received_endpoint(pkt.src.ip(), udp.get_source(), config.interface_index);
    pkt.src_mac = src_mac;
    handle_stamp_packet(udp.payload(), &pkt, config, transmitter);
}

/// Validate IP framing and the innermost UDP checksum before STAMP admission.
/// Capture sockets bypass kernel UDP validation. Zero checksums are deliberately
/// unsupported in both families; no checksum-offload bypass is inferred here.
fn checked_udp(mut bytes: &[u8], mut version: u8) -> Option<(UdpPacket<'_>, PacketMeta)> {
    let mut captured = super::CapturedHeaders {
        fixed_headers: Vec::new(),
        ipv6_ext_headers: Vec::new(),
    };
    for _ in 0..=MAX_IP_TUNNEL_DEPTH {
        let (src, dst, ttl, tos, proto, offset, end) = if version == 4 {
            let ip = Ipv4Packet::new(bytes)?;
            let ihl = usize::from(ip.get_header_length()) * 4;
            let end = usize::from(ip.get_total_length());
            if ip.get_version() != 4
                || ihl < 20
                || end < ihl
                || end > bytes.len()
                || ip.get_fragment_offset() != 0
                || ip.get_flags() & 1 != 0
                || pnet::packet::ipv4::checksum(&ip) != ip.get_checksum()
            {
                return None;
            }
            captured.fixed_headers.push(bytes[..ihl].to_vec());
            (
                IpAddr::V4(ip.get_source()),
                IpAddr::V4(ip.get_destination()),
                ip.get_ttl(),
                crate::tos::Tos::new(ip.get_dscp(), ip.get_ecn()).0,
                ip.get_next_level_protocol().0,
                ihl,
                end,
            )
        } else {
            let ip = Ipv6Packet::new(bytes)?;
            let end = 40 + usize::from(ip.get_payload_length());
            if ip.get_version() != 6 || end > bytes.len() || end == 40 {
                return None;
            }
            let ip = Ipv6Packet::new(&bytes[..end])?;
            captured.fixed_headers.push(bytes[..40].to_vec());
            let (ext, next, offset) = extract_ipv6_ext_headers(&ip);
            if offset > end {
                return None;
            }
            captured.ipv6_ext_headers.extend_from_slice(&ext);
            (
                IpAddr::V6(ip.get_source()),
                IpAddr::V6(ip.get_destination()),
                ip.get_hop_limit(),
                ip.get_traffic_class(),
                next.0,
                offset,
                end,
            )
        };
        let upper = bytes.get(offset..end)?;
        if proto == IpNextHeaderProtocols::Udp.0 {
            let udp = UdpPacket::new(upper)?;
            let len = usize::from(udp.get_length());
            if len < 8 || len != upper.len() || udp.get_checksum() == 0 {
                return None;
            }
            let checksum = match (src, dst) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => {
                    pnet::packet::udp::ipv4_checksum(&udp, &src, &dst)
                }
                (IpAddr::V6(src), IpAddr::V6(dst)) => {
                    pnet::packet::udp::ipv6_checksum(&udp, &src, &dst)
                }
                _ => return None,
            };
            let checksum = if checksum == 0 { u16::MAX } else { checksum };
            if checksum != udp.get_checksum() {
                static WARNED: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !WARNED.swap(true, AtomicOrdering::Relaxed) {
                    crate::warn_throttled!("Raw capture UDP checksum validation failed; corrupt and checksum-offload partial frames are rejected. Use a capture point with completed wire checksums.");
                }
                return None;
            }
            let pkt = PacketMeta {
                src: SocketAddr::new(src, udp.get_source()),
                dst_addr: dst,
                ttl,
                dscp: crate::tos::Tos(tos).dscp(),
                ecn: crate::tos::Tos(tos).ecn(),
                captured,
                src_mac: None,
            };
            return Some((udp, pkt));
        }
        version = match proto {
            PROTO_IPV4_IN_IP => 4,
            PROTO_IPV6_IN_IP => 6,
            _ => return None,
        };
        bytes = upper;
    }
    None
}

/// Walks IPv6 extension headers after the 40-byte fixed header.
/// Returns concatenated wire bytes, the final Next Header protocol, and the
/// upper-layer payload offset (draft-ietf-ippm-stamp-ext-hdr-15 §3.1/§4.1).
///
/// Captures Hop-by-Hop (0), Routing (43, including SRH), Fragment (44), and
/// Destination Options (60). HBH/Routing/DestOpts lengths are `(HdrExtLen + 1) * 8`;
/// Fragment is always eight bytes. Each record retains its own Next Header byte.
/// Stops at AH (51), ESP (50), or an upper-layer protocol; AH has a different
/// length encoding and ESP is encrypted.
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
        if this_header_type == 44 && (rec[2] != 0 || rec[3] & 0xf9 != 0) {
            break; // No reassembly at the capture layer; only atomic fragments proceed.
        }
        let this_next = rec[0];
        out.extend_from_slice(&rec[..len]);
        this_header_type = this_next;
        offset += len;
    }

    (out, this_header_type, offset)
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
    /// Source MAC of the Ethernet frame; `None` without an Ethernet header.
    src_mac: Option<[u8; 6]>,
}

fn handle_stamp_packet(
    data: &[u8],
    pkt: &PacketMeta,
    config: &CaptureConfig,
    transmitter: &std::sync::mpsc::SyncSender<QueuedTransmission>,
) {
    if config.shutdown.is_cancelled() {
        return;
    }
    let packet = ReceivedPacket {
        data,
        src: pkt.src,
        dst_addr: pkt.dst_addr,
        local: crate::net_scope::received_endpoint(
            pkt.dst_addr,
            config.local_port,
            config.interface_index,
        ),
        ttl: pkt.ttl,
        dscp: pkt.dscp,
        ecn: pkt.ecn,
        // Capture runs on one interface; only Linux can pin replies to it.
        ingress_ifindex: (cfg!(target_os = "linux") && config.interface_index != 0)
            .then_some(config.interface_index),
        src_mac: pkt.src_mac,
        captured_headers: Some(&pkt.captured),
        rx_timestamp: None,
        rx_method: crate::tlv::TimestampMethod::SwLocal,
    };
    if let Some(transmission) = config.core.ingest(&packet) {
        // The shared reservation also bounds the handoff channel. Never block
        // capture; a closed/full handoff drops and accounts for the owned work.
        let _ = transmitter.try_send(transmission);
    }
}

/// Own both sending sockets and interleave burst deadlines with new requests.
fn run_transmit_loop(
    receiver: std::sync::mpsc::Receiver<QueuedTransmission>,
    sockets: PnetSendContext,
    counters: &ReflectorCounters,
    limiter: &super::RateLimiter,
    shutdown: &CancellationToken,
    budget: &Arc<ReplyBudget>,
    grace: Duration,
) {
    let mut mtu_cache = super::mtu::MtuCache::default();
    run_transmit_loop_with_mtu(
        receiver,
        sockets,
        counters,
        limiter,
        shutdown,
        budget,
        grace,
        |local, target, options, refresh| mtu_cache.payload_cap(local, target, options, refresh),
    );
}

// Keep scheduler tests independent of platform route discovery while retaining
// the same queue, sockets, transmit policy and shutdown path as production.
#[allow(clippy::too_many_arguments)]
fn run_transmit_loop_with_mtu(
    receiver: std::sync::mpsc::Receiver<QueuedTransmission>,
    sockets: PnetSendContext,
    counters: &ReflectorCounters,
    limiter: &super::RateLimiter,
    shutdown: &CancellationToken,
    budget: &Arc<ReplyBudget>,
    grace: Duration,
    mut payload_cap: impl FnMut(
        std::net::SocketAddr,
        std::net::SocketAddr,
        &super::transmit::SendOptions,
        bool,
    ) -> std::io::Result<usize>,
) {
    let local_v4 = sockets.send_socket_v4.local_addr().ok();
    let local_v6 = sockets
        .send_socket_v6
        .as_ref()
        .and_then(|s| s.local_addr().ok());
    let mut sender_v4 = DatagramSender::new(&sockets.send_socket_v4);
    let mut sender_v6 = sockets.send_socket_v6.as_ref().map(DatagramSender::new);
    let mut replies = ReplyQueue::default();
    let mut drain = ShutdownDrain::default();
    let mut disconnected = false;
    loop {
        if shutdown.is_cancelled() || disconnected {
            drain.begin(Instant::now(), grace);
        }
        if drain.finished(Instant::now(), budget.is_empty()) {
            break;
        }
        // Admit at most one handoff each iteration so due bursts cannot starve
        // already reserved requests, even with sub-millisecond intervals.
        if !disconnected {
            match receiver.try_recv() {
                Ok(work) => replies.push_at(work, Instant::now()),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    disconnected = true;
                    continue;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(mut queued) = replies.pop_due() {
            let transmission = &mut queued.transmission;
            transmission.send_next_with_mtu(
                counters,
                limiter,
                |target, options, refresh| {
                    let local = if target.is_ipv4() { local_v4 } else { local_v6 };
                    let local = local.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::AddrNotAvailable,
                            "reply socket unavailable",
                        )
                    })?;
                    payload_cap(local, target, options, refresh)
                },
                |data, target, options| {
                    let sender = if target.is_ipv4() {
                        Some(&mut sender_v4)
                    } else {
                        sender_v6.as_mut()
                    };
                    sender
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::AddrNotAvailable,
                                "IPv6 socket unavailable",
                            )
                        })?
                        .send(data, target, options)
                },
            );
            replies.schedule_next(queued);
            continue;
        }
        let wait = replies.deadline().map_or(Duration::from_millis(250), |at| {
            at.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250))
        });
        let wait = drain.deadline().map_or(wait, |at| {
            wait.min(at.saturating_duration_since(Instant::now()))
        });
        if disconnected {
            std::thread::sleep(wait);
            continue;
        }
        match receiver.recv_timeout(wait) {
            Ok(transmission) => replies.push_at(transmission, Instant::now()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => disconnected = true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver::transmit::Transmission;
    use crate::{clock_format::ClockFormat, receiver::create_shared_state};

    #[test]
    fn transmit_worker_shutdown_finishes_or_cancels_reserved_bursts() {
        for (grace, interval, expected) in [
            (0, 1_000_000_000, 1),
            (80, 1_000_000_000, 1),
            (500, 80_000_000, 3),
        ] {
            let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let sockets = PnetSendContext {
                send_socket_v4: std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                send_socket_v6: None,
            };
            let counters = Arc::new(ReflectorCounters::new());
            let budget = ReplyBudget::new(1, Arc::clone(&counters));
            let shutdown = CancellationToken::new();
            let session = Arc::new(crate::session::Session::new(0));
            let response = super::super::StampResponse {
                data: vec![0; 44],
                cos_request: None,
                reply_source: None,
                tlv_hmac_generated: false,
                return_path_action: crate::tlv::ReturnPathAction::Normal,
                reflected_control: Some(super::super::ReflectedControlBehavior {
                    max_size: 1500,
                    extra_copies: 2,
                    interval_ns: interval,
                    suppress_reply_ext_headers: false,
                }),
            };
            let transmission = Transmission::new(
                response,
                Arc::clone(&session),
                peer.local_addr().unwrap(),
                ClockFormat::NTP,
                false,
                true,
                None,
                0,
                false,
            );
            let (sender, receiver) = std::sync::mpsc::sync_channel(1);
            assert!(sender
                .send(budget.reserve().unwrap().attach(transmission))
                .is_ok());
            let (done_sender, done_receiver) = std::sync::mpsc::channel();
            let worker_counters = Arc::clone(&counters);
            let worker_budget = Arc::clone(&budget);
            let worker_shutdown = shutdown.clone();
            let worker = std::thread::spawn(move || {
                run_transmit_loop_with_mtu(
                    receiver,
                    sockets,
                    &worker_counters,
                    &super::super::RateLimiter::new(0),
                    &worker_shutdown,
                    &worker_budget,
                    Duration::from_millis(grace),
                    |_, _, _, _| Ok(1472),
                );
                done_sender.send(()).unwrap();
            });
            peer.recv_from(&mut [0; 128]).unwrap();
            shutdown.cancel();
            drop(sender); // Wake the worker without waiting for its periodic poll.
            assert!(done_receiver.recv_timeout(Duration::from_secs(2)).is_ok());
            worker.join().unwrap();
            assert_eq!(session.get_transmitted_count(), expected);
            assert_eq!(
                counters
                    .queued_replies_cancelled
                    .load(AtomicOrdering::Relaxed),
                u64::from(3 - expected)
            );
            assert!(budget.is_empty());
        }
    }

    #[test]
    fn transmit_worker_interleaves_requests_and_burst_deadlines() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let sockets = PnetSendContext {
            send_socket_v4: std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            send_socket_v6: None,
        };
        let counters = Arc::new(ReflectorCounters::new());
        let session = Arc::new(crate::session::Session::new(0));
        let shutdown = CancellationToken::new();
        let budget = ReplyBudget::new(4, Arc::clone(&counters));
        let worker_budget = Arc::clone(&budget);
        let (sender, receiver) = std::sync::mpsc::sync_channel(4);
        let worker_counters = Arc::clone(&counters);
        let worker_shutdown = shutdown.clone();
        let worker = std::thread::spawn(move || {
            run_transmit_loop_with_mtu(
                receiver,
                sockets,
                &worker_counters,
                &super::super::RateLimiter::new(0),
                &worker_shutdown,
                &worker_budget,
                Duration::ZERO,
                |_, _, _, _| Ok(1472),
            )
        });
        let make = |seq: u32, extra| {
            let mut data = vec![0; 44];
            data[..4].copy_from_slice(&seq.to_be_bytes());
            data[24..28].copy_from_slice(&seq.to_be_bytes());
            data[13] = 1;
            let response = super::super::StampResponse {
                data,
                cos_request: None,
                reply_source: None,
                tlv_hmac_generated: false,
                return_path_action: crate::tlv::ReturnPathAction::Normal,
                reflected_control: Some(super::super::ReflectedControlBehavior {
                    max_size: 1500,
                    extra_copies: extra,
                    interval_ns: 120_000_000,
                    suppress_reply_ext_headers: false,
                }),
            };
            Transmission::new(
                response,
                Arc::clone(&session),
                peer.local_addr().unwrap(),
                ClockFormat::NTP,
                false,
                true,
                None,
                0,
                false,
            )
        };
        assert!(sender
            .send(budget.reserve().unwrap().attach(make(7, 2)))
            .is_ok());
        let mut data = [0; 256];
        peer.recv_from(&mut data).unwrap();
        assert_eq!(u32::from_be_bytes(data[..4].try_into().unwrap()), 0);
        assert!(sender
            .send(budget.reserve().unwrap().attach(make(8, 0)))
            .is_ok());
        for (sequence, request) in [(1u32, 8u32), (2, 7), (3, 7)] {
            let previous = data[4..12].to_vec();
            peer.recv_from(&mut data).unwrap();
            assert_eq!(u32::from_be_bytes(data[..4].try_into().unwrap()), sequence);
            assert_eq!(
                u32::from_be_bytes(data[24..28].try_into().unwrap()),
                request
            );
            assert!(data[4..12] > previous[..]);
        }
        drop(sender);
        worker.join().unwrap();
        assert_eq!(session.get_transmitted_count(), 4);
        assert_eq!(session.get_last_reflection().0, 3);
        assert_eq!(counters.packets_reflected.load(AtomicOrdering::Relaxed), 4);
    }
    #[test]
    fn transmit_worker_drops_unknown_mtu_burst_and_keeps_serving() {
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let sockets = PnetSendContext {
            send_socket_v4: std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            send_socket_v6: None,
        };
        let counters = Arc::new(ReflectorCounters::new());
        let budget = ReplyBudget::new(2, Arc::clone(&counters));
        let session = Arc::new(crate::session::Session::new(0));
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        for controlled in [true, false] {
            let mut data = vec![0; 44];
            data[24..28].copy_from_slice(&u32::from(controlled).to_be_bytes());
            let response = super::super::StampResponse {
                data,
                cos_request: None,
                reply_source: None,
                tlv_hmac_generated: false,
                return_path_action: crate::tlv::ReturnPathAction::Normal,
                reflected_control: controlled.then_some(super::super::ReflectedControlBehavior {
                    max_size: 1500,
                    extra_copies: 2,
                    interval_ns: 0,
                    suppress_reply_ext_headers: false,
                }),
            };
            let transmission = Transmission::new(
                response,
                Arc::clone(&session),
                peer.local_addr().unwrap(),
                ClockFormat::NTP,
                false,
                true,
                None,
                0,
                false,
            );
            assert!(sender
                .send(budget.reserve().unwrap().attach(transmission))
                .is_ok());
        }
        drop(sender);
        let mut lookups = 0;
        let mut mtu_cache = super::super::mtu::MtuCache::default();
        run_transmit_loop_with_mtu(
            receiver,
            sockets,
            &counters,
            &super::super::RateLimiter::new(0),
            &CancellationToken::new(),
            &budget,
            Duration::from_secs(1),
            |local, target, options, refresh| {
                lookups += 1;
                if cfg!(target_os = "linux") {
                    // Exercise the same failure on Linux, where discovery works.
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "fixture: no route MTU",
                    ))
                } else {
                    // Verify the real unsupported route lookup on Windows/macOS.
                    mtu_cache.payload_cap(local, target, options, refresh)
                }
            },
        );
        let mut data = [0; 128];
        let (len, _) = peer.recv_from(&mut data).unwrap();
        assert_eq!(len, 44);
        assert_eq!(&data[24..28], &0u32.to_be_bytes());
        let error = peer.recv_from(&mut data).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
        assert_eq!(lookups, 1);
        assert_eq!(session.get_transmitted_count(), 1);
        assert_eq!(counters.packets_reflected.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(counters.packets_dropped.load(AtomicOrdering::Relaxed), 1);
        assert_eq!(
            counters
                .queued_replies_cancelled
                .load(AtomicOrdering::Relaxed),
            0
        );
        assert!(budget.is_empty());
    }

    use clap::Parser;

    /// draft-ietf-ippm-stamp-ext-hdr-15 §4.2/§4.1: captured extension headers
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

    /// draft-ietf-ippm-stamp-ext-hdr-15 §4.2 rule 2 / §4.2's example list:
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
    fn walk_captures_atomic_fragment_header_as_fixed_eight_octets() {
        // Fragment header: next=UDP(17), Reserved byte = 0xAB (must be ignored
        // for length purposes), then 6 more octets = 8 total.
        let payload = [17u8, 0xAB, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44];
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
    /// Bind an ephemeral wildcard socket so socket setup succeeds before
    /// discovery rejects the address, which is not assigned to an interface.
    #[tokio::test]
    async fn run_receiver_clears_capture_alive_on_missing_interface() {
        let mut conf = Configuration::parse_from([
            "stamp-suite",
            "--remote-addr",
            "127.0.0.1",
            "--local-addr",
            "0.0.0.0",
            "--is-reflector",
        ]);
        // This library-level failure fixture does not need a fixed STAMP port.
        conf.local_port = 0;
        let shared = create_shared_state(&conf).unwrap();

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

#[cfg(test)]
mod revision13_tests {
    use super::*;
    // Independent Internet checksum oracle for raw fixture bytes.
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += u32::from(pair[0]) * 256 + u32::from(*pair.get(1).unwrap_or(&0));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    fn packet(v6: bool) -> Vec<u8> {
        let mut udp = vec![0xc0, 1, 3, 94, 0, 12, 0, 0, 1, 2, 3, 4];
        let mut ip = if v6 {
            let mut ip = vec![0; 40];
            ip[0] = 0x60;
            ip[5] = 12;
            ip[6] = 17;
            ip[7] = 254;
            ip[23] = 1;
            ip[39] = 2;
            ip
        } else {
            vec![
                0x45, 0, 0, 32, 0, 0, 0, 0, 254, 17, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2,
            ]
        };
        let mut pseudo = if v6 {
            ip[8..40].to_vec()
        } else {
            ip[12..20].to_vec()
        };
        if v6 {
            pseudo.extend_from_slice(&[0, 0, 0, 12, 0, 0, 0, 17]);
        } else {
            pseudo.extend_from_slice(&[0, 17, 0, 12]);
        }
        pseudo.extend_from_slice(&udp);
        let sum = checksum(&pseudo);
        udp[6..8].copy_from_slice(&sum.to_be_bytes());
        if !v6 {
            let sum = checksum(&ip);
            ip[10..12].copy_from_slice(&sum.to_be_bytes());
        }
        ip.extend(udp);
        ip
    }
    #[test]
    fn capture_validates_checksums_lengths_addresses_and_fragments() {
        for v6 in [false, true] {
            let version = if v6 { 6 } else { 4 };
            let offset = if v6 { 40 } else { 20 };
            let bytes = packet(v6);
            let (_, meta) = checked_udp(&bytes, version).unwrap();
            assert_eq!(meta.ttl, 254); // Lower received hop counts are admitted.
            for index in [offset + 6, offset + 8, if v6 { 23 } else { 12 }] {
                let mut corrupt = bytes.clone();
                corrupt[index] ^= 1;
                assert!(checked_udp(&corrupt, version).is_none());
            }
            let mut zero = bytes.clone();
            zero[offset + 6..offset + 8].fill(0);
            assert!(checked_udp(&zero, version).is_none());
            assert!(checked_udp(&bytes[..bytes.len() - 1], version).is_none());
            let mut fragment = bytes.clone();
            if v6 {
                fragment[6] = 44;
                fragment[5] += 8;
                fragment.splice(40..40, [17, 0, 0, 1, 0, 0, 0, 1]);
            } else {
                fragment[6] = 0x20;
                fragment[10..12].fill(0);
                let sum = checksum(&fragment[..20]);
                fragment[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            assert!(checked_udp(&fragment, version).is_none());
        }
    }
    #[test]
    fn tunnel_udp_uses_innermost_addresses_for_checksum_and_session_identity() {
        let inner = packet(true);
        let mut outer = packet(false)[..20].to_vec();
        outer[9] = 41;
        let len = (20 + inner.len()) as u16;
        outer[2..4].copy_from_slice(&len.to_be_bytes());
        outer[10..12].fill(0);
        let sum = checksum(&outer);
        outer[10..12].copy_from_slice(&sum.to_be_bytes());
        outer.extend(inner);
        let (_, meta) = checked_udp(&outer, 4).unwrap();
        assert_eq!(meta.src.ip(), "::1".parse::<IpAddr>().unwrap());
        assert_eq!(meta.dst_addr, "::2".parse::<IpAddr>().unwrap());
        assert_eq!(meta.captured.fixed_headers.len(), 2);
    }
}
