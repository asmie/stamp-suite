//! Startup settings and the per-packet ingest path shared by both backends.
//!
//! A backend owns its socket or capture handle and extracts a
//! [`ReceivedPacket`] from each datagram. Everything after that, from rate
//! limiting to the queued [`Transmission`], happens here, so the backends
//! cannot drift apart.

use super::*;
use crate::{
    configuration::is_auth, cos_policy::CosAdmissionPolicy, error_estimate::ErrorEstimate,
};
use transmit::{QueuedTransmission, ReplyBudget, Transmission};

/// Reflector settings resolved once from the configuration.
///
/// Policies that fail to parse stop startup here rather than falling back to
/// permissive defaults.
pub(crate) struct ReflectorSettings {
    pub use_auth: bool,
    pub clock_source: ClockFormat,
    pub clock_sync_source: SyncSource,
    pub hardware_clock_sync_source: SyncSource,
    pub error_estimate_wire: u16,
    /// Single key from `--hmac-key`/`--hmac-key-file`, used only when no
    /// per-SSID keyset is configured.
    pub hmac_key: Option<HmacKey>,
    pub require_hmac: bool,
    pub stateful_reflector: bool,
    pub tlv_mode: TlvHandlingMode,
    pub verify_tlv_hmac: bool,
    pub strict_packets: bool,
    #[cfg(feature = "metrics")]
    pub metrics_enabled: bool,
    pub drop_replayed: bool,
    pub location_disclosure: LocationDisclosure,
    pub cos_policy: CosAdmissionPolicy,
    pub local_addresses: Vec<std::net::IpAddr>,
    pub local_macs: Vec<[u8; 6]>,
    pub return_path_allow_alternate: bool,
    pub reflector_member_link_id: Option<u16>,
    /// The backend can send SRv6 return paths (RFC 9503 §4).
    pub srv6: bool,
}

impl ReflectorSettings {
    /// Resolves settings, loading the single HMAC key unless `shared` already
    /// holds a per-SSID keyset. `srv6` states whether this backend can attach
    /// an SRH to replies.
    ///
    /// # Errors
    /// Fails when authentication needs a key that cannot be loaded, or a
    /// policy specification does not parse.
    pub fn from_config(
        conf: &Configuration,
        shared: &ReceiverSharedState,
        srv6: bool,
    ) -> Result<Self, crate::StartupError> {
        let use_auth = is_auth(conf.auth_mode);
        let keyset_configured = shared
            .hmac_keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        // `create_shared_state` loads every configured source into the
        // keyset; the single key covers callers that built the state without it.
        let hmac_key = if keyset_configured {
            None
        } else {
            conf.key_source().load_key()?
        };
        if use_auth && hmac_key.is_none() && !keyset_configured {
            return Err(crate::StartupError::config(
                "Authenticated mode (-A A) requires --hmac-key, --hmac-key-file, or --hmac-key-dir",
            ));
        }
        if hmac_key.is_some() {
            log::info!("HMAC authentication enabled");
        }

        let error_estimate = ErrorEstimate::with_clock_format(
            conf.clock_synchronized,
            conf.clock_source,
            conf.error_scale,
            conf.error_multiplier,
        )
        .map_err(crate::StartupError::config)?;

        let location_disclosure = conf
            .location_disclosure()
            .map_err(crate::StartupError::config)?;
        let cos_policy = conf
            .cos_admission_policy()
            .map_err(crate::StartupError::config)?;
        if !cos_policy.is_permissive() {
            log::info!(
                "CoS admission policy active (--allowed-dscp {}, --allowed-ecn {}, {} \
                 destination rule(s)): a refused DSCP1/EC1 is reported via RPD/RPE \
                 instead of being applied",
                conf.allowed_dscp,
                conf.allowed_ecn,
                conf.allowed_dscp_for.len()
            );
        }
        if conf.tlv_mode != TlvHandlingMode::Ignore {
            log::info!("TLV handling mode: {:?}", conf.tlv_mode);
        }
        if conf.stateful_reflector {
            log::info!("Stateful reflector mode enabled (RFC 8762 §4)");
        }

        Ok(Self {
            use_auth,
            clock_source: conf.clock_source,
            clock_sync_source: conf.clock_sync_source.into(),
            hardware_clock_sync_source: conf.hardware_clock_sync_source.into(),
            error_estimate_wire: error_estimate.to_wire(),
            hmac_key,
            require_hmac: conf.require_hmac,
            stateful_reflector: conf.stateful_reflector,
            tlv_mode: conf.tlv_mode,
            verify_tlv_hmac: conf.verify_tlv_hmac,
            strict_packets: conf.strict_packets,
            #[cfg(feature = "metrics")]
            metrics_enabled: conf.metrics,
            drop_replayed: conf.drop_replayed,
            location_disclosure,
            cos_policy,
            // RFC 9503 §3 matching uses the bind address, or every interface
            // address for a wildcard bind.
            local_addresses: build_local_addresses(conf.local_addr),
            // RFC 10052 §3.1.1 L2 Address Groups match any local interface.
            local_macs: build_local_macs(),
            return_path_allow_alternate: conf.return_path_allow_alternate,
            reflector_member_link_id: conf.reflector_member_link_id,
            srv6,
        })
    }
}

/// What a backend learned about one received datagram.
pub(super) struct ReceivedPacket<'a> {
    pub(super) data: &'a [u8],
    pub(super) src: SocketAddr,
    /// Destination address the request was sent to.
    pub(super) dst_addr: std::net::IpAddr,
    /// Destination endpoint, including the IPv6 zone of a link-local address.
    pub(super) local: SocketAddr,
    pub(super) ttl: u8,
    pub(super) dscp: u8,
    pub(super) ecn: u8,
    /// Arrival interface when replies can be pinned to it (RFC 9503 §4.1.1).
    pub(super) ingress_ifindex: Option<u32>,
    pub(super) src_mac: Option<[u8; 6]>,
    /// Raw IP headers: fixed and extension headers from packet capture, or
    /// IPv6 extension headers only from the nix backend on Linux.
    pub(super) captured_headers: Option<&'a CapturedHeaders>,
    /// Kernel or NIC receive timestamp (T2) in the configured wire format.
    pub(super) rx_timestamp: Option<u64>,
    pub(super) rx_method: TimestampMethod,
}

/// The settings plus the shared state every packet needs.
pub(super) struct ReflectorCore {
    pub(super) settings: ReflectorSettings,
    pub(super) counters: Arc<ReflectorCounters>,
    pub(super) rate_limiter: Arc<RateLimiter>,
    pub(super) session_manager: Arc<SessionManager>,
    pub(super) hmac_keys: Arc<std::sync::RwLock<Option<crate::crypto::HmacKeySet>>>,
    pub(super) caps: Arc<RuntimeCaps>,
    pub(super) budget: Arc<ReplyBudget>,
}

impl ReflectorCore {
    pub(super) fn new(
        settings: ReflectorSettings,
        shared: &ReceiverSharedState,
        queue_capacity: usize,
    ) -> Self {
        Self {
            settings,
            counters: Arc::clone(&shared.counters),
            rate_limiter: Arc::clone(&shared.rate_limiter),
            session_manager: Arc::clone(&shared.session_manager),
            hmac_keys: Arc::clone(&shared.hmac_keys),
            caps: Arc::clone(&shared.caps),
            budget: ReplyBudget::new(queue_capacity, Arc::clone(&shared.counters)),
        }
    }

    /// Admits one datagram and returns its reply, ready to queue.
    ///
    /// The reply holds its queue slot until every copy is sent or dropped.
    /// `None` means the packet was dropped and already counted: rate limited,
    /// over the reply queue capacity, or rejected during processing.
    pub(super) fn ingest(&self, packet: &ReceivedPacket) -> Option<QueuedTransmission> {
        if !self.rate_limiter.allow(packet.src.ip()) {
            log::debug!("Rate-limited packet from {}", packet.src);
            self.counters
                .packets_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            self.counters
                .packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.counters
            .packets_received
            .fetch_add(1, Ordering::Relaxed);
        // The budget counts its own rejections.
        let reservation = self.budget.reserve()?;

        let settings = &self.settings;
        // The keyset guard covers authentication and assembly; the queued
        // reply owns the key it selected, so rotation cannot change it later.
        let keys = self.hmac_keys.read().unwrap_or_else(|e| e.into_inner());
        let ctx = ProcessingContext::for_packet(
            settings,
            packet,
            &self.caps,
            keys.as_ref(),
            &self.session_manager,
        );
        let transmission = process_session_packet_isolated(
            packet.data,
            packet.src,
            packet.ttl,
            settings.use_auth,
            &ctx,
            &self.counters,
            settings.drop_replayed,
        )
        .map(|(response, session, signing_key)| {
            reservation.attach(Transmission::new(
                response,
                session,
                packet.src,
                settings.clock_source,
                settings.use_auth,
                settings.stateful_reflector,
                signing_key,
                packet.dscp,
                settings.srv6,
            ))
        });
        if transmission.is_none() {
            self.counters
                .packets_dropped
                .fetch_add(1, Ordering::Relaxed);
        }
        transmission
    }
}

impl<'a> ProcessingContext<'a> {
    /// Builds the context for one received packet. Runtime caps are read once
    /// here so a concurrent control-plane change applies to whole packets.
    pub(super) fn for_packet(
        settings: &'a ReflectorSettings,
        packet: &ReceivedPacket<'a>,
        caps: &RuntimeCaps,
        hmac_key_set: Option<&'a crate::crypto::HmacKeySet>,
        session_manager: &'a Arc<SessionManager>,
    ) -> Self {
        Self {
            ingress_ifindex: packet.ingress_ifindex,
            packet_local_addr: Some(packet.local),
            replay_verdict: crate::session::ReplayVerdict::New,
            clock_source: settings.clock_source,
            clock_sync_source: settings.clock_sync_source,
            hardware_clock_sync_source: settings.hardware_clock_sync_source,
            error_estimate_wire: settings.error_estimate_wire,
            hmac_key: settings.hmac_key.as_ref(),
            hmac_key_set,
            require_hmac: settings.require_hmac,
            session_manager: Some(session_manager),
            stateful_reflector: settings.stateful_reflector,
            tlv_mode: settings.tlv_mode,
            verify_tlv_hmac: settings.verify_tlv_hmac,
            strict_packets: settings.strict_packets,
            #[cfg(feature = "metrics")]
            metrics_enabled: settings.metrics_enabled,
            received_dscp: packet.dscp,
            received_ecn: packet.ecn,
            reflector_rx_count: None,
            reflector_tx_count: None,
            packet_addr_info: Some(PacketAddressInfo {
                src_addr: packet.src.ip(),
                src_port: packet.src.port(),
                dst_addr: packet.dst_addr,
                dst_port: packet.local.port(),
                src_mac: packet.src_mac,
            }),
            last_reflection: None,
            location_disclosure: settings.location_disclosure,
            cos_policy: &settings.cos_policy,
            local_addresses: &settings.local_addresses,
            local_macs: &settings.local_macs,
            sender_port: packet.src.port(),
            return_path_allow_alternate: settings.return_path_allow_alternate,
            reflector_member_link_id: settings.reflector_member_link_id,
            captured_headers: packet.captured_headers,
            reflected_control_max_count: caps.reflected_control_max_count.load(Ordering::Relaxed),
            reflected_control_max_size: caps.reflected_control_max_size.load(Ordering::Relaxed),
            reflected_control_min_interval_ns: caps
                .reflected_control_min_interval_ns
                .load(Ordering::Relaxed),
            reflected_control_max_rate: caps.reflected_control_max_rate.load(Ordering::Relaxed),
            reflected_control_max_volume: caps.reflected_control_max_volume.load(Ordering::Relaxed),
            rx_timestamp: packet.rx_timestamp,
            rx_method: packet.rx_method,
            last_reflection_method: TimestampMethod::SwLocal,
        }
    }
}
