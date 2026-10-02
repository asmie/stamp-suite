//! Finalize every datagram at its actual send attempt, including burst copies.

use super::{RateLimiter, ReflectorCounters, StampResponse, AUTH_BASE_SIZE, UNAUTH_BASE_SIZE};
use crate::{
    clock_format::ClockFormat,
    crypto::HmacKey,
    session::Session,
    tlv::{
        ReturnPathAction, TlvFlags, TlvSpan, TlvType, DIRECT_MEASUREMENT_TLV_VALUE_SIZE,
        FOLLOW_UP_TELEMETRY_TLV_VALUE_SIZE, HMAC_TLV_VALUE_SIZE, TLV_HEADER_SIZE,
    },
};
use std::{
    cmp::Ordering as CmpOrdering,
    collections::BinaryHeap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub(super) struct SendOptions {
    pub tos: u8,
    pub source: Option<IpAddr>,
    /// Egress interface for RFC 9503 same-link replies (Linux only).
    pub egress_ifindex: Option<u32>,
    pub srh: Option<Arc<[u8]>>,
    pub dont_fragment: bool,
}

/// Request-owned transport policy, prepared only when the first copy is eligible.
/// Attempts clone these options; fallbacks never alter later copies' policy.
struct TransportPlan {
    target: SocketAddr,
    options: SendOptions,
    unsupported_srh: bool,
}

impl TransportPlan {
    fn new(response: &StampResponse, source: SocketAddr, base: usize, srv6: bool) -> Self {
        let target = match response.return_path_action {
            ReturnPathAction::AlternateAddress(addr)
            | ReturnPathAction::Srv6Forward {
                destination: Some(addr),
                ..
            } => match (addr, source) {
                (SocketAddr::V6(target), SocketAddr::V6(source))
                    if target.ip().is_unicast_link_local() && target.scope_id() == 0 =>
                {
                    std::net::SocketAddrV6::new(*target.ip(), target.port(), 0, source.scope_id())
                        .into()
                }
                _ => addr,
            },
            _ => source,
        };
        let mut options = SendOptions {
            tos: response.cos_request.map_or(0, |(d, e)| (d << 2) | e),
            source: response
                .reply_source
                .filter(|s| crate::reply_source::supported() && s.is_ipv4() == target.is_ipv4()),
            egress_ifindex: match response.return_path_action {
                ReturnPathAction::SameLink(index) => Some(index),
                _ => None,
            },
            srh: None,
            dont_fragment: response.reflected_control.is_some()
                || has_reflected_headers(&response.data, base)
                || (cfg!(target_os = "linux") && has_ber(&response.data, base)),
        };
        let mut unsupported_srh = false;
        if let ReturnPathAction::Srv6Forward { sids, .. } = &response.return_path_action {
            if srv6 && target.is_ipv6() && !sids.is_empty() {
                // Linux replaces Segment List[0] with the UDP destination.
                // Preserve every requested SID by reserving that final slot.
                let mut path = sids.clone();
                if path.last().copied().map(IpAddr::V6) != Some(target.ip()) {
                    if let IpAddr::V6(destination) = target.ip() {
                        path.push(destination);
                    }
                }
                options.srh = crate::srv6::build_srh(&path).map(Arc::from);
            }
            unsupported_srh = options.srh.is_none();
        }
        Self {
            target,
            options,
            unsupported_srh,
        }
    }
}

pub(super) struct Transmission {
    response: StampResponse,
    plan: Option<TransportPlan>,
    pub session: Arc<Session>,
    source: SocketAddr,
    clock: ClockFormat,
    auth: bool,
    stateful: bool,
    key: Option<HmacKey>,
    received_dscp: u8,
    srv6: bool,
    pub remaining: u16,
    pub interval: Duration,
    first: bool,
}

impl Transmission {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        response: StampResponse,
        session: Arc<Session>,
        source: SocketAddr,
        clock: ClockFormat,
        auth: bool,
        stateful: bool,
        key: Option<HmacKey>,
        received_dscp: u8,
        srv6: bool,
    ) -> Self {
        let extra = response.reflected_control.map_or(0, |b| b.extra_copies);
        let interval =
            Duration::from_nanos(response.reflected_control.map_or(0, |b| b.interval_ns) as u64);
        Self {
            response,
            plan: None,
            session,
            source,
            clock,
            auth,
            stateful,
            key,
            received_dscp,
            srv6,
            remaining: extra.saturating_add(1),
            interval,
            first: true,
        }
    }

    #[cfg(test)]
    #[cfg(test)]
    pub fn send_next(
        &mut self,
        counters: &ReflectorCounters,
        limiter: &RateLimiter,
        send: impl FnMut(&[u8], SocketAddr, &SendOptions) -> io::Result<usize>,
    ) -> Option<u32> {
        self.send_next_with_mtu(counters, limiter, |_, _, _| Ok(usize::MAX), send)
    }

    /// Check the destination budget for every copy and routing fallback, then
    /// shape, timestamp and sign immediately before its actual send attempt.
    pub fn send_next_with_mtu(
        &mut self,
        counters: &ReflectorCounters,
        limiter: &RateLimiter,
        mut payload_cap: impl FnMut(SocketAddr, &SendOptions, bool) -> io::Result<usize>,
        mut send: impl FnMut(&[u8], SocketAddr, &SendOptions) -> io::Result<usize>,
    ) -> Option<u32> {
        let Some(_active) = self.session.transmission_guard() else {
            counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.remaining = 0;
            return None;
        };
        if matches!(
            self.response.return_path_action,
            ReturnPathAction::SuppressReply
        ) {
            counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.remaining = 0;
            return None;
        }
        if !self.first && !limiter.allow(self.source.ip()) {
            counters
                .packets_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
            self.remaining = 0;
            return None;
        }
        self.first = false;
        // The last copy can take the buffer; earlier copies need it again.
        let mut data = if self.remaining <= 1 {
            std::mem::take(&mut self.response.data)
        } else {
            self.response.data.clone()
        };
        let base = if self.auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        };
        let sequence = if self.stateful {
            self.session.peek_sequence_number()
        } else {
            u32::from_be_bytes(data[..4].try_into().expect("validated response base"))
        };
        data[..4].copy_from_slice(&sequence.to_be_bytes());
        refresh_telemetry(&mut data, base, &self.session, self.stateful);
        let plan = self.plan.get_or_insert_with(|| {
            TransportPlan::new(&self.response, self.source, base, self.srv6)
        });
        let mut target = plan.target;
        let mut options = plan.options.clone();
        if plan.unsupported_srh {
            super::set_return_path_u_flag_in_response(&mut data, base);
        }
        let mut cos_fallback = false;
        let mut refresh_mtu = false;
        loop {
            // Always start from the untrimmed reply: a fallback route may have
            // a larger MTU and must not inherit another route's C flag/padding.
            let mut attempt = data.clone();
            let mut clamped = false;
            let budget = if options.dont_fragment {
                payload_cap(target, &options, refresh_mtu)
            } else {
                Ok(usize::MAX)
            };
            let result = budget.and_then(|cap| {
                let cap = cap.min(
                    self.response
                        .reflected_control
                        .map_or(usize::MAX, |b| usize::from(b.max_size)),
                );
                clamped = fit_reply(
                    &mut attempt,
                    base,
                    cap,
                    self.response.reflected_control.is_some(),
                )?;
                let timestamp = crate::time::generate_timestamp(self.clock);
                let offset = if self.auth { 16 } else { 4 };
                attempt[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
                if let Some(key) = &self.key {
                    if self.auth {
                        let hmac = crate::crypto::compute_packet_hmac(key, &attempt, 96);
                        attempt[96..112].copy_from_slice(&hmac);
                    }
                    if self.response.tlv_hmac_generated {
                        sign_tlvs(&mut attempt, base, key);
                    }
                }
                send(&attempt, target, &options).and_then(|sent| {
                    if sent == attempt.len() {
                        Ok(timestamp)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "incomplete UDP datagram send",
                        ))
                    }
                })
            });
            match result {
                Ok(timestamp) => {
                    if clamped {
                        self.remaining = 1;
                    }
                    if self.stateful {
                        self.session.generate_sequence_number();
                    }
                    self.session.record_transmitted();
                    self.session.record_reflection(sequence, timestamp);
                    counters.packets_reflected.fetch_add(1, Ordering::Relaxed);
                    self.remaining -= 1;
                    return Some(sequence);
                }
                Err(e) if options.dont_fragment && is_message_too_large(&e) => {
                    // MTU races must not strip SRH, source pinning or CoS. A
                    // fresh route query and re-shape gets one bounded retry.
                    if refresh_mtu {
                        break;
                    }
                    refresh_mtu = true;
                    continue;
                }
                Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                    log::debug!("reply cannot fit the route MTU: {e}");
                    break;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::WriteZero
                    ) =>
                {
                    // UDP queue pressure is a failed transmission, never a
                    // reason to downgrade requested routing/CoS metadata.
                    log::debug!("reflector datagram was not sent: {e}");
                    break;
                }
                Err(e) => {
                    refresh_mtu = false;
                    if options.egress_ifindex.take().is_some() {
                        // The arrival link cannot carry the reply (RFC 9503 §4).
                        super::set_return_path_u_flag_in_response(&mut data, base);
                    } else if options.srh.take().is_some() {
                        super::set_return_path_u_flag_in_response(&mut data, base);
                    } else if options.source.take().is_some() {
                        // RFC 9503 source pinning is best-effort.
                    } else if target != self.source {
                        target = self.source;
                        options.source = self.response.reply_source.filter(|s| {
                            crate::reply_source::supported() && s.is_ipv4() == target.is_ipv4()
                        });
                        super::set_return_path_u_flag_in_response(&mut data, base);
                    } else if self.response.cos_request.is_some()
                        && !cos_fallback
                        && super::cos_unable_fallback_tos(self.received_dscp) != options.tos
                    {
                        // Retry once with the received DSCP and Not-ECT
                        // (cos-ecn-01 §3.2), unless that is the byte that just
                        // failed.
                        cos_fallback = true;
                        options.tos = super::cos_unable_fallback_tos(self.received_dscp);
                        super::set_cos_policy_rejected(&mut data, base);
                    } else {
                        log::debug!("reflector send to {target} failed: {e}");
                        break;
                    }
                }
            }
        }
        counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
        self.remaining = 0;
        None
    }
}

fn is_message_too_large(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(nix::libc::EMSGSIZE)
    }
    #[cfg(not(unix))]
    {
        error.raw_os_error() == Some(10040)
    } // WSAEMSGSIZE
}

fn is_reflected_header(tlv: &TlvSpan) -> bool {
    matches!(
        tlv.tlv_type,
        TlvType::ReflectedIpv6ExtHdr | TlvType::ReflectedFixedHdr
    )
}

/// True when the reply is a complete, well-formed TLV chain that includes a
/// processed Type 246/247 TLV.
fn has_reflected_headers(data: &[u8], base: usize) -> bool {
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
fn has_ber(data: &[u8], base: usize) -> bool {
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

/// Preserve complete mandatory TLVs and the final HMAC. Only padding and
/// reflected header TLVs may be removed. Return true to terminate a burst.
fn fit_reply(data: &mut Vec<u8>, base: usize, cap: usize, controlled: bool) -> io::Result<bool> {
    if data.len() <= cap {
        return Ok(false);
    }
    let cannot_fit = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "mandatory reply fields exceed payload budget",
        )
    };
    if base > cap {
        return Err(cannot_fit());
    }
    if has_ber(data, base) && !controlled {
        let list = crate::tlv::TlvList::parse(&data[base..]).map_err(|_| cannot_fit())?;
        let mut tlvs: Vec<_> = list.iter().cloned().collect();
        crate::ber::fit_padding(&mut tlvs, cap, base)?;
        let mut resized = crate::tlv::TlvList::new();
        for mut tlv in tlvs {
            // The forward count described the original padding size. Mark
            // metadata unusable once route MTU trimming changes that size.
            if crate::ber::is_ber(tlv.tlv_type) {
                tlv.set_conformant_reflected();
            }
            resized.push(tlv).map_err(|_| cannot_fit())?;
        }
        data.truncate(base);
        data.extend_from_slice(&resized.to_bytes());
        return Ok(false);
    }
    // Every byte after the base must belong to a well-formed TLV.
    let mut pos = base;
    let mut tlvs = Vec::new();
    while pos < data.len() {
        let tlv = TlvSpan::at(data, pos).ok_or_else(cannot_fit)?;
        if tlv.flags.malformed {
            return Err(cannot_fit());
        }
        if !controlled || tlv.tlv_type != TlvType::ExtraPadding {
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
            return Err(cannot_fit());
        };
        size -= tlvs.remove(index).1.len();
    }
    if controlled {
        // RFC 10052 §3: a reply clamped to the MTU carries C.
        if let Some((_, control)) = tlvs
            .iter_mut()
            .find(|(tlv, _)| tlv.tlv_type == TlvType::ReflectedControl && tlv.flags.processed())
        {
            control[0] |= TlvFlags::C;
        }
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
            }
        }
    }
    data.truncate(base);
    for (_, bytes) in tlvs {
        data.extend_from_slice(&bytes);
    }
    Ok(controlled)
}

/// Refreshes send-time Direct Measurement counters and Follow-Up Telemetry
/// in TLVs the reflector processed. Processing stopped at the first malformed
/// TLV (RFC 8972 §4), so the walk stops there too.
fn refresh_telemetry(data: &mut [u8], base: usize, session: &Session, stateful: bool) {
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
fn sign_tlvs(data: &mut [u8], base: usize, key: &HmacKey) {
    const HMAC_TLV_SIZE: usize = TLV_HEADER_SIZE + HMAC_TLV_VALUE_SIZE;
    if data.len() < base + HMAC_TLV_SIZE {
        return;
    }
    let sign = |data: &mut [u8], hmac_at: usize| {
        let digest = key.compute_parts([&data[..4], &data[base..hmac_at]]);
        data[hmac_at + TLV_HEADER_SIZE..hmac_at + HMAC_TLV_SIZE].copy_from_slice(&digest);
    };
    // BER replies may carry Extra Padding after the HMAC, so walk the chain.
    if has_ber(data, base) {
        let mut pos = base;
        while let Some(tlv) = TlvSpan::at(data, pos) {
            if tlv.flags.malformed {
                break;
            }
            if tlv.tlv_type.is_hmac() && tlv.len == HMAC_TLV_VALUE_SIZE {
                sign(data, tlv.start);
                return;
            }
            pos = tlv.end();
        }
    }
    // Otherwise the HMAC is the last TLV, followed only by zero padding.
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

/// A slot covers processing, channel handoff, queued deadlines and the active
/// send. Keeping it through every copy bounds combined work in both backends.
pub(super) struct ReplyBudget {
    limit: usize,
    used: AtomicUsize,
    counters: Arc<ReflectorCounters>,
}

impl ReplyBudget {
    pub fn new(limit: usize, counters: Arc<ReflectorCounters>) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            counters,
        })
    }

    /// `fetch_update` is deprecated on current toolchains and its
    /// replacement is newer than the MSRV, so the CAS loop is spelled out.
    fn try_take_slot(&self) -> bool {
        let mut used = self.used.load(Ordering::Acquire);
        while used < self.limit {
            match self.used.compare_exchange_weak(
                used,
                used + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => used = actual,
            }
        }
        false
    }

    pub fn reserve(self: &Arc<Self>) -> Option<ReplyReservation> {
        if !self.try_take_slot() {
            self.counters
                .reply_queue_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.counters
                .packets_dropped
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(ReplyReservation(Arc::clone(self)))
    }

    pub fn is_empty(&self) -> bool {
        self.used.load(Ordering::Acquire) == 0
    }
}

pub(super) struct ReplyReservation(Arc<ReplyBudget>);
impl ReplyReservation {
    pub fn attach(self, transmission: Transmission) -> QueuedTransmission {
        QueuedTransmission {
            transmission,
            reservation: self,
        }
    }
}
impl Drop for ReplyReservation {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) struct QueuedTransmission {
    pub transmission: Transmission,
    reservation: ReplyReservation,
}
impl Drop for QueuedTransmission {
    fn drop(&mut self) {
        if self.transmission.remaining > 0 {
            let counters = &self.reservation.0.counters;
            counters
                .queued_replies_cancelled
                .fetch_add(u64::from(self.transmission.remaining), Ordering::Relaxed);
            counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// A shutdown deadline is set once and cannot be extended by later signals.
#[derive(Default)]
pub(super) struct ShutdownDrain {
    deadline: Option<Instant>,
}
impl ShutdownDrain {
    pub fn begin(&mut self, now: Instant, grace: Duration) {
        self.deadline.get_or_insert(now + grace);
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
    pub fn finished(&self, now: Instant, empty: bool) -> bool {
        self.deadline
            .is_some_and(|deadline| empty || now >= deadline)
    }
}

struct Pending {
    at: Instant,
    order: u64,
    transmission: QueuedTransmission,
}
impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.order == other.order
    }
}
impl Eq for Pending {}
impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl Ord for Pending {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.order.cmp(&self.order))
    }
}

#[derive(Default)]
pub(super) struct ReplyQueue {
    pending: BinaryHeap<Pending>,
    order: u64,
}
impl ReplyQueue {
    pub fn deadline(&self) -> Option<Instant> {
        self.pending.peek().map(|p| p.at)
    }
    pub fn push_at(&mut self, transmission: QueuedTransmission, at: Instant) {
        self.order = self.order.wrapping_add(1);
        self.pending.push(Pending {
            at,
            order: self.order,
            transmission,
        });
    }
    pub fn schedule_next(&mut self, transmission: QueuedTransmission) {
        if transmission.transmission.remaining > 0 {
            let at = Instant::now() + transmission.transmission.interval;
            self.push_at(transmission, at);
        }
    }
    pub fn pop_due(&mut self) -> Option<QueuedTransmission> {
        if self.deadline().is_some_and(|at| at <= Instant::now()) {
            self.pending.pop().map(|p| p.transmission)
        } else {
            None
        }
    }
}

/// The sole option-setting sender for a borrowed socket. Receive operations may
/// share the socket, but all sends/options go through this mutable owner.
/// Successful sticky settings are cached separately for IPv4 and IPv6.
pub(super) struct DatagramSender<'a> {
    #[cfg(unix)]
    fd: std::os::fd::BorrowedFd<'a>,
    #[cfg(windows)]
    socket: &'a std::net::UdpSocket,
    settings: [Option<i32>; 2],
    #[cfg(target_os = "linux")]
    srh: Option<Arc<[u8]>>,
}

impl<'a> DatagramSender<'a> {
    #[cfg(unix)]
    pub fn new(socket: &'a impl std::os::fd::AsFd) -> Self {
        Self {
            fd: socket.as_fd(),
            settings: [None; 2],
            #[cfg(target_os = "linux")]
            srh: None,
        }
    }

    #[cfg(windows)]
    pub fn new(socket: &'a std::net::UdpSocket) -> Self {
        Self {
            socket,
            settings: [None; 2],
        }
    }

    pub fn send(
        &mut self,
        payload: &[u8],
        dst: SocketAddr,
        options: &SendOptions,
    ) -> io::Result<usize> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            send_datagram(
                self.fd.as_raw_fd(),
                payload,
                dst,
                options,
                &mut self.settings,
                #[cfg(target_os = "linux")]
                &mut self.srh,
            )
        }
        #[cfg(windows)]
        {
            update_socket_option(
                &mut self.settings[usize::from(dst.is_ipv6())],
                i32::from(options.tos),
                || set_socket_tos(self.socket, options.tos, dst.is_ipv6()),
            )?;
            self.socket.send_to(payload, dst)
        }
    }
}

fn update_socket_option(
    cached: &mut Option<i32>,
    requested: i32,
    set: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if *cached != Some(requested) {
        set()?;
        *cached = Some(requested);
    }
    Ok(())
}

/// Ancillary data for one `sendmsg`, built in place on the stack.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct ControlBuffer {
    /// `usize` elements keep every header `cmsghdr`-aligned.
    words: [usize; 16],
    /// Bytes in use.
    used: usize,
}

#[cfg(target_os = "linux")]
impl ControlBuffer {
    fn append(&mut self, level: i32, kind: i32, bytes: &[u8]) {
        use nix::libc;
        // SAFETY: CMSG_SPACE only computes a size.
        let space = unsafe { libc::CMSG_SPACE(bytes.len() as _) } as usize;
        assert!(
            self.used + space <= std::mem::size_of_val(&self.words),
            "control buffer overflow"
        );
        // SAFETY: the assertion keeps the header and data inside `words`,
        // which starts zeroed, so padding stays zero. `used` is a multiple of
        // CMSG_ALIGN, so the header is aligned.
        unsafe {
            let header = self
                .words
                .as_mut_ptr()
                .cast::<u8>()
                .add(self.used)
                .cast::<libc::cmsghdr>();
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(bytes.len() as _) as _;
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), libc::CMSG_DATA(header), bytes.len());
        }
        self.used += space;
    }
}

/// CoS and source pinning accompany sendmsg; Linux SRH uses the sticky socket
/// option because the ancillary IPV6_RTHDR parser rejects routing type 4.
/// The exclusive send owner restores/clears SRH before a different reply.
/// Other Unix systems update cached TOS before sendmsg; the mutable send owner
/// never awaits between setting the socket option and issuing the syscall.
#[cfg(unix)]
fn send_datagram(
    fd: std::os::fd::RawFd,
    payload: &[u8],
    dst: SocketAddr,
    options: &SendOptions,
    settings: &mut [Option<i32>; 2],
    #[cfg(target_os = "linux")] srh_setting: &mut Option<Arc<[u8]>>,
) -> io::Result<usize> {
    use nix::libc;
    let mut addr4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut addr6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        addr4.sin_len = std::mem::size_of_val(&addr4) as _;
        addr6.sin6_len = std::mem::size_of_val(&addr6) as _;
    }
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    match dst {
        SocketAddr::V4(v) => {
            addr4.sin_family = libc::AF_INET as _;
            addr4.sin_port = v.port().to_be();
            addr4.sin_addr.s_addr = u32::from_ne_bytes(v.ip().octets());
            msg.msg_name = std::ptr::addr_of_mut!(addr4).cast();
            msg.msg_namelen = std::mem::size_of_val(&addr4) as _;
        }
        SocketAddr::V6(v) => {
            addr6.sin6_family = libc::AF_INET6 as _;
            addr6.sin6_port = v.port().to_be();
            addr6.sin6_addr.s6_addr = v.ip().octets();
            addr6.sin6_scope_id = v.scope_id();
            msg.msg_name = std::ptr::addr_of_mut!(addr6).cast();
            msg.msg_namelen = std::mem::size_of_val(&addr6) as _;
        }
    }
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    msg.msg_iov = std::ptr::addr_of_mut!(iov);
    msg.msg_iovlen = 1;
    #[cfg(target_os = "linux")]
    // TOS plus one PKTINFO fit well within 128 bytes; usize elements give
    // cmsghdr alignment without a heap allocation per send.
    let mut control = ControlBuffer::default();
    #[cfg(target_os = "linux")]
    {
        // This socket has one send owner. Restore normal PMTU policy for
        // ordinary STAMP replies after a size-controlled send on the same fd.
        let discover: libc::c_int = if options.dont_fragment {
            libc::IP_PMTUDISC_DO
        } else {
            libc::IP_PMTUDISC_WANT
        };
        update_socket_option(&mut settings[usize::from(dst.is_ipv6())], discover, || {
            if unsafe {
                libc::setsockopt(
                    fd,
                    if dst.is_ipv4() {
                        libc::IPPROTO_IP
                    } else {
                        libc::IPPROTO_IPV6
                    },
                    if dst.is_ipv4() {
                        libc::IP_MTU_DISCOVER
                    } else {
                        libc::IPV6_MTU_DISCOVER
                    },
                    std::ptr::addr_of!(discover).cast(),
                    std::mem::size_of_val(&discover) as _,
                )
            } < 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        })?;
        let tos = options.tos as libc::c_int;
        control.append(
            if dst.is_ipv4() {
                libc::IPPROTO_IP
            } else {
                libc::IPPROTO_IPV6
            },
            if dst.is_ipv4() {
                libc::IP_TOS
            } else {
                libc::IPV6_TCLASS
            },
            &tos.to_ne_bytes(),
        );
        if options
            .source
            .is_some_and(|source| source.is_ipv4() != dst.is_ipv4())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source/destination family mismatch",
            ));
        }
        // One PKTINFO carries the pinned source address and the egress
        // interface; either may be unset (zero).
        if options.source.is_some() || options.egress_ifindex.is_some() {
            let ifindex = options.egress_ifindex.unwrap_or(0);
            if dst.is_ipv4() {
                // SAFETY: in_pktinfo is plain old data; all-zero is valid.
                let mut info: libc::in_pktinfo = unsafe { std::mem::zeroed() };
                if let Some(IpAddr::V4(ip)) = options.source {
                    info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                }
                info.ipi_ifindex = ifindex as _;
                // SAFETY: the slice covers exactly `info`, which outlives it.
                control.append(libc::IPPROTO_IP, libc::IP_PKTINFO, unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(info).cast(),
                        std::mem::size_of_val(&info),
                    )
                });
            } else {
                // SAFETY: in6_pktinfo is plain old data; all-zero is valid.
                let mut info: libc::in6_pktinfo = unsafe { std::mem::zeroed() };
                if let Some(IpAddr::V6(ip)) = options.source {
                    info.ipi6_addr.s6_addr = ip.octets();
                }
                info.ipi6_ifindex = ifindex as _;
                // SAFETY: the slice covers exactly `info`, which outlives it.
                control.append(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::addr_of!(info).cast(),
                        std::mem::size_of_val(&info),
                    )
                });
            }
        }
        if *srh_setting != options.srh {
            let bytes = options.srh.as_deref().unwrap_or(&[]);
            // No await or other sender can interleave this option and sendmsg.
            // On failure retain the previous cache: a fallback must clear it
            // successfully before transmitting an ordinary reply.
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RTHDR,
                    bytes.as_ptr().cast(),
                    bytes.len() as _,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
            *srh_setting = options.srh.clone();
        }
        msg.msg_control = control.words.as_mut_ptr().cast();
        msg.msg_controllen = control.used as _;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let tos = options.tos as libc::c_int;
        update_socket_option(&mut settings[usize::from(dst.is_ipv6())], tos, || {
            let result = unsafe {
                libc::setsockopt(
                    fd,
                    if dst.is_ipv4() {
                        libc::IPPROTO_IP
                    } else {
                        libc::IPPROTO_IPV6
                    },
                    if dst.is_ipv4() {
                        libc::IP_TOS
                    } else {
                        libc::IPV6_TCLASS
                    },
                    std::ptr::addr_of!(tos).cast(),
                    std::mem::size_of_val(&tos) as _,
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        })?;
    }

    let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ber_tests;
