//! Finalize every datagram at its actual send attempt, including burst copies.

mod datagram;
mod errors;
mod queue;
mod shape;
#[cfg(target_os = "windows")]
mod windows;

// The test modules below reach every helper through `use super::*`.
pub(super) use datagram::DatagramSender;
#[cfg(test)]
use datagram::*;
#[cfg(any(not(target_os = "linux"), test))]
pub(super) use errors::cos_apply_error;
pub(super) use errors::local_send_error;
use errors::*;
pub(super) use queue::{QueuedTransmission, ReplyBudget, ReplyQueue, ShutdownDrain};
use shape::*;

use super::{
    RateLimiter, ReflectorCounters, StampResponse, AUTH_BASE_SIZE, AUTH_HMAC_OFFSET,
    UNAUTH_BASE_SIZE,
};
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
    /// False when marking is unavailable (CoS RPE=01), or not requested on Windows.
    pub apply_tos: bool,
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
            apply_tos: !cfg!(windows) || response.cos_request.is_some(),
            tos: response
                .cos_request
                .map_or(0, |(d, e)| crate::tos::Tos::new(d, e).0),
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
                || (has_ber(&response.data, base) && ber_route_mtu_supported(target.ip())),
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
    /// A target an earlier copy could not mark (option-setting failed for
    /// both the request and the Not-ECT fallback). Later copies to it start
    /// in that final state instead of failing the same attempts again.
    marking_unavailable_for: Option<SocketAddr>,
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
            marking_unavailable_for: None,
        }
    }

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
    /// A reply that is not sent ends the burst and counts as a drop.
    pub fn send_next_with_mtu(
        &mut self,
        counters: &ReflectorCounters,
        limiter: &RateLimiter,
        payload_cap: impl FnMut(SocketAddr, &SendOptions, bool) -> io::Result<usize>,
        send: impl FnMut(&[u8], SocketAddr, &SendOptions) -> io::Result<usize>,
    ) -> Option<u32> {
        match self.try_send_next_with_mtu(counters, limiter, payload_cap, send) {
            Ok(sequence) => Some(sequence),
            Err(reason) => {
                counters.record_drop(reason);
                self.remaining = 0;
                None
            }
        }
    }

    /// Sends the next copy, or returns the drop reason label: `session_expired`,
    /// `suppressed`, `rate_limited`, `cos_policy` (a restricted DSCP set that
    /// the backend cannot enforce), `mtu_exceeded` (the mandatory fields do not fit the route MTU)
    /// or `send_failed`.
    fn try_send_next_with_mtu(
        &mut self,
        counters: &ReflectorCounters,
        limiter: &RateLimiter,
        mut payload_cap: impl FnMut(SocketAddr, &SendOptions, bool) -> io::Result<usize>,
        mut send: impl FnMut(&[u8], SocketAddr, &SendOptions) -> io::Result<usize>,
    ) -> Result<u32, &'static str> {
        let Some(_active) = self.session.transmission_guard() else {
            return Err("session_expired");
        };
        if matches!(
            self.response.return_path_action,
            ReturnPathAction::SuppressReply
        ) {
            return Err("suppressed");
        }
        if !self.first && !limiter.allow(self.source.ip()) {
            counters
                .packets_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            return Err("rate_limited");
        }
        self.first = false;
        let base = if self.auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        };
        // Derive the policy while the response still owns its TLVs. Taking
        // the only copy first would hide header/BER MTU requirements.
        let plan = self.plan.get_or_insert_with(|| {
            TransportPlan::new(&self.response, self.source, base, self.srv6)
        });
        // The last copy can take the buffer; earlier copies need it again.
        let mut data = if self.remaining <= 1 {
            std::mem::take(&mut self.response.data)
        } else {
            self.response.data.clone()
        };
        let sequence = if self.stateful {
            self.session.peek_sequence_number()
        } else {
            u32::from_be_bytes(data[..4].try_into().expect("validated response base"))
        };
        data[..4].copy_from_slice(&sequence.to_be_bytes());
        // Echoes keep the values assembly left in them. Refreshing an echo
        // would change bytes covered by its copied HMAC.
        if self.response.tlv_processed {
            refresh_telemetry(&mut data, base, &self.session, self.stateful);
        }
        if plan.unsupported_srh {
            super::set_return_path_u_flag_in_response(&mut data, base);
        }
        let mut attempt = Attempt::new(plan);
        let reason = loop {
            if attempt.marking != Marking::Unavailable
                && self.marking_unavailable_for == Some(attempt.target)
            {
                // An earlier copy found this target cannot be marked. Start
                // where that fallback ended, so this copy is shaped,
                // timestamped and signed once, not three times.
                attempt.give_up_marking(&mut data, base, self.response.cos_request.is_some());
            }
            attempt.options.apply_tos = attempt.marking != Marking::Unavailable;
            let mut third_dscp = false;
            if let Some(policy) = &self.response.cos_reply_policy {
                let to_source = attempt.target == self.source;
                let fallback = attempt.marking != Marking::Requested;
                let selection = policy.select(to_source, self.received_dscp, fallback);
                // Without a working marking operation, an OS-selected DSCP
                // cannot be assumed to satisfy a restricted destination set.
                if !attempt.options.apply_tos
                    && policy.allowed(to_source) != crate::cos_policy::DscpSet::all()
                {
                    log::debug!(
                        "Cannot enforce restricted DSCP policy for {}",
                        attempt.target
                    );
                    break "cos_policy";
                }
                let (ecn, rpe) = policy.ecn(fallback, attempt.marking_reported);
                attempt.options.tos = crate::tos::Tos::new(selection.value, ecn).0;
                policy.apply(&mut data, base, selection, rpe);
                third_dscp = selection.third_value;
            }
            let mut clamped = false;
            let mut ber_conformance = self.response.ber_conformance;
            let mut tlv_conformance = self.response.tlv_conformance;
            if third_dscp {
                tlv_conformance.insert(crate::tlv::TlvConformanceReason::CosDscpFallback);
            }
            if attempt.marking_reported {
                tlv_conformance.insert(crate::tlv::TlvConformanceReason::CosMarkingUnavailable);
            }
            let (target, options) = (attempt.target, &attempt.options);
            let budget = if options.dont_fragment {
                payload_cap(target, options, attempt.mtu_refreshed)
            } else {
                Ok(usize::MAX)
            };
            let result = budget.and_then(|route_cap| {
                let admin_cap = self
                    .response
                    .reflected_control
                    .map_or(usize::MAX, |b| usize::from(b.max_size));
                let cap = route_cap.min(admin_cap);
                // Shaping needs a copy: another route may allow the untrimmed
                // reply and must not inherit this attempt's C flag/padding.
                // Otherwise reuse data; T3 and generated HMACs are overwritten
                // on every attempt, including after an untrimmed send fails.
                let mut shaped;
                let attempt = if data.len() > cap {
                    shaped = data.clone();
                    &mut shaped
                } else {
                    &mut data
                };
                clamped = fit_reply(
                    attempt,
                    base,
                    cap,
                    self.response.reflected_control.is_some(),
                    &mut ber_conformance,
                )?;
                if tlv_conformance.has_header_reasons() {
                    let mut pos = base;
                    let mut retained = 0;
                    while let Some(tlv) = TlvSpan::at(attempt, pos) {
                        retained += usize::from(is_reflected_header(&tlv) && tlv.flags.processed());
                        pos = tlv.end();
                    }
                    tlv_conformance.retain_headers(retained);
                }
                if clamped && has_control_c(attempt, base) {
                    // Ties mean both constraints bind. Rebuild these reasons
                    // for each attempt, so a failed route never gets counted.
                    if route_cap <= admin_cap {
                        tlv_conformance.insert(crate::tlv::TlvConformanceReason::Type12RouteMtu);
                    }
                    if admin_cap <= route_cap {
                        tlv_conformance.insert(crate::tlv::TlvConformanceReason::Type12SizeLimit);
                    }
                }
                let timestamp = crate::time::generate_timestamp(self.clock);
                // Reflector Timestamp offset: after the 4-byte Sequence Number,
                // plus 12 MBZ bytes in authenticated mode (RFC 8762 §4.3.2).
                let offset = crate::packets::reflected_timestamp_offset(self.auth);
                attempt[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
                if let Some(key) = &self.key {
                    if self.auth {
                        // The base-packet HMAC covers the octets before it
                        // and ends the base (RFC 8762 §4.3.2).
                        let hmac =
                            crate::crypto::compute_packet_hmac(key, attempt, AUTH_HMAC_OFFSET);
                        attempt[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE].copy_from_slice(&hmac);
                    }
                    if self.response.tlv_hmac_generated {
                        sign_tlvs(attempt, base, key);
                    }
                }
                send(attempt, target, options).and_then(|sent| {
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
                    counters.record_reflected();
                    counters.record_ber_conformance(ber_conformance);
                    counters.record_tlv_conformance(tlv_conformance);
                    self.remaining -= 1;
                    return Ok(sequence);
                }
                Err(e) if attempt.options.dont_fragment && is_message_too_large(&e) => {
                    // MTU races must not strip SRH, source pinning or CoS. A
                    // fresh route query and re-shape gets one bounded retry.
                    if attempt.mtu_refreshed {
                        break "mtu_exceeded";
                    }
                    attempt.mtu_refreshed = true;
                }
                Err(e) if is_cos_apply_error(&e) && attempt.options.apply_tos => {
                    // Only an option-setting failure establishes inability to
                    // mark. A datagram/routing failure says nothing about CoS.
                    let fallback_dscp = if let Some(policy) = &self.response.cos_reply_policy {
                        let to_source = attempt.target == self.source;
                        policy.select(to_source, self.received_dscp, true).value
                    } else {
                        self.received_dscp
                    };
                    let not_ect = super::cos_unable_fallback_tos(fallback_dscp);
                    let cos_requested = self.response.cos_request.is_some();
                    if cos_requested
                        && attempt.marking == Marking::Requested
                        && attempt.options.tos != not_ect
                    {
                        super::set_cos_policy_rejected(&mut data, base);
                        attempt.marking = Marking::NotEct;
                        attempt.options.tos = not_ect;
                    } else {
                        // Neither EC1 nor the Not-ECT fallback can be applied
                        // (draft-ietf-bpm-stamp-cos-ecn-00 §3.2). Preserve
                        // routing and sign RPE=01.
                        attempt.give_up_marking(&mut data, base, cos_requested);
                        self.marking_unavailable_for = Some(attempt.target);
                    }
                }
                Err(e) if is_reply_too_large(&e) => {
                    log::debug!("reply cannot fit the route MTU: {e}");
                    break "mtu_exceeded";
                }
                Err(e) if is_local_send_error(&e) => {
                    // The socket, not the reply's route, failed. Changing the
                    // return path would wrongly report it as unusable.
                    log::debug!("reflector cannot send to {}: {e}", attempt.target);
                    break "send_failed";
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
                    break "send_failed";
                }
                Err(e) => {
                    if !attempt.fall_back_route(
                        &mut data,
                        base,
                        self.source,
                        self.response.reply_source,
                        self.response.cos_reply_policy.is_some(),
                    ) {
                        log::debug!("reflector send to {} failed: {e}", attempt.target);
                        break "send_failed";
                    }
                }
            }
        };
        Err(reason)
    }
}

/// How far the CoS marking fallback has gone for the current target
/// (draft-ietf-bpm-stamp-cos-ecn-00 §3.2). Each option-setting failure moves
/// one step down; it never moves back for the same target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Marking {
    /// Apply the admitted DSCP and the requested ECN.
    Requested,
    /// The requested marking could not be set: retry with Not-ECT.
    NotEct,
    /// No marking can be set: send with the OS default and report RPE=01.
    Unavailable,
}

/// Where one copy's send attempts stand. Every retry moves exactly one of
/// these forward (a marking step, the single MTU refresh, or one route
/// fallback), which is what bounds the send loop.
struct Attempt {
    target: SocketAddr,
    options: SendOptions,
    marking: Marking,
    /// RPE=01 has been written into a processed CoS TLV of this copy.
    marking_reported: bool,
    /// The route MTU has been queried afresh after EMSGSIZE on this route.
    mtu_refreshed: bool,
}

impl Attempt {
    fn new(plan: &TransportPlan) -> Self {
        Self {
            target: plan.target,
            options: plan.options.clone(),
            marking: if plan.options.apply_tos {
                Marking::Requested
            } else {
                Marking::Unavailable
            },
            marking_reported: false,
            mtu_refreshed: false,
        }
    }

    /// Stop marking this copy. A CoS reply reports the refused request and
    /// RPE=01 in its processed CoS TLVs.
    fn give_up_marking(&mut self, data: &mut [u8], base: usize, cos_requested: bool) {
        if cos_requested {
            super::set_cos_policy_rejected(data, base);
            self.marking_reported |= super::reply_bytes::set_cos_marking_unavailable(data, base);
        }
        self.marking = Marking::Unavailable;
    }

    /// Drop the next routing request the failed send depended on, in RFC 9503
    /// §4 order: the arrival-link pin, the SRH, source pinning, and finally
    /// the alternate destination in favour of the sender. Returns false when
    /// nothing is left to drop.
    fn fall_back_route(
        &mut self,
        data: &mut [u8],
        base: usize,
        source: SocketAddr,
        reply_source: Option<IpAddr>,
        cos_policy: bool,
    ) -> bool {
        self.mtu_refreshed = false;
        if self.options.egress_ifindex.take().is_some() || self.options.srh.take().is_some() {
            // The arrival link or segment list cannot carry the reply.
            super::set_return_path_u_flag_in_response(data, base);
        } else if self.options.source.take().is_some() {
            // RFC 9503 source pinning is best-effort.
        } else if self.target != source {
            self.target = source;
            if cos_policy {
                // The sender's own destination policy applies afresh.
                self.marking = Marking::Requested;
                self.marking_reported = false;
            }
            self.options.source = reply_source
                .filter(|s| crate::reply_source::supported() && s.is_ipv4() == source.is_ipv4());
            super::set_return_path_u_flag_in_response(data, base);
        } else {
            return false;
        }
        true
    }
}

/// Whether this platform's route-MTU lookup covers a standalone BER reply to
/// `target`, so the reply can be sized and sent with fragmentation disabled.
fn ber_route_mtu_supported(target: IpAddr) -> bool {
    #[cfg(target_os = "macos")]
    {
        crate::net_policy::macos_mtu::native_unicast(target)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = target;
        cfg!(any(target_os = "linux", target_os = "windows"))
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod ber_tests;

#[cfg(test)]
mod diagnostics_tests;

#[cfg(test)]
mod benchmarks;

#[cfg(test)]
mod type12_diagnostics_tests;

#[cfg(test)]
mod header_diagnostics_tests;

#[cfg(test)]
mod cos_control_diagnostics_tests;

#[cfg(test)]
mod peer_c_diagnostics_tests;

#[cfg(test)]
mod dscp_tests;

#[cfg(any(target_os = "macos", test))]
mod send_buffer;
