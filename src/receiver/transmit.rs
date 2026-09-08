//! Finalize every datagram at its actual send attempt, including burst copies.

use super::{RateLimiter, ReflectorCounters, StampResponse, AUTH_BASE_SIZE, UNAUTH_BASE_SIZE};
use crate::{clock_format::ClockFormat, crypto::HmacKey, session::Session, tlv::ReturnPathAction};
use std::{
    cmp::Ordering as CmpOrdering,
    collections::BinaryHeap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub(super) struct SendOptions {
    pub tos: u8,
    pub source: Option<IpAddr>,
    pub srh: Option<Vec<u8>>,
}

pub(super) struct Transmission {
    response: StampResponse,
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

    /// One owner calls this for every send on its socket. Retries retain the
    /// sequence but refresh T3 and signatures; successful sends update state.
    pub fn send_next(
        &mut self,
        counters: &ReflectorCounters,
        limiter: &RateLimiter,
        mut send: impl FnMut(&[u8], SocketAddr, &SendOptions) -> io::Result<usize>,
    ) -> Option<u32> {
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
        let mut data = self.response.data.clone();
        let base = if self.auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        };
        let sequence = if self.stateful {
            self.session.generate_sequence_number()
        } else {
            u32::from_be_bytes(data[..4].try_into().expect("validated response base"))
        };
        data[..4].copy_from_slice(&sequence.to_be_bytes());
        refresh_telemetry(&mut data, base, &self.session, self.stateful);
        let mut target = match self.response.return_path_action {
            ReturnPathAction::AlternateAddress(addr) => addr,
            _ => self.source,
        };
        let mut options = SendOptions {
            tos: self.response.cos_request.map_or(0, |(d, e)| (d << 2) | e),
            source: self
                .response
                .reply_source
                .filter(|s| crate::reply_source::supported() && s.is_ipv4() == target.is_ipv4()),
            srh: None,
        };
        if let ReturnPathAction::Srv6Forward(sids) = &self.response.return_path_action {
            if self.srv6 && target.is_ipv6() {
                options.srh = crate::srv6::build_srh(sids);
            }
            if options.srh.is_none() {
                super::set_return_path_u_flag_in_response(&mut data, base);
            }
        }
        let mut cos_fallback = false;
        loop {
            let timestamp = crate::time::generate_timestamp(self.clock);
            let offset = if self.auth { 16 } else { 4 };
            data[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
            if let Some(key) = &self.key {
                if self.auth {
                    let hmac = crate::crypto::compute_packet_hmac(key, &data, 96);
                    data[96..112].copy_from_slice(&hmac);
                }
                sign_tlvs(&mut data, base, key);
            }
            match send(&data, target, &options) {
                Ok(_) => {
                    self.session.record_transmitted();
                    self.session.record_reflection(sequence, timestamp);
                    counters.packets_reflected.fetch_add(1, Ordering::Relaxed);
                    self.remaining -= 1;
                    return Some(sequence);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // UDP queue pressure is a failed transmission, never a
                    // reason to downgrade requested routing/CoS metadata.
                    log::debug!("reflector send queue full: {e}");
                    break;
                }
                Err(e) => {
                    if options.srh.take().is_some() {
                        super::set_return_path_u_flag_in_response(&mut data, base);
                    } else if options.source.take().is_some() {
                        // RFC 9503 source pinning is best-effort.
                    } else if target != self.source {
                        target = self.source;
                        options.source = self.response.reply_source.filter(|s| {
                            crate::reply_source::supported() && s.is_ipv4() == target.is_ipv4()
                        });
                        super::set_return_path_u_flag_in_response(&mut data, base);
                    } else if self.response.cos_request.is_some() && !cos_fallback {
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

fn refresh_telemetry(data: &mut [u8], base: usize, session: &Session, stateful: bool) {
    // Assembly deliberately skips semantic updates for an entire malformed
    // chain, including otherwise valid TLVs preceding the malformed tail.
    let mut scan = base;
    while scan + 4 <= data.len() {
        let len = u16::from_be_bytes([data[scan + 2], data[scan + 3]]) as usize;
        if data[scan] & 0x40 != 0 || scan + 4 + len > data.len() {
            return;
        }
        scan += 4 + len;
    }
    let mut pos = base;
    while pos + 4 <= data.len() {
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        if pos + 4 + len > data.len() {
            break;
        }
        let flags = data[pos];
        let kind = data[pos + 1];
        if flags & 0x40 != 0 {
            break;
        } // malformed tail must stay opaque
        if flags & 0xA0 == 0 {
            let value = &mut data[pos + 4..pos + 4 + len];
            match (kind, len) {
                (5, 12) => {
                    value[4..8].copy_from_slice(&session.get_received_count().to_be_bytes());
                    value[8..12].copy_from_slice(&session.get_transmitted_count().to_be_bytes());
                }
                (7, 16) if stateful => {
                    let (seq, ts) = session.get_last_reflection();
                    value[..4].copy_from_slice(&seq.to_be_bytes());
                    value[4..12].copy_from_slice(&ts.to_be_bytes());
                }
                (7, 16) => value[..12].fill(0),
                _ => {}
            }
        }
        pos += 4 + len;
    }
}

/// Assembly puts its HMAC after all TLVs (including opaque malformed tails),
/// possibly followed by symmetric zero padding. Only called on generated replies.
fn sign_tlvs(data: &mut [u8], base: usize, key: &HmacKey) {
    if data.len() < base + 20 {
        return;
    }
    for pos in (base..=data.len() - 20).rev() {
        if data[pos + 1..pos + 4] == [8, 0, 16] && data[pos + 20..].iter().all(|b| *b == 0) {
            let mut input = data[..4].to_vec();
            input.extend_from_slice(&data[base..pos]);
            data[pos + 4..pos + 20].copy_from_slice(&key.compute(&input));
            return;
        }
    }
}

struct Pending {
    at: Instant,
    order: u64,
    transmission: Transmission,
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
    pub fn push_at(&mut self, transmission: Transmission, at: Instant) {
        self.order = self.order.wrapping_add(1);
        self.pending.push(Pending {
            at,
            order: self.order,
            transmission,
        });
    }
    pub fn schedule_next(&mut self, transmission: Transmission) {
        if transmission.remaining > 0 {
            let at = Instant::now() + transmission.interval;
            self.push_at(transmission, at);
        }
    }
    pub fn pop_due(&mut self) -> Option<Transmission> {
        if self.deadline().is_some_and(|at| at <= Instant::now()) {
            self.pending.pop().map(|p| p.transmission)
        } else {
            None
        }
    }
}

/// A single syscall carries CoS, source pinning, and SRH together on Linux.
/// Other Unix systems set TOS immediately before sendmsg; each backend has one
/// send owner and never awaits between that setting and the syscall.
#[cfg(unix)]
pub(super) fn send_datagram(
    fd: std::os::fd::RawFd,
    payload: &[u8],
    dst: SocketAddr,
    options: &SendOptions,
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
    let mut control = Vec::<usize>::new();
    #[cfg(target_os = "linux")]
    {
        // usize allocation guarantees cmsghdr alignment; zero initialize all padding.
        fn append(control: &mut Vec<usize>, level: i32, kind: i32, bytes: &[u8]) {
            let start = control.len() * std::mem::size_of::<usize>();
            let space = unsafe { libc::CMSG_SPACE(bytes.len() as _) } as usize;
            control.resize((start + space).div_ceil(std::mem::size_of::<usize>()), 0);
            unsafe {
                let header = control
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(start)
                    .cast::<libc::cmsghdr>();
                (*header).cmsg_level = level;
                (*header).cmsg_type = kind;
                (*header).cmsg_len = libc::CMSG_LEN(bytes.len() as _) as _;
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), libc::CMSG_DATA(header), bytes.len());
            }
        }
        let tos = options.tos as libc::c_int;
        append(
            &mut control,
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
        if let Some(source) = options.source {
            if source.is_ipv4() != dst.is_ipv4() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "source/destination family mismatch",
                ));
            }
            match source {
                IpAddr::V4(ip) => {
                    let mut info: libc::in_pktinfo = unsafe { std::mem::zeroed() };
                    info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                    append(&mut control, libc::IPPROTO_IP, libc::IP_PKTINFO, unsafe {
                        std::slice::from_raw_parts(
                            std::ptr::addr_of!(info).cast(),
                            std::mem::size_of_val(&info),
                        )
                    });
                }
                IpAddr::V6(ip) => {
                    let mut info: libc::in6_pktinfo = unsafe { std::mem::zeroed() };
                    info.ipi6_addr.s6_addr = ip.octets();
                    append(
                        &mut control,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_PKTINFO,
                        unsafe {
                            std::slice::from_raw_parts(
                                std::ptr::addr_of!(info).cast(),
                                std::mem::size_of_val(&info),
                            )
                        },
                    );
                }
            }
        }
        if let Some(srh) = &options.srh {
            append(&mut control, libc::IPPROTO_IPV6, libc::IPV6_RTHDR, srh);
        }
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = (control.len() * std::mem::size_of::<usize>()) as _;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let tos = options.tos as libc::c_int;
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
            return Err(io::Error::last_os_error());
        }
    }
    let sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    if sent < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(sent as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(auth: bool, action: ReturnPathAction) -> Transmission {
        let mut data = vec![0; if auth { 112 } else { 44 }];
        data.extend_from_slice(&[0, 4, 0, 4, 184, 0, 0, 0]);
        data.extend_from_slice(&[0, 10, 0, 4, 0, 0, 0, 0]);
        if auth {
            data.extend_from_slice(&[0, 8, 0, 16]);
            data.extend_from_slice(&[0; 16]);
            data.extend_from_slice(&[0; 9]);
        }
        let response = StampResponse {
            data,
            cos_request: Some((46, 0)),
            return_path_action: action,
            reflected_control: Some(super::super::ReflectedControlBehavior {
                extra_copies: 2,
                interval_ns: 1,
                suppress_reply_ext_headers: false,
            }),
            reply_source: Some("127.0.0.2".parse().unwrap()),
        };
        Transmission::new(
            response,
            Arc::new(Session::new(0)),
            "127.0.0.1:4000".parse().unwrap(),
            ClockFormat::NTP,
            auth,
            true,
            auth.then(|| HmacKey::new(vec![0xCD; 16]).unwrap()),
            0,
            true,
        )
    }

    fn verify_signatures(data: &[u8]) {
        let key = HmacKey::new(vec![0xCD; 16]).unwrap();
        assert_eq!(
            &data[96..112],
            &crate::crypto::compute_packet_hmac(&key, data, 96)
        );
        let pos = 128; // CoS + Return Path, then HMAC, then symmetric zero padding.
        let mut input = data[..4].to_vec();
        input.extend_from_slice(&data[112..pos]);
        assert_eq!(&data[pos + 4..pos + 20], &key.compute(&input));
    }

    #[test]
    fn every_copy_retries_alternate_with_source_cos_and_valid_signatures() {
        let mut transmission = sample(
            true,
            ReturnPathAction::AlternateAddress("[::1]:4000".parse().unwrap()),
        );
        let counters = ReflectorCounters::new();
        let limiter = RateLimiter::new(0);
        let mut attempts = 0;
        for seq in 0..3 {
            assert_eq!(
                transmission.send_next(&counters, &limiter, |data, target, options| {
                    attempts += 1;
                    if target.is_ipv6() {
                        return Err(io::Error::new(
                            io::ErrorKind::NetworkUnreachable,
                            "injected alternate failure",
                        ));
                    }
                    assert_eq!(target, "127.0.0.1:4000".parse::<SocketAddr>().unwrap());
                    if crate::reply_source::supported() {
                        assert_eq!(options.source, Some("127.0.0.2".parse().unwrap()));
                    }
                    assert_eq!(options.tos, 184);
                    assert_ne!(data[120] & 0x80, 0);
                    verify_signatures(data);
                    Ok(data.len())
                }),
                Some(seq)
            );
        }
        assert_eq!(attempts, 6);
        assert_eq!(transmission.session.get_transmitted_count(), 3);
        assert_eq!(counters.packets_reflected.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn srv6_failure_keeps_cos_and_marks_every_copy() {
        let mut transmission = sample(
            true,
            ReturnPathAction::Srv6Forward(vec!["::1".parse().unwrap()]),
        );
        transmission.source = "[::1]:4000".parse().unwrap();
        transmission.response.reply_source = Some("::1".parse().unwrap());
        let counters = ReflectorCounters::new();
        let limiter = RateLimiter::new(0);
        for seq in 0..3 {
            let mut attempts = 0;
            assert_eq!(
                transmission.send_next(&counters, &limiter, |data, _, options| {
                    attempts += 1;
                    assert_eq!(options.tos, 184);
                    if crate::reply_source::supported() {
                        assert_eq!(options.source, Some("::1".parse().unwrap()));
                    }
                    if attempts == 1 {
                        assert!(options.srh.is_some());
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "injected SRH failure",
                        ));
                    }
                    assert!(options.srh.is_none());
                    assert_ne!(data[120] & 0x80, 0);
                    verify_signatures(data);
                    Ok(data.len())
                }),
                Some(seq)
            );
            assert_eq!(attempts, 2);
        }
    }

    #[test]
    fn cos_failure_uses_zero_ecn_fallback_and_resigns() {
        let mut transmission = sample(true, ReturnPathAction::Normal);
        transmission.response.reply_source = None;
        transmission.received_dscp = 10;
        let counters = ReflectorCounters::new();
        let limiter = RateLimiter::new(0);
        let mut attempts = 0;
        assert!(transmission
            .send_next(&counters, &limiter, |data, _, options| {
                attempts += 1;
                if attempts == 1 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "injected CoS failure",
                    ));
                }
                assert_eq!(options.tos, 40);
                assert_eq!(data[117] & 3, 1);
                assert_eq!((data[118] >> 4) & 3, 2);
                verify_signatures(data);
                Ok(data.len())
            })
            .is_some());
        assert_eq!(attempts, 2);
    }

    #[test]
    fn unsuccessful_sends_do_not_advance_transmit_or_follow_up_counts() {
        let mut transmission = sample(false, ReturnPathAction::Normal);
        let counters = ReflectorCounters::new();
        let limiter = RateLimiter::new(0);
        assert!(transmission
            .send_next(&counters, &limiter, |_, _, _| Err(
                io::ErrorKind::WouldBlock.into()
            ))
            .is_none());
        assert_eq!(transmission.session.get_transmitted_count(), 0);
        assert_eq!(transmission.session.get_last_reflection(), (0, 0));
        assert_eq!(counters.packets_dropped.load(Ordering::Relaxed), 1);
        assert_eq!(transmission.remaining, 0);
    }

    #[test]
    fn malformed_tail_stays_opaque_while_final_hmac_is_refreshed() {
        let key = HmacKey::new(vec![0xAB; 16]).unwrap();
        let mut data = vec![0; 44];
        data[3] = 42;
        data.extend_from_slice(&[0, 5, 0, 12]);
        data.extend_from_slice(&[99; 12]);
        data.extend_from_slice(&[0x40, 1, 255, 255, 7]);
        let hmac_offset = data.len();
        data.extend_from_slice(&[0, 8, 0, 16]);
        data.extend_from_slice(&[0; 16]);
        data.extend_from_slice(&[0; 13]);
        let before = data.clone();
        refresh_telemetry(&mut data, 44, &Session::new(0), true);
        assert_eq!(data, before);
        sign_tlvs(&mut data, 44, &key);
        let mut input = data[..4].to_vec();
        input.extend_from_slice(&data[44..hmac_offset]);
        assert_eq!(
            &data[hmac_offset + 4..hmac_offset + 20],
            &key.compute(&input)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn every_copy_pins_source_on_the_actual_socket() {
        use std::os::fd::AsRawFd;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let sender = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let mut transmission = sample(false, ReturnPathAction::Normal);
        transmission.source = receiver.local_addr().unwrap();
        let counters = ReflectorCounters::new();
        let limiter = RateLimiter::new(0);
        for seq in 0..3 {
            assert_eq!(
                transmission.send_next(&counters, &limiter, |data, target, options| send_datagram(
                    sender.as_raw_fd(),
                    data,
                    target,
                    options
                )),
                Some(seq)
            );
            let mut bytes = [0; 256];
            let (_, from) = receiver.recv_from(&mut bytes).unwrap();
            assert_eq!(from.ip(), "127.0.0.2".parse::<IpAddr>().unwrap());
        }
    }
}
