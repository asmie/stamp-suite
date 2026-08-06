//! Hardware-assisted timestamping support (F1).
//!
//! Provides a capability probe and `--hwtstamp` mode enum the rest of
//! the codebase consults when deciding which `TimestampMethod` to
//! advertise in the RFC 8972 §4.3 Timestamp Information TLV.
//!
//! **Defensive posture.** Per the project's hardware-dependent
//! contract: this module never panics and never refuses to start the
//! binary. Every capability step (probe, SO_TIMESTAMPING enablement,
//! SIOCSHWTSTAMP filters, per-packet cmsg extraction) degrades to the
//! next-best timestamp tier on failure, and `--hwtstamp on` warns when
//! the operator's explicit hardware request cannot be honoured (see
//! `startup_action`).
//!
//! **Current scope.** [`probe`](crate::hwtstamp::probe) performs a real
//! `ETHTOOL_GET_TS_INFO` ioctl (Linux) against the interface owning
//! `--local-addr` (resolved via
//! [`interface_for_addr`](crate::hwtstamp::interface_for_addr)). With
//! the `hwtstamp` cargo feature, the
//! kernel read paths are active: RX timestamps via `SO_TIMESTAMPING` /
//! `SCM_TIMESTAMPING` cmsgs (T2 on the reflector, T4 on the sender), TX
//! timestamps via `MSG_ERRQUEUE` with `SOF_TIMESTAMPING_OPT_ID`
//! correlation (correcting the sender's stored T1 and the reflector's
//! Follow-Up Telemetry record), and an optional NIC-hardware tier under
//! `--hwtstamp on` (`SIOCSHWTSTAMP`, falls back gracefully). macOS gets
//! the kernel software RX tier via `SO_TIMESTAMP`; Windows compiles to a
//! no-op (the pnet receiver has no socket to timestamp). NOTE the PHC
//! clock-domain caveat for the hardware tier in `doc/architecture.md`:
//! hardware timestamps are only comparable with the peer's CLOCK_REALTIME
//! when the PHC is synchronized (ptp4l/phc2sys).

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::tlv::TimestampMethod;

/// Operator preference for hardware-assisted timestamping. Selected via
/// the `--hwtstamp` CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HwTsMode {
    /// Use kernel *software* timestamps when the build supports them
    /// (feature "hwtstamp"); transparently fall back to userspace
    /// timestamps otherwise. Never reconfigures the NIC and needs no
    /// privileges. This is the default — safe to leave on every host.
    #[default]
    Auto,
    /// Additionally attempt NIC *hardware* timestamping: sets the NIC
    /// timestamp filters (SIOCSHWTSTAMP, needs CAP_NET_ADMIN) and requests
    /// the raw-hardware tier, falling back to kernel software timestamps
    /// with a warning when any step fails. Operators are responsible for
    /// PHC synchronization (ptp4l/phc2sys) — see doc/architecture.md.
    On,
    /// Always use software timestamping, even when HW is available.
    /// Useful for A/B-style measurement comparisons or as a fallback
    /// when a particular NIC's HW path is suspect.
    Off,
}

/// Result of the per-interface hardware-timestamping capability probe.
///
/// Constructed by [`probe`] from the NIC's ETHTOOL_GET_TS_INFO reply;
/// consumed by `startup_action` reporting today and by the future
/// recvmsg/sendmsg paths that will choose between HW and SW timestamping
/// per packet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HwTsCapability {
    /// True when the kernel + NIC pair reports support for
    /// `SOF_TIMESTAMPING_RX_HARDWARE`.
    pub rx_hw: bool,
    /// True when the kernel + NIC pair reports support for
    /// `SOF_TIMESTAMPING_TX_HARDWARE`.
    pub tx_hw: bool,
    /// True when the PTP hardware clock (`/dev/ptpN`) is exposed by
    /// the driver — informational; the receive/send paths don't
    /// require this directly.
    pub ptp_supported: bool,
}

impl HwTsCapability {
    /// True when at least one of rx_hw / tx_hw is supported. Reserved for
    /// the future cmsg path's decision of whether to attempt HW timestamping.
    #[must_use]
    pub fn any_hw_supported(&self) -> bool {
        self.rx_hw || self.tx_hw
    }

    /// Maps an ethtool `so_timestamping` bitmask + PHC index (the reply of
    /// the ETHTOOL_GET_TS_INFO ioctl) onto the capability flags.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn from_ethtool(so_timestamping: u32, phc_index: i32) -> Self {
        use ::nix::libc;
        Self {
            rx_hw: so_timestamping & libc::SOF_TIMESTAMPING_RX_HARDWARE != 0,
            tx_hw: so_timestamping & libc::SOF_TIMESTAMPING_TX_HARDWARE != 0,
            ptp_supported: phc_index >= 0,
        }
    }
}

/// ETHTOOL_GET_TS_INFO command value, per linux/ethtool.h. Not exposed
/// by the libc crate (which does provide `SIOCETHTOOL` and `ifreq`), so
/// defined locally.
#[cfg(target_os = "linux")]
const ETHTOOL_GET_TS_INFO: u32 = 0x41;

/// Reply structure of ETHTOOL_GET_TS_INFO, per `struct ethtool_ts_info`
/// in linux/ethtool.h.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EthtoolTsInfo {
    cmd: u32,
    so_timestamping: u32,
    phc_index: i32,
    tx_types: u32,
    tx_reserved: [u32; 3],
    rx_filters: u32,
    rx_reserved: [u32; 3],
}

/// Queries ETHTOOL_GET_TS_INFO for `interface`. Returns `None` when the
/// interface doesn't exist or the kernel/driver rejects the ioctl —
/// callers treat `None` as "no capabilities" (graceful fallback, never
/// fatal, per the project's defensive hardware-features contract).
#[cfg(target_os = "linux")]
fn ethtool_ts_info(interface: &str) -> Option<EthtoolTsInfo> {
    use std::os::fd::AsRawFd;

    use ::nix::libc;

    if interface.len() >= libc::IFNAMSIZ {
        return None;
    }
    // Any datagram socket works as the ioctl carrier.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;

    let mut info = EthtoolTsInfo {
        cmd: ETHTOOL_GET_TS_INFO,
        so_timestamping: 0,
        phc_index: -1,
        tx_types: 0,
        tx_reserved: [0; 3],
        rx_filters: 0,
        rx_reserved: [0; 3],
    };
    // SAFETY: `ifr` is fully zeroed before use; the interface name is
    // shorter than IFNAMSIZ (checked above) so the copy stays in bounds
    // and leaves a terminating NUL; `ifru_data` points at a live,
    // properly sized `EthtoolTsInfo` for the duration of the ioctl call,
    // and the kernel writes only within that struct for this command.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (dst, src) in ifr.ifr_name.iter_mut().zip(interface.as_bytes()) {
            *dst = *src as libc::c_char;
        }
        ifr.ifr_ifru.ifru_data = (&mut info as *mut EthtoolTsInfo).cast::<libc::c_char>();
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCETHTOOL, &mut ifr) != 0 {
            return None;
        }
    }
    Some(info)
}

/// Probes timestamping capabilities of `interface` via the
/// ETHTOOL_GET_TS_INFO ioctl.
///
/// Returns the all-false default when `interface` is `None` (e.g. a
/// wildcard bind, where no single interface applies), when the interface
/// is unknown or the driver rejects the query, and on non-Linux targets
/// (SO_TIMESTAMPING is Linux-specific). Never fails and never panics.
#[must_use]
pub fn probe(interface: Option<&str>) -> HwTsCapability {
    #[cfg(target_os = "linux")]
    {
        if let Some(name) = interface {
            if let Some(info) = ethtool_ts_info(name) {
                return HwTsCapability::from_ethtool(info.so_timestamping, info.phc_index);
            }
            log::debug!("hwtstamp: ETHTOOL_GET_TS_INFO unavailable for {name}");
        }
        HwTsCapability::default()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = interface;
        HwTsCapability::default()
    }
}

/// What a socket actually delivers after [`enable_socket_timestamping`]:
/// the kernel may accept the software tier but reject the hardware tier,
/// or reject timestamping entirely (non-Linux, ancient kernels).
#[cfg(feature = "hwtstamp")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnabledTimestamping {
    /// Kernel receive timestamps will arrive in cmsgs.
    pub rx_kernel: bool,
    /// Raw hardware receive timestamps were requested and accepted.
    pub rx_hw: bool,
    /// Transmit timestamps will arrive on the error queue.
    pub tx_kernel: bool,
    /// Raw hardware transmit timestamps were requested and accepted.
    pub tx_hw: bool,
}

/// A kernel-provided packet timestamp extracted from a control message.
#[cfg(feature = "hwtstamp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelTimestamp {
    /// Seconds since the Unix epoch (CLOCK_REALTIME for software stamps,
    /// the NIC PHC clock for hardware stamps — see the PHC caveat in
    /// `doc/architecture.md`).
    pub secs: i64,
    /// Sub-second nanoseconds.
    pub nanos: u32,
    /// True when this came from the NIC (`hw_raw` slot), false for the
    /// kernel-software slot.
    pub hardware: bool,
}

/// A transmit timestamp recovered from the socket error queue.
#[cfg(feature = "hwtstamp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxTimestampReport {
    /// `SOF_TIMESTAMPING_OPT_ID` counter: 0 for the first sendmsg after
    /// enablement, incrementing per send. Callers correlate this with
    /// their own send counter.
    pub opt_id: u32,
    /// STAMP wire-format timestamp (NTP or PTP per the requested format).
    pub timestamp: u64,
    /// True when the NIC produced the timestamp.
    pub hardware: bool,
}

/// Enables kernel timestamping on `fd` with a single `SO_TIMESTAMPING`
/// bitmask (a second setsockopt would overwrite the first, so RX and TX
/// wishes are combined in one call). `want_hw` additionally requests the
/// raw-hardware tier and silently retries without it when the kernel
/// refuses. Never fails: on error the returned struct is all-false and
/// the caller stays on userspace timestamps.
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
pub fn enable_socket_timestamping(
    fd: std::os::fd::RawFd,
    rx: bool,
    tx: bool,
    want_hw: bool,
) -> EnabledTimestamping {
    use ::nix::sys::socket::{setsockopt, sockopt, TimestampingFlag};

    let mut flags = TimestampingFlag::SOF_TIMESTAMPING_SOFTWARE;
    if rx {
        flags |= TimestampingFlag::SOF_TIMESTAMPING_RX_SOFTWARE;
    }
    if tx {
        flags |= TimestampingFlag::SOF_TIMESTAMPING_TX_SOFTWARE
            | TimestampingFlag::SOF_TIMESTAMPING_OPT_ID
            | TimestampingFlag::SOF_TIMESTAMPING_OPT_TSONLY;
    }
    let mut hw_flags = flags;
    if want_hw {
        hw_flags |= TimestampingFlag::SOF_TIMESTAMPING_RAW_HARDWARE;
        if rx {
            hw_flags |= TimestampingFlag::SOF_TIMESTAMPING_RX_HARDWARE;
        }
        if tx {
            hw_flags |= TimestampingFlag::SOF_TIMESTAMPING_TX_HARDWARE;
        }
    }

    // SAFETY: the caller guarantees `fd` is a live socket descriptor for
    // the duration of this call; BorrowedFd does not take ownership.
    let bfd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let hw_ok = want_hw && setsockopt(&bfd, sockopt::Timestamping, &hw_flags).is_ok();
    let sw_ok = hw_ok || setsockopt(&bfd, sockopt::Timestamping, &flags).is_ok();
    if !sw_ok {
        log::warn!("SO_TIMESTAMPING rejected by kernel; using userspace timestamps");
        return EnabledTimestamping::default();
    }
    EnabledTimestamping {
        rx_kernel: rx,
        rx_hw: rx && hw_ok,
        tx_kernel: tx,
        tx_hw: tx && hw_ok,
    }
}

/// macOS: kernel software *receive* timestamps via `SO_TIMESTAMP`
/// (microsecond resolution, `SCM_TIMESTAMP` cmsg). There is no public
/// TX-timestamp or hardware path on Darwin.
#[cfg(all(feature = "hwtstamp", target_os = "macos"))]
pub fn enable_socket_timestamping(
    fd: std::os::fd::RawFd,
    rx: bool,
    _tx: bool,
    _want_hw: bool,
) -> EnabledTimestamping {
    use ::nix::sys::socket::{setsockopt, sockopt};

    if !rx {
        return EnabledTimestamping::default();
    }
    // SAFETY: the caller guarantees `fd` is a live socket descriptor for
    // the duration of this call; BorrowedFd does not take ownership.
    let bfd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    match setsockopt(&bfd, sockopt::ReceiveTimestamp, &true) {
        Ok(()) => EnabledTimestamping {
            rx_kernel: true,
            ..Default::default()
        },
        Err(e) => {
            log::warn!("SO_TIMESTAMP rejected ({e}); using userspace timestamps");
            EnabledTimestamping::default()
        }
    }
}

/// Fallback for platforms without a kernel timestamping API in this
/// implementation (Windows: the receiver captures at the datalink layer
/// and has no socket; a sender-side SIO_TIMESTAMPING port is future work).
#[cfg(all(
    feature = "hwtstamp",
    not(any(target_os = "linux", target_os = "macos"))
))]
pub fn enable_socket_timestamping(
    _fd: std::os::raw::c_int,
    _rx: bool,
    _tx: bool,
    _want_hw: bool,
) -> EnabledTimestamping {
    EnabledTimestamping::default()
}

/// Extracts the kernel receive timestamp from a recvmsg cmsg iterator.
/// Prefers the raw-hardware slot when the NIC filled it; falls back to
/// the kernel-software slot. Returns `None` when no timestamping cmsg is
/// present (e.g. enablement failed).
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
pub fn extract_kernel_rx_timestamp(
    cmsgs: impl Iterator<Item = ::nix::sys::socket::ControlMessageOwned>,
) -> Option<KernelTimestamp> {
    use ::nix::sys::socket::ControlMessageOwned;

    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmTimestampsns(ts) = cmsg {
            if ts.hw_raw.tv_sec() != 0 || ts.hw_raw.tv_nsec() != 0 {
                return Some(KernelTimestamp {
                    secs: ts.hw_raw.tv_sec(),
                    nanos: ts.hw_raw.tv_nsec() as u32,
                    hardware: true,
                });
            }
            if ts.system.tv_sec() != 0 || ts.system.tv_nsec() != 0 {
                return Some(KernelTimestamp {
                    secs: ts.system.tv_sec(),
                    nanos: ts.system.tv_nsec() as u32,
                    hardware: false,
                });
            }
        }
    }
    None
}

/// macOS variant: `SCM_TIMESTAMP` carries a software timeval.
#[cfg(all(feature = "hwtstamp", target_os = "macos"))]
pub fn extract_kernel_rx_timestamp(
    cmsgs: impl Iterator<Item = ::nix::sys::socket::ControlMessageOwned>,
) -> Option<KernelTimestamp> {
    use ::nix::sys::socket::ControlMessageOwned;

    for cmsg in cmsgs {
        if let ControlMessageOwned::ScmTimestamp(tv) = cmsg {
            return Some(KernelTimestamp {
                secs: tv.tv_sec(),
                nanos: (tv.tv_usec() as u32).saturating_mul(1000),
                hardware: false,
            });
        }
    }
    None
}

/// Drains all pending transmit timestamps from the socket error queue
/// (non-blocking; returns what is available right now). Each entry pairs
/// the `SOF_TIMESTAMPING_OPT_ID` send counter with the STAMP wire-format
/// timestamp. Linux only — TX timestamps require `MSG_ERRQUEUE`.
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
pub fn drain_tx_timestamps(
    fd: std::os::fd::RawFd,
    cs: crate::configuration::ClockFormat,
) -> Vec<TxTimestampReport> {
    use std::io::IoSliceMut;

    use ::nix::errno::Errno;
    use ::nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};

    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; 64];
        let mut cmsg_buf = vec![0u8; 512];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let msg = match recvmsg::<SockaddrStorage>(
            fd,
            &mut iov,
            Some(&mut cmsg_buf),
            MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
        ) {
            Ok(m) => m,
            Err(Errno::EAGAIN) => break,
            Err(e) => {
                log::debug!("error-queue drain stopped: {e}");
                break;
            }
        };

        let Ok(cmsgs) = msg.cmsgs() else { continue };
        let mut stamp: Option<(i64, u32, bool)> = None;
        let mut opt_id: Option<u32> = None;
        for cmsg in cmsgs {
            match cmsg {
                ControlMessageOwned::ScmTimestampsns(ts) => {
                    stamp = if ts.hw_raw.tv_sec() != 0 || ts.hw_raw.tv_nsec() != 0 {
                        Some((ts.hw_raw.tv_sec(), ts.hw_raw.tv_nsec() as u32, true))
                    } else {
                        Some((ts.system.tv_sec(), ts.system.tv_nsec() as u32, false))
                    };
                }
                ControlMessageOwned::Ipv4RecvErr(err, _)
                | ControlMessageOwned::Ipv6RecvErr(err, _) => {
                    opt_id = Some(err.ee_data);
                }
                _ => {}
            }
        }
        if let (Some((secs, nanos, hardware)), Some(opt_id)) = (stamp, opt_id) {
            out.push(TxTimestampReport {
                opt_id,
                timestamp: crate::time::timestamp_from_parts(secs, nanos, cs),
                hardware,
            });
        }
    }
    out
}

/// Requests NIC-level hardware timestamping filters via `SIOCSHWTSTAMP`
/// (requires CAP_NET_ADMIN and reconfigures the interface for *all*
/// sockets — only attempted under `--hwtstamp on`). Returns true on
/// success; failure is logged and the caller stays on the software tier.
#[cfg(all(feature = "hwtstamp", target_os = "linux"))]
pub fn request_nic_hw_timestamping(interface: &str) -> bool {
    use std::os::fd::AsRawFd;

    use ::nix::libc;

    if interface.len() >= libc::IFNAMSIZ {
        return false;
    }
    let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") else {
        return false;
    };
    let mut cfg: libc::hwtstamp_config = unsafe { std::mem::zeroed() };
    cfg.tx_type = libc::HWTSTAMP_TX_ON as libc::c_int;
    cfg.rx_filter = libc::HWTSTAMP_FILTER_ALL as libc::c_int;
    // SAFETY: same contract as `ethtool_ts_info` — zeroed ifreq,
    // NUL-bounded name, `ifru_data` valid for the ioctl duration.
    let rc = unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (dst, src) in ifr.ifr_name.iter_mut().zip(interface.as_bytes()) {
            *dst = *src as libc::c_char;
        }
        ifr.ifr_ifru.ifru_data = (&mut cfg as *mut libc::hwtstamp_config).cast::<libc::c_char>();
        libc::ioctl(sock.as_raw_fd(), libc::SIOCSHWTSTAMP, &mut ifr)
    };
    if rc != 0 {
        log::warn!(
            "SIOCSHWTSTAMP on {interface} failed ({}); staying on kernel \
             software timestamps (hardware filters need CAP_NET_ADMIN and \
             NIC support)",
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

/// Resolves the interface that owns `addr`, used to pick the probe
/// target from `--local-addr` (there is no dedicated `--interface`
/// flag). Wildcard addresses return `None` — no single interface
/// applies, so the probe conservatively reports "not supported".
#[cfg(unix)]
#[must_use]
pub fn interface_for_addr(addr: std::net::IpAddr) -> Option<String> {
    if addr.is_unspecified() {
        return None;
    }
    let ifaddrs = ::nix::ifaddrs::getifaddrs().ok()?;
    for ifaddr in ifaddrs {
        let Some(storage) = ifaddr.address else {
            continue;
        };
        let found = if let Some(v4) = storage.as_sockaddr_in() {
            std::net::IpAddr::V4(v4.ip()) == addr
        } else if let Some(v6) = storage.as_sockaddr_in6() {
            std::net::IpAddr::V6(v6.ip()) == addr
        } else {
            false
        };
        if found {
            return Some(ifaddr.interface_name);
        }
    }
    None
}

/// Windows has no `getifaddrs`; capability probing is Linux-only anyway.
#[cfg(not(unix))]
#[must_use]
pub fn interface_for_addr(_addr: std::net::IpAddr) -> Option<String> {
    None
}

/// Resolves the effective `TimestampMethod` for the given mode and
/// probe result. This is what the receiver writes into the Type 3
/// TLV's `timestamp_in`/`timestamp_out` fields and what the sender
/// reports about itself.
///
/// Per RFC 8972 §4.3 the field may legitimately differ per packet —
/// e.g. when a NIC supports RX HW but not TX, the receiver advertises
/// `HwAssist` for ingress and `SwLocal` for egress. The current
/// implementation is conservative: it returns `HwAssist` only when
/// the relevant capability bit is true AND the operator's mode allows
/// HW. Anything else reports `SwLocal`.
#[must_use]
pub fn effective_method(
    mode: HwTsMode,
    cap: HwTsCapability,
    direction: Direction,
) -> TimestampMethod {
    let allow_hw = match mode {
        HwTsMode::On | HwTsMode::Auto => true,
        HwTsMode::Off => false,
    };
    let hw_present = match direction {
        Direction::Receive => cap.rx_hw,
        Direction::Transmit => cap.tx_hw,
    };
    if allow_hw && hw_present {
        TimestampMethod::HwAssist
    } else {
        TimestampMethod::SwLocal
    }
}

/// Which side of the timestamp pipeline we're asking about. Some NICs
/// support only RX or only TX hardware timestamping; the Type 3 TLV
/// reports the two independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Receive,
    Transmit,
}

/// What the binary should do at startup for a given `--hwtstamp` mode
/// and probed capabilities.
///
/// The kernel timestamp *read path* is not wired into recvmsg/sendmsg
/// yet, so no mode can actually deliver HW timestamps today. This type
/// keeps the CLI honest: instead of `--hwtstamp on` aborting (which would
/// falsely imply a working capability gate), the binary always continues
/// with software timestamping and warns when the operator explicitly
/// asked for HW.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupAction {
    /// Proceed with software timestamping, no message needed.
    Continue,
    /// Proceed with software timestamping, but first emit this
    /// operator-facing warning (they requested HW and aren't getting it).
    ContinueWithWarning(String),
}

/// Decides the startup behaviour from the requested `--hwtstamp` mode and
/// the [`probe`] result.
///
/// With the `hwtstamp` feature compiled in, `on` + a hardware-capable NIC
/// proceeds silently — hardware timestamping is genuinely attempted at
/// socket setup (failures are logged there). Without the feature, or
/// without NIC support, `on` warns with the true reason. `auto`/`off`
/// never warn.
#[must_use]
pub fn startup_action(mode: HwTsMode, cap: &HwTsCapability) -> StartupAction {
    match mode {
        HwTsMode::Off | HwTsMode::Auto => StartupAction::Continue,
        HwTsMode::On => {
            if !cap.any_hw_supported() {
                return StartupAction::ContinueWithWarning(
                    "--hwtstamp on: the bound interface does not support \
                     hardware timestamping; kernel software timestamps will \
                     be used where available. Use --hwtstamp auto or off to \
                     silence this warning."
                        .to_string(),
                );
            }
            #[cfg(feature = "hwtstamp")]
            {
                StartupAction::Continue
            }
            #[cfg(not(feature = "hwtstamp"))]
            {
                StartupAction::ContinueWithWarning(format!(
                    "--hwtstamp on: NIC supports hardware timestamping \
                     (rx_hw={}, tx_hw={}, ptp={}), but this build does not \
                     include the kernel timestamp read path — rebuild with \
                     `--features hwtstamp`; using software timestamps",
                    cap.rx_hw, cap.tx_hw, cap.ptp_supported
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn from_ethtool_maps_bits_and_phc() {
        use ::nix::libc;
        // Constants per linux/net_tstamp.h (provided by libc):
        // SOF_TIMESTAMPING_TX_HARDWARE = 1 << 0, RX_HARDWARE = 1 << 2.
        let none = HwTsCapability::from_ethtool(0, -1);
        assert!(!none.rx_hw && !none.tx_hw && !none.ptp_supported);
        assert!(!none.any_hw_supported());

        // Typical lo: software-only bits set, no PHC.
        let sw_only = HwTsCapability::from_ethtool(
            libc::SOF_TIMESTAMPING_RX_SOFTWARE
                | libc::SOF_TIMESTAMPING_TX_SOFTWARE
                | libc::SOF_TIMESTAMPING_SOFTWARE,
            -1,
        );
        assert!(!sw_only.any_hw_supported());
        assert!(!sw_only.ptp_supported);

        // HW-capable NIC with PHC index 3.
        let hw = HwTsCapability::from_ethtool(
            libc::SOF_TIMESTAMPING_RX_HARDWARE | libc::SOF_TIMESTAMPING_TX_HARDWARE,
            3,
        );
        assert!(hw.rx_hw && hw.tx_hw && hw.ptp_supported);
        assert!(hw.any_hw_supported());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn interface_for_addr_finds_loopback() {
        let lo = interface_for_addr("127.0.0.1".parse().unwrap());
        assert_eq!(lo.as_deref(), Some("lo"));
        // Wildcard → ambiguous → None.
        assert_eq!(interface_for_addr("0.0.0.0".parse().unwrap()), None);
        assert_eq!(interface_for_addr("::".parse().unwrap()), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_distinguishes_real_interface_from_unknown() {
        // The raw ioctl helper must observe lo (any modern kernel answers
        // ETHTOOL_GET_TS_INFO for it) and fail cleanly for a bogus name.
        assert!(ethtool_ts_info("lo").is_some());
        assert!(ethtool_ts_info("definitely-not-an-if0").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn probe_loopback_reports_no_hardware() {
        // lo supports kernel software timestamping but never hardware;
        // the probe must succeed (no panic, no error path) and report
        // no HW capabilities.
        let cap = probe(Some("lo"));
        assert!(!cap.any_hw_supported());
        assert!(!cap.ptp_supported);
    }

    #[test]
    fn probe_with_no_interface_returns_default() {
        // No interface hint → conservative "not supported".
        let cap = probe(None);
        assert!(!cap.any_hw_supported());
        assert!(!cap.rx_hw);
        assert!(!cap.tx_hw);
        assert!(!cap.ptp_supported);
    }

    #[test]
    fn probe_with_unknown_interface_returns_default() {
        let cap = probe(Some("nonexistent-iface-zzz"));
        assert!(!cap.any_hw_supported());
    }

    #[test]
    fn off_mode_always_reports_sw_local() {
        // Even if the probe says HW is available, --hwtstamp off must
        // produce SwLocal.
        let cap = HwTsCapability {
            rx_hw: true,
            tx_hw: true,
            ptp_supported: true,
        };
        assert_eq!(
            effective_method(HwTsMode::Off, cap, Direction::Receive),
            TimestampMethod::SwLocal
        );
        assert_eq!(
            effective_method(HwTsMode::Off, cap, Direction::Transmit),
            TimestampMethod::SwLocal
        );
    }

    #[test]
    fn auto_mode_uses_hw_when_present_else_sw() {
        let no_hw = HwTsCapability::default();
        let rx_only = HwTsCapability {
            rx_hw: true,
            tx_hw: false,
            ptp_supported: false,
        };
        let both = HwTsCapability {
            rx_hw: true,
            tx_hw: true,
            ptp_supported: true,
        };

        // No HW → SwLocal in both directions.
        assert_eq!(
            effective_method(HwTsMode::Auto, no_hw, Direction::Receive),
            TimestampMethod::SwLocal
        );
        assert_eq!(
            effective_method(HwTsMode::Auto, no_hw, Direction::Transmit),
            TimestampMethod::SwLocal
        );

        // RX-only HW → HwAssist on RX, SwLocal on TX.
        assert_eq!(
            effective_method(HwTsMode::Auto, rx_only, Direction::Receive),
            TimestampMethod::HwAssist
        );
        assert_eq!(
            effective_method(HwTsMode::Auto, rx_only, Direction::Transmit),
            TimestampMethod::SwLocal
        );

        // Both → HwAssist both directions.
        assert_eq!(
            effective_method(HwTsMode::Auto, both, Direction::Receive),
            TimestampMethod::HwAssist
        );
        assert_eq!(
            effective_method(HwTsMode::Auto, both, Direction::Transmit),
            TimestampMethod::HwAssist
        );
    }

    #[test]
    fn on_mode_reports_hw_when_present_sw_when_not() {
        // `On` mode behaves like Auto for the TLV reporting — the
        // fail-fast check is at startup, not per-packet.
        let cap = HwTsCapability {
            rx_hw: true,
            tx_hw: false,
            ptp_supported: false,
        };
        assert_eq!(
            effective_method(HwTsMode::On, cap, Direction::Receive),
            TimestampMethod::HwAssist
        );
        // TX HW not present → still SwLocal in the TLV, even under On.
        assert_eq!(
            effective_method(HwTsMode::On, cap, Direction::Transmit),
            TimestampMethod::SwLocal
        );
    }

    #[test]
    fn startup_action_reports_against_probe() {
        let no_hw = HwTsCapability::default();
        let hw = HwTsCapability {
            rx_hw: true,
            tx_hw: true,
            ptp_supported: true,
        };

        assert!(matches!(
            startup_action(HwTsMode::Off, &no_hw),
            StartupAction::Continue
        ));
        assert!(matches!(
            startup_action(HwTsMode::Auto, &no_hw),
            StartupAction::Continue
        ));
        // Auto with HW present: still software (the kernel read path is
        // not implemented), but that's not worth a warning — the operator
        // didn't explicitly demand hardware.
        assert!(matches!(
            startup_action(HwTsMode::Auto, &hw),
            StartupAction::Continue
        ));

        // `On` without NIC support warns honestly in every build.
        let StartupAction::ContinueWithWarning(msg) = startup_action(HwTsMode::On, &no_hw) else {
            panic!("On without HW caps must warn");
        };
        assert!(
            msg.contains("does not support hardware timestamping"),
            "no-HW warning must blame the NIC: {msg}"
        );

        // `On` with NIC support: with the kernel read path compiled in
        // (feature "hwtstamp") hardware timestamping will actually be
        // attempted at socket setup, so startup stays silent; without the
        // feature, warn that this build can't use it.
        #[cfg(feature = "hwtstamp")]
        assert!(
            matches!(startup_action(HwTsMode::On, &hw), StartupAction::Continue),
            "feature build with HW caps must proceed silently"
        );
        #[cfg(not(feature = "hwtstamp"))]
        {
            let StartupAction::ContinueWithWarning(msg) = startup_action(HwTsMode::On, &hw) else {
                panic!("non-feature build must warn even with HW caps");
            };
            assert!(
                msg.contains("hwtstamp"),
                "warning must point at the missing build feature: {msg}"
            );
        }
    }

    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    #[test]
    fn enable_and_extract_rx_kernel_timestamp_over_loopback() {
        use std::os::fd::AsRawFd;

        // Kernel software RX timestamps work on lo without privileges.
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let enabled = enable_socket_timestamping(rx.as_raw_fd(), true, false, false);
        assert!(enabled.rx_kernel, "lo must support kernel SW RX timestamps");
        assert!(!enabled.rx_hw);

        // The kernel activates RX timestamping via a deferred static key
        // (net_enable_timestamp), so the first packets after the very
        // first enable on a host can legitimately miss the cmsg — retry.
        let mut got = None;
        for _ in 0..50 {
            tx.send_to(b"ping", rx.local_addr().unwrap()).unwrap();

            let mut buf = [0u8; 64];
            let mut cmsg_buf = vec![0u8; 256];
            let mut iov = [std::io::IoSliceMut::new(&mut buf)];
            let msg = ::nix::sys::socket::recvmsg::<::nix::sys::socket::SockaddrStorage>(
                rx.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg_buf),
                ::nix::sys::socket::MsgFlags::empty(),
            )
            .unwrap();

            if let Some(ts) = extract_kernel_rx_timestamp(msg.cmsgs().unwrap()) {
                got = Some(ts);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let ts = got.expect("kernel RX timestamp must appear within retries");
        assert!(!ts.hardware, "lo delivers software timestamps");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            (ts.secs - now).abs() <= 5,
            "kernel timestamp must be near wall clock: ts={} now={now}",
            ts.secs
        );
    }

    #[cfg(all(feature = "hwtstamp", target_os = "linux"))]
    #[test]
    fn drain_tx_timestamps_over_loopback() {
        use std::os::fd::AsRawFd;

        use crate::configuration::ClockFormat;

        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let enabled = enable_socket_timestamping(tx.as_raw_fd(), false, true, false);
        assert!(enabled.tx_kernel, "lo must support kernel SW TX timestamps");

        tx.send_to(b"one", rx.local_addr().unwrap()).unwrap();
        tx.send_to(b"two", rx.local_addr().unwrap()).unwrap();

        // TX timestamps land on the error queue within microseconds, but
        // give the kernel a moment to be safe.
        let mut reports = Vec::new();
        for _ in 0..50 {
            reports.extend(drain_tx_timestamps(tx.as_raw_fd(), ClockFormat::PTP));
            if reports.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert_eq!(reports.len(), 2, "both sends must produce TX timestamps");
        // SOF_TIMESTAMPING_OPT_ID counts sendmsg calls from enablement: 0, 1.
        let mut ids: Vec<u32> = reports.iter().map(|r| r.opt_id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![0, 1]);
        for r in &reports {
            assert!(r.timestamp > 0, "wire timestamp must be non-zero");
            assert!(!r.hardware);
        }
    }

    #[test]
    fn any_hw_supported_combines_rx_tx() {
        assert!(!HwTsCapability::default().any_hw_supported());
        assert!(HwTsCapability {
            rx_hw: true,
            ..Default::default()
        }
        .any_hw_supported());
        assert!(HwTsCapability {
            tx_hw: true,
            ..Default::default()
        }
        .any_hw_supported());
    }
}
