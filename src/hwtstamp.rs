//! Hardware-assisted timestamping support (F1).
//!
//! Provides a capability probe and `--hwtstamp` mode enum the rest of
//! the codebase consults when deciding which `TimestampMethod` to
//! advertise in the RFC 8972 §4.3 Timestamp Information TLV.
//!
//! **Defensive posture.** Per the project's hardware-dependent
//! contract: this module never panics and never refuses to start the
//! binary. Every `--hwtstamp` mode currently falls back to software
//! timestamping; `--hwtstamp on` additionally emits a one-line warning
//! so an operator who explicitly asked for hardware isn't misled into
//! thinking they got it (see `startup_action`).
//!
//! **Current scope — probe functional, timestamps still software.**
//! [`probe`] performs a real `ETHTOOL_GET_TS_INFO` ioctl (Linux) against
//! the interface owning `--local-addr` (resolved via
//! [`interface_for_addr`]), and `--hwtstamp on` reports honestly whether
//! the limitation is the NIC or this implementation. The kernel
//! timestamp *read path* (`SO_TIMESTAMPING` cmsgs on recvmsg,
//! `MSG_ERRQUEUE` for TX) is **not implemented**, so all four STAMP
//! timestamps remain software and `effective_method` is not yet wired
//! into the TLV builders — they hardcode `SwLocal`, which is accurate.

use clap::ValueEnum;
use serde::Deserialize;

use crate::tlv::TimestampMethod;

/// Operator preference for hardware-assisted timestamping. Selected via
/// the `--hwtstamp` CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HwTsMode {
    /// Use hardware timestamping when the capability probe finds it
    /// available; transparently fall back to software otherwise. This
    /// is the default — safe to leave on every host. (The kernel read
    /// path is not implemented yet, so this is currently always
    /// software regardless of the probe.)
    #[default]
    Auto,
    /// Prefer hardware timestamping and warn (rather than fail) when it
    /// isn't usable, so operators who explicitly want HW are told they
    /// are getting software instead. The warning states the real reason:
    /// NIC without HW support, or the not-yet-implemented read path.
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
/// the [`probe`] result. Software timestamps are always used in the
/// current phase, so `On` always warns — with a message that reflects
/// whether the limitation is the NIC or this implementation.
#[must_use]
pub fn startup_action(mode: HwTsMode, cap: &HwTsCapability) -> StartupAction {
    match mode {
        HwTsMode::Off | HwTsMode::Auto => StartupAction::Continue,
        HwTsMode::On => {
            if cap.any_hw_supported() {
                StartupAction::ContinueWithWarning(format!(
                    "--hwtstamp on: NIC supports hardware timestamping \
                     (rx_hw={}, tx_hw={}, ptp={}), but the kernel timestamp \
                     read path is not yet implemented; using software \
                     timestamps",
                    cap.rx_hw, cap.tx_hw, cap.ptp_supported
                ))
            } else {
                StartupAction::ContinueWithWarning(
                    "--hwtstamp on: the bound interface does not support \
                     hardware timestamping; using software timestamps. \
                     Use --hwtstamp auto or off to silence this warning."
                        .to_string(),
                )
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

        // `On` always warns in this phase, but the reason must be honest.
        let StartupAction::ContinueWithWarning(msg) = startup_action(HwTsMode::On, &no_hw) else {
            panic!("On without HW caps must warn");
        };
        assert!(
            msg.contains("does not support hardware timestamping"),
            "no-HW warning must blame the NIC: {msg}"
        );
        assert!(msg.contains("software"));

        let StartupAction::ContinueWithWarning(msg) = startup_action(HwTsMode::On, &hw) else {
            panic!("On with HW caps must still warn: read path not implemented");
        };
        assert!(
            msg.contains("not yet implemented"),
            "HW-capable warning must blame the implementation: {msg}"
        );
        assert!(msg.contains("software"));
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
