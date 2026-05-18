//! Hardware-assisted timestamping support (F1).
//!
//! Provides a capability probe and `--hwtstamp` mode enum the rest of
//! the codebase consults when deciding which `TimestampMethod` to
//! advertise in the RFC 8972 §4.3 Timestamp Information TLV.
//!
//! **Defensive posture.** Per the project's hardware-dependent
//! contract: this module never panics, never refuses to start the
//! binary on a host without HW support, and silently falls back to
//! software timestamping. The only path that intentionally fails-fast
//! is `--hwtstamp on`, which is documented as an "operator-explicit"
//! mode for advanced users who'd rather know than guess.
//!
//! **Current scope.** The capability probe is feature-gated under
//! `hwtstamp`; without the feature it compiles to a stub returning
//! "not supported" so the rest of the pipeline keeps working unchanged.
//! Wiring `SO_TIMESTAMPING` / `MSG_ERRQUEUE` into the actual recvmsg /
//! sendmsg paths is a follow-up — the structure is in place so that
//! work can land without touching every TLV-builder call site.

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
    /// is the default — safe to leave on every host.
    #[default]
    Auto,
    /// Demand hardware timestamping. Fails-fast at startup when the
    /// probe says no, so operators who explicitly want HW timestamping
    /// don't silently get software measurements.
    On,
    /// Always use software timestamping, even when HW is available.
    /// Useful for A/B-style measurement comparisons or as a fallback
    /// when a particular NIC's HW path is suspect.
    Off,
}

/// Result of the per-host hardware-timestamping capability probe.
///
/// Constructed at startup by [`probe`]; consumed by the
/// `--hwtstamp on` validator and by the future recvmsg/sendmsg paths
/// that will choose between HW and SW timestamping per packet.
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
    /// True when at least one of rx_hw / tx_hw is supported. The
    /// `--hwtstamp on` fail-fast check uses this; `auto` uses it to
    /// decide whether to attempt the kernel cmsg path.
    #[must_use]
    pub fn any_hw_supported(&self) -> bool {
        self.rx_hw || self.tx_hw
    }
}

/// Probes the host for hardware-timestamping capability. The
/// `interface` hint is the outgoing-interface name (`eth0`, `enp0s3`,
/// etc.); when `None` the probe returns the conservative default of
/// "not supported." That matches operator expectations: until we
/// commit to a specific interface, we don't claim HW timestamping is
/// available.
///
/// **Without the `hwtstamp` feature** the function always returns
/// `HwTsCapability::default()` (all false). This is the default build
/// configuration — operators have to opt in to the feature.
///
/// **With the `hwtstamp` feature on Linux** the probe is currently a
/// placeholder that still returns `default()`. The actual
/// `ETHTOOL_GET_TS_INFO` ioctl wiring is a follow-up; the public API
/// is in place now so call sites don't need updating when it lands.
///
/// **On non-Linux platforms** the probe returns `default()`
/// unconditionally — SO_TIMESTAMPING is Linux-specific.
#[must_use]
pub fn probe(interface: Option<&str>) -> HwTsCapability {
    let _ = interface;
    // Placeholder for both feature-on-Linux and the fallback path:
    // the real `ETHTOOL_GET_TS_INFO` ioctl wiring is a follow-up.
    // Until then we report "not supported" so the default code
    // path stays software. The cfg-gating remains useful for
    // future divergence (e.g. enabling the ioctl path only under
    // hwtstamp + Linux).
    HwTsCapability::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_with_no_interface_returns_default() {
        // Default build (no hwtstamp feature) → always "not supported".
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
