//! Sender decisions consume validated fields; display text is diagnostic only.
use std::fmt;

use crate::tlv::{AccessReportTlv, MicroSessionIdTlv};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum HmacStatus {
    /// No TLV HMAC and no verification key configured.
    #[default]
    NotRequested,
    /// A key was configured but the peer supplied no TLV HMAC. Optional
    /// telemetry retains the legacy peer policy; required MSID rejects it.
    Missing,
    Verified,
    /// Verification unavailable: no key, unusable HMAC flags, or no wire bytes.
    Unverified,
    Failed,
}

impl HmacStatus {
    pub(super) fn permits_optional_values(self) -> bool {
        matches!(self, Self::NotRequested | Self::Missing | Self::Verified)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct FlagCounts {
    pub unrecognized: usize,
    pub malformed: usize,
    pub integrity_failed: usize,
}

/// Only usable, requested values enter decision fields. U skips a value;
/// M stops the remainder; I or failed/unavailable HMAC blocks all values.
/// Counts and HMAC status remain available when value consumption is blocked.
/// Micro-session rejection is a separate Result error, not a display marker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct TlvTelemetry {
    pub tlv_count: usize,
    pub flags: FlagCounts,
    pub hmac: HmacStatus,
    /// First usable Access Report, after typed length validation.
    pub access_report: Option<AccessReportTlv>,
    /// Any usable CoS TLV reported EC2=CE; later clean TLVs cannot clear it.
    pub forward_ce: bool,
    pub micro_session: Option<MicroSessionIdTlv>,
}

impl fmt::Display for TlvTelemetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} TLVs", self.tlv_count)?;
        match self.hmac {
            HmacStatus::NotRequested => {}
            HmacStatus::Missing => write!(f, ", no-hmac")?,
            HmacStatus::Verified => write!(f, ", HMAC:ok")?,
            HmacStatus::Unverified => write!(f, ", HMAC:unverified")?,
            HmacStatus::Failed => write!(f, ", HMAC:fail")?,
        }
        if self.access_report.is_some() {
            write!(f, ", AccessReport:ack")?;
        }
        if self.forward_ce {
            write!(f, ", CoS:CE")?;
        }
        if let Some(msid) = &self.micro_session {
            write!(
                f,
                ", MSID:ok(reflector={})",
                msid.reflector_micro_session_id
            )?;
        }
        for (count, flag) in [
            (self.flags.unrecognized, 'U'),
            (self.flags.malformed, 'M'),
            (self.flags.integrity_failed, 'I'),
        ] {
            if count > 0 {
                write!(f, ", {count}{flag}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_diagnostics_render_typed_fields_in_stable_order() {
        let report = TlvTelemetry {
            tlv_count: 8,
            flags: FlagCounts {
                unrecognized: 1,
                malformed: 2,
                integrity_failed: 0,
            },
            hmac: HmacStatus::Verified,
            access_report: Some(AccessReportTlv::new(1, 1)),
            forward_ce: true,
            micro_session: Some(MicroSessionIdTlv::new(7777, 42)),
        };
        assert_eq!(
            report.to_string(),
            "8 TLVs, HMAC:ok, AccessReport:ack, CoS:CE, MSID:ok(reflector=42), 1U, 2M"
        );
        assert_eq!(TlvTelemetry::default().to_string(), "0 TLVs");
    }
}
