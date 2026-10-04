//! Sender decisions consume validated fields; display text is diagnostic only.
use std::{collections::BTreeMap, fmt};

use crate::tlv::{
    AccessReportTlv, DirectMeasurementTlv, FollowUpTelemetryTlv, MicroSessionIdTlv, RawTlv, TlvList,
};

/// Cumulative TLV HMAC outcomes, counted once per evaluated reply.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TlvHmacSummary {
    pub not_requested: u64,
    pub missing: u64,
    pub verified: u64,
    pub unverified: u64,
    pub failed: u64,
}

/// Flags in parsed reflected TLVs. M includes parser-detected truncation.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TlvFlagSummary {
    pub unrecognized: u64,
    pub malformed: u64,
    pub integrity_failed: u64,
    pub conformant_reflected: u64,
}

impl TlvFlagSummary {
    fn record(&mut self, raw: &RawTlv) {
        self.unrecognized += u64::from(raw.is_unrecognized());
        self.malformed += u64::from(raw.is_malformed());
        self.integrity_failed += u64::from(raw.is_integrity_failed());
        self.conformant_reflected += u64::from(raw.flags.conformant_reflected);
    }
}

/// Observations of one TLV type; clear flags alone do not prove usability.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TlvTypeSummary {
    pub observed: u64,
    pub flags: TlvFlagSummary,
}

/// TLV evaluations before session admission and deduplication, including
/// required-ID rejections. Excludes packets dropped before evaluation,
/// such as base HMAC failures.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TlvValidationSummary {
    pub evaluated_replies: u64,
    pub rejected_replies: u64,
    pub observed_tlvs: u64,
    pub hmac: TlvHmacSummary,
    pub flags: TlvFlagSummary,
    /// Decimal wire type codepoints, including unknown types and HMAC.
    pub by_type: BTreeMap<u8, TlvTypeSummary>,
}

impl TlvValidationSummary {
    pub(super) fn record(&mut self, tlvs: &TlvList, info: &TlvTelemetry, rejected: bool) {
        self.evaluated_replies += 1;
        self.rejected_replies += u64::from(rejected);
        self.observed_tlvs += tlvs.len() as u64;
        match info.hmac {
            HmacStatus::NotRequested => self.hmac.not_requested += 1,
            HmacStatus::Missing => self.hmac.missing += 1,
            HmacStatus::Verified => self.hmac.verified += 1,
            HmacStatus::Unverified => self.hmac.unverified += 1,
            HmacStatus::Failed => self.hmac.failed += 1,
        }
        for raw in tlvs.all_tlvs() {
            self.flags.record(raw);
            let entry = self.by_type.entry(raw.tlv_type.to_byte()).or_default();
            entry.observed += 1;
            entry.flags.record(raw);
        }
    }
}

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

    /// Measurement values (counters, timestamps, BER) need a verified HMAC
    /// whenever a key is configured.
    pub(crate) fn permits_measurements(self) -> bool {
        matches!(self, Self::NotRequested | Self::Verified)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct FlagCounts {
    pub unrecognized: usize,
    pub malformed: usize,
    pub integrity_failed: usize,
}

/// Validated requested values. U skips, M stops the remainder, and I or
/// unusable HMAC blocks values while retaining diagnostics.
/// Required Micro-session ID failures return a separate error.
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
    pub direct_measurement: Option<DirectMeasurementTlv>,
    pub follow_up: Option<FollowUpTelemetryTlv>,
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
            direct_measurement: None,
            follow_up: None,
        };
        assert_eq!(
            report.to_string(),
            "8 TLVs, HMAC:ok, AccessReport:ack, CoS:CE, MSID:ok(reflector=42), 1U, 2M"
        );
        assert_eq!(TlvTelemetry::default().to_string(), "0 TLVs");
    }
}
