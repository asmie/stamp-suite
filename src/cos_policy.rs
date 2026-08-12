//! Class-of-Service admission policy for the Session-Reflector.
//!
//! RFC 8972 §4.4 requires that "the Session-Reflector MUST use the local policy
//! to verify whether the CoS corresponding to the value of the DSCP1 field is
//! permitted in the domain", §6 adds a SHOULD for "a local policy to confirm
//! whether the value sent by the Session-Sender can be used as the value of the
//! DSCP field", and draft-ietf-ippm-stamp-cos-ecn-01 §3.2 repeats the
//! requirement for DSCP1 and extends it to EC1 ("if it is permitted and capable
//! to do so").
//!
//! The distinction this module exists to draw is **permitted** versus
//! **capable**. Attempting the `IP_TOS`/`IPV6_TCLASS` setsockopt and treating a
//! failure as "not permitted" only ever answers *capable*: the kernel does not
//! know the operator's domain policy, and it will happily apply a DSCP the
//! network is not supposed to carry. This layer answers *permitted*, and the
//! existing syscall path continues to answer *capable* — a request has to clear
//! both.
//!
//! The draft names the shapes such a policy takes: "a system default policy, a
//! global policy ..., or a policy ... configured for specific destination
//! addresses or networks". Both forms are available here: a global set of
//! admissible values, plus per-destination-prefix overrides resolved
//! longest-prefix-first, matched against the address the reflected packet is
//! being sent *to*.
//!
//! The default permits everything, which keeps a general-purpose measurement
//! tool useful out of the box; the policy exists so an operator running a
//! reflector inside a DiffServ domain can constrain it.

use std::net::IpAddr;

/// Set of admissible 6-bit DSCP values, one bit per codepoint.
///
/// 64 codepoints fit exactly in a `u64`, so membership is a shift and a mask —
/// this is consulted per packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DscpSet(u64);

impl DscpSet {
    /// Every codepoint admissible.
    #[must_use]
    pub const fn all() -> Self {
        Self(u64::MAX)
    }

    /// No codepoint admissible.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// True when `dscp` (low 6 bits) is admissible.
    #[must_use]
    pub const fn contains(&self, dscp: u8) -> bool {
        self.0 & (1u64 << (dscp & 0x3F)) != 0
    }

    /// Parses `all`, `none`, or a comma-separated list of codepoints and
    /// inclusive ranges: `0,8,10-14,46`.
    ///
    /// # Errors
    /// Returns a message naming the offending token for an unparsable value, a
    /// codepoint above 63, an inverted range, or an empty list. `all`/`none`
    /// cannot be mixed with explicit values — `none,46` has no single reading.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut bits = 0u64;
        let mut saw_wildcard = false;
        let mut saw_value = false;

        for token in spec.split(',') {
            let token = token.trim();
            if token.is_empty() {
                // A wholly empty spec is reported as an empty list below. An
                // empty element *inside* a list (`0,,8`, `0,46,`) is a typo, and
                // skipping it silently would let the policy admit something the
                // operator never wrote.
                if spec.trim().is_empty() {
                    continue;
                }
                return Err(format!("empty entry in DSCP list '{spec}'"));
            }
            match token.to_ascii_lowercase().as_str() {
                "all" => {
                    bits = u64::MAX;
                    saw_wildcard = true;
                    continue;
                }
                "none" => {
                    bits = 0;
                    saw_wildcard = true;
                    continue;
                }
                _ => {}
            }
            saw_value = true;
            if let Some((lo, hi)) = token.split_once('-') {
                let lo = parse_dscp(lo.trim())?;
                let hi = parse_dscp(hi.trim())?;
                if lo > hi {
                    return Err(format!("inverted DSCP range '{token}'"));
                }
                for v in lo..=hi {
                    bits |= 1u64 << v;
                }
            } else {
                bits |= 1u64 << parse_dscp(token)?;
            }
        }

        if saw_wildcard && saw_value {
            return Err("'all'/'none' cannot be combined with explicit DSCP values".to_string());
        }
        if !saw_wildcard && !saw_value {
            return Err("empty DSCP list".to_string());
        }
        Ok(Self(bits))
    }
}

fn parse_dscp(s: &str) -> Result<u8, String> {
    let v: u16 = s
        .parse()
        .map_err(|_| format!("'{s}' is not a DSCP value (expected 0-63)"))?;
    if v > 63 {
        return Err(format!("DSCP {v} is out of range (0-63)"));
    }
    Ok(v as u8)
}

/// Set of admissible 2-bit ECN codepoints (Not-ECT, ECT(1), ECT(0), CE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnSet(u8);

impl EcnSet {
    /// Every codepoint admissible.
    #[must_use]
    pub const fn all() -> Self {
        Self(0x0F)
    }

    /// No codepoint admissible.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// True when `ecn` (low 2 bits) is admissible.
    #[must_use]
    pub const fn contains(&self, ecn: u8) -> bool {
        self.0 & (1u8 << (ecn & 0x03)) != 0
    }

    /// Parses `all`, `none`, or a comma-separated list of codepoints 0-3.
    ///
    /// # Errors
    /// Returns a message naming the offending token for an unparsable value, a
    /// codepoint above 3, an empty list, or `all`/`none` mixed with values.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut bits = 0u8;
        let mut saw_wildcard = false;
        let mut saw_value = false;

        for token in spec.split(',') {
            let token = token.trim();
            if token.is_empty() {
                // A wholly empty spec is reported as an empty list below. An
                // empty element *inside* a list (`0,,8`, `0,46,`) is a typo, and
                // skipping it silently would let the policy admit something the
                // operator never wrote.
                if spec.trim().is_empty() {
                    continue;
                }
                return Err(format!("empty entry in ECN list '{spec}'"));
            }
            match token.to_ascii_lowercase().as_str() {
                "all" => {
                    bits = 0x0F;
                    saw_wildcard = true;
                    continue;
                }
                "none" => {
                    bits = 0;
                    saw_wildcard = true;
                    continue;
                }
                _ => {}
            }
            saw_value = true;
            let v: u16 = token
                .parse()
                .map_err(|_| format!("'{token}' is not an ECN codepoint (expected 0-3)"))?;
            if v > 3 {
                return Err(format!("ECN {v} is out of range (0-3)"));
            }
            bits |= 1u8 << v;
        }

        if saw_wildcard && saw_value {
            return Err("'all'/'none' cannot be combined with explicit ECN values".to_string());
        }
        if !saw_wildcard && !saw_value {
            return Err("empty ECN list".to_string());
        }
        Ok(Self(bits))
    }
}

/// The shared permit-everything policy.
///
/// Returned as a `&'static` so a caller with no configured policy — a test, a
/// bench, or a backend whose configuration parsed to the default — can borrow
/// one without each site owning a copy.
#[must_use]
pub fn permissive() -> &'static CosAdmissionPolicy {
    static PERMISSIVE: std::sync::OnceLock<CosAdmissionPolicy> = std::sync::OnceLock::new();
    PERMISSIVE.get_or_init(CosAdmissionPolicy::permit_all)
}

/// A destination-scoped override: the DSCP values admissible when the reflected
/// packet is addressed inside `prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DestinationRule {
    prefix: IpAddr,
    prefix_len: u8,
    dscp: DscpSet,
}

/// The reflector's CoS admission policy (RFC 8972 §4.4/§6, cos-ecn-01 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosAdmissionPolicy {
    dscp: DscpSet,
    ecn: EcnSet,
    /// Sorted by descending prefix length so the first match is the most
    /// specific one.
    destinations: Vec<DestinationRule>,
}

impl Default for CosAdmissionPolicy {
    fn default() -> Self {
        Self::permit_all()
    }
}

impl CosAdmissionPolicy {
    /// The permissive default: every DSCP and ECN value admissible everywhere.
    #[must_use]
    pub fn permit_all() -> Self {
        Self {
            dscp: DscpSet::all(),
            ecn: EcnSet::all(),
            destinations: Vec::new(),
        }
    }

    /// Builds a policy from the global sets and any destination-scoped rules.
    ///
    /// Rules are stored longest-prefix-first, which is what makes resolution
    /// order independent of the order they were given on the command line.
    #[must_use]
    pub fn new(dscp: DscpSet, ecn: EcnSet, mut destinations: Vec<(IpAddr, u8, DscpSet)>) -> Self {
        destinations.sort_by_key(|rule| std::cmp::Reverse(rule.1));
        Self {
            dscp,
            ecn,
            destinations: destinations
                .into_iter()
                .map(|(prefix, prefix_len, dscp)| DestinationRule {
                    prefix,
                    prefix_len,
                    dscp,
                })
                .collect(),
        }
    }

    /// True when nothing has been restricted, so the per-packet check can be
    /// skipped entirely.
    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.dscp == DscpSet::all() && self.ecn == EcnSet::all() && self.destinations.is_empty()
    }

    /// Whether `dscp` may be used on a reply addressed to `destination`.
    ///
    /// The most specific matching destination rule decides; with no matching
    /// rule the global set decides. `destination` is `None` when the backend
    /// could not determine the reply's destination, in which case only the
    /// global set applies — a destination rule cannot be evaluated against an
    /// unknown address, and silently treating that as a match either way would
    /// misreport the policy.
    #[must_use]
    pub fn permits_dscp(&self, destination: Option<IpAddr>, dscp: u8) -> bool {
        if let Some(dest) = destination {
            for rule in &self.destinations {
                if prefix_matches(rule.prefix, rule.prefix_len, dest) {
                    return rule.dscp.contains(dscp);
                }
            }
        }
        self.dscp.contains(dscp)
    }

    /// Whether `ecn` may be used on a reply.
    ///
    /// ECN is a global decision: the draft's destination-scoped examples are
    /// about DiffServ codepoints, and a per-destination ECN policy would invite
    /// an operator to disable congestion signalling for a subset of peers, which
    /// is not a distinction worth making configurable.
    #[must_use]
    pub fn permits_ecn(&self, ecn: u8) -> bool {
        self.ecn.contains(ecn)
    }
}

/// True when `addr` falls inside `prefix`/`prefix_len`.
///
/// Mixed families never match. A zero-length prefix matches every address of
/// its own family, which is how `0.0.0.0/0` expresses "every IPv4 destination".
fn prefix_matches(prefix: IpAddr, prefix_len: u8, addr: IpAddr) -> bool {
    match (prefix, addr) {
        (IpAddr::V4(p), IpAddr::V4(a)) => bits_match(&p.octets(), &a.octets(), prefix_len, 32),
        (IpAddr::V6(p), IpAddr::V6(a)) => bits_match(&p.octets(), &a.octets(), prefix_len, 128),
        _ => false,
    }
}

fn bits_match(prefix: &[u8], addr: &[u8], prefix_len: u8, max_len: u8) -> bool {
    if prefix_len > max_len {
        return false;
    }
    let full = (prefix_len / 8) as usize;
    if prefix[..full] != addr[..full] {
        return false;
    }
    let rem = prefix_len % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    prefix[full] & mask == addr[full] & mask
}

/// Parses one `--allowed-dscp-for` rule: `<PREFIX>/<LEN>=<DSCP SPEC>`.
///
/// # Errors
/// Returns a message naming the problem for a missing `=`, an unparsable
/// address, a missing or out-of-range prefix length, or a bad DSCP list.
pub fn parse_destination_rule(spec: &str) -> Result<(IpAddr, u8, DscpSet), String> {
    let (network, values) = spec
        .split_once('=')
        .ok_or_else(|| format!("'{spec}' is missing '=' (expected PREFIX/LEN=DSCP,...)"))?;
    let (addr, len) = network
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("'{network}' is missing '/LEN'"))?;
    let addr: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| format!("'{addr}' is not an IP address"))?;
    let len: u16 = len
        .trim()
        .parse()
        .map_err(|_| format!("'{len}' is not a prefix length"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(format!(
            "prefix length {len} is out of range for this address family (0-{max})"
        ));
    }
    let dscp = DscpSet::parse(values.trim())?;
    Ok((addr, len as u8, dscp))
}

#[cfg(test)]
mod tests {

    /// An empty element inside a list is a typo, not a no-op: skipping it
    /// silently let `--allowed-dscp 0,,8` and a trailing comma through, so a
    /// mistyped policy admitted a set the operator never wrote.
    #[test]
    fn empty_list_elements_are_rejected() {
        for spec in ["0,,8", "0,46,", ",0", "0,,", "all,,"] {
            assert!(
                DscpSet::parse(spec).is_err(),
                "DSCP spec '{spec}' must be rejected"
            );
        }
        for spec in ["0,,1", "0,3,", ",1"] {
            assert!(
                EcnSet::parse(spec).is_err(),
                "ECN spec '{spec}' must be rejected"
            );
        }

        // Well-formed lists, the wildcards, and surrounding whitespace all
        // still parse.
        assert!(DscpSet::parse("0,8,10-14,46").is_ok());
        assert!(DscpSet::parse(" 0 , 46 ").is_ok());
        assert!(DscpSet::parse("all").is_ok());
        assert!(DscpSet::parse("none").is_ok());
        assert!(EcnSet::parse("0,1,2,3").is_ok());
        assert!(EcnSet::parse("all").is_ok());

        // A wholly empty spec keeps its own clearer diagnostic.
        assert!(DscpSet::parse("").is_err());
        assert!(DscpSet::parse("   ").is_err());
    }
    use super::*;

    #[test]
    fn dscp_set_parses_wildcards() {
        assert_eq!(DscpSet::parse("all").unwrap(), DscpSet::all());
        assert_eq!(DscpSet::parse("none").unwrap(), DscpSet::none());
        assert_eq!(DscpSet::parse(" ALL ").unwrap(), DscpSet::all());
    }

    #[test]
    fn dscp_set_parses_values_and_ranges() {
        let s = DscpSet::parse("0,8,10-14,46").unwrap();
        for permitted in [0u8, 8, 10, 11, 12, 13, 14, 46] {
            assert!(s.contains(permitted), "{permitted} must be permitted");
        }
        for denied in [1u8, 9, 15, 45, 47, 63] {
            assert!(!s.contains(denied), "{denied} must be denied");
        }
    }

    #[test]
    fn dscp_set_rejects_bad_input() {
        assert!(DscpSet::parse("64").is_err(), "63 is the maximum codepoint");
        assert!(DscpSet::parse("ef").is_err(), "names are not accepted");
        assert!(DscpSet::parse("14-10").is_err(), "inverted range");
        assert!(DscpSet::parse("").is_err(), "empty list is a typo");
        assert!(DscpSet::parse("none,46").is_err(), "ambiguous");
        assert!(DscpSet::parse("all,0").is_err(), "ambiguous");
    }

    #[test]
    fn dscp_set_boundaries() {
        let s = DscpSet::parse("0,63").unwrap();
        assert!(s.contains(0));
        assert!(s.contains(63));
        assert!(!s.contains(1));
        // Only the low 6 bits are significant: a caller handing over a full
        // TOS byte must not alias onto a different codepoint.
        assert!(s.contains(0x40), "0x40 masks to 0");
    }

    #[test]
    fn ecn_set_parses_and_validates() {
        assert_eq!(EcnSet::parse("all").unwrap(), EcnSet::all());
        assert_eq!(EcnSet::parse("none").unwrap(), EcnSet::none());
        let s = EcnSet::parse("1,2").unwrap();
        assert!(s.contains(1) && s.contains(2));
        assert!(!s.contains(0) && !s.contains(3));
        assert!(EcnSet::parse("4").is_err());
        assert!(EcnSet::parse("").is_err());
        assert!(EcnSet::parse("all,1").is_err());
    }

    #[test]
    fn default_policy_permits_everything() {
        let p = CosAdmissionPolicy::default();
        assert!(p.is_permissive());
        for dscp in 0..64u8 {
            assert!(p.permits_dscp(None, dscp));
        }
        for ecn in 0..4u8 {
            assert!(p.permits_ecn(ecn));
        }
    }

    #[test]
    fn global_policy_restricts_dscp_and_ecn() {
        let p = CosAdmissionPolicy::new(
            DscpSet::parse("0,46").unwrap(),
            EcnSet::parse("0,2").unwrap(),
            Vec::new(),
        );
        assert!(!p.is_permissive());
        assert!(p.permits_dscp(None, 46));
        assert!(!p.permits_dscp(None, 34));
        assert!(p.permits_ecn(2));
        assert!(!p.permits_ecn(1));
    }

    #[test]
    fn destination_rule_overrides_the_global_set() {
        let (prefix, len, dscp) = parse_destination_rule("192.0.2.0/24=34").unwrap();
        let p = CosAdmissionPolicy::new(
            DscpSet::parse("0,46").unwrap(),
            EcnSet::all(),
            vec![(prefix, len, dscp)],
        );

        let inside: IpAddr = "192.0.2.7".parse().unwrap();
        let outside: IpAddr = "198.51.100.7".parse().unwrap();

        // Inside the prefix the rule decides, and it decides *entirely* —
        // it replaces the global set rather than adding to it.
        assert!(p.permits_dscp(Some(inside), 34));
        assert!(!p.permits_dscp(Some(inside), 46));
        // Outside it, the global set applies.
        assert!(p.permits_dscp(Some(outside), 46));
        assert!(!p.permits_dscp(Some(outside), 34));
    }

    #[test]
    fn most_specific_destination_rule_wins_regardless_of_order() {
        let broad = parse_destination_rule("10.0.0.0/8=0").unwrap();
        let narrow = parse_destination_rule("10.1.2.0/24=46").unwrap();

        // Given in the "wrong" order, the /24 must still win.
        let p = CosAdmissionPolicy::new(DscpSet::none(), EcnSet::all(), vec![broad, narrow]);
        let target: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(p.permits_dscp(Some(target), 46));
        assert!(!p.permits_dscp(Some(target), 0));

        // And a /8-only address falls to the broader rule.
        let other: IpAddr = "10.9.9.9".parse().unwrap();
        assert!(p.permits_dscp(Some(other), 0));
        assert!(!p.permits_dscp(Some(other), 46));
    }

    #[test]
    fn unknown_destination_falls_back_to_the_global_set() {
        let rule = parse_destination_rule("192.0.2.0/24=34").unwrap();
        let p = CosAdmissionPolicy::new(DscpSet::parse("46").unwrap(), EcnSet::all(), vec![rule]);
        // No destination known: only the global set can be evaluated.
        assert!(p.permits_dscp(None, 46));
        assert!(!p.permits_dscp(None, 34));
    }

    #[test]
    fn destination_rules_do_not_match_across_families() {
        let rule = parse_destination_rule("192.0.2.0/24=63").unwrap();
        let p = CosAdmissionPolicy::new(DscpSet::none(), EcnSet::all(), vec![rule]);
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(
            !p.permits_dscp(Some(v6), 63),
            "an IPv4 rule must not govern an IPv6 destination"
        );
    }

    #[test]
    fn ipv6_destination_rules_match_on_bit_boundaries() {
        let rule = parse_destination_rule("2001:db8::/32=46").unwrap();
        let p = CosAdmissionPolicy::new(DscpSet::none(), EcnSet::all(), vec![rule]);
        assert!(p.permits_dscp(Some("2001:db8::1".parse().unwrap()), 46));
        assert!(!p.permits_dscp(Some("2001:db9::1".parse().unwrap()), 46));
    }

    #[test]
    fn non_byte_aligned_prefix_lengths_match_correctly() {
        // /28 splits a byte: 10.0.0.16/28 covers .16-.31 only.
        let rule = parse_destination_rule("10.0.0.16/28=46").unwrap();
        let p = CosAdmissionPolicy::new(DscpSet::none(), EcnSet::all(), vec![rule]);
        assert!(p.permits_dscp(Some("10.0.0.16".parse().unwrap()), 46));
        assert!(p.permits_dscp(Some("10.0.0.31".parse().unwrap()), 46));
        assert!(!p.permits_dscp(Some("10.0.0.15".parse().unwrap()), 46));
        assert!(!p.permits_dscp(Some("10.0.0.32".parse().unwrap()), 46));
    }

    #[test]
    fn zero_length_prefix_covers_its_whole_family() {
        let rule = parse_destination_rule("0.0.0.0/0=46").unwrap();
        let p = CosAdmissionPolicy::new(DscpSet::none(), EcnSet::all(), vec![rule]);
        assert!(p.permits_dscp(Some("203.0.113.9".parse().unwrap()), 46));
        assert!(
            !p.permits_dscp(Some("2001:db8::1".parse().unwrap()), 46),
            "an IPv4 default route must not cover IPv6"
        );
    }

    #[test]
    fn destination_rule_parse_errors_name_the_problem() {
        assert!(parse_destination_rule("192.0.2.0/24").is_err(), "no '='");
        assert!(parse_destination_rule("192.0.2.0=46").is_err(), "no '/'");
        assert!(parse_destination_rule("nonsense/24=46").is_err());
        assert!(parse_destination_rule("192.0.2.0/33=46").is_err());
        assert!(parse_destination_rule("2001:db8::/129=46").is_err());
        assert!(parse_destination_rule("192.0.2.0/24=99").is_err());
    }
}
