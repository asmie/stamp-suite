//! Header matching, reflection and reply assembly from synthetic captures.

use super::*;
use criterion::{BenchmarkId, Throughput};
use stamp_suite::{
    crypto::compute_packet_hmac,
    packets::{AUTH_BASE_SIZE, AUTH_HMAC_OFFSET, UNAUTH_BASE_SIZE},
    receiver::CapturedHeaders,
    tlv::{RawTlv, ReflectedFixedHdrTlv, ReflectedIpv6ExtHdrTlv, TlvConformanceReason, TlvFlags},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Ipv4,
    Ipv4Stack,
    Ipv6Fixed,
    Ipv6Small,
    Ipv6Large,
    Ipv6Selectors,
    NoCapture,
    PolicyDenied,
}

impl Scenario {
    const ALL: [Self; 8] = [
        Self::Ipv4,
        Self::Ipv4Stack,
        Self::Ipv6Fixed,
        Self::Ipv6Small,
        Self::Ipv6Large,
        Self::Ipv6Selectors,
        Self::NoCapture,
        Self::PolicyDenied,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4_fixed",
            Self::Ipv4Stack => "ipv4_stack_8",
            Self::Ipv6Fixed => "ipv6_fixed",
            Self::Ipv6Small => "ipv6_ext_8",
            Self::Ipv6Large => "ipv6_ext_256",
            Self::Ipv6Selectors => "ipv6_selectors_8",
            Self::NoCapture => "ipv6_capture_unavailable",
            Self::PolicyDenied => "ipv6_policy_denied",
        }
    }

    fn ipv6(self) -> bool {
        !matches!(self, Self::Ipv4 | Self::Ipv4Stack)
    }

    fn source(self) -> SocketAddr {
        if self.ipv6() {
            "[2001:db8::1]:12345"
        } else {
            "192.0.2.1:12345"
        }
        .parse()
        .unwrap()
    }
}

struct Fixture {
    scenario: Scenario,
    auth: bool,
    captured: CapturedHeaders,
    request_tlvs: Vec<RawTlv>,
    expected_tlvs: Vec<RawTlv>,
    reasons: Vec<TlvConformanceReason>,
    packet: Vec<u8>,
}

impl Fixture {
    fn new(scenario: Scenario, auth: bool, key: &HmacKey) -> Self {
        let mut fixture = Self {
            scenario,
            auth,
            captured: CapturedHeaders::default(),
            request_tlvs: Vec::new(),
            expected_tlvs: Vec::new(),
            reasons: Vec::new(),
            packet: if auth {
                build_auth_base()
            } else {
                build_unauth_base()
            },
        };
        let fixed_count = if scenario == Scenario::Ipv4Stack {
            8
        } else {
            1
        };
        for ordinal in 0..fixed_count {
            let mut header = vec![0; if scenario.ipv6() { 40 } else { 20 }];
            header[0] = if scenario.ipv6() { 0x60 } else { 0x45 };
            // Distinct captured tails make ordinal pairing observable.
            let last = header.len() - 1;
            header[last] = ordinal + 1;
            fixture.captured.fixed_headers.push(header.clone());
            fixture
                .request_tlvs
                .push(ReflectedFixedHdrTlv::request_with_capacity(header.len()).to_raw());
            fixture
                .expected_tlvs
                .push(ReflectedFixedHdrTlv::with_header(header).to_raw());
        }
        let (ext_count, ext_len) = match scenario {
            Scenario::Ipv6Small => (1, 8),
            Scenario::Ipv6Large => (1, 256),
            Scenario::Ipv6Selectors => (8, 16),
            Scenario::NoCapture | Scenario::PolicyDenied => (1, 16),
            _ => (0, 0),
        };
        let mut extensions = Vec::new();
        for ordinal in 0..ext_count {
            let mut header = vec![0; ext_len];
            header[0] = if ordinal + 1 == ext_count { 17 } else { 60 };
            header[1] = (ext_len / 8 - 1) as u8;
            // Unique selectors in the first eight bytes, without relying on
            // production matching code to generate the expected result.
            header[7] = ordinal as u8 + 1;
            fixture.captured.ipv6_ext_headers.extend_from_slice(&header);
            extensions.push(header);
        }
        if scenario == Scenario::Ipv6Selectors {
            // Reverse requests to exercise unique matching, not just first-fit
            // matching in capture order. Every capture is consumed once.
            extensions.reverse();
        }
        for header in extensions {
            fixture
                .request_tlvs
                .push(if scenario == Scenario::Ipv6Selectors {
                    ReflectedIpv6ExtHdrTlv::request_with_selector(&header[..8], header.len())
                        .to_raw()
                } else {
                    ReflectedIpv6ExtHdrTlv::request_with_capacity(header.len()).to_raw()
                });
            fixture
                .expected_tlvs
                .push(ReflectedIpv6ExtHdrTlv::with_data(header).to_raw());
        }
        for raw in &mut fixture.expected_tlvs {
            raw.clear_reflector_flags();
        }
        if matches!(scenario, Scenario::NoCapture | Scenario::PolicyDenied) {
            fixture.expected_tlvs.clone_from(&fixture.request_tlvs);
            for raw in &mut fixture.expected_tlvs {
                raw.clear_reflector_flags();
                raw.set_conformant_reflected();
            }
            fixture.reasons = if scenario == Scenario::NoCapture {
                vec![TlvConformanceReason::HeaderCaptureUnavailable]
            } else {
                vec![
                    TlvConformanceReason::HeaderFixedPolicy,
                    TlvConformanceReason::HeaderIpv6Policy,
                ]
            };
        }
        if auth {
            let digest = compute_packet_hmac(key, &fixture.packet, AUTH_HMAC_OFFSET);
            fixture.packet[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE].copy_from_slice(&digest);
        }
        let mut list = TlvList::new();
        for raw in &fixture.request_tlvs {
            list.push(raw.clone()).unwrap();
        }
        if auth {
            list.set_hmac(key, &fixture.packet[..4]);
        }
        fixture.packet.extend(list.to_bytes());
        fixture
    }

    fn base(&self) -> usize {
        if self.auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        }
    }

    fn context<'a>(&'a self, key: &'a HmacKey) -> ProcessingContext<'a> {
        let mut ctx = make_ctx(self.auth.then_some(key));
        let destination: SocketAddr = if self.scenario.ipv6() {
            "[2001:db8::2]:862"
        } else {
            "192.0.2.2:862"
        }
        .parse()
        .unwrap();
        let source = self.scenario.source();
        ctx.packet_local_addr = Some(destination);
        ctx.packet_addr_info = Some(PacketAddressInfo {
            src_addr: source.ip(),
            src_port: source.port(),
            dst_addr: destination.ip(),
            dst_port: destination.port(),
            src_mac: None,
        });
        ctx.captured_headers = (self.scenario != Scenario::NoCapture).then_some(&self.captured);
        ctx.reflect_fixed_header = self.scenario != Scenario::PolicyDenied;
        ctx.reflect_ipv6_ext_header = self.scenario != Scenario::PolicyDenied;
        ctx
    }

    fn validate(&self, ctx: &ProcessingContext<'_>, key: &HmacKey) {
        let request = TlvList::parse(&self.packet[self.base()..]).unwrap();
        assert_eq!(request.non_hmac_tlvs(), self.request_tlvs);
        if self.auth {
            request
                .verify_hmac(key, &self.packet[..4], &self.packet[self.base()..])
                .unwrap();
        }
        let response =
            process_stamp_packet(&self.packet, self.scenario.source(), 64, self.auth, ctx)
                .expect("header benchmark fixture rejected");
        let returned = TlvList::parse(&response.data[self.base()..]).unwrap();
        // Equality checks types, order, every value octet and all flag bits.
        assert_eq!(returned.non_hmac_tlvs(), self.expected_tlvs);
        for raw in returned.non_hmac_tlvs() {
            // Literal wire masks keep this check independent of flag setters.
            assert_eq!(
                raw.flags.to_byte(),
                if self.reasons.is_empty() { 0 } else { 0x10 }
            );
        }
        assert_eq!(response.data.len(), self.packet.len());
        assert_eq!(
            response.tlv_conformance.iter().collect::<Vec<_>>(),
            self.reasons
        );
        assert!(response.ber_conformance.is_empty());
        assert!(response.reflected_control.is_none());
        assert_eq!(response.tlv_hmac_generated, self.auth);
        assert_eq!(returned.hmac_tlv().is_some(), self.auth);
        if self.auth {
            assert_eq!(returned.hmac_tlv().unwrap().flags, TlvFlags::default());
            let digest = compute_packet_hmac(key, &response.data, AUTH_HMAC_OFFSET);
            assert_eq!(response.data[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE], digest);
            returned
                .verify_hmac(key, &response.data[..4], &response.data[self.base()..])
                .unwrap();
        }
    }
}

pub(super) fn bench(c: &mut Criterion) {
    let key = HmacKey::new(vec![0xab; 32]).unwrap();
    let mut group = c.benchmark_group("headers");
    group.throughput(Throughput::Elements(1));
    for scenario in Scenario::ALL {
        for auth in [false, true] {
            let fixture = Fixture::new(scenario, auth, &key);
            let ctx = fixture.context(&key);
            fixture.validate(&ctx, &key);
            let source = scenario.source();
            group.bench_function(
                BenchmarkId::new(scenario.name(), if auth { "auth" } else { "open" }),
                |b| {
                    b.iter(|| {
                        drop(black_box(process_stamp_packet(
                            black_box(&fixture.packet),
                            black_box(source),
                            black_box(64),
                            black_box(auth),
                            black_box(&ctx),
                        )));
                    });
                },
            );
        }
    }
    group.finish();
}
