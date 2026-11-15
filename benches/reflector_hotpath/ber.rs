//! BER parsing, measurement, repair and reply assembly; no transport work.

use super::*;
use criterion::{BenchmarkId, Throughput};
use stamp_suite::{
    crypto::compute_packet_hmac,
    packets::{AUTH_BASE_SIZE, AUTH_HMAC_OFFSET, UNAUTH_BASE_SIZE},
    tlv::{
        ExtraPaddingTlv, ResidualBerValue, TlvType, RESIDUAL_BER_DEFAULT_PATTERN,
        RESIDUAL_BER_PATTERN_SUBTLV_TYPE,
    },
};

const EXPLICIT_PATTERN: [u8; 5] = [0x12, 0x34, 0x56, 0x78, 0x9a];

#[derive(Clone, Copy)]
struct Case {
    auth: bool,
    ipv6: bool,
    explicit: bool,
    damaged: bool,
    padding: usize,
}

impl Case {
    fn name(self) -> String {
        format!(
            "{}_{}_{}_{}",
            if self.auth { "auth" } else { "open" },
            if self.ipv6 { "ipv6" } else { "ipv4" },
            if self.explicit { "explicit" } else { "default" },
            if self.damaged { "damaged" } else { "clean" },
        )
    }

    fn base(self) -> usize {
        if self.auth {
            AUTH_BASE_SIZE
        } else {
            UNAUTH_BASE_SIZE
        }
    }

    fn source(self) -> SocketAddr {
        if self.ipv6 {
            "[2001:db8::1]:12345"
        } else {
            "192.0.2.1:12345"
        }
        .parse()
        .unwrap()
    }

    fn pattern(self) -> &'static [u8] {
        if self.explicit {
            &EXPLICIT_PATTERN
        } else {
            &RESIDUAL_BER_DEFAULT_PATTERN
        }
    }

    fn clean_padding(self) -> Vec<u8> {
        assert_eq!(self.padding % self.pattern().len(), 0);
        self.pattern().repeat(self.padding / self.pattern().len())
    }

    fn packet(self, key: &HmacKey) -> Vec<u8> {
        let mut packet = if self.auth {
            build_auth_base()
        } else {
            build_unauth_base()
        };
        if self.auth {
            let digest = compute_packet_hmac(key, &packet, AUTH_HMAC_OFFSET);
            packet[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE].copy_from_slice(&digest);
        }
        let mut padding = self.clean_padding();
        if self.damaged {
            // One four-bit run spanning two octets, and one isolated bit.
            // This oracle does not call the production BER counting helper.
            padding[self.padding / 2] ^= 0x03;
            padding[self.padding / 2 + 1] ^= 0xc0;
            padding[self.padding - 2] ^= 0x80;
        }
        let mut tlvs = TlvList::new();
        tlvs.push(
            ResidualBerValue::request(
                RESIDUAL_BER_PATTERN_SUBTLV_TYPE,
                self.explicit.then_some(self.pattern()),
            )
            .unwrap()
            .to_raw()
            .unwrap(),
        )
        .unwrap();
        tlvs.push(ExtraPaddingTlv { padding }.to_raw()).unwrap();
        if self.auth {
            // BER serialization places padding after the HMAC and outside
            // its coverage, so damaged padding still exercises valid admission.
            tlvs.set_hmac(key, &packet[..4]);
        }
        packet.extend(tlvs.to_bytes());
        packet
    }

    fn context(self, key: &HmacKey) -> ProcessingContext<'_> {
        let mut ctx = make_ctx(self.auth.then_some(key));
        let source = self.source();
        let destination: SocketAddr = if self.ipv6 {
            "[2001:db8::2]:862"
        } else {
            "192.0.2.2:862"
        }
        .parse()
        .unwrap();
        ctx.packet_local_addr = Some(destination);
        ctx.packet_addr_info = Some(PacketAddressInfo {
            src_addr: source.ip(),
            src_port: source.port(),
            dst_addr: destination.ip(),
            dst_port: destination.port(),
            src_mac: None,
        });
        ctx
    }

    fn validate(self, packet: &[u8], ctx: &ProcessingContext<'_>, key: &HmacKey) {
        let request = TlvList::parse(&packet[self.base()..]).unwrap();
        assert_eq!(request.non_hmac_tlvs().len(), 2);
        if self.auth {
            request
                .verify_hmac(key, &packet[..4], &packet[self.base()..])
                .unwrap();
        }
        let reply = process_stamp_packet(packet, self.source(), 64, self.auth, ctx)
            .expect("BER benchmark fixture rejected");
        assert_eq!(reply.data.len(), packet.len());
        assert!(reply.ber_conformance.is_empty());
        assert!(reply.tlv_conformance.is_empty());
        assert!(reply.reflected_control.is_none());
        let tlvs = TlvList::parse(&reply.data[self.base()..]).unwrap();
        assert_eq!(tlvs.non_hmac_tlvs().len(), 2);
        for raw in tlvs.iter() {
            assert_eq!(
                raw.flags.to_byte(),
                0,
                "reply must be processed successfully"
            );
        }
        let ber = tlvs
            .iter()
            .find(|t| t.tlv_type == TlvType::ResidualBer)
            .map(|t| ResidualBerValue::from_raw(t).unwrap())
            .unwrap();
        let expected = if self.damaged { (5, 4) } else { (0, 0) };
        assert_eq!((ber.count, ber.max_burst), expected);
        assert_eq!(ber.sub_tlvs.len(), usize::from(self.explicit));
        if self.explicit {
            assert_eq!(ber.sub_tlvs[0].flags, 0);
            assert_eq!(ber.sub_tlvs[0].kind, RESIDUAL_BER_PATTERN_SUBTLV_TYPE);
            assert_eq!(ber.sub_tlvs[0].value, self.pattern());
        }
        let padding = tlvs
            .iter()
            .find(|t| t.tlv_type == TlvType::ExtraPadding)
            .unwrap();
        assert_eq!(padding.value, self.clean_padding());
        assert_eq!(reply.tlv_hmac_generated, self.auth);
        assert_eq!(tlvs.hmac_tlv().is_some(), self.auth);
        if self.auth {
            let digest = compute_packet_hmac(key, &reply.data, AUTH_HMAC_OFFSET);
            assert_eq!(reply.data[AUTH_HMAC_OFFSET..AUTH_BASE_SIZE], digest);
            tlvs.verify_hmac(key, &reply.data[..4], &reply.data[self.base()..])
                .unwrap();
        }
    }
}

pub(super) fn bench(c: &mut Criterion) {
    let key = HmacKey::new(vec![0xcd; 32]).unwrap();
    let mut group = c.benchmark_group("ber");
    group.throughput(Throughput::Elements(1));
    for ipv6 in [false, true] {
        for auth in [false, true] {
            for explicit in [false, true] {
                for damaged in [false, true] {
                    for padding in [120, 1200] {
                        let case = Case {
                            auth,
                            ipv6,
                            explicit,
                            damaged,
                            padding,
                        };
                        let packet = case.packet(&key);
                        let ctx = case.context(&key);
                        case.validate(&packet, &ctx, &key);
                        let source = case.source();
                        group.bench_function(BenchmarkId::new(case.name(), padding), |b| {
                            b.iter(|| {
                                drop(black_box(process_stamp_packet(
                                    black_box(&packet),
                                    black_box(source),
                                    black_box(64),
                                    black_box(auth),
                                    black_box(&ctx),
                                )));
                            });
                        });
                    }
                }
            }
        }
    }
    group.finish();
}
