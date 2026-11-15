//! Linux nix workload: fixed-header C fallback and real IPv6 option reflection.

use clap::ValueEnum;
use serde::Serialize;
use stamp_suite::{
    crypto::HmacKey,
    tlv::{RawTlv, ReflectedFixedHdrTlv, ReflectedIpv6ExtHdrTlv, TlvList, TypedTlv},
};
use std::{io, net::UdpSocket, os::fd::AsRawFd, process::Command};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(super) enum Mode {
    Fixed,
    Ipv6Ext,
    Combined,
}

pub(super) struct Profile {
    mode: Mode,
    ipv6: bool,
    denied: bool,
    options: Vec<u8>,
    request: TlvList,
    expected: Vec<RawTlv>,
}

impl Profile {
    pub(super) fn new(
        mode: Mode,
        ipv6: bool,
        bytes: Option<u16>,
        denied: bool,
    ) -> Result<Self, &'static str> {
        let fixed = mode != Mode::Ipv6Ext;
        let extension = mode != Mode::Fixed;
        if extension && !ipv6 {
            return Err("IPv6 extension header workloads require --ipv6");
        }
        if !extension && bytes.is_some() {
            return Err("--header-bytes requires an extension header workload");
        }
        let size = usize::from(bytes.unwrap_or(16));
        if extension && (!(16..=256).contains(&size) || !size.is_multiple_of(8)) {
            return Err("header bytes must be 16–256 and aligned to eight");
        }
        let mut profile = Self {
            mode,
            ipv6,
            denied,
            options: vec![],
            request: TlvList::new(),
            expected: vec![],
        };
        if fixed {
            let raw =
                ReflectedFixedHdrTlv::request_with_capacity(if ipv6 { 40 } else { 20 }).to_raw();
            profile.request.push(raw.clone()).unwrap();
            let mut reflected = raw;
            reflected.clear_reflector_flags();
            // Linux nix cannot capture fixed IP headers, even when permitted.
            reflected.set_conformant_reflected();
            profile.expected.push(reflected);
        }
        if extension {
            // One skippable experimental option occupies the entire header.
            // Its data length is at most 252; Next Header is set by the kernel.
            profile.options = vec![0; size];
            profile.options[1] = (size / 8 - 1) as u8;
            profile.options[2] = 0x1e;
            profile.options[3] = (size - 4) as u8;
            for (i, b) in profile.options[4..].iter_mut().enumerate() {
                *b = (i % 251 + 1) as u8;
            }
            let raw = ReflectedIpv6ExtHdrTlv::request_with_capacity(size).to_raw();
            profile.request.push(raw.clone()).unwrap();
            let mut reflected = if denied {
                raw
            } else {
                let mut captured = profile.options.clone();
                captured[0] = 17;
                ReflectedIpv6ExtHdrTlv::with_data(captured).to_raw()
            };
            reflected.clear_reflector_flags();
            if denied {
                reflected.set_conformant_reflected();
            }
            profile.expected.push(reflected);
        }
        Ok(profile)
    }

    pub(super) fn configure(&self, command: &mut Command, ip: &str) {
        if self.denied {
            return;
        }
        if self.mode != Mode::Ipv6Ext {
            command.args(["--reflect-fixed-header-from", ip]);
        }
        if self.mode != Mode::Fixed {
            command.args(["--reflect-ipv6-ext-header-from", ip]);
        }
    }

    pub(super) fn attach(&self, socket: &UdpSocket) -> io::Result<()> {
        if self.options.is_empty() {
            return Ok(());
        }
        // SAFETY: socket owns the open IPv6 descriptor; the bounded option
        // buffer stays live and its exact length is passed. The kernel validates it.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_DSTOPTS,
                self.options.as_ptr().cast(),
                self.options.len() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn append(&self, base: &mut Vec<u8>, key: Option<&HmacKey>) {
        let mut list = self.request.clone();
        if let Some(key) = key {
            list.set_hmac(key, &base[..4]);
        }
        base.extend(list.to_bytes());
    }

    pub(super) fn validate(&self, bytes: &[u8], base: usize, key: Option<&HmacKey>) -> bool {
        if bytes.len() != base + self.request.wire_size() + if key.is_some() { 20 } else { 0 } {
            return false;
        }
        let Ok(list) = TlvList::parse(&bytes[base..]) else {
            return false;
        };
        if list.non_hmac_tlvs() != self.expected || list.hmac_tlv().is_some() != key.is_some() {
            return false;
        }
        for raw in list.non_hmac_tlvs() {
            let expected_flag =
                if raw.tlv_type == stamp_suite::tlv::TlvType::ReflectedFixedHdr || self.denied {
                    0x10
                } else {
                    0
                };
            if raw.flags.to_byte() != expected_flag {
                return false;
            }
        }
        if let Some(key) = key {
            if list.hmac_tlv().unwrap().flags.to_byte() != 0
                || list.verify_hmac(key, &bytes[..4], &bytes[base..]).is_err()
            {
                return false;
            }
        }
        true
    }

    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"mode":self.mode,"ipv6":self.ipv6,"option_octets":self.options.len(),
            "policy_denied":self.denied,"backend":"linux_nix",
            "fixed_header_c_expected":self.mode != Mode::Ipv6Ext,
            "extension_header_c_expected":(self.mode != Mode::Fixed).then_some(self.denied)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(
        profile: &Profile,
        key: Option<&HmacKey>,
        mutate: impl FnOnce(&mut Vec<RawTlv>),
    ) -> Vec<u8> {
        let mut bytes = vec![0; if key.is_some() { 112 } else { 44 }];
        bytes[..4].copy_from_slice(&9u32.to_be_bytes());
        let mut raws = profile.expected.clone();
        mutate(&mut raws);
        let mut list = TlvList::new();
        for raw in raws {
            list.push(raw).unwrap();
        }
        if let Some(key) = key {
            assert!(list.set_hmac_response(key, &bytes[..4]));
        }
        bytes.extend(list.to_bytes());
        bytes
    }

    #[test]
    fn profiles_cover_fixed_fallback_extensions_policies_and_hmacs() {
        for ipv6 in [false, true] {
            for mode in [Mode::Fixed, Mode::Ipv6Ext, Mode::Combined] {
                if !ipv6 && mode != Mode::Fixed {
                    continue;
                }
                let sizes = if mode == Mode::Fixed {
                    vec![None]
                } else {
                    vec![Some(16), Some(256)]
                };
                for size in sizes {
                    for denied in [false, true] {
                        for auth in [false, true] {
                            let p = Profile::new(mode, ipv6, size, denied).unwrap();
                            let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
                            let base = if auth { 112 } else { 44 };
                            let mut request = vec![0; base];
                            p.append(&mut request, key.as_ref());
                            let list = TlvList::parse(&request[base..]).unwrap();
                            if let Some(key) = &key {
                                list.verify_hmac(key, &request[..4], &request[base..])
                                    .unwrap();
                            }
                            assert!(p.validate(
                                &response(&p, key.as_ref(), |_| {}),
                                base,
                                key.as_ref()
                            ));
                            if mode != Mode::Fixed {
                                assert_eq!(p.options[0], 0);
                                assert_eq!(p.options[2], 0x1e);
                                assert_eq!(usize::from(p.options[1] + 1) * 8, p.options.len());
                                assert_eq!(usize::from(p.options[3]) + 4, p.options.len());
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_incorrect_flags_headers_order_and_layout_are_rejected() {
        for denied in [false, true] {
            for auth in [false, true] {
                let p = Profile::new(Mode::Combined, true, Some(16), denied).unwrap();
                let key = auth.then(|| HmacKey::new(vec![0xcd; 32]).unwrap());
                let base = if auth { 112 } else { 44 };
                for variant in 0..7 {
                    let wrong = response(&p, key.as_ref(), |raws| match variant {
                        0 => raws[0].flags = stamp_suite::tlv::TlvFlags::default(),
                        1 => {
                            raws[1].flags =
                                stamp_suite::tlv::TlvFlags::from_byte(if denied { 0 } else { 0x10 })
                        }
                        2 => raws[1].value[0] ^= 1,
                        3 => raws[1].value[8] ^= 1,
                        4 => raws.swap(0, 1),
                        5 => {
                            raws.remove(0);
                        }
                        6 => raws.push(raws[1].clone()),
                        _ => unreachable!(),
                    });
                    assert!(!p.validate(&wrong, base, key.as_ref()), "variant {variant}");
                }
                let valid = response(&p, key.as_ref(), |_| {});
                assert!(!p.validate(&valid[..valid.len() - 1], base, key.as_ref()));
                if auth {
                    assert!(!p.validate(
                        &valid,
                        base,
                        Some(&HmacKey::new(vec![0xaa; 32]).unwrap())
                    ));
                }
            }
        }
    }

    #[test]
    fn header_bounds_and_address_family_are_explicit() {
        for mode in [Mode::Ipv6Ext, Mode::Combined] {
            assert!(Profile::new(mode, false, None, false).is_err());
            for size in [0, 8, 15, 17, 255, 257, u16::MAX] {
                assert!(Profile::new(mode, true, Some(size), false).is_err());
            }
        }
        assert!(Profile::new(Mode::Fixed, true, Some(16), false).is_err());
        assert!(Profile::new(Mode::Combined, true, Some(256), false).is_ok());
    }
}
