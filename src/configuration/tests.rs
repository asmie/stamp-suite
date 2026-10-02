#[test]
fn reflector_queue_settings_merge_validate_and_allow_cli_override() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("queue.toml");
    std::fs::write(
        &file,
        "reflector_queue_capacity = 2\nreflector_shutdown_grace_ms = 125\n",
    )
    .unwrap();
    let conf = load_from_args(&["test", "--config", file.to_str().unwrap()]).unwrap();
    assert_eq!(conf.reflector_queue_capacity, 2);
    assert_eq!(conf.reflector_shutdown_grace_ms, 125);
    let overridden = load_from_args(&[
        "test",
        "--config",
        file.to_str().unwrap(),
        "--reflector-queue-capacity",
        "3",
        "--reflector-shutdown-grace-ms",
        "0",
    ])
    .unwrap();
    assert_eq!(overridden.reflector_queue_capacity, 3);
    assert_eq!(overridden.reflector_shutdown_grace_ms, 0);
    for bad in [
        "reflector_queue_capacity = 0\n",
        "reflector_shutdown_grace_ms = 60001\n",
    ] {
        std::fs::write(&file, bad).unwrap();
        assert!(load_from_args(&["test", "--config", file.to_str().unwrap()]).is_err());
    }
    assert!(Configuration::try_parse_from(["test", "--reflector-queue-capacity", "0"]).is_err());
    assert!(
        Configuration::try_parse_from(["test", "--reflector-shutdown-grace-ms", "60001"]).is_err()
    );
}
use clap::Parser;
use std::net::IpAddr;

use super::*;

#[test]
fn ber_configuration_rejects_invalid_patterns_and_intervals() {
    use clap::Parser;
    for extra in [
        vec!["--ber-padding-size", "3"],
        vec!["--ber-padding-size", "0"],
        vec!["--ber-pattern", ""],
        vec!["--ber-pattern", "fg"],
        vec!["--ber-pattern", "fff"],
        vec!["--ber-interval", "0"],
        vec!["--send-delay", "0"],
        vec!["--ber-bit-threshold", "NaN"],
        vec!["--ber-packet-threshold", "1000001"],
    ] {
        let args = [vec!["test", "--ber"], extra].concat();
        let conf = Configuration::try_parse_from(args).unwrap();
        assert!(conf.validate().is_err());
    }
    let conf = Configuration::try_parse_from([
        "test",
        "--ber",
        "--ber-pattern",
        "0xaaff",
        "--ber-padding-size",
        "6",
    ])
    .unwrap();
    assert!(conf.validate().is_ok());
}

#[test]
fn ber_config_file_merges_and_validates_measurement_settings() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ber = true\nber_pattern = \"0xaa55\"\nber_padding_size = 6\nber_interval = 3\nber_bit_threshold = 12.5\nber_packet_threshold = 250.0\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).unwrap();
    assert_eq!(conf.ber_interval, 3);
    assert_eq!(conf.ber_bit_threshold, Some(12.5));
    assert_eq!(conf.ber_packet_threshold, Some(250.0));
    assert_eq!(conf.ber_pattern.as_deref(), Some("0xaa55"));
    let cli = load_from_args(&[
        "test",
        "--config",
        path.to_str().unwrap(),
        "--ber-interval",
        "4",
    ])
    .unwrap();
    assert_eq!(cli.ber_interval, 4);
    std::fs::write(&path, "ber = true\nber_padding_size = 3\n").unwrap();
    assert!(load_from_args(&["test", "--config", path.to_str().unwrap()]).is_err());
}

#[test]
fn sender_reflector_id_requires_a_sender_micro_session_id() {
    let mut conf = Configuration::parse_from(["stamp-suite", "--reflector-member-link-id", "9"]);
    assert!(conf
        .validate()
        .unwrap_err()
        .to_string()
        .contains("requires micro_session_id"));
    conf.micro_session_id = Some(7);
    assert!(conf.validate().is_ok());
    conf.micro_session_id = None;
    conf.is_reflector = true;
    assert!(conf.validate().is_ok());
}

#[test]
fn reflector_utc_offset_file_default_and_signed_cli_override() {
    for (args, expected) in [
        (vec!["stamp-suite"], 37),
        (vec!["stamp-suite", "--reflector-utc-offset", "-19"], -19),
        (vec!["stamp-suite", "--reflector-utc-offset", "0"], 0),
    ] {
        let matches = <Configuration as clap::CommandFactory>::command().get_matches_from(&args);
        let mut conf = <Configuration as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
        let file = toml::from_str("reflector_utc_offset = 37").unwrap();
        conf.merge_file(file, &matches);
        assert_eq!(conf.reflector_utc_offset, expected);
    }
}
#[test]
fn test_valid_configuration_parsing() {
    let args = vec![
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "0.0.0.0",
        "--remote-port",
        "862",
        "--local-port",
        "862",
        "--clock-source",
        "NTP",
        "--send-delay",
        "1000",
        "--count",
        "1000",
        "--timeout",
        "5",
        "--auth-mode",
        "A",
        "--is-reflector",
        "--hmac-key",
        "0123456789abcdef0123456789abcdef",
    ];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.remote_addr, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(conf.local_addr, "0.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(conf.remote_port, 862);
    assert_eq!(conf.local_port, 862);
    assert_eq!(conf.clock_source, ClockFormat::NTP);
    assert_eq!(conf.send_delay, ProbeInterval::from_millis(1000));
    assert_eq!(conf.count, 1000);
    assert_eq!(conf.timeout, 5);
    assert_eq!(conf.auth_mode, AuthMode::Authenticated);
    assert!(conf.is_reflector);
    assert!(conf.hmac_key.is_some());
    assert!(conf.validate().is_ok());
}

#[test]
fn session_provisioning_validation() {
    let base = [
        "test",
        "--is-reflector",
        "--local-addr",
        "0.0.0.0",
        "--local-port",
        "862",
        "--session-admission",
        "provisioned",
    ];
    let mut conf = Configuration::try_parse_from(base).unwrap();
    assert!(conf.provisioned_sessions().unwrap().is_empty()); // explicit deny-all
    for spec in [
        "42,127.0.0.1:4000,127.0.0.1:862",
        "0,127.0.0.1:4000,127.0.0.1:862",
        "42,127.0.0.1:4000,127.0.0.1:862,7",
    ] {
        conf.reflector_sessions = vec![spec.into()];
        assert_eq!(conf.provisioned_sessions().unwrap().len(), 1);
    }
    for spec in [
        "42,127.0.0.1:4000,0.0.0.0:862",
        "42,127.0.0.1:0,127.0.0.1:862",
        "42,127.0.0.1:4000,127.0.0.1:863",
        "42,[::1]:4000,[::1]:862",
        "oops",
    ] {
        conf.reflector_sessions = vec![spec.into()];
        assert!(conf.provisioned_sessions().is_err(), "{spec}");
    }
    conf.reflector_sessions = vec!["42,127.0.0.1:4000,127.0.0.1:862".into(); 2];
    assert!(conf.provisioned_sessions().is_err());
    conf.reflector_sessions.truncate(1);
    conf.session_admission = SessionAdmission::Permissive;
    assert!(conf.provisioned_sessions().is_err());
    conf.session_admission = SessionAdmission::Provisioned;
    conf.is_reflector = false;
    assert!(conf.provisioned_sessions().is_err());
}

#[test]
fn session_provisioning_toml_and_ipv6() {
    let file: FileConfiguration = toml::from_str(
        "session_admission = 'provisioned'\nreflector_sessions = ['42,[::1]:4000,[::1]:862,7']",
    )
    .unwrap();
    let mut conf = Configuration::try_parse_from([
        "test",
        "--is-reflector",
        "--local-addr",
        "::",
        "--local-port",
        "862",
    ])
    .unwrap();
    conf.session_admission = file.session_admission.unwrap();
    conf.reflector_sessions = file.reflector_sessions.unwrap();
    assert_eq!(conf.provisioned_sessions().unwrap().len(), 1);
    conf.local_addr = "::2".parse().unwrap();
    assert!(conf.provisioned_sessions().is_err());
}

#[test]
fn test_invalid_configuration_parsing() {
    let args = vec!["test", "--remote-addr", "invalid_addr"];
    let conf = Configuration::try_parse_from(args);
    assert!(conf.is_err());
}

/// A known-good argument set that passes `validate()`, for tests that want
/// to isolate a single new validation rule.
fn base_valid_args() -> Vec<String> {
    [
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--local-addr",
        "0.0.0.0",
        "--remote-port",
        "862",
        "--local-port",
        "862",
        "--clock-source",
        "NTP",
        "--send-delay",
        "1000",
        "--count",
        "1000",
        "--timeout",
        "5",
        "--auth-mode",
        "A",
        "--is-reflector",
        "--hmac-key",
        "0123456789abcdef0123456789abcdef",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

#[test]
fn ext_hdr_selector_requires_enabling_flag() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-ipv6-ext-hdr-selector".to_string(),
        "3c000102".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn ext_hdr_selector_with_flag_is_accepted() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-ipv6-ext-hdr".to_string(),
        "--reflected-ipv6-ext-hdr-selector".to_string(),
        "3c000102".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_ok());
    assert_eq!(
        conf.reflected_ipv6_ext_hdr_selector.as_deref(),
        Some("3c000102")
    );
}

#[test]
fn all_zero_ext_hdr_selector_is_rejected() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-ipv6-ext-hdr".to_string(),
        "--reflected-ipv6-ext-hdr-selector".to_string(),
        "00000000".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn fixed_hdr_selector_requires_enabling_flag() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-fixed-hdr-selector".to_string(),
        "45000054".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn multi_ext_hdr_occurrences_parse_and_validate() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-ipv6-ext-hdr".to_string(),
        "8".to_string(),
        "--reflected-ipv6-ext-hdr".to_string(),
        "16:3c000102".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_ok());
    let specs = conf.ext_hdr_requests();
    assert_eq!(specs.len(), 2);
    assert_eq!(specs[0].length, 8);
    assert!(specs[0].selector.is_none());
    assert_eq!(specs[1].length, 16);
    assert_eq!(
        specs[1].selector.as_deref(),
        Some(&[0x3c, 0x00, 0x01, 0x02][..])
    );
}

#[test]
fn standalone_selector_rejected_with_multiple_ext_hdr_occurrences() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-ipv6-ext-hdr".to_string(),
        "--reflected-ipv6-ext-hdr".to_string(),
        "--reflected-ipv6-ext-hdr-selector".to_string(),
        "3c000102".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn attach_ext_hdr_default_and_custom_parse() {
    let mut args = base_valid_args();
    args.extend([
        "--attach-ext-hdr".to_string(),
        "hbh".to_string(),
        "--attach-ext-hdr".to_string(),
        "dest:0000010400000000".to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_ok());
    let attaches = conf.attach_ext_hdrs();
    assert_eq!(attaches.len(), 2);
    assert_eq!(attaches[0].kind, AttachExtHdrKind::HopByHop);
    assert_eq!(attaches[0].bytes.len(), 8);
    assert_eq!(attaches[1].kind, AttachExtHdrKind::DestOpts);
    assert_eq!(attaches[1].bytes.len(), 8);
}

#[test]
fn extra_padding_above_wire_safe_bound_is_rejected() {
    let mut args = base_valid_args();
    args.extend([
        "--extra-padding".to_string(),
        (MAX_PADDING_BYTES + 1).to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err(), "over-bound padding must fail");

    let mut args = base_valid_args();
    args.extend(["--extra-padding".to_string(), MAX_PADDING_BYTES.to_string()]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_ok(), "the bound itself is allowed");
}

#[test]
fn ber_padding_size_above_wire_safe_bound_is_rejected() {
    let mut args = base_valid_args();
    args.extend([
        "--ber".to_string(),
        "--ber-padding-size".to_string(),
        (MAX_PADDING_BYTES + 1).to_string(),
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

/// `-A A` + `--tlv-hmac off` on the sender is rejected: the auth send
/// path always originates an HMAC TLV on TLV-bearing packets, so the
/// explicit interop control cannot be honored and must not be silently
/// ignored. A reflector config is unaffected (the flag is sender-side).
#[test]
fn auth_mode_with_tlv_hmac_off_is_rejected_for_sender() {
    let sender_args = |auth_mode: &str, tlv_hmac: &str| {
        vec![
            "test".to_string(),
            "--remote-addr".to_string(),
            "127.0.0.1".to_string(),
            "--auth-mode".to_string(),
            auth_mode.to_string(),
            "--hmac-key".to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
            "--tlv-hmac".to_string(),
            tlv_hmac.to_string(),
        ]
    };

    let conf = Configuration::try_parse_from(sender_args("A", "off")).unwrap();
    assert!(
        conf.validate().is_err(),
        "sender -A A + --tlv-hmac off must be rejected"
    );

    // Same combination in open mode remains valid (verify-only key).
    let conf = Configuration::try_parse_from(sender_args("O", "off")).unwrap();
    assert!(conf.validate().is_ok());

    // A reflector keeps accepting tlv_hmac = off with -A A: the flag
    // controls sender origination only.
    let mut args = base_valid_args();
    args.extend(["--tlv-hmac".to_string(), "off".to_string()]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_ok());
}

#[test]
fn attach_ext_hdr_unknown_kind_is_rejected() {
    let mut args = base_valid_args();
    args.extend(["--attach-ext-hdr".to_string(), "bogus".to_string()]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn attach_ext_hdr_non_multiple_of_8_is_rejected() {
    let mut args = base_valid_args();
    args.extend(["--attach-ext-hdr".to_string(), "dest:000001".to_string()]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn fixed_hdr_selector_too_long_for_ipv4_is_rejected() {
    let mut args = base_valid_args();
    args.extend([
        "--reflected-fixed-hdr".to_string(),
        "--reflected-fixed-hdr-selector".to_string(),
        "01".repeat(21), // 21 bytes > 20-byte IPv4 fixed header
    ]);
    let conf = Configuration::try_parse_from(args).unwrap();
    assert!(conf.validate().is_err());
}

#[test]
fn test_control_plane_flags() {
    let args = vec![
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--is-reflector",
        "--control",
        "--control-addr",
        "127.0.0.1:9999",
    ];
    let conf = Configuration::parse_from(args);
    assert!(conf.control);
    assert_eq!(conf.control_addr, "127.0.0.1:9999".parse().unwrap());
    assert!(conf.control_token_file.is_none());
    assert_eq!(conf.validate().is_ok(), cfg!(feature = "control"));

    // --control is reflector-only.
    let args = vec!["test", "--remote-addr", "127.0.0.1", "--control"];
    let conf = Configuration::parse_from(args);
    assert!(
        conf.validate().is_err(),
        "--control without --is-reflector must be rejected"
    );
}

#[test]
fn test_return_path_no_reply_conflicts_with_reflected_control() {
    // RFC 10052 §4.3: a sender MUST NOT
    // combine a Return Path "no reply requested" control code with a
    // non-zero Reflected Test Packet Control TLV.
    let args = vec![
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--return-path-cc",
        "0",
        "--reflected-control-count",
        "4",
    ];
    let conf = Configuration::parse_from(args);
    assert!(
        conf.validate().is_err(),
        "no-reply control code + reflected-control-count > 1 must be rejected"
    );

    // cc=1 (reply requested) combines fine.
    let args = vec![
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--return-path-cc",
        "1",
        "--reflected-control-count",
        "4",
    ];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());

    // The ext-hdr-control sub-TLV also makes the TLV non-zero, even at
    // the default count of 1 — same §4.3 conflict.
    let args = vec![
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--return-path-cc",
        "0",
        "--reflected-control-no-ext-hdr",
    ];
    let conf = Configuration::parse_from(args);
    assert!(
        conf.validate().is_err(),
        "no-reply control code + ext-hdr-control sub-TLV must be rejected"
    );
}

#[test]
fn test_is_auth() {
    assert!(is_auth(AuthMode::Authenticated));
    assert!(!is_auth(AuthMode::Open));
}

#[test]
fn test_auth_mode_method() {
    assert!(AuthMode::Authenticated.is_authenticated());
    assert!(!AuthMode::Open.is_authenticated());
}

#[test]
fn test_default_configuration() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.remote_addr, "0.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(conf.local_addr, "0.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(conf.remote_port, 862);
    assert_eq!(conf.local_port, 0);
    assert_eq!(conf.clock_source, ClockFormat::NTP);
    assert_eq!(conf.send_delay, ProbeInterval::from_millis(1000));
    assert_eq!(conf.count, 1000);
    assert_eq!(conf.timeout, 5);
    assert_eq!(conf.auth_mode, AuthMode::Open); // RFC 8762 default
    assert!(!conf.print_stats);
    assert!(!conf.is_reflector);
    assert_eq!(conf.error_scale, 0);
    assert_eq!(conf.error_multiplier, 1);
    assert!(!conf.clock_synchronized);
    assert!(conf.hmac_key.is_none());
    assert!(conf.hmac_key_file.is_none());
    assert!(!conf.require_hmac);
}

#[test]
fn test_ipv6_address_parsing() {
    let args = vec!["test", "--remote-addr", "::1", "--local-addr", "fe80::1"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.remote_addr, "::1".parse::<IpAddr>().unwrap());
    assert_eq!(conf.local_addr, "fe80::1".parse::<IpAddr>().unwrap());
}

#[test]
fn test_short_flags() {
    let args = vec!["test", "-R", "-i"];
    let conf = Configuration::parse_from(args);
    assert!(conf.print_stats);
    assert!(conf.is_reflector);
}

#[test]
fn test_timeout_values() {
    let args = vec!["test", "--timeout", "0"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.timeout, 0);

    let args = vec!["test", "--timeout", "255"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.timeout, 255);
}

#[test]
fn test_send_delay_values() {
    let args = vec!["test", "--send-delay", "0"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.send_delay, ProbeInterval::from_millis(0));

    let args = vec!["test", "--send-delay", "65535"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.send_delay, ProbeInterval::from_millis(65535));
}

#[test]
fn test_clock_source_ptp() {
    let args = vec!["test", "--clock-source", "PTP"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.clock_source, ClockFormat::PTP);
}

#[test]
fn test_invalid_clock_source() {
    let args = vec!["test", "--clock-source", "INVALID"];
    let result = Configuration::try_parse_from(args);
    assert!(result.is_err());
}

#[test]
fn test_auth_mode_variations() {
    // Authenticated mode (requires HMAC key)
    let args = vec![
        "test",
        "--auth-mode",
        "A",
        "--hmac-key",
        "0123456789abcdef0123456789abcdef",
    ];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
    assert!(is_auth(conf.auth_mode));
    assert_eq!(conf.auth_mode, AuthMode::Authenticated);

    // Open mode
    let args = vec!["test", "--auth-mode", "O"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
    assert!(!is_auth(conf.auth_mode));
    assert_eq!(conf.auth_mode, AuthMode::Open);
}

#[test]
fn test_auth_mode_invalid_rejected_by_clap() {
    // Invalid values are now rejected by clap at parse time
    let invalid_modes = ["AO", "OA", "AA", "E", "X", "AE", "", "a", "o"];
    for mode in invalid_modes {
        let args = vec!["test", "--auth-mode", mode];
        let result = Configuration::try_parse_from(args);
        assert!(result.is_err(), "Mode '{}' should be rejected", mode);
    }
}

#[test]
fn test_auth_mode_display() {
    assert_eq!(AuthMode::Authenticated.to_string(), "A");
    assert_eq!(AuthMode::Open.to_string(), "O");
}

#[test]
fn test_auth_mode_default() {
    assert_eq!(AuthMode::default(), AuthMode::Open);
}

#[test]
fn test_auth_reflector_requires_hmac_key() {
    // Authenticated mode reflector without HMAC key should fail validation
    let args = vec!["test", "-i", "--auth-mode", "A"];
    let conf = Configuration::parse_from(args);
    let result = conf.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("requires --hmac-key"));
}

#[test]
fn test_auth_reflector_with_hmac_key_valid() {
    // Authenticated mode reflector with HMAC key should pass validation
    let args = vec![
        "test",
        "-i",
        "--auth-mode",
        "A",
        "--hmac-key",
        "0123456789abcdef0123456789abcdef",
    ];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_auth_sender_requires_hmac_key() {
    // Authenticated mode sender requires HMAC key
    let args = vec!["test", "--auth-mode", "A"];
    let conf = Configuration::parse_from(args);
    let err = conf.validate().unwrap_err();
    assert!(err.to_string().contains("requires --hmac-key"));
}

#[test]
fn test_auth_sender_with_hmac_key_valid() {
    // Authenticated mode sender with HMAC key is valid
    let args = vec![
        "test",
        "--auth-mode",
        "A",
        "--hmac-key",
        "0123456789abcdef0123456789abcdef",
    ];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_invalid_port_number() {
    let args = vec!["test", "--remote-port", "99999"];
    let result = Configuration::try_parse_from(args);
    assert!(result.is_err());
}

#[test]
fn test_error_estimate_options() {
    let args = vec![
        "test",
        "--error-scale",
        "10",
        "--error-multiplier",
        "100",
        "--clock-synchronized",
    ];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.error_scale, 10);
    assert_eq!(conf.error_multiplier, 100);
    assert!(conf.clock_synchronized);
}

#[test]
fn test_error_scale_validation() {
    let args = vec!["test", "--error-scale", "63"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());

    let args = vec!["test", "--error-scale", "64"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_err());
}

#[test]
fn test_error_multiplier_zero_is_rejected() {
    let conf = Configuration::parse_from(["test", "--error-multiplier", "0"]);
    assert!(conf.validate().is_err());
    let conf = Configuration::parse_from(["test", "--error-multiplier", "1"]);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_hmac_key_option() {
    let args = vec!["test", "--hmac-key", "0123456789abcdef0123456789abcdef"];
    let conf = Configuration::parse_from(args);

    assert_eq!(
        conf.hmac_key.as_ref().map(SecretString::as_str),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert!(conf.hmac_key_file.is_none());
}

#[test]
fn test_secret_string_redacts_debug_and_roundtrips() {
    use std::str::FromStr;
    let secret = "0123456789abcdef0123456789abcdef";
    let s = SecretString::from_str(secret).unwrap();
    assert_eq!(s.as_str(), secret, "as_str must roundtrip the value");

    // Debug must NOT leak the secret (it is held redacted on purpose).
    let dbg = format!("{s:?}");
    assert!(
        !dbg.contains(secret),
        "Debug output must not contain the secret: {dbg}"
    );
    assert!(dbg.contains("redacted"));

    // And through the Configuration struct's Debug as well.
    let conf = Configuration::parse_from(vec!["test", "--hmac-key", secret]);
    assert!(
        !format!("{conf:?}").contains(secret),
        "Configuration Debug must not leak the HMAC key"
    );
}

#[test]
fn test_hmac_key_file_option() {
    let args = vec!["test", "--hmac-key-file", "/path/to/key"];
    let conf = Configuration::parse_from(args);

    assert!(conf.hmac_key.is_none());
    assert_eq!(
        conf.hmac_key_file,
        Some(std::path::PathBuf::from("/path/to/key"))
    );
}

#[test]
fn test_require_hmac_option() {
    let args = vec!["test", "--require-hmac"];
    let conf = Configuration::parse_from(args);

    assert!(conf.require_hmac);
}

#[test]
fn test_strict_packets_option() {
    let args = vec!["test", "--strict-packets"];
    let conf = Configuration::parse_from(args);

    assert!(conf.strict_packets);
}

#[test]
fn test_strict_packets_default_false() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    // Default is false (lenient mode is default per RFC 8762 §4.6)
    assert!(!conf.strict_packets);
}

#[test]
fn test_log_format_default_text() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.log_format, LogFormat::Text);
}

#[test]
fn test_log_format_explicit_json() {
    let args = vec!["test", "--log-format", "json"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.log_format, LogFormat::Json);
}

#[test]
fn test_log_format_explicit_text() {
    let args = vec!["test", "--log-format", "text"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.log_format, LogFormat::Text);
}

#[test]
fn test_log_format_rejects_invalid() {
    let args = vec!["test", "--log-format", "yaml"];
    let result = Configuration::try_parse_from(args);
    assert!(result.is_err(), "unknown log format must be rejected");
}

#[test]
fn test_log_format_toml_round_trip() {
    let toml_str = r#"
            remote_addr = "127.0.0.1"
            log_format = "json"
        "#;
    let file: FileConfiguration = toml::from_str(toml_str).expect("parse");
    assert_eq!(file.log_format, Some(LogFormat::Json));
}

// -----------------------------------------------------------------------
// D4: --print-config-schema.

/// The exported schema is well-formed JSON.
#[test]
fn test_config_schema_is_valid_json() {
    let v: serde_json::Value =
        serde_json::from_str(CONFIG_JSON_SCHEMA).expect("schema must parse as JSON");
    assert!(v.is_object(), "schema root must be an object");
    let obj = v.as_object().unwrap();
    assert_eq!(
        obj.get("$schema").and_then(|s| s.as_str()),
        Some("https://json-schema.org/draft/2020-12/schema"),
        "must declare draft 2020-12"
    );
    assert_eq!(obj.get("type").and_then(|s| s.as_str()), Some("object"));
    assert_eq!(
        obj.get("additionalProperties").and_then(|b| b.as_bool()),
        Some(false),
        "schema must mirror FileConfiguration's deny_unknown_fields"
    );
}

/// Schema properties must match every `FileConfiguration` field.
/// Derive the field list by serializing the default: each `Option` becomes null.
#[test]
fn test_config_schema_matches_file_config_fields_exactly() {
    let v: serde_json::Value = serde_json::from_str(CONFIG_JSON_SCHEMA).unwrap();
    let props = v
        .get("properties")
        .and_then(|p| p.as_object())
        .expect("schema must have a properties object");

    let fields = serde_json::to_value(FileConfiguration::default()).unwrap();
    let fields = fields
        .as_object()
        .expect("FileConfiguration must serialize as an object");

    for name in fields.keys() {
        assert!(
            props.contains_key(name),
            "schema is missing property '{name}'; update CONFIG_JSON_SCHEMA \
                 (additionalProperties is false, so a valid config would be rejected)"
        );
    }
    for name in props.keys() {
        assert!(
            fields.contains_key(name),
            "schema property '{name}' has no FileConfiguration field; \
                 the schema would accept a key the parser rejects"
        );
    }
}

#[test]
fn test_print_config_schema_flag_parses() {
    let args = vec!["test", "--print-config-schema"];
    let conf = Configuration::parse_from(args);
    assert!(conf.print_config_schema);
}

#[test]
fn test_print_config_schema_default_false() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);
    assert!(!conf.print_config_schema);
}

// -----------------------------------------------------------------------
// --hwtstamp.

#[test]
fn test_hwtstamp_default_auto() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.hwtstamp, HwTsMode::Auto);
}

#[test]
fn test_reflected_control_max_count_defaults_to_zero() {
    // RFC 10052: the reflected-packet feature MUST
    // be disabled by default. A zero cap means no amplification unless the
    // operator opts in via --reflected-control-max-count.
    let conf = Configuration::parse_from(["test"]);
    assert_eq!(
        conf.reflected_control_max_count, 0,
        "Type 12 reflection must be disabled by default"
    );
}

#[test]
fn test_hwtstamp_explicit_on() {
    let args = vec!["test", "--hwtstamp", "on"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.hwtstamp, HwTsMode::On);
}

#[test]
fn test_hwtstamp_explicit_off() {
    let args = vec!["test", "--hwtstamp", "off"];
    let conf = Configuration::parse_from(args);
    assert_eq!(conf.hwtstamp, HwTsMode::Off);
}

#[test]
fn test_hwtstamp_rejects_invalid_value() {
    let args = vec!["test", "--hwtstamp", "always"];
    let result = Configuration::try_parse_from(args);
    assert!(result.is_err(), "unknown hwtstamp mode must be rejected");
}

#[test]
fn test_hwtstamp_toml_round_trip() {
    let toml_str = r#"
            remote_addr = "127.0.0.1"
            hwtstamp = "on"
        "#;
    let file: FileConfiguration = toml::from_str(toml_str).expect("parse");
    assert_eq!(file.hwtstamp, Some(HwTsMode::On));
}

#[test]
fn test_stateful_reflector_option() {
    let args = vec!["test", "--stateful-reflector"];
    let conf = Configuration::parse_from(args);

    assert!(conf.stateful_reflector);
}

#[test]
fn test_stateful_reflector_default_false() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    assert!(!conf.stateful_reflector);
}

#[test]
fn test_session_timeout_default() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.session_timeout, 300);
}

#[test]
fn test_session_timeout_custom() {
    let args = vec!["test", "--session-timeout", "600"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.session_timeout, 600);
}

#[test]
fn test_session_timeout_zero_disables() {
    let args = vec!["test", "--session-timeout", "0"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.session_timeout, 0);
}

#[test]
fn test_stateful_reflector_with_timeout() {
    let args = vec!["test", "--stateful-reflector", "--session-timeout", "120"];
    let conf = Configuration::parse_from(args);

    assert!(conf.stateful_reflector);
    assert_eq!(conf.session_timeout, 120);
}

#[test]
fn test_tlv_mode_default() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.tlv_mode, TlvHandlingMode::Echo);
}

#[test]
fn test_tlv_mode_ignore() {
    let args = vec!["test", "--tlv-mode", "ignore"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.tlv_mode, TlvHandlingMode::Ignore);
}

#[test]
fn test_tlv_mode_echo() {
    let args = vec!["test", "--tlv-mode", "echo"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.tlv_mode, TlvHandlingMode::Echo);
}

#[test]
fn test_verify_tlv_hmac_with_key() {
    let args = vec![
        "test",
        "--verify-tlv-hmac",
        "--hmac-key",
        "0123456789abcdef",
    ];
    let conf = Configuration::parse_from(args);

    assert!(conf.verify_tlv_hmac);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_verify_tlv_hmac_with_key_file() {
    let args = vec![
        "test",
        "--verify-tlv-hmac",
        "--hmac-key-file",
        "/path/to/key",
    ];
    let conf = Configuration::parse_from(args);

    assert!(conf.verify_tlv_hmac);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_verify_tlv_hmac_requires_key() {
    // --verify-tlv-hmac without HMAC key should fail validation
    let args = vec!["test", "--verify-tlv-hmac"];
    let conf = Configuration::parse_from(args);

    assert!(conf.verify_tlv_hmac);
    let result = conf.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("--verify-tlv-hmac requires"));
}

#[test]
fn test_verify_tlv_hmac_default() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    assert!(!conf.verify_tlv_hmac);
}

#[test]
fn test_ssid_option() {
    let args = vec!["test", "--ssid", "12345"];
    let conf = Configuration::parse_from(args);

    assert_eq!(conf.ssid, Some(12345));
}

#[test]
fn test_ssid_default_none() {
    let args = vec!["test"];
    let conf = Configuration::parse_from(args);

    assert!(conf.ssid.is_none());
}

#[test]
fn test_tlv_handling_mode_from_str() {
    // ValueEnum::from_str(value, ignore_case)
    assert_eq!(
        TlvHandlingMode::from_str("ignore", false).unwrap(),
        TlvHandlingMode::Ignore
    );
    assert_eq!(
        TlvHandlingMode::from_str("echo", false).unwrap(),
        TlvHandlingMode::Echo
    );
    // Case-insensitive parsing
    assert_eq!(
        TlvHandlingMode::from_str("ECHO", true).unwrap(),
        TlvHandlingMode::Echo
    );
    assert!(TlvHandlingMode::from_str("invalid", false).is_err());
    assert!(TlvHandlingMode::from_str("process", false).is_err());
}

#[test]
fn test_tlv_handling_mode_display() {
    assert_eq!(TlvHandlingMode::Ignore.to_string(), "ignore");
    assert_eq!(TlvHandlingMode::Echo.to_string(), "echo");
}

// ===== RFC 9503 Configuration Tests =====

#[test]
fn test_dest_node_addr_requires_ssid() {
    let args = vec!["test", "--dest-node-addr", "192.168.1.1"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_err());
}

#[test]
fn test_dest_node_addr_with_ssid_ok() {
    let args = vec!["test", "--dest-node-addr", "192.168.1.1", "--ssid", "42"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_return_path_cc_valid_values() {
    let args = vec!["test", "--return-path-cc", "0"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());

    let args = vec!["test", "--return-path-cc", "1"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
}

#[test]
fn test_return_path_cc_invalid_value() {
    let args = vec!["test", "--return-path-cc", "2"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_err());
}

#[test]
fn test_return_path_cc_conflicts_with_return_address() {
    let result = Configuration::try_parse_from(vec![
        "test",
        "--return-path-cc",
        "0",
        "--return-address",
        "10.0.0.1",
    ]);
    assert!(result.is_err()); // clap conflict
}

#[test]
fn test_return_sr_mpls_labels_valid() {
    let args = vec!["test", "--return-sr-mpls-labels", "100,200,300"];
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_ok());
    assert_eq!(conf.return_sr_mpls_labels, Some(vec![100, 200, 300]));
}

#[test]
fn test_return_sr_mpls_labels_exceeds_20bit() {
    let args = vec!["test", "--return-sr-mpls-labels", "1048576"]; // 0x100000
    let conf = Configuration::parse_from(args);
    assert!(conf.validate().is_err());
}

#[test]
fn test_return_srv6_sids_parsed() {
    let args = vec!["test", "--return-srv6-sids", "2001:db8::1,2001:db8::2"];
    let conf = Configuration::parse_from(args);
    assert_eq!(
        conf.return_srv6_sids,
        Some(vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ])
    );
}

#[test]
fn test_return_sr_mpls_conflicts_with_srv6() {
    let args = vec![
        "test",
        "--return-sr-mpls-labels",
        "100,200",
        "--return-srv6-sids",
        "2001:db8::1",
    ];
    let result = Configuration::try_parse_from(args);
    assert!(result.is_err());
}

// ===== TOML Configuration File Tests =====

use clap::CommandFactory;

fn load_from_args(args: &[&str]) -> Result<Configuration, ConfigurationError> {
    let matches = Configuration::command()
        .try_get_matches_from(args)
        .map_err(|e| ConfigurationError::InvalidConfiguration(e.to_string()))?;
    Configuration::load_from_matches(matches)
}

#[test]
fn test_file_config_parses_minimal_toml() {
    let file: FileConfiguration = toml::from_str("").expect("empty TOML parses");
    assert!(file.remote_addr.is_none());
    assert!(file.remote_port.is_none());
    assert!(file.auth_mode.is_none());
    assert!(file.ber.is_none());
}

#[test]
fn test_file_config_parses_all_common_fields() {
    let toml_str = r#"
            remote_addr = "127.0.0.1"
            local_addr = "192.168.1.1"
            remote_port = 10862
            local_port = 20862
            clock_source = "PTP"
            send_delay = 500
            count = 10
            timeout = 2
            auth_mode = "A"
            is_reflector = true
            ber = true
            ber_padding_size = 128
            return_sr_mpls_labels = [100, 200, 300]
            return_srv6_sids = ["2001:db8::1", "2001:db8::2"]
            output_format = "json"
            tlv_mode = "ignore"
        "#;
    let file: FileConfiguration = toml::from_str(toml_str).expect("parses");
    assert_eq!(file.remote_addr, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(file.remote_port, Some(10862));
    assert_eq!(file.clock_source, Some(ClockFormat::PTP));
    assert_eq!(file.auth_mode, Some(AuthMode::Authenticated));
    assert_eq!(file.is_reflector, Some(true));
    assert_eq!(file.ber, Some(true));
    assert_eq!(file.ber_padding_size, Some(128));
    assert_eq!(file.return_sr_mpls_labels, Some(vec![100, 200, 300]));
    assert_eq!(
        file.return_srv6_sids,
        Some(vec![
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
        ])
    );
    assert_eq!(file.output_format, Some(OutputFormat::Json));
    assert_eq!(file.tlv_mode, Some(TlvHandlingMode::Ignore));
}

#[test]
fn test_file_config_rejects_unknown_key() {
    let toml_str = r#"remote_adddr = "127.0.0.1""#;
    let err =
        toml::from_str::<FileConfiguration>(toml_str).expect_err("unknown key must be rejected");
    assert!(err.to_string().contains("remote_adddr"));
}

#[test]
fn test_file_config_rejects_plaintext_hmac_key() {
    let toml_str = r#"hmac_key = "deadbeef""#;
    let err = toml::from_str::<FileConfiguration>(toml_str)
        .expect_err("hmac_key must not be accepted from TOML");
    assert!(err.to_string().contains("hmac_key"));
}

#[test]
fn test_file_config_allows_hmac_key_file() {
    let toml_str = r#"hmac_key_file = "/etc/stamp/key""#;
    let file: FileConfiguration = toml::from_str(toml_str).expect("parses");
    assert_eq!(file.hmac_key_file, Some(PathBuf::from("/etc/stamp/key")));
}

#[test]
fn test_merge_cli_overrides_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "remote_port = 5678\n").unwrap();

    let conf = load_from_args(&[
        "test",
        "--config",
        path.to_str().unwrap(),
        "--remote-port",
        "1234",
    ])
    .expect("load ok");
    assert_eq!(conf.remote_port, 1234);
}

#[test]
fn test_merge_file_overrides_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "remote_port = 5678\n").unwrap();

    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
    assert_eq!(conf.remote_port, 5678);
}

#[test]
fn test_merge_default_when_neither_set() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "").unwrap();

    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
    assert_eq!(conf.remote_port, 862);
}

#[test]
fn test_merge_bool_flag_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ber = true\nstateful_reflector = true\n").unwrap();

    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
    assert!(conf.ber);
    assert!(conf.stateful_reflector);
}

#[test]
fn test_merge_vec_field_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "return_sr_mpls_labels = [100, 200]\n").unwrap();

    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
    assert_eq!(conf.return_sr_mpls_labels, Some(vec![100, 200]));
}

#[test]
fn test_merge_option_field_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ssid = 42\nhmac_key_file = \"/etc/stamp/key\"\n").unwrap();

    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
    assert_eq!(conf.ssid, Some(42));
    assert_eq!(conf.hmac_key_file, Some(PathBuf::from("/etc/stamp/key")));
}

#[test]
fn test_merge_cli_overrides_file_for_bool() {
    // File sets ber=true but CLI does not; ber must be true.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ber = true\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).expect("load ok");
    assert!(conf.ber);
}

#[test]
fn test_merge_cli_overrides_file_for_option_field() {
    // File sets ssid=42, CLI passes --ssid 99; CLI must win.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ssid = 42\n").unwrap();

    let conf = load_from_args(&["test", "--config", path.to_str().unwrap(), "--ssid", "99"])
        .expect("load ok");
    assert_eq!(conf.ssid, Some(99));
}

#[test]
fn test_load_with_nonexistent_config_path() {
    let err = load_from_args(&["test", "--config", "/no/such/file/stamp.toml"])
        .expect_err("non-existent file must error");
    match err {
        ConfigurationError::ConfigFileError(msg) => {
            assert!(msg.contains("/no/such/file/stamp.toml"));
        }
        other => panic!("expected ConfigFileError, got {other:?}"),
    }
}

#[test]
fn test_load_with_malformed_toml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "remote_port = \"oops\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("malformed TOML must error");
    match err {
        ConfigurationError::ConfigFileError(msg) => {
            assert!(msg.contains(path.to_str().unwrap()));
        }
        other => panic!("expected ConfigFileError, got {other:?}"),
    }
}

#[test]
fn test_load_runs_validation_after_merge() {
    // File sets auth_mode to A but no HMAC key -> validate() must fail.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "auth_mode = \"A\"\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("authenticated mode without key must fail validation");
    assert!(matches!(err, ConfigurationError::InvalidConfiguration(_)));
}

#[test]
fn test_validate_rejects_out_of_range_dscp_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "dscp = 200\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("dscp > 63 must fail");
    assert!(err.to_string().contains("dscp"));
}

#[test]
fn test_validate_rejects_out_of_range_ecn_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ecn = 10\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("ecn > 3 must fail");
    assert!(err.to_string().contains("ecn"));
}

// ===== AIMD congestion-response (draft-ietf-ippm-stamp-cos-ecn-01 §3.4) =====

#[test]
fn test_validate_rejects_ecn_backoff_factor_not_greater_than_one() {
    let err = load_from_args(&["test", "--ecn-backoff-factor", "1.0"])
        .expect_err("backoff factor of exactly 1.0 must fail (no actual backoff)");
    assert!(err.to_string().contains("ecn_backoff_factor"));
}

#[test]
fn test_validate_rejects_ecn_backoff_factor_below_one() {
    let err = load_from_args(&["test", "--ecn-backoff-factor", "0.5"])
        .expect_err("backoff factor < 1.0 must fail");
    assert!(err.to_string().contains("ecn_backoff_factor"));
}

#[test]
fn test_validate_rejects_ecn_backoff_factor_non_finite() {
    let err = load_from_args(&["test", "--ecn-backoff-factor", "inf"])
        .expect_err("non-finite backoff factor must fail");
    assert!(err.to_string().contains("ecn_backoff_factor"));
}

#[test]
fn test_validate_rejects_ecn_recovery_step_zero() {
    let err = load_from_args(&["test", "--ecn-recovery-step", "0"])
        .expect_err("recovery step 0 must fail (would never recover)");
    assert!(err.to_string().contains("ecn_recovery_step"));
}

#[test]
fn test_validate_rejects_ecn_max_delay_zero() {
    let err = load_from_args(&["test", "--ecn-max-delay", "0"]).expect_err("max delay 0 must fail");
    assert!(err.to_string().contains("ecn_max_delay"));
}

#[test]
fn test_validate_rejects_ecn_max_delay_below_send_delay_when_active() {
    let err = load_from_args(&[
        "test",
        "--cos",
        "--ecn",
        "1",
        "--send-delay",
        "50000",
        "--ecn-max-delay",
        "1000",
    ])
    .expect_err("ecn_max_delay below send_delay while the controller is active must fail");
    assert!(err.to_string().contains("ecn_max_delay"));
}

#[test]
fn test_validate_allows_ecn_max_delay_below_send_delay_when_controller_inactive() {
    // No --cos: the controller never activates, so the default
    // ecn_max_delay (30000ms) being smaller than a large --send-delay
    // must not spuriously fail validation.
    let conf = load_from_args(&["test", "--send-delay", "50000"])
        .expect("controller inactive, cross-check must not apply");
    assert_eq!(conf.send_delay, ProbeInterval::from_millis(50000));
}

#[test]
fn test_validate_allows_ecn_max_delay_below_send_delay_when_ecn_zero() {
    // --cos set but --ecn left at its default (0 = Not-ECT): the
    // controller is inactive (activation requires ECT0/ECT1), so this
    // must not fail either.
    let conf = load_from_args(&[
        "test",
        "--cos",
        "--send-delay",
        "50000",
        "--ecn-max-delay",
        "1000",
    ])
    .expect("controller inactive when ecn=0, cross-check must not apply");
    assert_eq!(conf.send_delay, ProbeInterval::from_millis(50000));
}

#[test]
fn test_validate_accepts_default_ecn_aimd_parameters() {
    let conf =
        load_from_args(&["test", "--cos", "--ecn", "1"]).expect("defaults must satisfy validate()");
    assert!((conf.ecn_backoff_factor - 2.0).abs() < f64::EPSILON);
    assert_eq!(conf.ecn_max_delay, 30_000);
    assert_eq!(conf.ecn_recovery_step, 50);
}

#[test]
fn test_validate_rejects_out_of_range_access_report_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "access_report = 99\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("access_report > 15 must fail");
    assert!(err.to_string().contains("access_report"));
}

/// Reject Access ID 0 through both CLI parsing and TOML validation (RFC 8972 §4.6).
/// Use `try_get_matches_from` so parse errors cannot exit the test process.
#[test]
fn test_access_report_cli_rejects_zero() {
    let result = Configuration::command().try_get_matches_from(["test", "--access-report", "0"]);
    assert!(
        result.is_err(),
        "--access-report 0 must be rejected by the CLI parser"
    );
}

#[test]
fn test_validate_rejects_zero_access_report_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "access_report = 0\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("access_report == 0 must fail (no defined Access ID 0, RFC 8972 §4.6)");
    assert!(err.to_string().contains("access_report"));
}

/// Values 1 (3GPP) and 2 (Non-3GPP) are the RFC 8972 §4.6-defined
/// Access IDs and must be accepted without any error.
#[test]
fn test_access_report_accepts_defined_registry_values() {
    for value in ["1", "2"] {
        let conf = load_from_args(&["test", "--access-report", value])
            .unwrap_or_else(|e| panic!("--access-report {value} must be accepted: {e}"));
        assert_eq!(conf.access_report, Some(value.parse().unwrap()));
    }
}

/// RFC 8972 §4.6: reflectors discard Access IDs other than 1 and 2, so the
/// sender refuses to send them, from the CLI or a config file.
#[test]
fn test_access_report_rejects_ids_outside_registry() {
    for value in ["0", "3", "15", "16"] {
        assert!(
            Configuration::command()
                .try_get_matches_from(["test", "--access-report", value])
                .is_err(),
            "--access-report {value} must be rejected"
        );
    }
    let mut conf = Configuration::parse_from(["test"]);
    conf.access_report = Some(3);
    assert!(conf.validate().is_err());
    conf.access_report = Some(2);
    assert!(conf.validate().is_ok());
}

/// RFC 8972 §4.6: "The default value of the retransmission timer for
/// the Access Report TLV SHOULD be three seconds."
#[test]
fn test_access_report_timeout_default_is_three_seconds() {
    let conf = load_from_args(&["test"]).unwrap();
    assert_eq!(conf.access_report_timeout, 3);
}

/// RFC 8972 §4.6: "This retransmission SHOULD be repeated up to four
/// times before the procedure is aborted."
#[test]
fn test_access_report_retries_default_is_four() {
    let conf = load_from_args(&["test"]).unwrap();
    assert_eq!(conf.access_report_retries, 4);
}

/// RFC 8972 §4.6: "An implementation MUST provide control of the
/// retransmission timer value and the number of retransmissions" —
/// both must be overridable via the CLI.
#[test]
fn test_access_report_timeout_and_retries_are_configurable() {
    let conf = load_from_args(&[
        "test",
        "--access-report-timeout",
        "10",
        "--access-report-retries",
        "2",
    ])
    .unwrap();
    assert_eq!(conf.access_report_timeout, 10);
    assert_eq!(conf.access_report_retries, 2);
}

#[test]
fn test_access_report_timeout_cli_rejects_zero() {
    let result =
        Configuration::command().try_get_matches_from(["test", "--access-report-timeout", "0"]);
    assert!(
        result.is_err(),
        "--access-report-timeout 0 must be rejected by the CLI parser"
    );
}

#[test]
fn test_access_report_retries_accepts_zero() {
    // 0 is a legitimate operator choice: abort immediately on the first
    // missed acknowledgment instead of retransmitting.
    let conf = load_from_args(&["test", "--access-report-retries", "0"]).unwrap();
    assert_eq!(conf.access_report_retries, 0);
}

#[test]
fn test_validate_rejects_zero_access_report_timeout_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "access_report_timeout = 0\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("access_report_timeout == 0 must fail");
    assert!(err.to_string().contains("access_report_timeout"));
}

#[test]
fn test_validate_rejects_out_of_range_access_report_timeout_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "access_report_timeout = 99999\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("access_report_timeout > 3600 must fail");
    assert!(err.to_string().contains("access_report_timeout"));
}

#[test]
fn test_validate_rejects_out_of_range_access_report_retries_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "access_report_retries = 99999\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("access_report_retries > 255 must fail");
    assert!(err.to_string().contains("access_report_retries"));
}

#[test]
fn test_validate_rejects_zero_micro_session_id_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "micro_session_id = 0\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("micro_session_id == 0 must fail");
    assert!(err.to_string().contains("micro_session_id"));
}

#[test]
fn test_validate_rejects_zero_reflector_member_link_id_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "reflector_member_link_id = 0\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("reflector_member_link_id == 0 must fail");
    assert!(err.to_string().contains("reflector_member_link_id"));
}

#[test]
fn test_parse_u16_nonzero_dec_or_hex_accepts_decimal() {
    assert_eq!(parse_u16_nonzero_dec_or_hex("1").unwrap(), 1);
    assert_eq!(parse_u16_nonzero_dec_or_hex("255").unwrap(), 255);
    assert_eq!(parse_u16_nonzero_dec_or_hex("65535").unwrap(), 65535);
}

#[test]
fn test_parse_u16_nonzero_dec_or_hex_accepts_hex() {
    assert_eq!(parse_u16_nonzero_dec_or_hex("0x1").unwrap(), 1);
    assert_eq!(parse_u16_nonzero_dec_or_hex("0xff").unwrap(), 255);
    assert_eq!(parse_u16_nonzero_dec_or_hex("0xFF").unwrap(), 255);
    assert_eq!(parse_u16_nonzero_dec_or_hex("0X00ab").unwrap(), 0xab);
    assert_eq!(parse_u16_nonzero_dec_or_hex("0xffff").unwrap(), 65535);
}

#[test]
fn test_parse_u16_nonzero_dec_or_hex_rejects_zero() {
    assert!(parse_u16_nonzero_dec_or_hex("0").is_err());
    assert!(parse_u16_nonzero_dec_or_hex("0x0").is_err());
    assert!(parse_u16_nonzero_dec_or_hex("0x0000").is_err());
}

#[test]
fn test_parse_u16_nonzero_dec_or_hex_rejects_garbage() {
    assert!(parse_u16_nonzero_dec_or_hex("").is_err());
    assert!(parse_u16_nonzero_dec_or_hex("ff").is_err()); // hex without 0x prefix
    assert!(parse_u16_nonzero_dec_or_hex("0x1g").is_err());
    assert!(parse_u16_nonzero_dec_or_hex("0x10000").is_err()); // > u16::MAX
    assert!(parse_u16_nonzero_dec_or_hex("65536").is_err());
    // Empty string after stripping `0x` prefix → from_str_radix rejects.
    assert!(parse_u16_nonzero_dec_or_hex("0x").is_err());
    assert!(parse_u16_nonzero_dec_or_hex("0X").is_err());
}

#[test]
fn test_parse_u16_nonzero_dec_or_hex_handles_whitespace() {
    // clap doesn't usually pass whitespace, but the parser trims defensively
    // (e.g. when values are loaded from the TOML config file).
    assert_eq!(parse_u16_nonzero_dec_or_hex(" 0xff").unwrap(), 0xff);
    assert_eq!(parse_u16_nonzero_dec_or_hex("0xff ").unwrap(), 0xff);
    assert_eq!(parse_u16_nonzero_dec_or_hex(" 255 ").unwrap(), 255);
    assert_eq!(parse_u16_nonzero_dec_or_hex("\t0x1\n").unwrap(), 1);
}

#[test]
fn test_micro_session_id_accepts_hex_on_cli() {
    let conf = load_from_args(&[
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--micro-session-id",
        "0xff",
        "--reflector-member-link-id",
        "0xab",
    ])
    .unwrap();
    assert_eq!(conf.micro_session_id, Some(0xff));
    assert_eq!(conf.reflector_member_link_id, Some(0xab));
}

#[test]
fn test_micro_session_id_accepts_decimal_on_cli() {
    let conf = load_from_args(&[
        "test",
        "--remote-addr",
        "127.0.0.1",
        "--micro-session-id",
        "255",
    ])
    .unwrap();
    assert_eq!(conf.micro_session_id, Some(255));
}

#[test]
fn test_validate_rejects_return_path_cc_with_sr_mpls_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(
        &path,
        "return_path_cc = 0\nreturn_sr_mpls_labels = [100, 200]\n",
    )
    .unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("conflicting return-path options must fail");
    let msg = err.to_string();
    assert!(msg.contains("return_path_cc"));
    assert!(msg.contains("return_sr_mpls_labels"));
}

#[test]
fn test_validate_rejects_return_path_cc_with_srv6_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(
        &path,
        "return_path_cc = 1\nreturn_srv6_sids = [\"2001:db8::1\"]\n",
    )
    .unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("conflicting return-path options must fail");
    assert!(err.to_string().contains("return_srv6_sids"));
}

#[test]
fn test_control_tls_requires_both_halves_and_a_token() {
    // Both halves together, with a token: accepted.
    let conf = load_from_args(&[
        "test",
        "--control-tls-cert",
        "/tmp/c.pem",
        "--control-tls-key",
        "/tmp/k.pem",
        "--control-token-file",
        "/tmp/t",
    ])
    .expect("cert + key + token is the supported combination");
    assert!(conf.control_tls_cert.is_some() && conf.control_tls_key.is_some());

    // TLS without a token is refused: an unauthenticated key-management and
    // shutdown API should not be exposed, encrypted or not.
    let err = load_from_args(&[
        "test",
        "--control-tls-cert",
        "/tmp/c.pem",
        "--control-tls-key",
        "/tmp/k.pem",
    ])
    .expect_err("TLS without a bearer token must be refused");
    assert!(
        err.to_string().contains("control-token-file"),
        "the error must point at the missing token: {err}"
    );
}

#[test]
fn test_control_tls_half_configured_from_file_is_rejected() {
    // clap's `requires` covers the CLI, but a config file can set one
    // alone — validate() has to catch that too.
    for (key, other) in [
        ("control_tls_cert", "control_tls_key"),
        ("control_tls_key", "control_tls_cert"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stamp.toml");
        std::fs::write(&path, format!("{key} = \"/tmp/x.pem\"\n")).unwrap();
        let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
            .expect_err("half-configured TLS must be refused");
        assert!(
            err.to_string().contains(other),
            "the error must name the missing half ({other}): {err}"
        );
    }
}

#[test]
fn test_interop_flag_defaults_are_unchanged_behaviour() {
    let conf = load_from_args(&["test"]).unwrap();
    assert_eq!(conf.extra_padding, None);
    assert!(!conf.ber_omit_burst);
    assert_eq!(
        conf.tlv_hmac,
        TlvHmacMode::Auto,
        "auto preserves the long-standing origination behaviour"
    );
}

#[test]
fn test_extra_padding_conflicts_with_ber() {
    // On the CLI clap refuses it. `try_get_matches_from` rather than the
    // `load_from_args` helper: clap's own error path exits the process, so
    // the helper cannot observe it.
    let err = Configuration::command()
        .try_get_matches_from(["test", "--ber", "--extra-padding", "64"])
        .expect_err("BER owns the padding TLV; a second one would corrupt it");
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);

    // ...and from a config file, where clap cannot see the conflict.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "ber = true\nextra_padding = 64\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("the file form must be refused too");
    assert!(
        err.to_string().contains("extra_padding"),
        "the error must name the conflict: {err}"
    );
}

#[test]
fn test_tlv_hmac_on_requires_a_key() {
    let err = load_from_args(&["test", "--tlv-hmac", "on"])
        .expect_err("promising an HMAC TLV without a key is impossible");
    assert!(err.to_string().contains("tlv_hmac"), "{err}");

    // With a key it loads.
    let conf = load_from_args(&[
        "test",
        "--tlv-hmac",
        "on",
        "--hmac-key",
        "00112233445566778899aabbccddeeff",
    ])
    .expect("on + key is valid");
    assert_eq!(conf.tlv_hmac, TlvHmacMode::On);

    // `off` needs no key: it is the "hold a key but do not originate" case.
    let conf = load_from_args(&["test", "--tlv-hmac", "off"]).expect("off needs no key");
    assert_eq!(conf.tlv_hmac, TlvHmacMode::Off);
}

#[test]
fn test_interop_flags_merge_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(
        &path,
        "extra_padding = 128\nber_omit_burst = true\ntlv_hmac = \"off\"\n",
    )
    .unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect("file-configured interop flags must load");
    assert_eq!(conf.extra_padding, Some(128));
    assert!(conf.ber_omit_burst);
    assert_eq!(conf.tlv_hmac, TlvHmacMode::Off);
}

#[test]
fn test_control_tls_absent_by_default() {
    let conf = load_from_args(&["test"]).unwrap();
    assert!(conf.control_tls_cert.is_none());
    assert!(conf.control_tls_key.is_none());
}

#[test]
fn test_cos_policy_defaults_to_permit_all() {
    let conf = load_from_args(&["test"]).unwrap();
    assert_eq!(conf.allowed_dscp, "all");
    assert_eq!(conf.allowed_ecn, "all");
    assert!(
        conf.cos_admission_policy().unwrap().is_permissive(),
        "a measurement tool must answer every CoS request by default"
    );
}

#[test]
fn test_cos_policy_parses_flags_and_destination_rules() {
    let conf = load_from_args(&[
        "test",
        "--allowed-dscp",
        "0,46",
        "--allowed-ecn",
        "0,2",
        "--allowed-dscp-for",
        "192.0.2.0/24=34",
        "--allowed-dscp-for",
        "10.0.0.0/8=none",
    ])
    .expect("a valid policy must load");
    let policy = conf.cos_admission_policy().unwrap();
    assert!(!policy.is_permissive());
    assert!(policy.permits_dscp(None, 46));
    assert!(!policy.permits_dscp(None, 34));
    assert!(policy.permits_ecn(2));
    assert!(!policy.permits_ecn(1));
    // Destination rules replace the global set inside their prefix.
    let inside: std::net::IpAddr = "192.0.2.9".parse().unwrap();
    assert!(policy.permits_dscp(Some(inside), 34));
    assert!(!policy.permits_dscp(Some(inside), 46));
    let denied: std::net::IpAddr = "10.1.1.1".parse().unwrap();
    assert!(!policy.permits_dscp(Some(denied), 46));
}

#[test]
fn test_validate_rejects_bad_cos_policy() {
    // Each flag must fail at startup rather than degrading to permit-all
    // on every packet.
    let err =
        load_from_args(&["test", "--allowed-dscp", "64"]).expect_err("DSCP 64 is out of range");
    assert!(err.to_string().contains("allowed-dscp"), "{err}");

    let err = load_from_args(&["test", "--allowed-ecn", "9"]).expect_err("ECN 9 is out of range");
    assert!(err.to_string().contains("allowed-ecn"), "{err}");

    let err = load_from_args(&["test", "--allowed-dscp-for", "192.0.2.0/24"])
        .expect_err("a rule without '=' is malformed");
    assert!(err.to_string().contains("allowed-dscp-for"), "{err}");

    let err = load_from_args(&["test", "--allowed-dscp-for", "192.0.2.0/33=46"])
        .expect_err("prefix length out of range");
    assert!(err.to_string().contains("allowed-dscp-for"), "{err}");
}

#[test]
fn test_cos_policy_merges_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(
        &path,
        "allowed_dscp = \"46\"\nallowed_ecn = \"none\"\nallowed_dscp_for = [\"192.0.2.0/24=0\"]\n",
    )
    .unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect("file-configured policy must load");
    let policy = conf.cos_admission_policy().unwrap();
    assert!(policy.permits_dscp(None, 46));
    assert!(!policy.permits_dscp(None, 0));
    assert!(
        !policy.permits_ecn(0),
        "allowed_ecn = none refuses every value"
    );
    let inside: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    assert!(
        policy.permits_dscp(Some(inside), 0),
        "file rule must reach the policy"
    );
}

#[test]
fn test_drop_replayed_defaults_off_and_merges_from_file() {
    let conf = load_from_args(&["test"]).unwrap();
    assert!(
        !conf.drop_replayed,
        "dropping an ordinary duplicate must be opt-in: a restarted sender replays \
             its own numbering and dropping it would break honest measurement"
    );

    let conf = load_from_args(&["test", "--drop-replayed"]).unwrap();
    assert!(conf.drop_replayed);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "drop_replayed = true\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).unwrap();
    assert!(conf.drop_replayed);
}

#[test]
fn test_reflected_burst_pacing_warning_absent_without_a_burst() {
    // count defaults to 1: no Type-12 burst is requested, so the §5
    // SHOULD NOT cannot be violated.
    let conf = load_from_args(&["test"]).unwrap();
    assert_eq!(conf.reflected_control_count, 1);
    assert!(conf.reflected_burst_pacing_warning().is_none());
}

#[test]
fn test_reflected_burst_pacing_warning_fires_when_send_delay_too_short() {
    // 20 packets, 10 ms apart => the burst runs 190 ms; a 50 ms
    // --send-delay starts the next request mid-burst.
    let conf = load_from_args(&[
        "test",
        "--send-delay",
        "50",
        "--reflected-control-count",
        "20",
        "--reflected-control-interval-ns",
        "10000000",
    ])
    .unwrap();
    let w = conf
        .reflected_burst_pacing_warning()
        .expect("overlapping pacing must warn");
    assert!(w.contains("190.000 ms"), "expected burst duration in: {w}");
    assert!(w.contains("at least 190 ms"), "expected remedy in: {w}");
}

#[test]
fn test_reflected_burst_pacing_warning_silent_when_delay_is_sufficient() {
    // Same burst (190 ms) with a 200 ms gap: no overlap, no warning.
    let conf = load_from_args(&[
        "test",
        "--send-delay",
        "200",
        "--reflected-control-count",
        "20",
        "--reflected-control-interval-ns",
        "10000000",
    ])
    .unwrap();
    assert!(conf.reflected_burst_pacing_warning().is_none());
}

#[test]
fn test_reflected_burst_pacing_boundary_is_not_a_violation() {
    // Exactly equal is compliant: the SHOULD NOT is about sending
    // *before* the reflector is expected to be done.
    let conf = load_from_args(&[
        "test",
        "--send-delay",
        "10",
        "--reflected-control-count",
        "11",
        "--reflected-control-interval-ns",
        "1000000",
    ])
    .unwrap();
    assert!(conf.reflected_burst_pacing_warning().is_none());
}

#[test]
fn test_on_zero_ssid_defaults_to_continue_and_parses() {
    let conf = load_from_args(&["test"]).unwrap();
    assert_eq!(
        conf.on_zero_ssid,
        ZeroSsidAction::Continue,
        "continuing is RFC-permitted and the useful default for a probe"
    );

    let conf = load_from_args(&["test", "--on-zero-ssid", "stop"]).unwrap();
    assert_eq!(conf.on_zero_ssid, ZeroSsidAction::Stop);
}

#[test]
fn test_on_zero_ssid_merges_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "on_zero_ssid = \"stop\"\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect("file-configured action must load");
    assert_eq!(conf.on_zero_ssid, ZeroSsidAction::Stop);
}

/// `--hmac-key-dir` is a reflector concept: `KeySource::load_key` (the
/// sender's path) does not read directories, so a sender given one used to ignore it
/// silently — a typo'd path included.
#[test]
fn test_hmac_key_dir_is_reflector_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_str().unwrap();

    let err = load_from_args(&["test", "--hmac-key-dir", path])
        .expect_err("a sender must not silently ignore --hmac-key-dir");
    assert!(
        err.to_string().contains("reflector-only"),
        "unexpected error: {err}"
    );

    // The reflector accepts it, and a sender is told to use a key file.
    assert!(load_from_args(&["test", "--is-reflector", "--hmac-key-dir", path]).is_ok());
}

/// The schema must accept the full Return Code octet, including 255,
/// as the CLI and wire encoder do (RFC 8972 §4.6, Table 11).
#[test]
fn test_schema_access_return_code_spans_a_full_octet() {
    let schema: serde_json::Value =
        serde_json::from_str(CONFIG_JSON_SCHEMA).expect("schema must be valid JSON");
    let spec = &schema["properties"]["access_return_code"];
    assert_eq!(spec["minimum"], 0);
    assert_eq!(spec["maximum"], 255);

    // And the loader really does accept the top of that range. (256 is
    // rejected by clap's own range check, which exits the process rather
    // than returning an error, so it cannot be asserted here.)
    for value in [0u16, 15, 16, 255] {
        assert!(
            load_from_args(&["test", "--access-return-code", &value.to_string()]).is_ok(),
            "access_return_code {value} must load"
        );
    }
}

/// `--reflected-ipv6-ext-hdr=0` asks the reflector for a zero-length
/// extension header, which names nothing. Omitting the value is how you get
/// the default length.
#[test]
fn test_reflected_ipv6_ext_hdr_rejects_zero_length() {
    assert!(load_from_args(&["test", "--reflected-ipv6-ext-hdr=0"]).is_err());
    assert!(load_from_args(&["test", "--reflected-ipv6-ext-hdr=0:11000102"]).is_err());

    #[cfg(target_os = "linux")]
    {
        // The bare flag and an explicit non-zero length still work.
        assert!(load_from_args(&[
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "dest",
            "--reflected-ipv6-ext-hdr"
        ])
        .is_ok());
        assert!(load_from_args(&[
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "dest",
            "--reflected-ipv6-ext-hdr=8"
        ])
        .is_ok());
        assert!(load_from_args(&[
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "dest",
            "--reflected-ipv6-ext-hdr=8:1100010400000000"
        ])
        .is_ok());
    }
}

#[test]
fn test_location_disclose_defaults_to_all_and_parses() {
    let conf = load_from_args(&["test"]).expect("defaults must be valid");
    assert_eq!(conf.location_disclose, "all");
    assert_eq!(
        conf.location_disclosure().unwrap(),
        LocationDisclosure::all(),
        "the default policy must keep answering every field"
    );

    let conf = load_from_args(&["test", "--location-disclose", "ports,src-ip"])
        .expect("a valid field list must load");
    let policy = conf.location_disclosure().unwrap();
    assert!(policy.src_port && policy.dst_port && policy.src_ip);
    assert!(!policy.dst_ip);
}

#[test]
fn test_validate_rejects_bad_location_disclose() {
    // A typo must fail at startup, not silently degrade to a default
    // policy on every packet.
    let err = load_from_args(&["test", "--location-disclose", "src-vlan"])
        .expect_err("an unknown Location field must be rejected");
    assert!(
        err.to_string().contains("location-disclose"),
        "error must name the offending flag: {err}"
    );

    let err = load_from_args(&["test", "--location-disclose", "none,src-ip"])
        .expect_err("mixing a wildcard with named fields must be rejected");
    assert!(err.to_string().contains("location-disclose"), "{err}");
}

#[test]
fn test_location_disclose_merges_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "location_disclose = \"none\"\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect("file-configured policy must load");
    assert!(
        conf.location_disclosure().unwrap().discloses_nothing(),
        "the file value must reach the parsed policy"
    );
}

#[test]
fn test_validate_rejects_return_path_cc_with_return_address_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "return_path_cc = 0\nreturn_address = \"10.0.0.1\"\n").unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("conflicting return-path options must fail");
    assert!(err.to_string().contains("return_address"));
}

#[test]
fn test_validate_rejects_sr_mpls_with_srv6_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(
        &path,
        "return_sr_mpls_labels = [100]\nreturn_srv6_sids = [\"2001:db8::1\"]\n",
    )
    .unwrap();
    let err = load_from_args(&["test", "--config", path.to_str().unwrap()])
        .expect_err("conflicting return-path options must fail");
    assert!(err.to_string().contains("return_sr_mpls_labels"));
}

#[test]
fn test_validate_rejects_cli_return_path_cc_merged_with_file_srv6() {
    // CLI sets return_path_cc; file sets return_srv6_sids. The merge
    // leaves both present even though each side alone would be fine.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "return_srv6_sids = [\"2001:db8::1\"]\n").unwrap();
    let err = load_from_args(&[
        "test",
        "--config",
        path.to_str().unwrap(),
        "--return-path-cc",
        "0",
    ])
    .expect_err("CLI + file conflict must fail");
    assert!(err.to_string().contains("return_srv6_sids"));
}

#[test]
fn test_validate_rejects_cli_hmac_key_merged_with_file_hmac_key_file() {
    // CLI sets --hmac-key; file sets hmac_key_file. Both end up in
    // the final config even though the CLI would have rejected them
    // together.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "hmac_key_file = \"/etc/stamp/key\"\n").unwrap();
    let err = load_from_args(&[
        "test",
        "--config",
        path.to_str().unwrap(),
        "--hmac-key",
        "0123456789abcdef0123456789abcdef",
    ])
    .expect_err("hmac_key + hmac_key_file must be rejected");
    assert!(err.to_string().contains("hmac_key"));
    assert!(err.to_string().contains("hmac_key_file"));
}

#[test]
fn test_verbose_flag_defaults_to_zero() {
    let conf = Configuration::parse_from(["test"]);
    assert_eq!(conf.verbose, 0);
}

#[test]
fn test_verbose_flag_counts() {
    let conf = Configuration::parse_from(["test", "-v"]);
    assert_eq!(conf.verbose, 1);

    let conf = Configuration::parse_from(["test", "-vv"]);
    assert_eq!(conf.verbose, 2);

    let conf = Configuration::parse_from(["test", "-vvv"]);
    assert_eq!(conf.verbose, 3);

    // Long form is repeatable too, and combines with the short form.
    let conf = Configuration::parse_from(["test", "--verbose", "--verbose"]);
    assert_eq!(conf.verbose, 2);
    let conf = Configuration::parse_from(["test", "-v", "--verbose"]);
    assert_eq!(conf.verbose, 2);
}

#[test]
fn test_resolve_log_filter_default_is_info() {
    assert_eq!(resolve_log_filter(0, None), "info");
}

#[test]
fn test_resolve_log_filter_single_v_is_debug() {
    assert_eq!(resolve_log_filter(1, None), "debug");
}

#[test]
fn test_resolve_log_filter_double_v_and_beyond_is_trace() {
    assert_eq!(resolve_log_filter(2, None), "trace");
    assert_eq!(resolve_log_filter(5, None), "trace");
}

#[test]
fn test_resolve_log_filter_rust_log_env_overrides_verbose() {
    // An explicit, non-empty RUST_LOG always wins over -v/-vv, no
    // matter how many times the flag was repeated.
    assert_eq!(resolve_log_filter(0, Some("warn")), "warn");
    assert_eq!(
        resolve_log_filter(2, Some("stamp_suite=trace,tower=warn")),
        "stamp_suite=trace,tower=warn"
    );
}

#[test]
fn test_resolve_log_filter_empty_rust_log_env_falls_back_to_verbose() {
    // An empty RUST_LOG (e.g. present in the environment but set to
    // the empty string) must not be treated as "explicitly set" --
    // fall back to the -v/-vv-derived level instead.
    assert_eq!(resolve_log_filter(0, Some("")), "info");
    assert_eq!(resolve_log_filter(1, Some("")), "debug");
}
#[test]
fn scoped_ipv6_cli_and_file_preserve_numeric_zones() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scopes.toml");
    std::fs::write(&path, "local_addr = 'fe80::1'\nremote_addr = 'fe80::2'\nlocal_scope_id = 7\nremote_scope_id = 8\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).unwrap();
    assert_eq!(conf.local_socket_addr().to_string(), "[fe80::1%7]:0");
    assert_eq!(conf.remote_socket_addr().to_string(), "[fe80::2%8]:862");
    let conf = load_from_args(&[
        "test",
        "--config",
        path.to_str().unwrap(),
        "--remote-scope-id",
        "9",
    ])
    .unwrap();
    assert_eq!(conf.remote_scope_id, 9);
    let schema: serde_json::Value = serde_json::from_str(CONFIG_JSON_SCHEMA).unwrap();
    assert_eq!(schema["properties"]["local_scope_id"]["maximum"], u32::MAX);
}
#[test]
fn scoped_ipv6_rejects_missing_zone_and_ipv4_zone() {
    for args in [
        vec!["test", "--remote-addr", "fe80::1"],
        vec!["test", "--local-addr", "fe80::1"],
        vec!["test", "--local-scope-id", "3"],
        vec!["test", "--remote-scope-id", "3"],
    ] {
        assert!(load_from_args(&args).is_err(), "{args:?}");
    }
}

#[test]
fn clock_sync_sources_parse_merge_and_match_schema() {
    use crate::tlv::SyncSource;
    let schema: serde_json::Value = serde_json::from_str(CONFIG_JSON_SCHEMA).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clock.toml");
    for (index, name) in [
        "ntp", "ptp", "gps", "glonass", "loran-c", "bds", "galileo", "local", "ssu-bits",
    ]
    .iter()
    .enumerate()
    {
        let conf = load_from_args(&[
            "test",
            "--clock-source",
            "PTP",
            "--clock-sync-source",
            name,
            "--hardware-clock-sync-source",
            name,
        ])
        .unwrap();
        assert_eq!(
            SyncSource::from(conf.clock_sync_source).to_byte(),
            [1, 2, 4, 4, 4, 4, 4, 5, 3][index]
        );
        assert_eq!(conf.clock_sync_source, conf.hardware_clock_sync_source);
        assert!(!conf.clock_synchronized);
        for field in ["clock_sync_source", "hardware_clock_sync_source"] {
            assert!(schema["properties"][field]["enum"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(name)));
        }
        std::fs::write(
            &path,
            format!("clock_sync_source = {name:?}\nhardware_clock_sync_source = {name:?}\n"),
        )
        .unwrap();
        let file = load_from_args(&["test", "--config", path.to_str().unwrap()]).unwrap();
        assert_eq!(file.clock_sync_source, conf.clock_sync_source);
        assert_eq!(
            file.hardware_clock_sync_source,
            conf.hardware_clock_sync_source
        );
        let override_conf = load_from_args(&[
            "test",
            "--config",
            path.to_str().unwrap(),
            "--clock-sync-source",
            "local",
            "--hardware-clock-sync-source",
            "gps",
        ])
        .unwrap();
        assert_eq!(override_conf.clock_sync_source, ClockSyncSource::Local);
        assert_eq!(
            override_conf.hardware_clock_sync_source,
            ClockSyncSource::Gps
        );
    }
    for args in [
        vec!["test", "--clock-source", "PTP"],
        vec!["test", "--clock-synchronized"],
    ] {
        let conf = load_from_args(&args).unwrap();
        assert_eq!(conf.clock_sync_source, ClockSyncSource::Local);
        assert_eq!(conf.hardware_clock_sync_source, ClockSyncSource::Local);
    }
    assert!(Configuration::try_parse_from(["test", "--clock-sync-source", "PTP"]).is_err());
    assert!(
        toml::from_str::<FileConfiguration>("hardware_clock_sync_source = 'automatic'").is_err()
    );
}
#[test]
fn revision13_defaults_and_file_role_choose_correct_local_port() {
    assert_eq!(load_from_args(&["test"]).unwrap().local_port, 0);
    assert_eq!(
        load_from_args(&["test", "--is-reflector"])
            .unwrap()
            .local_port,
        862
    );
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(&path, "is_reflector = true\nsession_loss_threshold = 5\n").unwrap();
    let conf = load_from_args(&["test", "--config", path.to_str().unwrap()]).unwrap();
    assert_eq!(conf.local_port, 862);
    assert_eq!(conf.session_loss_threshold, 5);
    assert_eq!(
        load_from_args(&[
            "test",
            "--config",
            path.to_str().unwrap(),
            "--local-port",
            "0"
        ])
        .unwrap()
        .local_port,
        0
    );
    std::fs::write(&path, "ttl = 64\n").unwrap();
    assert!(load_from_args(&["test", "--config", path.to_str().unwrap()]).is_err());
}
#[test]
fn revision13_rejects_invalid_headers_selectors_and_direction_ports() {
    for args in [
        vec!["test", "--ttl", "64"],
        vec!["test", "--local-port", "862"],
        vec!["test", "--session-loss-threshold", "0"],
        vec!["test", "--reflected-fixed-hdr=4500000001"],
        vec!["test", "--reflected-ipv6-ext-hdr=8"],
        vec![
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "hbh",
            "--attach-ext-hdr",
            "hbh",
        ],
        vec![
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "dest",
            "--attach-ext-hdr",
            "hbh",
        ],
        vec![
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "dest",
            "--reflected-ipv6-ext-hdr=7",
        ],
        vec![
            "test",
            "--remote-addr",
            "::1",
            "--attach-ext-hdr",
            "dest",
            "--reflected-ipv6-ext-hdr=8:110001040000000001",
        ],
    ] {
        assert!(
            load_from_args(&args).is_err(),
            "unexpectedly accepted {args:?}"
        );
    }
}

#[test]
fn flags_for_missing_features_are_rejected() {
    for (flag, built) in [
        ("--metrics", cfg!(feature = "metrics")),
        ("--snmp", cfg!(all(unix, feature = "snmp"))),
        ("--control", cfg!(feature = "control")),
    ] {
        let conf = Configuration::parse_from(["test", "--is-reflector", flag]);
        match conf.validate() {
            Ok(()) => assert!(built, "{flag} accepted without its feature"),
            Err(e) => {
                assert!(!built, "{flag} rejected although built: {e}");
                assert!(e.to_string().contains(flag), "{e}");
            }
        }
    }
}

#[test]
fn sender_count_zero_runs_until_stopped() {
    let conf = Configuration::parse_from(["test", "--remote-addr", "127.0.0.1", "--count", "0"]);
    assert!(conf.validate().is_ok());
    let conf = Configuration::parse_from(["test", "--count", "100000"]);
    assert_eq!(conf.count, 100_000);
    let conf = Configuration::parse_from(["test", "--duration", "0"]);
    assert!(conf.validate().is_err());
}

#[test]
fn probe_interval_parses_units() {
    for (text, micros) in [
        ("1000", 1_000_000),
        ("0", 0),
        ("250us", 250),
        ("250µs", 250),
        ("1.5ms", 1500),
        ("2s", 2_000_000),
        ("0.5 ms", 500),
    ] {
        let interval: ProbeInterval = text.parse().unwrap();
        assert_eq!(interval.duration().as_micros(), micros, "{text}");
    }
    for bad in ["", "ms", "1h", "-5", "3601s", "1e3", "abc"] {
        assert!(bad.parse::<ProbeInterval>().is_err(), "{bad} accepted");
    }
    assert_eq!(
        "1500us".parse::<ProbeInterval>().unwrap().to_string(),
        "1500us"
    );
    assert_eq!("2s".parse::<ProbeInterval>().unwrap().to_string(), "2000");
}

#[test]
fn send_delay_and_schedule_load_from_toml() {
    for (value, micros) in [("50", 50_000), ("\"250us\"", 250)] {
        let file: FileConfiguration = toml::from_str(&format!(
            "send_delay = {value}\nsend_schedule = \"poisson\""
        ))
        .unwrap();
        assert_eq!(file.send_delay.unwrap().duration().as_micros(), micros);
        assert_eq!(file.send_schedule, Some(SendSchedule::Poisson));
    }
    assert!(toml::from_str::<FileConfiguration>("send_delay = \"5min\"").is_err());
}

#[test]
fn interface_names_are_checked() {
    let conf = Configuration::parse_from(["test", "--interface", "eth0"]);
    assert_eq!(
        conf.validate().is_ok(),
        cfg!(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos"
        ))
    );
    for bad in ["", "sixteen_chars_xx"] {
        let conf = Configuration::parse_from(["test", "--interface", bad]);
        assert!(conf.validate().is_err(), "{bad:?} accepted");
    }
}

/// Every CLI option can also be set in the config file, apart from a few
/// that must stay out of it.
#[test]
fn every_cli_option_has_a_config_file_key() {
    use clap::CommandFactory;
    // `hmac_key` keeps secrets out of files; `config` would be recursive;
    // the rest are one-shot or terminal-only switches.
    const CLI_ONLY: &[&str] = &[
        "hmac_key",
        "config",
        "print_config_schema",
        "verbose",
        "help",
        "version",
    ];
    let file = serde_json::to_value(FileConfiguration::default()).unwrap();
    let file = file.as_object().unwrap();
    let missing: Vec<String> = Configuration::command()
        .get_arguments()
        .map(|arg| arg.get_id().to_string())
        .filter(|id| !CLI_ONLY.contains(&id.as_str()) && !file.contains_key(id))
        .collect();
    assert!(missing.is_empty(), "no config file key for {missing:?}");
}
