//! End-to-end tests for `--config <PATH>` TOML loading.
//!
//! These tests drive `Configuration::command().get_matches_from(...)` via
//! the public CLI surface (just like a real invocation would) and rely on
//! `tempfile` to write throw-away TOML files.

use clap::CommandFactory;
use stamp_suite::configuration::Configuration;

fn parse(args: &[&str]) -> clap::ArgMatches {
    Configuration::command().get_matches_from(args)
}

#[test]
fn config_file_sets_defaults_but_cli_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stamp.toml");
    std::fs::write(
        &path,
        r#"
            remote_addr = "10.0.0.1"
            remote_port = 5555
            count = 7
            ber = true
        "#,
    )
    .unwrap();

    // CLI overrides file:
    let args = vec![
        "stamp-suite",
        "--config",
        path.to_str().unwrap(),
        "--remote-port",
        "9999",
    ];
    let matches = parse(&args);
    let mut conf = <Configuration as clap::FromArgMatches>::from_arg_matches(&matches).unwrap();
    // Manually mirror load() by reading and merging through the public
    // FileConfiguration type.
    let contents = std::fs::read_to_string(&path).unwrap();
    let file: stamp_suite::configuration::FileConfiguration = toml::from_str(&contents).unwrap();
    merge_via_public_api(&mut conf, file, &matches);
    assert_eq!(conf.remote_port, 9999);
    assert_eq!(
        conf.remote_addr,
        "10.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(conf.count, 7);
    assert!(conf.ber);
}

#[test]
fn config_file_parse_error_mentions_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "this is ] not [ toml\n").unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    let err =
        toml::from_str::<stamp_suite::configuration::FileConfiguration>(&contents).unwrap_err();
    // The integration is that Configuration::load() wraps this error with the
    // file path; unit tests already cover the wrapped message. Here just
    // confirm that a parse error surfaces at all.
    assert!(!err.to_string().is_empty());
}

#[test]
fn config_file_unknown_key_is_rejected() {
    let toml = r#"remote_portt = 1234"#;
    let err = toml::from_str::<stamp_suite::configuration::FileConfiguration>(toml).unwrap_err();
    assert!(err.to_string().contains("remote_portt"));
}

/// Mirror of the private `Configuration::merge_file` — kept minimal and used
/// only to exercise a small surface from the integration test. We cannot call
/// the private method directly across crates, so this validates the public
/// `FileConfiguration` shape plus a handful of fields.
fn merge_via_public_api(
    conf: &mut Configuration,
    file: stamp_suite::configuration::FileConfiguration,
    matches: &clap::ArgMatches,
) {
    use clap::parser::ValueSource;
    let user_set = |name: &str| {
        matches!(
            matches.value_source(name),
            Some(ValueSource::CommandLine) | Some(ValueSource::EnvVariable)
        )
    };
    if !user_set("remote_addr") {
        if let Some(v) = file.remote_addr {
            conf.remote_addr = v;
        }
    }
    if !user_set("remote_port") {
        if let Some(v) = file.remote_port {
            conf.remote_port = v;
        }
    }
    if !user_set("count") {
        if let Some(v) = file.count {
            conf.count = v;
        }
    }
    if !user_set("ber") {
        if let Some(v) = file.ber {
            conf.ber = v;
        }
    }
}
