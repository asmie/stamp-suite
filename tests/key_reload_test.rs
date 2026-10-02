//! Reloading the reflector's HMAC keys from a key directory (SIGHUP).
#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use clap::Parser;
use stamp_suite::{configuration::Configuration, receiver};

fn write_key(dir: &Path, ssid: u16, byte: u8) {
    let path = dir.join(format!("{ssid:04x}.key"));
    fs::write(&path, hex::encode([byte; 16])).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
}

fn ssids(shared: &receiver::ReceiverSharedState) -> Vec<u16> {
    let guard = shared.hmac_keys.read().unwrap();
    let mut ssids = guard.as_ref().map(|set| set.ssids()).unwrap_or_default();
    ssids.sort_unstable();
    ssids
}

#[test]
fn reload_picks_up_new_keys_and_keeps_old_ones_on_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    write_key(dir.path(), 1, 0x11);
    let conf = Configuration::parse_from([
        "stamp-suite",
        "--is-reflector",
        "--hmac-key-dir",
        dir.path().to_str().unwrap(),
    ]);
    let shared = receiver::create_shared_state(&conf).unwrap();
    assert_eq!(ssids(&shared), [1]);

    write_key(dir.path(), 2, 0x22);
    assert_eq!(receiver::reload_keys(&conf, &shared).unwrap(), 2);
    assert_eq!(ssids(&shared), [1, 2]);

    // An emptied directory is an error; the loaded keys stay in use.
    for entry in fs::read_dir(dir.path()).unwrap() {
        fs::remove_file(entry.unwrap().path()).unwrap();
    }
    assert!(receiver::reload_keys(&conf, &shared).is_err());
    assert_eq!(ssids(&shared), [1, 2]);
}

#[test]
fn reload_without_a_key_source_is_an_error() {
    let conf = Configuration::parse_from(["stamp-suite", "--is-reflector"]);
    let shared = receiver::create_shared_state(&conf).unwrap();
    assert!(receiver::reload_keys(&conf, &shared).is_err());
}
