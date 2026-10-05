//! Check the committed man page against the Linux clap definition.
//! Packages install this file without requiring clap_mangen.
//! Regenerate after CLI changes:
//!
//! ```text
//! STAMP_UPDATE_MAN=1 cargo test --all-features --test man_page
//! ```
//!
//! Other platforms may have different cfg-gated options; compare only on Linux.

#![cfg(target_os = "linux")]

use std::{fs, path::PathBuf};

use clap::CommandFactory;
use stamp_suite::configuration::Configuration;

const MAN_PAGE: &str = "dist/man/stamp-suite.1";

fn render() -> String {
    // clap_mangen drops the description of a single-paragraph option marked
    // `hide_short_help`; clear the flag so the manual keeps every description.
    let cmd = Configuration::command()
        .name("stamp-suite")
        .mut_args(|arg| arg.hide_short_help(false));
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd)
        .render(&mut buf)
        .expect("clap_mangen renders the CLI definition");
    String::from_utf8(buf).expect("rendered roff is UTF-8")
}

#[test]
fn committed_man_page_matches_cli_definition() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MAN_PAGE);
    let rendered = render();

    if std::env::var_os("STAMP_UPDATE_MAN").is_some() {
        fs::write(&path, &rendered).expect("write regenerated man page");
        return;
    }

    // Tolerate CRLF checkouts; .gitattributes pins LF but a stale clone may not.
    let committed = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{MAN_PAGE} is missing ({e}); run STAMP_UPDATE_MAN=1 cargo test --all-features --test man_page"))
        .replace("\r\n", "\n");
    assert_eq!(
        committed, rendered,
        "{MAN_PAGE} is stale; run STAMP_UPDATE_MAN=1 cargo test --all-features --test man_page"
    );
}

#[test]
fn man_page_keeps_advanced_option_descriptions() {
    let rendered = render();
    assert!(rendered.contains("Kernel/hardware timestamp handling"));
    assert!(rendered.contains("Bit pattern used to fill the Extra Padding TLV"));
}
