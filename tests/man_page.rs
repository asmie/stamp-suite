//! Keeps `dist/man/stamp-suite.1` in sync with the clap definition.
//!
//! Distribution packages (cargo-deb, cargo-generate-rpm, `dist/debian/`)
//! install the committed roff file rather than generating it at build
//! time, so packagers never need `clap_mangen` and the page cannot drift
//! from what `stamp-suite --help` actually prints. Regenerate with:
//!
//! ```text
//! STAMP_UPDATE_MAN=1 cargo test --all-features --test man_page
//! ```
//!
//! The page is rendered from the Linux CLI surface (the one every distro
//! package ships). Platform `cfg`s elsewhere may shape the clap definition,
//! so the byte-for-byte check only runs on Linux.

#![cfg(target_os = "linux")]

use std::{fs, path::PathBuf};

use clap::CommandFactory;
use stamp_suite::configuration::Configuration;

const MAN_PAGE: &str = "dist/man/stamp-suite.1";

fn render() -> String {
    let cmd = Configuration::command().name("stamp-suite");
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
