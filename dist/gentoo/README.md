# Gentoo packaging

A self-contained overlay tree for `net-analyzer/stamp-suite` plus the
`acct-user/stamp` and `acct-group/stamp` packages the systemd unit and
OpenRC script run under. Category, eclass usage (`cargo`, `systemd`,
`acct-*`) and file layout follow the main tree so the directories can be
copied into [GURU](https://wiki.gentoo.org/wiki/Project:GURU) or `::gentoo`
unchanged.

## Regenerating after a release

1. `CRATES=` and the dependent-crate `LICENSE+=` line are generated from
   `Cargo.lock` by [pycargoebuild](https://github.com/projg2/pycargoebuild):

   ```sh
   pycargoebuild -i net-analyzer/stamp-suite/stamp-suite-<ver>.ebuild <checkout>
   ```

2. Rename the ebuild to the new version. `SRC_URI` points at the GitHub
   tag archive (`v<ver>`), so the tag must exist before the next step.

3. Generate `Manifest` (needs a Gentoo host or container with the
   overlay registered):

   ```sh
   pkgdev manifest          # or: ebuild stamp-suite-<ver>.ebuild manifest
   pkgcheck scan            # QA lint expected by GURU reviewers
   ```

`Manifest` is deliberately not committed here: it embeds the checksum of
the tag archive, which only exists once the release is tagged.

## USE flags

| flag | Cargo feature | effect |
|------|---------------|--------|
| `control` | `control` | localhost control-plane REST API (TLS via rustls/ring) |
| `hwtstamp` (default on) | `hwtstamp` | kernel/NIC hardware timestamping |
| `metrics` | `metrics` | Prometheus exporter |
| `snmp` | `snmp` | SNMP AgentX subagent, installs `STAMP-SUITE-MIB` |

`ttl-nix` (the Linux socket backend) is always enabled; it is what the
Debian and RPM packages ship as well.

## Submitting

- **GURU**: fork `gentoo/guru` on GitHub, copy the three package
  directories in, add `Manifest` files, open a PR. Reviews there are
  light-touch; a green `pkgcheck scan` is the main expectation.
- **::gentoo**: after the package has users in GURU, file a bug at
  bugs.gentoo.org with the ebuild attached (or a PR to `gentoo/gentoo`) and
  request fixed `ACCT_USER_ID`/`ACCT_GROUP_ID` values from `uid-gid.txt`;
  `-1` (dynamic allocation) is only acceptable in overlays.
