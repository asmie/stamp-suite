# Gentoo packaging

This directory is an overlay tree for packagers. It holds
`net-analyzer/stamp-suite` and the `acct-user/stamp` and `acct-group/stamp`
packages that the systemd unit and OpenRC script run under. Category,
eclass usage (`cargo`, `systemd`, `acct-*`) and file layout follow the main
tree, so the directories can be copied into
[GURU](https://wiki.gentoo.org/wiki/Project:GURU) or `::gentoo` unchanged.

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

`Manifest` is not committed here because it contains the checksum of the
tag archive, which exists only after the release is tagged.

## USE flags

| Flag | Cargo feature | Effect |
|------|---------------|--------|
| `control` | `control` | Reflector control API (`--control`), HTTP on loopback by default, optional HTTPS through rustls and ring |
| `hwtstamp` (default on) | `hwtstamp` | Kernel software receive and transmit timestamps; NIC hardware timestamps only with `--hwtstamp on`, which needs `CAP_NET_ADMIN` |
| `metrics` | `metrics` | Prometheus endpoint (`--metrics`) |
| `snmp` | `snmp` | SNMP AgentX sub-agent (`--snmp`); installs `STAMP-SUITE-MIB` |

The ebuild always enables `ttl-nix`, so the package uses the nix UDP socket
backend. The DEB and RPM packages use the same backend.

## Submitting

- **GURU**: fork `gentoo/guru` on GitHub, copy the three package
  directories in, add `Manifest` files and open a pull request. Reviewers
  there mainly expect a clean `pkgcheck scan`.
- **::gentoo**: after the package has users in GURU, file a bug at
  bugs.gentoo.org with the ebuild attached (or a PR to `gentoo/gentoo`) and
  request fixed `ACCT_USER_ID`/`ACCT_GROUP_ID` values from `uid-gid.txt`;
  `-1` (dynamic allocation) is only acceptable in overlays.
