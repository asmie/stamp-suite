# Gentoo packaging

This overlay provides `net-analyzer/stamp-suite`, `acct-user/stamp` and
`acct-group/stamp` for the systemd and OpenRC services. Its categories,
eclasses and layout follow the main tree and can be copied into
[GURU](https://wiki.gentoo.org/wiki/Project:GURU) or `::gentoo`.

## Regenerating after a release

1. `CRATES=` and the dependent-crate `LICENSE+=` line are generated from
   `Cargo.lock` by [pycargoebuild](https://github.com/projg2/pycargoebuild):

   ```sh
   pycargoebuild -i net-analyzer/stamp-suite/stamp-suite-<ver>.ebuild <checkout>
   ```

2. Rename the ebuild to the new version. `SRC_URI` uses the release's
   source archive, which must be published before the next step.

3. Generate `Manifest` (needs a Gentoo host or container with the
   overlay registered):

   ```sh
   pkgdev manifest          # or: ebuild stamp-suite-<ver>.ebuild manifest
   pkgcheck scan            # QA lint expected by GURU reviewers
   ```

Generate `Manifest` from the published archive; its checksum is unavailable
before publication.

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
