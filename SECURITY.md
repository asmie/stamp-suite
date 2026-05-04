# Security Policy

## Reporting a Vulnerability

There is no formal coordinated-disclosure embargo today. Please use one of the following:

- **For obvious bugs that don't involve sensitive details** (e.g. a crash, a parser error): open a regular issue at <https://github.com/asmie/stamp-suite/issues>.
- **For anything that could be exploited against a deployed reflector or sender** (key disclosure, RCE, denial of service via crafted packets, authentication bypass): email the maintainer directly — `Piotr Olszewski <asmie@asmie.pl>` — with a minimal reproduction. Please give a reasonable window for a fix before publishing.

A formal SECURITY policy with a PGP key and a fixed disclosure window may be added once the project has more downstream users.

## Security Model and Hardening

For the project's threat model, HMAC authentication design, key handling, configuration-file and key-file permissions, the `stamp` system user, the systemd unit's hardening directives, the capability model, and a step-by-step walkthrough for switching the packaged systemd unit to authenticated mode, see [doc/security.md](doc/security.md).
