# Security

This document describes the security mechanisms in `stamp-suite`: the threat model, HMAC-based packet authentication, how HMAC keys are sourced and handled, recommended configuration-file and key-file permissions, the `stamp` system user created by the DEB and RPM packages, and the systemd unit's hardening directives.

## Threat Model

`stamp-suite` is a network-measurement tool, not a security boundary. It assumes:

- **Trusted**: the local filesystem (the user running it can read its config and key files), the kernel network stack, the local clock source.
- **Semi-trusted**: peers in HMAC-authenticated mode — they hold the shared key, so they can forge packets. HMAC proves *which key* signed the packet, not *which person*.
- **Untrusted**: arbitrary network peers in open mode (`auth_mode = "O"`), the network path itself (any router can drop, delay, reorder, duplicate, or remark packets — that's exactly what stamp-suite measures).

What HMAC defends against: tampering with sequence numbers, timestamps, or TLV payloads in flight; off-path injection of forged STAMP packets without the shared key. What it does *not* defend against: replay of intact, previously-valid authenticated packets (HMAC authenticates bytes; it does not provide freshness — the sender's pending-sequence bookkeeping rejects some stale *replies*, but a captured authenticated *request* still verifies if replayed at the reflector); a compromised peer with the shared key; traffic-analysis side channels; DoS via flooding (UDP/862 is open by design).

If you're running stamp-suite on a host shared with untrusted users, the configuration file and HMAC key file are the assets to protect — see [Configuration File and Key-File Permissions](#configuration-file-and-key-file-permissions).

## HMAC Authentication

stamp-suite supports two independent HMAC mechanisms:

1. **RFC 8762 authenticated-mode packets** (`--auth-mode A`). The base STAMP packet carries an HMAC over its fixed fields. The reflector verifies this on receive (`crypto::verify_packet_hmac`) and computes a new HMAC for the reply (`crypto::compute_packet_hmac`). Open mode (`-A O`, the default) skips this entirely.

2. **TLV HMAC (RFC 8972 Type 8)** (`--verify-tlv-hmac`). An optional TLV that, when present, must be the last TLV in the chain and authenticates the entire TLV block. The flag enables verification on the reflector side; senders include it automatically when an HMAC key is configured.

Both mechanisms use the same `HmacKey`. `auth_mode = "A"` without an `hmac_key`, `hmac_key_file`, or `STAMP_HMAC_KEY` produces a validation error at startup (caught by `Configuration::validate()`) — the daemon will not start.

## Key Sourcing & Precedence

An HMAC key can be supplied through any of these inputs. From highest to lowest priority:

1. **`--hmac-key <HEX>`** — passed on the command line. Useful for ad-hoc testing; visible in `ps` output.
2. **`STAMP_HMAC_KEY`** — environment variable. Higher priority than the config file; lower than CLI. Useful for systemd `Environment=` or container secret-injection.
3. **`--hmac-key-file <PATH>`** — path to a file whose contents are the hex-encoded key. Recommended for production: the key never appears on the command line or in a process listing.
4. **`hmac_key_file = "..."`** in the TOML config file. Same semantics as `--hmac-key-file` but configured declaratively.

The plaintext **`hmac_key` field is deliberately rejected** when it appears in the TOML config file — that would put a long-lived secret on disk in clear text. The `config` field is also rejected from the file (it would be recursive).

If `hmac_key_file` is used, treat its file permissions exactly like the config file (see next section): owner-only, `chmod 600`. The HMAC key file is checked at load time (`HmacKey::from_file` in `src/crypto.rs`): any bit in `0o077` — i.e. *any* group or other permission, including read — triggers a warning. The config file uses a looser mask (`0o022`, write-only).

## Configuration File and Key-File Permissions

Because the config file can set `hmac_key_file` and every other setting, treat it as trusted: an attacker who can overwrite it can change any STAMP parameter. On Unix, `stamp-suite` logs a warning if the file is writable by group or other (any bit in `0o022`).

```bash
# Recommended on the config file
chmod 600 /etc/stamp/reflector.toml
chown root:root /etc/stamp/reflector.toml

# Recommended on the HMAC key file
chmod 600 /etc/stamp/hmac.key
chown root:root /etc/stamp/hmac.key
```

If you run stamp-suite as the `stamp` system user (created by the DEB/RPM packages — see below), make the key file owned by `stamp` so the daemon can read it without granting access to anyone else. The `0o077` check on the key file means even `chmod 640` (group read) will warn — the recommended setup is owner-only `0400`:

```bash
chown stamp:stamp /etc/stamp/hmac.key
chmod 400 /etc/stamp/hmac.key
```

The config file uses the looser `0o022` writability check, so `chmod 640 root:stamp` on the config file is fine — only group/other *write* triggers the warning.

## System User & Group (`stamp`)

The DEB and RPM packages create a dedicated `stamp` system user and group at install time. The user has no shell, no home directory, and no privileges beyond what the systemd unit grants.

**On DEB** (created by `dist/debian/postinst`):

```sh
addgroup --system stamp
adduser --system --ingroup stamp --no-create-home \
    --home /nonexistent --shell /usr/sbin/nologin stamp
```

**On RPM** (created by the `pre_install_script` in `[package.metadata.generate-rpm]` in `Cargo.toml`):

```sh
getent group stamp >/dev/null || groupadd -r stamp
getent passwd stamp >/dev/null || useradd -r -g stamp -s /sbin/nologin \
    -d /nonexistent -c "STAMP Suite service account" stamp
```

The user is removed on full DEB purge (`dist/debian/postrm`); on RPM uninstall the user is intentionally retained (consistent with Fedora/RHEL packaging policy — file ownership of leftover logs would otherwise become orphaned UIDs).

The systemd unit runs the daemon as this user. That means: any process compromise gets `stamp:stamp` privileges, not root. The user cannot log in, cannot read `/root` or other users' homes (the unit additionally locks down filesystem access — see next section), and cannot escalate via setuid binaries (`NoNewPrivileges=yes`).

## Systemd Unit Hardening

The shipped unit at `dist/systemd/stamp-suite.service` applies the following hardening. Each setting is annotated with what it blocks.

```ini
[Service]
User=stamp
Group=stamp
ExecStart=/usr/bin/stamp-suite --is-reflector

# Capability model (see next section)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

Restart=on-failure
RestartSec=5

# Filesystem
ProtectSystem=strict      # Whole filesystem is read-only except /tmp, /var/tmp, runtime dirs
ProtectHome=yes           # /home, /root, /run/user are inaccessible
PrivateTmp=yes            # Private /tmp not visible to other services
PrivateDevices=yes        # No access to physical devices in /dev (only ptys, null/zero/random)

# Privilege escalation
NoNewPrivileges=yes       # Setuid/setgid bits ignored on exec
RestrictSUIDSGID=yes      # Cannot create files with setuid/setgid
LockPersonality=yes       # personality(2) is locked at startup

# Kernel surface
ProtectKernelTunables=yes # /proc/sys, /sys, /proc/sysrq-trigger are read-only or hidden
ProtectKernelModules=yes  # Cannot load or unload modules
ProtectControlGroups=yes  # /sys/fs/cgroup is read-only
ProtectClock=yes          # Cannot change wall-clock time (settimeofday, adjtime, RTC)

# Process / memory
RestrictRealtime=yes      # Cannot acquire SCHED_FIFO/SCHED_RR
MemoryDenyWriteExecute=yes  # No mprotect/mmap with PROT_WRITE+PROT_EXEC; blocks JIT-style payloads
RestrictNamespaces=yes    # No CLONE_NEW* — cannot create user/network/mount namespaces

# Network
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
                          # Anything else (AF_PACKET, AF_NETLINK, AF_BLUETOOTH...) returns EAFNOSUPPORT
```

The relevant takeaways:

- **`ProtectSystem=strict`** makes the entire filesystem read-only for the unit (except `/dev`, `/proc`, `/sys`, and the unit's own `RuntimeDirectory`/`StateDirectory`/`CacheDirectory`/`LogsDirectory`). It does *not* grant or revoke read access — read access is governed by the usual Unix permissions for the `stamp` user. So `/etc/shadow` (mode 0640 root:shadow) is unreadable here because the daemon runs as `User=stamp`, not because of `ProtectSystem`. **`ProtectHome=yes`** additionally hides `/home`, `/root`, and `/run/user`. Together they shrink the writable-and-reachable filesystem to a small whitelist.
- **`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`** is what makes the SNMP feature work (AgentX uses `AF_UNIX`) without granting `AF_PACKET` to the nix backend. The pnet backend, if used, requires `AF_PACKET` and the operator must edit the unit accordingly.
- **`MemoryDenyWriteExecute=yes`** is harmless for Rust code (we don't JIT) and significantly raises the cost of a hypothetical RCE.

If you customize the unit, run `systemd-analyze security stamp-suite.service` to score the result. The shipped unit scores in the low single digits (lower is better).

## Enabling Authenticated Mode on the Packaged Unit

The DEB and RPM packages ship a unit with `ExecStart=/usr/bin/stamp-suite --is-reflector` — that is **open mode** (`-A O` is the default). Open mode accepts unsigned packets from any peer, which is fine on a closed lab network or behind a firewall but not appropriate for the public internet. Before exposing UDP/862, switch the service to authenticated mode.

1. **Generate a key** (32+ random bytes recommended; the file should be hex):

   ```bash
   sudo install -d -m 0750 -o root -g stamp /etc/stamp
   openssl rand -hex 32 | sudo tee /etc/stamp/hmac.key >/dev/null
   sudo chown stamp:stamp /etc/stamp/hmac.key
   sudo chmod 0400 /etc/stamp/hmac.key
   ```

2. **Override the unit's ExecStart** with `systemctl edit stamp-suite`. systemd will create a drop-in at `/etc/systemd/system/stamp-suite.service.d/override.conf`:

   ```ini
   [Service]
   ExecStart=
   ExecStart=/usr/bin/stamp-suite --is-reflector \
       --auth-mode A \
       --hmac-key-file /etc/stamp/hmac.key \
       --verify-tlv-hmac \
       --require-hmac
   ```

   The empty `ExecStart=` line clears the default before defining the new one. `--require-hmac` makes the daemon refuse to start if the key is missing — important so a misconfiguration does not silently revert to open mode.

3. **Reload and restart**:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart stamp-suite
   sudo journalctl -u stamp-suite -n 50
   ```

   The journal should show the reflector starting in authenticated mode and the key file being loaded; no `WARN ... overly permissive permissions` line should appear (if it does, recheck `chmod 0400` and ownership).

4. **Distribute the same key** to legitimate senders (the only entities that should be able to reach this reflector). Any peer that does not present a packet HMAC computed with this key is rejected.

If you need to roll the key, generate a new one, replace the file, and `systemctl restart stamp-suite` — there is no in-place rotation; senders need to switch to the new key in lockstep.

## Capability Model

stamp-suite needs to bind UDP/862, which is below the privileged-port threshold (1024 on Linux). The unit grants exactly one capability — `CAP_NET_BIND_SERVICE` — through `AmbientCapabilities` (so it survives the `setuid` to the `stamp` user) and bounds the set with `CapabilityBoundingSet` so no further capabilities can ever be acquired.

| Backend | Capabilities required (beyond the usual) |
|---------|------------------------------------------|
| `nix` (default on Linux/macOS) | `CAP_NET_BIND_SERVICE` only — granted by the unit. |
| `pnet` (Windows default; opt-in on Unix via `--features ttl-pnet`) | `CAP_NET_RAW` *in addition*, or `setcap cap_net_raw=eip` on the binary, or running as root. The shipped unit does **not** grant this — operators using the pnet backend must add it explicitly. |

If you need to bind the standard port without granting any capability at all (e.g. for very paranoid deployments), pass `--local-port <high-port>` and use a load balancer or DNAT rule to redirect 862 — then the daemon needs no capabilities and can drop `CAP_NET_BIND_SERVICE` from the bounding set.

See [architecture.md#receiver-backends](architecture.md#receiver-backends) for the full discussion of why `nix` is the default and what `pnet` buys you.

## Reporting Vulnerabilities

There is no formal embargo / coordinated-disclosure process today. For now:

- For obvious bugs that don't involve sensitive details: open a regular GitHub issue at <https://github.com/asmie/stamp-suite/issues>.
- For anything involving exploitation of a deployed system (key disclosure, RCE on a hardened reflector, etc.): email the maintainer directly at the address listed in `Cargo.toml` (`authors`). Please include a minimal reproduction.

A formal `SECURITY.md` with a PGP key and a 90-day disclosure window may be added once the project has more downstream users.

## See Also

- [README](../README.md) — install and basic usage.
- [architecture.md](architecture.md) — receiver backends, packet pipeline, configuration reference.
