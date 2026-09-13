# Security

## Threat model

The host filesystem, kernel, and clock are trusted. Network traffic is untrusted;
routers and peers can drop, delay, reorder, duplicate, or remark packets.
A peer holding a shared HMAC key can forge messages authenticated with that key.

HMAC detects changes to covered bytes and rejects injections without the key.
It does not encrypt traffic, establish freshness, prevent flooding, or protect
against a compromised key holder. IP headers are outside STAMP HMAC coverage.

### Reflection and amplification (open mode)

An open reflector can reply to spoofed source addresses. Limit access with
network policy and use authenticated mode on untrusted networks.

Defaults restrict additional amplification:

- `--return-path-allow-alternate` is off. Return Address requests get U set and
  replies go to the packet source.
- `--srv6-return-forwarding` is off. Unsupported requests get U set.
- `--reflected-control-max-count` defaults to 0. Type-12 requests receive one
  normal C-flagged reply, without requested padding or extra copies.

Enable these features only for a controlled measurement domain. Authenticated
mode rejects invalid base HMACs before session mutation or reply generation.
Open-mode TLV integrity does not authenticate the base packet.

### Bounded session state

`--max-sessions` limits runtime identities (default 65536; 0 means unlimited).
The key includes source and destination UDP endpoints, SSID, and optional sender
Micro-session ID. At capacity, new identities are dropped; existing sessions
continue. Idle expiry or explicit expiry frees capacity.

`--max-pps` limits traffic per source IP and SSID; it defaults to unlimited.
`--reflector-queue-capacity` separately bounds accepted pending requests
(default 1024), including bursts. It is a request limit, not a byte quota.
See [capacity and drain](usage.md#session-capacity-drain-and-restart).

Replay detection tracks a 31-entry window per session. Handled Type-12 requests
with non-new sequences get one U-flagged reply; `--drop-replayed` additionally
suppresses ordinary duplicates. Reordering or sender restarts can also produce
non-new verdicts. See [reflector behavior](usage.md#reflector-mode).

## HMAC authentication

Both mechanisms use HMAC-SHA256 truncated to 16 bytes:

| Mechanism | Coverage and behavior |
| --- | --- |
| Base authentication (`--auth-mode A`) | Authenticates fixed packet fields. Missing keys prevent startup; invalid packet HMACs cause drops. |
| TLV HMAC (RFC 8972 Type 8) | Covers the sequence number and TLVs before HMAC. Only Extra Padding may follow it, outside coverage. `--verify-tlv-hmac` enables reflector verification. Failed TLV integrity produces I-flagged echoes under RFC 8972. |

The sender's `--tlv-hmac auto` includes an HMAC TLV when a key is configured.
`on` requires a key; `off` disables origination in open mode while retaining
reply verification. Authenticated mode rejects `off`.

## Key sourcing & precedence

Choose one source: `--hmac-key HEX` (also supplied by `STAMP_HMAC_KEY`),
`--hmac-key-file PATH`, or reflector-only `--hmac-key-dir DIR`. These sources
conflict; a CLI/environment key does not override a file source.
CLI fields override matching TOML fields. TOML accepts key paths, not plaintext
`hmac_key` or recursive `config` entries.

CLI keys are visible in process arguments; environment keys are visible to users
who can read the process environment. Prefer a file for service deployments.
Files accept hex text or raw key bytes, with at least 16 decoded bytes.
Use 32 random bytes for new keys.

Key directories map hexadecimal filename stems to SSIDs; `default.key` supplies
a fallback. Removing a per-SSID entry does not revoke access while a default key
still applies. Invalid key files are logged and skipped; an empty or unusable
configured keyset prevents startup. Keys are redacted from debug output and
zeroized when their owned storage is dropped.

## Configuration file and key-file permissions

On Unix:

| File | Check |
| --- | --- |
| TOML config | Warns if group/other can write (`0o022`) |
| HMAC key or control token | Rejects any group/other permission (`0o077`) |
| Key directory | Rejects group/other write access |

Secret-file checks use the opened descriptor, avoiding a separate path lookup.
Symlinks are allowed when their targets pass the permission check.

For the packaged `stamp` service:

```sh
sudo install -d -m 0750 -o root -g stamp /etc/stamp
sudo chown root:stamp /etc/stamp/reflector.toml
sudo chmod 0640 /etc/stamp/reflector.toml
sudo chown stamp:stamp /etc/stamp/hmac.key
sudo chmod 0400 /etc/stamp/hmac.key
```

A mode-0640 key is rejected even if its group is `stamp`. The config can use that
mode because its check concerns write access.

## System user & group (`stamp`)

DEB/RPM packages create a non-login `stamp` account without a home directory.
The service runs as `stamp:stamp`. DEB purge removes the account; RPM uninstall
retains it. The account needs read access to configured keys and certificates.

## Systemd unit hardening

The [packaged unit](../dist/systemd/stamp-suite.service) grants
`CAP_NET_BIND_SERVICE`, restarts on failure, makes the filesystem read-only,
hides home directories, and restricts devices, namespaces, privilege changes,
and kernel settings. Its allowed socket families are `AF_INET`, `AF_INET6`,
and `AF_UNIX`.

Read access still follows Unix ownership and permissions. For pnet capture,
add the required raw-socket capability and address family. The packaged family
restriction also excludes `AF_NETLINK`, which Linux route-MTU queries and
interface discovery may need; configure a suitable override before relying on
those features. Hardware timestamping needs additional device/capability access.
Review the resulting unit with `systemd-analyze security stamp-suite.service`.

## Enabling authenticated mode on the packaged unit

The packaged service starts in open mode. To enable authentication:

1. Generate an owner-only key:

   ```sh
   sudo install -d -m 0750 -o root -g stamp /etc/stamp
   sudo install -m 0400 -o stamp -g stamp /dev/null /etc/stamp/hmac.key
   openssl rand -hex 32 | sudo tee /etc/stamp/hmac.key >/dev/null
   ```

2. Run `sudo systemctl edit stamp-suite` and add:

   ```ini
   [Service]
   ExecStart=
   ExecStart=/usr/bin/stamp-suite --is-reflector --auth-mode A --hmac-key-file /etc/stamp/hmac.key --verify-tlv-hmac --require-hmac
   ```

   The empty `ExecStart=` assignment clears the packaged command. Authenticated mode requires
   a usable key; `--require-hmac` also requires one at startup.

3. Restart and inspect startup errors:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl restart stamp-suite
   sudo journalctl -u stamp-suite -n 50
   ```

4. Give authorized senders the same key and use `--auth-mode A` on them.

Rotate a file-backed key by replacing the file and restarting, or use the
[control API](control-plane.md) to update the runtime keyset. Runtime changes do
not persist. Queued replies retain the key selected when their request was
accepted; allow for those replies during rotation.

## Capability model

On Linux, binding below the configured unprivileged-port threshold may require
`CAP_NET_BIND_SERVICE`. A high local port avoids that requirement.
The nix receiver needs no raw-socket capability; pnet needs `CAP_NET_RAW`.
NIC configuration for `--hwtstamp on` needs `CAP_NET_ADMIN` and compatible hardware.
These capabilities must also be allowed by the service/container policy.

## Reporting vulnerabilities

Follow [SECURITY.md](../SECURITY.md). For setup options, see [usage](usage.md).
