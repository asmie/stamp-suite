# Security

This document is for operators who deploy a stamp-suite reflector or sender.
It covers the threat model, HMAC authentication, where keys come from and how
to rotate them, file permissions, and hardening of the packaged service.

## Threat model

The host filesystem, kernel and clock are trusted. Network traffic is
untrusted: routers and peers can drop, delay, reorder, duplicate or remark
packets. A peer that holds a shared HMAC key can forge messages authenticated
with that key.

HMAC detects changes to covered bytes and rejects packets injected without
the key. It does not encrypt traffic, establish freshness, prevent flooding or
protect against a compromised key holder. IP headers are outside STAMP HMAC
coverage.

### Reflection and amplification (open mode)

An open reflector can reply to spoofed source addresses. Limit access with
network policy, and use authenticated mode on untrusted networks.

The defaults limit additional amplification:

- `--return-path-allow-alternate` is off. Return Address requests get the U
  flag and replies go to the packet source.
- `--srv6-return-forwarding` is off. Unsupported return-path requests get the
  U flag.
- `--reflected-control-max-count` defaults to 0, which disables Type 12.
  Such a request gets one normal reply with the U flag, without the requested
  padding or extra copies. When Type 12 is enabled,
  `--reflected-control-max-rate` and `--reflected-control-max-volume` bound
  the bytes each request can generate.

Enable these features only inside a controlled measurement domain.
Authenticated mode rejects packets with an invalid base HMAC before it
changes session state or builds a reply. In open mode, TLV integrity does not
authenticate the base packet.

### Bounded session state

`--max-sessions` limits tracked session identities (default 65536; 0 means
unlimited). An identity is both UDP endpoints, the SSID and the optional
sender Micro-session ID. At capacity, new identities are dropped and existing
sessions continue. Idle expiry or explicit expiry frees capacity.

`--max-pps` limits reflected packets per second per source IP address. It
defaults to 0 (unlimited). `--reflector-queue-capacity` (default 1024)
separately bounds accepted requests waiting for replies, including bursts. It
counts requests, not bytes. See
[Capacity, drain and shutdown](usage.md#capacity-drain-and-shutdown).

Replay detection keeps a 31-entry window per session. A Type 12 request whose
sequence number is not new gets one reply with the U flag.
`--drop-replayed` also suppresses ordinary duplicates. Reordering and sender
restarts can also produce sequence numbers that are not new. See
[Reflector](usage.md#reflector).

## HMAC authentication

Both mechanisms use HMAC-SHA-256 truncated to 16 bytes:

| Mechanism | Coverage and behavior |
| --- | --- |
| Base authentication (`--auth-mode A`) | Covers the fixed packet fields (RFC 8762 §4.4). A missing key prevents startup. Packets with an invalid HMAC are dropped. |
| TLV HMAC (RFC 8972 §4.8, Type 8) | Covers the sequence number and the TLVs before the HMAC TLV. Only Extra Padding may follow it, outside coverage. `--verify-tlv-hmac` turns on verification at the reflector. A failed check produces a reply with the I flag set. |

The sender's `--tlv-hmac auto` (the default) adds an HMAC TLV when a key is
configured. `on` requires a key. `off` stops the sender from adding one; the
key is still used to verify reflected TLV HMACs. Authenticated mode rejects
`off`.

## Key sourcing and rotation

### Key sources

Configure exactly one key source:

| Source | Use |
| --- | --- |
| `--hmac-key HEX` or the `STAMP_HMAC_KEY` environment variable | Testing. The key is visible in process arguments or the process environment. |
| `--hmac-key-file PATH` | One key for all sessions. Preferred for services. |
| `--hmac-key-dir DIR` | Reflector only: one key per SSID, plus an optional default. |

Combining sources fails startup. This also applies across the command line
and the configuration file: a key on the command line or in the environment
conflicts with a key file set in TOML instead of overriding it. The TOML
configuration accepts `hmac_key_file` and `hmac_key_dir` but has no field for
an inline key.

A key file holds the key as hex text or as raw bytes, and must decode to at
least 16 bytes. Use 32 random bytes for new keys:

```sh
openssl rand -hex 32
```

At startup the reflector loads its source into one keyset. A single key from
`--hmac-key`, `STAMP_HMAC_KEY` or `--hmac-key-file` becomes the keyset's
default key. Keys are redacted from debug output and wiped from memory when
dropped.

### Key directories

In a key directory, each file's name without its extension is the SSID in
hexadecimal, and `default.key` holds the fallback key:

```text
/etc/stamp/keys/
├── 002a.key      # SSID 42
├── 0100.key      # SSID 256
└── default.key   # any other SSID
```

A packet uses the key for its SSID, or the default key when there is none.
In authenticated mode a packet whose SSID matches no key is dropped. Removing
a per-SSID key does not revoke that SSID while a default key exists.

Invalid key files and files with other names are logged and skipped. A
directory with no usable key fails startup.

### File permissions

On Unix, stamp-suite checks permissions when it opens these files:

| File | Check |
| --- | --- |
| TOML configuration | Warns if group or other can write it (`0o022`). |
| HMAC key file or control token file | Rejects any group or other permission (`0o077`). |
| Key directory | Rejects group or other write permission. |

Key and token checks use the opened file descriptor, so the file cannot be
swapped between the check and the read. Symlinks are allowed when their
targets pass the check.

For the packaged `stamp` service:

```sh
sudo install -d -m 0750 -o root -g stamp /etc/stamp
sudo chown root:stamp /etc/stamp/reflector.toml
sudo chmod 0640 /etc/stamp/reflector.toml
sudo chown stamp:stamp /etc/stamp/hmac.key
sudo chmod 0400 /etc/stamp/hmac.key
```

A key with mode 0640 is rejected even when its group is `stamp`. The
configuration file can use 0640 because its check concerns write access only.

### Rotation

A reflector can change keys without a restart in two ways:

- **SIGHUP** (Unix, reflector only) reloads the key file or key directory
  and replaces the whole keyset, including keys added through the control
  API. If the reload fails, the reflector logs a warning and keeps its
  current keys. A reload fails when the key file is unreadable, invalid or
  has unsafe permissions, or when the directory is unreadable, writable by
  group or other, or has no usable key. Inside a directory, an invalid file
  is skipped as at startup, so its SSID loses its key after the reload. A key
  given with `--hmac-key` or `STAMP_HMAC_KEY` is reloaded unchanged.

  ```sh
  sudo systemctl kill --signal=HUP stamp-suite
  ```

- **The control API** (`control` feature) adds, replaces and removes keys
  with `PUT` and `DELETE` on `/v1/keys/{ssid}` and `/v1/keys/default`. These
  changes last until the process exits or the next SIGHUP. Put lasting keys in
  the key file or directory. See [Endpoints](control-plane.md#endpoints).

Restarting the reflector also loads the current files.

Both ends of a session must use the same key, and a sender loads its key only
at startup. Packets signed with the old key are dropped once the reflector
switches, so change the sender and reflector together, or rotate one SSID at a
time with a key directory. Replies already queued keep the key that was in
use when their request was accepted.

## Service account (`stamp`)

DEB and RPM packages create a non-login `stamp` account without a home
directory. The service runs as `stamp:stamp`. Purging the DEB package removes
the account; removing the RPM package keeps it. The account needs read access
to the configured keys and certificates.

## Systemd unit hardening

The [packaged unit](../dist/systemd/stamp-suite.service) runs
`stamp-suite --is-reflector` as `stamp:stamp`, restarts it on failure after
5 seconds, and grants only `CAP_NET_BIND_SERVICE` (as an ambient capability
and as the whole bounding set). It also sets:

| Setting | Effect |
| --- | --- |
| `ProtectSystem=strict` | The file system is read-only for the service. |
| `ProtectHome=yes`, `PrivateTmp=yes` | Home directories are hidden; `/tmp` is private. |
| `PrivateDevices=yes` | Only pseudo devices such as `/dev/null` are visible. |
| `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` | The process cannot gain privileges. |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock` | Kernel settings, modules, cgroups and the system clock cannot be changed. |
| `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute` | No new namespaces, realtime scheduling, personality changes or writable executable memory. |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK` | Linux uses netlink for route-MTU lookups and to list interface addresses. |

Read access still follows Unix ownership and permissions. Some options need
more than the unit allows:

- The pnet backend needs `CAP_NET_RAW` and the `AF_PACKET` address family.
- `--hwtstamp on` needs `CAP_NET_ADMIN` to configure NIC timestamping.

Add these with a drop-in (`sudo systemctl edit stamp-suite`) and review the
result with `systemd-analyze security stamp-suite.service`.

## Enabling authenticated mode on the packaged unit

The packaged service starts in open mode. To turn on authentication:

1. Create an owner-only key:

   ```sh
   sudo install -d -m 0750 -o root -g stamp /etc/stamp
   sudo install -m 0400 -o stamp -g stamp /dev/null /etc/stamp/hmac.key
   openssl rand -hex 32 | sudo tee /etc/stamp/hmac.key >/dev/null
   ```

2. Run `sudo systemctl edit stamp-suite` and add:

   ```ini
   [Service]
   ExecStart=
   ExecStart=/usr/bin/stamp-suite --is-reflector --auth-mode A --hmac-key-file /etc/stamp/hmac.key --verify-tlv-hmac
   ```

   The empty `ExecStart=` line clears the packaged command. Authenticated mode
   does not start without a usable key.

3. Restart the service and check for startup errors:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl restart stamp-suite
   sudo journalctl -u stamp-suite -n 50
   ```

4. Give authorized senders the same key and run them with `--auth-mode A`.

To change the key later, see [Rotation](#rotation).

## Capability model

On Linux, binding a port below `net.ipv4.ip_unprivileged_port_start` (1024
by default) needs `CAP_NET_BIND_SERVICE`. The reflector's default port is 862;
a port of 1024 or higher avoids the requirement. The nix backend needs no
raw-socket capability; the pnet backend needs `CAP_NET_RAW`. `--hwtstamp on`
needs `CAP_NET_ADMIN` and NIC support. The service manager or container
runtime must also allow these capabilities.

## Reporting vulnerabilities

Follow [SECURITY.md](../SECURITY.md). For configuration options, see
[usage](usage.md).
