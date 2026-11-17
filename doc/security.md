# Security

How to run stamp-suite safely: what it trusts, how HMAC keys are loaded and
rotated, which file permissions it checks, and how the packaged service is
locked down.

## Threat model

stamp-suite trusts the host's filesystem, kernel and clock. It does not trust
the network: routers and peers can drop, delay, reorder, duplicate or remark
packets. Anyone who holds a shared HMAC key can forge messages authenticated
with that key.

HMAC detects changes to the bytes it covers and rejects packets injected by
someone without the key. It does not encrypt traffic, prove that a packet is
fresh, stop flooding, or help against a compromised key holder. STAMP HMAC
does not cover IP headers.

### Reflection and amplification (open mode)

An open reflector will reply to spoofed source addresses. Restrict who can
reach it with network policy, and use authenticated mode on untrusted
networks.

For Type 12, the protected profile combines authenticated mode with
`--verify-tlv-hmac` and a key source, so the HMAC also covers the extension
that controls amplification. An open reflector that verifies optional HMACs
still accepts a request with no HMAC TLV at all. The conformance matrix's
protected-profile claim does not cover that setup.

The defaults keep extra amplification low:

- `--return-path-allow-alternate` is off. Return Address requests get the U
  flag, and replies go to the packet's source address.
- `--srv6-return-forwarding` is off. Return-path requests the reflector does
  not support get the U flag.
- `--reflected-control-max-count` defaults to 0, which disables Type 12. A
  Type 12 request then gets one normal reply with the U flag, without the
  requested padding or extra copies. If you enable Type 12,
  `--reflected-control-max-rate` and `--reflected-control-max-volume` cap the
  bytes a single request can generate.

Only enable these features inside a measurement domain you control.
Authenticated mode rejects a packet with an invalid base HMAC before it
touches session state or builds a reply. In open mode, a valid TLV HMAC does
not authenticate the base packet.

### Bounded session state

`--max-sessions` limits how many session identities the reflector tracks
(default 65536; 0 means no limit). An identity is the pair of UDP endpoints,
the SSID and, if present, the sender Micro-session ID. When the table is full,
packets that would start a new identity are dropped, and existing sessions
keep working. Space frees up when a session idles out or is expired by hand.

`--max-pps` rate-limits per source IP. Each incoming request costs one token,
charged before validation and session admission, and each extra Type 12 reply
copy costs one more. The default is 0 (no limit). `--reflector-queue-capacity`
(default 1024) is a separate cap on accepted requests that are waiting for
their replies, bursts included. It counts requests, not bytes. See
[Capacity, drain and shutdown](usage.md#capacity-drain-and-shutdown).

The rate limiter keeps at most 16,384 source-IP buckets, whatever
`--max-sessions` is set to. Sources that arrive after that share a single
overflow budget, while sources that already have a bucket keep it. A bucket
that has been idle for 60 s can be removed; each request scans at most four
entries for removal. The Type 12 count, size and volume caps apply on top of
this.

Replay detection keeps a window of 31 sequence numbers per session. A Type 12
request with a sequence number the session has already seen gets one reply
with the U flag. With `--drop-replayed`, ordinary duplicates are dropped too.
Keep in mind that reordering and sender restarts also produce sequence
numbers that are not new. See [Reflector](usage.md#reflector).

## HMAC authentication

Both mechanisms use HMAC-SHA-256 truncated to 16 bytes:

| Mechanism | Coverage and behavior |
| --- | --- |
| Base authentication (`--auth-mode A`) | Covers the fixed packet fields (RFC 8762 §4.4). Without a key the process does not start. Packets with an invalid HMAC are dropped. |
| TLV HMAC (RFC 8972 §4.8, Type 8) | Covers the sequence number and every TLV before the HMAC TLV. Only Extra Padding may come after it, and that padding is not covered. The reflector checks it only with `--verify-tlv-hmac`. If the check fails, the reply has the I flag set. |

On the sender, `--tlv-hmac auto` (the default) adds an HMAC TLV whenever a key
is configured. `on` fails without a key. `off` stops the sender from adding
the TLV, but the key is still used to verify TLV HMACs in replies, and a
reply without one is accepted. Authenticated mode does not accept `off`.

A reflector with a key always signs authenticated replies that carry TLVs,
except when the only TLV is Extra Padding, which RFC 8972 §4.8 exempts. In
open mode it signs a reply when the request carried an HMAC TLV, so the sender
decides; with `--tlv-hmac on` it signs every open-mode reply that has TLVs. A
sender without the key cannot verify those signatures and ignores the reply's
measurement values. A reflector does not accept `off`.

### ECN measurement integrity

Someone who tampers with the CoS TLV can fake EC2 or the requested reverse
marking. To protect it, configure a shared key, leave the sender's
`--tlv-hmac` at `auto` (or set `on`), and run the reflector with
`--verify-tlv-hmac`. The base packet HMAC does not cover the CoS TLV, and
neither HMAC covers the ECN bits in the IP header, which routers are allowed
to change. A key holder can still fake measurements.

The [CoS/ECN draft §6](https://www.ietf.org/archive/id/draft-ietf-bpm-stamp-cos-ecn-00.txt)
also suggests using a destination UDP port from the dynamic range
(49152–65535), so that port-based middleboxes are less likely to spot STAMP
traffic. To do that, set the reflector's `--local-port` and the sender's
`--remote-port` to the same port and open it in your firewall and
provisioning rules. stamp-suite does not pick a random port for you. A
different port does not authenticate anything, and a middlebox can still
identify or modify the packets.

## Key sourcing and rotation

### Key sources

Configure exactly one key source:

| Source | Use |
| --- | --- |
| `--hmac-key HEX` or the `STAMP_HMAC_KEY` environment variable | Testing only. Other users can see the key in the process arguments or environment. |
| `--hmac-key-file PATH` | One key for all sessions. Use this for services. |
| `--hmac-key-dir DIR` | Reflector only: one key per SSID, plus an optional default. |

If more than one source is set, startup fails. This also holds across the
command line and the configuration file: a key given on the command line or
in the environment does not override a key file set in TOML, it conflicts
with it. The TOML file accepts `hmac_key_file` and `hmac_key_dir`, but has no
field for an inline key.

A key file contains the key either as hex text or as raw bytes, and it must
decode to at least 16 bytes. Generate new keys as 32 random bytes:

```sh
openssl rand -hex 32
```

At startup the reflector loads its key source into a single keyset. A single
key from `--hmac-key`, `STAMP_HMAC_KEY` or `--hmac-key-file` becomes the
keyset's default key. Keys never appear in debug output, and their memory is
wiped when they are dropped.

### Key directories

In a key directory, each file is named after an SSID in hexadecimal (the
extension is ignored), and `default.key` holds the fallback key:

```text
/etc/stamp/keys/
├── 002a.key      # SSID 42
├── 0100.key      # SSID 256
└── default.key   # any other SSID
```

A packet is checked with the key for its SSID, or with the default key if its
SSID has none. In authenticated mode, a packet whose SSID has no key and no
default to fall back on is dropped. This means that deleting a per-SSID key
does not lock that SSID out while a default key exists.

Invalid key files, and files with names that do not fit the scheme, are
logged and skipped. If no usable key is left in the directory, startup fails.

### File permissions

On Unix, stamp-suite checks permissions when it opens these files:

| File | Check |
| --- | --- |
| TOML configuration | Warns if group or other can write it (`0o022`). |
| HMAC key file or control token file | Rejects any group or other permission (`0o077`). |
| Key directory | Rejects group or other write permission. |

Key and token files are checked through the file descriptor that is then read,
so nobody can swap the file between the check and the read. Symlinks are
fine as long as their target passes the check.

For the packaged `stamp` service:

```sh
sudo install -d -m 0750 -o root -g stamp /etc/stamp
sudo chown root:stamp /etc/stamp/reflector.toml
sudo chmod 0640 /etc/stamp/reflector.toml
sudo chown stamp:stamp /etc/stamp/hmac.key
sudo chmod 0400 /etc/stamp/hmac.key
```

A key file with mode 0640 is rejected even if its group is `stamp`. The
configuration file can be 0640 because only write access is checked for it.

### Rotation

You can change a reflector's keys without restarting it, in two ways:

- **SIGHUP** (Unix, reflector only) rereads the key file or key directory and
  replaces the whole keyset, including any keys added through the control
  API. If the reload fails, the reflector logs a warning and keeps the keys
  it had. A reload fails when the key file is unreadable, invalid or has
  unsafe permissions, or when the directory is unreadable, writable by group
  or other, or holds no usable key. An invalid file inside a directory is
  skipped, just as at startup, so its SSID ends up with no key after the
  reload. A key given with `--hmac-key` or `STAMP_HMAC_KEY` is kept as it
  is.

  ```sh
  sudo systemctl kill --signal=HUP stamp-suite
  ```

- **The control API** (`control` feature) adds, replaces and removes keys
  with `PUT` and `DELETE` on `/v1/keys/{ssid}` and `/v1/keys/default`. These
  changes last until the process exits or the next SIGHUP, so put keys you
  want to keep in the key file or directory. See
  [Endpoints](control-plane.md#endpoints).

A restart also picks up the current files.

Both ends of a session must use the same key, and a sender reads its key only
at startup. Once the reflector switches keys, it drops packets signed with
the old one. Change the sender and the reflector together, or use a key
directory and rotate one SSID at a time. Replies that are already queued are
signed with the key that was in use when their request was accepted.

## Service account (`stamp`)

The DEB and RPM packages create a `stamp` account with no login shell and no
home directory, and the service runs as `stamp:stamp`. Purging the DEB package
deletes the account; removing the RPM package leaves it in place. The account
needs read access to the configured keys and certificates.

## Systemd unit hardening

The [packaged unit](../dist/systemd/stamp-suite.service) runs
`stamp-suite --is-reflector` as `stamp:stamp` and restarts it 5 seconds after
a failure. The only capability it grants is `CAP_NET_BIND_SERVICE`, both as an
ambient capability and as the entire bounding set. It also sets:

| Setting | Effect |
| --- | --- |
| `ProtectSystem=strict` | The file system is read-only for the service. |
| `ProtectHome=yes`, `PrivateTmp=yes` | Home directories are hidden; `/tmp` is private. |
| `PrivateDevices=yes` | Only pseudo devices such as `/dev/null` are visible. |
| `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` | The process cannot gain privileges. |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock` | The service cannot change kernel settings, modules, cgroups or the system clock. |
| `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `MemoryDenyWriteExecute` | The service cannot create namespaces, use realtime scheduling, change its personality or map memory that is both writable and executable. |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK` | Netlink is allowed because Linux uses it to look up route MTUs and list interface addresses. |

Reading files is still governed by normal Unix ownership and permissions.
Some options need more than the unit allows:

- The pnet backend needs `CAP_NET_RAW` and the `AF_PACKET` address family.
- `--hwtstamp on` needs `CAP_NET_ADMIN` to configure NIC timestamping.

Add these in a drop-in (`sudo systemctl edit stamp-suite`), then review the
result with `systemd-analyze security stamp-suite.service`.

## Enabling authenticated mode on the packaged unit

The packaged service starts in open mode. To turn on authentication:

1. Create a key that only its owner can read:

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

   The empty `ExecStart=` line clears the packaged command. In authenticated
   mode the service will not start without a usable key.

3. Restart the service and look for startup errors:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl restart stamp-suite
   sudo journalctl -u stamp-suite -n 50
   ```

4. Give the same key to each authorized sender and run them with
   `--auth-mode A`.

To change the key later, see [Rotation](#rotation).

## Capability model

On Linux, binding to a port below `net.ipv4.ip_unprivileged_port_start` (1024
by default) needs `CAP_NET_BIND_SERVICE`. The reflector listens on port 862 by
default; pick a port of 1024 or higher and you do not need the capability.
The nix backend needs no raw-socket capability, while the pnet backend needs
`CAP_NET_RAW`. `--hwtstamp on` needs `CAP_NET_ADMIN` and a NIC that supports
it. Whatever you need, the service manager or container runtime has to allow
it as well.

## Reporting vulnerabilities

Follow [SECURITY.md](../SECURITY.md). For configuration options, see
[usage](usage.md).
