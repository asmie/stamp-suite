# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-05

First stable release. Everything below shipped as 1.0.0, including the
post-review closeout pass of 2026-08-04/05, which closed the last fifteen
non-Compliant conformance rows. The compliance statement in
`doc/conformance/README.md` records 368 audited clauses at 320 Compliant /
0 Partial / 3 Gap, where all three remaining Gaps and three Excluded rows are
documented, deliberate exclusions.

### Added

- **`--location-disclose <FIELDS>`** — reflector control over which Location TLV
  fields are reported (RFC 8972 §4.2.2). A withheld field is answered as zeroes,
  so the reply's size and TLV structure do not change; a withheld IP request
  keeps its generic sub-TLV type so the address family is not disclosed either.
- **`--allowed-dscp`, `--allowed-ecn`, `--allowed-dscp-for PREFIX/LEN=SPEC`** —
  the CoS admission policy RFC 8972 §4.4/§6 and cos-ecn-01 §3.2 ask for,
  separating *permitted* (operator policy) from *capable* (what the socket will
  do). A refused DSCP1 reports RPD=0b01 and keeps the received DSCP; a refused
  EC1 forces Not-ECT and reports RPE=0b10.
- **`--on-zero-ssid continue|stop`** — the sender control RFC 8972 §3 requires
  for a reflector that returns a zeroed SSID. Inert unless a non-zero `--ssid`
  was configured.
- **Replay detection** (asymmetrical-pkts §5) — per-session tracking of received
  Sequence Numbers, with `packets_replayed` and `packets_reordered` on the
  control plane's `/v1/status`. Detection is unconditional; acting on it is the
  opt-in `--drop-replayed`.
- **Control-plane TLS** — `--control-tls-cert` / `--control-tls-key` serve the
  API over HTTPS. TLS additionally requires `--control-token-file`.
- **Live egress-MTU query (reflector)** — the reply-size cap is now the smaller
  of `--reflected-control-max-size` and the egress interface's MTU.
- **Reply source-address pinning** — a matched Destination Node Address is used
  as the reply's IP source address (RFC 9503 §3), on both backends.
- **`--extra-padding <BYTES>`** — an Extra Padding TLV independent of `--ber`.
- **`--ber-omit-burst`** — omit the Type-242 TLV, whose Experimental-range
  codepoint collides with another implementation's incompatible Heartbeat TLV.
- **`--tlv-hmac auto|on|off`** — control HMAC TLV origination separately from
  holding a key.
- **`scripts/check_conformance_citations.py`** — checks the conformance
  matrices' `file:line` citations and exits non-zero on drift.

### Changed

- **Reply-size cap is smaller by default.** With `--reflected-control-max-size`
  at its 1500 default on a 1500-byte link, the effective STAMP payload cap is
  now 1472 (1452 for IPv6) rather than 1500. The flag bounds the STAMP payload
  while an MTU bounds the whole datagram, so the previous default permitted a
  1528-byte datagram; the draft's MTU-exceeded C-flag path now fires where it
  belongs. Raise the flag for a jumbo link.
- **Timestamp Information TLV**: all four value octets are filled from the
  reflector's own clocks, with the ingress (T2) and egress (T3) acquisition
  methods reported separately instead of merged into one conservative value.
- **An Extra Padding TLV following the HMAC TLV is accepted** as RFC 8972 §4.8
  explicitly permits, instead of being marked malformed.
- **A misplaced HMAC TLV** now runs §4.8's verification-failure procedure (the
  I flag on every TLV), not only the parser's M flag on the offending TLV.
- `TlvList`'s `PartialEq`/`Eq` are hand-written so parse provenance does not
  affect equality.

### Fixed

- **Panic in packet processing.** `l2_group_matches_any_local` validated only
  the mask length before indexing both mask and group, so an Address Group
  sub-TLV whose group was shorter than six octets panicked. Unreachable from the
  current parser, but a panic there is a reflector-wide denial of service.
- **Type-12 length overshoot.** A keyed reflector appends its own HMAC TLV after
  the length-padding decision, so a request from a peer that sends no HMAC TLV
  received a reply exactly 20 octets over the length it asked for. The existing
  test asserted the reply was *at least* the requested length, which the
  overshoot satisfied; it now asserts equality.
- **Missing control TLV on retransmission.** With the AIMD congestion response
  active, an Access Report wait-phase retransmission carried no Reflected Test
  Packet Control TLV at all, because that path rebuilt its TLV set from the list
  the main loop deliberately omits it from.
- **HMAC coverage arithmetic.** The covered prefix was derived from the sum of
  non-HMAC TLV sizes, which is the true wire prefix only while the HMAC TLV is
  last — the blocker that had to be fixed before trailing Extra Padding could be
  accepted.
- **Redundant syscall.** The cos-ecn-01 zero-ECN fallback re-issued the exact
  TOS byte the kernel had just refused when EC1 was already 0 and DSCP1 matched
  the received DSCP.
- **18 incorrect RFC citations.** U/M/I flag semantics were attributed to
  RFC 8972 §4.4.1, which does not exist; they are defined in §4.
- Documentation corrections: `TlvList::clear_reflector_flags` claimed to
  preserve the C bit while the method it delegates to clears it deliberately;
  `--hmac-key` called 32+ hex chars "recommended" when shorter keys are rejected
  outright; the reflected-header module doc described an earlier draft round's
  positional matching.
- The release workflow's `package` job no longer inherits `contents: write`.

### Security

- Replay/duplicate detection for received Sequence Numbers, which the draft
  notes the HMAC TLV does not defend against, since a replayed packet carries a
  valid HMAC. Per-event logging stays at debug level deliberately: the sequence
  numbers are attacker-controlled, so warning per event would be a
  log-amplification lever.
- A misplaced HMAC TLV is treated as the integrity condition §4.8 defines.
- Control-plane TLS, with a bearer token mandatory whenever TLS is enabled — an
  unauthenticated key-management and shutdown endpoint should not be reachable
  encrypted or not.
- The CoS admission policy stops treating a successful `setsockopt` as evidence
  that a codepoint is permitted in the operator's domain.
- The Address Group panic above was reachable only from a malformed sub-TLV, but
  is fixed as a denial-of-service class defect.

### Security

- **Reflection/amplification hardening (open mode).** The reflector no longer
  redirects replies or amplifies reply size for unauthenticated peers by
  default:
  - A Return Path TLV "Return Address" sub-TLV (RFC 9503 §5) is now ignored
    unless the operator opts in with the new `--return-path-allow-alternate`
    flag. When off (the default) the reflector echoes the sub-TLV with the
    U-flag and replies to the packet source, preventing an open reflector from
    being used to aim traffic at a third party.
  - A Reflected Test Packet Control TLV (Type 12) "length" request no longer
    pads the single reply unless asymmetric reflection is enabled
    (`--reflected-control-max-count > 0`, default `0`). Previously the
    single-reply padding ran regardless of the count cap, allowing ~15×
    amplification. The request is now refused with the C flag when disabled.
- **Bounded session table.** New `--max-sessions` flag (default `65536`, `0` =
  unlimited) caps the per-client session table. Previously the reflector
  created an unbounded session entry per distinct source `IP:port` on every
  packet, so an unauthenticated peer could grow the table until the process was
  OOM-killed. When the cap is reached, new clients are still answered but not
  tracked, and stale entries are reclaimed by the periodic cleanup. The
  "cap reached" warning is now logged once per saturation episode instead of
  once per rejected client, closing a log-amplification side channel.
- **Per-packet panic isolation.** Both receive backends now run
  `process_stamp_packet` through `process_stamp_packet_isolated`, which catches
  any panic, drops the offending packet, and continues. Previously a panic in
  the processing path would unwind out of the `nix` receive loop and terminate
  the process (a remote, single-packet DoS) or permanently stop the `pnet`
  capture task. No reachable panic is known; this is defence-in-depth. The
  caught-panic message is logged once at `error`, then at `debug`, to avoid a
  log-amplification side channel.
- **Key-file permissions are now enforced, not just warned.** `HmacKey::from_file`
  rejects a key file with any group/other permission bit (`0o077`) instead of
  logging a warning and using it anyway; in authenticated mode the daemon then
  refuses to start (fail-closed) rather than silently running unauthenticated.
  The check is done on the opened file descriptor (`fstat`), closing the
  time-of-check/time-of-use gap and validating the real target's permissions
  even when the path is a symlink. `O_NOFOLLOW` is intentionally not used so
  Kubernetes / systemd-credential secret mounts (which expose secrets as
  symlinks) keep working. `--hmac-key-dir` now also rejects a directory that is
  group/other-writable (key-injection risk) while still allowing the
  recommended group-readable `0750` layout.

  **Breaking:** a key file previously accepted at `0640`/`0644` (with a warning)
  is now refused. Use `chmod 0400`/`0600` (owner-only). See
  [doc/security.md](doc/security.md#configuration-file-and-key-file-permissions).
- **SNMP GETBULK/GETNEXT CPU-amplification hardening.** The AgentX sub-agent now
  (a) caps the number of SearchRanges processed per PDU at 256, and (b) computes
  the OID-space snapshot **once per PDU** instead of rebuilding and re-sorting it
  on every `get_next` lookup. Previously a single GETBULK could pack ~65k ranges,
  each multiplied by up to 100 repetitions, with every lookup rebuilding the full
  (session-table-sized) OID list — heavy CPU and lock contention. (The master
  agent is local/semi-trusted, so this is robustness hardening.)
- **CLI/env HMAC key is now zeroized and redacted.** `--hmac-key` /
  `STAMP_HMAC_KEY` are parsed into a new `SecretString` wrapper instead of a
  plain `String`: the plaintext key is zeroized on drop (so it can't be
  recovered from a core dump or freed heap) and redacted from `Debug` (so it
  can't leak through a `{:?}` of `Configuration`). Previously the decoded
  `HmacKey` was zeroized but the original hex string lingered in memory for the
  whole process lifetime. (`--hmac-key-file` remains the recommended source; a
  command-line key is still visible in `ps`/`/proc/<pid>/cmdline`.)

### Added

- **`process_stamp_packet` fuzz target.** New `fuzz/fuzz_targets/process_stamp_packet.rs`
  drives the full reflector pipeline (parse → flag re-derive/HMAC → semantic TLV
  processing → response assembly) for both authenticated and unauthenticated
  packets. The previous fuzz targets covered only the low-level parsers in
  isolation, not the in-place TLV mutators and length arithmetic.

### Added

- **Runtime control-plane REST API** (new cargo feature `control`, reflector
  only; reuses the already-optional axum/tokio-util — no new dependencies).
  `--control` starts a localhost HTTP server (default `127.0.0.1:9091`,
  `--control-addr` to change) exposing `/v1`: live status and session table,
  session expiry, **runtime per-SSID HMAC key management** (write-only —
  key bytes are never returned or logged, request strings are zeroized),
  live cap tuning (`max_pps`, `rate_burst`, `max_sessions`, Type 12
  amplification caps), drain mode (new clients still get replies but no
  session state accretes), and graceful shutdown. Optional bearer-token
  auth via `--control-token-file` (constant-time comparison); non-loopback
  binds log a loud warning. Strict request validation: unknown JSON fields
  are rejected. Full design: `doc/control-plane.md`.
  - Supporting refactors: the per-SSID `HmacKeySet` moved into
    `ReceiverSharedState` behind `Arc<RwLock<…>>` (packet loops take short
    read guards that never cross an await); the `RateLimiter` is now always
    constructed with atomically adjustable rate/burst (rate 0 = unlimited,
    short-circuits without allocating buckets); Type 12 caps live in a
    shared `RuntimeCaps` atomics struct; `SessionManager` gained
    `expire_session`/drain/runtime `max_sessions`.

- **`--hwtstamp` now performs a real capability probe.** At startup the
  reflector/sender queries `ETHTOOL_GET_TS_INFO` (via `SIOCETHTOOL`) on the
  interface owning `--local-addr` and logs the NIC's actual timestamping
  capabilities (`rx_hw`, `tx_hw`, PHC presence). Wildcard binds, unknown
  interfaces, and non-Linux platforms degrade gracefully to "no
  capabilities"; the probe never fails startup.

- **Kernel and hardware packet timestamping** (new cargo feature
  `hwtstamp`, no extra dependencies; included in the Debian package build).
  With the feature enabled and `--hwtstamp auto` (the default mode):
  - **Linux RX:** the reflector's T2 and the sender's T4 come from
    `SO_TIMESTAMPING` kernel timestamps (`SCM_TIMESTAMPING` cmsgs) taken at
    packet arrival, removing scheduler-wakeup latency from one-way delays
    (measured over loopback: forward OWD drops from tens of µs to
    single-digit µs).
  - **Linux TX:** transmit timestamps are recovered from the socket error
    queue (`MSG_ERRQUEUE`, correlated via `SOF_TIMESTAMPING_OPT_ID`). The
    sender retroactively corrects the stored T1 used for forward OWD; the
    reflector corrects its Follow-Up Telemetry record so the FUT TLV
    (RFC 8972 §4.7) carries the previous reply's kernel TX time.
  - **macOS:** kernel software receive timestamps via `SO_TIMESTAMP`
    (µs resolution). **Windows:** compiles to a no-op (the pnet receiver
    has no socket to timestamp); `SIO_TIMESTAMPING` support is future work.
  - `--hwtstamp on` additionally attempts NIC **hardware** timestamps:
    `SIOCSHWTSTAMP` filters (CAP_NET_ADMIN) + the raw-hardware cmsg tier,
    falling back to kernel software timestamps with a warning on any
    failure. The Timestamp Information TLV reports `HwAssist` only when
    both directions are hardware-timestamped; operators must keep the PHC
    disciplined (ptp4l/phc2sys) for cross-clock OWD to be meaningful — see
    the PHC caveat in `doc/architecture.md`.
  - The startup warning for `--hwtstamp on` is now conditional and honest:
    silent when hardware will genuinely be attempted, explicit about the
    missing build feature or NIC capability otherwise.

- **IPv6 Extension Header Control sub-TLV (draft-ietf-ippm-stamp-ext-hdr-08
  §5.3).** The reflector now recognizes the presence-only sub-TLV inside a
  Reflected Test Packet Control TLV as a request for one-way measurement mode
  (do not attach received IPv6 extension headers to the reply's IPv6 header)
  and records it in `ReflectedControlBehavior::suppress_reply_ext_headers`.
  Since neither backend attaches extension headers to replies, the request is
  honoured trivially today; the bit is plumbed for a future reply-attachment
  path. The sender gains `--reflected-control-no-ext-hdr` to emit the sub-TLV
  (implies emitting the Type 12 TLV even at count 1); combining it with
  `--return-path-cc 0` is rejected per asymmetrical-pkts-14 §4.3. The sub-TLV
  codepoint is TBA3 at IANA; until assignment we use 240 from the shared
  STAMP Sub-TLV Types Experimental range — renumber when the RFC publishes.

### Changed

- **Reflected Test Packet Control (Type 12) processing now follows
  draft-ietf-ippm-asymmetrical-pkts-14 §3 exactly.** Behavioral changes on the
  reflector (only when asymmetric reflection is enabled, i.e.
  `--reflected-control-max-count > 0`):
  - A request exceeding the volume limit (`--reflected-control-max-count`) or
    the rate limit (`--reflected-control-min-interval-ns`) now gets the C flag
    and a **single** reflected packet, as the draft mandates — previously the
    count/interval were silently clamped and a reduced burst was sent.
  - A request with `count = 0` now suppresses the reply entirely ("MUST NOT
    send any reflected packets").
  - Echoed Extra Padding TLVs are stripped before computing the reply length
    (§3 rule a), so a sender can request replies *shorter* than its test
    packet; the requested length is honoured aligned up to a 4-octet boundary
    (§3 rule b). The padding target is now computed from the actual reflected
    base size instead of being inferred from the presence of a TLV-HMAC key.
  - The C flag received from the wire is ignored and re-derived by the
    reflector (§3); previously a sender-set C leaked into the echo.
  - Combining a Return Path "no reply requested" control code with a non-zero
    Type 12 TLV (a sender error per §4.3) now yields a single normal reply
    with the U flag set on both TLVs, plus a warning log. The sender-side
    configuration rejects `--return-path-cc 0` together with
    `--reflected-control-count > 1` up front.

### Fixed

- **Dockerfile was unbuildable and produced a non-running image.** Two
  latent breaks: (1) the dependency-caching stub stage created only
  `src/main.rs`, so cargo couldn't parse the manifest once the lib target
  and the `reflector_hotpath` bench were declared — the stage now stubs
  all three target files; (2) the `rust:*-slim` builder tag silently moved
  to Debian trixie (glibc 2.38) while the runtime stage stayed on bookworm
  (glibc 2.36), so the binary failed to start — both stages are now pinned
  to the same Debian release. The image also builds with the production
  feature set (overridable `ARG FEATURES`: ttl-nix, metrics, snmp,
  hwtstamp, control) and documents the 9090/9091 ports. Verified
  end-to-end: containerized reflector answered a host sender with 0% loss.
  The nix flake's `cargoHash` was regenerated and its feature list now
  includes `hwtstamp` and `control`; the Debian package gained `control`.

- **CoS TLV (Type 4) wire format was incompatible with RFC 8972.** The
  encoder packed `DSCP1|ECN` into value byte 0 and `DSCP2|ECN2` into byte 1;
  RFC 8972 §4.4 places DSCP1 and DSCP2 adjacently (`| DSCP1 | DSCP2 |ECN|RP|`),
  so every CoS field except DSCP1 landed in the wrong bits when talking to a
  conformant peer (e.g. teaparty, Junos). The TLV now uses the correct layout,
  extended with the **EC1/RPE reverse-path ECN fields of
  draft-ietf-ippm-stamp-cos-ecn-00** (which occupy former Reserved bits and
  are backward compatible): EC1 carries the ECN value requested for the
  reflected packet (the existing `--ecn` flag, previously sent in the
  home-grown byte-0 position), and the reflector reports RPE=0b11 when it set
  the reply's ECN to EC1 or 0b10 when it could not (e.g. setsockopt failure,
  which now also sets RPD=0b01). NOTE: pre-fix stamp-suite peers parse CoS
  fields from the old positions, so mixed-version CoS measurements will
  misreport DSCP2/ECN values — upgrade both ends.

- **SNMP sub-agent now reconnects to the AgentX master.** Previously, if
  net-snmpd restarted or closed the session, the sub-agent exited and stayed
  down for the life of the process. The AgentX event loop now runs inside a
  reconnect loop with capped exponential backoff (1 s → 30 s) that re-connects
  and re-registers the MIB subtree, honouring the shutdown signal during
  backoff. The initial connect remains synchronous so a misconfigured socket
  path still fails fast at startup.
- **AgentX SET requests are now answered, and byte order is declared (RFC 2741
  conformance).** The sub-agent is read-only; it now replies to a TestSet with
  `notWritable` (and to Commit/UndoSet with the matching failure code, ignoring
  CleanupSet) instead of silently dropping the PDU and leaving the master to
  time out. Every emitted PDU now sets the `NETWORK_BYTE_ORDER` flag to match
  its big-endian encoding (previously the flag byte was 0, falsely declaring
  little-endian), and incoming request PDUs that declare a different byte order
  are rejected rather than silently misinterpreted.

### Security

- **Session-Sender reflected-TLV validation order hardened (RFC 8972
  §4-17/18/19, §4.8-16/17).** `validate_reflected_tlvs` (`src/sender.rs`) is
  restructured so a reflected packet's U/M/I flags and its TLV-HMAC
  verification result are all evaluated *before* any TLV value — the
  Micro-session ID used for session binding, the Access Report acknowledgment
  marker, the CoS CE congestion marker — is read for effect: a U-flagged TLV
  is now skipped rather than trusted, an M-flagged TLV halts the scan of the
  remaining TLVs, and any I-flagged TLV or a failed TLV-HMAC closes the
  integrity gate for the whole reflected TLV set. Previously a reflected
  packet could have a forged Micro-session ID (or other TLV value) consumed
  before its own flags/HMAC failure was accounted for. Tests:
  `test_forged_msid_with_{u,m,i}_flag_not_consumed`,
  `test_forged_msid_ignored_when_tlv_hmac_fails` (`src/sender.rs`).

### Added

- **draft-ietf-ippm-stamp-ext-hdr-11: the remaining MUST cluster.**
  `--reflected-ipv6-ext-hdr` and `--reflected-fixed-hdr` are now repeatable
  (`[LEN[:SELECTORHEX]]` per occurrence), emitting one Type-246/Type-247 TLV
  each, in order; the single-flag form and the standalone
  `--reflected-ipv6-ext-hdr-selector`/`--reflected-fixed-hdr-selector` flags
  stay backward compatible. New `--attach-ext-hdr hbh|dest[:HEX]` makes the
  sender attach a real IPv6 Hop-by-Hop or Destination Options header to its
  own egress packets (sticky `IPV6_HOPOPTS`/`IPV6_DSTOPTS`, Linux/macOS) and
  emit the matching request TLV. The reflector's capture walk now traverses
  the full IPv6 extension header chain (Routing, including the Segment
  Routing Header, and the fixed-size Fragment header), terminating cleanly
  with a C-flag at AH/ESP (neither can be reflected), and descends IP-in-IP
  tunnels (protocols 4/41, depth-capped at 4) to capture stacked outer/inner
  fixed headers for multi-TLV Type-247 requests. Both roles are now MTU-aware:
  the sender queries the live route MTU (`IP_MTU`/`IPV6_MTU`, 1280/1500
  fallback) and trims header TLVs tail-first (Type-246 before Type-247,
  BER padding never removed) when the assembled packet would exceed it; the
  reflector trims reflected-header data against `--reflected-control-max-size`
  as its egress-MTU stand-in. The reflector also now enforces §3.3's
  ordering rule: if a Type-246 TLV appears before its Type-247 sibling in the
  packet, every header TLV is returned with the C flag and no data is copied.
- **draft-ietf-ippm-stamp-cos-ecn-01: AIMD congestion response.** New
  `src/rate_control.rs` implements the multiplicative-backoff /
  linear-recovery controller described in §3.4: on a CE-marked reply — either
  the reflected CoS TLV's EC2 field (forward path, integrity-gated the same
  as any other reflected TLV value) or the reply packet's own on-wire ECN
  observed via new `recvmsg`/`IP_RECVTOS`/`IPV6_RECVTCLASS` plumbing on the
  sender socket (reverse path, Linux/macOS) — the sender's inter-packet send
  interval grows by `--ecn-backoff-factor`, capped at `--ecn-max-delay`, and
  decays on clean replies. Active automatically whenever `--cos`+`--ecn`
  request ECT0/ECT1, with no escape hatch, matching the unconditional MUST.
  Non-Linux/macOS platforms log a one-time warning and fall back to
  forward-path-only detection.
- **Layer-2 Address Group sub-TLV filter (draft-ietf-ippm-asymmetrical-pkts-14
  §3.1.1).** The Reflected Test Packet Control TLV's L2 (MAC-based) Address
  Group sub-TLV is now evaluated against the reflector's own local MAC
  addresses, mirroring the existing L3 (IP-prefix) handling: a match replies
  normally, a mismatch drops the packet with no reply. Netns evidence:
  `tests/netns_conformance.rs::scenario_5_address_group_filters`.
- **Access Report retransmission (RFC 8972 §4.6).** The sender now arms a
  retransmission timer whenever it sends a packet carrying the Access Report
  TLV, retransmitting the same TLV up to `--access-report-retries` times
  (default 4) at `--access-report-timeout`-second intervals (default 3s, per
  §4.6-13) until a reflected packet with a recognized, integrity-intact
  Access Report TLV disarms it or the retry budget is exhausted (`Aborted`).
  The timer runs to completion independently of `--count`/`--interval` via a
  post-loop wait-phase extension, so a run shorter than the full retry budget
  still retransmits and aborts correctly rather than reporting `Pending`
  forever. `--access-report` also now rejects an Access ID outside the RFC's
  1-2 registry values (`0` is explicitly invalid per §4.6; 3-15 warn as
  forward-compatible but are accepted on the sender side).
- **RFC 9534 Reflector Micro-session ID validation on the sender.** The
  sender now validates the reflected Reflector Micro-session ID field on
  every reply, not only when `--reflector-member-link-id` is pre-configured:
  absent a pre-known value, the first validly-received reply's Reflector
  Micro-session ID is latched and becomes the expected value for the rest of
  the session (zero-config path); a pre-known value always takes precedence
  and is never overridden. A mismatch on either path discards the packet
  (`TlvRejection::ReflectorMsidMismatch`).
- **`-v`/`--verbose` CLI flag.** Repeatable (`-v`, `-vv`, `-vvv`, ...),
  raising the effective log level from `info` to `debug` to `trace`
  (`resolve_log_filter`); an explicit `RUST_LOG` environment variable always
  takes precedence over the flag at any count.
- **Privileged network-namespace conformance tier.** New
  `tests/netns_conformance.rs` (9 scenarios) exercises on-wire behaviour that
  unit and loopback tests cannot reach — real IP TOS/ECN/TTL marking, IPv6
  extension headers, SRv6 SRH return-path routing (the first live exercise of
  `send_with_srh()`), Address Group filtering, and Type-12 multi-reply
  pacing/count/length — over a pair of Linux network namespaces joined by a
  `veth` link. Every scenario is `#[ignore]`d and additionally gated on
  `STAMP_NETNS_TESTS=1` plus root/`CAP_NET_ADMIN`, so an ordinary `cargo test`
  run never touches the network. Full instructions, prerequisites, and a
  rootless (`unshare -Urn`) path: `doc/testing-netns.md`.
- **Clause-level conformance matrices and a rolled-up compliance statement.**
  `doc/conformance/` now carries an independently re-verified,
  clause-by-clause matrix (quote, RFC-2119 level, role, status, code/test
  evidence) for RFC 8762, RFC 8972 (incl. errata 8199/8339), RFC 9503, RFC
  9534, RFC 8545, and drafts asymmetrical-pkts-14, stamp-cos-ecn-01, and
  stamp-ext-hdr-11 — 368 clauses total. `doc/conformance/README.md` rolls
  these up into a single compliance statement: per-document counts, a
  maintainer-adjudicated list of documented exclusions (SR-MPLS return-path
  forwarding, SNMP SET, STAMP YANG, Windows/macOS platform-tier limits,
  NIC-hardware timestamp verification, SSID-based session admission) versus
  genuinely open Partials/Gaps, the experimental-codepoint disclosure, and a
  summary of this project's verification tiers.
- **Release pipeline hardening: preflight, gated publish, artifacts.** A new
  `release-preflight` CI job runs before packaging or publishing: it checks
  that the git tag, `Cargo.toml`, `CHANGELOG.md`, the Debian changelog, and
  the OpenWrt Makefile all agree on the same version, and dry-run packages
  for crates.io (`cargo publish --dry-run --locked`) to catch manifest/
  packaging errors before any build or test time is spent. Packaging jobs
  now additionally assemble a plain tarball per target (Linux DEB/RPM
  targets and two new macOS targets, `aarch64`/`x86_64-apple-darwin`) and
  crates.io publishing itself is gated behind the preflight and test jobs
  passing.
- **`cargo-deny` CI gate.** New `deny.toml` runs `cargo deny check` in CI
  (advisories, licenses allow-list, duplicate-version/wildcard-dependency
  bans, and a crates.io-only source restriction) across the full
  `--all-features` dependency graph, alongside the existing RustSec
  `audit-check` job (kept side by side deliberately — `audit-check` posts
  inline PR annotations and can open issues for new advisories,
  `cargo-deny` additionally covers licenses/bans/sources and is the one
  command contributors run locally).
- **Best-effort Windows CI test job.** `rust.yml` now also runs the test
  suite on `windows-2022`; the job is explicitly non-gating (a Windows test
  failure is reported but does not block the pipeline), consistent with
  Windows being the `pnet`/libpcap-Npcap fallback tier rather than the
  primary `nix` backend.

### Changed

- **Internal library modules are now `#[doc(hidden)]` (binary-first API).**
  `clock_format`, `configuration`, `crypto`, `error_estimate`, `hwtstamp`,
  `packets`, `rate_control`, `receiver`, `sender`, `session`, `srv6`,
  `stats`, `time`, `tlv`, and the optional `control`/`metrics`/`snmp`
  modules remain `pub` (needed by this crate's own integration tests,
  benches, and fuzz targets) but no longer appear in generated rustdoc; a new
  Stability doc comment on the crate root states plainly that the stable 1.x
  surface is the CLI flags, the config-file schema, and on-the-wire
  behaviour — not these Rust APIs, which are exempt from semver and may
  change in any 1.x release.
- **Experimental/pending-IANA TLV codepoints centralized.** The six
  codepoint stand-ins this implementation uses ahead of IANA allocation —
  the BER Pattern/Count/Max-Burst TLV types (240/241/242,
  draft-gandhi-ippm-stamp-ber), the Reflected IPv6 Extension Header Data and
  Reflected Fixed Header Data TLV types (246/247, TBA1/TBA2 in
  draft-ietf-ippm-stamp-ext-hdr), and the IPv6 Extension Header Control
  sub-TLV type (240 of Type 12, TBA3 in the same draft) — now live as
  individually documented named constants in a new `src/tlv/experimental.rs`
  module, each doc comment stating which draft defines the TLV, the IANA
  action that will trigger renumbering, and that the constant is the single
  edit point. Pure refactor: `TlvType`'s enum discriminants and
  `from_byte`/`to_byte` now reference these constants instead of bare
  literals; on-the-wire behaviour and all existing import paths are
  unchanged. Deliberately no runtime/config override mechanism (YAGNI).

### Fixed

- **`IP_PKTINFO` destination address was byte-reversed on the `nix` backend
  (little-endian hosts).** `ipv4_addr_from_pktinfo` called
  `ipi_addr.s_addr.to_be_bytes()` on a value the kernel already fills in
  network byte order as a raw `u32` — on any little-endian host (effectively
  all x86_64/aarch64 deployments) this silently reversed the octets, so the
  Location TLV's captured destination address (and any other consumer of
  `extract_dst_addr_from_cmsgs`) could report the wrong IP. Changed to
  `to_ne_bytes()`, which copies the underlying byte layout as-is regardless
  of host endianness. Test: `ipv4_pktinfo_extraction_preserves_octet_order`.
- **Reflector replies were silently truncated when a request's trailing
  padding was an all-zero run with no TLVs (RFC 8762 §4.3/§4.6).**
  `TlvList::parse_lenient` correctly drops a trailing all-zero run at a
  4-byte-aligned offset, but the Echo-mode assembly path never re-padded to
  compensate, so e.g. a classic TWAMP-Light packet with 50 zero-octet padding
  and no TLVs came back truncated to base-packet size. Fixed by re-padding
  the reply up to the received length after writing TLVs, skipped only when
  a Reflected Test Packet Control TLV (Type 12) deliberately governs reply
  size. Tests: `test_zero_trailer_reply_preserves_symmetric_size_{unauth,auth}`,
  `test_nonaligned_garbage_trailer_preserves_size_unauth`.
- **Location TLV sub-TLVs used a non-registry wire format, and the reflector
  did not preserve the TLV's own length on echo (RFC 8972 §4.2.1/§4.2.2).**
  Sub-TLVs now use the same 4-octet Flags/Type/Length header as top-level
  TLVs, matching Figure 5 of the RFC instead of a bespoke layout; the
  reflector's update now edits sub-TLV value bytes strictly in place so the
  Location TLV's own wire Length is never resized.
- **Timestamp Information TLV request leaked the sender's own clock into
  reserved fields (RFC 8972 §4.3).** The Session-Sender's request TLV is now
  built via `TimestampInfoTlv::request()`, which zeroes all four value
  octets as the RFC requires ("MUST NOT fill any information fields...
  All other fields MUST be filled with zeroes"); the prior constructor wrote
  the sender's own sync source and timestamp into fields the reflector alone
  is meant to fill.
- **Follow-Up Telemetry TLV was not zeroed in stateless mode, and an
  invalid-length value was not zeroed (RFC 8972 §4.7, erratum 8339).** The
  reflector now zeroes the Sequence Number and Follow-Up Timestamp fields
  when `--stateful-reflector` is off (§4.7-7) and also zeroes them (in
  addition to setting the M flag) when the received TLV's own Length is
  invalid (§4.7-6), instead of leaving stale or attacker-echoed bytes in
  place.
- **Access Report TLV's value size was 2 octets instead of the RFC-mandated
  4, and an invalid Access ID was not discarded (RFC 8972 §4.6-3/§4.6-4).**
  `ACCESS_REPORT_TLV_VALUE_SIZE` is now 4 (ID+Resv, Return Code, and the
  2-octet Reserved tail §4.6 actually specifies); a well-formed Access Report
  TLV whose Access ID is not 1 or 2 is now marked unrecognized (U flag) by
  the reflector via `discard_invalid_access_report_tlvs`, instead of being
  silently accepted.

## [0.8.0] - 2026-05-18

### Added

- **Per-SSID HMAC key set (B6)** — `--hmac-key-dir <DIR>` flag and new
  `crypto::HmacKeySet` type let a single reflector serve multiple
  senders without sharing a key. Each file's name (minus extension) is
  the SSID in hex; an optional `default.key` is the fallback for
  unknown SSIDs. Mutually exclusive with `--hmac-key` /
  `--hmac-key-file`; the legacy single-key path is preserved. The
  reflector peeks the incoming packet's SSID, resolves the per-SSID
  key, and uses it for both verification and response HMAC.
- **Per-client token-bucket rate limiting (B4)** — rewrote `RateLimiter`
  from a fixed-window counter to a true token bucket keyed by
  `(source_ip, ssid)`. New `--reflector-rate-burst` flag tunes bucket
  capacity independently of `--max-pps` (which retains its old
  semantic of "tokens / second"; `burst = 0` falls back to `rate` for
  backward compat). New `packets_rate_limited` counter distinguishes
  rate-limit drops from generic drops in metrics and SNMP. Reflected
  Test Packet Control (Type 12) extra-copy emission consumes one
  token per extra send and breaks the loop early on bucket
  exhaustion, so an asymmetric burst cannot exceed the per-client
  budget.
- **Reflected Test Packet Control Type 12 — draft-14 alignment (A1)** —
  the reflector now honours the requested reply length by inserting an
  `ExtraPaddingTlv` ahead of the HMAC TLV up to a configurable cap;
  parses Layer-3 Address Group sub-TLV (Type 11) and drops the packet
  (via `ReturnPathAction::SuppressReply`) when no local address
  matches the requested prefix per draft §3; parses Layer-2 Address
  Group sub-TLV (Type 10) and sets the U flag on the echoed Type 12
  when MAC visibility isn't available (UDP-socket backends). New
  CLI flags `--reflected-control-max-count`,
  `--reflected-control-max-size`,
  `--reflected-control-min-interval-ns` expose the previously
  compile-time amplification caps as runtime config. Minimum
  value-field size raised from 8 to 12 octets per draft §3; the
  encoder zero-pads short emissions to 12 bytes (placeholder sub-TLV
  header) so existing single-TLV senders stay on the wire.
- **`draft-ietf-ippm-stamp-ext-hdr-08` Type 247 length-mismatch
  conformance (A3)** — the Reflected Fixed Header Data TLV's Length
  MUST equal 20 (IPv4) or 40 (IPv6) per §5.2. If the sender's
  requested Length doesn't match the captured header size (e.g. a
  20-byte request reaches an IPv6 reflector), the reflector now
  zero-fills the Value and sets the U-flag rather than silently
  truncating or padding. New `log_reflected_hdr_length_mismatch_once`
  helper emits a one-time warning citing draft §5.2.
- **Structured logging via `tracing-subscriber` (D5)** — new
  `--log-format text|json` flag selects between the historic
  human-readable single-line output (default) and one-line-per-event
  JSON suitable for Fluent Bit, Vector, or journald JSON forwarding.
  `tracing-log` bridges existing `log::*` call sites so the
  conversion is transparent. `RUST_LOG` continues to control
  verbosity in both modes.
- **`--print-config-schema` for TOML config validation (D4)** — dumps
  a hand-maintained JSON Schema (draft 2020-12) for the
  `FileConfiguration` accepted by `--config`. Pair with the
  `jsonschema` CLI or an IDE plugin for autocomplete /
  pre-deployment validation. Hand-maintained alongside the struct;
  a coverage test fails loudly when a new TOML field has no
  corresponding schema property.
- **Defensive hardware-timestamping scaffold (F1)** — new `hwtstamp`
  Cargo feature (default-off), `--hwtstamp auto|on|off` flag,
  `crypto::HwTsMode` enum, capability probe stub, and
  `effective_method` resolver that picks `HwAssist` vs `SwLocal` per
  direction. `auto` (default) silently falls back to software when
  the kernel/NIC doesn't advertise support; `on` fails-fast at
  startup; `off` always uses software. The kernel-side
  `SO_TIMESTAMPING` / `MSG_ERRQUEUE` wiring is a tracked follow-up;
  the public API is in place so call sites won't change when it
  lands.
- **Capture-thread liveness signal (B2)** — new `capture_alive: Arc<AtomicBool>`
  on `ReceiverSharedState`. Both backends clear the flag when their
  receive loop exits unexpectedly (interface-not-found, channel-init
  failure, send-socket bind failure, `spawn_blocking` panic) so a
  future readiness probe and `systemd`'s `MonitorPolicy` can tell
  "process alive but not reflecting" from "process alive and
  healthy." Every `eprintln!` in the pnet capture path replaced with
  structured `log::error!` / `log::warn!`.
- **AgentX sub-agent panic-resistance (B1)** — audited every
  `unwrap()` / `panic!` / `unreachable!()` reachable from the AgentX
  event loop (`agentx::decode_header`, `decode_oid`,
  `decode_search_range`, `handle_get_bulk`, `MibHandler::get` /
  `get_next`); confirmed every buffer-indexing site is preceded by
  an explicit length check returning `AgentXError::Protocol`. Added
  a supervisor task that observes the `spawn_blocking` JoinHandle so
  an unforeseen panic logs `JoinError::is_panic()` instead of being
  silently dropped. Module-level doc comment in `src/snmp/mod.rs`
  records the audit conclusion so a future reader doesn't redo it.
- **Asymmetric observability failure semantics (B3)** — `--metrics`
  fails fast on bind error with the specific `io::ErrorKind`
  (AddrInUse / AddrNotAvailable / PermissionDenied) in the exit
  message; `--snmp` degrades gracefully on missing AgentX master,
  logs a warning, and continues. Reasoning: silent metrics disable
  leaves dashboards blind; silent SNMP disable doesn't affect the
  reflector's primary duty. Documented in `doc/usage.md`.

### Changed

- **`apply_semantic_tlv_processing` thread the resolved HMAC key** —
  `process_auth_packet` now takes an explicit `resolved_hmac_key`
  parameter set by `process_stamp_packet` after a per-SSID lookup,
  replacing the previous direct read of `ctx.hmac_key`. Required by
  the new `HmacKeySet` path; the single-key path is unchanged because
  the legacy field still feeds `resolve_hmac_key()` when no set is
  configured.
- **`REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE` constant** — added
  alongside the raised-to-12 minimum so the parser can address the
  fixed header (length + count + interval) and the sub-TLV chain
  separately without re-deriving the offset.
- **TLV reference table in `doc/architecture.md`** — adopt
  `supported / partial / experimental / interop-only` labels.
  Type 10 → partial (SR-MPLS / SRv6 echoed with U-flag). Type 12 →
  supported (post-A1). Types 246 / 247 → partial (pnet backend only).
  Type 242 documented as having a wire-format collision with
  teaparty's Heartbeat use of the same byte; both implementations
  are in the experimental range so neither is wrong per IANA, but
  mixed deployments need to pick one.
- **Operational characteristics section** (new in `doc/architecture.md`):
  `--strict-packets` contract, `capture_alive` semantics, metrics
  fail-fast vs SNMP graceful, AgentX panic-audit results, and the
  new `--hwtstamp` modes.

### Fixed

- **RFC 8972 §3 `set_reflected_control_u_flag`** — when a Layer-2
  Address Group sub-TLV arrives on a backend without MAC visibility,
  the reflector now sets the U flag on the echoed Type 12 TLV and
  continues processing. Previously the sub-TLV was silently ignored,
  giving the sender no signal that the filter wasn't honoured.

### Tests

- **Malformed-input suite (C6)** — 12 hand-crafted hostile byte
  sequences across base-packet length boundaries (RFC 8762 §4.1.x),
  TLV-header length-field abuses (overflow, u16::MAX, truncated
  header), HMAC ordering violations (TLV after HMAC, wrong-length
  HMAC value, corrupted digest → I-flag on every TLV per §4.8),
  Return Path sub-TLV nesting overflow, and high-entropy spot
  checks. Implementation handles every case correctly — no
  production change.
- **TLV flag-semantics audit (A7)** — 15 tests pinning the
  RFC 8972 §3 / §4.8 + draft-asymmetrical §3 U/M/I/C wire bit
  positions (0x80 / 0x40 / 0x20 / 0x10), unknown-type echo with U,
  length-mismatch with M, HMAC failure with I on every TLV
  (packet still echoed), Reflected Control clamping with C, plus
  flag-independence negative controls.
- **BER on-wire regression (A4)** — 6 tests covering clean
  channel, single-bit flip, intra-byte 3-bit burst, cross-byte
  4-bit burst (exercises the MSB-first bit walker), sender
  hex-dump verification, and a custom non-default pattern.
- **PTP timestamp end-to-end (A8)** — 6 tests covering wire-encoding
  distinction (NTP-vs-PTP epoch offset), Type 3 TLV
  `sync_src_out` reporting under PTP and NTP reflector modes,
  mixed-mode preservation of sender-declared sync source, and
  big-endian timestamp placement at byte offset 4..12.
- **Stats edge cases (C11)** — 10 tests covering RFC 3550 jitter
  on single-sample / zero-jitter / negative-skew / alternating
  patterns, two-sample std-dev boundary, large-RTT u128 overflow
  safety, percentile of empty set and out-of-range p, single-sample
  percentile off-by-one, and zero-sent loss_percent NaN guard.
- **IPv6 TLV-by-TLV parity (C4)** — 10 tests driving every major
  reflector code path with an IPv6 source: unauth + auth round
  trips, CoS DSCP/ECN echo, RFC 9503 Destination Node Address
  match / mismatch, Micro-session ID, BER trio, Location sub-TLVs,
  combined auth+CoS, unknown-TLV U-flag.
- **Multi-key HMAC integration (B6)** — 6 tests: legacy single-key
  SSID=0 / non-zero compat, per-SSID happy path, wrong-key-for-SSID
  rejection, unknown-SSID + `require_hmac` drop, default-key
  fallback for missing per-SSID entries.
- **pnet backend integration (C10)** — 3 `#[ignore]`'d tests that
  spin up a real pnet receiver on the `lo` interface and round-trip
  open mode, authenticated mode, and a TLV chain. Self-skip when
  the process lacks `CAP_NET_RAW`. Gated by
  `target_os = "linux" + feature = "ttl-pnet" + not ttl-nix`.
  `tests/README.md` documents the privileged-run invocation.
- **AgentX malformed-PDU coverage (C9)** — 8 tests on the public
  decoders + 4 OID-boundary tests on the handler dispatch, locking
  in the B1 audit invariant that every buffer index is bounds-checked.
- **Rate-limit isolation (B4)** — 7 tests: burst exhaustion,
  multi-client isolation (greedy client doesn't drain a polite
  one), per-SSID isolation (same IP, different SSIDs → independent
  buckets), atomic `allow_n`, sustained-rate refill, backward-compat
  burst=0, expired-bucket reaping.
- **`--strict-packets` contract (B7)** — 7 tests pinning the
  lenient-vs-strict asymmetry across short / full / empty buffers
  in both modes, MBZ-always-ignored per RFC 8762 §4.1.1, and
  require_hmac interactions.
- **Property-based + libfuzzer harnesses (C5)** — 16 proptest cases
  (default `cargo test` run) covering typed-TLV round-trips and
  arbitrary-bytes no-panic invariants for every parser. Seven
  cargo-fuzz targets under `fuzz/` (workspace-excluded, nightly-only)
  exercise the same code paths via libfuzzer. New manual /
  weekly GitHub Actions workflow runs each fuzz target for 60s
  and uploads crashes as artifacts.
- **Criterion benchmark suite (E2)** — `benches/reflector_hotpath.rs`
  measures `process_stamp_packet` end-to-end without UDP: open mode
  no-TLV (~100 ns/op), one TLV, full chain, authenticated mode HMAC
  success path, authenticated full chain. Reference numbers in
  `doc/architecture.md` for regression triage.

### CI / build

- **`mib-lint` job** — runs `smilint -l 4` against
  `mibs/STAMP-SUITE-MIB.mib` on every push/PR. Package install
  tries `smitools` (Ubuntu 24.04+) then falls back to
  `libsmi2-bin` for older base images.
- **`fuzz.yml` workflow** — manual / weekly cron; matrix-builds and
  runs each of the seven cargo-fuzz targets for 60s. Failures
  upload `fuzz/artifacts/` + `fuzz/corpus/`.
- **`windows-2022` pin** — Windows test and build-release jobs pin
  to `windows-2022` instead of `windows-latest`. The
  `windows-2025` rollover dropped the bundled tooling that was
  satisfying pnet's load-time `wpcap.dll` / `Packet.dll` imports,
  and the Npcap silent installer hangs on Server 2025 (UAC +
  driver-signing prompts). Long-term answer is to gate pnet behind
  a Cargo feature on Windows.
- **Documentation refresh** — `doc/architecture.md` reorganised
  with a new "Operational Characteristics" section, a Hardware-
  Assisted Timestamping section, a Benchmarks section, and an
  updated TLV table.

## [0.7.0] - 2026-05-04

### Added

- **draft-ietf-ippm-stamp-ext-hdr Reflected Fixed / IPv6 Extension Header Data
  TLVs (Types 247 / 246)**: let the sender ask the reflector to echo the raw
  bytes of the received IP fixed header (Type 247 — 20 B IPv4 or 40 B IPv6)
  and IPv6 Hop-by-Hop / Destination Options extension headers (Type 246),
  which allows end-to-end diagnostics of DSCP remarking, TTL decrement,
  Flow Label rewriting, and in-path tampering with IPv6 options.
  - New typed TLVs `ReflectedFixedHdrTlv` and `ReflectedIpv6ExtHdrTlv`
    implementing `TypedTlv`, plus `TlvType::ReflectedFixedHdr` /
    `ReflectedIpv6ExtHdr` enum variants and length validation that treats
    the Value as variable-length (sender pre-allocates a zero-filled
    Value sized to the expected header length per draft-ietf-ippm-stamp-ext-hdr;
    populated bytes on response).
  - New `CapturedHeaders` struct threaded through `ProcessingContext` so the
    reflector's TLV processing can see the raw IP-layer bytes captured at
    receive time.
  - New `TlvList::process_reflected_headers()` invoked from
    `apply_semantic_tlv_processing` — copies captured bytes into the TLV or
    sets the U-flag when the backend cannot observe the IP layer.
  - `pnet` backend populates `CapturedHeaders` from `Ipv4Packet` / `Ipv6Packet`
    and walks Hop-by-Hop (NextHeader=0) / Destination Options (NextHeader=60)
    in wire format (NextHeader byte + HdrExtLen byte + body, per RFC 8200);
    non-options headers (Routing, Fragment, ESP, AH) stop the walk, matching
    the draft's scope. For IPv4 only the fixed 20-byte header is copied —
    IPv4 options are intentionally dropped.
  - `nix` backend passes `captured_headers: None` unconditionally; the
    reflector echoes the TLV empty with the U-flag set per RFC 8972 §4.2
    and emits a one-time log warning suggesting a rebuild with
    `--features ttl-pnet` if header reflection is genuinely required. An
    empty Value on an IPv4 packet or an IPv6 packet without extension
    headers is legitimate and does **not** set the U-flag.
  - Sender CLI: `--reflected-fixed-hdr`, `--reflected-ipv6-ext-hdr` (plus
    matching `FileConfiguration` TOML fields). Sender attaches a zero-filled
    request TLV sized to the destination's IP family for Type 247 and an
    8-byte default (one option's worth) for Type 246; reflector fills them
    on the pnet backend or U-flags them on nix.

### Fixed

- **RFC 8972 §4.4.1 sender flag default**: `TlvFlags::for_sender()` now
  returns `U=1, M=0, I=0` instead of all-zero. The RFC requires the
  Session-Sender to send every TLV with the U flag set; the reflector then
  overwrites it. Sender-built TLVs (`RawTlv::new`) inherit the corrected
  default. Visible on the wire as the leading flag byte of every outgoing
  TLV flipping from `0x00` to `0x80`.
- **RFC 8972 §4.4.1 reflector flag overwrite**: the reflector now clears
  U, M, and I on every parsed TLV before the type-recognition / length-
  validation / HMAC-verification pass re-derives them. Previously each
  flag was only ever set to 1; the RFC's three "Otherwise … MUST set …
  to 0" clauses require them to be cleared as well. Practically: an
  echoed CoS TLV (or any other recognized type) now reports `U=0` to the
  sender even when the sender obeyed the §4.4.1 mandate to send `U=1`.
  The C-flag (`conformant_reflected`, draft-ietf-ippm-asymmetrical-pkts)
  and parser-detected truncation M-flag are preserved across the clear.
- **draft-ietf-ippm-stamp-ext-hdr Type 246 / 247 sender request encoding**:
  Session-Sender now pre-allocates the Value field with zeros sized to the
  expected header length (20 for IPv4 fixed header, 40 for IPv6 fixed
  header, 8-byte capacity for IPv6 ext-header chain) per the draft.
  Previously sent length=0; conforming reflectors that validate the
  request's Length field rejected it as malformed.

### Changed

- **Shared `build_local_addresses` between backends**: the interface-address
  enumeration used for Destination Node Address TLV matching (RFC 9503 §4)
  was duplicated in `receiver/nix.rs` and `receiver/pnet.rs` with platform-
  specific implementations. Consolidated into a single
  `receiver::build_local_addresses()` with `cfg(unix)` / `cfg(not(unix))`
  internals — `nix::ifaddrs::getifaddrs` on Unix, `pnet::datalink::interfaces`
  on Windows. Removes ~60 lines of near-duplicate code and a class of
  drift bugs.
- `--micro-session-id` and `--reflector-member-link-id` (RFC 9534 LAG
  identifiers) now accept `0x`-prefixed hex (`0xff`, `0XFF`, `0x00ab`)
  in addition to decimal. Aligns with the conventional way these wire
  fields are written.

### Breaking

- `ReflectedFixedHdrTlv::request()` removed; replaced by
  `ReflectedFixedHdrTlv::request_for(IpAddr)` (chooses 20 / 40 bytes from
  the destination address family) or
  `ReflectedFixedHdrTlv::request_with_capacity(usize)` (explicit zero-fill
  size). The old API produced an empty-Value TLV that did not match the
  draft's request format.
- `ReflectedIpv6ExtHdrTlv::request()` removed; replaced by
  `ReflectedIpv6ExtHdrTlv::request_with_capacity(usize)` so the caller
  picks the zero-filled Value size to match the path's expected
  extension-header chain. The default size for the sender flag
  (`--reflected-ipv6-ext-hdr`) is exposed as
  `tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY` (8 bytes — one option).
- Reflector behavior change: when populating Type 246 / 247 responses,
  the reflector now preserves the sender-advertised Length, zero-padding
  short captures and truncating long ones. Callers that depended on the
  response length matching the captured-bytes length should size the
  request appropriately.

### Documentation

- README gained a **Receiver Backends** section explaining the two capture
  paths (nix UDP socket + cmsg vs pnet datalink capture), why `nix` stays
  the default on Linux/macOS (unprivileged execution, no libpcap runtime
  dependency, kernel-side UDP demultiplex, firewall integration, kernel-
  handled checksums / fragmentation / ARP, socket observability), and what
  the tradeoff is (TLV 246/247 only on the pnet backend; two capture loops
  to maintain).
- **README split** into a slim landing page (~200 lines) and three deep
  references under `doc/`:
  - `doc/usage.md` — TOML configuration file format, supported keys,
    validation behavior, and the full grouped CLI flag reference.
  - `doc/architecture.md` — module layout, receiver backends, packet
    processing pipeline, session management, full TLV reference,
    Prometheus and SNMP subsystems.
  - `doc/security.md` — threat model, HMAC and TLV integrity, key
    sourcing precedence (with the `STAMP_HMAC_KEY` + `hmac_key_file`
    mutual-exclusion caveat), config and key file permissions, the
    `stamp` system user, an annotated walkthrough of the systemd unit's
    hardening directives, the capability model, and a step-by-step
    procedure for switching the packaged systemd unit from open to
    authenticated mode before exposing UDP/862. Top-level `SECURITY.md`
    pointer added for GitHub auto-discovery.
- Cargo packaging (`cargo deb` / `cargo generate-rpm`) ships the three
  new docs at `/usr/share/doc/stamp-suite/` alongside `README.md`.

## [0.6.0] - 2026-04-22

### Added

- **TOML configuration file support** (`--config <PATH>`): every CLI option can
  be supplied through a TOML file so long-lived deployments (systemd units,
  reflectors, reproducible test rigs) no longer need sprawling command lines.
  - New `FileConfiguration` struct mirrors `Configuration` with all fields
    optional; unknown keys are rejected at parse time (`deny_unknown_fields`)
    so typos surface with the full list of valid keys.
  - Precedence: command-line flag / `STAMP_HMAC_KEY` env var > TOML file
    value > hardcoded default. Detected via `clap::ArgMatches::value_source`
    so the same `Configuration` struct serves both sources.
  - New `Configuration::load()` entry point parses CLI, merges the optional
    TOML file, then runs `validate()`. `main.rs` uses it in place of
    `Configuration::parse()`.
  - Plaintext `hmac_key` is deliberately absent from the file schema; only
    `hmac_key_file` is accepted, so secrets cannot leak into a shared config.
  - On Unix, a warning is logged if the config file is writable by group or
    other (mask `0o022`) — mirrors the existing check on `--hmac-key-file`.
  - Range checks for `dscp` (0-63), `ecn` (0-3), `access_report` (0-15),
    `micro_session_id` (>=1), `reflector_member_link_id` (>=1) were added to
    `Configuration::validate()` since clap's CLI-side `value_parser!().range()`
    does not run on values deserialized from TOML.
  - New dependency: `toml = "0.9"`; dev-dependency: `tempfile = "3"`.
  - `AuthMode`, `ClockFormat`, `TlvHandlingMode`, and `OutputFormat` gained
    `serde::Deserialize` derives with renames matching the existing
    `ValueEnum` string forms.

- **draft-ietf-ippm-asymmetrical-pkts Reflected Test Packet Control TLV (Type 12)**:
  asymmetrical reply measurement
  - `ReflectedControlTlv` struct (Length / Count / Interval + opaque sub-TLV bytes)
  - Reflector emits up to `REFLECTED_CONTROL_MAX_COUNT` (16) reply packets per
    request, spaced by the requested interval (clamped to
    `REFLECTED_CONTROL_MIN_INTERVAL_NS` of 1 µs). Excess count, clamped interval,
    or any non-zero requested length sets the new Conformant (C) flag on the
    echoed TLV.
  - nix backend emits extra copies on a spawned tokio task so the recv loop is
    not blocked; pnet backend sleeps inline (fallback platforms only).
  - New C-flag bit (0x10) added to `TlvFlags` and `RawTlv::set_conformant_reflected()`.
    The draft leaves the C bit position TBA; we place it at bit 3, the first bit
    unused by RFC 8972's U/M/I triple.
  - Sender CLI: `--reflected-control-count`, `--reflected-control-length`,
    `--reflected-control-interval-ns`.
- **draft-gandhi-ippm-stamp-ber BER TLVs**:
  - Bit Pattern in Padding (Type 240), Bit Error Count in Padding (Type 241),
    Max Bit Error Burst Size (Type 242). Type numbers are TBD in the draft;
    240/241/242 from RFC 8972's experimental range.
  - Reflector XORs the received Extra Padding against the Bit Pattern TLV (or
    the draft's 0xFF00 default), counts error bits and longest consecutive run
    across byte boundaries, and writes the results into the Count and Max Burst
    TLVs.
  - Missing Extra Padding or duplicate BER TLVs mark all BER TLVs with the
    U-flag per draft §3.
  - Sender CLI: `--ber`, `--ber-pattern <HEX>`, `--ber-padding-size`.

- **RFC 9534 Micro-session ID TLV**: Per-member-link performance measurement on LAGs
  - Micro-session ID TLV (Type 11) with sender and reflector member link identifiers
  - `--micro-session-id <ID>` sender CLI option to identify the local LAG member link
  - `--reflector-member-link-id <ID>` reflector CLI option to fill in reflector-side member link ID
  - Reflector validates non-zero reflector ID in received TLV (discards on mismatch per RFC 9534 §3.2)
  - Full `MicroSessionIdTlv` struct with `new`/`from_raw`/`to_raw` and `TlvList::update_micro_session_id_tlvs()`
- `SenderSnmpStats::inc_lost_by(count)` for batched loss counter updates
- `record_packets_lost(count)` batch metrics API for sender loss events

### Fixed

- AgentX OID decode (`decode_oid`) now requires 8 bytes minimum instead of 4, preventing panic when reading `prefix`/`include` fields from short buffers
- AgentX OID decode uses `checked_mul`/`checked_add` for expected buffer length to prevent overflow on 32-bit targets with crafted wire data
- Sender interim report (`--report-interval`) now uses confirmed `packets_lost` counter instead of `pending.len()`, which incorrectly counted in-flight packets as lost
- SNMP `loss_pct_x100` is now computed on read instead of cached, preventing stale values when `packets_sent` increases without corresponding loss events

- Sender timeout eviction replaced O(n) full HashMap scan with O(k) `VecDeque`-based lazy eviction queue; deadlines are naturally time-ordered since packets are sent sequentially
- Final sender loss accounting uses batched `inc_lost_by()` and `record_packets_lost()` instead of per-packet loops
- Reflector TLV semantic processing (CoS, Timestamp Info, Direct Measurement, Location, Follow-Up Telemetry, Destination Node Address, Micro-session ID, Return Path, HMAC recomputation) extracted into shared `apply_semantic_tlv_processing()` helper, eliminating duplication between `assemble_unauth_answer_with_tlvs` and `assemble_auth_answer_with_tlvs`
- `TlvList::validate_known_tlv_lengths()` refactored to use shared `validate_known_tlv_lengths_slice()` helper operating on both `tlvs` and `wire_order_tlvs`
- `TlvList::update_micro_session_id_tlvs()` uses shared `apply_micro_session_id()` helper for both TLV vectors

### Removed

- `SenderStatsSnapshot` struct and `SenderSnmpStats::update_from_snapshot()` — all sender SNMP counters are now updated live; the final-snapshot path was dead code

## [0.5.0] - 2026-02-13

### Added

- **SNMP AgentX Sub-Agent**: MIB-based monitoring via net-snmpd (requires `snmp` feature, Unix only)
  - Minimal AgentX protocol implementation (RFC 2741) with no external SNMP crate dependency
  - STAMP-SUITE-MIB under enterprise OID `.1.3.6.1.4.1.65134` with SMIv2 definition (`mibs/STAMP-SUITE-MIB.mib`)
  - Reflector subtree: configuration scalars, packet counters (received/reflected/dropped), active session count, uptime
  - Session table: per-client address, port, packet counts, last sequence number, last active time
  - Sender subtree: configuration scalars, packets sent/received/lost, RTT min/max/avg, jitter, loss percentage
  - Live sender statistics updated in the hot path (received, RTT min/max/avg, jitter) — SNMP polling during long runs reflects current progress
  - `--snmp` and `--snmp-socket <PATH>` CLI options
- `SessionManager::session_summaries_extended()` for retrieving per-session state
- `ReceiverSharedState` struct for sharing counters and session manager between receiver backends and SNMP

### Fixed

- pnet backend no longer drops valid fallback responses for Return-Path alternate IPv6 targets; the early-return gate that bypassed the try_send + U-flag fallback path has been removed
- `snmp` feature is now platform-gated with `cfg(unix)` — on non-Unix platforms, `--snmp` prints a clear error and exits instead of failing to compile

### Changed

- Receiver backends (`nix.rs`, `pnet.rs`) now accept `&ReceiverSharedState` instead of creating their own `Arc<ReflectorCounters>` and `Arc<SessionManager>` internally
- `run_sender` accepts an optional `Arc<SenderSnmpStats>` (behind `snmp` feature gate) for live statistics export

## [0.4.0] - 2026-02-11

### Added

- **RFC 9503 Segment Routing Extensions**: STAMP extensions for SR-MPLS and SRv6 networks
  - Destination Node Address TLV (Type 9): sender specifies intended reflector address; reflector sets U-flag on mismatch
  - Return Path TLV (Type 10) with sub-TLV support:
    - Control Code sub-TLV: suppress reply (code 0) or request same-link reply (code 1); reserved bits ignored per RFC 9503
    - Return Address sub-TLV: reflector sends reply to an alternate IP address
    - SR-MPLS Label Stack sub-TLV: proper MPLS LSE encoding (Label/TC/S/TTL); echoed with U-flag (userspace SR forwarding unsupported)
    - SRv6 Segment List sub-TLV: echoed with U-flag (userspace SR forwarding unsupported)
  - `--dest-node-addr <IP>` sender CLI option (requires `--ssid`)
  - `--return-path-cc <CODE>` sender CLI option (0=suppress, 1=same-link)
  - `--return-address <IP>` sender CLI option for alternate reply address
  - `--return-sr-mpls-labels <LABELS>` sender CLI option (comma-separated 20-bit labels)
  - `--return-srv6-sids <SIDS>` sender CLI option (comma-separated IPv6 SIDs)
- Alternate-address send failure fallback: on failure, reflector sets U-flag on Return Path TLV, recomputes HMAC, and retries to original source address
- Local address enumeration for Destination Node Address matching (nix: `getifaddrs`, pnet: `datalink::interfaces`)

### Fixed

- SR-MPLS labels are now encoded as proper MPLS Label Stack Entries (Label<<12 | TC | S-bit | TTL) instead of raw u32 values
- Return Path Control Code decoding uses `cc & 1` bit masking instead of rejecting reserved bits, per RFC 9503
- `--return-sr-mpls-labels` and `--return-srv6-sids` now correctly conflict with each other at the CLI level

### Changed

- `ProcessingContext.local_addresses` changed from `Vec<IpAddr>` to `&[IpAddr]` to avoid per-packet cloning in hot path

## [0.3.1] - 2026-02-08

### Changed

- Multiple optimizations and refactorings.

## [0.3.0] - 2026-02-08

### Added

- **RFC 8972 TLV Extension Support**: Full implementation of Type-Length-Value extensions
  - New `tlv` module with `TlvFlags`, `TlvType`, `RawTlv`, `TlvList`, `ExtraPaddingTlv`, `HmacTlv`, and `SessionSenderId` types
  - TLV handling modes: `ignore` (strip TLVs) and `echo` (reflect TLVs with appropriate flags)
  - `--tlv-mode` CLI option to control TLV handling behavior (default: `echo`)
  - `--verify-tlv-hmac` CLI option to verify incoming TLV HMAC
  - `--ssid` CLI option for sender to include Session-Sender Identifier in Extra Padding TLV
  - HMAC TLV (Type 8) support for TLV integrity verification
  - Proper flag handling: U-flag for unrecognized types, M-flag for malformed TLVs, I-flag for integrity failures
- Extended packet types: `ExtendedPacketAuthenticated`, `ExtendedPacketUnauthenticated`, and their reflected variants
- Lenient packet parsing with `from_bytes_lenient()` methods for short-packet interoperability (RFC 8762 Section 4.6)
- Canonical buffer support for HMAC verification of zero-padded short packets
- Wire-order preservation for TLV failure echo paths per RFC 8972 Section 4.8
- Truncated TLV byte-exact echo: preserves original wire length in header for malformed TLVs
- Sender-side TLV validation with `validate_reflected_tlvs()` helper
- Configuration validation: `--verify-tlv-hmac` now requires `--hmac-key` or `--hmac-key-file`

### Changed

- **Breaking**: `auth_mode` now only accepts exactly `A` (authenticated) or `O` (open/unauthenticated)
  - Composite strings like `AO` are no longer valid (modes are mutually exclusive per RFC 8762)
  - `is_auth()` and `is_open()` now use exact string matching instead of substring search
- Receiver assembly functions updated to handle TLV extensions
- Both `nix` and `pnet` receiver backends updated for TLV-aware packet processing
- HMAC verification in authenticated mode now uses canonical zero-padded buffers

### Fixed

- Sender TLV-HMAC validation now uses fixed base offset (44/112 bytes) instead of fragile inference from packet length
- Short authenticated packets are now properly zero-filled before HMAC verification
- Malformed TLVs are echoed byte-exactly with original declared length preserved

### Removed

- Removed unsupported `process` TLV handling mode from documentation
- Removed `E` (encrypted) auth mode option (not defined in RFC 8762)

## [0.2.0] - 2024-12-01

### Added

- Multi-session support in reflector with `SessionManager`
- Stateful reflector mode (`--stateful-reflector`) per RFC 8972
- Session timeout configuration (`--session-timeout`)
- HMAC authentication support with `--hmac-key` and `--hmac-key-file` options
- `--require-hmac` option to mandate HMAC verification
- Error estimate configuration (`--error-scale`, `--error-multiplier`, `--clock-synchronized`)
- Integration tests using loopback interface
- RFC 8762 compatibility improvements

### Changed

- Improved packet serialization using big-endian encoding
- Enhanced error handling throughout the codebase

## [0.1.0] - 2024-01-01

### Added

- Initial implementation of STAMP protocol (RFC 8762)
- Session-Sender and Session-Reflector modes
- Unauthenticated and authenticated packet formats
- NTP and PTP timestamp support
- IPv4 and IPv6 support
- Basic RTT and packet loss statistics
- CLI interface with clap
