# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A sender can measure several reflectors at once: repeat `--remote-addr` or
  give a comma-separated list (a string or an array in TOML). Each target runs
  its own session concurrently, and reports carry a `target` label.
- `--count 0` sends until `--duration` ends or the sender is interrupted, and
  `--count` accepts values up to 2^32 - 1. `--duration SECONDS` limits a run by
  time. Before this change, `--count 0` sent nothing and reported success.
- `--send-delay` accepts units (`250us`, `1.5ms`, `2s`; a plain number is
  milliseconds) and intervals below 1 ms, which are busy-waited for exact
  spacing. On loopback, 100 µs gives 30,000 probes in 3 s.
- `--send-schedule poisson` spaces probes with exponential gaps
  (RFC 2330 §11.1.1).
- `--interface NAME` binds the sender, the nix reflector and the pnet reply
  sockets to a device or VRF. The pnet backend also captures on it.
- A sender stops on Ctrl-C or SIGTERM and prints the statistics collected so
  far. It used to exit without a summary.
- SIGHUP reloads the reflector's HMAC keys from the configured key file or
  directory. It used to terminate the process.
- The nix reflector on Linux reflects IPv6 extension headers (Type 246) from
  ancillary data (`IPV6_RECVHOPOPTS`, `IPV6_RECVDSTOPTS`, `IPV6_RECVRTHDR`),
  without raw capture. Fixed headers (Type 247) still need the pnet backend.
- `--session-admission provisioned` answers only the exact session identities
  listed with `--reflector-session`. Permissive admission, which learns
  incoming sessions, is the default.
- `--reflector-queue-capacity` (default 1024) bounds reflector work across
  processing, capture handoff and queued burst copies.
  `--reflector-shutdown-grace-ms` sets an optional shutdown grace period; the
  default cancels immediately. The reflector handles SIGTERM, polls promptly
  when the pnet capture is idle, uses nonblocking reply sockets and cleans up
  the workers it owns. Reflector summaries and control status report queue
  rejections and cancelled copies, and the reflector CSV gains two columns.
  Overload, recovery and shutdown regression tests cover this.
- The sender reports reply copies, duplicates, late replies and reordering
  (with bounded storage), directional Direct Measurement windows and Follow-Up
  reverse-delay summaries. They appear as `measurements` in JSON and text
  output and as sender CSV column 28; probe and BER summary semantics are
  unchanged. The sender drains requested burst copies within the final timeout.
  Tests cover independent IPv4/open and IPv6/authenticated peers, and the
  documentation describes the limits.
- The sender reports idle, active and failed session states, with validated
  recovery, structured logs and a `measurements.session_state` summary field.
  `--session-loss-threshold` sets how many consecutive unanswered probes mark a
  session failed.
- Sender output shows the endpoints' synchronization declarations, the decoded
  advertised clock errors and counts of invalid or unknown clock quality next
  to the OWD and Follow-Up delays. They are sender CSV column 29,
  `owd_clock_quality`. Existing delay samples are unchanged.
- IPv6 link-local addresses work in both backends: source and destination
  zones are preserved through session lookup and replies, and
  `--local-scope-id` and `--remote-scope-id` set numeric zones. Isolated tests
  cover link-local bursts, alternate addresses and the sender.
- `--help` and the man page group options into sections (Endpoints, Sender,
  Authentication, Reflector, and so on).
- The DEB, RPM and Debian packaging ship a generated man page
  (`dist/man/stamp-suite.1`, kept in sync by `tests/man_page.rs`). Each release
  publishes a source tarball, a `cargo vendor` tarball and Sigstore build
  provenance, plus an optional GPG-signed `SHA256SUMS`, so distribution
  packagers have stable, verifiable inputs.
- A Gentoo overlay tree under `dist/gentoo/` provides `net-analyzer/stamp-suite`
  with a USE flag per Cargo feature, OpenRC service files, and `acct-user` and
  `acct-group` packages.
- A Linux live UDP benchmark (`live_udp_bench`) sends paced traffic, validates
  reply and loss accounting, samples CPU under load and when idle, sends probes
  after the idle period, repeats trials and records reproducibility metadata.
  It covers IPv4 and IPv6, open and authenticated modes, and stateful baseline
  workloads, and accepts `--hwtstamp` and `--metrics`. The Criterion suite has
  a stateful case with a populated session table. The documentation describes
  the generator's limits, and unsourced speed figures were removed.
- A weekly standards revision monitor checks for new revisions of the
  implemented documents, with offline replay and failure reporting.
- Release test fixtures cover bearer-authenticated HTTP and HTTPS key rotation
  with live packets and a real Net-SNMP master, including bulk queries and
  reconnects. A documented hardware timestamp verification procedure has
  explicit unavailable and fallback outcomes.
- Independent Python wire fixtures cover key-directory bursts, CoS, source
  matching, SRv6 fallback and mixed clocks, with frozen payloads and JSON
  evidence. CI runs them for default and all-features builds and checks the
  oracle against corrupted replies.

### Changed

- The documentation was rewritten against the code. `doc/usage.md` is
  reorganized by task (configuration file, sender, reflector, authentication,
  timestamps, networking, observability); each topic has one home and other
  pages link to it. New pages: `CONTRIBUTING.md` and `doc/protocol.md` (a
  STAMP overview and glossary). The conformance matrices share one layout,
  and the AgentX and ext-hdr revision-13 review records were folded into
  `doc/architecture.md` and the ext-hdr matrix. `tests/README.md` lists every
  test file.
- **Breaking for Type 246:** IPv6 header reflection follows
  draft-ietf-ippm-stamp-ext-hdr-15. The move from -11 to -13 introduced
  eight-octet Type 246 selectors, strict request and attachment validation,
  sender route-MTU checks, and checksum verification before raw-capture
  admission. Type 247 keeps four-octet selectors. This changes the
  experimental Type 246 wire format, so upgrade both peers together. Revision
  -15 does not change the wire format or procedures from -13; citations use
  the -15 section numbers, and the conformance matrix adds the new data-plane
  and measurement-type provisioning requirements as Partial rows.
- draft-ietf-ippm-asymmetrical-pkts was published as RFC 10052. Codepoints are
  unchanged; citations, the conformance matrix and the standards monitor refer
  to the RFC.
- BER support follows draft-gandhi-ippm-stamp-ber-07. Pattern alignment is
  validated, invalid combinations get C, and padding is repaired and kept
  outside TLV-HMAC coverage. The sender reports directional interval
  statistics, burst aggregates and optional threshold alarms (`--ber-interval`,
  `--ber-bit-threshold`, `--ber-packet-threshold`, also in TOML and the schema)
  in text, JSON and CSV output, and stops BER measurement when the peer
  reports it unsupported. On Linux, route-MTU budgets apply to BER padding, and resized replies are
  rejected as measurement inputs. Wire, integrity, interval and IPv4/IPv6
  regression tests and a BER conformance matrix cover this.
- Reflector synchronization-source declarations are separate from the NTP/PTP
  timestamp format and the Error Estimate S bit. `--clock-sync-source` (system
  clock) and `--hardware-clock-sync-source` (PHC) default to `local`. The
  RFC 8972 wire codes are corrected: SSU/BITS is 3, external sources 4, local
  5. Type 3 reports software timestamping for the current T3, and Follow-Up
  records the method of the timestamp actually stored, including software
  fallback and later hardware corrections. Timestamp and method snapshots stay
  coherent, and unrelated error-queue events are rejected. The CLI, TOML,
  schema, `ProcessingContext` callers, documentation and wire tests are
  updated.
- The sender uses a randomized dynamic source port by default, sender and
  reflector ports must differ, and both endpoints transmit with TTL/Hop Limit
  255. Lower configured TTL values are rejected; lower received values are
  still accepted.
- Reflector sequences, counters, replay windows and Follow-Up state are kept
  per session identity: both UDP endpoints, the SSID and the sender
  micro-session ID. Control and shutdown output report the complete identity,
  and control expiry requires disambiguation when one source has several
  sessions.
- At the session limit or during drain, the reflector rejects new session
  identities. It used to reply with temporary counters and a stateful sequence
  number that stayed at zero. Existing sessions are kept when the limit
  shrinks, admission is serialized with runtime control changes, and expiry
  retires pending transmissions before an identity restarts.
- On Linux the reflector enforces the actual reply-route MTU for Type 12 and
  reflected-header replies, including wildcard binds, alternate destinations
  and SRH overhead. MTU caches are bounded and invalidated on route and
  interface changes, replies are never fragmented, an MTU race is retried
  once, and signatures are regenerated after resizing. Replies whose mandatory
  fields cannot fit, or whose route budget is unavailable, are dropped. Runtime
  caps report administrative limits. Route MTU lookup is Linux-only.
- A non-monotonic Type 12 request gets one U-flagged reply in both reflector
  backends. Burst handling after sequence wraparound is unchanged, requested
  padding is skipped on ordering failures, and the final HMACs cover the flags.
  This response is required by the draft and stays active with
  `--drop-replayed`; ordinary duplicate suppression is configurable.
- With configured sender micro-sessions, a reply must carry exactly one usable
  Micro-session ID. Missing, flagged, malformed, duplicate or unverifiable IDs
  are rejected before measurements are consumed, and the reflector ID is
  learned only from accepted pending replies. Numeric TLV validation does not
  implement physical LAG steering or ingress-member verification.
- Diagnostics go to stderr in both log formats, and `-R` packet details go to
  stderr when JSON or CSV measurement output is selected. Reflector startup
  notices are logged, and periodic and final sender reports share one CSV
  header. CLI stream regression tests cover this, and the documentation
  describes the output streams and library reporting state.
- Sender RTT and OWD storage is bounded: quantiles are exact through 4096
  observations, then come from full-run histograms with less than 0.78125%
  magnitude error. Each snapshot sorts or traverses the RTT data once, and
  cumulative moments and 64-bit sample counts are kept. Variance uses centered
  online updates, which fixes overflow and cancellation. Text and JSON output
  state the precision, and two sender CSV columns before `ber` carry it.
- The sender keeps at most 1024 completed BER intervals and 1024 alarms, with
  omission counters and the current partial interval. Lifetime totals and
  alarm logs are preserved. Full-range, long-run, accuracy and output
  regression tests cover this. The documentation describes retention and
  corrects the RTT jitter metric's inaccurate RFC 3550 attribution.
- The minimum supported Rust version is 1.85 (was 1.93), so the crate builds
  with the rustc shipped by Debian trixie. The only dependency that had to
  change was `criterion` (0.8 to 0.5, dev-only). The container builder image is
  pinned to the MSRV (`rust:1.85-slim-bookworm`, runtime `debian:bookworm-slim`).

**Performance**

- Probe TLVs are written directly into the packet buffer instead of being
  copied into a list and serialized; the static TLVs (including BER padding)
  are no longer cloned per probe, and the authenticated base packet is
  serialized once.

Measured with `live_udp_bench` on loopback (Intel Core Ultra 9 275HX, WSL2),
median of three trials, reflector CPU as a share of one core:

| Load | Before | After |
| --- | --- | --- |
| 50 kpps open | 23.0% | 18.7% |
| 50 kpps authenticated, stateful | 25.7% | 20.3% |
| 200 kpps open | 84.7%, 1.6% loss | 62.0%, no loss |
| 200 kpps authenticated, stateful | 95.0%, 1.3% loss | 73.7%, 0.005% loss |
| 50 kpps open, `--hwtstamp auto` | 28.7% | 22.3% |

- The nix reflector sends the first copy of each reply as soon as it is built;
  only later burst copies wait in the deadline queue. It handles up to 32
  datagrams per readiness wakeup.
- The reflector socket requests a 4 MiB receive buffer (capped by
  `net.core.rmem_max`). The default absorbed about a millisecond of traffic at
  200 kpps.
- Kernel TX-timestamp error queues are read only while a send awaits its
  timestamp, instead of on every loop iteration.
- Known sessions are looked up under the session table's read lock.
  Authenticated session acquisition carries one provisioning decision through,
  uses one table entry lookup for existing and new sessions, keeps the limit
  and drain checks under the write lock, and reuses the acquired handle for
  standalone sequencing and live transmission. Operation-count and
  admission-race regression tests cover this.
- `HmacKey` holds the keyed HMAC state and shares it between clones, so the
  key schedule is computed once and a reply's signing key is a reference
  count, not a copy. The state is wiped when the last clone is dropped, and the
  raw key bytes are not retained.
- Ancillary data for each send is built on the stack, and the last copy of a
  reply reuses its buffer. TLV error metrics are recorded once per packet with
  static labels, and only when metrics are enabled.
- Prometheus handles for per-packet metrics are looked up once. At 200 kpps
  `--metrics` cost about 7% of a core in registry lookups; with cached handles
  the reflector's CPU use is close to running without metrics.
  `live_udp_bench --metrics` measures it.
- Reflector transport metadata and SRH storage are reused across burst copies.
  Both backends send through one mutable sender per socket, cache successful
  PMTU and CoS settings, and reuse bound endpoints for route lookups. Fallback
  changes stay local to each copy, and incomplete sends are rejected without
  being counted. Socket-isolation and cache regression tests cover this, and
  the ownership contract is documented.
- Each parsed TLV is stored once, with indices that preserve the wire order of
  malformed TLVs and of legal HMAC and padding TLVs. Mirrored semantic updates
  are gone, flag and length validation is shared, BER patterns are borrowed,
  and HMAC input is streamed without concatenation. Reply capacity is reserved
  before serialization. Duplicate-HMAC partitioning stays linear, and property
  tests cover malformed tails, mutation and signing.
- BER bit-error and burst counting processes a byte at a time with a lookup
  table instead of a bit at a time, about 8× faster on 1400-byte padding.
- Interim reports are formatted and written on a separate thread instead of
  inside the sender's send and receive loop. With `--ber` and a full interval
  history, an interim report held up the loop for 0.3 to 0.8 ms even with
  stdout redirected to `/dev/null`, which delayed probes and inflated the RTT
  of replies arriving meanwhile. The loop now pauses only for the snapshot,
  0.06 to 0.2 ms. With several targets, reports no longer wait for each other
  behind a lock.
- The sender verifies a reply's TLV HMAC once, and BER sampling reuses that
  result. The receive control-message buffer is allocated once per run, and the
  wall clock is read once per reply.

**Internal**

- `src/receiver/mod.rs` and `src/sender.rs` are split into focused modules,
  and large inline test modules moved into `tests.rs` files next to the code.
  Behavior is unchanged.
- The sender loop moved from one 1300-line function into `sender/run.rs`:
  `SenderRun::open` does setup, and the send, drain and Access Report phases
  share one receive helper.
- Both reflector backends share one ingest path (`receiver/ingest.rs`).
  Settings are resolved once at startup, and each datagram goes through the
  same rate limit, queue reservation, processing and reply construction. This
  replaces two hand-maintained context literals of about 70 lines per packet.
- Serialized replies are inspected through `tlv::TlvSpan` instead of seven
  hand-written byte walkers with literal type codes and flag masks, so
  codepoint changes in `tlv` reach the send path. Two of those walkers
  allocated a parsed TLV list per reply.
- Packet layout constants (base sizes, HMAC and SSID offsets) are defined once
  in `packets.rs`.
- `ReceiverSharedState::capture_alive` is removed. Nothing outside tests read
  it, and every path that cleared it ended the process.
- Each base packet's field layout is declared once with the `wire_packet!`
  macro, which generates the struct, `to_bytes`, `from_bytes` and the lenient
  parsers, and fails the build if the field offsets leave a gap or overlap.
  The four `Extended*` packet types are aliases of one generic
  `Extended<B: BasePacket>`, whose `from_bytes_lenient` returns the zero-filled
  base packet with the parsed packet. `PacketAuthenticated`'s
  `mbz1a`/`mbz1b`/`mbz1c` fields are one `mbz1: [u8; 68]`. Decoding of 2000
  random buffers was compared before and after and is identical.
- Thirteen per-TLV length errors are one `TlvError::InvalidLength { kind,
  length }`, and the expected length comes from one table. Fixed and IPv6
  extension header reflection share one matching function, and Location
  sub-TLVs use the shared `TlvSpan` header reader.
- `StartupError` is an enum (`Config`, `Io`, `Key`, `Service`) that keeps the
  underlying error, and `HmacError` keeps its `io::Error` and hex errors. Key
  loading moved from `receiver` to `crypto::KeySource`, and
  `create_shared_state` returns a `Result`.
- One `CancellationToken` carries shutdown: signals and the control API cancel
  it, and the reflector backends, the sender and the SNMP sub-agent observe
  it. The nix reflector does not poll a flag every 250 ms any more.
  `tokio-util` is a required dependency.
- Sender metrics and SNMP counters are `SenderObserver` implementations
  instead of feature-gated calls throughout the send and receive paths.
  `run_sender(conf)` and `run_sender_with_output(conf, output, observers,
  shutdown)` replace the feature-dependent signatures. The unused RTT min/max
  gauge helpers are removed.
- `Configuration::remote_addr` is a list; `remote_ip()` and `per_target()` give
  the single-target view. `sender::run_senders` runs every target,
  `StatsOutput` clones share one stream, and `StatsSnapshot` has a `target`
  field. `receiver::reload_keys` backs SIGHUP.
- `Configuration::validate` is split into per-topic checks. `merge_file`
  destructures the file configuration, so an unmerged key fails to compile,
  and a test checks that every CLI option has a configuration file key.
  Configuration errors go through one `invalid()` helper.
- The sender returns typed TLV telemetry for Access Report acknowledgements,
  forward congestion and validated micro-session IDs, and formats diagnostics
  only for `-R`. Control decisions no longer depend on status strings, and
  transient formatting allocations are gone. Summary schemas and diagnostic
  stream routing are unchanged.
- DSCP/ECN packing and unpacking go through `tos::Tos`.
- The reflector skips the CoS fallback retry when the fallback TOS byte is the
  one that just failed to send.
- Send-time Direct Measurement and Follow-Up Telemetry refresh covers TLVs
  before a malformed TLV, matching the RFC 8972 §4 stop rule used during
  assembly.
- Accepted sender reply observations are grouped into a named record.
- Session acquisition helpers return `Option` on rejection.
  `ReflectedControlBehavior::max_size` holds queued request limits, replacing
  the startup ceiling helpers and field.
- Unused library code is removed: `reply_source::send_from`,
  `srv6::send_with_srh`, `Stats::print_interim`, the TLV-HMAC recompute and
  isolated-processing helpers in `receiver`, and duplicate metric and
  pattern-parsing wrappers. Test-only helpers are `#[cfg(test)]`. The library
  API is internal and not covered by the 1.x contract.
- `receiver` exports only what the binary, tests and benchmarks use; other
  helpers there and crate-internal functions elsewhere are `pub(crate)`. This
  exposed two unused functions, which were removed.
- The `chrono` dependency is dropped; timestamps come from `SystemTime`. The
  Prometheus exporter is built without its default HTTP listener and push
  gateway, which removes hyper-rustls and aws-lc-rs from `metrics` builds.
- Code comments were checked against the code and the standards. Stale
  statements and wrong section citations were fixed, every `unsafe` block has a
  SAFETY comment, magic numbers in the netlink and capture code are explained,
  and citations use the `RFC NNNN §X` form. Conformance matrix citations name
  files rather than line ranges, stale conformance source citations are
  updated, and so is the TLV ownership documentation.
- The conformance citation checker verifies `path::item` citations and
  identifiers attributed to a file. It had checked none since line numbers were
  dropped from citations; six stale citations were fixed.
- CI runs on pull requests and on pushes to the release branches, with one run
  per pull request (a newer push cancels the older run). The redundant
  `ttl-nix` legs and one of the two packaging release builds are removed.
  Clippy warnings are fixed in default, nix, pnet and all-features builds, and
  the CI lint gates cover all targets, including an all-features leg.
- The fuzz job installs a prebuilt cargo-fuzz, caches each target's corpus and
  adds a `sender_reply` target. `process_stamp_packet` covers keys and captured
  headers, and the parser targets check round trips.
- Conformance CI requires successful three-namespace SRv6 forwarding with
  authenticated wire checks, and keeps the captures. It also runs strict
  privileged tests with exact artifact and test-count checks, capture readiness
  and error reporting, SRv6 fallback evidence, matrix and rollup drift checks,
  and full citation inventories. Conformance limits, totals and the separate
  fuzz lockfile were refreshed.
- CI keeps native default and all-features Cargo logs and revision-bound JSON
  reports, and rejects incomplete or wrong-platform evidence. Native Windows CI
  runs a bounded runtime suite, the library unit tests and the startup-error
  tests.
- The macOS MTU-race test no longer expects Linux-only source pinning. The
  extension-header (ext-hdr-13) wire tests run on macOS, including mapped IPv4
  with TTL 255, and key rotation coverage stays active while unsupported
  size-controlled drops are checked.
- pnet burst scheduler tests do not depend on platform route-MTU support, and
  check that unsupported-MTU drops preserve ordinary replies. pnet fixtures
  require valid authenticated replies and join their workers on shutdown.
- Five existing combination test suites no longer use production HMAC helpers.
  CLI stream tests replace JSON parsing workarounds in the wire tests.
- A non-Linux unreachable-code warning in IPv6 attachment validation is
  removed, and the deprecated `AtomicUsize::fetch_update` is replaced so clippy
  passes on current toolchains.
- `clock_metadata_test` restarts the reflector when another test takes its
  port, and skips late replies to warm-up probes.
- `loopback_test` binds its sender sockets to port 0 instead of a port chosen
  earlier, which another test could take in the meantime.

### Fixed

- SNMP workers stop when their owner exits, including during silent initial or
  reconnect handshakes. AgentX validates administrative responses and reads
  both network-order and little-endian PDUs.
- Senders validate the complete UDP payload before probing and return terminal
  send failures. Other send errors have an eight-attempt consecutive limit.
- Prometheus counts successful reflected copies and records drops at the same
  boundaries as reflector summaries, including queue and rate rejections.
- Measurement output uses an eight-item queue and a five-second final flush
  deadline. Slow output skips interim reports and text packet details; broken
  pipes return errors. Formatting runs in a buffered writer thread.
- Per-source limiter state is capped at 16,384 entries, with a shared overflow
  bucket and at most four expiry checks per request.
- The authenticated full-chain benchmark now verifies its TLV HMAC and reply
  before timing. A separate benchmark covers missing TLV authentication.
- Releases require the full reusable CI and conformance gates at the tagged
  commit. Debian builds require supplied offline vendor inputs; OpenWrt release
  recipes contain the hash of the exact published source archive.

- The pnet reflector on macOS loopback finds the IP header after pnet's zeroed
  placeholder instead of assuming 14 octets. pnet_datalink 0.35 inserts 12
  octets on 64-bit macOS, so every request on `lo0` was misparsed and dropped.
- A panic in the pnet capture thread makes the reflector exit non-zero. It
  exited with status 0, so a supervisor configured to restart on failure did
  not restart it.
- STAMP-SUITE-MIB has a new REVISION for the clarified object descriptions.
- RFC8972-3-10 (stop on a zeroed SSID) and RFC8972-4.1-5 (Extra Padding for
  larger test packets) are scored Compliant. Both are implemented, and the
  matrices use N-A only for optional behavior that is not.
- The CHANGELOG has entries for 0.6.1 and 0.9.0, and the 0.1.0 and 0.2.0
  dates match the version history.
- T1 and the RTT start are read after the probe's TLVs are built, just before
  the base packet is written and sent. Building the TLVs (BER padding, Direct
  Measurement, the TLV HMAC) counted as network delay; on loopback with
  authenticated BER probes the median RTT dropped by about 3 µs.
- macOS and Windows builds compile without warnings, and `--features snmp`
  tests no longer fail to build on Windows. CI now runs clippy on the macOS
  and Windows jobs.
- A configuration file with `return_srv6_sids = []` or
  `return_sr_mpls_labels = []` is rejected at startup. It passed validation
  and the sender sent a Segment List sub-TLV with Length 0 (RFC 9503 §4.1.3).
  The command line already rejected empty lists.
- The text report prints `n/a` for an average with no samples (reply RTT,
  Follow-Up reverse delay) instead of an empty value.
- `--require-hmac` help describes what the option does: the reflector drops
  authenticated packets for which no key is configured.
- Trailing zero padding is parsed in linear time. A crafted datagram of zeros
  ending in one non-zero byte cost about 75 ms of reflector CPU at 64 KB.
- Probes are sent on a fixed schedule. Each send deadline was measured from the
  end of the previous send, so send time and timer rounding stretched every
  interval: 2000 probes at `--send-delay 1` took 4.2 s and take 2.2 s with the
  fix. A probe up to 2 ms late is followed at once by the next; further behind,
  the schedule restarts from the current time rather than sending a burst.
- The sender keeps its send schedule when sends fail or the reflector answers
  with ICMP port unreachable. Repeated send and receive errors are printed on
  the 1st, 10th, 100th, ... occurrence.
- A failed per-probe route-MTU lookup does not abort a sender run, and Type
  246/247 requests are restored when the route MTU grows again.
- Linux SRv6 replies use the supported sticky routing-header option, preserve
  transit SIDs and the final UDP destination, and clear the SRH before ordinary
  replies.
- macOS IPv6 startup works: the reflector applies Darwin's shared hop policy
  for IPv6 and mapped IPv4, and decodes received hop metadata by
  control-message type.
- The pnet backend validates its bind addresses and keys before starting
  privileged capture, reports socket and authentication startup failures
  before capture-interface discovery, and keeps the underlying interface
  error.
- On Windows, the sender retries when an automatically selected source port
  fails with WSAEACCES. Port selection stays bounded and randomized, and an
  explicitly configured port still fails with an error.
- The nix reflector and the sender's ECN and kernel-timestamp receive paths
  clear Tokio socket readiness after a raw `recvmsg` returns `WouldBlock`.
  They used to consume a CPU core when idle after traffic. Regression tests
  cover IPv4, IPv6, ancillary metadata and receiving again after idle.
- `AF_NETLINK` is allowed in the packaged systemd unit. Route-MTU lookups and
  interface address discovery failed under the previous restriction.
- `--max-pps` is documented as a per-source-IP limit, which is what it has
  always enforced. The unused per-SSID limiter API is removed.
- The pnet backend reflected each loopback request twice, because Linux shows
  loopback frames to packet sockets both leaving and arriving. The capture
  socket sets `PACKET_IGNORE_OUTGOING`.
- A fixed 1600-byte buffer in Apple loopback capture panicked the capture
  thread on larger IP packets; it is removed.
- An echoed TLV HMAC is left unchanged when sending. After a failed TLV HMAC
  check, the reflector re-signed the copied HMAC TLV at send time; RFC 8972
  §4.8 requires it to be copied.
- Failure echoes no longer reorder legal padding around the HMAC TLV. Missing
  HMAC prefix bytes are rejected, and malformed digests and flags are preserved
  when the reply is regenerated.
- The received TLV order is kept when Extra Padding precedes the HMAC TLV in a
  packet that also carries BER TLVs. Serialization moved the padding after the
  HMAC, so an echoed reply reordered the sender's TLVs. The round-trip fuzz
  oracle found this.
- The route-MTU netlink query is nonblocking, so it cannot stall the reflector
  receive loop.
- The route-MTU cache subscribes to IPv6 policy-rule changes. It subscribed to
  the ND user-option group by mistake, so IPv6 rule changes were picked up only
  when a cache entry expired.
- The reflector refuses to start when the CoS admission or Location disclosure
  policy cannot be parsed, instead of falling back to permissive defaults.
- Warnings that a remote peer can trigger per packet (bad HMAC, strict-mode
  parse failures, missing keys, capture checksum errors) are throttled. Each
  call site logs its 1st, 10th, 100th, ... occurrence at warn level.
- The AgentX connect and registration handshake runs off the async runtime.
  Each SNMP request reads the session table once and finds successors by
  binary search; a table walk was quadratic in the number of sessions.
  Little-endian AgentX responses are rejected, as requests already were.
- AgentX GETBULK iterates in the correct order, uses the correct end-of-MIB
  placeholders and handles inclusive starts. Partial request headers and
  payloads survive timeout checks, the sub-agent stops promptly on
  cancellation, and master Close requests are acknowledged before teardown.
  Excess search ranges get an indexed error instead of silently omitting
  columns. Independent master wire fixtures cover this, and the RFC section
  citations are corrected.
- The AgentX session closes with reasonShutdown (5) instead of reasonOther (1)
  (RFC 2741 §6.2.2).
- Return Path sub-TLVs are parsed as raw sub-TLVs in wire order. They were
  parsed as top-level TLVs, so sub-type 8 was moved last as if it were an HMAC
  TLV.
- The `ExtraPaddingTlv::from_raw` and `HmacTlv::from_raw` inherent methods,
  which skipped the TLV type check, are removed; the `TypedTlv` versions check
  it.
- Key-file read buffers and rejected keys are wiped from memory.
- HMAC key load failures are reported with the option, path and OS error at
  the point of failure. They were logged and followed by a generic "no usable
  key" error. The sender loads its key before opening sockets.
- Reflected-TLV telemetry is blocked when an HMAC is present but cannot be
  verified, and Access Report acknowledgements with an invalid length are
  rejected. Flags are counted across duplicate HMACs. Mixed flag/integrity and
  output-mode regression tests cover this, and stale sender citations are
  updated.
- The reflector validates base packets and configured HMACs before creating or
  refreshing a session, so rejected packets cannot consume session slots or
  change counters, sequence numbers, replay windows or Follow-Up state. Both
  receive backends count processing rejections as aggregate drops and reuse
  the validated session handle through the initial send. TLV integrity-failure
  replies are still sent.
- The per-SSID key selected during reflector validation is the one used at
  transmission. Both backends reuse that snapshot for base and TLV signatures,
  fallback flag changes and queued burst copies. Key-directory, default-key,
  rotation, revocation and CoS/SRv6 fallback regression tests cover this.
- Every burst reply gets a fresh transmit timestamp, stateful sequence number
  and HMACs, and counters and Follow-Up state are updated after each
  successful send. CoS, source pinning and return-path fallback apply to every
  copy. Kernel TX correlation is serialized in the nix loop, and pnet burst
  waits run off the capture thread.
- A stateful reflector consumes a sequence number only when the reply is sent,
  so failed sends leave no gap (RFC 8762 §4.3.1).
- The sender rejects reflected packets whose nonzero SSID differs from the
  configured session before updating measurements or control state.
  Zero-SSID compatibility stays configurable. Tests cover open and
  authenticated replies over IPv4 and IPv6.
- The sender decodes reflector timestamps using their Error Estimate Z bit
  before computing one-way delay. NTP and PTP epochs are normalized and wrapped
  seconds are unfolded, including at the 2036 NTP era boundary.
  `--reflector-utc-offset` sets an explicitly known remote timescale offset.
  Invalid PTP fractions omit OWD but keep RTT.
- TLV processing stops at a malformed TLV instead of skipping the whole packet
  or ignoring the stop (RFC 8972 §4). TLVs before it are processed, the
  malformed TLV gets M, and later TLVs are copied with U. A TLV whose Length is
  wrong for its type also stops processing.
- Timestamp Information TLVs that carry optional sub-TLVs (RFC 8972 §4.3) are
  accepted; they were flagged malformed.
- Content after the base packet that the reflector does not parse is copied
  instead of zeroed: 1-3 trailing octets in echo mode, and everything in
  `--tlv-mode ignore`, which behaves like a reflector without TLV support
  (RFC 8762 §4.3, RFC 8972 §4).
- A Location Source MAC request is answered with the frame's EUI-48 source
  address when the pnet backend sees it (RFC 8972 §4.2.2). `--location-disclose`
  accepts `src-mac`.
- `--error-multiplier 0` (RFC 4656 §4.1.2) and `--access-report` IDs other
  than 1 and 2, which reflectors must discard (RFC 8972 §4.6), are rejected.
- In authenticated mode, only a single Extra Padding TLV is allowed without an
  HMAC TLV, not several (RFC 8972 §4.8). The sender treats an authenticated
  reply without the HMAC TLV as an integrity failure.
- RFC 9503 Control Code 0x1 (reply on the same link) is honored. On Linux the
  reply is pinned to the arrival interface with `IP_PKTINFO`/`IPV6_PKTINFO`;
  elsewhere, or when pinning fails, the Return Path TLV gets U. It was treated
  as a normal reply.
- A Return Address and an SRv6 Segment List can be used together
  (RFC 9503 §4.1), and the first segment-list sub-TLV in wire order is the one
  acted on (§4.1.3).
- RFC 10052 per-request byte-rate and byte-volume limits apply to Type 12
  bursts: `--reflected-control-max-rate` (default 12.5 MB/s) and
  `--reflected-control-max-volume` (default 1.5 MB), also adjustable through
  the control API. Exceeding either gives one C-flagged reply.
- With Type 12 disabled (`--reflected-control-max-count 0`), the TLV is treated
  as unsupported and gets U instead of C.
- CoS TLV Reserved bits are zeroed in replies, and every processed CoS TLV is
  marked when the requested DSCP/ECN cannot be applied (RFC 8972 §4.4,
  cos-ecn-01 §3.1/§3.2).
- An all-zero Requested field in a reflected Type 246/247 TLV is filled with
  the matched header's first 8 or 4 octets
  (draft-ietf-ippm-stamp-ext-hdr-15 §4.2 and §6.2 rule 1). The reflector left
  it zero.
- Sender probe counters are 64 bits wide, since a continuous run would
  overflow 32-bit counters. The Direct Measurement counter on the wire stays 32
  bits and wraps.
- `--report-interval` reports keep printing while the sender waits for
  outstanding replies and Access Report acknowledgements; they used to stop
  with the last probe.
- Startup fails with an error when the local Error Estimate cannot be built,
  instead of panicking.
- `--metrics` and `--snmp` given to a binary built without that feature stop
  startup, as `--control` already did. Both used to print a warning and run
  without the service.
- macOS release archives are built with the `metrics` feature. It was left out
  because the exporter's default features did not build there.
- Log and error text is corrected: header-reflection warnings do not tell nix
  users to rebuild with pnet for IPv6 extension headers, and a debug message
  that lost a run of spaces is fixed.
- Stale RFC 9503 section references in source comments, CLI help and
  documentation are corrected.

## [1.0.0] - 2026-08-05

First stable release. It closed the last fifteen non-Compliant conformance
rows. At release, the compliance statement in `doc/conformance/README.md`
recorded 368 audited clauses: 320 Compliant, 0 Partial and 3 Gap. The three
Gaps and three Excluded rows were documented, deliberate exclusions.

### Added

- **Runtime control-plane REST API** (cargo feature `control`, reflector only;
  it uses the already-optional axum and tokio-util, so it adds no
  dependencies). `--control` starts a localhost HTTP server (default
  `127.0.0.1:9091`, change it with `--control-addr`) that exposes `/v1`: live
  status and session table, session expiry, runtime per-SSID HMAC key
  management, live cap tuning (`max_pps`, `rate_burst`, `max_sessions`, Type 12
  amplification caps), drain mode (new clients still get replies but no
  session state accumulates) and graceful shutdown. Key management is
  write-only: key bytes are never returned or logged, and request strings are
  zeroized. `--control-token-file` enables bearer-token authentication with
  constant-time comparison, and non-loopback binds log a loud warning. Unknown
  JSON fields in requests are rejected. The design is described in
  `doc/control-plane.md`.
  - Supporting changes: the per-SSID `HmacKeySet` moved into
    `ReceiverSharedState` behind `Arc<RwLock<…>>` (packet loops take short read
    guards that never cross an await). The `RateLimiter` is always constructed
    with atomically adjustable rate and burst (rate 0 means unlimited and
    short-circuits without allocating buckets). Type 12 caps live in a shared
    `RuntimeCaps` struct of atomics, and `SessionManager` gained
    `expire_session`, drain and a runtime `max_sessions`.
- **Control-plane TLS:** `--control-tls-cert` and `--control-tls-key` serve the
  API over HTTPS. TLS requires `--control-token-file` as well, because an
  unauthenticated key-management and shutdown endpoint should not be reachable,
  encrypted or not.
- **Kernel and hardware packet timestamping** (cargo feature `hwtstamp`, no
  extra dependencies, included in the Debian package build). With the feature
  enabled and `--hwtstamp auto` (the default mode):
  - Linux RX: the reflector's T2 and the sender's T4 come from
    `SO_TIMESTAMPING` kernel timestamps (`SCM_TIMESTAMPING` cmsgs) taken at
    packet arrival, which removes scheduler wakeup latency from one-way delays.
    Over loopback, forward OWD dropped from tens of µs to single-digit µs.
  - Linux TX: transmit timestamps are recovered from the socket error queue
    (`MSG_ERRQUEUE`, correlated with `SOF_TIMESTAMPING_OPT_ID`). The sender
    corrects the stored T1 used for forward OWD after the fact, and the
    reflector corrects its Follow-Up Telemetry record, so the FUT TLV
    (RFC 8972 §4.7) carries the previous reply's kernel TX time.
  - macOS: kernel software receive timestamps through `SO_TIMESTAMP`
    (µs resolution). Windows: compiles to a no-op, because the pnet receiver
    has no socket to timestamp; `SIO_TIMESTAMPING` support is future work.
  - `--hwtstamp on` also attempts NIC hardware timestamps: `SIOCSHWTSTAMP`
    filters (CAP_NET_ADMIN) and the raw-hardware cmsg tier, falling back to
    kernel software timestamps with a warning on any failure. The Timestamp
    Information TLV reports `HwAssist` only when both directions are
    hardware-timestamped. Operators must keep the PHC disciplined
    (ptp4l/phc2sys) for cross-clock OWD to be meaningful; see the PHC caveat
    in `doc/architecture.md`.
  - The startup warning for `--hwtstamp on` is conditional: it is silent when
    hardware timestamping will be attempted, and names the missing build
    feature or NIC capability otherwise.
- **`--hwtstamp` capability probe.** At startup the reflector or sender queries
  `ETHTOOL_GET_TS_INFO` (through `SIOCETHTOOL`) on the interface that owns
  `--local-addr` and logs the NIC's timestamping capabilities (`rx_hw`,
  `tx_hw`, PHC presence). Wildcard binds, unknown interfaces and non-Linux
  platforms report no capabilities; the probe never fails startup.
- **`--location-disclose <FIELDS>`** selects which Location TLV fields the
  reflector reports (RFC 8972 §4.2.2). A withheld field is answered as zeroes,
  so the reply's size and TLV structure do not change. A withheld IP request
  keeps its generic sub-TLV type, so the address family is not disclosed
  either.
- **CoS admission policy:** `--allowed-dscp`, `--allowed-ecn` and
  `--allowed-dscp-for PREFIX/LEN=SPEC` implement the policy RFC 8972 §4.4/§6
  and cos-ecn-01 §3.2 ask for, which separates what is permitted (operator
  policy) from what the socket can do. A successful `setsockopt` is not taken
  as evidence that a codepoint is permitted in the operator's domain. A
  refused DSCP1 reports RPD=0b01 and keeps the received DSCP; a refused EC1
  forces Not-ECT and reports RPE=0b10.
- **Replay detection** (asymmetrical-pkts §5) tracks received Sequence Numbers
  per session and reports `packets_replayed` and `packets_reordered` in the
  control plane's `/v1/status`. Detection is unconditional; `--drop-replayed`
  opts in to acting on it. The HMAC TLV does not defend against replay, since
  a replayed packet carries a valid HMAC. Per-event logging stays at debug
  level on purpose: the sequence numbers are attacker-controlled, so a warning
  per event would allow log amplification.
- **Reply source-address pinning:** a matched Destination Node Address is used
  as the reply's IP source address (RFC 9503 §3), on both backends.
- **Layer-2 Address Group sub-TLV filter** (draft-ietf-ippm-asymmetrical-pkts-14
  §3.1.1). The L2 (MAC-based) Address Group sub-TLV of the Reflected Test
  Packet Control TLV is evaluated against the reflector's own local MAC
  addresses, like the L3 (IP-prefix) sub-TLV: a match replies normally, a
  mismatch drops the packet with no reply. Network namespace evidence:
  `tests/netns_conformance.rs::scenario_5_address_group_filters`.
- **IPv6 Extension Header Control sub-TLV** (draft-ietf-ippm-stamp-ext-hdr-08
  §5.3). The reflector recognizes this presence-only sub-TLV inside a
  Reflected Test Packet Control TLV as a request for one-way measurement mode
  (do not attach received IPv6 extension headers to the reply's IPv6 header)
  and records it in `ReflectedControlBehavior::suppress_reply_ext_headers`.
  Neither backend attached extension headers to replies at 1.0.0, so the
  request was honored trivially; the bit is available for a future
  reply-attachment path. The sender option `--reflected-control-no-ext-hdr`
  emits the sub-TLV (and therefore the Type 12 TLV, even at count 1);
  combining it with `--return-path-cc 0` is rejected per asymmetrical-pkts-14
  §4.3. The sub-TLV codepoint is TBA3 at IANA; until assignment, the
  implementation uses 240 from the shared STAMP Sub-TLV Types Experimental
  range, to be renumbered when the RFC is published.
- **draft-ietf-ippm-stamp-ext-hdr-11 requirements.** `--reflected-ipv6-ext-hdr`
  and `--reflected-fixed-hdr` are repeatable (`[LEN[:SELECTORHEX]]` per
  occurrence) and emit one Type 246 or Type 247 TLV each, in order. The
  single-option form and the standalone `--reflected-ipv6-ext-hdr-selector`
  and `--reflected-fixed-hdr-selector` options stay backward compatible.
  - `--attach-ext-hdr hbh|dest[:HEX]` makes the sender attach a real IPv6
    Hop-by-Hop or Destination Options header to its own packets (sticky
    `IPV6_HOPOPTS`/`IPV6_DSTOPTS`, Linux and macOS) and emit the matching
    request TLV.
  - The reflector's capture walk traverses the full IPv6 extension header
    chain (Routing, including the Segment Routing Header, and the fixed-size
    Fragment header) and stops with a C flag at AH or ESP, neither of which
    can be reflected. It descends IP-in-IP tunnels (protocols 4 and 41, depth
    capped at 4) to capture stacked outer and inner fixed headers for
    multi-TLV Type 247 requests.
  - Both roles are MTU-aware. The sender queries the live route MTU
    (`IP_MTU`/`IPV6_MTU`, 1280/1500 fallback) and trims header TLVs from the
    tail (Type 246 before Type 247, BER padding never removed) when the packet
    would exceed it. The reflector trims reflected-header data to its reply
    size cap (see the reply-size cap under Changed).
  - If a Type 246 TLV appears before its Type 247 sibling in the packet, every
    header TLV is returned with the C flag and no data is copied (§3.3).
- **AIMD congestion response** (draft-ietf-ippm-stamp-cos-ecn-01 §3.4).
  `src/rate_control.rs` implements multiplicative backoff and linear recovery.
  A CE-marked reply is detected from the reflected CoS TLV's EC2 field
  (forward path, integrity-gated like any other reflected TLV value) or from
  the reply packet's own ECN, read through `recvmsg` with
  `IP_RECVTOS`/`IPV6_RECVTCLASS` on the sender socket (reverse path, Linux and
  macOS). On CE the sender's inter-packet interval grows by
  `--ecn-backoff-factor`, capped at `--ecn-max-delay`, and it decays on clean
  replies. The controller is always active when `--cos` with `--ecn` requests
  ECT0 or ECT1, with no way to turn it off, matching the unconditional MUST.
  Other platforms log a one-time warning and detect congestion on the forward
  path only.
- **Access Report retransmission** (RFC 8972 §4.6). A packet carrying the
  Access Report TLV arms a retransmission timer. The sender retransmits the
  TLV up to `--access-report-retries` times (default 4) at
  `--access-report-timeout`-second intervals (default 3 s, per §4.6-13) until
  a reflected packet with a recognized, integrity-intact Access Report TLV
  disarms it or the retries are exhausted (`Aborted`). The timer runs to
  completion independently of `--count` and `--send-delay`, through a wait
  phase after the send loop, so a run shorter than the retry budget still
  retransmits and aborts instead of reporting `Pending` forever.
  `--access-report` rejects an Access ID outside the registry values 1 and 2:
  `0` is invalid per §4.6, and 3-15 log a warning as forward-compatible but
  are accepted on the sender side.
- **RFC 9534 Reflector Micro-session ID validation on the sender.** The sender
  validates the Reflector Micro-session ID on every reply, not only when
  `--reflector-member-link-id` is configured. Without a configured value, the
  first valid reply's ID is latched and expected for the rest of the session;
  a configured value always takes precedence and is never overridden. A
  mismatch on either path discards the packet
  (`TlvRejection::ReflectorMsidMismatch`).
- **`--on-zero-ssid continue|stop`:** the sender control RFC 8972 §3 requires
  for a reflector that returns a zeroed SSID. It has no effect unless a
  non-zero `--ssid` is configured.
- **`--extra-padding <BYTES>`** adds an Extra Padding TLV independent of
  `--ber`.
- **`--ber-omit-burst`** omits the Type 242 TLV, whose Experimental-range
  codepoint collides with another implementation's incompatible Heartbeat TLV.
- **`--tlv-hmac auto|on|off`** controls HMAC TLV origination separately from
  holding a key.
- **`-v`/`--verbose`** is repeatable (`-v`, `-vv`, `-vvv`, ...) and raises the
  log level from `info` to `debug` to `trace` (`resolve_log_filter`). An
  explicit `RUST_LOG` environment variable takes precedence at any count.
- **`process_stamp_packet` fuzz target.**
  `fuzz/fuzz_targets/process_stamp_packet.rs` drives the full reflector
  pipeline (parse, flag re-derivation and HMAC, semantic TLV processing,
  response assembly) for authenticated and unauthenticated packets. The
  earlier fuzz targets covered only the low-level parsers in isolation, not
  the in-place TLV mutators and length arithmetic.
- **Privileged network namespace conformance tests.**
  `tests/netns_conformance.rs` (9 scenarios) exercises on-wire behavior that
  unit and loopback tests cannot reach: IP TOS/ECN/TTL marking, IPv6 extension
  headers, SRv6 SRH return-path routing (the first live exercise of
  `send_with_srh()`), Address Group filtering, and Type 12 multi-reply pacing,
  count and length, over two Linux network namespaces joined by a `veth`
  link. Every scenario is `#[ignore]`d and also requires
  `STAMP_NETNS_TESTS=1` and root or `CAP_NET_ADMIN`, so an ordinary
  `cargo test` never touches the network. Instructions, prerequisites and a
  rootless (`unshare -Urn`) path are in `doc/testing-netns.md`.
- **Clause-level conformance matrices and a compliance statement.**
  `doc/conformance/` carries an independently re-verified clause-by-clause
  matrix (quote, RFC 2119 level, role, status, code and test evidence) for
  RFC 8762, RFC 8972 (including errata 8199 and 8339), RFC 9503, RFC 9534,
  RFC 8545, and the drafts asymmetrical-pkts-14, stamp-cos-ecn-01 and
  stamp-ext-hdr-11: 368 clauses at 1.0.0. `doc/conformance/README.md` rolls
  them up into one compliance statement with per-document counts, a
  maintainer-adjudicated list of documented exclusions (SR-MPLS return-path
  forwarding, SNMP SET, STAMP YANG, Windows and macOS platform-tier limits,
  NIC hardware timestamp verification, SSID-based session admission) as
  opposed to open Partials and Gaps, the experimental-codepoint disclosure,
  and a summary of the verification tiers.
- **`scripts/check_conformance_citations.py`** checks the conformance
  matrices' `file:line` citations and exits non-zero on drift.
- **Release preflight and gated publishing.** A `release-preflight` CI job runs
  before packaging or publishing. It checks that the git tag, `Cargo.toml`,
  `CHANGELOG.md`, the Debian changelog and the OpenWrt Makefile agree on the
  version, and runs `cargo publish --dry-run --locked` to catch manifest and
  packaging errors before any build or test time is spent. Packaging jobs also
  assemble a plain tarball per target (the Linux DEB/RPM targets and two new
  macOS targets, `aarch64-apple-darwin` and `x86_64-apple-darwin`), and
  crates.io publishing runs only after the preflight and test jobs pass.
- **`cargo-deny` CI gate.** `deny.toml` runs `cargo deny check` in CI
  (advisories, a license allow-list, duplicate-version and wildcard-dependency
  bans, and a crates.io-only source restriction) across the full
  `--all-features` dependency graph. The RustSec `audit-check` job runs
  alongside it on purpose: `audit-check` posts inline PR annotations and can
  open issues for new advisories, while `cargo-deny` also covers licenses,
  bans and sources and is the command contributors run locally.
- **Best-effort Windows CI test job.** `rust.yml` runs the test suite on
  `windows-2022`. The job does not gate the pipeline (a Windows test failure is
  reported but does not block it), since Windows is the `pnet`/Npcap fallback
  tier rather than the primary `nix` backend.

### Changed

- **The reply-size cap is smaller by default.** The reflector queries the
  egress interface's MTU, and the reply-size cap is the smaller of
  `--reflected-control-max-size` and that MTU. With the option at its 1500
  default on a 1500-byte link, the effective STAMP payload cap is 1472 (1452
  for IPv6) rather than 1500. The option bounds the STAMP payload while an MTU
  bounds the whole datagram, so the old default permitted a 1528-byte
  datagram; the draft's MTU-exceeded C-flag path now fires where it belongs.
  Raise the option for a jumbo link.
- **Reflected Test Packet Control (Type 12) processing follows
  draft-ietf-ippm-asymmetrical-pkts-14 §3.** These reflector changes apply
  only when asymmetric reflection is enabled
  (`--reflected-control-max-count > 0`):
  - A request over the volume limit (`--reflected-control-max-count`) or the
    rate limit (`--reflected-control-min-interval-ns`) gets the C flag and a
    single reflected packet, as the draft mandates. The count and interval
    used to be clamped silently and a reduced burst sent.
  - A request with `count = 0` suppresses the reply entirely ("MUST NOT send
    any reflected packets").
  - Echoed Extra Padding TLVs are stripped before the reply length is computed
    (§3 rule a), so a sender can request replies shorter than its test packet.
    The requested length is honored, aligned up to a 4-octet boundary (§3 rule
    b). The padding target is computed from the actual reflected base size
    instead of being inferred from whether a TLV-HMAC key is present.
  - The C flag received from the wire is ignored and re-derived by the
    reflector (§3); a sender-set C used to leak into the echo.
  - A Return Path "no reply requested" control code combined with a non-zero
    Type 12 TLV (a sender error per §4.3) yields a single normal reply with
    the U flag set on both TLVs, plus a warning log. The sender rejects
    `--return-path-cc 0` together with `--reflected-control-count > 1` at
    startup.
- **Timestamp Information TLV:** the reflector fills all four value octets
  from its own clocks and reports the ingress (T2) and egress (T3) acquisition
  methods separately instead of merging them into one conservative value.
- **An Extra Padding TLV after the HMAC TLV is accepted**, as RFC 8972 §4.8
  explicitly permits, instead of being marked malformed.
- **Internal library modules are `#[doc(hidden)]`.** `clock_format`,
  `configuration`, `crypto`, `error_estimate`, `hwtstamp`, `packets`,
  `rate_control`, `receiver`, `sender`, `session`, `srv6`, `stats`, `time`,
  `tlv` and the optional `control`, `metrics` and `snmp` modules stay `pub`
  for this crate's integration tests, benchmarks and fuzz targets, but do not
  appear in generated rustdoc. A Stability comment on the crate root states
  that the stable 1.x surface is the CLI options, the configuration file
  schema and on-the-wire behavior, not these Rust APIs, which are exempt from
  semver and may change in any 1.x release.
- **Experimental and pending-IANA TLV codepoints are centralized.** The six
  codepoints used ahead of IANA allocation are named constants in
  `src/tlv/experimental.rs`: the BER Pattern, Count and Max-Burst TLV types
  (240/241/242, draft-gandhi-ippm-stamp-ber), the Reflected IPv6 Extension
  Header Data and Reflected Fixed Header Data TLV types (246/247, TBA1/TBA2 in
  draft-ietf-ippm-stamp-ext-hdr), and the IPv6 Extension Header Control
  sub-TLV type (240 within Type 12, TBA3 in the same draft). Each constant's
  documentation states which draft defines the TLV, which IANA action will
  trigger renumbering, and that the constant is the single place to change.
  `TlvType`'s discriminants and `from_byte`/`to_byte` use these constants
  instead of literals. On-the-wire behavior and import paths are unchanged,
  and there is deliberately no runtime or configuration override.
- `TlvList`'s `PartialEq`/`Eq` are hand-written, so parse provenance does not
  affect equality.

### Fixed

- **CoS TLV (Type 4) wire format was incompatible with RFC 8972.** The encoder
  packed `DSCP1|ECN` into value byte 0 and `DSCP2|ECN2` into byte 1, while
  RFC 8972 §4.4 places DSCP1 and DSCP2 next to each other
  (`| DSCP1 | DSCP2 |ECN|RP|`), so every CoS field except DSCP1 landed in the
  wrong bits when talking to a conformant peer (for example teaparty or
  Junos). The TLV uses the correct layout, extended with the EC1/RPE
  reverse-path ECN fields of draft-ietf-ippm-stamp-cos-ecn-00, which occupy
  formerly Reserved bits and are backward compatible. EC1 carries the ECN
  value requested for the reflected packet (the existing `--ecn` option,
  previously sent in a non-standard byte-0 position). The reflector reports
  RPE=0b11 when it set the reply's ECN to EC1, or 0b10 when it could not (for
  example on a setsockopt failure, which also sets RPD=0b01). Earlier
  stamp-suite peers parse CoS fields from the old positions, so mixed-version
  CoS measurements misreport DSCP2 and ECN values; upgrade both ends.
- **`IP_PKTINFO` destination address was byte-reversed on the `nix` backend on
  little-endian hosts.** `ipv4_addr_from_pktinfo` called
  `ipi_addr.s_addr.to_be_bytes()` on a value the kernel already fills in
  network byte order as a raw `u32`. On little-endian hosts (in practice all
  x86_64 and aarch64 deployments) this reversed the octets, so the Location
  TLV's captured destination address, and any other consumer of
  `extract_dst_addr_from_cmsgs`, could report the wrong IP. It uses
  `to_ne_bytes()`, which copies the byte layout as-is on any host. Test:
  `ipv4_pktinfo_extraction_preserves_octet_order`.
- **Reflector replies were truncated when a request's trailing padding was an
  all-zero run with no TLVs** (RFC 8762 §4.3/§4.6). `TlvList::parse_lenient`
  correctly drops a trailing all-zero run at a 4-byte-aligned offset, but the
  echo-mode assembly path did not re-pad to compensate, so a classic
  TWAMP-Light packet with 50 zero octets of padding and no TLVs came back
  truncated to the base packet size. The reply is re-padded to the received
  length after the TLVs are written, except when a Reflected Test Packet
  Control TLV (Type 12) governs the reply size. Tests:
  `test_zero_trailer_reply_preserves_symmetric_size_{unauth,auth}`,
  `test_nonaligned_garbage_trailer_preserves_size_unauth`.
- **Location TLV sub-TLVs used a non-registry wire format, and the reflector
  did not preserve the TLV's own length on echo** (RFC 8972 §4.2.1/§4.2.2).
  Sub-TLVs use the same 4-octet Flags/Type/Length header as top-level TLVs,
  matching Figure 5 of the RFC. The reflector edits sub-TLV value bytes
  strictly in place, so the Location TLV's own wire Length never changes.
- **The Timestamp Information TLV request leaked the sender's clock into
  reserved fields** (RFC 8972 §4.3). The Session-Sender builds its request TLV
  with `TimestampInfoTlv::request()`, which zeroes all four value octets as the
  RFC requires ("MUST NOT fill any information fields... All other fields MUST
  be filled with zeroes"). The previous constructor wrote the sender's own
  sync source and timestamp into fields only the reflector should fill.
- **The Follow-Up Telemetry TLV was not zeroed in stateless mode or when its
  length was invalid** (RFC 8972 §4.7, erratum 8339). The reflector zeroes the
  Sequence Number and Follow-Up Timestamp fields when `--stateful-reflector`
  is off (§4.7-7), and also zeroes them, besides setting the M flag, when the
  received TLV's Length is invalid (§4.7-6), instead of leaving stale or
  attacker-echoed bytes in place.
- **The Access Report TLV value was 2 octets instead of the required 4, and an
  invalid Access ID was not discarded** (RFC 8972 §4.6-3/§4.6-4).
  `ACCESS_REPORT_TLV_VALUE_SIZE` is 4 (ID and Resv, Return Code, and the
  2-octet Reserved tail §4.6 specifies). The reflector marks a well-formed
  Access Report TLV whose Access ID is not 1 or 2 as unrecognized (U flag)
  through `discard_invalid_access_report_tlvs`, instead of accepting it.
- **Type 12 length overshoot.** A keyed reflector appends its own HMAC TLV
  after the length-padding decision, so a request from a peer that sends no
  HMAC TLV got a reply exactly 20 octets longer than requested. The test
  asserted that the reply was at least the requested length, which the
  overshoot satisfied; it now asserts equality.
- **Missing control TLV on retransmission.** With the AIMD congestion response
  active, an Access Report retransmission in the wait phase carried no
  Reflected Test Packet Control TLV, because that path rebuilt its TLV set
  from the list the main loop deliberately leaves it out of.
- **HMAC coverage arithmetic.** The covered prefix was derived from the sum of
  non-HMAC TLV sizes, which equals the wire prefix only while the HMAC TLV is
  last. This had to be fixed before trailing Extra Padding could be accepted.
- **Redundant syscall.** The cos-ecn-01 zero-ECN fallback re-issued the exact
  TOS byte the kernel had just refused when EC1 was already 0 and DSCP1
  matched the received DSCP.
- **SNMP sub-agent reconnects to the AgentX master.** If net-snmpd restarted or
  closed the session, the sub-agent exited and stayed down for the life of the
  process. The AgentX event loop runs inside a reconnect loop with capped
  exponential backoff (1 s to 30 s) that reconnects and re-registers the MIB
  subtree and honors the shutdown signal during backoff. The initial connect
  is synchronous, so a misconfigured socket path still fails at startup.
- **AgentX SET requests are answered and byte order is declared** (RFC 2741).
  The sub-agent is read-only. It replies to a TestSet with `notWritable`, to
  Commit and UndoSet with the matching failure code, and ignores CleanupSet,
  instead of dropping the PDU and leaving the master to time out. Every PDU it
  sends sets the `NETWORK_BYTE_ORDER` flag to match its big-endian encoding
  (the flag byte was 0, which declared little-endian), and incoming request
  PDUs that declare a different byte order are rejected rather than
  misinterpreted.
- **The Dockerfile could not be built and produced an image that did not
  run.** The dependency-caching stub stage created only `src/main.rs`, so
  cargo could not parse the manifest once the lib target and the
  `reflector_hotpath` bench were declared; the stage stubs all three target
  files. The `rust:*-slim` builder tag had moved to Debian trixie (glibc 2.38)
  while the runtime stage stayed on bookworm (glibc 2.36), so the binary
  failed to start; both stages are pinned to the same Debian release. The
  image builds with the production feature set (overridable
  `ARG FEATURES`: ttl-nix, metrics, snmp, hwtstamp, control) and documents
  ports 9090 and 9091. A containerized reflector answered a host sender with
  0% loss. The Nix flake's `cargoHash` was regenerated and its feature list
  includes `hwtstamp` and `control`; the Debian package includes `control`.
- **18 incorrect RFC citations.** U/M/I flag semantics were attributed to
  RFC 8972 §4.4.1, which does not exist; they are defined in §4.
- Documentation corrections: `TlvList::clear_reflector_flags` claimed to
  preserve the C bit while the method it delegates to clears it on purpose;
  `--hmac-key` called 32 or more hex characters "recommended" when shorter keys
  are rejected; the reflected-header module documentation described an earlier
  draft round's positional matching.
- The release workflow's `package` job does not inherit `contents: write`.

### Security

- **Reflection and amplification hardening (open mode).** By default the
  reflector does not redirect replies or amplify reply size for
  unauthenticated peers:
  - A Return Path TLV Return Address sub-TLV (RFC 9503 §5) is ignored unless
    the operator sets `--return-path-allow-alternate`. When it is off (the
    default), the reflector echoes the sub-TLV with the U flag and replies to
    the packet source, so an open reflector cannot be used to aim traffic at a
    third party.
  - A Reflected Test Packet Control TLV (Type 12) length request pads the
    single reply only when asymmetric reflection is enabled
    (`--reflected-control-max-count > 0`, default `0`). The single-reply
    padding used to run regardless of the count cap, which allowed about 15×
    amplification. When asymmetric reflection is disabled, the request is
    refused with the C flag.
- **Bounded session table.** `--max-sessions` (default `65536`, `0` =
  unlimited) caps the per-client session table. The reflector used to create
  an unbounded session entry for every distinct source `IP:port`, so an
  unauthenticated peer could grow the table until the process was
  OOM-killed. At the cap, new clients were answered but not tracked, and the
  periodic cleanup reclaimed stale entries. The "cap reached" warning is
  logged once per saturation episode instead of once per rejected client,
  which closes a log-amplification side channel.
- **Per-packet panic isolation.** Both receive backends run
  `process_stamp_packet` through `process_stamp_packet_isolated`, which catches
  any panic, drops the offending packet and continues. A panic in the
  processing path would otherwise unwind out of the `nix` receive loop and end
  the process (a remote, single-packet DoS) or permanently stop the `pnet`
  capture task. No reachable panic is known; this is defense in depth. The
  caught-panic message is logged once at `error`, then at `debug`, to avoid a
  log-amplification side channel.
- **Address Group panic.** `l2_group_matches_any_local` validated only the
  mask length before indexing both mask and group, so an Address Group
  sub-TLV whose group was shorter than six octets panicked. The current parser
  could not reach it, but a panic there is a reflector-wide denial of service,
  so it is fixed as that class of defect.
- **Key file permissions are enforced.** `HmacKey::from_file` rejects a key
  file with any group or other permission bit (`0o077`) instead of logging a
  warning and using it. In authenticated mode the daemon then refuses to start
  (fail-closed) rather than running unauthenticated. The check runs on the
  opened file descriptor (`fstat`), which closes the time-of-check to
  time-of-use gap and checks the real target's permissions even when the path
  is a symlink. `O_NOFOLLOW` is deliberately not used, so Kubernetes and
  systemd-credential secret mounts (which expose secrets as symlinks) keep
  working. `--hmac-key-dir` rejects a directory that is group- or
  other-writable (a key-injection risk) and allows the recommended
  group-readable `0750` layout.

  **Breaking:** a key file that was accepted at `0640` or `0644` (with a
  warning) is refused. Use `chmod 0400` or `0600` (owner-only). See
  [doc/security.md](doc/security.md#file-permissions).
- **CLI and environment HMAC keys are zeroized and redacted.** `--hmac-key` and
  `STAMP_HMAC_KEY` are parsed into a `SecretString` wrapper instead of a plain
  `String`. The plaintext key is zeroized on drop, so it cannot be recovered
  from a core dump or freed heap, and is redacted from `Debug`, so it cannot
  leak through a `{:?}` of `Configuration`. The decoded `HmacKey` was already
  zeroized, but the original hex string stayed in memory for the life of the
  process. `--hmac-key-file` is the recommended source; a command-line key is
  still visible in `ps` and `/proc/<pid>/cmdline`.
- **SNMP GETBULK/GETNEXT CPU amplification.** The AgentX sub-agent processes at
  most 256 SearchRanges per PDU and computes the OID-space snapshot once per
  PDU instead of rebuilding and re-sorting it for every `get_next` lookup. A
  single GETBULK could pack about 65k ranges, each multiplied by up to 100
  repetitions, with every lookup rebuilding the full OID list (sized by the
  session table), which caused heavy CPU use and lock contention. The master
  agent is local and semi-trusted, so this is robustness hardening.
- **A misplaced HMAC TLV is treated as an integrity failure.** It triggers the
  RFC 8972 §4.8 verification-failure procedure (the I flag on every TLV), not
  only the parser's M flag on the offending TLV.
- **Session-Sender reflected-TLV validation order** (RFC 8972 §4-17/18/19,
  §4.8-16/17). `validate_reflected_tlvs` (`src/sender.rs`) evaluates a
  reflected packet's U/M/I flags and its TLV-HMAC result before reading any
  TLV value for effect (the Micro-session ID used for session binding, the
  Access Report acknowledgement marker, the CoS CE congestion marker). A
  U-flagged TLV is skipped rather than trusted, an M-flagged TLV stops the scan
  of the remaining TLVs, and any I-flagged TLV or a failed TLV-HMAC closes the
  integrity gate for the whole reflected TLV set. A forged Micro-session ID (or
  other TLV value) could be consumed before its own flag or HMAC failure was
  accounted for. Tests: `test_forged_msid_with_{u,m,i}_flag_not_consumed`,
  `test_forged_msid_ignored_when_tlv_hmac_fails` (`src/sender.rs`).

## [0.9.0] - 2026-06-10

### Added

- **One-way delay statistics.** The sender reports forward (T2 − T1) and
  reverse (T4 − T3) one-way delay as min, average, median and max next to RTT.
  The figures are meaningful only when both ends have synchronized clocks.
- **Egress IP header marking.** `--ttl` sets the IPv4 TTL or IPv6 Hop Limit of
  test packets, and `--cos` also sets the DSCP and ECN of outgoing test packets
  to the values the Class of Service TLV requests (Linux and macOS).
- **Malformed TLV injection.** `--malformed bad-flags|bad-length` appends a
  deliberately malformed TLV to every test packet, to test how a reflector
  handles RFC 8972 §4.2 flags and lengths. It is not for normal measurements.
- **SRv6 return path.** With `--srv6-return-forwarding`, a Linux reflector
  answering over IPv6 inserts a Segment Routing Header built from the Return
  Path TLV's SRv6 Segment List (RFC 9503 §5, RFC 8754). Without the option, or
  where the kernel or path does not support it, the reflector replies normally
  and sets the U flag. SR-MPLS segment lists are echoed with the U flag.

### Changed

- Reflected Test Packet Control (Type 12) multi-reply is off by default:
  `--reflected-control-max-count` defaults to 0, so the reflector sends one
  reply and sets the C flag. Set a positive value to allow more replies.
- `--hwtstamp on` warns and uses software timestamps when hardware
  timestamping is unavailable instead of refusing to start. Hardware
  timestamping was not implemented in this release.
- Dependencies updated to their current versions, including criterion 0.8 for
  the benchmarks.

## [0.8.0] - 2026-05-18

### Added

- **Per-SSID HMAC key set.** `--hmac-key-dir <DIR>` and the
  `crypto::HmacKeySet` type let one reflector serve several senders without
  sharing a key. Each file's name (without extension) is the SSID in hex; an
  optional `default.key` is the fallback for unknown SSIDs. The option is
  mutually exclusive with `--hmac-key` and `--hmac-key-file`, and the
  single-key path still works. The reflector reads the incoming packet's SSID,
  resolves the per-SSID key and uses it for both verification and the
  response HMAC.
- **Per-client token-bucket rate limiting.** `RateLimiter` is a token bucket
  keyed by `(source_ip, ssid)` instead of a fixed-window counter.
  `--reflector-rate-burst` sets the bucket capacity independently of
  `--max-pps`, which still means tokens per second; `burst = 0` falls back to
  `rate` for backward compatibility. A `packets_rate_limited` counter
  separates rate-limit drops from other drops in metrics and SNMP. Each extra
  Reflected Test Packet Control (Type 12) copy consumes one token, and the
  burst stops early when the bucket is empty, so an asymmetric burst cannot
  exceed the per-client budget.
- **Reflected Test Packet Control (Type 12) aligned with draft-14.** The
  reflector honors the requested reply length by inserting an
  `ExtraPaddingTlv` ahead of the HMAC TLV, up to a configurable cap. It parses
  the Layer-3 Address Group sub-TLV (Type 11) and drops the packet (through
  `ReturnPathAction::SuppressReply`) when no local address matches the
  requested prefix (draft §3). It parses the Layer-2 Address Group sub-TLV
  (Type 10) and sets the U flag on the echoed Type 12 when MAC visibility is
  not available (UDP socket backends). `--reflected-control-max-count`,
  `--reflected-control-max-size` and `--reflected-control-min-interval-ns`
  expose the amplification caps, which were compile-time constants, as
  runtime configuration. The minimum value-field size is 12 octets instead of
  8 (draft §3); the encoder zero-pads short emissions to 12 bytes (a
  placeholder sub-TLV header) so existing single-TLV senders stay on the wire.
- **draft-ietf-ippm-stamp-ext-hdr-08 Type 247 length-mismatch handling.** The
  Reflected Fixed Header Data TLV's Length must equal 20 (IPv4) or 40 (IPv6)
  (§5.2). If the sender's requested Length does not match the captured header
  size (for example a 20-byte request reaching an IPv6 reflector), the
  reflector zero-fills the Value and sets the U flag rather than truncating or
  padding. `log_reflected_hdr_length_mismatch_once` emits a one-time warning
  citing draft §5.2.
- **Structured logging with `tracing-subscriber`.** `--log-format text|json`
  selects human-readable single-line output (the default) or one JSON object
  per event, for Fluent Bit, Vector or journald JSON forwarding. `tracing-log`
  bridges existing `log::*` call sites. `RUST_LOG` controls verbosity in both
  modes.
- **`--print-config-schema`** prints a hand-maintained JSON Schema (draft
  2020-12) for the `FileConfiguration` accepted by `--config`. Use it with the
  `jsonschema` CLI or an IDE plugin for autocompletion and validation before
  deployment. A coverage test fails when a TOML field has no schema property.
- **Hardware timestamping scaffold.** A `hwtstamp` Cargo feature (off by
  default), `--hwtstamp auto|on|off`, a `crypto::HwTsMode` enum, a capability
  probe stub and an `effective_method` resolver that picks `HwAssist` or
  `SwLocal` per direction. `auto` (the default) falls back to software
  silently when the kernel or NIC does not advertise support, `on` fails at
  startup, and `off` always uses software. The kernel-side `SO_TIMESTAMPING`
  and `MSG_ERRQUEUE` wiring was left for a later release; the public API is in
  place so call sites do not change when it lands.
- **Capture-thread liveness signal.** `ReceiverSharedState` has a
  `capture_alive: Arc<AtomicBool>`. Both backends clear it when their receive
  loop exits unexpectedly (interface not found, channel initialization
  failure, send-socket bind failure, `spawn_blocking` panic), so a readiness
  probe or systemd's `MonitorPolicy` can tell "process alive but not
  reflecting" from "process alive and healthy". The pnet capture path logs
  with `log::error!` and `log::warn!` instead of `eprintln!`.
- **AgentX sub-agent panic resistance.** Every `unwrap()`, `panic!` and
  `unreachable!()` reachable from the AgentX event loop
  (`agentx::decode_header`, `decode_oid`, `decode_search_range`,
  `handle_get_bulk`, `MibHandler::get` and `get_next`) was checked: each
  buffer index is preceded by an explicit length check that returns
  `AgentXError::Protocol`. A supervisor task observes the `spawn_blocking`
  JoinHandle, so an unexpected panic logs `JoinError::is_panic()` instead of
  being dropped. The module documentation in `src/snmp/mod.rs` records the
  result.
- **Observability failure semantics.** `--metrics` fails at startup on a bind
  error and names the `io::ErrorKind` (AddrInUse, AddrNotAvailable,
  PermissionDenied) in the exit message. `--snmp` logs a warning and continues
  when the AgentX master is missing. A silently disabled metrics endpoint
  leaves dashboards blind, while a disabled SNMP sub-agent does not affect the
  reflector's main job. Documented in `doc/usage.md`.
- **Malformed-input tests:** 12 hand-crafted hostile byte sequences across
  base packet length boundaries (RFC 8762 §4.1.x), TLV header length abuses
  (overflow, u16::MAX, truncated header), HMAC ordering violations (TLV after
  HMAC, wrong-length HMAC value, corrupted digest giving the I flag on every
  TLV per §4.8), Return Path sub-TLV nesting overflow, and high-entropy spot
  checks. The implementation handled every case correctly; no production code
  changed.
- **TLV flag semantics tests:** 15 tests pin the RFC 8972 §3/§4.8 and
  draft-asymmetrical §3 U/M/I/C bit positions (0x80/0x40/0x20/0x10),
  unknown-type echo with U, length mismatch with M, HMAC failure with I on
  every TLV (the packet is still echoed), Reflected Control clamping with C,
  and flag-independence negative controls.
- **BER on-wire tests:** 6 tests cover a clean channel, a single-bit flip, an
  intra-byte 3-bit burst, a cross-byte 4-bit burst (exercising the MSB-first
  bit walker), sender hex-dump verification and a custom non-default pattern.
- **PTP timestamp end-to-end tests:** 6 tests cover the wire encoding
  difference (NTP versus PTP epoch offset), Type 3 TLV `sync_src_out`
  reporting with PTP and NTP reflector modes, preservation of the
  sender-declared sync source in mixed mode, and big-endian timestamp
  placement at byte offset 4..12.
- **Statistics edge-case tests:** 10 tests cover RFC 3550 jitter on
  single-sample, zero-jitter, negative-skew and alternating patterns, the
  two-sample standard deviation boundary, large-RTT u128 overflow safety,
  percentile of an empty set and out-of-range p, a single-sample percentile
  off-by-one, and the zero-sent `loss_percent` NaN guard.
- **IPv6 TLV parity tests:** 10 tests drive every major reflector code path
  with an IPv6 source: unauthenticated and authenticated round trips, CoS
  DSCP/ECN echo, RFC 9503 Destination Node Address match and mismatch,
  Micro-session ID, the BER TLVs, Location sub-TLVs, combined authentication
  and CoS, and unknown-TLV U flag.
- **Multi-key HMAC integration tests:** 6 tests cover single-key mode with
  SSID 0 and non-zero SSIDs, the per-SSID happy path, rejection of the wrong
  key for an SSID, unknown SSID with `require_hmac` (dropped), and default-key
  fallback for missing per-SSID entries.
- **pnet backend integration tests:** 3 `#[ignore]`d tests start a real pnet
  receiver on the `lo` interface and round-trip open mode, authenticated mode
  and a TLV chain. They skip themselves when the process lacks `CAP_NET_RAW`
  and require `target_os = "linux"`, `feature = "ttl-pnet"` and not
  `ttl-nix`. `tests/README.md` documents the privileged invocation.
- **AgentX malformed-PDU tests:** 8 tests on the public decoders and 4
  OID-boundary tests on the handler dispatch confirm that every buffer index
  is bounds-checked.
- **Rate-limit isolation tests:** 7 tests cover burst exhaustion, multi-client
  isolation (a greedy client does not drain a polite one), per-SSID isolation
  (same IP with different SSIDs gets independent buckets), atomic `allow_n`,
  sustained-rate refill, backward-compatible `burst = 0` and expired-bucket
  reaping.
- **`--strict-packets` contract tests:** 7 tests pin the lenient versus strict
  behavior for short, full and empty buffers in both modes, MBZ always ignored
  (RFC 8762 §4.1.1), and `require_hmac` interactions.
- **Property-based and libFuzzer harnesses.** 16 proptest cases (run by the
  default `cargo test`) cover typed TLV round trips and no-panic invariants on
  arbitrary bytes for every parser. Seven cargo-fuzz targets under `fuzz/`
  (excluded from the workspace, nightly only) exercise the same code paths.
  The `fuzz.yml` workflow (manual or weekly cron) builds and runs each target
  for 60 s and uploads `fuzz/artifacts/` and `fuzz/corpus/` on failure.
- **Criterion benchmark suite.** `benches/reflector_hotpath.rs` measures
  `process_stamp_packet` end to end without UDP: open mode with no TLVs
  (about 100 ns/op), one TLV, a full chain, the authenticated HMAC success
  path, and an authenticated full chain. Reference numbers are in
  `doc/architecture.md` for regression triage.
- **`mib-lint` CI job.** It runs `smilint -l 4` against
  `mibs/STAMP-SUITE-MIB.mib` on every push and pull request. The package
  install tries `smitools` (Ubuntu 24.04 and later) and falls back to
  `libsmi2-bin` on older images.

### Changed

- `process_auth_packet` takes an explicit `resolved_hmac_key` parameter that
  `process_stamp_packet` sets after a per-SSID lookup, instead of reading
  `ctx.hmac_key` directly. The `HmacKeySet` path needs this; the single-key
  path is unchanged because the legacy field still feeds `resolve_hmac_key()`
  when no key set is configured.
- A `REFLECTED_CONTROL_TLV_FIXED_FIELDS_SIZE` constant, added with the
  12-octet minimum, lets the parser address the fixed header (length, count,
  interval) and the sub-TLV chain separately without re-deriving the offset.
- The TLV reference table in `doc/architecture.md` uses the labels supported,
  partial, experimental and interop-only. Type 10 is partial (SR-MPLS and
  SRv6 are echoed with the U flag), Type 12 is supported after the draft-14
  alignment above, and Types 246 and 247 are partial (pnet backend only).
  Type 242 is documented as colliding on the wire with teaparty's Heartbeat
  use of the same byte; both implementations are in the experimental range,
  so neither is wrong per IANA, but mixed deployments need to pick one.
- `doc/architecture.md` is reorganized, with an Operational Characteristics
  section (the `--strict-packets` contract, `capture_alive` semantics, metrics
  failing at startup versus SNMP continuing, the AgentX panic-resistance
  results and the `--hwtstamp` modes), a Hardware-Assisted Timestamping
  section, a Benchmarks section and an updated TLV table.
- Windows test and release-build jobs are pinned to `windows-2022` instead of
  `windows-latest`. The `windows-2025` image dropped the bundled tooling that
  satisfied pnet's load-time `wpcap.dll` and `Packet.dll` imports, and the
  Npcap silent installer hangs on Server 2025 (UAC and driver-signing
  prompts). The long-term fix is to gate pnet behind a Cargo feature on
  Windows.

### Fixed

- **Layer-2 Address Group without MAC visibility** (RFC 8972 §3,
  `set_reflected_control_u_flag`). When a Layer-2 Address Group sub-TLV
  arrives on a backend without MAC visibility, the reflector sets the U flag
  on the echoed Type 12 TLV and continues processing. The sub-TLV used to be
  ignored silently, which gave the sender no signal that the filter was not
  honored.

## [0.7.0] - 2026-05-04

### Added

- **Reflected Fixed and IPv6 Extension Header Data TLVs (Types 247 and 246,
  draft-ietf-ippm-stamp-ext-hdr).** The sender can ask the reflector to echo
  the raw bytes of the received IP fixed header (Type 247: 20 bytes for IPv4,
  40 bytes for IPv6) and the IPv6 Hop-by-Hop and Destination Options extension
  headers (Type 246). This allows end-to-end diagnosis of DSCP remarking, TTL
  decrement, Flow Label rewriting and in-path tampering with IPv6 options.
  - Typed TLVs `ReflectedFixedHdrTlv` and `ReflectedIpv6ExtHdrTlv` implement
    `TypedTlv`, with `TlvType::ReflectedFixedHdr` and `ReflectedIpv6ExtHdr`
    variants. Length validation treats the Value as variable-length: the
    sender pre-allocates a zero-filled Value sized to the expected header
    length (per draft-ietf-ippm-stamp-ext-hdr), and the response carries the
    populated bytes.
  - A `CapturedHeaders` struct is passed through `ProcessingContext`, so the
    reflector's TLV processing can see the raw IP-layer bytes captured at
    receive time.
  - `TlvList::process_reflected_headers()`, called from
    `apply_semantic_tlv_processing`, copies the captured bytes into the TLV or
    sets the U flag when the backend cannot observe the IP layer.
  - The `pnet` backend fills `CapturedHeaders` from `Ipv4Packet` and
    `Ipv6Packet` and walks Hop-by-Hop (NextHeader 0) and Destination Options
    (NextHeader 60) headers in wire format (NextHeader byte, HdrExtLen byte,
    body, per RFC 8200). Other headers (Routing, Fragment, ESP, AH) stop the
    walk, matching the draft's scope. For IPv4, only the fixed 20-byte header
    is copied; IPv4 options are dropped on purpose.
  - The `nix` backend passes `captured_headers: None`. The reflector echoes the
    TLV empty with the U flag set (RFC 8972 §4.2) and logs a one-time warning
    suggesting a rebuild with `--features ttl-pnet` if header reflection is
    needed. An empty Value on an IPv4 packet, or on an IPv6 packet without
    extension headers, is legitimate and does not set the U flag.
  - Sender options `--reflected-fixed-hdr` and `--reflected-ipv6-ext-hdr`,
    with matching `FileConfiguration` TOML fields. The sender attaches a
    zero-filled request TLV sized to the destination's IP family for Type 247,
    and an 8-byte default (one option) for Type 246. The reflector fills them
    on the pnet backend or sets U on nix.
- `doc/usage.md`, `doc/architecture.md` and `doc/security.md` hold the
  detailed documentation, and the README is a short landing page of about 200
  lines:
  - `doc/usage.md`: the TOML configuration file format, supported keys,
    validation behavior and the full grouped CLI option reference.
  - `doc/architecture.md`: module layout, receiver backends, the packet
    processing pipeline, session management, the full TLV reference, and the
    Prometheus and SNMP subsystems.
  - `doc/security.md`: the threat model, HMAC and TLV integrity, key sourcing
    precedence (including the `STAMP_HMAC_KEY` and `hmac_key_file` mutual
    exclusion caveat), configuration and key file permissions, the `stamp`
    system user, an annotated walkthrough of the systemd unit's hardening
    directives, the capability model, and a step-by-step procedure for
    switching the packaged systemd unit from open to authenticated mode before
    exposing UDP port 862. A top-level `SECURITY.md` points to it for GitHub
    discovery.
- The README has a Receiver Backends section. It explains the two capture
  paths (nix UDP socket with cmsg, pnet datalink capture), why `nix` is the
  default on Linux and macOS (unprivileged execution, no libpcap runtime
  dependency, kernel-side UDP demultiplexing, firewall integration,
  kernel-handled checksums, fragmentation and ARP, socket observability), and
  the tradeoff (TLVs 246 and 247 only on the pnet backend, and two capture
  loops to maintain).

### Changed

- **Breaking:** when filling Type 246 and 247 responses, the reflector keeps
  the Length the sender advertised, zero-padding short captures and truncating
  long ones. Callers that relied on the response length matching the
  captured length should size the request accordingly.
- `build_local_addresses` is shared between backends. The interface address
  enumeration used for Destination Node Address TLV matching (RFC 9503 §4)
  was duplicated in `receiver/nix.rs` and `receiver/pnet.rs`. It is one
  `receiver::build_local_addresses()` with `cfg(unix)` and `cfg(not(unix))`
  internals (`nix::ifaddrs::getifaddrs` on Unix,
  `pnet::datalink::interfaces` on Windows), which removes about 60 lines of
  near-duplicate code and a class of drift bugs.
- `--micro-session-id` and `--reflector-member-link-id` (RFC 9534 LAG
  identifiers) accept `0x`-prefixed hex (`0xff`, `0XFF`, `0x00ab`) as well as
  decimal, the usual way these wire fields are written.
- Cargo packaging (`cargo deb` and `cargo generate-rpm`) installs the three
  documents in `/usr/share/doc/stamp-suite/` next to `README.md`.

### Removed

- **Breaking:** `ReflectedFixedHdrTlv::request()` is removed. Use
  `ReflectedFixedHdrTlv::request_for(IpAddr)`, which picks 20 or 40 bytes from
  the destination address family, or
  `ReflectedFixedHdrTlv::request_with_capacity(usize)` for an explicit
  zero-fill size. The old API produced an empty-Value TLV that did not match
  the draft's request format.
- **Breaking:** `ReflectedIpv6ExtHdrTlv::request()` is removed. Use
  `ReflectedIpv6ExtHdrTlv::request_with_capacity(usize)`, so the caller picks
  the zero-filled Value size to match the path's expected extension header
  chain. The default size for `--reflected-ipv6-ext-hdr` is
  `tlv::DEFAULT_IPV6_EXT_HDR_REQUEST_CAPACITY` (8 bytes, one option).

### Fixed

- **Sender flag default** (RFC 8972 §4). `TlvFlags::for_sender()` returns
  `U=1, M=0, I=0` instead of all zeroes. The RFC requires the Session-Sender
  to send every TLV with the U flag set; the reflector then overwrites it.
  Sender-built TLVs (`RawTlv::new`) inherit the corrected default. On the
  wire, the leading flag byte of every outgoing TLV changes from `0x00` to
  `0x80`.
- **Reflector flag overwrite** (RFC 8972 §4). The reflector clears U, M and I
  on every parsed TLV before the type recognition, length validation and HMAC
  verification pass re-derives them. Each flag used to be only ever set to 1,
  but the RFC's three "Otherwise … MUST set … to 0" clauses require clearing
  them as well. As a result, an echoed CoS TLV (or any other recognized type)
  reports `U=0` to the sender even when the sender followed the requirement to
  send `U=1`. The C flag (`conformant_reflected`,
  draft-ietf-ippm-asymmetrical-pkts) and the M flag for parser-detected
  truncation are preserved across the clear.
- **Type 246 and 247 sender request encoding**
  (draft-ietf-ippm-stamp-ext-hdr). The Session-Sender pre-allocates the Value
  with zeros sized to the expected header length (20 for the IPv4 fixed
  header, 40 for the IPv6 fixed header, 8 bytes for the IPv6 extension header
  chain), as the draft requires. It used to send Length 0, which conforming
  reflectors that validate the request's Length rejected as malformed.

## [0.6.1] - 2026-04-22

### Changed

- The `toml` dependency is updated from 0.9 to 1.1.

## [0.6.0] - 2026-04-22

### Added

- **TOML configuration file** (`--config <PATH>`). Every CLI option can be set
  in a TOML file, so long-lived deployments (systemd units, reflectors,
  reproducible test rigs) do not need long command lines.
  - The `FileConfiguration` struct mirrors `Configuration` with all fields
    optional. Unknown keys are rejected at parse time (`deny_unknown_fields`),
    so typos are reported with the full list of valid keys.
  - Precedence: command-line option or `STAMP_HMAC_KEY` environment variable,
    then the TOML file value, then the built-in default. The source is
    detected with `clap::ArgMatches::value_source`, so one `Configuration`
    struct serves both sources.
  - `Configuration::load()` parses the CLI, merges the optional TOML file and
    runs `validate()`. `main.rs` uses it instead of `Configuration::parse()`.
  - A plaintext `hmac_key` is not part of the file schema; only
    `hmac_key_file` is accepted, so secrets cannot leak into a shared
    configuration.
  - On Unix, a warning is logged if the configuration file is writable by
    group or other (mask `0o022`), like the existing check on
    `--hmac-key-file`.
  - `Configuration::validate()` checks the ranges of `dscp` (0-63), `ecn`
    (0-3), `access_report` (0-15), `micro_session_id` (>=1) and
    `reflector_member_link_id` (>=1), because clap's CLI-side
    `value_parser!().range()` does not run on values read from TOML.
  - New dependency `toml = "0.9"`; new dev-dependency `tempfile = "3"`.
  - `AuthMode`, `ClockFormat`, `TlvHandlingMode` and `OutputFormat` derive
    `serde::Deserialize`, with renames matching their `ValueEnum` string forms.
- **Reflected Test Packet Control TLV (Type 12,
  draft-ietf-ippm-asymmetrical-pkts)** for asymmetrical reply measurement.
  - `ReflectedControlTlv` struct (Length, Count, Interval and opaque sub-TLV
    bytes).
  - The reflector sends up to `REFLECTED_CONTROL_MAX_COUNT` (16) reply packets
    per request, spaced by the requested interval (clamped to
    `REFLECTED_CONTROL_MIN_INTERVAL_NS`, 1 µs). An excess count, a clamped
    interval or any non-zero requested length sets the Conformant (C) flag on
    the echoed TLV.
  - The nix backend sends extra copies from a spawned tokio task so the
    receive loop is not blocked; the pnet backend sleeps inline (fallback
    platforms only).
  - A C flag bit (0x10) in `TlvFlags` and `RawTlv::set_conformant_reflected()`.
    The draft leaves the C bit position TBA; this implementation uses bit 3,
    the first bit not used by RFC 8972's U/M/I flags.
  - Sender options `--reflected-control-count`, `--reflected-control-length`
    and `--reflected-control-interval-ns`.
- **BER TLVs (draft-gandhi-ippm-stamp-ber).**
  - Bit Pattern in Padding (Type 240), Bit Error Count in Padding (Type 241)
    and Max Bit Error Burst Size (Type 242). The draft leaves the type numbers
    TBD; 240/241/242 come from RFC 8972's experimental range.
  - The reflector XORs the received Extra Padding against the Bit Pattern TLV
    (or the draft's 0xFF00 default), counts error bits and the longest run of
    consecutive errors across byte boundaries, and writes the results into the
    Count and Max Burst TLVs.
  - Missing Extra Padding or duplicate BER TLVs mark all BER TLVs with the U
    flag (draft §3).
  - Sender options `--ber`, `--ber-pattern <HEX>` and `--ber-padding-size`.
- **Micro-session ID TLV (RFC 9534)** for per-member-link performance
  measurement on LAGs.
  - Micro-session ID TLV (Type 11) with sender and reflector member link
    identifiers.
  - Sender option `--micro-session-id <ID>` identifies the local LAG member
    link.
  - Reflector option `--reflector-member-link-id <ID>` fills in the reflector
    member link ID.
  - The reflector validates a non-zero reflector ID in the received TLV and
    discards the packet on mismatch (RFC 9534 §3.2).
  - `MicroSessionIdTlv` struct with `new`, `from_raw` and `to_raw`, and
    `TlvList::update_micro_session_id_tlvs()`.
- `SenderSnmpStats::inc_lost_by(count)` for batched loss counter updates.
- `record_packets_lost(count)` batch metrics API for sender loss events.

### Changed

- Sender timeout eviction uses an O(k) `VecDeque`-based lazy eviction queue
  instead of an O(n) scan of the whole HashMap. Deadlines are naturally in
  time order because packets are sent sequentially.
- Final sender loss accounting uses the batched `inc_lost_by()` and
  `record_packets_lost()` instead of per-packet loops.
- Reflector TLV semantic processing (CoS, Timestamp Info, Direct Measurement,
  Location, Follow-Up Telemetry, Destination Node Address, Micro-session ID,
  Return Path, HMAC recomputation) is in a shared
  `apply_semantic_tlv_processing()` helper, which removes the duplication
  between `assemble_unauth_answer_with_tlvs` and
  `assemble_auth_answer_with_tlvs`.
- `TlvList::validate_known_tlv_lengths()` uses a shared
  `validate_known_tlv_lengths_slice()` helper that operates on both `tlvs` and
  `wire_order_tlvs`.
- `TlvList::update_micro_session_id_tlvs()` uses a shared
  `apply_micro_session_id()` helper for both TLV vectors.

### Removed

- `SenderStatsSnapshot` and `SenderSnmpStats::update_from_snapshot()`. All
  sender SNMP counters are updated live, so the final-snapshot path was dead
  code.

### Fixed

- AgentX OID decoding (`decode_oid`) requires at least 8 bytes instead of 4,
  which prevents a panic when reading the `prefix` and `include` fields from
  short buffers.
- AgentX OID decoding uses `checked_mul` and `checked_add` for the expected
  buffer length, which prevents overflow on 32-bit targets with crafted wire
  data.
- The sender's interim report (`--report-interval`) uses the confirmed
  `packets_lost` counter instead of `pending.len()`, which counted in-flight
  packets as lost.
- SNMP `loss_pct_x100` is computed on read instead of cached, so it does not go
  stale when `packets_sent` increases without new loss events.

## [0.5.0] - 2026-02-13

### Added

- **SNMP AgentX sub-agent** for MIB-based monitoring through net-snmpd
  (requires the `snmp` feature, Unix only).
  - A minimal AgentX implementation (RFC 2741) with no external SNMP crate.
  - STAMP-SUITE-MIB under enterprise OID `.1.3.6.1.4.1.65134`, with an SMIv2
    definition in `mibs/STAMP-SUITE-MIB.mib`.
  - Reflector subtree: configuration scalars, packet counters (received,
    reflected, dropped), active session count and uptime.
  - Session table: per-client address, port, packet counts, last sequence
    number and last active time.
  - Sender subtree: configuration scalars, packets sent, received and lost,
    RTT min/max/avg, jitter and loss percentage.
  - Sender statistics (received, RTT min/max/avg, jitter) are updated in the
    hot path, so SNMP polling during long runs shows current progress.
  - `--snmp` and `--snmp-socket <PATH>` options.
- `SessionManager::session_summaries_extended()` returns per-session state.
- `ReceiverSharedState` shares counters and the session manager between the
  receiver backends and SNMP.

### Changed

- The receiver backends (`nix.rs`, `pnet.rs`) take `&ReceiverSharedState`
  instead of creating their own `Arc<ReflectorCounters>` and
  `Arc<SessionManager>`.
- `run_sender` accepts an optional `Arc<SenderSnmpStats>` (behind the `snmp`
  feature) for live statistics export.

### Fixed

- The pnet backend no longer drops valid fallback responses for Return Path
  alternate IPv6 targets. An early return that bypassed the `try_send` and
  U-flag fallback path is removed.
- The `snmp` feature is gated with `cfg(unix)`. On other platforms, `--snmp`
  prints a clear error and exits instead of failing to compile.

## [0.4.0] - 2026-02-11

### Added

- **RFC 9503 Segment Routing extensions** for SR-MPLS and SRv6 networks.
  - Destination Node Address TLV (Type 9): the sender names the intended
    reflector address, and the reflector sets the U flag on a mismatch.
  - Return Path TLV (Type 10) with sub-TLVs:
    - Control Code sub-TLV: suppress the reply (code 0) or request a
      same-link reply (code 1). Reserved bits are ignored, per RFC 9503.
    - Return Address sub-TLV: the reflector sends the reply to an alternate IP
      address.
    - SR-MPLS Label Stack sub-TLV: MPLS LSE encoding (Label, TC, S, TTL),
      echoed with the U flag (userspace SR forwarding is not supported).
    - SRv6 Segment List sub-TLV: echoed with the U flag (userspace SR
      forwarding is not supported).
  - Sender option `--dest-node-addr <IP>` (requires `--ssid`).
  - Sender option `--return-path-cc <CODE>` (0 = suppress, 1 = same link).
  - Sender option `--return-address <IP>` for an alternate reply address.
  - Sender option `--return-sr-mpls-labels <LABELS>` (comma-separated 20-bit
    labels).
  - Sender option `--return-srv6-sids <SIDS>` (comma-separated IPv6 SIDs).
- If sending to the alternate address fails, the reflector sets the U flag on
  the Return Path TLV, recomputes the HMAC and retries to the original source
  address.
- Local address enumeration for Destination Node Address matching (nix:
  `getifaddrs`, pnet: `datalink::interfaces`).

### Changed

- `ProcessingContext.local_addresses` is `&[IpAddr]` instead of
  `Vec<IpAddr>`, which avoids cloning per packet in the hot path.

### Fixed

- SR-MPLS labels are encoded as MPLS Label Stack Entries
  (`Label<<12 | TC | S | TTL`) instead of raw u32 values.
- Return Path Control Code decoding masks with `cc & 1` instead of rejecting
  reserved bits, per RFC 9503.
- `--return-sr-mpls-labels` and `--return-srv6-sids` conflict with each other
  at the CLI level.

## [0.3.1] - 2026-02-08

### Changed

- Multiple optimizations and refactorings.

## [0.3.0] - 2026-02-08

### Added

- **RFC 8972 TLV extensions.**
  - A `tlv` module with `TlvFlags`, `TlvType`, `RawTlv`, `TlvList`,
    `ExtraPaddingTlv`, `HmacTlv` and `SessionSenderId` types.
  - TLV handling modes: `ignore` (strip TLVs) and `echo` (reflect TLVs with
    the appropriate flags).
  - `--tlv-mode` selects the TLV handling mode (default: `echo`).
  - `--verify-tlv-hmac` verifies the incoming TLV HMAC.
  - `--ssid` makes the sender include a Session-Sender Identifier in the Extra
    Padding TLV.
  - HMAC TLV (Type 8) for TLV integrity verification.
  - Flag handling: U flag for unrecognized types, M flag for malformed TLVs,
    I flag for integrity failures.
- Extended packet types: `ExtendedPacketAuthenticated`,
  `ExtendedPacketUnauthenticated` and their reflected variants.
- Lenient packet parsing with `from_bytes_lenient()` for short-packet
  interoperability (RFC 8762 §4.6).
- Canonical buffers for HMAC verification of zero-padded short packets.
- Wire-order preservation for TLV failure echo paths (RFC 8972 §4.8).
- Byte-exact echo of truncated TLVs: the original wire length is kept in the
  header of a malformed TLV.
- Sender-side TLV validation with the `validate_reflected_tlvs()` helper.
- Configuration validation: `--verify-tlv-hmac` requires `--hmac-key` or
  `--hmac-key-file`.

### Changed

- **Breaking:** `auth_mode` accepts exactly `A` (authenticated) or `O` (open).
  Composite strings like `AO` are invalid, because the modes are mutually
  exclusive (RFC 8762). `is_auth()` and `is_open()` use exact string matching
  instead of substring search.
- The receiver assembly functions handle TLV extensions.
- Both `nix` and `pnet` receiver backends process TLV-aware packets.
- HMAC verification in authenticated mode uses canonical zero-padded buffers.

### Removed

- The unsupported `process` TLV handling mode is removed from the
  documentation.
- The `E` (encrypted) auth mode option is removed; RFC 8762 does not define
  it.

### Fixed

- Sender TLV-HMAC validation uses a fixed base offset (44 or 112 bytes)
  instead of inferring it from the packet length.
- Short authenticated packets are zero-filled before HMAC verification.
- Malformed TLVs are echoed byte-exactly, with the original declared length
  preserved.

## [0.2.0] - 2026-02-03

### Added

- Multi-session support in the reflector with `SessionManager`.
- Stateful reflector mode (`--stateful-reflector`) per RFC 8972.
- Session timeout configuration (`--session-timeout`).
- HMAC authentication with `--hmac-key` and `--hmac-key-file`.
- `--require-hmac` to require HMAC verification.
- Error estimate configuration (`--error-scale`, `--error-multiplier`,
  `--clock-synchronized`).
- Integration tests on the loopback interface.
- RFC 8762 compatibility improvements.

### Changed

- Packet serialization uses big-endian encoding.
- Error handling is improved throughout the codebase.

## [0.1.0] - 2022-03-10

This entry covers versions 0.1.0 to 0.1.3 (2022-03-10 to 2024-06-03).

### Added

- Initial implementation of the STAMP protocol (RFC 8762).
- Session-Sender and Session-Reflector modes.
- Unauthenticated and authenticated packet formats.
- NTP and PTP timestamp support.
- IPv4 and IPv6 support.
- Basic RTT and packet loss statistics.
- CLI built with clap.
