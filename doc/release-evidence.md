# Release verification

Release claims should name the tested revision, build features, platform and
wire profile. The [conformance matrices](conformance/README.md) cover frozen
specifications; successful compilation or an ignored test is not runtime proof.
The [remediation record](reviews/2026-09-08/progress.md) contains checkpoint
commands, raw results and limitations. O11 adds the following release checks.

## Authenticated control and a reference SNMP master

On Linux with Python 3.10+, OpenSSL and Net-SNMP tools available:

```sh
cargo build --locked --all-features
python3 scripts/release_checks.py --binary target/debug/stamp-suite --report /tmp/release-integration.json
```

The script runs four control cases (IPv4/IPv6 × HTTP/HTTPS) and one reference
SNMP case. `--only control` or `--only snmp` selects an explicit subset, which
is recorded in `expected_cases`. All selected cases must pass; missing tools
are errors. Reports retain commands, logs, HTTP responses, UDP payloads,
Net-SNMP queries, binary/runner hashes, counts and completion state. These are
temporary fixture keys, tokens and communities, never production credentials.

Control checks use the real binary and HTTP server, a mode-0600 token file,
and independently encoded/authenticated UDP traffic. They verify:

- Missing or incorrect bearer tokens cannot read status or mutate keys.
- HTTP key replacement during a burst affects new requests; accepted queued
  copies retain the old key and valid signatures after SRv6 U-flag fallback.
  Their software T3 must be after the successful HTTP rotation acknowledgement;
  already-transmitted copies cannot satisfy this check.
- The old key is rejected, the replacement works without resetting session
  sequencing, deletion revokes access, and default-key insertion/removal affects
  both an existing SSID and a new one.
- Key inventory omits secret bytes, and authenticated shutdown exits cleanly.

HTTPS cases generate a temporary self-signed certificate with an IP SAN. The
client trusts that certificate explicitly and performs normal certificate and
endpoint validation; verification is never disabled. This tests the TLS server
and bearer authentication, not mTLS or an external CA deployment.

The Net-SNMP fixture launches its own `snmpd` in the foreground on an ephemeral
IPv4 loopback port, with a private AgentX socket and persistence directory.
The configuration limits its read-only community to the STAMP enterprise
subtree. It neither reads system daemon configuration nor starts/stops an
existing service. The real stamp-suite subagent registers with that master.
Independent `snmpget`, `snmpwalk`, `snmpbulkget` and `snmpgetnext` clients check
initial/live counters, two session rows across seven columns, repeater ordering
and the end-of-MIB boundary. The fixture restarts only its own master, confirms
that authenticated STAMP still reflects while it is down, then verifies
re-registration with counters/session state preserved.

Net-SNMP master configuration and process isolation follow its
[AgentX guide](https://www.net-snmp.org/docs/README.agentx.html) and
[snmpd options](https://www.net-snmp.org/docs/man/snmpd.html).
This complements the [independent AgentX framing fixtures](conformance/agentx-review.md);
it does not certify every SNMP version, context, byte order or writable MIB.

`conformance.yml` gates all five cases. Its Ubuntu job downloads and extracts
Net-SNMP packages/dependencies into `/tmp`, with no package installation or
system-service startup. Locally installed tools also work. The September 11
local run used Ubuntu packages `5.9.4+dfsg-2ubuntu3`; the daemon itself reports
`5.9.4.pre2`. Both identities belong in the evidence, rather than silently
normalizing the version string. All five cases passed on Linux/WSL2.

## Windows runtime gate

`rust.yml` now requires seven explicit runtime test targets on Windows:
configuration files, malformed input, TLV properties, mixed clocks, required
micro-session validation, SSID validation and sender measurement summaries.
These exercise codecs and UDP sender peers without running a capture reflector.
The job retains pinned Npcap SDK/runtime downloads and validates the staged
DLLs' x64 PE machine type. Missing DLLs or a failed core test fail the job.
Its full-suite step remains informational because a capture-driver fixture is
not installed. Both logs are uploaded.

The same seven targets can be selected explicitly:

```sh
cargo test --locked --no-default-features --features ttl-pnet \
  --test config_file_test --test malformed_input_test --test proptest_tlv \
  --test mixed_clock_test --test required_micro_session_test \
  --test session_ssid_validation_test --test sender_measurement_test
```

The workflow definition is the new gate; this Linux checkpoint is not a Windows
execution result. A release claiming Windows runtime coverage should retain
the successful Windows core artifact for its exact commit. Raw capture and
hardware timestamp support have separate platform limits. Repository branch
protection is administered separately from these workflow definitions.

## Hardware timestamps

Use the [two-host hardware procedure](testing-hardware-timestamps.md) on a
controlled testbed with capable NICs. The O11 host's `ethtool -T eth0` reports
software timestamps only and no PHC, so no hardware success is recorded here.

## Standards revision monitor

[`standards.json`](conformance/standards.json) pins four implemented draft
revisions and six RFC metadata records. The checker queries the public IETF
Datatracker document API and RFC Editor JSON, validates document identity and
required fields, and saves source JSON plus SHA-256. Draft pins must also match
their matrix text. New revisions, RFC publication, expiry, or changes to an RFC's
status/update/obsolescence relationships request review. Expiry within 14 days
is an advisory warning. Network failures and malformed/missing evidence never
count as unchanged.

```sh
python3 scripts/check_standards.py --report /tmp/standards.json --cache /tmp/standards-source
python3 scripts/check_standards.py --offline /tmp/standards-source \
  --as-of 2026-09-11 --report /tmp/standards-replay.json
```

Exit codes: **0** current, **1** specification review needed, **2** incomplete
check. Offline mode replays saved observations; it does not establish the latest
revision. `standards.yml` runs weekly and on demand, uploading results even on
failure. It does not edit pins, open issues or send messages. Only reviewed
implementation/matrix changes should update the frozen draft revision. The
monitor does not automatically audit normative text, IANA code points or errata;
release review should check each RFC's linked errata page and retain the result.

The September 11 run detected **ext-hdr -13 versus implemented -11** and an
approaching asymmetrical-pkts expiry. The [delta review](conformance/ext-hdr-13-review.md)
records new requirements and current limits. The monitor deliberately continues
to return **1** for this known drift; its alert is evidence, not a passing
conformance result. RFC 8545 and RFC 2741 baselines use the verified RFC Editor
statuses, Proposed Standard and Draft Standard respectively.

STAMP YANG management and full TWAMP-Control remain explicit product scope
choices. This release-evidence work does not add either feature or turn them
into automatic implementation backlog. A future draft revision likewise needs
an explicit adoption review; it does not retroactively change what the frozen
matrix claims to have checked.
