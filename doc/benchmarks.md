# Measuring reflector performance

The in-process Criterion benchmarks isolate parsing, authentication, TLV
processing and reply assembly. The live UDP benchmark adds the receive and send
syscalls, session locks and the scheduler, and checks that the reflector goes
back to sleep once traffic stops. Use both.

## Live UDP on Linux

Build the reflector and the load generator together, with the same feature
flags:

```bash
cargo build --locked --release --bin stamp-suite --example live_udp_bench
target/release/examples/live_udp_bench --rate 10000 > live-ipv4-open.json
target/release/examples/live_udp_bench --rate 10000 --ipv6 --authenticated \
  --stateful > live-ipv6-auth-stateful.json
```

Each invocation runs three trials in sequence, each against a fresh reflector.
A trial uses one loopback session: a readiness probe, 2 s idle, a probe, 3 s of
load, a 500 ms drain, 2 s idle, and a final verified probe. Probe traffic is
not counted in the load numbers. By default packets are 44 bytes in open mode
or 112 bytes authenticated, with no TLVs. The optional BER workloads add
metadata, padding and, in authenticated mode, a TLV HMAC. The optional Type 12
workloads request bursts, and the header workloads exercise header reflection
on their own. Kernel and NIC timestamps are not used. Echoes are checked
against a fixed timestamp. For round-trip observations, pass `--latency`. The
HMAC key is public test data.

Options (`live_udp_bench --help` lists limits and defaults):

| Option | Effect |
| --- | --- |
| `--reflector PATH` | Binary to launch; defaults to `target/release/stamp-suite`. |
| `--ipv6` | Use `::1` instead of `127.0.0.1`. |
| `--authenticated` | Generate and verify HMACs on every packet. |
| `--stateful` | Make the reflector keep its own sequence counter. |
| `--rate PPS` | Requested send rate, 1–1,000,000 packets/sec. |
| `--seconds N` | Load duration, 1–60 seconds. |
| `--idle-seconds N` | Length of each idle observation, 1–60 seconds. |
| `--repeats N` | Number of trials, each with a fresh reflector, 1–100. |
| `--drain-ms N` | Extra time to collect responses, 1–10,000 ms. |
| `--workers N` | Reflector Tokio workers, 1–256; default 2. |
| `--hwtstamp MODE` | Reflector `--hwtstamp` mode: `off` (default), `auto` or `on`. `auto` is the reflector's own default and adds TX timestamp work when the binary is built with `hwtstamp`. |
| `--metrics` | Start the reflector with `--metrics` on an ephemeral loopback port, to include the cost of metrics. The reflector binary must be built with the `metrics` feature, or it fails at startup. |
| `--ber-padding OCTETS` | Add combined BER metadata and 16–1,200 padding octets, made of whole four-octet default patterns. |
| `--ber-damaged` | Needs `--ber-padding`. Injects five bit errors into the padding, including a four-bit run across an octet boundary. |
| `--latency` | Measure the time from the local send call to receipt of the first valid reply. Needs `rate × seconds` ≤1,000,000 probe slots. Off by default. |
| `--memory` | Read reflector and generator RSS/PSS from Linux `smaps_rollup` before load, after the drain and after the idle period. Off by default. Missing or malformed data fails the trial. |
| `--burst-count N` | Request 1–16 Type 12 reply copies per probe. Needs `--stateful` and cannot be combined with BER. `rate × seconds × count` may not exceed 1,000,000 scheduled copies. |
| `--burst-bytes OCTETS` | Needs `--burst-count`. Requests 240–1,200 payload octets, a multiple of four; default 240. |
| `--headers MODE` | Linux nix backend only. `fixed` tests the fixed-header C fallback, `ipv6-ext` tests Destination Options, and `combined` tests both. Cannot be combined with BER or bursts. The extension modes need `--ipv6`. |
| `--header-bytes OCTETS` | Needs an extension mode. 16–256 Destination Options octets, a multiple of eight; default 16. |
| `--headers-denied` | Needs `--headers`. Keeps reflection denied on the temporary child reflector, while the generator still attaches the requested forward options. |
| `--sessions N` | Cycle through 1–65,534 measured SSIDs on one UDP tuple. Needs `--stateful` and cannot be combined with BER, bursts or headers. Includes session creation on first use, disables expiry and reserves separate identities for warm-up. |
| `--inventory MODE` | Needs `--sessions` and the `control` build feature. Runs the control API next to the UDP load: idle (`idle`), full reads (`full`) or cursor walks (`page100`, `page500`). |

Each reflector binds UDP port zero and, with an inventory workload, control
port zero. The benchmark starts it with `--log-format json` and reads the
assigned ports from its startup log lines, so no port is released and then
bound again. The reflector log is copied to stderr, filtered to errors plus the
startup lines. If the reflector exits or does not report its UDP endpoint
within ten seconds, the trial fails; it is not retried.

The generator sends in 1 ms batches, skips pacing slots it has missed, and
reads replies on a separate thread. Its bookkeeping holds at most
`rate × seconds + 1` slots (about 60 MB at the maximum). The startup and
post-idle probes each have a five-second limit. The run fails if a child
exits, a socket error occurs, the accounting does not add up, or no valid reply
arrives. All child processes are reaped.

A reply must come from the connected source and match the packet length, the
echoed fields, the sequence range and the HMAC. Duplicates and invalid replies
are counted separately. Loss is reported even when the process exits
successfully. Save the stderr diagnostics together with the JSON from stdout.
These checks keep the benchmark's counts honest; they are not a conformance
test. BER replies must also have the exact counter and burst
values, repaired padding, processed flags, the expected TLV layout, and valid
base and TLV HMACs where those apply. In authenticated mode the BER padding is
not covered by the TLV HMAC, so the injected corruption tests a successful
authentication followed by measurement and repair. All sockets use normal UDP
checksums. This is not a zero-checksum wire test.

```bash
target/release/examples/live_udp_bench --rate 5000 --ber-padding 120
target/release/examples/live_udp_bench --rate 5000 --ber-padding 1200 \
  --ber-damaged --authenticated --ipv6
```

The JSON also includes the request payload size, the expected BER profile and
a `completed` flag. If a trial hits a runtime error, the trials completed
before it and the error are printed, and the process exits nonzero. A failure
in startup metadata or hashing, or a panic, can still prevent any report.
Always check both the exit code and the `completed` flag.

### Process memory observations

```bash
target/release/examples/live_udp_bench --stateful --sessions 65534 \
  --rate 40000 --seconds 2 --latency --memory
```

With `--memory`, each trial's `memory` object has three snapshots:
`before_load`, taken after warm-up and after the bookkeeping is allocated;
`after_drain`, taken after the receiver and any inventory worker have joined;
and `after_idle`, taken before the final readiness probe. Each snapshot holds
the reflector and generator PIDs and, in bytes, RSS, PSS, private and shared
memory (clean plus dirty) and swap. The total `collection_seconds` is recorded
too. The [Linux proc documentation](https://docs.kernel.org/filesystems/proc.html)
defines these fields. RSS counts resident pages, and PSS divides shared pages
among the processes that share them. The private and shared totals add up the
clean and dirty fields. None of these fields include explicit hugetlbfs memory.
Kernel `kB` values are converted at 1,024 bytes per unit.

The reads happen outside the load and idle CPU timing windows, one process
after the other, so they are not an atomic snapshot across processes. Reading
still costs something and can affect later observations. The generator's
numbers include reply and RTT bookkeeping, memory the allocator holds on to,
and reports from earlier trials. Each reflector is a fresh process, but the
generator lives across all repeats. If a comparison needs a clean generator
baseline, use separate invocations.

These are observations at phase boundaries. They are not peak memory,
allocations per packet, heap-only usage or exact per-session costs. Buffers are
still allocated after the drain, and RSS after idle does not have to drop when
sessions expire. Nothing forces memory to be reclaimed. A missing or unreadable
`smaps_rollup`, a malformed field or an overflow fails the trial. None of these
is reported as zero. Without the flag, the `memory` field is null and no rollup
files are read.

### Many stateful sessions

```bash
target/release/examples/live_udp_bench --stateful --sessions 8192 \
  --rate 20000 --seconds 2 --latency
target/release/examples/live_udp_bench --stateful --sessions 65534 \
  --rate 40000 --seconds 2 --ipv6 --authenticated --latency
```

The measured socket cycles through distinct nonzero SSIDs and skips SSID 7,
which is reserved for warm-up. The two warm-up UDP tuples are not among the
measured identities. The child reflector gets `--session-timeout 0` and
`--max-sessions N+2`, so expiry and drops at the admission cap do not distort
this creation-and-lookup workload. Session creation is included in the load CPU
and RTT, so these are not steady-state numbers from a prepopulated table.
Packet payloads stay at 44 or 112 octets. You can combine this mode with
`--latency`, but not with the BER, header or burst workloads.

Startup rejects more sessions than there are scheduled probes
(`rate × seconds`). Missed pacing slots can still mean that fewer sessions are
actually used, so check `offered_sessions` instead of assuming the requested
number was reached. Sequence numbers of successful sends stay contiguous across
all sessions. Each reply must echo the SSID assigned to its sequence number, as
well as the timestamp and Error Estimate, with a valid HMAC in authenticated
mode. Late replies to warm-up probes are kept out of the measured counts.

`session_profile` records the workload settings. Each trial's `sessions` object
reports the configured and offered identities, the identities that got
replies, the identities that were fully replied, partially replied or
unanswered, the unique and missing probe replies, and the minimum and maximum
number of replies per offered identity. This accounting adds at most 65,534 u32
counters (256 KiB). Global deduplication and the optional RTT bounds still
apply. Each unique accepted reply is counted once, including replies that
arrive during the drain. The unique and missing totals in this summary match
the ordinary probe totals.

This mode tests many SSIDs over one destination and one source socket. It does
not measure many source ports or destinations, concurrent control inventory,
expiry, queue saturation, or packet arrivals that do not depend on the
generator. The offered and answered identities are not a direct snapshot of
the reflector's session table. Before you blame a difference on the reflector's
session cost, compare repeated runs of matched builds and record the
generator's CPU use and any pacing shortfall.

### Concurrent session inventory

```bash
cargo build --locked --release --features control --bin stamp-suite --example live_udp_bench
target/release/examples/live_udp_bench --stateful --sessions 65534 \
  --rate 40000 --seconds 2 --latency --memory --inventory full
target/release/examples/live_udp_bench --stateful --sessions 65534 \
  --rate 40000 --seconds 2 --latency --memory --inventory page100
```

With identical builds and traffic settings, compare these modes: no
`--inventory` (control server off), `idle` (server and inventory index on, no
HTTP requests during load), `full`, `page100` and `page500`. These workloads
include session creation, so a walk that runs while sessions are still being
created can end below the final table size. `--sessions` keeps expiry
disabled.

The child reflector binds its control API to TCP port zero on IPv4 loopback,
even when the UDP traffic uses IPv6. A random bearer token is kept in a
temporary mode-0600 file, which is removed when the trial ends. A status
request checks that the server is ready before load starts. The benchmark
never uses an existing server or changes its configuration.

One generator thread sends HTTP/1.1 requests one at a time, each over a new TCP
connection, and pauses 10 ms after each validated response. It starts no new
requests after the load deadline, but the last request can finish during or
after the UDP drain. Each request has a two-second I/O deadline and a 32 MiB
response limit. The trial fails on an unexpected status or framing, malformed
JSON identities, oversized pages, the same session identity appearing twice in
one walk, or a cursor that is invalid or does not advance. This small client
handles only the application's fixed-length JSON responses. It does not
support redirects, TLS or chunked responses.

Each trial's `inventory` object records the totals of requests, rows and body
bytes, the largest row count in a single response, completed and incomplete
walks, walks that finished after the load deadline, the length of that tail,
and the observed request latency. Latency includes TCP, HTTP, JSON parsing and
identity validation, and the report states the precision of its quantiles. A
full read counts as one complete walk. Paginated walks follow the creation
boundary and only restart after a null cursor. Identity tracking is capped at
the configured session limit, which includes the two warm-up sessions. It
checks that walks are consistent. It does not check counter values or take a
frozen snapshot of the inventory.

UDP counts and first-reply RTT mean the same as in the other modes. Load CPU
includes the concurrent HTTP client and server work up to the end of the UDP
load, but not any HTTP tail after that. The after-drain memory snapshot does
include that tail. The generator's HTTP buffers, identity tracking and decoding
also add to memory and CPU. The requests are closed-loop, so their rate changes
as responses get cheaper or more expensive. Check the actual request and row
rates before comparing modes. This is a baseline for live ingest. It does not
time how long locks are held, and it is not a saturation test with
independently arriving traffic.

### Live header reflection

```bash
target/release/examples/live_udp_bench --rate 5000 --headers fixed --latency
unshare -Urn sh -ec 'ip link set lo up
  exec target/release/examples/live_udp_bench --rate 5000 --ipv6 --authenticated \
    --headers combined --header-bytes 256 --latency'
unshare -Urn sh -ec 'ip link set lo up
  exec target/release/examples/live_udp_bench --rate 5000 --ipv6 \
    --headers ipv6-ext --headers-denied'
```

Header profiles use the Linux nix backend. Builds with only pnet reject them at
startup. Attaching IPv6 options needs `CAP_NET_RAW` on Linux. The commands
above get it inside a private user and network namespace and bring up that
namespace's loopback. They need unprivileged namespaces to be allowed and
`iproute2` to be installed. If attaching fails, the run returns an error. The
fixed-only cases need no capability for attaching. Fixed-header requests expect
the backend's C fallback with the zero values left in place, for both IPv4 and
IPv6. The extension modes attach one Destination Options header through
`IPV6_DSTOPTS` before connecting each generator socket. A skippable
experimental option carries deterministic bytes, and the kernel sets Next
Header to UDP. The reflector reads the forward header from ancillary data and
returns its bytes inside Type 246. In combined mode the Type 247 fixed-header
request comes before Type 246.

By default the temporary reflector allows requested reflection for the
loopback sender. `--headers-denied` keeps the default-deny policy. Extension
requests then expect C and unchanged values, while the sockets still attach the
same options. Every reply must have the exact TLV order, values, flags and
length, the right base identity, and valid base and TLV HMACs where they apply.
A failed attachment or missing expected data fails the run with an error. The
JSON records `header_profile`, which is null for the other workload profiles.
These cases measure real socket-option, capture and reflection work on
loopback. They make no claim about physical capture, verification by a
separate raw capture, attaching IP headers in the reverse direction, or pnet
header performance. When you compare modes and sizes, remember that the
generator's serialization and verification costs are included and that RTT
covers only the first reply.

### Type 12 reply bursts

```bash
target/release/examples/live_udp_bench --rate 100 --stateful \
  --burst-count 16 --burst-bytes 1200 --latency
```

Burst mode turns on Type 12 in the temporary child reflector, with count and
size caps that match the workload. Requests use a 1 ms interval and go through
the reflector's normal rate and volume policies. BER and bursts are separate
workload profiles. Before load starts, the probes collect every expected copy
and then drain until a read times out, so warm-up copies cannot leak into the
load window. Readiness and drain still have deadlines and fail with an error.

Each copy must pass the base identity and HMAC checks and have the exact
Type 12 fields, processed flags, reply size, zero padding and, where it
applies, the TLV HMAC. A copy is identified by the pair of echoed sender
sequence number and stateful reflector sequence number, so the check does not
assume that copies arrive back to back or in order. A repeated pair is a
duplicate. Other distinct copies within the requested count are valid. Copies
beyond the requested count increment the invalid-reply counter. Copies are
stored in fixed-size flat arrays (about 5 MB at most, plus reserved slots),
separate from the normal per-probe accounting and the optional latency
storage.

`sent`, `achieved_send_pps`, unique replies and ordinary loss count probes.
The `burst` object reports expected, unique and missing copies, the copy
counts during load and drain, and the number of probes that were fully,
partially or never replied to. Its denominator is the number of successful
probe sends times the requested copies. `unique_reply_copy_pps_during_load`
reports copy throughput. In burst mode, duplicate counts refer to repeated
pairs. Latency is still taken only from the first valid reply to each probe,
so it says nothing about the delay of later copies and does not check the
actual spacing between copies. UDP checksums are normal. This is not physical
capture or raw zero-checksum evidence. Keep the probe rate low enough that you
can tell generator, queue and amplification effects apart. Copy throughput is
not the probe request rate.

### Optional round-trip observations

```bash
target/release/examples/live_udp_bench --rate 5000 --latency
target/release/examples/live_udp_bench --rate 5000 --latency \
  --ber-padding 1200 --ber-damaged --authenticated --ipv6
```

With `--latency`, each trial includes `observed_rtt`: the sample count, the
exact minimum and maximum, the mean, p50, p95 and p99 in nanoseconds, and
`quantile_precision`. The tracker publishes a monotonic timestamp after the
request is built and before the send syscall. Receipt is recorded right after
`recv` returns, before base, HMAC and BER validation. A sample is kept only for
the first validated reply to a sent sequence number. Warm-up probes, invalid
replies and duplicates do not count, but valid replies during the drain do. The
sample count must equal the number of unique valid replies during load and
drain, or the trial fails.

These observations include publishing the timestamp, the work done in the send
call, kernel and socket queues, reflector processing and the scheduling of the
generator's receive thread. They do not include building the request or
validating the reply after receipt. They are round-trip observations taken in
the local application, with no wire or NIC timestamps and no attempt to infer
one-way delay. Pacing still works in batches. Missing replies have no timing
sample, so loss can bias the reported distribution.

Timestamp storage is capped at 1,000,000 scheduled probes (about 8 MB plus the
reserved warm-up slot), however many pacing positions are actually sent. The
RTT collector keeps exact order statistics up to 4,096 samples. After that it
reports its quantization bound relative to the magnitude of the values. Clock
error and statistical uncertainty come on top of that bound. Compare runs with
and without the flag, because the atomics, clock reads and statistics add work
to the generator and can affect the observations. Without the flag,
`observed_rtt` is null and neither the timestamp ledger nor the RTT collector
is created.

### Reading the results

- `achieved_send_pps` counts successful send syscalls per second of actual
  load wall time. Compare it with `settings.rate`. `skipped_pacing_slots`
  counts positions in the requested schedule that were never sent. A low
  achieved rate can be a generator or scheduler limit. It does not show that
  the reflector has reached capacity.
- `unique_receive_pps_during_load` counts unique valid replies read during the
  configured load window. Late replies are reported separately as
  `unique_during_drain`, so they do not inflate the steady-load throughput.
- `missing_after_drain` and `loss_percent` compare successful sends with all
  unique replies collected before the drain deadline. Loss can happen in either
  direction or in the generator's receive queue, and this harness cannot tell
  which.
- CPU comes from the user and system ticks in each process's `/proc/PID/stat`,
  including all its threads. `percent_one_core` is CPU seconds / wall seconds
  × 100, so it can go above 100 when several threads are busy. Generator CPU
  includes building packets, request HMACs, validating replies and
  bookkeeping. Load CPU is sampled when the sender stops, so the drain is not
  included. Socket timeouts and scheduler delays can make that stop slightly
  later than the requested load window, so the report gives the wall interval
  actually used for CPU.
- Idle samples report raw ticks and the tick frequency. Zero ticks means usage
  below the accounting resolution, not proof that no CPU work happened. Use
  longer idle windows to compare small changes. `resume_after_idle` confirms
  that the last probe got a valid reply. The `idle_cpu_test` integration tests
  enforce an idle CPU ceiling separately.

The JSON also records the command, the generator's feature flags, whether it is
a debug build, the SHA-256 hashes of the binaries, the kernel, the CPU model
and the inherited CPU affinity. Record `rustc -Vv`, the build commands, the
revision and the host load next to it. The feature flags describe the generator
build only. They cannot verify an arbitrary reflector binary. Do not rebuild
either executable during a run. Use release builds, repeat each case, and
compare medians and ranges, not a single best result.

Sweep IPv4 and IPv6 and both authentication modes at 5,000, 25,000 and
100,000 pps. Add `--stateful` to include session costs. Keep the worker count,
CPU affinity, features and host load the same across runs, and use more
repeats on a quiet host. This single-session loopback test can be limited by
either process or by the kernel. It does not measure NIC throughput, scaling
with many clients, other TLVs or hardware timestamps. To judge an optimization
you need matched runs before and after it. BER adds request serialization,
bit-pattern checks and TLV HMAC work to the generator as well as to the
reflector, so compare generator CPU and the achieved send rate before you
conclude that the reflector is the limit.

For pnet, build with `--no-default-features --features ttl-pnet` and run with
`CAP_NET_RAW` in an isolated network namespace. Raw capture needs complete UDP
checksums, and loopback frames with checksum offload can fail validation. If
loopback cannot provide complete checksums, use a controlled veth setup. Where
unprivileged user namespaces are available:

```bash
cargo build --locked --release --no-default-features --features ttl-pnet \
  --bin stamp-suite --example live_udp_bench
unshare -Urn sh -ec 'ip link set lo up; target/release/examples/live_udp_bench --rate 5000' \
  > live-pnet-ipv4-open.json
```

`--all-features` selects nix, so it does not measure pnet. Other operating
systems need a different CPU-accounting adapter, and the harness stops with an
error on them. Missing IPv6, missing raw-socket permission or a failed
reflector startup also stop the run with an error instead of producing a
skipped benchmark.

## In-process regression benchmarks

```bash
cargo bench --locked --bench reflector_hotpath
cargo bench --locked --bench reflector_hotpath -- unauth_full_chain
cargo test --locked --example live_udp_bench
```

Criterion writes HTML reports under `target/criterion/<bench>/report/`. These
benchmarks complement the live measurements. Their operations per second do not
predict end-to-end UDP packets per second. The example's unit tests check reply
validation and the loss, duplicate and reordering accounting without needing
sockets. Linux CI runs these accounting tests but does not enforce throughput
thresholds on shared runners.

`auth_full_chain` includes valid base and TLV HMACs, Location requests and
observed address and counter metadata. Before timing, setup checks the
response's integrity flags and HMAC. `auth_chain_missing_tlv_hmac` measures the
rejection path on its own and checks its I flags. To run the fixture checks
without timing:

```sh
cargo test --locked --all-features --bench reflector_hotpath -- --test
```

### BER processing and reply assembly

The `ber` group covers 32 combinations: 120 or 1,200 padding octets, the
default four-octet or an explicit five-octet pattern, clean or damaged padding,
open or authenticated packets, and IPv4 or IPv6 address metadata. Both sizes
hold whole patterns. Damaged padding has a four-bit error run across an octet
boundary plus a separate one-bit error. Before timing, each fixture checks for
exactly five errors and a maximum burst of four (zero and zero when clean),
processed TLV flags, repaired padding, explicit patterns left intact, a reply
the same size as the request, and valid request and reply HMACs in
authenticated mode. The damaged padding is outside the BER TLV's HMAC
coverage, so these cases measure successful verification followed by
processing.

```sh
cargo test --locked --bench reflector_hotpath -- --test ber/
cargo bench --locked --bench reflector_hotpath -- ber/
```

Building the request, creating keys and validating fixtures happen outside the
timed loop. Each iteration calls `process_stamp_packet` and drops the owned
reply. That covers parsing, base and TLV authentication where they apply, BER
counting and repair, timestamp generation and response serialization. One
reported element is one processed request. The context has no session manager,
so live admission, replay classification, session locks, UDP checksums, route
and MTU lookup, kernel timestamps, burst transmission and syscalls are all left
out. The IPv4 and IPv6 cases differ only in the in-memory source and
destination metadata. No IP headers are built, and neither network backend is
tested. This group does not measure a transport with zero UDP checksums or
packets that arrive independently.

Linux CI runs all reflector fixtures in Criterion's test mode, with no timing
budget. For local measurements, pick the executable from Cargo's JSON compiler
artifacts, keep build features, compiler and CPU affinity the same, and save
the raw Criterion samples from repeated processes before you interpret any
variation. Use the live UDP harness for transport costs and the transmission
profiling fixtures for the per-copy cost of bursts. In-process iterations per
second are not packets per second on the wire.

### Header reflection and reply assembly

The `headers` group covers eight synthetic capture scenarios, each in open and
authenticated mode (16 cases): one IPv4 fixed header; eight stacked IPv4 fixed
headers; one IPv6 fixed header; an IPv6 fixed header plus 8 or 256 octets of
extension data; eight 16-octet extension records requested by unique selectors
in reverse capture order; a missing capture; and fixed and extension
reflection denied by policy. The last two cases request IPv6 fixed and
extension data and check the exact C flags, unchanged request values and
diagnostic reasons. Successful fixtures compare every returned header octet,
TLV type, order and flag against separately stored copies of the captures.
Authenticated fixtures verify the request TLV HMACs and the reply base and TLV
HMACs before timing.

```sh
cargo test --locked --bench reflector_hotpath -- --test headers/
cargo bench --locked --bench reflector_hotpath -- headers/
```

Each timed iteration processes one request and drops the owned response.
Building the synthetic captures, creating selectors and requests, signing,
setting up the context and validation all happen outside the timing. The
captures are byte fixtures with no IP checksum, option or forwarding
validation. So this measures splitting header records, matching and copying
them, handling refusals and assembling the reply from metadata that is already
available. It does not include actual capture, ancillary-data parsing,
attaching IP headers, sockets, session management, route and MTU work or burst
transmission. Linux CI's existing reflector fixture command runs every case
without timing budgets. Repeat runs of optimized builds and record the
compiler, features, binary and source hashes, affinity and host load. Keep
Criterion batch costs apart from live packet throughput and latency
measurements.

## Session-table scaling

The separate `session_scaling` harness measures IPv4 and IPv6 session tables
holding 1,024, 16,384 and 65,536 distinct, complete session identities. Fixture
setup checks capacity, inventory membership, a cleanup that keeps all entries,
and full expiry. The addresses exist only in memory, and the harness sends no
packets.

```sh
cargo test --locked --bench session_scaling -- --test
cargo bench --locked --bench session_scaling
cargo bench --locked --bench session_scaling -- 'session_table/inventory_'
```

Each benchmark name contains the operation, the address family and the table
size:

| Operation | Timed work |
| --- | --- |
| `lookup_refresh` | Step through a deterministic permutation of the seeded identities: acquire each selected session, refresh its activity and release the returned Arc. |
| `inventory` | Collect and destroy the full extended summary vector used by control/SNMP inventory. HTTP DTO conversion and serialization are excluded. |
| `cleanup_keep` | Scan a full table with no expired sessions (`Duration::MAX` timeout). |
| `cleanup_expire` | Remove and retire every entry from a fresh full table (`Duration::ZERO` timeout). Filling the table and destroying it at the end are kept out of the timing by using one fixture per iteration. |
| `control_churn` | Cycle over unique clients: expire one through the control API's manager operation and admit its replacement, so the table does not grow. Includes that operation's full-table ambiguity scan; HTTP is excluded. |

Filling the table, building the access order and validating fixtures happen
outside the timed loops. Lookup and control churn keep their access cursor
across samples and use an odd-stride permutation, so short samples are spread
over the whole table. A short run does not have to visit every key.
`unauth_stateful_sessions` processes one source over and over against a
populated table. Inventory includes allocating and freeing the vector. Expiry
includes retiring and removing sessions. The cleanup assertions stay inside
the timed loop, so an empty table or a no-op cannot quietly replace the
intended workload.

These are timings of single operations on one thread. They do not measure
blocked ingest, concurrent inventory, expiry of entries with mixed ages,
allocation counts or packet latency. Criterion's sample distributions are not
per-request latency percentiles. Measure those separately before you choose a
change to cleanup or pagination.

Record the revision, the patch and build flags, the compiler, the executable
hash, the CPU affinity, the host load and the variation between repeated runs.
Use the same fixtures and features for before/after comparisons, and pin a CPU
on Linux if the environment allows it. Process CPU and RSS measurements include
setup and Criterion's analysis, so they are not the resource cost of the
operation alone. Keep generated results in ignored or external storage. Linux
CI runs the fixture checks without timing thresholds.

## Session instruction profiles

The same `session_scaling` executable has a separate profiling mode that runs a
fixed number of operations. Its non-inlined `session_scaling::profile_operation`
function wraps exactly one operation: a lookup and refresh, a full inventory, a
cleanup that keeps all entries, a full expiry, or a control expiry and
replacement. The normal Criterion timing loops never call this wrapper. Build
optimized code with debug information, and pick Cargo's exact executable
instead of a wildcard match that might be stale:

```sh
CARGO_PROFILE_BENCH_DEBUG=1 cargo bench --locked --bench session_scaling \
  --no-run --message-format=json > /tmp/session-profile-build.jsonl
PROFILE_BIN=$(python3 -c '
import json
builds = [json.loads(line) for line in open("/tmp/session-profile-build.jsonl")]
print(next(build["executable"] for build in builds
           if build.get("executable") and build["target"]["name"] == "session_scaling"))
')
valgrind --tool=callgrind --collect-atstart=no \
  '--toggle-collect=*session_scaling*profile_operation*' \
  --callgrind-out-file=/tmp/session-inventory.callgrind \
  "$PROFILE_BIN" --profile-operations --sessions 65536 \
  --operation inventory --iterations 10 > /tmp/session-profile.json
callgrind_annotate --auto=no --tree=both /tmp/session-inventory.callgrind
```

Install Valgrind and the matching system debug symbols separately. The
[Callgrind manual](https://valgrind.org/docs/manual/cl-manual.html) explains how
collection toggling works and how instructions and call graphs are attributed.
Check that the profile has a nonzero `Ir` and the expected number of
`profile_operation` calls, and that their inclusive instruction cost accounts
for the collected total. If the symbol pattern does not match, the profile can
come out empty. Call counters on other functions can include calls made while
collection was off. Use the allocation example to count allocator requests.

`--profile-operations` must be the executable's first argument. Its options
are `--sessions` (1–65,536, default 16,384), `--ipv6`, `--operation`
(`lookup-refresh`, `inventory`, `cleanup-keep`, `cleanup-expire`, `control-churn`)
and `--iterations` (1–1,000, default 10). Every iteration gets a fresh full
table. Filling the table, choosing keys, validation, storing results, writing
the report and destroying the table at the end are outside the profiling
boundary. Dropping the returned Arc or vector, and the removal and retirement
work, are inside it. No other session references or transmission guards are
held. The fixture checks run all ten family and operation combinations and the
argument limits without needing a profiler.

The JSON reports the validated item counts and the final table size for each
operation, the build features, the executable and source hashes, and whether
it is a release or debug build. Debug runs fail. A panic makes the process fail
instead of producing a completed JSON report. Save the raw profile, the
annotations, the compiler and build command, the revision and patch, the tool
version and the process output together. Repeat each workload with the same
build and profiling setup before you read anything into differences.

Callgrind's `Ir` counts instrumented user-space instructions, including the
wrapper and its checks. It is not CPU cycles, kernel work, wall-clock latency,
lock-wait time or packet throughput. Hash-table order, heap state, code
generation and the profiler itself all affect the profile. This single-thread
mode has no concurrent expiry, no active transmit guards, no network traffic
and no hardware caches. Cache and branch simulation are off in the command
above. Look at the native timing and contention measurements together with the
profiles before you choose an optimization.

## Concurrent session management

`session_contention` times each foreground session-manager call while a second
thread keeps collecting the full inventory or scanning all sessions for
cleanup. Compare each case with `--background none` using the same build,
table size, probe mode and CPU affinity:

```sh
cargo build --locked --release --example session_contention
target/release/examples/session_contention --sessions 65536 --probe admission \
  --background none > /tmp/session-baseline.json
target/release/examples/session_contention --sessions 65536 --probe admission \
  --background inventory > /tmp/session-inventory.json
target/release/examples/session_contention --sessions 65536 --probe refresh \
  --background cleanup > /tmp/session-cleanup.json
cargo test --locked --example session_contention
```

`--probe refresh` cycles through existing identities. `--probe admission`
cycles through clients on a separate source port. It creates one temporary
session and then retires it with the control manager operation, so the table
always holds N or N+1 sessions. Admission latency does not include the
retirement. `retirement_latency` covers the retirement, including its
full-table ambiguity scan and any wait for the table lock, and
`admission_cycle_latency` covers both stages.

`--sessions` takes 1–65,536 entries, and `--ipv6` selects IPv6 identities.
Each invocation runs three one-second trials by default (`--seconds` 1–60,
`--repeats` 1–100). `--pause-us` sets a pause after each background operation,
1,000 microseconds by default. Zero gives continuous management pressure. It
is a pause, not a guaranteed rate of management requests. Use at least two CPUs
and record the affinity. Allowing two CPUs does not pin each thread to its own
core. Debug builds refuse to run performance measurements.

The JSON records counts, observed closed-loop operations per second, min, max,
mean, p50, p95 and p99 call latency in nanoseconds, the cost of the background
operations, window overrun, the final table size, feature flags and the binary
and source hashes. Every call goes into the full-run quantiles. They are exact
up to 4,096 observations and after that have a magnitude quantization error
below 0.78125%. The counts of calls at or above 1 ms and 10 ms, and the
observed extremes, stay exact. Sampling uncertainty and scheduler and clock
effects come on top of that quantization bound.

The producer is closed-loop: it makes its next call only after the previous
cycle ends. So it measures neither independently arriving traffic nor the
queueing time that packets would build up while a call is blocked. Reported
throughput includes collecting statistics and, for admission, the retirement
work. Clock and call overhead are included. No packets, HTTP, mixed-age expiry,
transmit guards or hardware timestamps are involved. Cleanup uses
`Duration::MAX` and removes no entries. Filling the table and creating the
threads happen before the active window, and worker teardown and the final
summary come after it. If the probe or the requested background work makes no
progress, the run fails and prints an incomplete report with the trials that
did complete. CI tests the invariants and the failure handling, but imposes no
latency or throughput threshold.

With `--features control`, `session_contention --indexed-inventory` turns on,
before timing starts, the same ordered index that the control server uses.
With `--background none` this measures index maintenance during admission with
no inventory requests. Add `--inventory-page-size 100` or `500` together with
`--background inventory` to collect one page per background operation. That
option also turns on the index. Each page continues the current walk, and a new
walk starts after the last page. Background latency then describes one page,
not a whole inventory. Compare indexed full inventory, paged inventory and no
management activity with the same table size, compiler, build and pause. The
index is initialized after the table is filled, outside the timed window.

```sh
cargo build --locked --release --features control --example session_contention
target/release/examples/session_contention --sessions 65536 --probe admission \
  --background none --indexed-inventory > /tmp/session-indexed-idle.json
target/release/examples/session_contention --sessions 65536 --probe admission \
  --background inventory --indexed-inventory > /tmp/session-indexed-full.json
target/release/examples/session_contention --sessions 65536 --probe admission \
  --background inventory --inventory-page-size 100 > /tmp/session-paged.json
cargo bench --locked --features control --bench session_scaling -- session_inventory
```

The additional `session_inventory` Criterion group covers 100- and 500-row
pages, one-time index initialization, indexed lookup, control churn and full
expiry, with the same table sizes and both address families. Page timing
includes collecting summaries, encoding the cursor and dropping the result,
including final pages that are only partly filled. Initialization excludes
filling the table. Full expiry excludes filling the table and setting up the
index. Compare maintenance costs with the original `session_table` cases from
the same build. The index keeps O(n) extra storage and adds work to creation
and removal, and in exchange collecting a page has a bounded cost. These
manager-call fixtures do not directly measure how long locks are held, HTTP
serialization, network ingest or packet queueing.

## Expiry and transmission-guard contention

The test-only fixture `session::benchmarks::expiry_contention_measurements`
times one cleanup call while a closed-loop producer keeps refreshing one
persistent identity. It covers 1,024, 16,384 and 65,536 seeded sessions, IPv4
and IPv6, and 0%, 50% or 100% expired entries, with three fresh trials for each
combination. The mixed and full expiry cases also run with a transmission guard
held on one expired entry and released after a requested 10 ms delay. That
makes 90 trials.

```sh
cargo test --locked --release --lib \
  session::benchmarks::expiry_contention_measurements \
  -- --exact --ignored --nocapture --test-threads=1 > /tmp/session-expiry.log
cargo test --locked --lib session::benchmarks
```

Use at least two CPUs, and record the affinity, the revision and patch, the
compiler, the build flags and the executable hash. Save the
`EXPIRY_CONTENTION_JSON=` line from the log as JSON. Debug builds refuse to run
measurements. No packets or sockets are used. The module exists only in test
builds and adds no production API or dependency.

Setup moves the manager's epoch back by 120 seconds and gives the expired
entries an activity offset of zero. Live entries keep real current offsets and
a 60-second timeout. A separate live probe brings the actual table size to
N+1, so 100% expiry removes all N seeded entries and leaves the probe. Each
trial checks the exact removals, the remaining count, the live identities and
the guarded retirement. Filling the table, verification and destroying the
table at the end are outside the cleanup timing. An expired entry normally
drops its last Arc during cleanup. In the guarded case one extra Arc is held
until cleanup has finished.

The JSON reports the duration of the cleanup call, 32 refresh calls made before
cleanup, and every refresh in the concurrent window, including the exact
maximum and the counts at or above 1 ms and 10 ms. The quantiles use the same
bounded collector as the contention example. The report states how much the
longest refresh overlapped the measured cleanup interval. With zero overlap,
that call tells you nothing about a cleanup stall. Scheduling can prevent
overlap, especially with short scans. A call that does overlap still includes
scheduling and normal call overhead, so it is not a pure lock-wait measurement.
Percentiles from a single trial can hide one blocked call, so check the maxima
and pause counts too.

The guard delay starts just before cleanup and can run long because of
scheduling. Its observed release time is reported separately. It models an
in-flight transmission that is retired late, without doing a real network
send. Handshakes and thread creation happen before cleanup timing starts. The
concurrent window can include calls just before or after cleanup, and it always
includes at least one call, even if the producer only gets to run after cleanup
has finished. The measurements cover refreshing an existing session. They do
not cover creating new sessions, packet queues, independently arriving traffic
or sustained cleanup rates. The normal tests check small fixtures without
latency thresholds.

The separate fixture `session::benchmarks::expiry_admission_measurements` runs
the same 90-case matrix of size, family, expiry and guard for new-session
creation:

```sh
cargo test --locked --release --lib \
  session::benchmarks::expiry_admission_measurements \
  -- --exact --ignored --nocapture --test-threads=1 > /tmp/session-expiry-admission.log
```

Save the `EXPIRY_ADMISSION_JSON=` line as JSON. This mode reserves one extra
slot: the cap is N+2, and before cleanup the table holds between N+1 and N+2
entries. Each closed-loop cycle creates an identity on source port 10001,
checks that its sequence and counter state are fresh, and then removes it
through the control manager API. Seeded entries and the persistent live probe
use port 10000. The temporary entries keep real live activity offsets, so
cleanup removes exactly the seeded entries it should. Final validation checks
the remaining IDs, the retirement and the table size.

Admission duration covers getting the session from the manager and reading its
ID. The Arc is held until retirement. Retirement duration covers only the
control manager call, whose ambiguity scan can look at the whole table.
Complete-cycle duration also includes the freshness and retirement assertions
and the final Arc release. The JSON gives these three distributions separately
for 32 cycles before cleanup and for every concurrent cycle, and reports how
much each phase's longest call overlapped cleanup. A cycle can overlap cleanup
while its admission phase does not, so check the per-phase overlap fields
before you blame a stall on session creation.

The reported cycle window runs from the start of the first call to the end of
the last cycle, and its observed cycles per second include collecting
statistics between cycles. The window can extend just before or after cleanup
and always completes at least one cycle. This workload measures one temporary
identity at a time, removed through the control API between admissions. It is
not sustained table growth, independently arriving traffic, pure lock wait or
packet queueing. Read the latencies together with the removal counts and the
exact maxima and pause counts. The small normal tests run both families and all
expiry and guard combinations without timing thresholds. These fixtures exist
only in tests and add no runtime API or production behavior.

## Indexed session expiry

With `--features control`, the ignored fixture
`session::benchmarks::indexed_expiry_measurements` times cleanup with the
inventory index enabled. It runs 180 sequential trials (three sizes, IPv4 and
IPv6, 0/1/50/75/99/100% expiry, five repeats) and 288 concurrent trials
(1/50/99/100% expiry, refresh or admission, zero or 10 ms guard delay, three
repeats). Like the fixtures above, it keeps one live probe in addition to the N
seeded entries. The sequential timing covers only cleanup. Setup, index
initialization, result validation and destroying the manager at the end are
excluded. The concurrent results have the same scope and limits as the
admission and refresh measurements described above. Save the
`INDEXED_EXPIRY_JSON=` line and compare the same compiled fixture across
revisions.

```sh
cargo test --locked --release --features control --lib \
  session::benchmarks::indexed_expiry_measurements \
  -- --exact --ignored --nocapture --test-threads=1 > /tmp/indexed-expiry.log
cargo test --locked --features control --lib session::benchmarks
```

To also measure the case that ends with an empty table, use the existing
indexed full-expiry Criterion cases. To count its allocator requests, use
`session_allocations --indexed-inventory --workload cleanup-expire`. Retiring
entries from the index in bulk can use temporary ordinal and replacement
storage to do less removal work while the table lock is held. The duration of
the manager call still includes destruction after unlocking, so it is not a
direct measurement of lock hold time and does not guarantee packet latency.

## Session allocation requests

`session_allocations` counts the Rust allocator requests that one
session-manager operation makes on the calling thread. Its allocator wrapper
passes every call on to `System` and exists only in this example executable. It
does not change the allocator used by `stamp-suite`, the other examples or
anyone using the library.

```sh
cargo build --locked --release --example session_allocations
target/release/examples/session_allocations --sessions 65536 \
  --workload inventory > /tmp/session-inventory-allocations.json
target/release/examples/session_allocations --sessions 65536 --ipv6 \
  --workload cleanup-expire > /tmp/session-expiry-allocations.json
cargo test --locked --example session_allocations
```

Pick `--workload lookup-refresh`, `inventory`, `cleanup-keep`,
`cleanup-expire` or `control-churn`. These match the single-thread
session-table scaling operations above. Each sample runs exactly one operation
against a freshly filled table. Inside the counted scope, lookup drops the Arc
it gets back, inventory drops its summary vector, and control churn expires one
client and drops its replacement's Arc. Full expiry includes removal,
retirement and destroying the sessions. No outside session references or
active transmit guards are held. Filling the table, choosing keys, storing
results, validation, JSON output and destroying the manager at the end are
excluded.

`--sessions` takes 1–65,536 identities (default 16,384), `--ipv6` selects
IPv6, and `--iterations` takes 1–1,000 samples (default 10). Debug builds
refuse to run measurements. The JSON records each sample, the final table
size, the build features, the executable and source hashes and the Git HEAD
seen at run time. Record the compiler, the build command and the revision or
patch alongside the output. The counts describe that one compiled build, since
optimization can change allocator calls.

`alloc_calls` and `alloc_zeroed_calls` count successful requests of each kind,
and `allocated_bytes` covers both. Successful `realloc_calls` record the old
and new requested sizes separately and do not also bump the alloc or dealloc
counts. `dealloc_calls` and `deallocated_bytes` include blocks that were
allocated during setup if the operation frees them. `requested_bytes_delta` is
allocated bytes plus reallocated-to bytes, minus deallocated bytes and
reallocated-from bytes. It can be negative during expiry. A detected
accounting or table error fails the run with an incomplete report of the
completed samples. A panic or an allocator abort can end the process before
any report is written.

These are the requested layout sizes seen at Rust's `GlobalAlloc` boundary.
They are not allocation-site backtraces, calls inside the `System` allocator,
memory copies, live or peak heap usage, or RSS. Other threads and native
allocations that bypass the Rust allocator are not counted. The counter itself
uses thread-local storage that does not allocate. Counting changes the
execution cost, so this example reports no timing or throughput. Use a CPU or
heap profiler and matched workloads before you decide on an optimization. CI
checks allocator accounting, thread isolation and operation invariants, but
does not enforce allocation budgets.

With `--features control`, `--workload inventory-page --page-size 100` counts
one first page, including its cursor and dropping the returned values.
`--page-size` takes 1–500 and defaults to 100. Index setup is not counted for
this operation. `--workload inventory-index` instead counts the one-time
registration of the ordered index on a table that is already full, and keeps
the index until the sample ends. Its positive `requested_bytes_delta` is the
requested index storage, not RSS. Do not pass `--indexed-inventory` with this
initialization workload. For the other workloads, `--indexed-inventory` turns
on the index before counting starts, so expiry and churn include index
maintenance and freeing index nodes. Compare all of these with full inventory
and with the index disabled, in the same build.

## MTU-cache capacity and route-query cost

Three ignored library tests give opt-in measurements of the private MTU cache
in release builds. They expose no application API and do not change the cache
policy. Normal CI runs a functional fixture test, not these timing
measurements.

```sh
cargo test --locked --release --lib \
  receiver::mtu::benchmarks::capacity_scaling \
  -- --exact --ignored --nocapture --test-threads=1 > /tmp/mtu-capacity.log
cargo test --locked --release --lib \
  receiver::mtu::benchmarks::loopback_route_queries \
  -- --exact --ignored --nocapture --test-threads=1 > /tmp/mtu-query.log
cargo test --locked --release --lib \
  receiver::mtu::benchmarks::loopback_capacity \
  -- --exact --ignored --nocapture --test-threads=1 > /tmp/mtu-live-cache.log
```

A successful run prints one `MTU_BENCH_JSON ` line with its JSON report among
the Rust test harness output. Measurement runs in a debug build fail. Reports
include the executable, cache and driver source hashes, the feature flags and
every sample. Also record the compiler, the build command, the revision or
patch, the CPU affinity and the host load. Each invocation does three
repetitions. Run several fresh processes.

The capacity traces use 128, 256, 257, 512 and 1,024 distinct destination IPs,
in IPv4 and IPv6. One trace cycles through all destinations. The other does
eight lookups cycling over 64 hot destinations, then one lookup cycling over
the remaining destinations. After one unmeasured pass over all keys, sixteen
complete traversals of the destinations or of the cold set follow. Each case
starts with a fresh cache.

The capacity driver calls the real internal lookup policy with a cheap
synthetic query result that is different for each destination. It freezes the
time passed to the lookup so that entries never expire, which keeps capacity
behavior apart from the 250 ms TTL. It skips route-key construction and
notification handling. The counts report synthetic queries and misses, hits,
warmup queries, peak and final entries, and a checksum. Every result and the
cache size limit are validated. The native batch wall time includes cloning
keys, counters, comparing results and tracking the checksum and peak. Building
the input, warmup and the final destruction are excluded. This is not a packet
workload, and it does not measure the throughput of kernel route lookups.

The Linux-only calibration calls the real route query directly, 1,000 times
per sample, after one unmeasured query. It covers wildcard and bound sources on
IPv4 and IPv6 loopback, checks that the MTU stays valid and unchanged, and
records every individual wall latency plus exact nearest-rank p50 and p99 and
the extremes. It uses route netlink requests and an interface MTU lookup. No
UDP packets are sent. The socket lifecycle, building the request, the syscalls
and parsing the response are timed. Recording and sorting the samples are not.
The subscription and invalidation path and the payload-cap calculation are not
part of this measurement. If Linux support, socket permission or the routes are
missing, or if the MTU changes, no completed calibration report is produced.

The Linux-only `loopback_capacity` driver runs the same working-set sizes and
trace patterns through the full payload-cap lookup path with real time. Each
case does four traversals after warmup, and includes route-key construction,
notification polling, expiry checks, route queries and the IP/UDP overhead
calculation. IPv4 uses distinct addresses in 127.0.0.0/8. IPv6 uses distinct
destination ports on ::1, so its distinct keys stand for UDP flows, not
distinct IPs. No UDP packets are sent. The notification subscription has to
succeed, and every cap, every hit and query count and the cache size limit are
checked. A thread-local counter that exists only in test builds records the
real route-query calls, so application builds do no extra work. Input setup,
warmup and final destruction are outside the batch timing. Counters, result
comparisons and peak tracking are inside it. TTL expiry or real route
notifications can raise the query counts, so keep all the counts together with
the timing.

To compare eviction policies, build both with the same driver code, features
and compiler, keep both executables, and alternate which one runs first on the
same CPU. Compare the query counts as well as repeated native wall times. Do
not turn a timing difference on synthetic queries into a claim about packet
throughput.

Use the query counts to compare how the policies behave on the same traces. A
cyclic working set larger than the cache can miss under several eviction
policies. The hot/cold trace tests whether capacity pressure also evicts
frequently used entries. Loopback query latency gives a sense of what a miss
costs, but it is not a formula for packet latency. Real route churn, TTL
expiry, EMSGSIZE refresh, isolation by egress, source and traffic class, and
behavior when notifications are missing all still need their functional tests
and live workloads before an eviction change is accepted.

## Reply-transmission allocation and copy profiles

An ignored library test profiles replies that are already assembled as they go
through the real transmission finalizer. Normal CI validates all 30 fixtures
without timing or allocation budgets. This driver exists only in tests and does
not change application code or allocators. Build optimized code with debug
information and pick the exact library-test executable:

```sh
CARGO_PROFILE_RELEASE_DEBUG=1 cargo test --locked --release --lib --no-run \
  --message-format=json > /tmp/transmit-profile-build.jsonl
TX_BIN=$(python3 -c '
import json
builds = [json.loads(line) for line in open("/tmp/transmit-profile-build.jsonl")]
print(next(build["executable"] for build in builds
           if build.get("executable") and build["target"]["name"] == "stamp_suite"))
')
STAMP_TX_BENCH_CASE=burst-auth-ipv6 valgrind --tool=dhat --mode=heap \
  --num-callers=40 --dhat-out-file=/tmp/transmit-heap.dhat \
  "$TX_BIN" receiver::transmit::benchmarks::transmission_allocations \
  --exact --ignored --nocapture --test-threads=1 > /tmp/transmit-profile.log
```

Repeat with `--mode=copy` and a different output file to see copy events. The
[DHAT manual](https://valgrind.org/docs/manual/dh-manual.html) describes how it
accounts for heap blocks and reallocations, how copy mode works, and its JSON
and viewer output. Look only at program points whose stack contains
`benchmarks::profile_send_region`. Whole-process totals also include work done
by the test harness, the fixtures, verification and the report. In copy mode,
tell the benchmark's preallocated frame-capture copy point apart from the
transport copies, because both are inside the named region. The memcpy and
memmove events that DHAT sees do not include copies that the compiler inlined
into other instructions, so they do not count every copied byte. Heap totals
are DHAT allocation blocks and bytes, not Rust `GlobalAlloc` request counts or
RSS.

`STAMP_TX_BENCH_CASE` defaults to `ordinary-open-ipv4`. A tag combines a
scenario (`ordinary`, `padded`, `burst`, `trim`, `alternate`, `mtu_race`,
`cos`, `srv6`), `open` or `auth`, and `ipv4` or `ipv6`. SRv6 cases exist only
for IPv6. `STAMP_TX_BENCH_ITERATIONS` defaults to ten and takes 1–1,000. Debug
runs and invalid selections fail without a completed report. A successful run
prints a `TX_BENCH_JSON ` report with counts, source and binary hashes and
features.

Ordinary replies are just the 44/112-byte base. The other replies are 1,440
bytes and carry Direct Measurement and Follow-Up Telemetry. Authenticated
replies with TLVs also carry a generated TLV HMAC. Bursts produce 32 successful
copies. Trim fixtures clamp the reply to 900 bytes and stop the burst. When a
send to an alternate return address or over SRv6 fails, the fallback restores
the untrimmed reply. EMSGSIZE refreshes the budget once, and CoS retries the
marking with the fallback value. Validation checks the base and TLV
signatures, sequence number, T3, counters and previous-reflection fields of
every attempt. It also checks the final length, the C and U flags, the routing
options and the count of successful copies.

Allocating fixtures, keys and captures, validation and report generation all
happen outside the named boundary. Plan preparation, finalization, shaping,
signing, retries and dropping buffers, as done by the send method, happen
inside it. The mock sends copy into preallocated frame buffers and inject
controlled errors. Packets, sockets, kernel send cost, input parsing,
admission, queue scheduling and real rate pressure are not measured. Native
elapsed time includes frame capture, and elapsed time under the profiler
includes the tool's overhead. Neither predicts packet throughput. Save the raw
profiles, the build, compiler, revision and tool metadata, and the process
reports, and repeat cases before you compare buffer changes.

