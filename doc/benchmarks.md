# Measuring reflector performance

Measure reflector throughput and CPU cost with Criterion and live UDP tests.

Use both the in-process Criterion benchmarks and the live UDP benchmark.
Criterion isolates parsing, authentication, TLV processing and assembly. The
live benchmark adds the receive and send syscalls, session locks and the
scheduler, and checks that the reflector sleeps after traffic.

## Live UDP on Linux

Build the reflector and load generator together, with identical feature flags:

```bash
cargo build --locked --release --bin stamp-suite --example live_udp_bench
target/release/examples/live_udp_bench --rate 10000 > live-ipv4-open.json
target/release/examples/live_udp_bench --rate 10000 --ipv6 --authenticated \
  --stateful > live-ipv6-auth-stateful.json
```

Each invocation runs three fresh reflectors, sequentially. Each trial uses
one loopback session: readiness probe, 2 s idle, probe, 3 s load, 500 ms drain,
2 s idle, then a final verified probe. Probe traffic is excluded from load
counts. Packets are 44 bytes open or 112 authenticated, without TLVs, bursts
or kernel/NIC timestamps. A fixed timestamp checks echoes; delays are not
measured. The HMAC key is public test data.

Options (`live_udp_bench --help` lists limits and defaults):

| Option | Effect |
| --- | --- |
| `--reflector PATH` | Binary to launch; defaults to `target/release/stamp-suite`. |
| `--ipv6` | Use `::1` instead of `127.0.0.1`. |
| `--authenticated` | Generate and verify HMACs on every packet. |
| `--stateful` | Enable the reflector's independent sequence counter. |
| `--rate PPS` | Requested send rate, 1–1,000,000 packets/sec. |
| `--seconds N` | Load duration, 1–60 seconds. |
| `--idle-seconds N` | Duration of each idle observation, 1–60 seconds. |
| `--repeats N` | Independent trials, 1–100. |
| `--drain-ms N` | Extra response collection time, 1–10,000 ms. |
| `--workers N` | Reflector Tokio workers, 1–256; default 2. |
| `--hwtstamp MODE` | Reflector `--hwtstamp` mode: `off` (default), `auto` or `on`. `auto` is the reflector's own default and adds TX timestamp work when the binary is built with `hwtstamp`. |
| `--metrics` | Start the reflector with `--metrics` on an ephemeral loopback port, to include the metrics cost. The reflector binary must be built with the `metrics` feature, or it fails at startup. |

The generator sends 1 ms batches, skips missed pacing slots, and drains replies
on a separate thread. Bookkeeping is bounded by `rate × seconds + 1` slots
(about 60 MB at the maximum). Startup and post-idle probes have five-second
limits. Child exit, socket errors, invalid accounting, or zero valid replies
fail the run; all child processes are reaped.

Replies must match the connected source, packet length, echoed fields, sequence
range, and HMAC. Duplicates and invalid replies are counted separately. Loss is
reported even if the process exits successfully. Save stderr diagnostics with
the JSON on stdout. These checks validate benchmark accounting, not conformance.

### Reading the results

- `achieved_send_pps` counts successful send syscalls per actual load wall time.
  Compare it with `settings.rate`; `skipped_pacing_slots` counts unsent positions
  in the requested schedule. A low achieved rate can be a generator/scheduler
  limit. It is not evidence that the reflector has reached capacity.
- `unique_receive_pps_during_load` counts unique valid replies read during the
  configured load window. Late replies are reported separately as
  `unique_during_drain`, rather than inflating steady-load throughput.
- `missing_after_drain` and `loss_percent` compare successful sends with all
  unique replies collected before the drain deadline. Loss can occur in either
  direction or in the generator's receive queue; this harness cannot localize it.
- CPU comes from each process's `/proc/PID/stat` user + system ticks, including
  its threads. `percent_one_core` is CPU seconds / wall seconds × 100 and can
  exceed 100 for multiple busy threads. The generator CPU includes packet
  creation, request HMACs, receive validation and bookkeeping. Load CPU is
  sampled at the sender's stop, excluding the subsequent drain. Socket timeout
  and scheduler delays can make that stop slightly later than the requested
  receive/load window; the actual CPU wall interval is reported.
- Idle samples report raw ticks and their frequency. Zero observed ticks means
  usage below the accounting resolution, not proof of zero CPU work. Use longer
  idle windows when comparing small changes. `resume_after_idle` confirms that
  the last probe received a valid reply. The `idle_cpu_test` integration tests
  enforce an idle CPU ceiling separately.

JSON also records the command, generator feature flags, debug-build indicator,
binary SHA-256 hashes, kernel, CPU model and inherited CPU affinity. Record
`rustc -Vv`, build commands, revision and host load alongside it. Feature flags
describe the generator build; they cannot verify an arbitrary reflector binary.
Do not rebuild either executable during a run. Use release builds, repeat each
case, and compare medians and ranges rather than a single best result.

Sweep IPv4/IPv6 and both authentication modes at 5,000, 25,000 and 100,000 pps.
Add `--stateful` to measure session costs. Hold workers, CPU affinity, features
and host load constant; use more repeats on a quiet host. This single-session
loopback test can be limited by either process or the kernel. It does not
measure NIC throughput, multi-client scaling, latency, TLVs, bursts or hardware
timestamps, and requires matched before/after runs to assess an optimization.

For pnet, build with `--no-default-features --features ttl-pnet` and run with
`CAP_NET_RAW` in an isolated network namespace. Raw capture requires complete
UDP checksums, and checksum-offloaded loopback frames can fail validation; use
a controlled veth setup if loopback cannot provide complete checksums. Where
unprivileged user namespaces are available:

```bash
cargo build --locked --release --no-default-features --features ttl-pnet \
  --bin stamp-suite --example live_udp_bench
unshare -Urn sh -ec 'ip link set lo up; target/release/examples/live_udp_bench --rate 5000' \
  > live-pnet-ipv4-open.json
```

`--all-features` selects nix, so it is not a pnet measurement. Other operating
systems need a different CPU-accounting adapter; this harness fails explicitly
there. Missing IPv6, raw-socket permissions or a failed reflector startup also
fail explicitly rather than yielding a skipped benchmark.

## In-process regression benchmarks

```bash
cargo bench --locked --bench reflector_hotpath
cargo bench --locked --bench reflector_hotpath -- unauth_full_chain
cargo test --locked --example live_udp_bench
```

Criterion HTML reports land under `target/criterion/<bench>/report/`. These
benchmarks complement the live measurements; their operations/sec do not
predict end-to-end UDP packets/sec. The example's unit tests check reply
validation and loss/duplicate/reordering accounting without requiring sockets.
Linux CI runs these accounting tests; it does not enforce throughput thresholds
on shared runners.

`auth_full_chain` includes valid base and TLV HMACs, Location requests and
observed address/counter metadata. Setup verifies the response's integrity
flags and HMAC before timing. `auth_chain_missing_tlv_hmac` separately measures
the rejection path and checks its I flags. Run fixture checks without a timing
comparison with:

```sh
cargo test --locked --all-features --bench reflector_hotpath -- --test
```

## Session-table scaling

The separate `session_scaling` harness measures IPv4 and IPv6 tables with
1,024, 16,384 and 65,536 distinct, complete session identities. Fixture setup
checks capacity and inventory membership, retained cleanup and full expiry.
Addresses are in-memory fixtures; the harness sends no packets.

```sh
cargo test --locked --bench session_scaling -- --test
cargo bench --locked --bench session_scaling
cargo bench --locked --bench session_scaling -- 'session_table/inventory_'
```

Each benchmark name includes the operation, address family and table size:

| Operation | Timed work |
| --- | --- |
| `lookup_refresh` | Step through a deterministic permutation of seeded identities, acquire each selected session, refresh activity and release the returned Arc. |
| `inventory` | Collect and destroy the full extended summary vector used by control/SNMP inventory. HTTP DTO conversion and serialization are excluded. |
| `cleanup_keep` | Scan a full table with no expired sessions (`Duration::MAX` timeout). |
| `cleanup_expire` | Remove and retire every entry from a fresh full table (`Duration::ZERO` timeout). Population and final table destruction are excluded using one fixture per iteration. |
| `control_churn` | Cycle over unique clients, expire one through the control API's manager operation and admit its replacement while keeping table size bounded. Includes that operation's full-table ambiguity scan; HTTP is excluded. |

Population, access-order construction and fixture validation are outside the
timed loops. Lookup and control churn retain their access cursor across samples
and use an odd-stride permutation to spread short samples across the table.
A short run need not visit every key. `unauth_stateful_sessions` repeatedly
processes one source against a populated table. Inventory includes vector
allocation/free; expiry includes the session retirement/removal work. Cleanup
assertions remain in the timed loop so an empty-table or no-op result cannot
silently replace the intended workload.

These are single-thread operation timings. They do not measure blocked ingest,
concurrent inventory, mixed-age expiry, allocation counts or packet latency.
Criterion's sample distributions are not per-request latency percentiles.
Measure those separately before selecting a cleanup or pagination change.

Record revision, patch/build flags, compiler, executable hash, affinity, host
load and repeated-run variation. Use the same fixtures and features for matched
before/after comparisons; pin a CPU on Linux if the environment permits it.
Process CPU/RSS measurements include setup and Criterion analysis, so they
are not operation-only resource costs. Keep generated results in ignored or
external storage. Linux CI executes fixture checks without timing thresholds.

## Session instruction profiles

The same `session_scaling` executable has a separate fixed-count profiling
mode. Its non-inlined `session_scaling::profile_operation` boundary contains
one lookup/refresh, full inventory, retained cleanup, full expiry, or control
expiry/replacement operation. Normal Criterion timing loops do not call this
wrapper. Build optimized code with debug information, and select Cargo's exact
executable rather than a potentially stale wildcard match:

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

Install Valgrind and matching system debug symbols separately. The
[Callgrind manual](https://valgrind.org/docs/manual/cl-manual.html) explains
collection toggling and instruction/call-graph attribution. Check that the
profile has nonzero `Ir`, the expected number of `profile_operation` calls,
and that their inclusive instruction cost accounts for the collected total;
an unmatched symbol can otherwise produce an empty profile. Call counters on
other functions can include calls from phases where collection is disabled;
use the allocation example for allocator-request counts.

`--profile-operations` must be the executable's first argument. Its options
are `--sessions` (1–65,536, default 16,384), `--ipv6`, `--operation`
(`lookup-refresh`, `inventory`, `cleanup-keep`, `cleanup-expire`, `control-churn`)
and `--iterations` (1–1,000, default 10). Every iteration gets a fresh full table.
Population, key selection, validation, result storage, report generation and
final table destruction are outside the profiling boundary. Returned Arc/vector
destruction and removal/retirement work are inside. No other session references
or transmission guards are held. Fixture checks exercise all ten family/
operation combinations and argument bounds without requiring a profiler.

JSON reports validated item counts and final table size per operation, build
features, executable/source hashes and release/debug status. Debug runs fail;
panics produce a failing process rather than a completed JSON report. Save the
raw profile, annotations, compiler/build command, revision/patch, tool version
and process output together. Repeat each workload with the same build and
profiling configuration before interpreting differences.

Callgrind's `Ir` is a count of instrumented user-space instructions, including
the wrapper and its checks. It is not CPU cycles, kernel work, wall latency,
lock-wait time or packet throughput. Hash-table order, heap state, code generation
and profiler behavior affect the profile. This single-thread mode covers no
concurrent expiry, active transmit guards, network traffic or hardware caches;
cache/branch simulation is off in the command above. Use the native timing and
contention measurements alongside profiles before selecting an optimization.

## Concurrent session management

`session_contention` measures each foreground session-manager call while a
second thread repeatedly collects full inventory or scans retained sessions
for cleanup. Compare each case with `--background none` using the same build,
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
cycles through clients on a separate source port, creates one transient
session, then retires it using the control manager operation. The table stays
between N and N+1 sessions. Admission latency excludes retirement;
`retirement_latency` reports its full-table ambiguity scan and any wait for the
table lock, while `admission_cycle_latency` includes both stages.

`--sessions` accepts 1–65,536 entries; `--ipv6` selects IPv6 identities.
Each invocation defaults to three one-second trials (`--seconds` 1–60,
`--repeats` 1–100). `--pause-us` pauses after each background operation,
defaulting to 1,000 microseconds; zero requests continuous management pressure.
This is a pause, not a guaranteed management request rate. Use at least two
CPUs and record their affinity; allowing two CPUs does not pin each thread
to a separate core. Debug builds refuse performance runs.

JSON records counts, observed closed-loop operations/sec, min/max/mean and
p50/p95/p99 call latency in nanoseconds, background operation costs, window
overrun, final table size, feature flags and binary/source hashes. Every call
contributes to bounded full-run quantiles: exact through 4,096 observations,
then less than 0.78125% magnitude quantization error. Counts at or above 1 ms/10 ms
and observed extrema remain exact. Sampling uncertainty and scheduler/clock
effects are separate from that quantization bound.

This closed-loop producer issues its next call after the previous cycle ends.
It measures neither independently arriving traffic nor the queueing time that
packets could accumulate while a call is blocked. Reported throughput includes
statistics collection and, for admission, retirement work. Clock/call overhead
is included; no packets, HTTP, mixed-age expiry, transmit guards or hardware
timestamps are involved. Cleanup uses `Duration::MAX` and removes no entries.
Table population and thread creation precede the active window; worker
teardown and final summarization follow it. A run with
no probe or requested background progress fails and prints an incomplete
report with the completed trials. CI tests invariants and failure handling;
it imposes no latency or throughput threshold.

## Session allocation requests

`session_allocations` counts Rust allocator requests made by one session-manager
operation on the calling thread. Its allocator wrapper delegates to `System`
and exists only in this example executable. It does not change the allocator
used by `stamp-suite`, other examples or the library's consumers.

```sh
cargo build --locked --release --example session_allocations
target/release/examples/session_allocations --sessions 65536 \
  --workload inventory > /tmp/session-inventory-allocations.json
target/release/examples/session_allocations --sessions 65536 --ipv6 \
  --workload cleanup-expire > /tmp/session-expiry-allocations.json
cargo test --locked --example session_allocations
```

Choose `--workload lookup-refresh`, `inventory`, `cleanup-keep`,
`cleanup-expire` or `control-churn`; these correspond to the single-thread
session-table scaling operations above. Each sample runs exactly one operation
against a freshly populated table. Lookup releases its returned Arc, inventory
destroys its summary vector, and control churn expires one client and releases
its replacement Arc inside the counted scope. Full expiry includes removal,
retirement and session destruction. No external session references or active
transmit guards are held. Table population, key selection, result storage,
validation, JSON and final manager destruction are excluded.

`--sessions` accepts 1–65,536 identities (default 16,384), `--ipv6` selects
IPv6, and `--iterations` accepts 1–1,000 samples (default 10). Debug builds
refuse measurement runs. JSON records each sample, final table size, build
features, executable/source hashes and the Git HEAD observed at execution.
Record compiler, build command and revision/patch alongside the output.
Counts describe that compiled build; optimization can change allocator calls.

`alloc_calls` and `alloc_zeroed_calls` are separate successful requests;
`allocated_bytes` includes both. Successful `realloc_calls` report old and new
requested sizes separately, without also incrementing alloc/dealloc counts.
`dealloc_calls` and `deallocated_bytes` include blocks allocated during setup
when the operation frees them. `requested_bytes_delta` is allocated plus
reallocated-to bytes minus deallocated and reallocated-from bytes. It can be
negative during expiry. Detected accounting or table errors fail the run with
an incomplete report containing completed samples. Panics or allocator aborts
can terminate the process before a report is emitted.

These are requested layout sizes at Rust's `GlobalAlloc` boundary. They are
neither allocation site backtraces, internal `System` allocator calls, memory
copies, live/peak heap usage nor RSS. Other threads and native allocations
that bypass the Rust allocator are excluded. The counter itself uses
allocation-free thread-local storage. It changes execution cost, so this
example reports no timing or throughput. Use a CPU/heap profiler and matched
workloads before deciding on an optimization. CI checks allocator accounting,
thread isolation and operation invariants without enforcing allocation budgets.

## MTU-cache capacity and route-query cost

Three ignored library tests provide opt-in release measurements of the private
MTU cache without exposing application APIs or changing cache policy. Normal
CI runs a functional fixture test; it does not run these timing measurements.

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

Successful runs print one `MTU_BENCH_JSON ` line containing their JSON report
alongside the Rust test harness output. Debug measurement runs fail. Reports
include executable/cache/driver source hashes, feature flags and each sample.
Record compiler, build command, revision/patch, CPU affinity and host load too.
Run multiple fresh processes; each invocation contains three repetitions.

Capacity traces use 128, 256, 257, 512 and 1,024 distinct destination IPs in
IPv4/IPv6. One trace cycles through all destinations; the other issues eight
lookups cycling over 64 hot destinations, then one lookup cycling over the
remaining destinations. Sixteen complete destination/cold-set traversals follow
one unmeasured pass over all keys. Each case starts with a fresh cache.

The capacity driver calls the real internal lookup policy with a cheap,
destination-specific synthetic query result. It freezes the lookup's supplied
time so entries never expire, isolating capacity behavior from the 250 ms TTL.
It bypasses route-key construction and notification handling. Counts report
synthetic queries/misses, hits, warmup queries, peak/final entries and a checksum;
every result and the cache bound are validated. Native batch wall time includes
key cloning, counters, result comparisons and checksum/peak tracking. Input
construction, warmup and final destruction are excluded. This is neither a
packet workload nor a measurement of kernel-route lookup throughput.

The Linux-only calibration directly calls the real route query 1,000 times per
sample, after one unmeasured query. It covers wildcard/bound sources for IPv4
and IPv6 loopback, checks that MTU stays valid and unchanged, and records all
individual wall latencies plus exact nearest-rank p50/p99 and extrema. It uses
route netlink requests and interface MTU lookup; no UDP packets are sent. The
socket lifecycle, request construction, syscalls and response parsing are timed;
sample recording and sorting are excluded. The subscription/invalidation path
and payload-cap computation are not included. Missing Linux support, socket
permission, routes or a changing MTU prevents a completed calibration report.

The Linux-only `loopback_capacity` driver runs the same working-set sizes and
trace patterns through the full payload-cap lookup path with real time. Each
case uses four traversals after warmup, with route-key construction, notification
polling, expiry checks, route queries and IP/UDP overhead calculation included.
IPv4 uses distinct addresses in 127.0.0.0/8; IPv6 uses distinct destination ports
on ::1, so its distinct keys represent UDP flows rather than distinct IPs.
No UDP packets are sent. A successful notification subscription is required;
every cap, hit/query count and cache bound is checked. A test-only thread-local
counter records real route-query calls and adds no work to application builds.
Input setup, warmup and final destruction are outside batch timing; counters,
result comparisons and peak tracking are inside. TTL expiry or actual route
notifications can increase query counts, so retain all counts with the timing.

For an eviction comparison, build both policies with identical driver code,
features and compiler, retain both executables, and alternate their run order
on the same CPU. Compare query counts as well as repeated native wall times;
do not turn a synthetic-query timing difference into a packet-throughput claim.

Use query counts to compare policy behavior on identical traces. A cyclic
working set larger than the cache can miss under several eviction policies;
the hot/cold trace tests whether capacity pressure also loses frequently used
entries. Loopback query latency is context for miss cost, not a formula for
packet latency. Real route churn, TTL expiry, EMSGSIZE refresh, egress/source/
traffic-class isolation and missing notification behavior still require their
functional tests and live workloads before accepting an eviction change.

## Reply-transmission allocation and copy profiles

An ignored library test profiles already-assembled replies through the real
transmission finalizer. Normal CI validates all 30 fixtures without timing or
allocation budgets. Application code and allocators are unchanged by this
test-only driver. Build optimized code with debug information and select the
exact library-test executable:

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

Repeat with `--mode=copy` and a different output file to inspect copy events.
The [DHAT manual](https://valgrind.org/docs/manual/dh-manual.html) describes its
heap/reallocation accounting, copy mode and JSON/viewer output. Select only
program points whose stack contains `benchmarks::profile_send_region`; whole-
process totals also include test-harness, fixture, verification and report work.
In copy mode, separate the benchmark's preallocated frame-capture copy point
from transport copies. Both are inside the named region. Observed memcpy/
memmove events exclude copies inlined into other machine instructions, so they
are not a complete count of all copied bytes. Heap totals are DHAT allocation
blocks/bytes rather than Rust `GlobalAlloc` request counts or RSS.

`STAMP_TX_BENCH_CASE` defaults to `ordinary-open-ipv4`. Tags combine a scenario
(`ordinary`, `padded`, `burst`, `trim`, `alternate`, `mtu_race`, `cos`, `srv6`),
`open`/`auth` and `ipv4`/`ipv6`. SRv6 cases are IPv6-only. The
`STAMP_TX_BENCH_ITERATIONS` count defaults to ten and accepts 1–1,000. Debug
runs and invalid selections fail without a completed report. Successful runs
print a `TX_BENCH_JSON ` report with counts, source/binary hashes and features.

Ordinary replies have only the 44/112-byte base. Other replies are 1,440 bytes
with Direct Measurement and Follow-Up Telemetry; authenticated TLV replies also
carry a generated TLV HMAC. Bursts produce 32 successful copies. Trim fixtures
clamp to 900 bytes and stop the burst. Alternate/SRv6 failures restore the
untrimmed reply on fallback; EMSGSIZE refreshes the budget once; CoS retries
marking with the fallback value. Validation checks every attempt's base/TLV
signatures, sequence, T3, counters and previous-reflection fields, plus final
length, C/U flags, routing options and successful-copy accounting.

Fixture/key/capture allocation, validation and report generation are outside
the named boundary. Plan preparation, finalization, shaping, signing, retries
and buffer destruction performed by the send method are inside. Mock sends
copy into preallocated frame buffers and inject controlled errors. No packets,
sockets, kernel send costs, input parsing, admission, queue scheduling or real
rate pressure are measured. Native elapsed time includes frame capture, and
profiler-instrumented elapsed time includes tool overhead. Neither predicts
packet throughput. Save raw profiles, build/compiler/revision/tool metadata
and process reports, and repeat cases before comparing buffer changes.

The [2026-09-10 baseline](performance/2026-09-10-live-udp.md) records
54 live trials on both Linux backends, including the duplicate replies observed
with pnet loopback. Use its environment and workload limits when comparing results.
