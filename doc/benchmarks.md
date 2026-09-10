# Measuring reflector performance

Use both the in-process Criterion benchmarks and the live UDP benchmark.
Criterion isolates parsing, authentication, TLV processing and assembly. The
live benchmark includes the receive/send syscalls, session locks and scheduler,
and measures whether the reflector sleeps after traffic.

## Live UDP on Linux

Build the reflector and load generator together, with identical feature flags:

```bash
cargo build --locked --release --bin stamp-suite --example live_udp_bench
target/release/examples/live_udp_bench --rate 10000 > live-ipv4-open.json
target/release/examples/live_udp_bench --rate 10000 --ipv6 --authenticated \
  --stateful > live-ipv6-auth-stateful.json
```

Each invocation starts three fresh reflector processes in sequence. Each trial
uses one measured UDP session on loopback, sends a readiness probe, observes two
seconds of idle time, probes the measured session, sends traffic for three
seconds, drains replies for 500 ms, observes another two seconds of idle time,
and verifies another reply. Hardware/kernel timestamping is explicitly off.
Probe traffic is excluded from load accounting. This is a baseline packet
workload (44 bytes open, 112 authenticated), with no TLVs or burst requests.
The fixed sender timestamp is an echo-validation marker; no latency or OWD is
measured. The HMAC key is a public test fixture.

Options (`--help` lists limits and defaults):

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

Packets are paced in 1 ms batches using a monotonic clock. Missed batches are
skipped instead of generating a catch-up burst. A separate blocking receive
thread drains the socket while the main thread sends. Bookkeeping is bounded
by `rate * seconds + 1` sequence slots (at most about 60 MB). Receive/send waits
are bounded; startup and post-idle probes must succeed within five seconds.
Child exit, socket errors, invalid accounting or zero valid load replies fail
the invocation. Loss or invalid replies are recorded, not hidden by a successful
process exit. Child processes are killed and reaped when a trial ends or fails.
Reflector diagnostics and progress go to stderr; only the final JSON goes to
stdout. Preserve stderr alongside the JSON when collecting evidence.

The connected UDP socket filters the response source. The generator checks
exact packet length, echoed SSID/timestamp/error estimate, sender sequence
range, and authenticated response HMAC. Unique replies, duplicates, invalid
replies and unique out-of-order replies are counted separately. This validates
benchmark accounting; it is not an independent protocol-conformance test.

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
  the last probe received a valid reply; existing `idle_cpu_test` regressions
  separately enforce a CPU ceiling.

JSON also records the command, generator feature flags, debug-build indicator,
binary SHA-256 hashes, kernel, CPU model and inherited CPU affinity. Record
`rustc -Vv`, build commands, revision and host load alongside it. Feature flags
describe the generator build; they cannot verify an arbitrary reflector binary.
Do not rebuild either executable during a run. Use release builds, repeat each
case, and compare medians and ranges rather than a single best result.

For a small rate sweep, run both families and authentication modes at 5,000,
25,000 and 100,000 requested packets/sec. Add `--stateful` when studying session
costs. Keep runtime workers, CPU affinity, feature flags and host load constant
across revisions. A larger repeat count and a quiet dedicated host improve
comparability. This is a single-session loopback workload: it does not establish
NIC throughput, multi-client scaling, latency, TLV/burst costs, hardware timestamp
performance or an optimization's before/after gain. Shared-host results can be
limited by either process and by loopback/kernel scheduling.

For pnet, build with `--no-default-features --features ttl-pnet` and run with
CAP_NET_RAW in an isolated network namespace. For example, where unprivileged
user namespaces are supported:

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

The [2026-09-10 baseline](performance/2026-09-10-live-udp.md) records the first
54 live trials on both Linux backends, including the duplicate replies observed
with pnet loopback. Use its environment and workload limits when comparing results.
