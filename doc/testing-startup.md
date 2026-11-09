# Reflector startup fixtures

T6 removes the released-port handoff from nine live suites and preserves
actionable startup diagnostics. The parent revision was `0b290a4`. This work
does not change CLI defaults, packet processing, production worker counts or
pnet socket setup.

## Diagnosis

The old pattern selected an address by binding a temporary UDP socket, closed
it, then launched the reflector on that address. Readiness traffic used another
ephemeral socket. The temporary socket reserved the port only until close;
another socket could claim it before the reflector bound it. Most fixtures
discarded stderr, leaving only an exit/readiness assertion.

Local diagnosis on 9 November 2026 used the parent application, IPv4/IPv6
loopback, four concurrent launchers and captured stderr/exit status:

| Experiment | Result |
|---|---|
| Original pattern, default Tokio worker selection | 32/32 ready |
| Original pattern, two Tokio workers | 32/32 ready |
| Explicit competing bind in the released-port gap, both families and worker settings | 4/4 exit status 1, `Cannot bind to address` / OS error 98 |
| Migrated replay suite, 20 rounds with eight parallel tests | 160/160 tests passed, no retries |

This confirms a real handoff vulnerability and reproduces its bind failure.
The natural startup failure did not recur during the 64 original-pattern runs,
so neither port contention nor resource pressure is proven to explain every
historical failure. The new diagnostics preserve evidence if another cause
appears. Worker bounding is a test resource policy, not a claimed causal fix.

Temporary local records are `/tmp/t6-startup-probe.json`,
`/tmp/t6-startup-probe.log` and `/tmp/t6-repeat.json`; these are not durable CI
artifacts. The deterministic reproducer is retained in
[`reflector_launcher_test.rs`](../tests/reflector_launcher_test.rs): it takes the
released port before starting the old-style child, verifies the bind error and
reaped status, then starts a port-zero reflector while the competing socket
is still held. A request/reply verifies that the new endpoint actually works.

## Shared lifecycle

[`tests/common/reflector.rs`](../tests/common/reflector.rs) serves replay,
burst-transmission, idle-CPU, BER-measurement, session-capacity and reply-queue
tests. Each child binds port zero. The helper parses the existing JSON startup
message for the actual bound address and sends no readiness packets. The tests
still exercise IPv4/IPv6, open/authenticated modes, stateful/stateless sessions,
kernel timestamps, burst interleaving and bounded shutdown.

The session-capacity fixture's control API also binds TCP port zero; it reads
the existing control startup announcement before issuing HTTP requests, removing
the analogous temporary TCP reservation there.

Stderr is piped and continuously drained on a reader thread. Both the diagnostic
tail and the pending readiness line are bounded at 64 KiB; oversized lines are
discarded for readiness parsing without blocking drainage. Startup exit or
timeout returns a reason, PID, human-readable exit status and stderr tail.
The helper kills/waits its child and joins its reader on failure and teardown.
A short EOF grace permits collecting a child's actual exit status before forced
cleanup. It never restarts a failed child. Child fixtures use two Tokio workers
regardless of host CPU count, preserving ordinary test-harness parallelism.

[`tests/common/receiver.rs`](../tests/common/receiver.rs) serves session-identity,
keyset-fallback and session-auth-admission tests. These fixtures need exact
provisioned endpoints or direct access to counters/keys. They retain the bound
socket while building configuration and pass ownership to
`receiver::run_receiver_with_socket` on the nix backend. A dedicated
current-thread runtime runs each receiver, avoiding blocking a test's runtime
with synchronous UDP operations. Teardown cancels the receiver, bounds draining
to two seconds and joins its thread. Unexpected startup completion reports the
underlying result rather than merely asserting that a task finished.

The embedding API checks that the socket is unconnected and matches the
configured endpoint. Port zero accepts its assigned port. All existing socket
options, validation, settings, ancillary reception and packet processing still
run. No descriptor is released and rebound. The CLI's ordinary bind path
delegates to this same implementation after binding.

Admission fixtures send invalid input only once and wait for both receive and
drop counters, avoiding a race where receipt was observed before processing.
Other fixtures needing a warmup send one packet after obtaining the endpoint;
no automatic startup send/restart loop hides failure. The reply-queue fixture
still captures its JSON shutdown summary on stdout.

## Validation and reproduction

Local suites passed 1,315 default, 1,416 all-features and 1,264 pnet tests;
12/12/13 privileged tests remained ignored. All three Clippy profiles passed
with warnings denied. Rust 1.87 checked all-features/all-targets; Rustdoc,
rustfmt, 81 Python tests, matrix counts and 1,019 citations passed. The final
control-port change additionally passed all eight session-capacity tests and
the seven launcher tests with all features. Remote CI has not run this chunk;
native macOS runtime was not tested locally.

Seven launcher tests cover the deterministic race, valid assigned endpoints,
retained ownership and release, socket mismatch/connection rejection, missing
executables, early exit diagnostics, and timeout/flood cleanup. The controlled
child fixture reuses the test executable, requiring no shell/Python child and
creating no grandchildren. Tests check `waitpid` reports the failed/timed-out
child already reaped. The flood emits more than three diagnostic windows without
a newline before its tail, checking bounded memory and continuous drainage.

```sh
cargo test --locked --test reflector_launcher_test -- --nocapture
cargo test --locked --all-features
cargo test --locked
cargo test --locked --no-default-features --features ttl-pnet
```

For repeated replay runs, use a fixed build profile and run each command
sequentially; do not replace the executable with another build while running it:

```sh
for iteration in $(seq 1 20); do
  cargo test --locked --test replay_control_test -- --test-threads=8 || exit 1
done
```

The first failed round stops the repetition. This is stress validation, not
retrying failed tests until they pass. Linux gates already include all affected
targets; Unix nix targets also run in the existing native macOS jobs. No CI job
or concurrency suppression is needed. Local Linux runtime evidence does not
substitute for a native macOS run or ignored privileged tests.
