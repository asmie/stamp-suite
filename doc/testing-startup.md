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
artifacts. The control in
[`reflector_launcher_test.rs`](../tests/reflector_launcher_test.rs) now holds the
competing endpoint continuously, verifies a fixed-port child's bind error and
reaped status, then starts a port-zero reflector while the competing socket
is still held. A request/reply verifies that the new endpoint actually works.
The follow-up below removes the control's own reserve/drop/rebind gap.

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

## Teardown ownership follow-up (10 November 2026)

Review against `59c3d94` follows the T22b5 all-features failure at
`retained_socket_excludes_other_binders_and_is_released_on_teardown`: after
dropping the receiver, the test tried to bind its just-released ephemeral port
and received AddrInUse. That assertion confuses the receiver retaining its
socket with another owner making the endpoint unavailable.

The new Linux control
`tests/reflector_launcher_test.rs::teardown_observer_distinguishes_retained_socket_from_another_endpoint_owner`
checks both cases independently, in IPv4 and IPv6. A deliberately retained
duplicate remains detectable after the receiver has stopped. Dropping that
duplicate closes the original socket, while a different socket still holds
the same endpoint. The old rebind assertion fails in this state even though
the original socket is closed; `/tmp/t6b-before.log` records that red check.
Both control sockets enable reuse before binding, so establishing the other
owner needs no unreserved bind window. This is test setup, not a production
socket-option change.

The observer records the original socket's inode link and checks all descriptors
in the test process after shutdown. Linux documents the socket identity format
in [proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).
It retains no duplicate itself, distinguishes another socket at the same
endpoint, and detects an original duplicate under any descriptor number.
Unrelated descriptors can close during enumeration; only those NotFound races
are ignored. Other observation errors fail the test. This check concerns this
process's ownership, not global port availability or descriptors in other
processes.

The first stress run after changing the teardown assertion failed on round 2
in the separate `released_reservation_can_be_taken_but_port_zero_startup_is_unaffected`
control. Its own reserve/drop/rebind sequence hit AddrInUse before a receiver
was launched. `/tmp/t6b-stress-before.log` preserves that failure without retry.
The control now keeps the competing socket continuously bound, checks the
fixed-port reflector's bind failure and reaped child, and verifies that a
port-zero reflector serves a real request while the occupied endpoint remains
held. Neither test assumes that a released endpoint stays free.

`tests/common/receiver.rs` now accepts an owned socket for inspection and offers
explicit `stop()`: cancel, drain and join, returning the worker's result or
panic error. The main lifecycle test checks this result before asserting Linux
socket closure. `tests/reflector_launcher_test.rs::explicit_receiver_stop_reports_startup_failure`
verifies that a connected socket's startup failure reaches the caller. Drop
remains best-effort cleanup, including during unwinding.

There are nine launcher tests on Linux and eight on other Unix nix profiles.
Both families retain live request/reply, exclusive-bind and clean-exit checks;
the independent kernel identity/duplicate checks require Linux procfs. This
removes two unsafe rebind assumptions, but does not identify the uncaptured
competing owner in the original T22b5 failure. No application code, CLI defaults,
production socket policy, worker limits or CI gates change.

Final T6b checks pass all 18 targeted shared-fixture/lifecycle tests, then
20 consecutive all-features launcher rounds with eight workers (180/180 tests,
no failed rounds retried). Full default/all-features/pnet suites pass
**1,354/1,456/1,291** tests, respectively, with 13 privileged tests ignored in
each ordinary run. All three Clippy profiles, rustfmt, 104 Python tests,
matrix counts, 1,144 source citations and 443 documentation links pass.
The normative test-reference inventory stays **322 applicable, 237 with
references, 85 missing**; strict CI enforcement remains pending.

The optional macOS cross-test check could not finish: C dependency builds for
`alloca` and `ring` invoke the host `cc`, which rejects Darwin options such as
`-arch` and `-mmacosx-version-min`. Run the existing native macOS CI job with
its native compiler/SDK to verify that profile. No native macOS or remote CI
pass is claimed. Application/fuzz code and wire formats did not change, so no
new privileged, wire-oracle or fuzz run was needed for this fixture-only chunk.
Logs are `/tmp/t6b-*`; the failed controls remain recorded separately from
the final passing runs.

```sh
cargo test --locked --all-features --test reflector_launcher_test --test session_identity_test --test keyset_fallback_test --test session_auth_admission_test
cargo test --locked --all-features --test reflector_launcher_test --no-run --message-format=json > /tmp/t6b-launcher-artifacts.json
```

Stress uses that one fixed all-features executable for 20 sequential rounds,
each with `--test-threads=8`, requires exactly nine passing/unignored tests per
round, and stops on the first failure. Do not rebuild/change profiles while
the stress executable is running.

## CI follow-up (10 November 2026)

[CI run 42791508079](https://github.com/asmie/stamp-suite/actions/runs/42791508079)
failed on `64465ea12eea343fdd0bb4e898b5b0537669e7f0`, before the local
CoS/ECN evidence commit `06c4848`. Five failed jobs have three test defects:

| Failed jobs | Cause | Correction |
| --- | --- | --- |
| Native macOS, default and all-features | Launcher tests reference `libc`, but the direct dev dependency is Linux-only. | Import the existing `nix::libc` re-export on Unix. |
| Windows runtime core | The ECN fallback test expects source pinning on Windows, where the transport uses kernel source selection. | Require the requested source on Linux and `None` elsewhere; retain destination, DF, marking, burst-copy and signature assertions. |
| Ubuntu beta and default-feature tests | Peer receipt can precede post-send session bookkeeping, allowing the authentication test to snapshot an incomplete valid reflection. | Wait for the reflected-packet counter, which advances after the session updates, before taking the baseline. Disable unrelated asynchronous kernel TX timestamp correction in this admission fixture. |

The missing macOS test-artifact errors follow the compile failure: the test
step never ran. Existing artifact and test gates remain unchanged.
[Conformance evidence passed](https://github.com/asmie/stamp-suite/actions/runs/42791508083)
on the same commit. These observations do not establish CI status for the
uncommitted corrections.

For a causal Linux reproduction, a temporary `LD_PRELOAD` interposer calls the
real `sendmsg`, preserves its result and errno, then delays return by 50 ms
after successful delivery. This gives the peer time to receive a valid reply
before the receiver updates its state. The original invalid-HMAC test fails
with the same zero-baseline/nonzero-final timestamp assertion as CI. The
corrected test passes under the identical delay. It now requires one recorded
transmission and a nonzero baseline reflection timestamp before sending the
invalid requests; authentication rejection assertions remain intact.

All four admission tests then pass 20 rounds in each of the all-features and
default profiles under that delay, with four test workers: **160/160**, no
ignored tests and no failed rounds retried. Both address families remain
covered. The interposer and stress driver are temporary diagnostics, not
production dependencies. Logs use `/tmp/ci-fix-*`.

An isolated macOS-target check of the exact launcher test source reproduces
the three unresolved-`libc` errors before the import and compiles after it.
The temporary Cargo harness uses the real default-feature library as a path
dependency and the launcher's direct dependencies, avoiding unrelated
`alloca`/`ring` cross-C builds. Its dummy binary only supplies the compile-time
executable path. This checks macOS source compilation, not native execution
or the complete all-features graph. Native macOS and Windows jobs must run
after the manual commit; no remote pass is claimed.

Final local checks pass full default/all-features/pnet suites with
**1,364/1,466/1,295** tests, respectively (13 privileged tests ignored in each
ordinary run). The corrected ECN fallback case passes in all three profiles.
All three Clippy profiles, rustfmt, 104 Python tests, release metadata, matrix
counts, 1,201 source citations and documentation checks pass. The link checker
checks 377 local links and classifies 68 external links (445 total); external
destinations are not fetched. Strict evidence checking fails only on the
expected 56 missing references.

No application code, wire format, dependency graph or CI gate changes.
Conformance status and the **320 applicable / 264 referenced / 56 missing**
test-evidence inventory stay unchanged. Strict evidence enforcement remains
pending.

## macOS metadata startup follow-up (10 November 2026)

The next [CI run, 42799623458](https://github.com/asmie/stamp-suite/actions/runs/42799623458),
on `ef3f78d3aeaa0711741884aee41d05ac9bdadaa8`, passes 21 of 23 jobs.
Windows, Linux stable/beta, all Clippy jobs and macOS compilation pass.
Only the two native macOS runtime jobs fail: eight tests in the default
profile and ten with all features, across keyset-fallback, launcher,
authentication-admission and session-identity suites. They share the
in-process receiver fixture. Timeouts can leave received counters at zero;
two admission tests pass in the default profile but fail with all features.

The fixture retained the bound port but returned immediately after spawning
its receiver thread. A caller could send before that thread enabled
`IP_RECVTTL`/`IPV6_RECVHOPLIMIT`. Apple's
[UDP input path](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/udp_usrreq.c)
constructs ancillary controls before appending a datagram to the socket queue;
[IPv4 control creation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/ip_input.c)
includes TTL only when its receive option is enabled. A queued early packet
can therefore lack metadata even after setup completes. The nix receiver
requires real TTL and discards such a packet before session counters advance.
This explains the macOS symptoms; native execution of the correction remains
pending the manual commit and next CI run.

The fixture now acknowledges its receiver's initial poll over a bounded
channel before returning. The nix backend completes socket setup before its
first suspension. The acknowledgement also unblocks on a startup error so
existing `stop`/`assert_running` checks retain the actual failure. The parent
bounds startup waiting to five seconds and keeps its normal shutdown owner
while waiting. No warmup request, retry or fixed startup sleep is added, so
authentication/admission tests still start with untouched session state.

The new IPv4/IPv6 regression observes the real socket's TTL/Hop Limit receive
option before sending anything, requires zero received/reflected packets and
zero sessions, closes its temporary observation descriptor and checks clean
shutdown. A temporary `setsockopt` interposer delays enabling metadata by
100 ms, then calls the real syscall without changing its arguments or result.
The regression fails against the original fixture (`TTL capture must be
enabled before return`, value zero) and passes with the acknowledgement under
the same delay. This reproduces the ordering defect on Linux; it does not
claim to reproduce the Darwin kernel itself. Logs use `/tmp/ci-macos-*`.

All four affected suites pass under the setup delay in default and
all-features profiles: **38/38** tests with eight workers. The new startup
regression also passes 20 consecutive delayed rounds per profile, **40/40**
tests with both families each round. No failures are retried or tests ignored.
The isolated macOS-target harness compiles the exact modified fixture and
launcher source against the real default library; full native execution is
still required in CI.

Final Linux default/all-features/pnet suites pass **1,365/1,467/1,295** tests,
respectively, with 13 privileged tests ignored in each ordinary run. Both nix
profiles also pass the existing startup-error propagation check. All three
Clippy profiles, rustfmt, 104 Python tests, release metadata, matrix counts,
1,201 source citations and documentation checks pass. The link checker checks
378 local links and classifies 71 external links (449 total). Strict checking
fails only on the unchanged 56 missing test references. No remote CI pass is
claimed for this correction.

```sh
cargo test --locked --all-features --test reflector_launcher_test --test keyset_fallback_test --test session_auth_admission_test --test session_identity_test
```

The change is confined to shared test startup, a regression and documentation.
Application code, TTL requirements, dependency graphs and CI gates are
unchanged. Remaining conformance references and strict enforcement stay
separate from this repair.

## Validation and reproduction

Original T6 snapshot: local suites passed 1,315 default, 1,416 all-features and
1,264 pnet tests;
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
