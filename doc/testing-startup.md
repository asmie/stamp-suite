# Reflector startup fixtures

Task T6 removed the released-port handoff from nine live test suites and kept
startup diagnostics that you can act on. It was based on revision `0b290a4`.
It does not change CLI defaults, packet processing, production worker counts
or pnet socket setup.

## Diagnosis

The old fixtures picked an address by binding a temporary UDP socket, closed
that socket, and then started the reflector on the same address. Readiness
traffic went through yet another ephemeral socket. The temporary socket held
the port only until it was closed, so another socket could take the port before
the reflector bound it. Most fixtures threw stderr away, so a failure left
nothing but an exit or readiness assertion.

The local diagnosis on 9 November 2026 ran the parent application over IPv4
and IPv6 loopback with four launchers at once, and captured stderr and the exit
status:

| Experiment | Result |
|---|---|
| Original pattern, default Tokio worker selection | 32/32 ready |
| Original pattern, two Tokio workers | 32/32 ready |
| Explicit competing bind in the released-port gap, both families and worker settings | 4/4 exit status 1, `Cannot bind to address` / OS error 98 |
| Migrated replay suite, 20 rounds with eight parallel tests | 160/160 tests passed, no retries |

So the handoff race is real, and binding into the gap reproduces the bind
failure. The failure did not happen on its own in any of the 64 runs of the
original pattern. Neither port contention nor resource pressure has been shown
to explain every past failure. If some other cause shows up, the new
diagnostics will capture it. Limiting the worker count is a resource policy for
the tests, not a claimed fix for the failure.

The local records from this work are `/tmp/t6-startup-probe.json`,
`/tmp/t6-startup-probe.log` and `/tmp/t6-repeat.json`. They are temporary files,
not CI artifacts. The control test in
[`reflector_launcher_test.rs`](../tests/reflector_launcher_test.rs) now holds
the competing endpoint for the whole test. It checks that a child on a fixed
port gets a bind error and has been reaped. Then it starts a reflector on port
zero while the competing socket is still bound, and a request and reply confirm
that the new endpoint works. The follow-up below removes the place where the
control test itself reserved, dropped and rebound a port.

## Shared lifecycle

[`tests/common/reflector.rs`](../tests/common/reflector.rs) is used by the
replay, burst-transmission, idle-CPU, BER-measurement, session-capacity and
reply-queue tests. Each child process binds port zero. The helper reads the
actual bound address from the JSON startup message the reflector already prints,
and sends no readiness packets. The tests still cover IPv4 and IPv6, open and
authenticated modes, stateful and stateless sessions, kernel timestamps, burst
interleaving and shutdown within a time limit.

The session-capacity fixture's control API also binds TCP port zero. The
fixture reads the control API's existing startup message before it sends HTTP
requests. This removes the same kind of temporary TCP reservation there.

Stderr is piped to a reader thread that reads it continuously. The diagnostic
tail and the pending readiness line are each capped at 64 KiB. A longer line is
dropped for readiness parsing, and reading carries on without blocking. If the
child exits or times out during startup, the helper returns the reason, the
PID, a readable exit status and the tail of stderr. On failure and at teardown
the helper kills its child, waits for it and joins the reader thread. A short
grace period after EOF lets it collect the child's real exit status before
forcing cleanup. It never restarts a failed child. Child fixtures run with two
Tokio workers whatever the host's CPU count, which leaves room for the test
harness's normal parallelism.

[`tests/common/receiver.rs`](../tests/common/receiver.rs) is used by the
session-identity, keyset-fallback and session-auth-admission tests. These
fixtures need exact provisioned endpoints or direct access to counters and
keys. They keep the bound socket open while building the configuration, then
hand it to `receiver::run_receiver_with_socket` on the nix backend. Each
receiver runs on its own current-thread runtime, so its synchronous UDP calls do
not block the test's runtime. Teardown cancels the receiver, gives it at most
two seconds to drain and joins its thread. If the receiver finishes during
startup when it should not, the fixture reports the underlying result instead
of only asserting that a task finished.

The embedding API checks that the socket is not connected and that it matches
the configured endpoint. With port zero it accepts whatever port was assigned.
All the usual socket options, validation, settings, ancillary-data reception
and packet processing still run. No descriptor is closed and bound again. After
binding, the CLI's normal path calls this same code.

Admission fixtures send invalid input only once and wait for both the receive
and the drop counters. That avoids a race where the test sees the packet arrive
before it has been processed. Other fixtures that need a warmup send one packet
once they have the endpoint. There is no automatic send-and-restart loop at
startup that could hide a failure. The reply-queue fixture still captures its
JSON shutdown summary from stdout.

## Teardown ownership follow-up (10 November 2026)

This review against `59c3d94` follows the T22b5 all-features failure in
`retained_socket_excludes_other_binders_and_is_released_on_teardown`. After
dropping the receiver, the test tried to bind the ephemeral port that had just
been released, and got AddrInUse. The assertion mixed up two different things:
the receiver still holding its socket, and some other owner making the endpoint
unavailable.

The new Linux control test
`tests/reflector_launcher_test.rs::teardown_observer_distinguishes_retained_socket_from_another_endpoint_owner`
checks the two cases separately, over IPv4 and IPv6. A duplicate descriptor
that the test keeps on purpose can still be found after the receiver has
stopped. Dropping that duplicate closes the original socket while a different
socket still holds the same endpoint. In that state the old rebind assertion
fails even though the original socket is closed. `/tmp/t6b-before.log` records
that failing check. Both control sockets enable address reuse before binding,
so setting up the other owner needs no moment where the port is unreserved.
This only affects test setup. Production socket options are unchanged.

The observer records the inode link of the original socket and, after
shutdown, checks every descriptor in the test process. Linux documents the
socket identity format in
[proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html).
The observer keeps no duplicate of its own. It tells another socket on the same
endpoint apart from the original, and it finds a duplicate of the original
under any descriptor number. Unrelated descriptors can close while the list is
being read. Only those NotFound races are ignored; any other error while
observing fails the test. The check is about which sockets this process owns.
It says nothing about whether the port is free system-wide, or about
descriptors in other processes.

After the teardown assertion was changed, the first stress run failed in round
2, in the separate
`released_reservation_can_be_taken_but_port_zero_startup_is_unaffected`
control. That control's own reserve, drop and rebind sequence hit AddrInUse
before any receiver was started. `/tmp/t6b-stress-before.log` keeps that
failure; it was not retried. The control now keeps the competing socket bound
the whole time. It checks that the fixed-port reflector fails to bind and that
its child is reaped, and checks that a port-zero reflector answers a real
request while the occupied endpoint is still held. Neither test assumes that a
released endpoint stays free.

`tests/common/receiver.rs` now accepts an owned socket for inspection and
provides `stop()`. It cancels, drains and joins the receiver, and returns the
worker's result or its panic error. The main lifecycle test checks that result
before it asserts that Linux closed the socket.
`tests/reflector_launcher_test.rs::explicit_receiver_stop_reports_startup_failure`
checks that a startup failure on a connected socket reaches the caller. Drop
still does best-effort cleanup, including during unwinding.

There are nine launcher tests on Linux and eight on the other Unix nix
profiles. Both sets keep the live request/reply, exclusive-bind and clean-exit
checks. The kernel identity and duplicate checks need Linux procfs. This
removes two unsafe assumptions about rebinding. It does not identify the
competing owner in the original T22b5 failure, which was never captured. No
application code, CLI defaults, production socket policy, worker limits or CI
gates change.

The final T6b checks passed all 18 targeted shared-fixture and lifecycle tests,
then 20 consecutive all-features launcher rounds with eight workers (180/180
tests, no failed rounds retried). The full default, all-features and pnet
suites passed **1,354/1,456/1,291** tests respectively, with 13 privileged
tests ignored in each ordinary run. All three Clippy profiles, rustfmt, 104
Python tests, the matrix counts, 1,144 source citations and 443 documentation
links passed. The normative test-reference inventory stayed at
**322 applicable, 237 with references, 85 missing**. Strict CI enforcement is
still pending.

The optional macOS cross-test check could not finish. The C dependency builds
for `alloca` and `ring` call the host `cc`, which rejects Darwin options such
as `-arch` and `-mmacosx-version-min`. To verify that profile, run the existing
native macOS CI job with its own compiler and SDK. No native macOS or remote CI
pass is claimed. Application code, fuzz code and wire formats did not change,
so this fixture-only chunk needed no new privileged, wire-oracle or fuzz run.
The logs are `/tmp/t6b-*`. The failed control runs are recorded separately
from the final passing runs.

```sh
cargo test --locked --all-features --test reflector_launcher_test --test session_identity_test --test keyset_fallback_test --test session_auth_admission_test
cargo test --locked --all-features --test reflector_launcher_test --no-run --message-format=json > /tmp/t6b-launcher-artifacts.json
```

The stress run uses that one fixed all-features executable for 20 rounds in a
row, each with `--test-threads=8`. Every round must have exactly nine passing,
non-ignored tests, and the run stops at the first failure. Do not rebuild or
switch profiles while the stress executable is running.

## CI follow-up (10 November 2026)

[CI run 42791508079](https://github.com/asmie/stamp-suite/actions/runs/42791508079)
failed on `64465ea12eea343fdd0bb4e898b5b0537669e7f0`, which comes before the
local CoS/ECN evidence commit `06c4848`. The five failed jobs came from three
test defects:

| Failed jobs | Cause | Correction |
| --- | --- | --- |
| Native macOS, default and all-features | Launcher tests use `libc`, but the direct dev dependency on it is Linux-only. | Import the existing `nix::libc` re-export on Unix. |
| Windows runtime core | The ECN fallback test expects the source to be pinned on Windows, where the transport leaves source selection to the kernel. | Require the requested source on Linux and `None` elsewhere. Keep the destination, DF, marking, burst-copy and signature assertions. |
| Ubuntu beta and default-feature tests | The peer can receive a reply before the reflector finishes its post-send session bookkeeping, so the authentication test can snapshot a valid reflection that is not complete yet. | Before taking the baseline, wait for the reflected-packet counter, which advances after the session is updated. Turn off the unrelated asynchronous kernel TX timestamp correction in this admission fixture. |

The missing macOS test-artifact errors followed from the compile failure,
because the test step never ran. The existing artifact and test gates were not
changed.
[Conformance evidence passed](https://github.com/asmie/stamp-suite/actions/runs/42791508083)
on the same commit. None of this shows the CI status of the corrections, which
were not committed at the time.

To reproduce the cause on Linux, a temporary `LD_PRELOAD` interposer calls the
real `sendmsg`, keeps its result and errno, and then waits 50 ms before
returning from a successful send. That gives the peer time to receive a valid
reply before the receiver updates its state. With this delay the original
invalid-HMAC test fails with the same assertion as in CI: a zero baseline and a
nonzero final timestamp. The corrected test passes under the same delay. It now
requires one recorded transmission and a nonzero baseline reflection timestamp
before it sends the invalid requests. The assertions that authentication
rejects those requests are unchanged.

With that delay in place, all four admission tests then passed 20 rounds in
each of the all-features and default profiles, with four test workers:
**160/160**, no ignored tests and no failed rounds retried. Both address
families are still covered. The interposer and the stress driver were temporary
diagnostics, not production dependencies. The logs are `/tmp/ci-fix-*`.

An isolated check of the exact launcher test source for the macOS target
reproduced the three unresolved-`libc` errors before the import was added, and
compiled cleanly after it. The temporary Cargo harness used the real
default-feature library as a path dependency, plus the launcher's direct
dependencies. That avoids the unrelated `alloca` and `ring` C cross-builds.
Its dummy binary only supplies the executable path needed at compile time. This
checks that the source compiles for macOS. It does not run anything natively
and does not cover the full all-features dependency graph. The native macOS
and Windows jobs had to run after the manual commit. No remote pass is claimed.

The final local checks passed the full default, all-features and pnet suites
with **1,364/1,466/1,295** tests respectively (13 privileged tests ignored in
each ordinary run). The corrected ECN fallback case passed in all three
profiles. All three Clippy profiles, rustfmt, 104 Python tests, the release
metadata, matrix counts, 1,201 source citations and the documentation checks
passed. The link checker checked 377 local links and classified 68 external
links (445 total). It does not fetch external destinations. Strict evidence
checking failed only on the expected 56 missing references.

No application code, wire format, dependency graph or CI gate changed. The
conformance status and the test-evidence inventory
(**320 applicable / 264 referenced / 56 missing**) did not change. Strict
evidence enforcement is still pending.

## macOS metadata startup follow-up (10 November 2026)

The next [CI run, 42799623458](https://github.com/asmie/stamp-suite/actions/runs/42799623458),
on `ef3f78d3aeaa0711741884aee41d05ac9bdadaa8`, passed 21 of 23 jobs. Windows,
Linux stable and beta, all Clippy jobs and macOS compilation passed. Only the
two native macOS runtime jobs failed: eight tests in the default profile and
ten with all features, in the keyset-fallback, launcher,
authentication-admission and session-identity suites. All of them use the
in-process receiver fixture. The timeouts could leave the received counters at
zero. Two admission tests passed in the default profile but failed with all
features.

The fixture kept the bound port, but returned as soon as it had spawned the
receiver thread. A caller could therefore send before that thread enabled
`IP_RECVTTL`/`IPV6_RECVHOPLIMIT`. Apple's
[UDP input path](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/udp_usrreq.c)
builds the ancillary control data before it appends a datagram to the socket
queue, and
[IPv4 control creation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/ip_input.c)
adds the TTL only when its receive option is enabled. A packet that was queued
early can therefore lack the metadata even after setup has finished. The nix
receiver requires a real TTL, so it discards such a packet before the session
counters advance. This explains the macOS symptoms. Running the correction
natively had to wait for the manual commit and the next CI run.

The fixture now waits, over a bounded channel, until its receiver acknowledges
its first poll, and only then returns. The nix backend finishes socket setup
before it first suspends. The acknowledgement is also sent on a startup error,
so the existing `stop`/`assert_running` checks still see the real failure. The
parent waits at most five seconds for startup and keeps its normal shutdown
owner while it waits. No warmup request, retry or fixed startup sleep was
added, so the authentication and admission tests still start with untouched
session state.

The new IPv4/IPv6 regression test reads the TTL/Hop Limit receive option on the
real socket before sending anything. It requires zero received and reflected
packets and zero sessions, closes the temporary descriptor it used to read the
option, and checks for a clean shutdown. A temporary `setsockopt` interposer
delays enabling the metadata by 100 ms, then calls the real syscall with the
same arguments and returns its result unchanged. The regression fails against
the original fixture (`TTL capture must be enabled before return`, value zero)
and passes with the acknowledgement under the same delay. This reproduces the
ordering bug on Linux. It does not claim to reproduce the Darwin kernel's
behavior. The logs are `/tmp/ci-macos-*`.

Under the setup delay, all four affected suites passed in the default and
all-features profiles: **38/38** tests with eight workers. The new startup
regression also passed 20 delayed rounds in a row per profile, **40/40** tests,
with both families in every round. No failures were retried and no tests were
ignored. The isolated macOS-target harness compiled the exact modified fixture
and launcher source against the real default library. Full native execution
still had to happen in CI.

The final Linux default, all-features and pnet suites passed
**1,365/1,467/1,295** tests respectively, with 13 privileged tests ignored in
each ordinary run. Both nix profiles also passed the existing startup-error
propagation check. All three Clippy profiles, rustfmt, 104 Python tests, the
release metadata, matrix counts, 1,201 source citations and the documentation
checks passed. The link checker checked 378 local links and classified 71
external links (449 total). Strict checking failed only on the same 56 missing
test references. No remote CI pass is claimed for this correction.

```sh
cargo test --locked --all-features --test reflector_launcher_test --test keyset_fallback_test --test session_auth_admission_test --test session_identity_test
```

The change touches only the shared test startup code, one regression test and
documentation. Application code, TTL requirements, dependency graphs and CI
gates did not change. The remaining conformance references and strict
enforcement are separate from this repair.

## Windows startup test port reuse follow-up (10 November 2026)

[CI run 42803965201](https://github.com/asmie/stamp-suite/actions/runs/42803965201)
on `ea4f0370b44407ec412577cd571efae18765935f` passed **22 of 23 jobs**,
including both native macOS runtime profiles. That gives the metadata startup
repair above its native execution evidence. Only Windows runtime core failed,
in `sender_total_loss_is_not_a_startup_failure`: both of its calls to
`free_port` returned port 58867. The sender correctly rejected the equal
explicit local and remote ports before it measured any loss. This failure is
unrelated to the earlier macOS receive timeouts.
[Conformance evidence](https://github.com/asmie/stamp-suite/actions/runs/42803964952)
and [CodeQL](https://github.com/asmie/stamp-suite/actions/runs/42803964806)
also passed on this commit.

The helper bound port zero, read the assigned port and dropped the socket. That
does not reserve the port, and it does not guarantee that the next allocation
returns a different one. The total-loss fixture now keeps a silent peer bound
for the whole run and asks for local port zero, so the sender's existing
allocator picks a different dynamic source port. For both IPv4 and IPv6 the
test requires one sent packet, zero replies, the probe actually arriving at the
silent peer, and a different source port. The peer never replies, on purpose.

The other startup checks in the same file have also stopped picking ports by
binding and releasing them. Local sockets use port zero unless the test is
about failing on an occupied port. Network peers stay bound. Key-loading
failures need no temporary ports. Tests about occupied ports still hold their
conflicting sockets. Sender validation, allocation policy and application
behavior did not change.

A temporary Linux `bind` interposer hands the first assigned IPv4 loopback port
to later port-zero requests when that port is free. If it is taken, the
interposer falls back to the kernel's normal allocation. With the original
fixture, this forced reuse produces the exact CI error,
`sender local and remote ports must differ`. With the bound peer and the
automatic local port, the test passes for both families under the same
allocator behavior. This models the allocation that CI observed. It is not a
claim about the Windows runtime. The logs are `/tmp/ci-port-*` and
`/tmp/ci-windows-port-*`.

Under that forced reuse, all 12 startup tests passed 20 rounds in a row in each
of three Linux profiles: default, all-features, and the Windows CI feature set
(`--no-default-features --features ttl-pnet,metrics,control`). That is
**720/720** tests with eight workers, no ignored tests and no failed rounds
retried. Each total-loss case covers both families. An isolated Windows-target
harness compiled the exact modified test against the real default Windows
library. It leaves out unrelated dev and optional C dependencies, so a full
native Windows CI run is still required.

The full default, all-features and pnet Linux suites passed
**1,365/1,467/1,295** tests respectively, with 13 privileged tests ignored in
each ordinary run. All three Clippy profiles, rustfmt, 104 Python tests, the
release metadata, matrix counts, 1,201 source citations and the documentation
checks passed. The link checker checked 379 local links and classified 74
external links (453 total). Strict evidence checking failed only on the
existing 56 missing test references. No remote CI pass is claimed for the
Windows correction, which was not committed at the time.

Only test fixtures, their assertions and documentation changed. CI gates,
production code and the conformance inventory did not. Native Windows
verification of this correction follows the manual commit and push.

## Validation and reproduction

Original T6 snapshot: the local suites passed 1,315 default, 1,416
all-features and 1,264 pnet tests, with 12/12/13 privileged tests ignored. All
three Clippy profiles passed with warnings denied. Rust 1.87 checked all
features and all targets. Rustdoc, rustfmt, 81 Python tests, the matrix counts
and 1,019 citations passed. The final control-port change also passed all eight
session-capacity tests and the seven launcher tests with all features. Remote
CI had not run this chunk, and the native macOS runtime was not tested locally.

Seven launcher tests cover the deterministic race, valid assigned endpoints,
keeping and then releasing socket ownership, rejection of a mismatched or
connected socket, missing executables, diagnostics for an early exit, and
cleanup after a timeout or a flood of output. The controlled child fixture
reuses the test executable, so it needs no shell or Python child and creates no
grandchildren. The tests check that `waitpid` reports the failed or timed-out
child as already reaped. The flood test writes more than three diagnostic
windows' worth of output with no newline before its tail. That checks that
memory use stays capped and the pipe keeps draining.

```sh
cargo test --locked --test reflector_launcher_test -- --nocapture
cargo test --locked --all-features
cargo test --locked
cargo test --locked --no-default-features --features ttl-pnet
```

For repeated replay runs, stick to one build profile and run each command in
turn. Do not replace the executable with another build while it is running:

```sh
for iteration in $(seq 1 20); do
  cargo test --locked --test replay_control_test -- --test-threads=8 || exit 1
done
```

The first failed round stops the loop. This is stress validation, not retrying
failed tests until they pass. The Linux gates already include all the affected
targets, and the Unix nix targets also run in the existing native macOS jobs,
so no new CI job or concurrency suppression is needed. Local Linux runtime
evidence does not replace a native macOS run or the ignored privileged tests.
