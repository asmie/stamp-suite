# Reflector startup fixtures

How the live test suites start reflectors, and the startup failures that
shaped those fixtures.

## Why fixtures bind port zero

Older fixtures picked a port by binding a temporary UDP socket, closing it, and
then starting the reflector on the same port. Nothing held the port in between,
so another socket could take it first. Most of those fixtures also threw stderr
away, so the failure showed up only as an exit or readiness assertion.

A diagnosis on 9 November 2026 confirmed the race. Binding a competing socket
into the gap made the reflector exit with `Cannot bind to address`
(OS error 98) every time, over IPv4 and IPv6. In 64 runs without the forced
competitor the race never fired on its own, so it may not explain every past
failure. The fixtures now report enough to catch any other cause.

The control test in [`reflector_launcher_test.rs`](../tests/reflector_launcher_test.rs)
holds a competing endpoint for the whole test. It checks that a child started
on that fixed port gets a bind error and is reaped. Then it starts a reflector
on port zero while the competitor is still bound, and checks that a request
gets a reply.

## Shared lifecycle

[`tests/common/reflector.rs`](../tests/common/reflector.rs) starts reflector
child processes for the replay, burst-transmission, idle-CPU, BER-measurement,
session-capacity and reply-queue tests, among others. Each child binds port
zero. The helper reads the bound address from the JSON startup message the
reflector prints, and sends no readiness packets. The session-capacity
fixture's control API binds TCP port zero the same way, and the fixture waits
for its startup message before sending HTTP requests.

Stderr goes to a reader thread that drains it continuously. The diagnostic
tail and the pending readiness line are each capped at 64 KiB; a longer line is
dropped for readiness parsing and reading continues. If the child exits or
times out during startup, the helper returns the reason, the PID, the exit
status and the tail of stderr. On failure and at teardown it kills the child,
waits for it and joins the reader thread. It never restarts a failed child.
Child fixtures run with two Tokio workers regardless of the CPU count, which
leaves room for the test harness's own parallelism.

[`tests/common/receiver.rs`](../tests/common/receiver.rs) runs an in-process
receiver for the session-identity, keyset-fallback and session-auth-admission
tests, which need exact provisioned endpoints or direct access to counters and
keys. The fixture keeps its bound socket open while it builds the
configuration, then hands it to `receiver::run_receiver_with_socket` on the
nix backend. That function checks that the socket is unconnected and matches
the configured endpoint, then runs the same setup and packet processing as the
CLI; nothing is closed and bound again. Each receiver runs on its own
current-thread runtime. `stop()` cancels the receiver, gives it up to two
seconds to drain, joins its thread and returns its result or panic, so a
startup failure reaches the test instead of a bare "task finished" assertion.

Admission fixtures send each invalid input once and wait for both the receive
and the drop counters, so the test never sees a packet arrive before it was
processed. Fixtures that need a warm-up send one packet after they have the
endpoint. There is no send-and-restart loop that could hide a failure.

## Past startup failures

### Teardown ownership follow-up (10 November 2026)

An all-features run failed in
`retained_socket_excludes_other_binders_and_is_released_on_teardown`. After
the receiver stopped, the test tried to bind the port that had just been
released, and got AddrInUse. The assertion mixed up two things: the receiver
still holding its socket, and some other process owning the endpoint. The
other owner was never identified.

`teardown_observer_distinguishes_retained_socket_from_another_endpoint_owner`
now checks the two cases separately, over IPv4 and IPv6, on Linux. It records
the inode of the receiver's socket and, after shutdown, checks every descriptor
of the test process for it (see
[proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)).
That tells the original socket apart from another socket on the same endpoint.
It says nothing about whether the port is free system-wide. A related control,
`released_reservation_can_be_taken_but_port_zero_startup_is_unaffected`, had
the same reserve-drop-rebind problem and now keeps its competing socket bound
throughout. `explicit_receiver_stop_reports_startup_failure` checks that a
receiver's startup error reaches the caller.

The suite then had nine launcher tests on Linux and eight on other Unix systems; the
kernel identity checks need Linux procfs. The fix passed 20 consecutive
all-features rounds with eight test threads, with no retries.

### CI follow-up (10 November 2026)

[CI run 42791508079](https://github.com/asmie/stamp-suite/actions/runs/42791508079)
on `64465ea` failed five jobs because of three test defects:

| Failed jobs | Cause | Fix |
| --- | --- | --- |
| Native macOS, default and all-features | Launcher tests used `libc`, but the direct dev dependency on it is Linux-only. | Import the `nix::libc` re-export on Unix. |
| Windows runtime core | The ECN fallback test expected the source address to be pinned on Windows, where the kernel chooses it. | Require the requested source on Linux and `None` elsewhere. |
| Ubuntu beta and default-feature tests | The peer could receive a reply before the reflector finished its post-send session bookkeeping, so the authentication test took its baseline too early. | Wait for the reflected-packet counter, which advances after the session update, and disable the unrelated asynchronous TX timestamp correction in that fixture. |

The race in the third row was reproduced on Linux with an `LD_PRELOAD` shim
that delays each successful `sendmsg` by 50 ms: the old test failed with the CI
assertion, and the fixed one passed 20 rounds in both nix profiles.

### macOS metadata startup follow-up (10 November 2026)

[CI run 42799623458](https://github.com/asmie/stamp-suite/actions/runs/42799623458)
on `ef3f78d` failed only the two native macOS runtime jobs, in suites that use
the in-process receiver fixture. The fixture returned as soon as it spawned the
receiver thread, so a test could send before the receiver enabled
`IP_RECVTTL`/`IPV6_RECVHOPLIMIT`. Darwin builds a datagram's control data when
it is queued
([UDP input](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/udp_usrreq.c),
[IPv4 control data](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/ip_input.c)),
so an early packet has no TTL, and the nix receiver drops packets without one.

The fixture now waits, for up to five seconds, until the receiver acknowledges
its first poll; the nix backend finishes socket setup before that. A startup
error sends the acknowledgement too, so `stop` still reports it. A regression
test reads the TTL/Hop Limit receive option on the real socket before sending
anything. With a shim that delays enabling the option by 100 ms, it fails
against the old fixture and passes with the fix.
[CI run 42803965201](https://github.com/asmie/stamp-suite/actions/runs/42803965201)
then passed both native macOS runtime profiles.

### Windows startup test port reuse follow-up (10 November 2026)

That same run failed only Windows runtime core, in
`sender_total_loss_is_not_a_startup_failure`. The test's `free_port` helper
bound port zero, read the port and dropped the socket; both of its calls
returned 58867, and the sender correctly rejected equal local and remote ports.
Dropping a socket reserves nothing, and the next allocation may return the same
port.

The test now keeps a silent peer bound for the whole run and lets the sender
choose its own source port. For both families it requires one sent probe, zero
replies, the probe arriving at the peer, and a different source port. The other
startup tests stopped picking ports by binding and releasing them too: local
sockets use port zero unless the test is about an occupied port, and peers stay
bound. A Linux `bind` shim that forces later port-zero requests onto the first
assigned port reproduced the CI error with the old test; the fixed tests passed
20 rounds under it in the default, all-features and Windows CI feature sets.

## Validation and reproduction

The launcher tests cover the forced bind race, assigned endpoints, keeping and
releasing socket ownership, rejection of a mismatched or connected socket,
missing executables, early-exit diagnostics, and cleanup after a timeout or a
flood of output. The controlled child reuses the test executable, so it needs
no shell or Python child. The flood test writes more than three diagnostic
windows of output without a newline, checking that memory stays capped and
the pipe keeps draining.

```sh
cargo test --locked --test reflector_launcher_test -- --nocapture
cargo test --locked --all-features --test reflector_launcher_test --test session_identity_test --test keyset_fallback_test --test session_auth_admission_test
cargo test --locked
cargo test --locked --all-features
cargo test --locked --no-default-features --features ttl-pnet
```

For a stress run, use one build profile and do not rebuild while it runs. The
loop stops at the first failure; it does not retry failed tests:

```sh
for iteration in $(seq 1 20); do
  cargo test --locked --test replay_control_test -- --test-threads=8 || exit 1
done
```
