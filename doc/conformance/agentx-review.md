# AgentX targeted review — finding 14

Reviewed 9 September 2026 against [RFC 2741](https://www.rfc-editor.org/rfc/rfc2741.html).
This is a targeted repair record, not a complete AgentX/SNMP conformance matrix;
it does not add rows to the STAMP clause totals.

| Reference | Behavior checked | Implementation and evidence |
|---|---|---|
| §7.2.3.3 | Iteration-first GETBULK results; exhausted ranges retain their positions until an all-exhausted iteration. | `src/snmp/agentx.rs::handle_get_bulk`; independent fixtures assert ordered OIDs and exception types, including an initially exhausted range. |
| §§5.2, 7.2.3.2–7.2.3.3 | Inclusive initial starts and exclusive ends. | `SearchRange::next` preserves the decoded start flag; the bulk cursor clears it after its first result. Fixtures cover GETNEXT, non-repeaters, repeating ranges, zero repetitions and an inclusive start equal to the exclusive end. |
| §7.2.3 | Indexed errors on request-processing failures. | More than 256 ranges receives genErr/index 257 and no varbinds. The following request on the same connection succeeds; omitted ranges cannot silently change bulk column positions. |
| §§6.1, 6.2.2, 7.1.8 | Complete PDU framing and correlated Close acknowledgment. | `PduReader::poll` retains offsets/buffers, bounds payloads before allocation and treats EOF as connection loss. `AgentXSession::run_loop` writes the response before returning from master Close. |

`tests/agentx_protocol_test.rs` implements an independent master over a real Unix
socket and calls the same public session/event loop used in production. Its wire
encoder and response decoder do not call production codec helpers. Header and payload
fragments each cross a 1.25-second gap, exercising the one-second read timeout; a
following request verifies synchronization. Coalesced PDUs and cancellation during
an incomplete frame have separate checks. Unit tests cover every split offset with
WouldBlock, TimedOut and Interrupted, plus truncated frames and oversized headers.

The fixtures reproduced five failures before the fix; the sixth original case
(zero repetitions/non-repeaters) already passed. Later tests add stream and limit
coverage. Final commands/results are in the [repair tracker](../reviews/2026-09-08/progress.md).

Limits: 1 MiB incoming payloads, 256 search ranges and 100 bulk iterations. Read-only
SET handling is unchanged. Network-byte-order/default-context operation is the
supported subset; byte order is a per-PDU flag, not negotiated by Open. This repair
does not add little-endian payload or named-context support. Net-SNMP tools were
not installed for that original repair; its results are historical.

O11 (11 September 2026) adds and passes a separate real Net-SNMP master/client
fixture on Linux. `scripts/release_checks.py::snmp_case` starts an isolated
master and the actual stamp-suite subagent, then verifies authenticated live
packet counters, two session rows, GET/GETNEXT/walk/GETBULK ordering and the
end-of-MIB boundary. STAMP continues reflecting while the master is restarted;
the subagent reconnects with counters and session state preserved. The tools
are Ubuntu package `5.9.4+dfsg-2ubuntu3`; the daemon reports `5.9.4.pre2`.
See [release evidence](../release-evidence.md) for commands, captured queries and
limits. This is reference-master interoperability evidence for the exercised
subset; no macOS execution or full SNMP certification is claimed.
