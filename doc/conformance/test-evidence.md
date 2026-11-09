# Conformance test references

Source validity, test-reference presence and verified behavior are different
checks. This policy adds the second without treating it as the third.

## Policy

For a Compliant row whose Level includes MUST, MUST NOT, SHALL, SHALL NOT or
REQUIRED, including structural/implied requirements, the Evidence column must
identify a test of the claimed behavior. A parenthetical profile qualifier does
not waive this requirement. Other statuses and SHOULD/MAY/descriptive rows are
outside this inventory; their source references still need to be valid.

The checker recognizes:

- A real Rust test function with a built-in or namespaced test attribute, such
  as an ordinary test, Tokio test or annotated property test. Prefer a qualified
  reference such as `src/receiver/transmit/tests.rs::single_header_reply_checks_mtu_trims_and_resigns`.
  An unqualified name is accepted only if it identifies one test without a
  conflicting helper name.
- A dedicated test file containing annotated tests, such as
  `tests/session_identity_test.rs`, or an explicitly declared test module such
  as `src/tlv/list/mod.rs::tests`. File/child-module lookup follows the existing
  citation checker's source convention, not compiler name resolution. A broad
  suite reference needs manual review of the relevant assertions; named cases
  are preferable.
- A Python unittest method or suite that contains actual TestCase methods,
  such as `scripts/tests/test_interop_ber.py::BerOracleChecks::test_hmac_rfc4231_and_bit_reference`.
  Tests of an oracle alone do not establish application conformance.
- An explicitly identified wire-driver function. For example, Wire tests:
  `scripts/interop_ber.py::reflector_case`, `scripts/interop_ber.py::sender_case`.
  Each function must exist. Review must establish that the driver invokes the
  application and validates the relevant bytes/behavior. Identify the scenario
  or vector in the surrounding evidence.

Comments, string literals, helper names containing "test", ordinary production
files and fixture data alone do not qualify. For example,
`src/receiver/transmit.rs::fit_reply` identifies implementation, not a test of
its caller. Explicitly qualified Python references are also checked for stale
files/functions, including outside normative Compliant rows.

The scanner supports the repository's built-in/Tokio/property-test and unittest
conventions; it is not a general Rust macro expander or Python test runner.
Unrecognized or ambiguous references need a clearer citation or reviewer work,
not a claim that the behavior is necessarily untested.

## Semantic and execution review

Before approving a row, trace the trigger through the claimed production path
to the assertion. Check role, authentication mode, IP family, backend and
failure/fallback conditions. A codec test can establish field encoding without
establishing dispatch. A mocked transport can establish finalization logic but
does not prove OS routing or physical behavior. Shared implementation is not
runtime evidence for every backend.

Test presence is not a pass. Ignored tests, platform/feature-gated declarations
and source-only wire drivers require execution evidence for the claimed profile.
The JSON report sets `execution_checked` to false and identifies directly ignored
Rust tests/suite counts. Counts describe source declarations, not runnable cases
in a particular build. It does not infer execution from Cargo builds, prior runs
or the existence of fixtures. A few representative assertions also do not
certify every statement in a broad requirement.

When evidence is insufficient, add a regression through the correct entry
point, narrow the profile with an explanation, or lower the status. Do not
rename a helper, add a generic suite or change the normative Level simply to
clear the inventory. Links to shared notes do not replace a direct test
reference on the row.

## Inventory and rollout

```sh
python3 scripts/check_conformance_citations.py --json --details > citations.json
python3 scripts/check_conformance_citations.py --require-test-evidence --json > strict-citations.json
```

The first command keeps stale citation failures and adds `test_evidence` with
the policy version, applicable clause counts, missing rows and, with `--details`,
all clause/reference records. Counts distinguish rows with a test reference
from rows missing one; they are not coverage percentages. Existing citation
counts describe Rust source references; qualified Python test references are
recorded under the test inventory, and invalid ones also fail source checking.

Missing test references are advisory by default. `--require-test-evidence`
returns nonzero and adds `missing-test-evidence` problems while any remain.
The existing CI citation step retains this inventory in its `citations.json`
artifact. Whole-backlog enforcement will be enabled only after review and
resolution; an advisory success is not a claim that all rows are tested.

The initial source inventory on 9 November 2026 (parent `d6a4f8a`) found
325 applicable rows: 159 with explicit test references and 166 missing them.
This first review resolves 40 missing references and lowers three existing
Both-role MTU claims to Partial. The resulting inventory is **322 applicable,
196 with references, 126 missing**. The rollup is **471 clauses: 390 Compliant,
28 Partial, two Gap, 48 N-A and three Excluded**. These are review snapshots;
rerun the checker after edits rather than treating the numbers as certification.

## First reviewed batch

| Area | Evidence and what it establishes | Limits / remaining work |
|---|---|---|
| 39 normative Compliant BER rows | Explicit role-specific wire drivers now appear on every applicable BER row. Seventeen reflector vectors and sender baseline/gating/U scenarios check counters, flags, repaired padding, unknown/malformed children, configuration and directional statistics. | Linux nix software-loopback profile using agreed experimental types; no zero-checksum, physical-link or maintained-peer certification. Existing Partial/Gap rows remain. |
| RFC 8972 HMAC rows 4.8-1, 6, 7, 8, 11, 13, 14 | A new production Rust signer/verifier known-answer test uses RFC 4231 case 1, truncated to 128 bits. Independent wire roles check actual HMAC type/length/coverage; a malformed-length parser test checks M. Failed extension-HMAC echoes preserve all copied values and the failed digest with I. | Primitive/equivalence tests supplement the wire driver; they do not replace send-path checks. The copied failure digest is not regenerated into a successful one. |
| RFC 8972 admission rows 3-6 to 3-8 | Named IPv4 open/authenticated and IPv6 identity tests run the nix receiver with exact provisioned endpoints, SSIDs and micro IDs. Authentication tests verify invalid bases cannot allocate or refresh state. | Provisioned profile only. Shared-core tests are distinct from pnet capture runtime or physical ingress validation. |
| Reflected-header MTU rows 7.2-1, 3, 5 | The single-reply tests invoke actual transmission finalization, checking trimming, final signatures, unavailable budgets and EMSGSIZE refresh. The required namespace test exercises real route budgets. | These test reflection. Sender trimming is implemented but currently has helper-level evidence here; all three Both-role claims are now Partial pending sender production-path tests. |
| Type 12 C signaling | The existing flag-semantics suite exercises packet processing with requests within and above administrative caps. | This is distinct from the unreviewed exact-timing claim and from physical transmission scheduling guarantees. |

The remaining 126 missing references span six matrices. The next batch must
prioritize sender MTU dispatch and the remaining authentication, C-flag and
admission claims, then work through the rest. The full test-evidence goal and
strict CI gate remain unfinished.

## Local validation for this batch

The all-features focused runs exercise 90 HMAC tests (including the new known
answer), 12 tests selected by the single-reply filter, one tracked-admission
unit test and the identity/authentication/flag-semantics integration suites.
The identity/authentication/flag suites passed 62 tests. The independent
all-features BER profile passed all 60 cases. The required route-MTU namespace
test passed its eight family/auth/binding combinations, with no prerequisite
skip. The new known answer also passed in default and pnet builds; the shared
admission-core regression passed in pnet without requiring a capture driver.
All 104 Python tests, all-features Clippy, rustfmt, matrix counts and source/link
checks pass. Results apply only to these local profiles; they do not establish
remote CI or unexecuted native platform behavior. Temporary logs and reports
use `/tmp/t22-*`; durable source tests and CI reproduction remain in the repository.

Run builds and wire suites sequentially so Cargo cannot replace a live binary:

```sh
cargo test --locked --all-features --lib hmac
cargo test --locked --all-features --lib single_
cargo test --locked --all-features --test session_identity_test --test session_auth_admission_test --test tlv_flag_semantics
cargo build --locked --all-features
python3 scripts/interop_ber.py --binary target/debug/stamp-suite --report /tmp/t22-ber-wire.json
cargo test --locked --all-features --test route_mtu_test --no-run --message-format=json > /tmp/t22-mtu-artifacts.json
python3 scripts/run_privileged_test.py /tmp/t22-mtu-artifacts.json route_mtu_test 1 unshare -Urn env STAMP_MTU_NETNS_TESTS=1 TOKIO_WORKER_THREADS=2
```
