# Runtime Control Plane — Design

Status: **implemented** (cargo feature `control`, module `src/control/`).
This document is the authoritative API contract.

## 1. Goals and non-goals

**Goals**

- Manage the reflector at runtime without restarts: per-SSID HMAC keys,
  rate/amplification caps, session table, drain and shutdown.
- Live operational visibility richer than Prometheus gauges (full session
  table, effective caps, key inventory — names only).
- Close the operational gap with teaparty's meta API while staying honest
  to stamp-suite's model (keys are SSID-scoped, sessions are lazily
  created per client `IP:port`).
- Zero new runtime dependencies; localhost-safe by default.

**Non-goals (v1)**

- Sender-mode control (the control plane is reflector-only).
- TLS / mTLS termination — remote access goes through an SSH tunnel or a
  reverse proxy; the API itself stays plain HTTP on loopback.
- Session *pre-provisioning* (teaparty's 4-tuple create-with-key). In
  stamp-suite, "provision a key for a measurement" is `PUT /v1/keys/{ssid}`;
  the session table entry appears when the client's first packet does.
- Config-file persistence of runtime changes. Changes live until process
  exit; persistent settings belong in the TOML config.
- Runtime change of `--session-timeout` (its cleanup tick interval is
  baked into both backends at startup).

## 2. Architecture

```
                 ┌──────────────────────────────────────────────┐
                 │ main.rs (reflector startup)                  │
                 │  create_shared_state() ──► ReceiverSharedState│
                 │       │                ┌─────────┴─────────┐ │
                 │       ├── snmp::init   │ counters  (Arc)   │ │
                 │       ├── metrics::init│ session_manager   │ │
                 │       └── control::init│ rate_limiter      │ │
                 │             │          │ hmac_keys RwLock  │ │
                 │             ▼          │ caps (atomics)    │ │
                 │   axum Router (tokio   │ shutdown_requested│ │
                 │   task, CancellationToken) └───────┬───────┘ │
                 │                                    │         │
                 │   run_receiver(conf, &shared) ◄────┘         │
                 │     nix.rs / pnet.rs packet loops            │
                 └──────────────────────────────────────────────┘
```

- A new `src/control/` module (cargo feature `control`, reusing the
  already-optional `axum` + `tokio-util` from the `metrics` feature)
  copies the metrics server's lifecycle pattern: bind → fail-fast,
  `tokio::spawn(axum::serve)`, `CancellationToken` shutdown, non-loopback
  bind warning.
- State threading copies the SNMP pattern: `main.rs` clones `Arc`s out of
  `ReceiverSharedState` into a `ControlState` handed to the router. The
  control plane never reaches into a backend directly; everything it
  touches is shared state both backends already consult.
- Three pieces of state move/are added to `ReceiverSharedState` to become
  runtime-mutable (see §4): the HMAC keyset, a `RuntimeCaps` atomics
  struct, and a `shutdown_requested` flag.

## 3. API specification

All endpoints live under the **`/v1`** prefix. Requests and responses are
`application/json`. Errors return `{"error": "<message>"}` with the
status code. Request bodies are validated strictly
(`serde(deny_unknown_fields)`) so an operator's typo in a cap name is a
`400`, not a silent no-op.

| Method | Path | Body | Success | Purpose |
|---|---|---|---|---|
| GET | `/v1/status` | — | 200 | Version, uptime, counters, draining flag |
| GET | `/v1/sessions` | — | 200 | Session table as JSON array |
| POST | `/v1/sessions/expire` | `{"client":"ip:port"}` | 200 / 404 | Remove one session |
| GET | `/v1/keys` | — | 200 | Key inventory — SSIDs and default-presence only |
| PUT | `/v1/keys/{ssid}` | `{"key_hex":"…"}` | 204 / 400 | Add or replace a per-SSID key |
| DELETE | `/v1/keys/{ssid}` | — | 204 / 404 | Remove a per-SSID key |
| PUT | `/v1/keys/default` | `{"key_hex":"…"}` | 204 / 400 | Set the fallback key |
| DELETE | `/v1/keys/default` | — | 204 / 404 | Remove the fallback key |
| GET | `/v1/caps` | — | 200 | Effective runtime caps |
| PATCH | `/v1/caps` | partial caps object | 200 | Adjust caps; returns effective state |
| POST | `/v1/drain` | `{"draining":bool}` | 200 | Stop/resume accepting **new** sessions |
| POST | `/v1/shutdown` | — | 202 | Request graceful process shutdown |

`POST` for `sessions/expire` (instead of `DELETE /v1/sessions/{client}`)
is deliberate: IPv6 literals like `[::1]:5000` are hostile to path
segments; a JSON body parses as a plain `SocketAddr`.

### Response shapes

`GET /v1/status`:

```json
{
  "version": "0.9.0",
  "uptime_seconds": 12345,
  "draining": false,
  "sessions": 17,
  "counters": {
    "packets_received": 123456,
    "packets_reflected": 123450,
    "packets_dropped": 4,
    "packets_rate_limited": 2
  }
}
```

`GET /v1/sessions` (note `idle_seconds`, not a raw `Instant`):

```json
[
  {
    "client": "192.0.2.10:4862",
    "session_id": 3,
    "packets_received": 1200,
    "packets_transmitted": 1200,
    "last_reflected_seq": 1199,
    "idle_seconds": 0.42
  }
]
```

`GET /v1/caps` / `PATCH /v1/caps` (PATCH body: any subset of the same
fields; `0` consistently means "unlimited/disabled", mirroring the CLI):

```json
{
  "max_pps": 0,
  "rate_burst": 0,
  "max_sessions": 65536,
  "reflected_control_max_count": 0,
  "reflected_control_max_size": 1500,
  "reflected_control_min_interval_ns": 1000
}
```

### Semantics worth pinning

- **Keys are write-only.** No endpoint ever returns key material; logs
  never contain it; request strings are zeroized after parsing. `key_hex`
  goes through the same `HmacKey::from_hex` validation as the CLI.
- **Drain** flips `SessionManager.draining`: unknown clients still get
  *replies* (transient, unstored sessions — same mechanism as the
  max-sessions cap), but no new state is created; existing sessions are
  unaffected. Reply behaviour is intentionally preserved so draining a
  reflector doesn't fail in-flight measurements; it only stops new ones
  from accreting state.
- **Shutdown** sets `shutdown_requested`; the nix backend polls it on a
  250 ms tick, pnet per capture iteration. The HTTP response (202) lands
  before the process exits.
- **Caps PATCH** is per-field atomic but not transactional across fields;
  each `Some` field is stored independently (Relaxed atomics — these are
  tuning knobs, not synchronization points).

## 4. Concurrency and state model

| State | Type | Readers | Writer | Notes |
|---|---|---|---|---|
| HMAC keyset | `Arc<RwLock<Option<HmacKeySet>>>` | packet loops (read guard per packet) | control plane | The guard is scoped to never cross an `.await` in the nix backend (std guard is not `Send`); acquire → build `ProcessingContext` → process (sync) → drop guard → async send. `ProcessingContext.hmac_key_set: Option<&HmacKeySet>` keeps its borrow type — zero churn in the hot path. |
| Runtime caps | `RuntimeCaps` (AtomicU16/U32/Usize) | packet loops, per packet | control plane | pnet receives the `Arc` via `CaptureConfig` (moves into `spawn_blocking`). |
| Rate limiter | always-constructed `RateLimiter` with atomic rate/burst | packet loops | control plane | `rate == 0` short-circuits to allow; enables turning limiting *on* at runtime even when started unlimited. |
| Draining / max-sessions | atomics inside `SessionManager` | packet loops | control plane | |
| Session table | existing `RwLock<HashMap<SocketAddr, …>>` | both | both | `expire_session` takes the write lock; `GET /v1/sessions` uses the existing `session_summaries_extended()`. |
| Shutdown flag | `Arc<AtomicBool>` | backends (poll) | control plane | |
| Legacy single `--hmac-key` | unchanged, startup-immutable | packet loops | — | Deliberate boundary: the control plane manages the *keyset* (per-SSID + default); the CLI single key stays fixed. |

Lock-poisoning follows the codebase convention:
`unwrap_or_else(|e| e.into_inner())`.

## 5. Security model

- **Bind:** `127.0.0.1:9091` by default (`--control-addr` to change); a
  non-loopback bind logs the same loud warning the metrics server uses.
- **Authentication:** optional static bearer token from
  `--control-token-file` (mode-checked like key files). Comparison is
  constant-time (`subtle`, same as HMAC verification). With no token and
  a loopback bind, local-user access equals control — same trust model as
  the AgentX socket.
- **Why a token matters even on loopback:** `PUT /v1/keys` grants
  measurement access and `POST /v1/shutdown` is a kill switch; multi-user
  hosts should set the token.
- **No TLS in v1:** remote management = SSH tunnel / reverse proxy. The
  API never carries key material *out*, only *in*.
- **Abuse surface:** all mutating endpoints are constant-time-cheap and
  rate-limited implicitly by being a localhost HTTP server; no endpoint
  allocates unbounded memory (session list is bounded by `max_sessions`,
  key inventory by u16 SSID space).

## 6. Failure modes

- **Bind failure → process exit** (matches metrics: if the operator asked
  for the control plane, silently running without it would hide an
  outage).
- **Keyset lock contention:** writes are rare (operator actions); packet
  loops hold read guards for microseconds. No fairness concern at STAMP
  packet rates.
- **Shutdown while draining:** independent flags; shutdown wins.
- **Feature off / flag on:** `--control` without the `control` build
  feature is a startup error (exit 1), mirroring `--snmp`/`--metrics`
  behaviour.

## 7. Observability of the control plane itself

Every mutating call logs one structured line at `info` (`control: key
added ssid=42`, `control: caps updated max_pps=500`, `control: drain
enabled`, `control: shutdown requested`) — never key material. These
lines are the audit trail; v1 has no separate audit log.

## 8. Future extensions (explicitly out of v1)

- `GET /v1/status` gaining a `timestamping` object (the `hwtstamp`
  feature's `EnabledTimestamping` is currently backend-local; exposing it
  requires threading it into `ReceiverSharedState`).
- Drain-then-shutdown convenience (`POST /v1/shutdown {"drain_seconds": N}`).
- Session pre-provisioning, if a concrete teaparty-interop need appears.
- OpenAPI document generation; Prometheus counters for control actions.
- Windows/`SIO_TIMESTAMPING`, TLS, SNMP SET parity — tracked elsewhere.

## 9. Known collision

The Task-5 keyset refactor touches the CoS-reject HMAC recompute path,
which today silently skips recomputation under `--hmac-key-dir`
(`src/receiver/nix.rs` uses only the legacy single key there). The
implementation plan flags it: fix in passing only if the diff stays
small, otherwise file as a follow-up bug.
