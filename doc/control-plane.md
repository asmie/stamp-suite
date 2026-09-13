# Runtime control API

The `control` build feature provides a reflector-only HTTP API for keys,
sessions, rate and burst limits, drain, and shutdown.

```sh
stamp-suite --is-reflector --control --control-token-file /etc/stamp/control.token
```

The default listener is `127.0.0.1:9091`. Send the token as
`Authorization: Bearer <token>`. Runtime changes last until process exit;
put persistent settings in TOML. Session provisioning, idle timeout, and queue
settings cannot be changed through the API. Installing a key does not provision
an endpoint; see [session provisioning](usage.md#session-provisioning).

## Endpoints

All endpoints live under the **`/v1`** prefix. Requests and responses are
`application/json`. Errors return `{"error": "<message>"}` with the
status code. Request bodies are validated strictly
(`serde(deny_unknown_fields)`) so an operator's typo in a cap name is a
`400`, not a silent no-op.

| Method | Path | Body | Success | Purpose |
|---|---|---|---|---|
| GET | `/v1/status` | — | 200 | Version, uptime, counters, draining flag |
| GET | `/v1/sessions` | — | 200 | Session table as JSON array |
| POST | `/v1/sessions/expire` | `{"client":"ip:port","session_id":3}` | 200 / 404 / 409 | Remove one runtime session; ID optional if unambiguous |
| GET | `/v1/keys` | — | 200 | Key inventory — SSIDs and default-presence only |
| PUT | `/v1/keys/{ssid}` | `{"key_hex":"…"}` | 204 / 400 | Add or replace a per-SSID key |
| DELETE | `/v1/keys/{ssid}` | — | 204 / 404 | Remove a per-SSID key |
| PUT | `/v1/keys/default` | `{"key_hex":"…"}` | 204 / 400 | Set the fallback key |
| DELETE | `/v1/keys/default` | — | 204 / 404 | Remove the fallback key |
| GET | `/v1/caps` | — | 200 | Effective runtime caps |
| PATCH | `/v1/caps` | partial caps object | 200 | Adjust caps; returns effective state |
| POST | `/v1/drain` | `{"draining":bool}` | 200 | Stop/resume accepting **new** sessions |
| POST | `/v1/shutdown` | — | 202 | Request graceful process shutdown |

The optional `session_id` in an expiry request is the internal ID returned by
`/v1/sessions`, not the wire SSID. A client-only request requires exactly one
match; multiple matches return 409 without removing anything. Expiry preserves
provisioning, so later traffic can recreate the runtime session.

Session receive counts and idle timestamps are updated only after base parsing
and configured authentication succeed. Invalid base HMACs and unknown/revoked
keys cannot create entries or keep existing entries alive. Aggregate
`packets_received` / `packets_dropped` still account for rejected processing.

Deleting a key **revokes access**: once a keyset exists, an authenticated
packet whose SSID resolves to no key (unknown SSID with no default, or the
last key deleted) is dropped. Removing keys can only make the reflector
stricter — it never falls back to answering authenticated-layout packets
without verification, regardless of `--require-hmac`. A configured default key
still applies after removing a per-SSID entry. Rotation/revocation affects new
requests, while already accepted replies (including queued burst copies) retain
the key used for their validation and assembly. Key changes do not cancel them.

### Response shapes

`GET /v1/status`:

```json
{
  "version": "1.0.0",
  "uptime_seconds": 12345,
  "draining": false,
  "sessions": 17,
  "session_admission": "provisioned",
  "provisioned_sessions": 20,
  "counters": {
    "packets_received": 123456,
    "packets_reflected": 123450,
    "packets_dropped": 4,
    "packets_rate_limited": 2,
    "reply_queue_rejected": 0,
    "queued_replies_cancelled": 0
  }
}
```

`GET /v1/sessions`:

```json
[
  {
    "client": "192.0.2.10:4862",
    "local": "192.0.2.20:862",
    "ssid": 42,
    "sender_micro_session_id": null,
    "session_id": 3,
    "packets_received": 1200,
    "packets_transmitted": 1200,
    "last_reflected_seq": 1199,
    "idle_seconds": 0.42
  }
]
```

`GET /v1/caps` / `PATCH /v1/caps` (PATCH body: any subset of the same
fields):

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

Zero disables rate limiting (`max_pps`) or the session cap (`max_sessions`).
A zero `reflected_control_max_count` disables requested burst/size control;
it does not permit unlimited copies. `rate_burst = 0` uses the current rate as the bucket capacity. Size and interval
fields are unsigned limits; PATCH does not validate cross-field combinations.

### Runtime behavior

- **Keys are write-only.** No endpoint ever returns key material; logs
  never contain it; request strings are zeroized after parsing. `key_hex`
  goes through the same `HmacKey::from_hex` validation as the CLI.
- **Drain** rejects new identities in both sequencing modes. Existing sessions
  and their queued replies continue. Turning drain off restores normal admission.
- **Session cap** rejects new identities at capacity without evicting existing
  entries, including when a runtime PATCH lowers the cap below the current count.
  Provisioned identities also need a slot; provisioning does not reserve capacity.
- **Expiry** removes the selected runtime identity and retires its transmissions.
  It waits for a datagram already being sent; old queued copies cannot transmit
  after expiry returns. Re-admission starts fresh sequence/counter/replay state
  under a new internal ID. Provisioning survives expiry. Idle cleanup uses the
  same retirement rule; the idle clock is refreshed by incoming accepted packets.
- **Shutdown** sets `shutdown_requested`; both backends observe it through a
  250 ms control poll. They stop new packet intake and finish accepted work for
  up to `--reflector-shutdown-grace-ms` (0–60000 ms, default 0), then cancel
  remaining copies. Pnet capture polls at 100 ms independently of session expiry;
  send-worker deadlines are checked between nonblocking sends. The grace interval
  starts when the send loop observes shutdown, and an empty queue exits early.
  The HTTP response (202) lands before exit; repeated requests do not extend the
  deadline. Ctrl-C and Unix SIGTERM use the same queue policy.
- **Queued work** is separately bounded by startup `--reflector-queue-capacity`
  (default 1024), shared across processing, handoff, deadlines and active sends.
  Queue overflow drops the new request without creating/refreshing a session.
  Status exposes `reply_queue_rejected` (requests) and `queued_replies_cancelled`
  (unsent copies). Both contribute to aggregate dropped packets, once per
  rejected request or cancelled remainder. Queue settings are not runtime PATCH fields.
- **Caps PATCH** is per-field atomic but not transactional across fields;
  fields are applied independently. Session-cap and drain changes additionally
  take the session-table write lock to serialize with new admission. `reflected_control_max_size`
  reports the administrative payload limit. Each burst copy and routing fallback
  also checks its actual Linux route MTU immediately before sending; PATCH
  cannot bypass that check. Queued requests retain the administrative cap
  captured during request processing.

## Shared state

Both receiver backends read the same state. Keyset reads cover validation,
assembly, and a copy of the selected key; the lock is released before queuing or
sending. Each accepted request retains that key until its replies finish.

Cap fields update independently. Session cap and drain changes hold the
session-table write lock to serialize with admission. A per-session lifetime
lock covers each send and its counter updates, so expiry waits for an in-flight
send and prevents later sends from that session instance.

The API manages the per-SSID/default keyset. The legacy single CLI key remains
fixed at startup; an installed keyset takes precedence.

## Security and failures

- `--control-token-file` enables bearer authentication. Without it, any client
  that can reach the listener can change keys and limits or stop the reflector.
- `--control-tls-cert` and `--control-tls-key` take PEM files and enable HTTPS.
  Both require `--control-token-file`. Client certificates (mTLS) are unsupported.
- Certificate, key, token, and bind failures stop startup. Enabling `--control`
  without the build feature also fails startup.
- Non-loopback HTTP binds produce a warning. Use TLS or an SSH tunnel for remote
  access. Loopback binding does not authenticate local users or rate-limit calls.
- Key inventory responses contain identifiers only. Key and token files use the
  [secret-file permission checks](security.md#configuration-file-and-key-file-permissions).

Mutating calls log an `info` event without key material. There is no separate
audit log.

## Verification

`tests/keyset_fallback_test.rs` checks directory/default keys, revocation,
fallback signing, and rotation during queued bursts. Shared transmission tests
inject CoS failures and also run in pnet-only builds.

`scripts/release_checks.py` drives a real reflector over bearer-authenticated
HTTP and certificate-verified HTTPS, using independently signed UDP packets.
It checks rejected tokens, queued-burst rotation, deletion, default-key fallback,
inventory redaction, and shutdown. See [release verification](release-evidence.md).
