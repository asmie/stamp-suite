# Runtime control API

Reflector HTTP API: setup, authentication, endpoints and request/response formats.

The API needs a binary built with the `control` feature and runs only in
reflector mode. It manages HMAC keys, sessions, rate and session limits,
drain and shutdown.

```sh
stamp-suite --is-reflector --control --control-token-file /etc/stamp/control.token
```

The default listener is `127.0.0.1:9091` (`--control-addr`). With a token file,
send the token as `Authorization: Bearer <token>`:

```sh
curl -H "Authorization: Bearer $(sudo cat /etc/stamp/control.token)" \
  http://127.0.0.1:9091/v1/status
```

Changes made through the API last until the process exits. Put lasting
settings in the command line or the [configuration file](usage.md#configuration-file).
Session provisioning, the idle timeout and the queue capacity cannot be
changed through the API. Installing a key does not provision a session; see
[Session provisioning](usage.md#session-provisioning).

## Endpoints

All paths start with `/v1`. Request and response bodies are JSON; send
`Content-Type: application/json` with a body.

| Method | Path | Request body | Success | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/v1/status` | none | 200 | Version, uptime, drain flag, session counts and counters |
| GET | `/v1/sessions` | none | 200 | Tracked sessions |
| POST | `/v1/sessions/expire` | `{"client": "ip:port", "session_id": 3}` | 200 | Remove one tracked session |
| GET | `/v1/keys` | none | 200 | SSIDs that have a key, and whether a default key exists |
| PUT | `/v1/keys/{ssid}` | `{"key_hex": "..."}` | 204 | Add or replace the key for one SSID (decimal, 0 to 65535) |
| DELETE | `/v1/keys/{ssid}` | none | 204 | Remove the key for one SSID |
| PUT | `/v1/keys/default` | `{"key_hex": "..."}` | 204 | Set the default key |
| DELETE | `/v1/keys/default` | none | 204 | Remove the default key |
| GET | `/v1/caps` | none | 200 | Current runtime limits |
| PATCH | `/v1/caps` | any subset of the limits | 200 | Change limits; returns all current limits |
| POST | `/v1/drain` | `{"draining": true}` | 200 | Stop or resume admitting new sessions |
| POST | `/v1/shutdown` | none | 202 | Stop the reflector |

### Errors

| Status | When | Body |
| --- | --- | --- |
| 400 | Invalid key (bad hex or shorter than 16 bytes) | `{"error": "invalid key: ..."}` |
| 400 | Body is not valid JSON, or the SSID in the path is not a number from 0 to 65535 | Plain text |
| 401 | Token configured and the header is missing or wrong | `{"error": "missing or invalid bearer token"}` |
| 404 | No matching session, no key for that SSID, or no default key | `{"error": "..."}` |
| 409 | Expiry request matches more than one session | `{"error": "multiple sessions for client; specify session_id"}` |
| 415 | Body sent without `Content-Type: application/json` | Plain text |
| 422 | Unknown field, missing field or wrong type in the body | Plain text |

Request bodies reject unknown fields, so a misspelled limit name returns 422
instead of being ignored.

### Status

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
    "reply_queue_rejected": 0,
    "queued_replies_cancelled": 0,
    "packets_rate_limited": 2,
    "packets_replayed": 0,
    "packets_reordered": 1
  }
}
```

`session_admission` is `permissive` or `provisioned`. The counters are totals
since startup:

| Counter | Meaning |
| --- | --- |
| `packets_received` | Packets received, including ones dropped after the rate limit check. Packets dropped by `--max-pps` are not counted here. |
| `packets_reflected` | Replies sent. |
| `packets_dropped` | Packets not answered, for any reason. |
| `reply_queue_rejected` | Requests dropped because the reply queue was full. Also counted in `packets_dropped`. |
| `queued_replies_cancelled` | Queued reply copies that were never sent because their work was cancelled, for example at shutdown. Each affected request adds one to `packets_dropped`. |
| `packets_rate_limited` | Packets dropped by `--max-pps`. Also counted in `packets_dropped`. |
| `packets_replayed` | Packets whose sequence number the session had already seen (RFC 10052 §5). Counted also when `--drop-replayed` is off. |
| `packets_reordered` | Packets older than the session's highest sequence number but not seen before. |

### Sessions

`GET /v1/sessions` returns an array:

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

`session_id` is an internal number, not the wire SSID. `idle_seconds` is the
time since the last accepted packet for the session.

`POST /v1/sessions/expire` removes one session. `session_id` is optional when
the client address matches exactly one session. When it matches several, the
call returns 409 and removes nothing. A successful call returns 200 with an
empty body. Expiry does not remove provisioning, so later traffic from the
same client can create the session again with fresh counters and a new
`session_id`. After the call returns, no queued reply from the old session is
sent.

Session counters and the idle time change only for packets that pass parsing
and authentication. Packets with an invalid HMAC, or for an SSID without a
key, cannot create a session or keep one alive. They still count in the
`packets_received` and `packets_dropped` totals.

### Keys

`GET /v1/keys`:

```json
{ "default": true, "ssids": [42, 256] }
```

No endpoint returns key material, and the reflector never logs it. Each key
change logs one `info` line that names the SSID but not the key. `key_hex` must decode to
at least 16 bytes, the same rule as `--hmac-key`.

The API edits the reflector's keyset. A single key given at startup with
`--hmac-key`, `STAMP_HMAC_KEY` or `--hmac-key-file` is that keyset's default
key, so `PUT` and `DELETE` on `/v1/keys/default` replace or remove it. A
SIGHUP reloads the key file or directory and discards changes made through
the API.

Deleting a key revokes access. When a keyset exists, an authenticated packet
whose SSID resolves to no key is dropped, also after the last key is deleted.
The reflector never falls back to answering such packets without
verification. A default key still applies after its per-SSID key is removed.
Key changes affect new requests only; replies already queued keep the key that
validated their request. [Key sourcing and rotation](security.md#key-sourcing-and-rotation)
covers key files and rotation procedure.

### Limits

`GET /v1/caps` and `PATCH /v1/caps` return:

```json
{
  "max_pps": 0,
  "rate_burst": 0,
  "max_sessions": 65536,
  "reflected_control_max_count": 0,
  "reflected_control_max_size": 1500,
  "reflected_control_min_interval_ns": 1000,
  "reflected_control_max_rate": 12500000,
  "reflected_control_max_volume": 1500000
}
```

The fields match the options of the same name (`--max-pps`,
`--reflector-rate-burst`, `--max-sessions`, `--reflected-control-*`). The PATCH
body can contain any subset of them:

```sh
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"max_pps": 1000, "max_sessions": 5000}' http://127.0.0.1:9091/v1/caps
```

- `max_pps` 0 disables rate limiting; `rate_burst` 0 uses the rate as the
  bucket size.
- `max_sessions` 0 removes the session limit. Lowering it below the current
  count does not evict sessions; new sessions are rejected until the count
  falls below the limit.
- `reflected_control_max_count` 0 disables Type 12 requests; it does not
  allow unlimited copies. `reflected_control_max_rate` (bytes per second) and
  `reflected_control_max_volume` (bytes) limit what one request can generate.
- `reflected_control_max_size` is an administrative payload limit. Each reply
  copy is also checked against the route MTU on Linux before it is sent, and
  PATCH cannot bypass that check.

Each field is applied on its own. PATCH does not check combinations of
fields, and a request with several fields is not applied as one transaction.
Requests already queued keep the `reflected_control_max_size` that applied
when they were accepted.

### Drain and shutdown

`POST /v1/drain` with `{"draining": true}` stops admitting new sessions;
existing sessions and their queued replies continue. `{"draining": false}`
resumes admission. The response repeats the new state.

`POST /v1/shutdown` stops the reflector the same way as SIGINT or SIGTERM. It
returns 202 before the process exits; calling it again has no further effect.
How queued replies are finished or cancelled, and the related options, are
described in [Capacity, drain and shutdown](usage.md#capacity-drain-and-shutdown).

## Security and failures

- `--control-token-file` turns on bearer-token authentication. Without it, any
  client that can reach the listener can change keys and limits or stop the
  reflector.
- `--control-tls-cert` and `--control-tls-key` take PEM files and turn on
  HTTPS. They must be used together, and both require `--control-token-file`.
  Client certificates (mutual TLS) are not supported.
- A missing or unreadable certificate, key or token file, a token file with
  group or other permissions, or a failed bind stops startup. So does
  `--control` in a binary built without the `control` feature, or in sender
  mode.
- Binding to a non-loopback address without TLS logs a warning. Use TLS or an
  SSH tunnel for remote access. A loopback listener does not authenticate
  local users and does not rate-limit calls.
- Token files use the same [permission checks](security.md#file-permissions)
  as key files.

There is no separate audit log. Key, limit, drain and shutdown calls each log
one `info` line; session expiry is not logged.

## Verification

`tests/keyset_fallback_test.rs` checks directory and default keys, revocation,
fallback signing and rotation while bursts are queued. `tests/control_api_test.rs`
and the unit tests in `src/control/tests.rs` cover the endpoints and their
error codes.

`scripts/release_checks.py` drives a real reflector over bearer-authenticated
HTTP and certificate-verified HTTPS with independently signed UDP packets. It
checks rejected tokens, key rotation during queued bursts, deletion, default
key fallback, inventory redaction and shutdown. See
[release verification](release-evidence.md).
