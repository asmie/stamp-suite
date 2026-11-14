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
| GET | `/v1/sessions/page?limit=100&cursor=...` | none | 200 | Bounded page of tracked sessions |
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
| 400 | Invalid session page query, limit or cursor | `{"error": "..."}` |
| 410 | Session page cursor from another manager or process lifetime | `{"error": "..."}` |
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
    "packets_reordered": 1,
    "ber_conformance": {
      "missing_padding": 0,
      "duplicate_padding": 0,
      "duplicate_ber": 0,
      "short_ber_value": 0,
      "duplicate_pattern": 0,
      "padding_misaligned": 0,
      "padding_resized": 0
    },
    "tlv_conformance": {
      "type12_count_limit": 0,
      "type12_interval_limit": 0,
      "type12_size_limit": 0,
      "type12_rate_limit": 0,
      "type12_volume_limit": 0,
      "type12_route_mtu": 0,
      "type12_padding_unencodable": 0,
      "header_order": 0,
      "header_fixed_policy": 0,
      "header_ipv6_policy": 0,
      "header_ipv6_length": 0,
      "header_capture_unavailable": 0,
      "header_selector_ambiguous": 0,
      "header_selector_no_match": 0,
      "header_length_unavailable": 0,
      "cos_marking_unavailable": 0,
      "reply_header_unsupported": 0,
      "reply_header_duplicate": 0,
      "peer_c_preserved": 0
    }
  }
}
```

`session_admission` is `permissive` or `provisioned`. The counters are totals
since startup:

`counters.ber_conformance` counts successful reflected datagrams per locally
generated BER C condition. Each reason counts at most once per datagram;
successful burst copies count separately. Failed, cancelled and suppressed
sends do not add a reason. Protected payloads are not semantically classified
after an integrity failure. A locally generated `short_ber_value` C is counted
even if verification subsequently sets I: its cause is the structural length
check, not a payload interpretation. These counters do not diagnose every fault
in an invalid packet.
`padding_resized` includes Type 12 and MTU changes that invalidate the original
BER denominator. Opaque echoes and M-only nested errors add no BER C diagnostic.
The seven keys are fixed and include zero values. See [BER diagnostics](ber-migration.md#conformance-diagnostics).

`counters.tlv_conformance` counts successfully sent datagrams with
reflected Type 12, header-reflection, CoS and nested control C conditions,
plus preserved peer C provenance. It uses the same once-per-reason,
successful-send rules as the BER counters and includes all
19 fixed keys, including zero values. The Type 12 reasons are:

| Reason | Meaning |
| --- | --- |
| `type12_count_limit` | Requested count exceeds the configured maximum. |
| `type12_interval_limit` | Multiple copies request an interval below the configured floor. |
| `type12_size_limit` | Rounded requested size exceeds the configured cap, or the cap binds at send-time shaping. |
| `type12_rate_limit` | Requested multi-copy byte rate exceeds the configured maximum. |
| `type12_volume_limit` | Requested total bytes exceed the configured maximum. |
| `type12_route_mtu` | The route payload budget binds when shaping a processed Type 12 reply. |
| `type12_padding_unencodable` | The requested size leaves a gap smaller than a padding TLV header. |

If route and configured caps tie during shaping, both reasons count. A failed
attempt contributes no send-time reason to a later retry. Disabled, replayed,
opaque and integrity-failed requests add no Type 12 limit diagnostics. BER reasons
remain independent; a reply can increment both groups.

Header reasons describe processed Type 246/247 C flags:

| Reason | Meaning |
| --- | --- |
| `header_order` | A fixed-header request follows an extension-header request. |
| `header_fixed_policy` | Local policy refuses fixed-header reflection. |
| `header_ipv6_policy` | Local policy refuses IPv6 extension-header reflection. |
| `header_ipv6_length` | An extension-header request is shorter than eight octets or not a multiple of eight. |
| `header_capture_unavailable` | The backend cannot supply captures of the requested header class. |
| `header_selector_ambiguous` | A nonzero selector matches multiple unconsumed records. |
| `header_selector_no_match` | Records of the requested length remain, but none matches the selector. |
| `header_length_unavailable` | No unconsumed record has the requested length and minimum selector size. |

Size trimming removes optional headers from the end. A header reason counts
only if a header that produced it survives in the sent reply. Repeated headers
with the same reason count once per datagram. A failed MTU attempt neither
adds nor removes a reason from a later retry. Opaque, malformed and
integrity-failed echoes add no header reason.

| Reason | Meaning |
| --- | --- |
| `cos_marking_unavailable` | The backend cannot apply either requested ECN or the Not-ECT fallback, and marks a processed CoS TLV with C. |
| `reply_header_unsupported` | A processed IPv6 Extension Header Control child receives C because reply-header attachment is unsupported. |
| `reply_header_duplicate` | A Type 12 parent has multiple complete IPv6 Extension Header Control children and at least one receives C. |
| `peer_c_preserved` | A complete child header in a known container retains C supplied by the peer, with no corresponding local C-generation cause. |

A successful Not-ECT fallback, a policy refusal without C, and an ordinary
UDP send error add no CoS reason. Repeated child Cs count once per reason per
successful copy. A nonzero-length control child gets M rather than C and adds
no C reason by itself. A locally marked child remains diagnosed if its parent
later receives U for disabled or replayed Type 12 handling. Ignored later
parents, unknown children and integrity-failed opaque values do not manufacture
the local-cause reasons.

`peer_c_preserved` is a provenance observation, including when HMAC failure
requires an opaque echo. It does not establish a verified measurement or a
local/network fault. Only child headers in the defined Location, Timestamp
Information, Return Path, Type 12 and BER layouts are observed. Values and
unknown container formats are not decoded; an incomplete child stops observation
of that chain. A child C generated locally uses its specific local reason even
if the sender also supplied C. Separate preserved children can add the peer
reason on the same datagram. No packet bytes or authentication decisions change.
Legacy `--tlv-mode ignore` copies an uninterpreted tail and has no TLV provenance
claim. These diagnostics describe the TLV-enabled reflector profile.

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

For large tables, use `GET /v1/sessions/page` instead. It returns an object
with `items` (the same session fields as above) and `next_cursor` (an opaque
string, or `null` when the walk is complete). The optional `limit` defaults
to 100 and accepts 1 through 500. For example:

```sh
curl -sS 'http://127.0.0.1:9091/v1/sessions/page?limit=100'
# Pass the returned cursor unchanged, URL encoded, for the next page:
curl -sS --get 'http://127.0.0.1:9091/v1/sessions/page' \
  --data-urlencode 'limit=100' --data-urlencode "cursor=$next_cursor"
```

Use the configured bearer token on every request when authentication is enabled.
An empty table returns `{"items":[],"next_cursor":null}`. Invalid limits,
malformed cursors, duplicate parameters and unknown query fields return 400
with a JSON `error`. A cursor from a different session manager, including
after a process restart, returns 410 with a JSON `error`; start again without
a cursor. Cursors otherwise remain valid for that manager's lifetime and have
no time based expiry. The limit may change between pages.

Each walk has a fixed creation boundary taken on its first page. Entries have
a stable internal inventory order; entries present when the control server
starts have an unspecified initial order, and subsequent entries follow
creation order. Deletions are skipped. Later creations, including recreation
of an expired identity or reuse of an internal `session_id`, are excluded
from that walk. Counters and idle times are live when each page is collected;
this is not a snapshot of the whole table. If remaining entries disappear,
the final page can be empty. Retiring identities remain visible until removal
completes, as they do in the legacy inventory.

Each page collects only its range: O(log n + limit) index work and O(limit)
response storage. The control server initializes an ordered key index once,
before accepting requests. Initialization holds the table write lock for O(n)
work and retains O(n) index storage; creation and removal maintain that index.
Managers without a control server do not enable it. Page requests can still
wait for table access or per-session metadata updates, so the page size does
not impose a wall clock latency bound.

The existing `GET /v1/sessions` continues to return its complete, unordered
array. Migration is opt-in: switch the path, read `items`, and repeat with
`next_cursor` until it is `null`.

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
