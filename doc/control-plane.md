# Runtime control API

The reflector's HTTP API: how to turn it on and secure it, its endpoints, and
the request and response formats.

The API is only available in a binary built with the `control` feature, and
only in reflector mode. Through it you can manage HMAC keys and sessions,
change the rate and session limits, and drain or stop the reflector.

```sh
stamp-suite --is-reflector --control --control-token-file /etc/stamp/control.token
```

By default the API listens on `127.0.0.1:9091` (`--control-addr`). If you set
a token file, send the token as `Authorization: Bearer <token>`:

```sh
curl -H "Authorization: Bearer $(sudo cat /etc/stamp/control.token)" \
  http://127.0.0.1:9091/v1/status
```

Changes made through the API are lost when the process exits. Put settings you
want to keep on the command line or in the
[configuration file](usage.md#configuration-file). The API cannot change
session provisioning, the idle timeout or the queue capacity. Installing a key
does not provision a session; see
[Session provisioning](usage.md#session-provisioning).

## Endpoints

All paths start with `/v1`. Request and response bodies are JSON. When you
send a body, also send `Content-Type: application/json`.

| Method | Path | Request body | Success | Purpose |
| --- | --- | --- | --- | --- |
| GET | `/v1/status` | none | 200 | Version, uptime, drain flag, session counts and counters |
| GET | `/v1/sessions` | none | 200 | Tracked sessions |
| GET | `/v1/sessions/page?limit=100&cursor=...` | none | 200 | One page of tracked sessions, up to `limit` entries |
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

Request bodies reject unknown fields, so a misspelled limit name gets a 422
rather than being silently ignored.

### Status

`GET /v1/status`:

```json
{
  "version": "1.1.0",
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
      "cos_dscp_fallback": 0,
      "reply_header_unsupported": 0,
      "reply_header_duplicate": 0,
      "peer_c_preserved": 0
    }
  }
}
```

`session_admission` is `permissive` or `provisioned`. All counters are totals
since startup.

`counters.ber_conformance` has one counter for each reason the reflector
itself sets the C flag in a BER TLV. A counter goes up by one for each reply
datagram that is actually sent with that reason. A reason counts at most once
per datagram, and each copy in a burst is its own datagram. Sends that fail,
are cancelled or are suppressed count nothing. After an integrity failure the
reflector does not interpret the protected payload, so it does not classify
it. `short_ber_value` is the exception: it comes from a structural length
check, not from reading the payload, so it is counted even if verification
then sets the I flag. These counters do not report every fault in an invalid
packet.

`padding_resized` also counts replies where Type 12 or an MTU limit changed
the padding size, which makes the original BER denominator invalid. Opaque
echoes and nested errors that set only M add no BER reason. All seven keys are
always present, even when they are zero. See
[BER diagnostics](ber-migration.md#conformance-diagnostics).

`counters.tlv_conformance` uses the same rules for other C conditions: Type 12
limits, header reflection, nested control children, CoS marking that the
backend cannot apply, the third-DSCP fallback, and C flags preserved from the
peer. A reason counts at most once per datagram, and only when the datagram is
sent. All 20 keys are always present, even when they are zero. The Type 12
reasons are:

| Reason | Meaning |
| --- | --- |
| `type12_count_limit` | The requested count is above the configured maximum. |
| `type12_interval_limit` | A request for several copies asks for an interval below the configured floor. |
| `type12_size_limit` | The rounded requested size is above the configured cap, or the cap is the limiting factor when the reply is shaped at send time. |
| `type12_rate_limit` | The requested byte rate for several copies is above the configured maximum. |
| `type12_volume_limit` | The requested total bytes are above the configured maximum. |
| `type12_route_mtu` | The route's payload budget is the limiting factor when a processed Type 12 reply is shaped. |
| `type12_padding_unencodable` | The requested size leaves a gap too small to hold a padding TLV header. |

If the route budget and a configured cap give the same limit during shaping,
both reasons count. When a send attempt fails, the reasons it found at send
time are not carried over to a retry. Requests that are disabled, replayed,
echoed opaquely or fail an integrity check add no Type 12 limit reasons. BER
reasons are counted separately, so one reply can raise counters in both
groups.

Header reasons cover the C flags set while processing Type 246 and 247 TLVs:

| Reason | Meaning |
| --- | --- |
| `header_order` | A fixed-header request comes after an extension-header request. |
| `header_fixed_policy` | Local policy refuses fixed-header reflection. |
| `header_ipv6_policy` | Local policy refuses IPv6 extension-header reflection. |
| `header_ipv6_length` | An extension-header request is shorter than eight octets or not a multiple of eight. |
| `header_capture_unavailable` | The backend cannot capture headers of the requested class. |
| `header_selector_ambiguous` | A nonzero selector matches more than one unconsumed record. |
| `header_selector_no_match` | There are unconsumed records of the requested length, but none matches the selector. |
| `header_length_unavailable` | No unconsumed record has the requested length and the minimum selector size. |

When a reply has to shrink, optional headers are removed from the end. A
header reason counts only if a header that caused it is still in the reply
that is sent. Several headers with the same reason count once per datagram. A
failed MTU attempt neither adds nor removes reasons for a later retry. Echoes
that are opaque, malformed or failed an integrity check add no header reason.

| Reason | Meaning |
| --- | --- |
| `cos_marking_unavailable` | The backend can apply neither the requested ECN value nor the Not-ECT fallback, and reports RPE=01 in a processed CoS TLV. |
| `cos_dscp_fallback` | Neither DSCP1 nor DSCP2 is permitted, so a successful reply uses a third DSCP that local policy permits, with RPD=01 and C. |
| `reply_header_unsupported` | A processed IPv6 Extension Header Control child gets C because the reflector cannot attach headers to replies. |
| `reply_header_duplicate` | A Type 12 parent has more than one complete IPv6 Extension Header Control child, and at least one of them gets C. |
| `peer_c_preserved` | A complete child header in a known container keeps a C flag that the peer set, and the reflector had no local reason to set C. |

These add no CoS reason: a Not-ECT fallback that succeeds, a policy refusal
that does not set C, and an ordinary UDP send error. If several children carry
C for the same reason, that reason counts once per copy that is sent. A
control child with a nonzero length gets M instead of C, and adds no C reason
on its own. If the reflector sets C on a child and the parent then gets U
because Type 12 is disabled or the request is a replay, the child's reason
still counts. Later parents that the reflector ignores, unknown children, and
opaque values that failed an integrity check never produce a local-cause
reason.

`peer_c_preserved` only records where a C flag came from. It is counted even
when an HMAC failure forces an opaque echo. It does not mean the measurement
was verified, and it does not point to a fault on the reflector or in the
network. The reflector only looks at child headers in the defined layouts of
the Location, Timestamp Information, Return Path, Type 12 and BER TLVs. It
does not decode values or unknown container formats, and it stops following a
chain at the first incomplete child. If the reflector sets C on a child
itself, the child counts under that specific local reason, even if the sender
had already set C. Other children in the same datagram that kept the peer's C
can still add `peer_c_preserved`. Counting never changes packet bytes or
authentication decisions. Legacy `--tlv-mode ignore` copies the tail without
interpreting it, so it reports nothing about where C flags came from. All of
these diagnostics apply to a reflector with TLV processing enabled.

| Counter | Meaning |
| --- | --- |
| `packets_received` | Packets that passed the rate limit check, including ones dropped later. Packets dropped by `--max-pps` are not counted here. |
| `packets_reflected` | Replies sent. |
| `packets_dropped` | Packets not answered, for any reason. |
| `reply_queue_rejected` | Requests dropped because the reply queue was full. Also counted in `packets_dropped`. |
| `queued_replies_cancelled` | Queued reply copies that were never sent because their work was cancelled, for example at shutdown. Each affected request adds one to `packets_dropped`. |
| `packets_rate_limited` | Packets dropped by `--max-pps`. Also counted in `packets_dropped`. |
| `packets_replayed` | Packets whose sequence number the session had already seen (RFC 10052 §5). Counted whether or not `--drop-replayed` is on. |
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

`session_id` is an internal number, not the SSID on the wire. `idle_seconds`
is the time since the session last accepted a packet.

For large tables, use `GET /v1/sessions/page` instead. It returns an object
with `items` (the same session fields as above) and `next_cursor`, an opaque
string that is `null` on the last page. The optional `limit` defaults to 100
and accepts 1 through 500. For example:

```sh
curl -sS 'http://127.0.0.1:9091/v1/sessions/page?limit=100'
# Pass the returned cursor unchanged, URL encoded, for the next page:
curl -sS --get 'http://127.0.0.1:9091/v1/sessions/page' \
  --data-urlencode 'limit=100' --data-urlencode "cursor=$next_cursor"
```

If authentication is on, send the bearer token with every request. An empty
table returns `{"items":[],"next_cursor":null}`. An invalid limit, a malformed
cursor, a repeated parameter or an unknown query field gets a 400 with a JSON
`error`. A cursor from a different session manager, which includes any cursor
from before a process restart, gets a 410 with a JSON `error`; start again
without a cursor. Otherwise a cursor stays valid as long as its manager exists
and never times out. You can change the limit from one page to the next.

The first page of a walk decides which sessions the walk can return: only the
ones that existed at that moment. Sessions come in a stable internal order.
Sessions that already existed when the control server started come in an
unspecified order, and later ones follow in the order they were created. A
session deleted during the walk is skipped. A session created after the first
page is left out, and that includes an expired identity that comes back and a
new session that reuses an internal `session_id`. Counters and idle times are
read when each page is built, so a walk is not a snapshot of the whole table.
If all the remaining sessions disappear, the last page can be empty. A session
that is being retired stays visible until its removal finishes, as it does in
`GET /v1/sessions`.

Building a page costs O(log n + limit) index work and O(limit) memory for the
response. Paging relies on an ordered key index that the control server builds
once, before it accepts requests. Building it holds the session table's write
lock for O(n) work, and the index keeps using O(n) memory; after that, session
creation and removal keep it up to date. Without a control server the index is
not built. A page request can still wait for the table lock or for per-session
metadata updates, so a small page does not guarantee a fast response.

`GET /v1/sessions` still returns the whole table as one unordered array. To
switch to paging, change the path, read `items`, and repeat with
`next_cursor` until it is `null`.

`POST /v1/sessions/expire` removes one session. You can leave out
`session_id` if the client address matches exactly one session. If it matches
several, the call returns 409 and removes nothing. On success it returns 200
with an empty body. Expiry does not remove provisioning, so later traffic from
the same client can create the session again, with fresh counters and a new
`session_id`. Once the call returns, no queued reply from the old session is
sent.

Session counters and the idle time only change for packets that pass parsing
and authentication. A packet with an invalid HMAC, or for an SSID that has no
key, cannot create a session or keep one alive. It still counts in the
`packets_received` and `packets_dropped` totals.

### Keys

`GET /v1/keys`:

```json
{ "default": true, "ssids": [42, 256] }
```

No endpoint returns key material, and the reflector never logs it. Each key
change logs one `info` line that names the SSID but not the key. `key_hex`
must decode to at least 16 bytes, the same rule as for `--hmac-key`.

The API edits the reflector's keyset. A single key given at startup with
`--hmac-key`, `STAMP_HMAC_KEY` or `--hmac-key-file` is the keyset's default
key, so `PUT` and `DELETE` on `/v1/keys/default` replace or remove that key. A
SIGHUP rereads the key file or directory and throws away changes made through
the API.

Deleting a key revokes access. Once a keyset exists, an authenticated packet
whose SSID has no key is dropped, and that stays true after you delete the
last key. The reflector never falls back to answering such packets without
checking them. If a default key exists, it still applies after the per-SSID
key is removed. Key changes apply to new requests only: replies that are
already queued use the key that validated their request.
[Key sourcing and rotation](security.md#key-sourcing-and-rotation) covers key
files and how to rotate keys.

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

Each field matches the option with the same name (`--max-pps`,
`--reflector-rate-burst`, `--max-sessions`, `--reflected-control-*`). A PATCH
body can contain any subset of them:

```sh
curl -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"max_pps": 1000, "max_sessions": 5000}' http://127.0.0.1:9091/v1/caps
```

- `max_pps` 0 turns rate limiting off. `rate_burst` 0 makes the bucket size
  equal to the rate.
- `max_sessions` 0 removes the session limit. Setting it below the current
  session count does not evict anyone; new sessions are rejected until the
  count drops below the limit.
- `reflected_control_max_count` 0 disables Type 12 requests. It does not mean
  unlimited copies. `reflected_control_max_rate` (bytes per second) and
  `reflected_control_max_volume` (bytes) cap what a single request can
  generate.
- `reflected_control_max_size` is an administrative limit on payload size. On
  Linux and Windows, each reply copy is also checked against the route MTU
  before it is sent, and PATCH cannot turn that check off.

`max_pps` and `rate_burst` are stored, read and updated as a pair. Two PATCH
requests that arrive at the same time and each change one of them do not undo
each other's change. If you leave out `rate_burst`, it keeps its current
value: a nonzero burst size stays as it is, and a zero burst size follows the
new rate. To reset the burst size to the rate in the same update, send
`rate_burst: 0`. Existing buckets keep their tokens and use the new limits the
next time they admit a packet.

The other fields are set one by one. PATCH does not check whether the values
make sense together, and a request with several fields is not applied as a
single transaction. Requests that are already queued keep the
`reflected_control_max_size` that was in force when they were accepted.

### Drain and shutdown

`POST /v1/drain` with `{"draining": true}` stops the reflector from admitting
new sessions. Existing sessions and their queued replies carry on.
`{"draining": false}` starts admitting again. The response repeats the new
state.

`POST /v1/shutdown` stops the reflector just as SIGINT or SIGTERM would. It
returns 202 before the process exits, and calling it again does nothing.
[Capacity, drain and shutdown](usage.md#capacity-drain-and-shutdown) explains
how queued replies are finished or cancelled, and which options control that.

## Security and failures

- `--control-token-file` turns on bearer-token authentication. Without it,
  any client that can reach the listener can change keys and limits or stop
  the reflector.
- `--control-tls-cert` and `--control-tls-key` take PEM files and turn on
  HTTPS. You must give both, and both require `--control-token-file`. Client
  certificates (mutual TLS) are not supported.
- Startup fails if a certificate, key or token file is missing or unreadable,
  if the token file has any group or other permissions, or if the bind fails.
  It also fails if you pass `--control` to a binary built without the
  `control` feature, or in sender mode.
- Binding to a non-loopback address without TLS logs a warning. For remote
  access, use TLS or an SSH tunnel. A loopback listener does not authenticate
  local users and does not rate-limit calls.
- Token files go through the same
  [permission checks](security.md#file-permissions) as key files.

There is no separate audit log. Each key, limit, drain and shutdown call logs
one `info` line. Session expiry is not logged.

## Verification

`tests/keyset_fallback_test.rs` tests directory and default keys, revocation,
signing with the fallback key, and rotation while bursts are queued.
`tests/control_api_test.rs` and the unit tests in `src/control/tests.rs` cover
the endpoints and their error codes.

`scripts/release_checks.py` runs a real reflector and talks to it over HTTP
with a bearer token and over HTTPS with certificate verification, while
sending UDP packets that the script signs with its own code. It checks that
bad tokens are rejected, and tests key rotation during queued bursts, key
deletion, fallback to the default key, that the key list hides key material,
and shutdown. See [release verification](release-evidence.md).
