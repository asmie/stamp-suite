# draft-ietf-ippm-stamp-ext-hdr conformance

This matrix maps each normative clause of draft-ietf-ippm-stamp-ext-hdr
(reflected IPv6 extension headers and fixed IP headers, Types 246 and 247) to
the stamp-suite code and tests that implement it. It is for contributors and
reviewers who need to know what header reflection does, where, and on which
backend.

Revision frozen: draft-ietf-ippm-stamp-ext-hdr-15, 30 September 2026.
Source: [draft-ietf-ippm-stamp-ext-hdr-15](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-ext-hdr-15.txt).

Summary: 63 clauses: 54 Compliant, 2 Partial, 0 Gap, 7 N-A, 0 Excluded.

The Clause column paraphrases the draft. Row IDs follow the revision-15
section numbers.

## Scope

### Wire format

Type 246 (Reflected IPv6 Extension Header) carries an eight-octet Requested
field followed by a Reflected field of Length − 8 octets. Type 247 (Reflected
Fixed Header) carries a four-octet Requested field followed by Length − 4
octets. The request's Length equals the size of the header it selects.

On a match the reflector copies the whole header into the TLV value
(`copy_reflected` in `src/tlv/list/processing.rs`). A nonzero Requested field
already equals the header's first octets and is unchanged. An all-zero
Requested field selects the first unconsumed header of matching length and is
filled with that header's first eight (Type 246) or four (Type 247) octets. An
eight-octet header has no Reflected tail, so a successful reply to an
all-zero eight-octet request carries the header in its Requested field.

### Interoperability

This is an Internet-Draft. Types 246 and 247 and the Type 12 sub-TLV 240
(IPv6 Extension Header Control) are local experimental codepoints (see the
[experimental codepoints](README.md#experimental-codepoints) table); no IANA
allocation is claimed. Both endpoints must implement this revision. Peers
built for revisions before 13 use a four-octet Type 246 Requested field and do
not interoperate. There is no version negotiation, and selectors are not
reconstructed from replies.

### Backend support

| Capability | nix backend, Linux | nix backend, macOS | pnet backend |
|---|---|---|---|
| Type 246 reflection | Hop-by-Hop, Destination Options and Routing headers from ancillary data | C flag | All extension headers from raw capture |
| Type 247 reflection | C flag | C flag | IPv4 and IPv6 fixed headers, including nested ones |
| Reverse-path header attachment (sub-TLV 240) | C flag | C flag | C flag |

The nix backend reads ancillary data in
`src/receiver/nix.rs::extract_ipv6_ext_headers`. It never sees Fragment
headers, because the kernel removes them during reassembly, and truncated
ancillary data yields no headers (the request gets C). Raw capture in
`src/receiver/pnet.rs::checked_udp` validates IP framing and the UDP checksum
of the innermost IP endpoints before STAMP admission.

### Checksums and capture

Kernel UDP sockets generate and verify checksums. The application never
enables IPv6 zero-checksum operation (RFC 6936). Raw capture rejects
truncated, fragmented, corrupt and zero-checksum datagrams, so successful raw
reflection needs a capture point that sees complete wire checksums. Frames with
incomplete checksums from TX checksum offload (local loopback traffic, for
example) are rejected, never treated as verified measurements. The private
veth tests disable TX checksum offload; the loopback tests inject complete
checksums and also check that corrupt packets are rejected.

### Sender requirements

`--attach-ext-hdr` attaches one Hop-by-Hop and one Destination Options header
to IPv6 probes on Linux. Header requests (`--attach-ext-hdr`,
`--reflected-ipv6-ext-hdr`, `--reflected-fixed-hdr`) need a known egress route
MTU, which the sender reads only on Linux (`egress_mtu` in
`src/sender/socket.rs`); on other platforms the sender refuses to start with
them. Sender source ports are random dynamic ports by default, and
explicit local and remote ports must differ. Both endpoints send with TTL/Hop
Limit 255.

### Deployment assumptions

Operators provision both endpoints and Session-IDs, provide processing capacity
for the offered load, and deploy within the draft's single administrative
domain. Queue, session and burst caps can suppress replies under overload;
correlate those counters with session-state notifications before attributing
loss to the network. IOAM processing is not implemented.

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ext-hdr-3.1-1 | Choose randomized source UDP ports. | SHOULD | Sender | Compliant | `src/net_policy.rs::bind_sender` draws ports from the OS CSPRNG with bounded collision retries (including Windows WSAEACCES). Explicit local ports are an operator override. |
| ext-hdr-3.1-2 | Prefer source ports in 49152–65535. | SHOULD | Sender | Compliant | `src/net_policy.rs::bind_sender` binds in the dynamic range by default. Reflector replies use the provisioned listening port, as UDP reply demultiplexing requires. |
| ext-hdr-3.1-3 | Source ports distinguish replies from reverse-direction requests. | MUST | Both | Compliant | Sender local and remote ports must differ; reflectors reply from their listening port; connected sender sockets filter the peer tuple. `tests/ext_hdr_revision13_test.rs::sender_random_ports_hops_and_state_notifications_over_both_families`. |
| ext-hdr-3.1-4 | Set outgoing IPv4 TTL and IPv6 Hop Limit to 255. | MUST | Both | Compliant | `src/net_policy.rs::set_hops` runs before sending in both reflector backends and the sender; failure aborts startup. CLI and TOML reject other TTL values. Independent IPv4/IPv6 wire tests check 255. |
| ext-hdr-3.1-5 | Do not reject requests solely because the received TTL/Hop Limit is below 255. | MUST NOT | Both | Compliant | No hop-count admission filter exists. `tests/ext_hdr_revision13_test.rs::reflector_transmits_255_and_accepts_lower_received_hops` sends 37; raw-capture checksum tests accept 254. |
| ext-hdr-4.1-A | Packets may contain multiple Type 246 TLVs. | MAY | Both | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`, `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [request construction](#request-construction). |
| ext-hdr-4.1-B | The eight-octet Requested field selects the matching extension header. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. |
| ext-hdr-4.1-C | An all-zero Requested field selects the first matching-length extension header, and the reflector fills Requested with its first eight octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [header matching](#header-matching). |
| ext-hdr-4.1-D | Initialize the Reflected field to zero in requests. | MUST | Sender | Compliant | `src/tlv/typed/reflected_ipv6_ext_hdr.rs::ReflectedIpv6ExtHdrTlv::request_with_selector` writes only the eight-octet selector and zero-fills the rest. The CLI rejects selectors longer than eight octets. |
| ext-hdr-4.1-E | Return C when a recognized extension-header request cannot be fulfilled. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::reflected_ipv6_ext_hdr_selector_no_match_sets_c_flag_end_to_end`. Missing capture, length mismatch and unmatched selectors keep the value and set C. See [backend support](#backend-support). |
| ext-hdr-4.2-1 | Add a matching Type 246 request for each attached extension header whose reflection is required. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Request Length equals the attached header size; attachment failure aborts startup. |
| ext-hdr-4.2-2 | Order multiple Type 246 requests with their corresponding extension headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The sender attaches at most one Hop-by-Hop header followed by one Destination Options header. |
| ext-hdr-4.2-3 | Omit requests for headers whose reflection is not required. | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Explicit requests can select a subset; a same-length subset needs matching selectors. |
| ext-hdr-4.2-4 | Do not originate more Type 246 requests than extension headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Unattached requests and duplicate attachment kinds are rejected. |
| ext-hdr-4.2-5 | Reflect the extension-header bytes after its first eight octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [wire format](#wire-format). |
| ext-hdr-4.2-6 | Process received extension headers in outer-to-inner order. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [header matching](#header-matching). |
| ext-hdr-4.2-7 | Use the first eight on-wire octets as the selector when a same-length subset is ambiguous. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The kernel-assigned Next Header octet is derived from the attached header chain; selector bytes must match the attached header. |
| ext-hdr-4.2-8 | Match all eight nonzero Requested octets before reflection. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled` (headers that differ only in octets 4–7). |
| ext-hdr-4.2-9 | Keep the entire resulting packet within the IPv6 MTU. | MUST | Both | Compliant | `src/receiver/mtu.rs`, `src/receiver/transmit.rs::fit_reply`. See [MTU budget](#mtu-budget). |
| ext-hdr-4.2-10 | Remove optional reflected extension-header TLVs when needed for the MTU. | MUST | Both | Compliant | `src/receiver/mtu.rs`, `src/receiver/transmit.rs::fit_reply`. See [MTU budget](#mtu-budget). |
| ext-hdr-4.3-1 | The reflector's data plane provides received IPv6 extension headers to the reflector. | MUST | Reflector | Partial | `src/receiver/pnet.rs::checked_udp`, `src/receiver/nix.rs::extract_ipv6_ext_headers`, `tests/netns_conformance.rs::scenario_4a_ext_hdr_nix_ancillary`. The nix backend on macOS and on Fragment headers cannot supply them. See [backend support](#backend-support). |
| ext-hdr-4.3-2 | The sender's data plane provides reply extension headers to the sender for bidirectional measurement. | MUST | Sender | N-A | Bidirectional measurement is not supported (ext-hdr-5.2-1). |
| ext-hdr-5-1 | One-way measurement may omit matching reverse-path extension headers. | MAY | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Reverse-header attachment is not implemented; Type 246 reflection is independent of it. |
| ext-hdr-5.2-1 | Add matching reverse-path extension headers when requested, or use the specified cannot-add fallback. | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Both backends use the fallback: C in the control sub-TLV. See [control sub-TLV](#control-sub-tlv). |
| ext-hdr-5.2-2 | Without the control sub-TLV, reverse-header attachment may be omitted. | MAY | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. |
| ext-hdr-5.2-3 | Reflect received header data regardless of the reverse-header control sub-TLV. | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Type 246 processing runs independently of the sub-TLV. |
| ext-hdr-5.2-4 | Signal inability to add matching reverse headers with C in the control sub-TLV. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::reflected_control_single_ext_hdr_control_sets_c_on_subtlv`. |
| ext-hdr-5.2-5 | Do not originate duplicate extension-header control sub-TLVs in one Type 12 TLV. | MUST NOT | Sender | Compliant | `src/sender/packet.rs::build_reflected_control_tlv` adds the sub-TLV at most once. |
| ext-hdr-5.2-6 | Set C on every duplicated extension-header control sub-TLV. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::reflected_control_duplicate_ext_hdr_control_sets_c_on_all_copies`. |
| ext-hdr-6.1-A | Packets may contain multiple Type 247 TLVs. | MAY | Both | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, with multi-candidate fixed-header unit tests. The sender originates one; the pnet reflector handles several. |
| ext-hdr-6.1-B | The four-octet Requested field selects the matching fixed header. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, with fixed-header selector unit tests. |
| ext-hdr-6.1-C | An all-zero Requested field selects the first matching-length IP header, and the reflector fills Requested with its first four octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. Matching consumes candidates in wire order. See [header matching](#header-matching). |
| ext-hdr-6.1-D | Initialize the fixed-header Reflected field to zero in requests. | MUST | Sender | Compliant | `src/tlv/typed/reflected_fixed_hdr.rs::ReflectedFixedHdrTlv::request_with_selector`. The CLI limits the selector to four octets. |
| ext-hdr-6.1-E | Return C when fixed-header reflection cannot be fulfilled. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. Missing capture, length mismatch and selector mismatch each set C and keep the value. The nix backend always returns C for Type 247. |
| ext-hdr-6.2-1 | Add multiple fixed-header requests in corresponding header order. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The sender originates one IP header and allows at most one Type 247 request. |
| ext-hdr-6.2-2 | Omit fixed-header requests when reflection is not requested. | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Type 247 is opt-in. |
| ext-hdr-6.2-3 | Do not originate more fixed-header requests than IP headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. At most one request for the one originated IP header. |
| ext-hdr-6.2-4 | Copy the fixed-header portion after the four-octet Requested field. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. See [wire format](#wire-format). |
| ext-hdr-6.2-5 | Process encapsulated fixed headers in outer-to-inner order. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `src/receiver/pnet.rs::checked_udp` (captures nested IP headers in order and rejects excessive nesting). |
| ext-hdr-6.2-6 | Use a four-octet selector for ambiguous same-length fixed headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The CLI accepts up to four selector octets and zero-pads the rest. |
| ext-hdr-6.2-7 | Match a nonzero Requested fixed-header field before copying. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, with fixed-header selector unit tests. |
| ext-hdr-6.2-8 | Keep the resulting packet within the IP MTU. | MUST | Both | Compliant | `src/receiver/mtu.rs`, `src/receiver/transmit.rs::fit_reply`. See [MTU budget](#mtu-budget). |
| ext-hdr-6.2-9 | Remove optional fixed-header TLVs as necessary for the MTU. | MUST | Both | Compliant | `src/receiver/mtu.rs`, `src/receiver/transmit.rs::fit_reply`. See [MTU budget](#mtu-budget). |
| ext-hdr-6.3-1 | Place Type 247 TLVs before Type 246 TLVs. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs` emits fixed-header requests first. |
| ext-hdr-6.3-2 | Return out-of-order reflected-header TLVs with C set. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_headers` checks the global order before copying. Combined-header wire and unit tests cover both orders. |
| ext-hdr-7-1 | IOAM DEX may omit a Type 246 reflection request. | MAY | Sender | Compliant | Reflection requests are opt-in. No IOAM processor or DEX exporter is implemented. |
| ext-hdr-8.1-1 | Enable IPv4 UDP checksums by default. | MUST | Both | Compliant | Kernel UDP sockets generate checksums and no option disables them. Raw capture rejects missing or invalid UDP checksums. |
| ext-hdr-8.2-1 | An IPv6 zero-checksum implementation follows RFC 6936/RFC 8085 with the stated deviation. | MUST | Both | N-A | IPv6 zero-checksum mode is not implemented; the application never sets UDP_NO_CHECK6 options. |
| ext-hdr-8.2-2 | Unauthenticated IPv6 zero-checksum sessions obey the listed operational constraints. | MUST | Both | N-A | IPv6 zero-checksum mode is not implemented. |
| ext-hdr-8.2-3 | Use authenticated packets where integrity is required. | RECOMMENDED | Both | Compliant | Authenticated STAMP and TLV HMAC modes are available and recommended in the deployment guide. |
| ext-hdr-8.2-4 | Zero-checksum middleboxes follow the referenced RFC 6936 requirements. | MUST | N-A | N-A | External middlebox requirement, conditional on a mode that is not implemented. |
| ext-hdr-8.2-5 | Enable IPv6 UDP checksums by default. | MUST | Both | Compliant | Kernel UDP sockets generate checksums; raw capture verifies them before STAMP admission. |
| ext-hdr-8.2-6 | Verify nonzero UDP checksums; discard failures and exclude them from measurements. | MUST / MUST NOT | Both | Compliant | Kernel UDP receive validates checksums. `src/receiver/pnet.rs::checked_udp` validates framing, fragments and the innermost pseudo-header checksum before `handle_stamp_packet`. See [checksums and capture](#checksums-and-capture). |
| ext-hdr-8.2-7 | Permit IPv6 zero-checksum only on explicitly enabled STAMP ports and validate both endpoint addresses. | MUST | Both | Compliant | No port enables zero-checksum operation; raw capture rejects zero and invalid checksums. |
| ext-hdr-8.2-8 | Zero-checksum sessions assume no correctness of received data and tolerate corruption. | MUST / MUST NOT | Both | N-A | IPv6 zero-checksum mode is not implemented. |
| ext-hdr-9-1 | Allow the measurement type to be provisioned as unidirectional or bidirectional. | MUST | Both | Partial | Unidirectional measurement is supported. A bidirectional request (control sub-TLV 240) is answered with C because reply-header attachment is not implemented. |
| ext-hdr-9-2 | An operator may suppress header reflection to avoid information disclosure. | MAY | Reflector | N-A | No header-disclosure switch is implemented; this optional control is not claimed. |
| ext-hdr-9.2-1 | Notify idle when the sender stops transmitting. | SHOULD | Sender | Compliant | `src/sender/session_state.rs::Monitor`. See [session state](#session-state). |
| ext-hdr-9.2-2 | Notify active after a validated reply while transmitting. | SHOULD | Sender | Compliant | `src/sender/session_state.rs::Monitor`. See [session state](#session-state). |
| ext-hdr-9.2-3 | Notify failed after the configured consecutive-loss threshold following activation. | SHOULD | Sender | Compliant | `src/sender/session_state.rs::Monitor`, `--session-loss-threshold`. See [session state](#session-state). |
| ext-hdr-9.2-4 | Notify recovery to active after a reply resumes while transmitting. | SHOULD | Sender | Compliant | `src/sender/session_state.rs::Monitor`. See [session state](#session-state). |
| ext-hdr-9.3-1 | Do not police incoming test traffic more tightly than its transmit rate. | MUST NOT | Both | Compliant | No per-source ingress rate policer exists by default. Queue, session and burst caps bound resource use; see [deployment assumptions](#deployment-assumptions). |
| ext-hdr-10-1 | Do not assign Session-IDs predictably. | MUST NOT | Sender | N-A | The application does not allocate Session-IDs. Nonzero values are provisioned by the operator; an unset SSID is the RFC 8972 zero value. |

## Notes

### Request construction

`src/configuration.rs::Configuration::validate_ext_hdr_flags` checks selector
widths, attachment lengths and order, and the number of requests at startup.
`src/sender/packet.rs::reflected_header_request_tlvs` builds the requests.
Explicit `--reflected-ipv6-ext-hdr` requests replace the automatic requests
that `--attach-ext-hdr` adds and select a subset of the attached headers.

### Header matching

`src/tlv/list/processing.rs::apply_reflected_header` pairs each request with
the first unconsumed captured header of the same length whose first octets
match a nonzero selector (any header for an all-zero selector). Headers are
captured in wire order, so successive requests pair outer to inner. A failed
match consumes nothing and sets C. The regression
`revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`
(`tests/tlv_flag_semantics.rs`) builds raw bytes independently of the encoder.

### MTU budget

The sender rechecks the connected route MTU before each normal send and each
Access Report retry, removes optional Type 246/247 TLVs to fit, and refuses an
oversized mandatory packet. On Linux it sets Don't Fragment, so a route change
cannot fragment a probe. The reflector sizes each reply against the actual
destination route before signing (`src/receiver/mtu.rs`,
`src/receiver/transmit.rs::fit_reply`); an unknown budget fails closed. Header
requests need a known route MTU, which only Linux provides. That limits where
the feature runs; it never permits an oversized packet.

### Control sub-TLV

`src/receiver/mod.rs::apply_semantic_tlv_processing` calls
`src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, which sets C on
every IPv6 Extension Header Control sub-TLV in Type 12. This is the draft's
cannot-add response (§5.2 rule 4), used on both backends because reply-header
attachment is not implemented. Duplicate sub-TLVs all get C.

### Session state

`src/sender/session_state.rs::Monitor` runs after authentication, session and
duplicate admission in `Measurements`. Structured logs and the
`measurements.session_state` report field show idle, active and failed
transitions. Each probe has a `--timeout` deadline; `--session-loss-threshold`
(default 3) consecutive unanswered probes mark an active session failed, and a
validated reply recovers it. Invalid-session and duplicate replies do not
drive recovery. Independent IPv4/IPv6 wire and state tests cover failure,
recovery and invalid-session replies.

## Coverage

The table lists the draft's uppercase normative clauses, with the §9.2 SHOULD
expanded into its four state outcomes. Figures 6 and 7 are covered by the
field width and length rows. Keyword boilerplate, topology examples, IOAM
descriptions, implementation-status text and IANA procedures add no runtime
requirement. The zero-checksum subconditions (port scoping, controlled
domain, payload integrity, middleboxes, corruption) do not apply because that
mode is not implemented. Requirements of referenced RFCs are covered by their
own matrices.

See the [namespace tests](../testing-netns.md), [measurement
semantics](../measurements.md) and [release verification](../release-evidence.md).
