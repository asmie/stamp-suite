# draft-ietf-ippm-stamp-ext-hdr conformance

Fixed IP and IPv6 extension header reflection (Types 247/246): requirements,
implementation, tests and backend limits.

Revision frozen: draft-ietf-ippm-stamp-ext-hdr-25, 22 October 2026.
Source: [draft-ietf-ippm-stamp-ext-hdr-25](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-ext-hdr-25.txt).

Summary: 71 clauses: 62 Compliant, 6 Partial, 0 Gap, 3 N-A, 0 Excluded.

The Clause column paraphrases the draft. Existing row IDs remain stable where
possible; moved ordering and MTU clauses use their revision-25 section numbers.

## Scope

### Wire format

Type 246 (Reflected IPv6 Extension Header) carries an eight-octet Requested
field followed by a Received field of Length − 8 octets. Type 247 (Reflected
Fixed Header) carries a four-octet Requested field followed by Length − 4
octets. The request's Length equals the size of the header it selects.

The reflector compares only nonzero Requested octets; each zero octet is a
wildcard. A nonzero selector must identify exactly one unmatched header of
the requested length and is returned unchanged. Ambiguous selectors return C
without copying or consuming a header. An all-zero Requested field selects
the first unconsumed header of matching length and is filled with that header's
first eight (Type 246) or four (Type 247) octets. The remaining bytes are copied
into the Received field (`copy_reflected` in `src/tlv/list/processing.rs`). An
eight-octet header has no Received tail, so a successful reply to an
all-zero eight-octet request carries the header in its Requested field.

### Interoperability

This is an Internet-Draft. Types 246 and 247 and the Type 12 sub-TLV 240
(IPv6 Extension Header Control) are local experimental codepoints (see the
[experimental codepoints](README.md#experimental-codepoints) table); no IANA
allocation is claimed. Both endpoints must implement this revision. Peers
built for revisions before 13 use a four-octet Type 246 Requested field and do
not interoperate. There is no version negotiation, and selectors are not
reconstructed from replies.

### Local reflection policy

Header reflection is denied by default. `--reflect-fixed-header-from IP` and
`--reflect-ipv6-ext-header-from IP` separately authorize fixed and extension
header data for explicitly provisioned sender IPs; repeat each flag for more
senders. TOML uses `reflect_fixed_header_from` and
`reflect_ipv6_ext_header_from` arrays. The common ingest path evaluates the
original source IP before either backend copies data. IPv4-mapped addresses
are compared as IPv4. A policy refusal preserves the request value and sets C.
An enabled UDP endpoint or Type 12 support alone does not grant permission.

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
domain. Operators configure aggregate rate and burst limits in both directions,
including encapsulation and concurrent sessions, and filter traffic at domain
boundaries. Sender `--send-delay` paces probes; Type 12 rate, volume and interval
caps bound reflected bursts. Queue, session and burst caps can suppress replies
under overload; correlate those counters with session-state notifications before attributing
loss to the network. IOAM processing is not implemented.

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ext-hdr-3.1-1 | Choose randomized source UDP ports. | Descriptive | Sender | Compliant | `src/net_policy.rs::bind_sender` draws ports from the OS CSPRNG with bounded collision retries. Explicit local ports are an operator override; revision 25 uses lowercase should. |
| ext-hdr-3.1-2 | Prefer source ports in 49152–65535. | SHOULD | Sender | Compliant | `src/net_policy.rs::bind_sender` binds in the dynamic range by default. Reflector replies use the provisioned listening port, as UDP reply demultiplexing requires. |
| ext-hdr-3.1-3 | The sender source port must differ from the local reflector port. | MUST NOT | Sender | Compliant | Sender and reflector roles use separate sockets; an occupied local reflector port cannot be bound by the sender. `src/net_policy.rs::bind_sender` also excludes the remote reflector port. |
| ext-hdr-3.1-4 | Set outgoing IPv4 TTL and IPv6 Hop Limit to 255. | MUST | Both | Compliant | `src/net_policy.rs::set_hops` runs before sending in both reflector backends and the sender; failure aborts startup. CLI and TOML reject other TTL values. Independent IPv4/IPv6 wire tests check 255. |
| ext-hdr-4.1-A | Packets may contain multiple Type 246 TLVs. | MAY | Both | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`, `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [request construction](#request-construction). |
| ext-hdr-4.1-B | Select extension headers by nonzero Requested octets; zero octets are wildcards. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-4.1-C | An all-zero Requested field selects the first matching-length extension header, and the reflector fills Requested with its first eight octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [header matching](#header-matching). |
| ext-hdr-4.1-D | Initialize the Received field to zero in requests. | MUST | Sender | Compliant | `src/tlv/typed/reflected_ipv6_ext_hdr.rs::ReflectedIpv6ExtHdrTlv::request_with_selector` writes only the eight-octet selector and zero-fills the rest. The CLI rejects selectors longer than eight octets. |
| ext-hdr-4.1-E | Return C without copying data when extension-header reflection cannot be fulfilled, including ambiguous selection. | MUST / MUST NOT | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. No match, multiple matches, unsupported capture and invalid length preserve the request. |
| ext-hdr-4.2-1 | Add a matching Type 246 request for each attached extension header whose reflection is required. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Request Length equals the attached header size; attachment failure aborts startup. |
| ext-hdr-4.2-2 | Order multiple Type 246 requests with their corresponding extension headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The sender attaches at most one Hop-by-Hop header followed by one Destination Options header. |
| ext-hdr-4.2-3 | Omit requests for headers whose reflection is not required. | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Explicit requests can select a subset; a same-length subset needs matching selectors. |
| ext-hdr-4.2-4 | Do not originate more Type 246 requests than extension headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Unattached requests and duplicate attachment kinds are rejected. |
| ext-hdr-4.2-5 | Reflect the extension-header bytes after its first eight octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [wire format](#wire-format). |
| ext-hdr-4.2-6 | Process received extension headers in outer-to-inner order. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [header matching](#header-matching). |
| ext-hdr-4.2-7 | Use the first eight on-wire octets as the selector when a same-length subset is ambiguous. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The kernel-assigned Next Header octet is derived from the attached header chain; selector bytes must match the attached header. |
| ext-hdr-4.2-8 | Match each nonzero Requested octet exactly, and select only a unique unmatched header. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. An ambiguous request consumes no header. |
| ext-hdr-4.3-1 | The reflector's data plane provides received IPv6 extension headers to the reflector. | MUST | Reflector | Partial | `src/receiver/pnet.rs::checked_udp`, `src/receiver/nix.rs::extract_ipv6_ext_headers`, `tests/netns_conformance.rs::scenario_4a_ext_hdr_nix_ancillary`. The nix backend on macOS and on Fragment headers cannot supply them. See [backend support](#backend-support). |
| ext-hdr-4.3-2 | The sender's data plane provides reply extension headers to the sender for bidirectional measurement. | MUST | Sender | N-A | Bidirectional measurement is not supported (ext-hdr-5.2-1). |
| ext-hdr-5-1 | In unidirectional mode omit matching reverse-path headers in response to received headers. | MUST | Reflector | Compliant | Neither backend adds matching reverse-path headers. Independent SRv6 Return Path requests remain separate. |
| ext-hdr-5.2-1 | Add matching reverse-path extension headers when requested, or use the specified cannot-add fallback. | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Both backends use the fallback: C in the control sub-TLV. See [control sub-TLV](#control-sub-tlv). |
| ext-hdr-5.2-2 | Without the control sub-TLV omit matching reverse-path headers. | MUST | Reflector | Compliant | Neither backend adds matching reverse-path extension headers. |
| ext-hdr-5.2-3 | Reflect received header data regardless of the reverse-header control sub-TLV. | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Type 246 processing runs independently of the sub-TLV. |
| ext-hdr-5.2-4 | Signal inability to add matching reverse headers with C in the control sub-TLV. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::reflected_control_single_ext_hdr_control_sets_c_on_subtlv`. |
| ext-hdr-5.2-5 | Do not originate duplicate extension-header control sub-TLVs in one Type 12 TLV. | MUST NOT | Sender | Compliant | `src/sender/packet.rs::build_reflected_control_tlv` adds the sub-TLV at most once. |
| ext-hdr-5.2-6 | Set C on every duplicated extension-header control sub-TLV. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::reflected_control_duplicate_ext_hdr_control_sets_c_on_all_copies`. |
| ext-hdr-6.1-A | Packets may contain multiple Type 247 TLVs. | MAY | Both | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, with multi-candidate fixed-header unit tests. The sender originates one; the pnet reflector handles several. |
| ext-hdr-6.1-B | Select fixed headers by nonzero Requested octets; zero octets are wildcards. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-6.1-C | An all-zero Requested field selects the first matching-length IP header, and the reflector fills Requested with its first four octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. Matching consumes candidates in wire order. See [header matching](#header-matching). |
| ext-hdr-6.1-D | Initialize the fixed-header Received field to zero in requests. | MUST | Sender | Compliant | `src/tlv/typed/reflected_fixed_hdr.rs::ReflectedFixedHdrTlv::request_with_selector`. The CLI limits the selector to four octets. |
| ext-hdr-6.1-E | Return C without copying data when fixed-header reflection cannot be fulfilled, including ambiguous selection. | MUST / MUST NOT | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-6.2-1 | Add multiple fixed-header requests in corresponding header order. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The sender originates one IP header and allows at most one Type 247 request. |
| ext-hdr-6.2-2 | Omit fixed-header requests when reflection is not requested. | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Type 247 is opt-in. |
| ext-hdr-6.2-3 | Do not originate more fixed-header requests than IP headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. At most one request for the one originated IP header. |
| ext-hdr-6.2-4 | Copy the fixed-header portion after the four-octet Requested field. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. See [wire format](#wire-format). |
| ext-hdr-6.2-5 | Process encapsulated fixed headers in outer-to-inner order. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `src/receiver/pnet.rs::checked_udp` (captures nested IP headers in order and rejects excessive nesting). |
| ext-hdr-6.2-6 | Use a four-octet selector for ambiguous same-length fixed headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The CLI accepts up to four selector octets and zero-pads the rest. |
| ext-hdr-6.2-7 | Match each nonzero Requested fixed-header octet exactly, and select only a unique unmatched header. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-7.1-1 | Place Type 247 TLVs before Type 246 TLVs. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs` emits fixed-header requests first. |
| ext-hdr-7.1-2 | Return out-of-order reflected-header TLVs with C set. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_headers` checks the global order before copying. Combined-header wire and unit tests cover both orders. |
| ext-hdr-7-1 | Omit Type 246 reflection requests for IOAM Direct Exporting. | MUST | Sender | N-A | No IOAM DEX processor or exporter is implemented. Arbitrary operator-supplied IPv6 options are outside an IOAM implementation claim. |
| ext-hdr-9-1 | Allow the measurement type to be provisioned as unidirectional or bidirectional. | MUST | Both | Partial | Unidirectional measurement is supported. A bidirectional request (control sub-TLV 240) is answered with C because reply-header attachment is not implemented. |
| ext-hdr-9-2 | Provide a configurable reflector policy identifying permitted senders and header data. | MUST | Reflector | Compliant | `src/receiver/ingest.rs::ProcessingContext::for_packet`, `src/configuration.rs::Configuration`. Separate source-IP allowlists for Types 246 and 247 default to deny; see [local reflection policy](#local-reflection-policy). |
| ext-hdr-9.2-1 | Report idle when the sender stops transmitting. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`; deadline and state regression tests. |
| ext-hdr-9.2-2 | Report active after a validated reply while transmitting. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`; admission precedes state changes. |
| ext-hdr-9.2-3 | Report failed after the configured consecutive-loss threshold following activation. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`, `--session-loss-threshold`. |
| ext-hdr-9.2-4 | Recover from failed to active after a validated reply while transmitting. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`. |
| ext-hdr-9.3-1 | Provision receive policing to accommodate aggregate transmitted traffic and bursts. | MUST NOT | Both | Compliant | Ingress limiting is disabled by default. `--max-pps`, `--reflector-rate-burst`, queue, session and Type 12 caps are operator-provisioned; see [deployment assumptions](#deployment-assumptions). |
| ext-hdr-10-1 | Do not assign Session-IDs predictably. | MUST NOT | Sender | N-A | The application does not allocate Session-IDs. Nonzero values are provisioned by the operator; an unset SSID is the RFC 8972 zero value. |

| ext-hdr-4.1-type | Use the assigned Type for the extension-header TLV. | MUST | Both | Partial | `src/tlv/experimental.rs::REFLECTED_IPV6_EXT_HDR_TLV_TYPE` uses experimental 246 pending IANA allocation. |
| ext-hdr-4.2-mutable | Zero every Requested octet containing mutable option data; never depend on matching a zero-valued octet. | MUST / MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags` checks attached Hop-by-Hop and Destination Options header selectors, wildcard uniqueness and option change-en-route bits. The sender does not originate Routing headers. |
| ext-hdr-4.2-policy | Explicitly request extension-header data; enforce reflector policy before copying and return C on refusal. | MUST / MUST NOT | Both | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/receiver/ingest.rs::ProcessingContext::for_packet`, `src/tlv/list/processing.rs::process_reflected_headers_with_policy`. |
| ext-hdr-5.1-type | Use the assigned Type for the extension-header control sub-TLV. | MUST | Both | Partial | `src/tlv/experimental.rs::REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` uses experimental 240 pending IANA allocation. |
| ext-hdr-5.1-length | Set control sub-TLV length to zero; reflect nonzero lengths with M. | MUST | Both | Compliant | `src/sender/packet.rs::build_reflected_control_tlv`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::revision25_control_sub_tlv_nonzero_length_is_malformed`. |
| ext-hdr-5.1-shape | When Type 12 only carries the extension-header control sub-TLV, request one packet with interval and length zero. | MUST | Sender | Compliant | `src/sender/packet.rs::build_reflected_control_tlv`; default count=1, length=0, interval=0. Explicit asymmetric traffic settings additionally request reply shaping. |
| ext-hdr-6.1-type | Use the assigned Type for the fixed-header TLV. | MUST | Both | Partial | `src/tlv/experimental.rs::REFLECTED_FIXED_HDR_TLV_TYPE` uses experimental 247 pending IANA allocation. |
| ext-hdr-6.2-request | Add a fixed-header TLV for each header requested for reflection. | MUST | Sender | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`; the sender originates one fixed IP header. |
| ext-hdr-6.2-mutable | Zero every Requested octet containing mutable DSCP/ECN bits; never depend on matching a zero-valued octet. | MUST / MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/configuration/tests.rs::revision25_fixed_selector_masks_mutable_octets`. IPv4 byte 1 and IPv6 bytes 0 and 1 must be zero. |
| ext-hdr-6.2-policy | Explicitly request fixed-header data; enforce reflector policy before copying and return C on refusal. | MUST / MUST NOT | Both | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`, `src/receiver/ingest.rs::ProcessingContext::for_packet`, `src/tlv/list/processing.rs::process_reflected_headers_with_policy`. |
| ext-hdr-7.2-1 | Keep the complete transmitted packet within the applicable path MTU. | MUST | Both | Compliant | `src/sender/packet.rs::enforce_egress_mtu`, `src/receiver/transmit.rs::fit_reply`; see [MTU budget](#mtu-budget). |
| ext-hdr-7.2-2 | Remove complete reflected-header TLVs from the end, skipping HMAC, until the packet fits. | MUST | Both | Compliant | `src/sender/packet.rs::enforce_egress_mtu`, `src/tlv/list/processing.rs::trim_reflected_headers_to_size`; each uses the last header TLV. |
| ext-hdr-7.2-3 | Update the HMAC digest if a preceding TLV was removed. | MUST | Both | Compliant | `src/receiver/transmit.rs::fit_reply`, `src/receiver/transmit.rs::Transmission`; the send path trims before signing each copy. Sender builds and signs after trimming. |
| ext-hdr-7.2-4 | Retain the relative order of remaining TLVs, including returned requests. | MUST | Both | Compliant | `src/tlv/list/mod.rs::remove_non_hmac` repairs wire indices; sender removes one vector entry at a time. |
| ext-hdr-7.2-5 | Do not transmit when removing all optional header TLVs cannot satisfy the MTU. | MUST NOT | Both | Compliant | `src/sender/run.rs`, `src/receiver/transmit.rs::fit_reply`; oversized mandatory packets are refused. |
| ext-hdr-9-errors | Log each C error condition locally and increment its condition counter. | SHOULD | Reflector | Partial | Header match and policy failures log their reasons; Type 12 rejections are logged. Separate counters for every C error condition are not implemented. |
| ext-hdr-9.2-0 | Optionally generate session state-change notifications. | MAY | Sender | Compliant | `src/sender/session_state.rs::Monitor` exposes structured logs and report summaries. |
| ext-hdr-9.2-5 | Report failed after N consecutive losses even before the first reply. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::tests::failure_before_first_reply_and_recovery`. |
| ext-hdr-9.3-2 | Provide configurable transmission rate and burst limits. | SHOULD | Both | Compliant | `--send-delay` and finite probe count bound sender traffic; Type 12 interval, rate, count and volume caps bound reflected bursts. |
| ext-hdr-9.3-3 | Pace packet transmissions to avoid excessive bursts. | SHOULD | Both | Compliant | Sender scheduling and `src/receiver/transmit.rs::Transmission` pace each reply copy. Operators can explicitly request zero-delay test traffic. |
| ext-hdr-9.3-4 | Allow overload drops or suppressed responses for resource protection. | MAY | Both | Compliant | `src/receiver/ingest.rs::ReflectorCore::ingest`, `src/receiver/transmit.rs`; queue, session and burst limits. |
| ext-hdr-9.3-5 | Expose local limiting counters or notifications so operators can distinguish local suppression from network loss. | SHOULD | Reflector | Compliant | `src/receiver/limits.rs::ReflectorCounters` separates rate-limited, queue-rejected and cancelled work; control and SNMP expose reflector counters. |

## Notes

### Request construction

`src/configuration.rs::Configuration::validate_ext_hdr_flags` checks selector
widths, attachment lengths and order, and the number of requests at startup.
`src/sender/packet.rs::reflected_header_request_tlvs` builds the requests.
Explicit `--reflected-ipv6-ext-hdr` requests replace the automatic requests
that `--attach-ext-hdr` adds and select a subset of the attached headers.

### Header matching

`src/tlv/list/processing.rs::apply_reflected_header` pairs each request with
a unique unconsumed captured header of the same length matching each nonzero
selector octet. Zero octets are wildcards. An all-zero selector selects the
first unconsumed header of matching length. Headers are
captured in wire order, so successive requests pair outer to inner. A missing or ambiguous match consumes nothing and sets C. Nonzero Requested
fields remain unchanged; all-zero Requested fields are filled from capture. The regression
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
cannot-add response (§5.1 rule 4), used on both backends because reply-header
attachment is not implemented. Duplicate sub-TLVs all get C.

### Session state

`src/sender/session_state.rs::Monitor` runs after authentication, session and
duplicate admission in `Measurements`. Structured logs and the
`measurements.session_state` report field show idle, active and failed
transitions. Each probe has a `--timeout` deadline; `--session-loss-threshold`
(default 3) consecutive unanswered probes mark a transmitting session failed,
including before its first valid reply. A validated reply activates or recovers
it. Invalid-session and duplicate replies do not
drive recovery. Independent IPv4/IPv6 wire and state tests cover failure,
recovery and invalid-session replies.

## Coverage

The table lists the draft's uppercase normative clauses and structural field
requirements, with the §9.2 MAY expanded into its five descriptive state outcomes.
Stable clause IDs are retained where possible; control procedure rows reference
§5.1 in revision 25, and the combined-header ordering rows now reference §7.1.
Figures 6 and 7 are covered by the field width and length rows. Keyword boilerplate, topology examples, IOAM
descriptions, implementation-status text and IANA procedures add no runtime
requirement. Revision 25 removes revision 15's zero-checksum section. Checksums
remain enabled and validated; the application does not implement zero-checksum
mode. Requirements of referenced RFCs are covered by their own matrices.

See the [namespace tests](../testing-netns.md), [measurement
semantics](../measurements.md) and [release verification](../release-evidence.md).

## Revision 25 review (2026-10-26)

Compared the complete revision 15 and 25 texts from the IETF archive. The
review covered changes through revision 25, including wildcard selectors and
ambiguity rejection, mutable-octet masking, explicit sender configuration and
reflector disclosure policy, control sub-TLV length validation, initial session
failure, and the expanded rate/burst and overload guidance. MTU and mixed-header
ordering requirements moved to §§7.1–7.2. Trimming still precedes signing;
`src/receiver/transmit/tests.rs::reflected_headers_are_trimmed_before_ber_padding`
now covers the mixed BER/header case, which removes header TLVs before BER
padding and refuses a packet whose remaining mandatory fields cannot fit. The zero-checksum section was removed. IANA values
remain TBA1/TBA2/TBA3, so the local experimental allocations are retained and
scored Partial. Reverse-path attachment and backend capture limits remain as
stated above. Per-condition C error counters are a recorded SHOULD limitation.

Source SHA-256 (downloaded 2026-10-26):

- Revision 15: `5c7337d11e1c9beffe1ce5a26438aa1d6f3411df8e280f3e022c27c363cd71e7`.
- Revision 25: `cbb4b1682184ba6ff49b64f7e562cd74a5f0074df04b4ccd0ff00d01da70bb16`.
