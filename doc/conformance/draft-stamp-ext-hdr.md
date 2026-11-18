# draft-ietf-ippm-stamp-ext-hdr conformance

Fixed IP and IPv6 extension header reflection (Types 247/246): requirements,
implementation, tests and backend limits.

Revision frozen: draft-ietf-ippm-stamp-ext-hdr-26, 27 October 2026.
Source: [draft-ietf-ippm-stamp-ext-hdr-26](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-ext-hdr-26.txt).

Summary: 75 clauses: 63 Compliant, 9 Partial, 0 Gap, 3 N-A, 0 Excluded.

The Clause column paraphrases the draft. Row IDs are kept from earlier
revisions where possible; the ordering and MTU rows use revision 26 section
numbers.

## Scope

### Wire format

Type 246 (Reflected IPv6 Extension Header) carries an eight-octet Requested
field followed by a Received field of Length − 8 octets. Type 247 (Reflected
Fixed Header) carries a four-octet Requested field followed by Length − 4
octets. The request's Length equals the size of the header it selects.

The reflector compares only nonzero Requested octets; each zero octet is a
wildcard. A nonzero selector must identify exactly one unmatched header of
the requested length, and the reflector returns it unchanged. An ambiguous
selector gets C, and no header is copied or consumed. An all-zero Requested
field selects the first unconsumed header of matching length and is filled
with that header's first eight (Type 246) or four (Type 247) octets. The
remaining bytes go into the Received field (`copy_reflected` in
`src/tlv/list/processing.rs`). An eight-octet header has no Received tail, so
a successful reply to an all-zero eight-octet request carries the whole header
in its Requested field.

Revision 26 gives an example of repeated nonzero requests with identical
prefixes that conflicts with its own ambiguity rules. stamp-suite follows the
rules, and the two rows for the example are Partial. See
[revision 26 interpretation](#revision-26-interpretation).

### Interoperability

Types 246 and 247 and the Type 12 sub-TLV 240 (IPv6 Extension Header
Control) are local experimental codepoints, listed under
[experimental codepoints](README.md#experimental-codepoints); IANA has not
allocated them. Both endpoints must implement this revision. Peers built for
revisions before 13 use a four-octet Type 246 Requested field and do not
interoperate. There is no version negotiation, and selectors are not
reconstructed from replies.

### Local reflection policy

Header reflection is denied by default. `--reflect-fixed-header-from IP` and
`--reflect-ipv6-ext-header-from IP` allow fixed and extension header data,
separately, for the listed sender IPs; repeat a flag for more senders. TOML
uses the `reflect_fixed_header_from` and `reflect_ipv6_ext_header_from`
arrays. The shared ingest path checks the original source IP before either
backend copies data, and compares IPv4-mapped addresses as IPv4. A refused
request keeps its value and gets C. Neither an open UDP port nor Type 12
support grants permission.

### Backend support

| Capability | nix backend, Linux | nix backend, macOS | pnet backend |
|---|---|---|---|
| Type 246 reflection | Hop-by-Hop, Destination Options and Routing headers from ancillary data | C flag | All extension headers from raw capture |
| Type 247 reflection | C flag | C flag | IPv4 and IPv6 fixed headers, including nested ones |
| Reverse-path header attachment (sub-TLV 240) | C flag | C flag | C flag |

The nix backend reads ancillary data in
`src/receiver/nix.rs::extract_ipv6_ext_headers`. It never sees Fragment
headers, because the kernel removes them during reassembly. Truncated
ancillary data yields no headers, so the request gets C. Raw capture in
`src/receiver/pnet.rs::checked_udp` validates IP framing and the UDP checksum
for the innermost IP endpoints before STAMP admission.

### Checksums and capture

Kernel UDP sockets generate and verify checksums. The separate
[authenticated IPv4 BER sender option](../usage.md#zero-checksum-ber-transmission)
can omit request checksums on Linux. stamp-suite never enables IPv6
zero-checksum operation (RFC 6936). Raw capture drops truncated, fragmented,
corrupt and zero-checksum datagrams; a fragmented request is counted as a
`fragmented` drop and logged. Raw reflection therefore needs a capture point
that sees complete wire checksums. Frames with incomplete checksums from TX
checksum offload, such as local loopback traffic, are dropped, never treated
as verified. The private veth tests disable TX checksum offload; the loopback
tests inject complete checksums and check that corrupt packets are dropped.

### Sender requirements

`--attach-ext-hdr` attaches one Hop-by-Hop and one Destination Options header
to IPv6 probes on Linux. Header requests (`--attach-ext-hdr`,
`--reflected-ipv6-ext-hdr`, `--reflected-fixed-hdr`) need a known egress route
MTU. The sender reads it on Linux, on Windows, and on macOS for connected
native unicast IPv6 without interface pinning, honoring the socket minimum-MTU
policy (`egress_mtu` in `src/sender/socket.rs` and
`src/sender/socket/windows.rs`, and `src/net_policy/macos_mtu.rs`). On other
sockets the sender refuses to start with header requests. Windows and macOS
support fixed-header requests; extension-header attachment is Linux-only.
Sender source ports are random dynamic ports by default, and an explicit local
port must differ from the remote port. Both endpoints send with TTL or Hop
Limit 255.

### Deployment assumptions

Operators provision both endpoints and Session-IDs, provide processing
capacity for the offered load, and deploy within the draft's single
administrative domain. They configure aggregate rate and burst limits in both
directions, allowing for encapsulation and concurrent sessions, and filter
traffic at domain boundaries. Sender `--send-delay` paces probes; Type 12
count, interval, rate, volume and duration caps bound reflected bursts. Queue,
session and burst caps can suppress replies under overload, so compare those
counters with session-state notifications before blaming the network for
loss. IOAM processing is not implemented.

## Clauses

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ext-hdr-3.1-1 | Choose randomized source UDP ports. | Descriptive | Sender | Compliant | `src/net_policy.rs::bind_sender` draws ports from the OS CSPRNG with bounded collision retries. Explicit local ports are an operator override; revision 25 uses lowercase should. |
| ext-hdr-3.1-2 | Prefer source ports in 49152–65535. | SHOULD | Sender | Compliant | `src/net_policy.rs::bind_sender` binds in the dynamic range by default. Reflector replies use the provisioned listening port, as UDP reply demultiplexing requires. |
| ext-hdr-3.1-3 | The sender source port must differ from the local reflector port. | MUST NOT | Sender | Partial | `src/net_policy.rs::bind_sender` skips the remote port, and binding fails on a local endpoint that is already held. Test: `tests/ext_hdr_revision13_test.rs::sender_hops_and_held_local_endpoint_separation_cover_both_families_and_keys`. A sender on another local IP can still use the local reflector's port number; stamp-suite keeps no inventory of local role ports. See [port and policing limits](#port-and-policing-limits). |
| ext-hdr-3.1-4 | Set outgoing IPv4 TTL and IPv6 Hop Limit to 255. | MUST | Both | Compliant | `src/net_policy.rs::set_hops` runs before sending in both reflector backends and the sender; a failure stops startup. Tests: `tests/ext_hdr_revision13_test.rs::sender_hops_and_held_local_endpoint_separation_cover_both_families_and_keys`, `tests/ext_hdr_revision13_test.rs::reflector_transmits_255_and_accepts_lower_received_hops`, `tests/pnet_endpoint_test.rs::pnet_assigned_ipv4_ports_reach_capture_metadata_and_both_reply_families`, `tests/pnet_endpoint_test.rs::pnet_assigned_ipv6_ports_reach_capture_metadata_and_both_reply_families`. Received ancillary metadata shows outgoing hops of 255 for IPv4 and IPv6 in open, keyed and authenticated modes; the pnet cases run in network namespaces. |
| ext-hdr-4.1-A | Packets may contain multiple Type 246 TLVs. | MAY | Both | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`, `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [request construction](#request-construction). |
| ext-hdr-4.1-B | Select extension headers by nonzero Requested octets; zero octets are wildcards. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-4.1-C | An all-zero Requested field selects the first unmatched extension header of the requested length, and the reflector fills Requested with its first eight octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision26_identical_headers_use_strict_unmatched_selection`. See [header matching](#header-matching). |
| ext-hdr-4.1-D | Initialize the Received field to zero in requests. | MUST | Sender | Compliant | `src/tlv/typed/reflected_ipv6_ext_hdr.rs::ReflectedIpv6ExtHdrTlv::request_with_selector` writes only the eight-octet selector and zero-fills the rest. The CLI rejects selectors longer than eight octets. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`. |
| ext-hdr-4.1-E | Return C without copying data when extension-header reflection cannot be fulfilled, including ambiguous selection. | MUST / MUST NOT | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. No match, multiple matches, unsupported capture and invalid length preserve the request. |
| ext-hdr-4.2-1 | Add a matching Type 246 request for each attached extension header whose reflection is required. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Request Length equals the attached header size; attachment failure aborts startup. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`. |
| ext-hdr-4.2-2 | Order multiple Type 246 requests with their corresponding extension headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The sender attaches at most one Hop-by-Hop header followed by one Destination Options header. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`. |
| ext-hdr-4.2-3 | Omit requests for headers whose reflection is not required. | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Explicit requests can select a subset; a same-length subset needs matching selectors. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`, `src/configuration/tests.rs::revision26_sender_subset_rules_apply_to_cli_and_toml`. |
| ext-hdr-4.2-4 | Do not originate more Type 246 requests than extension headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Unattached requests and duplicate attachment kinds are rejected. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`, `src/configuration/tests.rs::revision26_sender_subset_rules_apply_to_cli_and_toml`. |
| ext-hdr-4.2-5 | Reflect the extension-header bytes after its first eight octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [wire format](#wire-format). |
| ext-hdr-4.2-6 | Process received extension headers in outer-to-inner order. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`. See [header matching](#header-matching). |
| ext-hdr-4.2-7 | Use the first eight on-wire octets as the selector when a same-length subset is ambiguous. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The kernel-assigned Next Header octet is derived from the attached header chain; selector bytes must match the attached header. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`, `src/configuration/tests.rs::revision26_sender_subset_rules_apply_to_cli_and_toml`. |
| ext-hdr-4.2-8 | Match each nonzero Requested octet exactly, and select only a unique unmatched header. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. An ambiguous request consumes no header. |
| ext-hdr-4.2-subset | Do not use identical first-eight-octet prefixes to select only some equal-length extension headers. | MUST NOT | Sender | Compliant (originated profile) | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/configuration/tests.rs::revision26_sender_subset_rules_apply_to_cli_and_toml`, `src/configuration/tests.rs::revision26_sender_rejects_profiles_with_indistinguishable_originated_headers`. The supported hbh/dest chain has distinct kernel-assigned Next Header octets; masking away that distinction cannot select an ambiguous subset. |
| ext-hdr-4.2-identical | Allow all equal-length extension headers with identical prefixes to be reflected using repeated nonzero requests in packet order. | Descriptive | Reflector | Partial | `tests/tlv_flag_semantics.rs::revision26_identical_headers_use_strict_unmatched_selection`. Repeated nonzero selectors get C under explicit rule 1; all-zero requests reflect every header in order. See [revision 26 interpretation](#revision-26-interpretation). |
| ext-hdr-4.3-1 | The reflector's data plane provides received IPv6 extension headers to the reflector. | MUST | Reflector | Partial | `src/receiver/pnet.rs::checked_udp`, `src/receiver/nix.rs::extract_ipv6_ext_headers`, `tests/netns_conformance.rs::scenario_4a_ext_hdr_nix_ancillary`. The nix backend on macOS and on Fragment headers cannot supply them. See [backend support](#backend-support). |
| ext-hdr-4.3-2 | The sender's data plane provides reply extension headers to the sender for bidirectional measurement. | MUST | Sender | N-A | Bidirectional measurement is not supported (ext-hdr-5.2-1). |
| ext-hdr-5-1 | In unidirectional mode omit matching reverse-path headers in response to received headers. | MUST | Reflector | Compliant | Neither backend adds matching reverse-path headers. Independent SRv6 Return Path requests remain separate. Tests: `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-5.2-1 | Add matching reverse-path extension headers when requested, or use the specified cannot-add fallback. | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Both backends use the fallback: C in the control sub-TLV. See [control sub-TLV](#control-sub-tlv). Tests: `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-5.2-2 | Without the control sub-TLV omit matching reverse-path headers. | MUST | Reflector | Compliant | Neither backend adds matching reverse-path extension headers. Tests: `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-5.2-3 | Reflect received header data regardless of the reverse-header control sub-TLV. | MUST | Reflector | Compliant | `src/receiver/mod.rs::apply_semantic_tlv_processing`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`. Type 246 processing runs independently of the sub-TLV. Tests: `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-5.2-4 | Signal inability to add matching reverse headers with C in the control sub-TLV. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::reflected_control_single_ext_hdr_control_sets_c_on_subtlv`. |
| ext-hdr-5.2-5 | Do not originate duplicate extension-header control sub-TLVs in one Type 12 TLV. | MUST NOT | Sender | Compliant | `src/sender/packet.rs::build_reflected_control_tlv` adds the sub-TLV at most once. Tests: `tests/header_request_wire_test.rs::sender_control_request_is_unique_zero_length_and_opt_in`. |
| ext-hdr-5.2-6 | Set C on every duplicated extension-header control sub-TLV. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::reflected_control_duplicate_ext_hdr_control_sets_c_on_all_copies`. |
| ext-hdr-6.1-A | Packets may contain multiple Type 247 TLVs. | MAY | Both | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, with multi-candidate fixed-header unit tests. The sender originates one; the pnet reflector handles several. |
| ext-hdr-6.1-B | Select fixed headers by nonzero Requested octets; zero octets are wildcards. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-6.1-C | An all-zero Requested field selects the first matching-length IP header, and the reflector fills Requested with its first four octets. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. Matching consumes candidates in wire order. See [header matching](#header-matching). Tests: `tests/tlv_flag_semantics.rs::fixed_header_reflection_fills_requested_and_copies_received_in_capture_order`, `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-6.1-D | Initialize the fixed-header Received field to zero in requests. | MUST | Sender | Compliant | `src/tlv/typed/reflected_fixed_hdr.rs::ReflectedFixedHdrTlv::request_with_selector`. The CLI limits the selector to four octets. Tests: `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`. |
| ext-hdr-6.1-E | Return C without copying data when fixed-header reflection cannot be fulfilled, including ambiguous selection. | MUST / MUST NOT | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-6.2-1 | Add multiple fixed-header requests in corresponding header order. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The sender originates one IP header and allows at most one Type 247 request. Tests: `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`, `src/configuration/tests.rs::revision26_sender_rejects_profiles_with_indistinguishable_originated_headers`. |
| ext-hdr-6.2-2 | Omit fixed-header requests when reflection is not requested. | MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. Type 247 is opt-in. Tests: `tests/header_request_wire_test.rs::sender_control_request_is_unique_zero_length_and_opt_in`, `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`. |
| ext-hdr-6.2-3 | Do not originate more fixed-header requests than IP headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. At most one request for the one originated IP header. Tests: `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`, `src/configuration/tests.rs::revision26_sender_rejects_profiles_with_indistinguishable_originated_headers`. |
| ext-hdr-6.2-4 | Copy the fixed-header portion after the four-octet Requested field. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`. See [wire format](#wire-format). Tests: `tests/tlv_flag_semantics.rs::fixed_header_reflection_fills_requested_and_copies_received_in_capture_order`, `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-6.2-5 | Process encapsulated fixed headers in outer-to-inner order. | MUST | Reflector | Compliant | `src/receiver/pnet.rs::checked_udp` captures in wire order; `src/tlv/list/processing.rs::apply_reflected_header` consumes matching captures once. Test: `tests/pnet_nested_headers_test.rs::actual_nested_capture_reflects_outer_to_inner_and_rejects_bad_checksums_and_depth`. pnet capture reflects mixed IPv4/IPv6 headers two and three layers deep with exact bytes, inner endpoint and hop metadata, and signatures checked separately. Bad inner UDP checksums and excessive depth get no reply, and later valid requests still work. The capture is Linux software loopback. |
| ext-hdr-6.2-6 | Use a four-octet selector for ambiguous same-length fixed headers. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs`. The CLI accepts up to four selector octets and zero-pads the rest. Tests: `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`, `src/configuration/tests.rs::fixed_hdr_selector_too_long_for_ipv4_is_rejected`. |
| ext-hdr-6.2-7 | Match each nonzero Requested fixed-header octet exactly, and select only a unique unmatched header. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_header`, `tests/tlv_flag_semantics.rs::revision25_wildcards_ambiguity_and_policy`. |
| ext-hdr-6.2-subset | Do not use identical first-four-octet prefixes to select only some equal-length fixed headers. | MUST NOT | Sender | Compliant (originated profile) | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/configuration/tests.rs::revision26_sender_rejects_profiles_with_indistinguishable_originated_headers`. The sender originates one fixed IP header and rejects multiple fixed-header requests through both CLI and TOML. |
| ext-hdr-6.2-identical | Allow all equal-length fixed headers with identical prefixes to be reflected using repeated nonzero requests in packet order. | Descriptive | Reflector | Partial | `tests/tlv_flag_semantics.rs::revision26_identical_headers_use_strict_unmatched_selection`. The same explicit rule 1 and all-zero workaround apply as for Type 246. See [revision 26 interpretation](#revision-26-interpretation). |
| ext-hdr-7.1-1 | Place Type 247 TLVs before Type 246 TLVs. | MUST | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/sender/packet.rs::reflected_header_request_tlvs` emits fixed-header requests first. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`. |
| ext-hdr-7.1-2 | Return out-of-order reflected-header TLVs with C set. | MUST | Reflector | Compliant | `src/tlv/list/processing.rs::apply_reflected_headers` checks the global order before copying. Combined-header wire and unit tests cover both orders. Tests: `tests/tlv_flag_semantics.rs::global_header_order_refusal_preserves_all_requests_before_copying`, `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-7-1 | Omit Type 246 reflection requests for IOAM Direct Exporting. | MUST | Sender | N-A | No IOAM DEX processor or exporter is implemented. Attaching arbitrary operator-supplied IPv6 options does not make stamp-suite an IOAM implementation. |
| ext-hdr-9-1 | Allow the measurement type to be provisioned as unidirectional or bidirectional. | MUST | Both | Partial | Unidirectional measurement is supported. A bidirectional request (control sub-TLV 240) is answered with C because reply-header attachment is not implemented. |
| ext-hdr-9-2 | Provide a configurable reflector policy identifying permitted senders and header data. | MUST | Reflector | Compliant | `src/receiver/ingest.rs::ProcessingContext::for_packet`, `src/configuration.rs::Configuration`. Separate source-IP allowlists for Types 246 and 247 default to deny; see [local reflection policy](#local-reflection-policy). Tests: `src/receiver/ingest.rs::tests::header_reflection_policy_is_per_source_and_header_kind`, `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-9.2-1 | Report idle when the sender stops transmitting. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`; deadline and state regression tests. |
| ext-hdr-9.2-2 | Report active after a validated reply while transmitting. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`; admission precedes state changes. |
| ext-hdr-9.2-3 | Report failed after the configured consecutive-loss threshold following activation. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`, `--session-loss-threshold`. |
| ext-hdr-9.2-4 | Recover from failed to active after a validated reply while transmitting. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::Monitor`. |
| ext-hdr-9.3-1 | Provision receive policing to accommodate aggregate transmitted traffic and bursts. | MUST NOT | Both | Partial | Ingress limiting is disabled by default and caps are operator-provisioned. Test: `src/configuration/tests.rs::receive_policing_defaults_and_provisioned_cli_toml_values_reach_runtime` verifies defaults, CLI/TOML precedence and actual runtime rate/burst values. The application does not check receive limits against aggregate offered traffic, concurrent sessions and deployment capacity. See [port and policing limits](#port-and-policing-limits). |
| ext-hdr-10-1 | Do not assign Session-IDs predictably. | MUST NOT | Sender | N-A | The application does not allocate Session-IDs. Nonzero values are provisioned by the operator; an unset SSID is the RFC 8972 zero value. |
| ext-hdr-4.1-type | Use the assigned Type for the extension-header TLV. | MUST | Both | Partial | `src/tlv/experimental.rs::REFLECTED_IPV6_EXT_HDR_TLV_TYPE` uses experimental 246 pending IANA allocation. |
| ext-hdr-4.2-mutable | Zero every Requested octet containing mutable option data; never depend on matching a zero-valued octet. | MUST / MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags` checks attached Hop-by-Hop and Destination Options header selectors, wildcard uniqueness and option change-en-route bits. The sender does not originate Routing headers. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`, `src/configuration/tests.rs::revision25_extension_selector_masks_mutable_option_data`. |
| ext-hdr-4.2-policy | Explicitly request extension-header data; enforce reflector policy before copying and return C on refusal. | MUST / MUST NOT | Both | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/receiver/ingest.rs::ProcessingContext::for_packet`, `src/tlv/list/processing.rs::process_reflected_headers_with_policy`. Tests: `tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`, `src/receiver/ingest.rs::tests::header_reflection_policy_is_per_source_and_header_kind`, `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-5.1-type | Use the assigned Type for the extension-header control sub-TLV. | MUST | Both | Partial | `src/tlv/experimental.rs::REFLECTED_CONTROL_SUBTLV_IPV6_EXT_HDR_CONTROL` uses experimental 240 pending IANA allocation. |
| ext-hdr-5.1-length | Set control sub-TLV length to zero; reflect nonzero lengths with M. | MUST | Both | Compliant | `src/sender/packet.rs::build_reflected_control_tlv`, `src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, `tests/tlv_flag_semantics.rs::revision25_control_sub_tlv_nonzero_length_is_malformed`. |
| ext-hdr-5.1-shape | When Type 12 only carries the extension-header control sub-TLV, request one packet with interval and length zero. | MUST | Sender | Compliant | `src/sender/packet.rs::build_reflected_control_tlv`; default count=1, length=0, interval=0. Explicit asymmetric traffic settings additionally request reply shaping. Tests: `tests/header_request_wire_test.rs::sender_control_request_is_unique_zero_length_and_opt_in`. |
| ext-hdr-6.1-type | Use the assigned Type for the fixed-header TLV. | MUST | Both | Partial | `src/tlv/experimental.rs::REFLECTED_FIXED_HDR_TLV_TYPE` uses experimental 247 pending IANA allocation. |
| ext-hdr-6.2-request | Add a fixed-header TLV for each header requested for reflection. | MUST | Sender | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`; the sender originates one fixed IP header. Tests: `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`. |
| ext-hdr-6.2-mutable | Zero every Requested octet containing mutable DSCP/ECN bits; never depend on matching a zero-valued octet. | MUST / MUST NOT | Sender | Compliant | `src/configuration.rs::Configuration::validate_ext_hdr_flags`, `src/configuration/tests.rs::revision25_fixed_selector_masks_mutable_octets`. IPv4 byte 1 and IPv6 bytes 0 and 1 must be zero. |
| ext-hdr-6.2-policy | Explicitly request fixed-header data; enforce reflector policy before copying and return C on refusal. | MUST / MUST NOT | Both | Compliant | `src/sender/packet.rs::reflected_header_request_tlvs`, `src/receiver/ingest.rs::ProcessingContext::for_packet`, `src/tlv/list/processing.rs::process_reflected_headers_with_policy`. Tests: `tests/header_request_wire_test.rs::sender_fixed_header_requests_have_family_length_selector_and_zero_received`, `src/receiver/ingest.rs::tests::header_reflection_policy_is_per_source_and_header_kind`, `tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`. |
| ext-hdr-7.2-1 | Keep the complete transmitted packet within the applicable path MTU. | MUST | Both | Compliant | `src/sender/packet.rs::enforce_egress_mtu`, `src/receiver/transmit.rs::fit_reply`; tests: `src/receiver/transmit/tests.rs::single_header_reply_checks_mtu_trims_and_resigns`, `tests/route_mtu_test.rs::live_route_mtu_changes_and_alternate_destinations`. See [MTU budget](#mtu-budget). Sender dispatch: `tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes` checks real Linux IPv4/IPv6 budgets, dynamic TLVs, ordered trimming/restoration and final signatures. |
| ext-hdr-7.2-2 | Remove complete reflected-header TLVs from the end, skipping HMAC, until the packet fits. | MUST | Both | Compliant | Sender: `src/sender/packet.rs::enforce_egress_mtu` removes the last header TLV until the probe fits; the HMAC is per-probe overhead and never a candidate. Reflector, administrative limit (`--reflected-control-max-size`): `src/tlv/list/processing.rs::trim_reflected_headers_to_size` selects header TLVs from the end in one pass and removes them in a second pass that leaves the HMAC alone. Reflector, route MTU: `src/receiver/transmit.rs::fit_reply` removes the last processed header TLV until the reply fits. Test: `src/tlv/list/processing/tests.rs::trim_reflected_headers_matches_removing_the_last_header_repeatedly` checks that the two-pass trim removes the same TLVs as repeated last-header removal. Tests: `src/receiver/transmit/tests.rs::single_header_reply_checks_mtu_trims_and_resigns`, `tests/route_mtu_test.rs::live_route_mtu_changes_and_alternate_destinations`. Sender dispatch: `tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes` checks real Linux IPv4/IPv6 budgets, dynamic TLVs, ordered trimming/restoration and final signatures. Administrative trimming: `src/receiver/transmit/header_diagnostics_tests.rs::administrative_header_trimming_reserves_only_a_new_hmac_and_keeps_framing` verifies open/authenticated IPv4/IPv6, keyed/unkeyed requests and existing/new extension HMACs without refilling removed headers. |
| ext-hdr-7.2-3 | Update the HMAC digest if a preceding TLV was removed. | MUST | Both | Compliant | `src/receiver/transmit.rs::fit_reply`, `src/receiver/transmit.rs::Transmission`; tests: `src/receiver/transmit/tests.rs::single_header_reply_checks_mtu_trims_and_resigns`, `src/receiver/transmit/tests.rs::single_header_reply_refreshes_mtu_and_resigns_after_emsgsize`, `tests/route_mtu_test.rs::live_route_mtu_changes_and_alternate_destinations`. The send path trims before signing each copy. Sender builds and signs after trimming. Sender dispatch: `tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes` checks real Linux IPv4/IPv6 budgets, dynamic TLVs, ordered trimming/restoration and final signatures. Administrative trimming: `src/receiver/transmit/header_diagnostics_tests.rs::administrative_header_trimming_reserves_only_a_new_hmac_and_keeps_framing` verifies open/authenticated IPv4/IPv6, keyed/unkeyed requests and existing/new extension HMACs without refilling removed headers. |
| ext-hdr-7.2-4 | Retain the relative order of remaining TLVs, including returned requests. | MUST | Both | Compliant | `src/tlv/list/mod.rs::retain_non_hmac` removes the chosen TLVs in one pass and repairs the wire-order indices. `src/receiver/transmit.rs::fit_reply` and the sender remove one entry at a time from an ordered list. Tests: `src/receiver/transmit/tests.rs::single_header_reply_checks_mtu_trims_and_resigns`, `src/tlv/list/processing/tests.rs::trim_reflected_headers_matches_removing_the_last_header_repeatedly`, `tests/route_mtu_test.rs::live_route_mtu_changes_and_alternate_destinations`. Sender dispatch: `tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes` checks real Linux IPv4/IPv6 budgets, dynamic TLVs, ordered trimming/restoration and final signatures. |
| ext-hdr-7.2-5 | Do not transmit when removing all optional header TLVs cannot satisfy the MTU. | MUST NOT | Both | Compliant | `src/sender/run.rs`, `src/receiver/transmit.rs::fit_reply`; test: `src/receiver/transmit/tests.rs::single_header_reply_refuses_missing_mtu_or_oversized_mandatory_fields`. Oversized mandatory packets and unavailable route budgets are refused. Sender dispatch: `tests/route_mtu_test.rs::live_sender_trims_restores_and_refuses_oversized_probes` checks real Linux IPv4/IPv6 budgets, dynamic TLVs, ordered trimming/restoration and final signatures. `src/sender/run/mtu_tests.rs::refused_probes_share_the_send_failure_budget_without_pending_state` checks that a refused probe is not sent; the live test checks mandatory oversize at startup and after a route decrease. |
| ext-hdr-9-errors | Log each C error condition locally and increment its condition counter. | SHOULD | Reflector | Compliant (TLV-enabled profile) | Type 246/247 C conditions and Type 12 limits have fixed counters and their own throttled logs, updated after successful sends. Reasons for headers removed by trimming are dropped, and an MTU retry starts again from the original reasons. Tests: `src/receiver/transmit/header_diagnostics_tests.rs::header_reasons_match_processed_c_flags_and_signed_successful_sends`, `src/receiver/transmit/header_diagnostics_tests.rs::header_diagnostics_follow_only_surviving_headers_after_size_trimming`, `src/receiver/transmit/diagnostics_tests.rs::diagnostics_log_each_reason_independently_without_per_packet_log_floods`. Nested unsupported/duplicate controls also have fixed diagnostics: `src/receiver/transmit/cos_control_diagnostics_tests.rs::nested_control_reasons_count_only_generated_c_and_distinguish_duplicates`, `src/receiver/transmit/cos_control_diagnostics_tests.rs::nested_control_reports_follow_actual_mutations_across_parents_and_later_u`. A C flag kept from the peer in a complete child header of a known container counts under a separate reason; values are not decoded or changed. Tests: `src/receiver/transmit/peer_c_diagnostics_tests.rs::preserved_peer_c_uses_known_layouts_and_preserves_failed_integrity_values`, `src/receiver/transmit/peer_c_diagnostics_tests.rs::preserved_peer_c_observations_require_successful_sends_and_base_admission`. This does not cover `--tlv-mode ignore`. |
| ext-hdr-9.2-0 | Optionally generate session state-change notifications. | MAY | Sender | Compliant | `src/sender/session_state.rs::Monitor` exposes structured logs and report summaries. |
| ext-hdr-9.2-5 | Report failed after N consecutive losses even before the first reply. | Descriptive | Sender | Compliant | `src/sender/session_state.rs::tests::failure_before_first_reply_and_recovery`. |
| ext-hdr-9.3-2 | Provide configurable transmission rate and burst limits. | SHOULD | Both | Compliant | `--send-delay` and a finite probe count bound sender traffic; Type 12 count, interval, rate, volume and duration caps bound reflected bursts. |
| ext-hdr-9.3-3 | Pace packet transmissions to avoid excessive bursts. | SHOULD | Both | Compliant | Sender scheduling and `src/receiver/transmit.rs::Transmission` pace each reply copy. Operators can explicitly request zero-delay test traffic. |
| ext-hdr-9.3-4 | Allow overload drops or suppressed responses for resource protection. | MAY | Both | Compliant | `src/receiver/ingest.rs::ReflectorCore::ingest`, `src/receiver/transmit.rs`; queue, session and burst limits. |
| ext-hdr-9.3-5 | Expose local limiting counters or notifications so operators can distinguish local suppression from network loss. | SHOULD | Reflector | Compliant | `src/receiver/limits.rs::ReflectorCounters` separates rate-limited, queue-rejected and cancelled work; control and SNMP expose reflector counters. |

## Notes

### Port and policing limits

A test runs the sender while the local reflector socket is held, in IPv4 and
IPv6 and three key modes, and the sender cannot bind that endpoint. This does
not keep the port numbers apart across local IPs. In a manual run in a private
namespace, a pnet reflector held `127.0.0.1:56620` while the sender sent from
`127.0.0.2:56620` to another port; the peer saw the same source port number
and the reflector kept running. Operators must give the sender and reflector
different local ports on every address.

Receive policing (token bucket) is off by default, and a test checks that
configured rate and burst values reach the runtime from the CLI and TOML.
That shows configuration handling, not that a deployed limit fits the
aggregate traffic. Operators must size limits for concurrent sessions and
bursts and compare local drop counters with loss reports; stamp-suite does
not check that receive and transmit limits fit together. Both rows were
Compliant before and are now Partial.

### Request construction

`src/configuration.rs::Configuration::validate_ext_hdr_flags` checks selector
widths, attachment lengths and order, and the number of requests at startup.
`src/sender/packet.rs::reflected_header_request_tlvs` builds the requests.
Explicit `--reflected-ipv6-ext-hdr` requests replace the automatic requests
that `--attach-ext-hdr` adds and select a subset of the attached headers.

The sender test is
`tests/header_request_wire_test.rs::linux::sender_header_requests_follow_actual_attached_order_and_select_subsets`.
In a private Linux namespace, a UDP peer reads the Hop-by-Hop and Destination
Options headers from ancillary data and compares the TLVs with expected bytes
built separately, in unkeyed open, keyed open and authenticated modes. It
covers automatic and explicit requests, equal and unequal lengths, both
same-length subsets, masking of mutable option data, zero Received tails and
fixed-before-extension order. CI requires the case in the nix and pnet jobs.
It tests what the sender sends, not reflector dispatch or raw capture. The
same file has separate tests for Linux fixed-header requests and portable
control-only defaults.

A selector argument must contain at least one nonzero byte; a bare length
requests an all-zero wildcard field. The CLI and TOML checks enforce this,
reject a wrong order, length or count and ambiguous subsets, and accept the
wildcard form that covers the whole group.

### Header matching

`src/tlv/list/processing.rs::apply_reflected_header` pairs each request with
the one unconsumed captured header of the same length that matches every
nonzero selector octet. Zero octets are wildcards, and an all-zero selector
takes the first unconsumed header of that length. Headers are captured in wire
order, so successive requests pair outer to inner. A missing or ambiguous
match consumes nothing and sets C. Nonzero Requested fields are returned
unchanged; all-zero ones are filled from the capture. The test
`revision13_selector_uses_all_eight_octets_and_zero_selector_is_filled`
(`tests/tlv_flag_semantics.rs`) builds its raw bytes without the crate's
encoder.

Signed raw-byte tests through packet processing cover 20- and 40-octet fixed
headers: all-zero Requested fields are filled in capture order, unique
selectors keep their wildcard bytes, Received tails are copied, and requests
left without a capture get C and no data. A separate test checks that an
out-of-order request list gets C on every header request before anything is
copied. These tests supply the captured headers. ext-hdr-6.2-5 has a test
with real nested capture through pnet; it does not cover physical tunnels.

`tests/header_reflection_wire_test.rs::reflector_disclosure_order_and_control_use_actual_headers_without_reverse_attachment`
checks Linux nix and pnet replies in private namespaces. Default deny,
unmatched-source, fixed-only, extension-only and both-kind policies are
applied before copying. Matching headers are reflected with zero, one or two
control sub-TLVs, every control sub-TLV gets C, and reversed Type 246/247
order returns both requests with C. nix cannot supply fixed headers; pnet
checks both fixed and extension headers captured from IPv6 packets. The test
checks signatures and failed-integrity copies, and that replies carry no
matching Hop-by-Hop or Destination Options headers. It does not cover physical
interfaces or nested tunnels.

### Revision 26 interpretation

Sections 4.2 and 6.2 describe reflecting all headers with identical prefixes
through successive requests. Their numbered rule 1, and the inability cases
in Sections 4.1 and 6.1, require C for a nonzero selector that matches more
than one unselected header. Until the authors resolve this, stamp-suite
applies the explicit ambiguity rule: repeating the same nonzero selector does
not resolve the ambiguity and does not consume a capture. Ordered all-zero
requests do reflect every header. Once a request consumes a header, later
selectors see only the remaining captures.

`tests/tlv_flag_semantics.rs::revision26_identical_headers_use_strict_unmatched_selection`
builds requests for Types 246 and 247 without the crate's encoder, in open and
authenticated mode with both HMACs. It checks that ambiguous requests keep
their data, that all-zero requests consume captures once and in order, and
that a later nonzero selector can match the one remaining header. It tests
packet processing with supplied capture metadata, not headers on the wire.

The sender already meets the new subset restriction. It originates one fixed
IP header and at most one Hop-by-Hop header followed by one Destination
Options header, and those two have different Next Header octets. A request
that masks those octets must still match exactly one remaining header;
ambiguous subsets and duplicate selections are rejected, with CLI and TOML
tests. Originating other header chains would need this restriction checked
again.

A [clarification request](ext-hdr-26-clarification.md) for the draft authors
has been drafted; it has not been sent and there is no answer yet.

### MTU budget

The sender reads the connected route MTU before each send and each Access
Report retry, removes optional Type 246/247 TLVs to fit, and refuses a probe
whose mandatory fields do not fit. A failed route lookup also refuses the
probe; the previous budget is not reused. Space for the Type 12 TLV, Direct
Measurement, Access Report, the diagnostic trailer and the sender's HMAC is
reserved before trimming. Each probe starts from the full request list, so
header requests come back when the MTU grows, even if startup removed all of
them. On Linux, Windows and supported macOS IPv6 sockets the sender sets
Don't Fragment, so a route change cannot fragment a probe.

The reflector applies two limits. During TLV processing,
`src/tlv/list/processing.rs::trim_reflected_headers_to_size` trims header
TLVs to the administrative `--reflected-control-max-size` (default 1500
bytes), reserving room for an HMAC it will add. At send time,
`src/receiver/transmit.rs::fit_reply` sizes the reply against the route to
the actual destination before signing (`src/receiver/mtu.rs`), and an unknown
budget drops the reply. Route lookup exists on Linux, Windows and unpinned
native unicast IPv6 on macOS. Elsewhere header reflection does not work, but
no oversized packet is sent.

Windows sender tests in `src/sender/run/windows_mtu_tests.rs` query native
IPv4, IPv6 and IPv4-mapped sockets, apply socket-local caps without changing
host routes, and check trimming and restoration, refusal of oversized
mandatory fields and the fragmentation policy. Open, keyed-open and
authenticated sends have their HMACs checked. The portable fixed-header wire
test in `tests/header_request_wire_test.rs` also runs on Windows. These tests
use kernel estimates and socket caps; they do not probe the path or change
host routes. Windows loopback may skip MTU enforcement even with Don't
Fragment set, so they show the application's refusal and socket policy, not
physical fragmentation.

The Windows reflector reads the selected route, path MTU and interface MTU on
every attempt and drops the reply if no budget is available. Native tests in
`src/receiver/mtu/windows.rs` cover bound and wildcard sources, bypassing a
stale cache, unavailable sources and IPv6 zone encoding. The transmit test
`src/receiver/transmit/windows_tests.rs::windows_reflector_mtu_shapes_native_datagrams_and_restores_policy`
checks IPv4 and IPv6 datagrams, Type 12 clamping, header removal, whole BER
patterns, HMACs and restoring the normal socket policy. These are loopback
send-side tests, without a capture driver, real route changes or a physical
path.

macOS sender tests in `src/sender/run/macos_mtu_tests.rs` cover connected IPv6
queries, minimum-MTU policy changes, removing and restoring optional headers,
refusing oversized mandatory fields, initial BER fitting and signatures. The
macOS reflector tests in `src/receiver/transmit/macos_tests.rs` cover Type 12
sizing, optional-header removal, whole-pattern BER fitting, signatures and
repeated fragmentation and CoS setting changes; the query tests in
`src/receiver/mtu/macos.rs` cover wildcard sources, forced refresh and
unsupported cases. These tests run only in native macOS CI; cross-compilation
does not run them. They do not show physical fragmentation or real route
changes.

Single replies without Type 12 set their transport policy before the reply
buffer is moved. Transmit tests cover Types 246/247, IPv4 and IPv6, open and
authenticated replies, mandatory TLV order, re-signing, missing budgets and
refreshing after EMSGSIZE. The live route test checks single-reply trimming
over a smaller reverse route, including C-marked header requests with no
captured data. The sender namespace test runs the public sender loop against
a separate UDP peer that checks HMACs. It covers IPv4 and IPv6, open, keyed
open (with and without an originated HMAC) and authenticated modes, including
a real IPv6 Hop-by-Hop header. It checks refusal of oversized mandatory fields
at startup and after a route decrease, and restoration when no header request
survived startup. A separate test disconnects the shared sender socket to
make a route lookup fail. These tests show Linux kernel-route behavior, not
end-to-end PMTU discovery or physical links. In 1.0.0 single replies could be
sent oversized; these rows describe the fixed code.

### Control sub-TLV

`src/receiver/mod.rs::apply_semantic_tlv_processing` calls
`src/tlv/list/processing.rs::mark_ipv6_ext_hdr_control_c`, which sets C on
every IPv6 Extension Header Control sub-TLV in Type 12, duplicates included.
This is the draft's cannot-add response (§5.1 rule 4). Both backends use it,
because attaching headers to replies is not implemented.

### Session state

`src/sender/session_state.rs::Monitor` runs in `Measurements` after the
authentication, session and duplicate checks. Structured logs and the
`measurements.session_state` report field show idle, active and failed
transitions. Each probe has a `--timeout` deadline. After
`--session-loss-threshold` (default 3) consecutive unanswered probes, a
transmitting session is marked failed, even before its first valid reply. A
validated reply activates or recovers it; duplicates and replies that fail the
session check do not. IPv4 and IPv6 wire tests and state tests cover failure,
recovery and replies that fail the session check.

## Coverage

The table lists the draft's uppercase normative clauses and structural field
requirements, with the §9.2 MAY split into its five state outcomes. Control
procedure rows cite revision 26 §5.1, and the combined-header ordering rows
cite §7.1. The field width and length rows cover Figures 6 and 7. Keyword
boilerplate, topology examples, IOAM descriptions, implementation-status text
and IANA procedures add no runtime requirement. Revision 25 removed revision
15's zero-checksum section. IPv6 checksums stay enabled and validated; the
Linux IPv4 authenticated BER sender option has no IPv6 zero-checksum mode.
Requirements of referenced RFCs are in their own matrices.

See the [namespace tests](../testing-netns.md), [measurement
semantics](../measurements.md) and [Releasing](../releasing.md).

## Revision 26 review 2026-11-09

Compared the full archived texts of revisions 25 and 26. Field lengths and
the wire layout are unchanged: Length is the selected header's full size, with
its Requested prefix counted once. The revised matching text excludes headers
that were already selected, which the existing in-order consumption already
did. The sender's originated profile meets the new sender restrictions. The
conflicting repeated-nonzero examples add two Partial rows. Reflector matching
and the experimental codepoints did not change.

On the review date, Datatracker listed revision 26 as Active. Archived source
SHA-256 values:

- Revision 25: `cbb4b1682184ba6ff49b64f7e562cd74a5f0074df04b4ccd0ff00d01da70bb16`.
- Revision 26: `75f9d776a3c7f9ed4637a7240dae62922158d28ca34444287e17311587fc6a3e`.

## Revision 25 review (2026-10-26)

Compared the full revision 15 and 25 texts from the IETF archive. The review
covered wildcard selectors and ambiguity rejection, masking of mutable octets,
explicit sender configuration, reflector disclosure policy, control sub-TLV
length validation, failure before the first reply, and the expanded rate,
burst and overload guidance. The MTU and mixed-header ordering requirements
moved to §§7.1–7.2, and the zero-checksum section was removed. Trimming still
happens before signing.
`src/receiver/transmit/tests.rs::reflected_headers_are_trimmed_before_ber_padding`
checks that header TLVs are removed before padding is touched and that a reply
whose remaining fields cannot fit is refused. Its first TLV is the retired
Type 241, which now parses as unknown, so the test no longer contains a BER
TLV;
`src/receiver/transmit/ber_tests.rs::controlled_header_trimming_marks_only_changed_ber_denominators`
covers header trimming with a real BER TLV. The IANA values are still
TBA1/TBA2/TBA3, so the experimental codepoints stay and their rows are
Partial. Per-condition C counters were missing at this review; they were added
later (ext-hdr-9-errors).

Source SHA-256 (downloaded 2026-10-26):

- Revision 15: `5c7337d11e1c9beffe1ce5a26438aa1d6f3411df8e280f3e022c27c363cd71e7`.
- Revision 25: `cbb4b1682184ba6ff49b64f7e562cd74a5f0074df04b4ccd0ff00d01da70bb16`.
