# Extension-header draft revision 13 implementation review

[draft-ietf-ippm-stamp-ext-hdr-13](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-ext-hdr-13.txt)
changes Type 246 to an eight-octet Requested field and a Length−8 Reflected field.
Type 247 keeps its four-octet selector. Both revisions are Internet-Drafts.
Upgrade both endpoints together; there is no version negotiation.
See the [60-row matrix](draft-stamp-ext-hdr.md).

Changes include:

- Match and preserve all eight Type 246 Requested octets; copy only header[8..].
  Enforce selector widths, valid attachment lengths/order and request cardinality.
  Explicit requests select attached headers rather than adding duplicate requests.
- Use TTL/Hop Limit 255 on both endpoints. Sender source ports default to randomized
  dynamic ports; explicit sender and reflector ports must differ for direction
  disambiguation. Reflectors retain their listening source port.
- Validate raw-capture IP framing and UDP checksums using the innermost IP endpoints
  before STAMP admission. Reject truncated, fragmented, corrupt and zero-checksum
  capture datagrams. Normal kernel UDP checksums remain enabled.
- Report idle/active/failed state transitions through structured logs and sender
  summaries, with a configurable consecutive-loss threshold and recovery on a
  validated reply. Invalid-session and duplicate packets do not drive recovery.
- Recheck sender route MTU and trim optional header requests; prevent fragmentation
  and fail closed when a reliable budget or requested attachment is unavailable.

The supported profile does not enable optional IPv6 zero-checksum operation.
Header origination requires Linux and a known route MTU. Nix still uses the draft's
C-flag fallback for unavailable raw headers; reverse-header insertion uses the
specified cannot-add C-flag response on both backends. Successful raw reflection
requires a capture point with complete wire checksums. Incomplete checksum-offload
frames (notably local loopback traffic) are rejected, never treated as verified
measurements. Private veth tests disable TX checksum offload; loopback tests inject
complete checksums and also check rejection of corrupt packets.

An eight-byte Type 246 request has no Reflected tail; an all-zero Requested field
therefore remains all zero on a successful reply. Selectors are not reconstructed
from replies. Revision-11 peers interpret the experimental codepoint differently. No final
IANA assignment is claimed. SSIDs remain provisioned rather than automatically generated. Operators
must provision both endpoints and sufficient processing capacity, deploy within the
draft's administrative-domain assumptions, and correlate policing/overload counters
with failure notifications before attributing loss to the network.

Verification: [namespace tests](../testing-netns.md), [measurement semantics](../measurements.md),
and [release procedures](../release-evidence.md).
