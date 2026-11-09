# Retired legacy BER profile

Revision frozen: draft-gandhi-ippm-stamp-ber-07, 30 June 2026.
Source: [legacy draft](https://www.ietf.org/archive/id/draft-gandhi-ippm-stamp-ber-07.txt).

Summary: 30 clauses: 0 Compliant, 0 Partial, 0 Gap, 1 N-A, 29 Excluded.

## Scope

This matrix now records the explicitly retired legacy wire profile. It makes
no current compliance claim for that profile. Both endpoints use the successor
combined BER TLV. The frozen legacy marker remains solely for the outstanding
standards review; T5c will rebuild this matrix from the successor requirements
and update the manifest after independent live evidence is complete.

The active format uses local experimental outer Type 243 and pattern sub-TLV
Type 241; legacy outer Types 240–242 get U. See the [migration guide](../ber-migration.md)
for configuration changes, compatibility, tested endpoint behavior and the
limitations of the draft-listed independent peer. Retained legacy Rust types
serialize historical fixtures only; they do not enable a legacy endpoint mode.

## Clauses

The Clause column paraphrases the retired draft. These exclusions are a profile
retirement decision, not successor conformance scores. Prior implementation
results remain available in repository history at commit `04de534`.

| ID | Clause | Level | Role | Status | Evidence |
|---|---|---|---|---|---|
| ber-3-1 | Sender and reflector adjust the extra padding so test packets do not exceed the path MTU. | MUST | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-1 | A test packet carries one Bit Error Count TLV and one Extra Padding TLV, and at most one Bit Pattern and one burst TLV. | Descriptive | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-2 | Add an Extra Padding TLV whenever a Bit Pattern TLV is added. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-3 | The Bit Pattern TLV contains the pattern used in the Extra Padding TLV. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-4 | The padding length is an integer multiple of the pattern length. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-5 | Add an Extra Padding TLV whenever a Bit Error Count TLV is added. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-6 | The sender sets the bit error count to zero. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1-7 | On a reply with U set on the BER TLVs, the sender disables BER and continues other measurements. | Descriptive | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.1.1-1 | Without a Bit Pattern TLV, both ends use the default pattern 0xFF00. | Descriptive | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2-1 | Check the padding against the pattern and count mismatched bits. | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2-2 | Write the bit error count into the reflected Bit Error Count TLV (zero when there are none). | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2-3 | Write the longest run of mismatched bits into the reflected burst TLV. | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2-4 | Correct the padding to the pattern and reflect it for reverse-direction BER. | Descriptive | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2-5 | A reflector that does not recognize a BER TLV returns it with U set. | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2.1-1 | Set C on the BER TLVs when the Extra Padding TLV is missing or duplicated. | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2.1-2 | Set C on the BER TLVs when any BER type is duplicated. | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.2.1-3 | Set C on the Bit Pattern TLV when the padding is not a multiple of the pattern length. | MUST | Reflector | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.3-1 | The procedure applies to each member link of a LAG, using RFC 9534 micro-sessions. | Descriptive | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-4.3-2 | Use padding that matches the link MTU. | RECOMMENDED | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-5.1-1 | Bit Pattern TLV: variable-length pattern. | MUST (implied, structural) | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-5.2-1 | Bit Error Count TLV: Length 4. | MUST (implied, structural) | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-5.3-1 | Maximum Bit Error Burst Size TLV: Length 4. | MUST (implied, structural) | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-6.1-1 | Configuration allows padding size, pattern and transmit interval. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-6.1-2 | Configuration allows the computation interval as a multiple of the transmit interval. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-6.2-1 | Report received packets and packets with errors, per direction. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-6.2-2 | Report padding bits and bit error totals, per direction. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-6.2-3 | Report maximum and average burst sizes, per direction. | MUST | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-6.2-4 | Thresholds on bit errors and errored packets per million raise alarms. | Descriptive | Sender | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-7-1 | RFC 8762 and RFC 8972 security considerations apply, including HMAC protection. | Descriptive | Both | Excluded (retired legacy profile) | Legacy wire support is retired. Types 240–242 receive U; current successor behavior and pending evidence are described in the [migration guide](../ber-migration.md). |
| ber-9-1 | IANA allocates the three TLV types. | Descriptive (IANA) | N-A | N-A | Registry action is external. See [scope](#scope) for the local experimental types. |
