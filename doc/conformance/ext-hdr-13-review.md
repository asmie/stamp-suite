# Extension-header draft -13 adoption review (2026-09-11)

The revision monitor found
[draft-ietf-ippm-stamp-ext-hdr-13](https://datatracker.ietf.org/doc/html/draft-ietf-ippm-stamp-ext-hdr-13)
(9 September 2026). The implementation and 40-row
[matrix](draft-stamp-ext-hdr.md) remain frozen at
[-11](https://datatracker.ietf.org/doc/html/draft-ietf-ippm-stamp-ext-hdr-11).
The release-evidence checkpoint compares the documents; it does not claim -13
adoption or silently relabel the old clauses.

| Delta from -11 | Current implementation / release implication |
| --- | --- |
| New §3.1 IP/UDP header requirements, including source-port recommendations, direction disambiguation and TTL/Hop Limit 255 | On Linux/macOS, sender `--ttl 255` and suitable local ports can be configured; the CLI retains its previous defaults and permits lower TTL values. That sender option does not establish a reflector TTL policy. A new-profile configuration/validation audit and wire regressions are needed before claiming these requirements. |
| New §6 UDP checksum policy, including narrowly constrained zero-checksum operation | Normal UDP sockets retain OS checksum behavior. No IPv6 zero-checksum mode is exposed. Supporting that optional mode would require its full endpoint, integrity, rate and middlebox constraints, not merely disabling a checksum. Pnet receive-side handling must be audited separately from the kernel UDP path. |
| New §7.1 idle/active/failed notifications, with a configured consecutive-loss threshold and recovery | Existing aggregate loss counters and final/periodic summaries do not implement that notification state machine. This is an additional behavior gap against -13. |
| Expanded §7.2 rate-limiting considerations | Rate/cap and queue controls exist; claims about policing relative to offered traffic and notification correlation need a new-profile review. |
| Section renumbering and new references | The prior §§3.1/3.2/3.3 become §§3.2/3.3/3.4; the old operational/security sections move. Existing -11 citations are explicitly revision-bound and must not be mechanically renumbered while retaining old requirement text. |

Release decision: retain the documented -11 profile and experimental code
points. The standards monitor reports the difference as **review needed** (exit
1). A release must not claim complete -13 conformance based on the unchanged
-11 scores. Adoption is additional protocol work beyond the original sixteen
findings and eleven optimization checkpoints; the newly identified requirements
are recorded here for a separate scope decision. No clause scores are changed.

The raw -11/-13 source texts, textual diff and public metadata are retained with
the O11 review artifacts. The new normative text is materially different, so
this drift is not treated as a stale citation that can be repaired by changing
a version number alone.
