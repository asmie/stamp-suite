# Header reflection draft 26 clarification request

Prepared for `draft-ietf-ippm-stamp-ext-hdr@ietf.org`. Maintainer submission is
pending. Source: [revision 26](https://www.ietf.org/archive/id/draft-ietf-ippm-stamp-ext-hdr-26.txt),
Sections 4.1, 4.2, 6.1 and 6.2.

Subject: Repeated nonzero selectors for indistinguishable headers in revision 26

Sections 4.2 and 6.2 describe requesting every equal-length header with identical
Requested-field prefixes by repeating the corresponding TLV in packet order.
Their numbered rule 1 nevertheless requires C, with no copying, whenever a
nonzero selector matches more than one unselected header. The inability cases
in Sections 4.1 and 6.1 also require C for an ambiguous nonzero selector.

For two equal-length headers A and B with identical prefixes but different tails,
two nonzero requests S,S therefore both receive C under rule 1: the first request
consumes neither header, so the second is equally ambiguous. Two all-zero
requests instead return A and B in order. A zero request followed by S also
succeeds because only B remains eligible.

Should complete ordered groups of identical nonzero selectors override the
ambiguity rule? If so, how should incomplete groups be handled? Alternatively,
should the all-header example explicitly require all-zero Requested fields?

stamp-suite currently applies numbered rule 1 and records the repeated-nonzero
example as Partial pending clarification. The same question applies to both
Type TBA1 and Type TBA2.
