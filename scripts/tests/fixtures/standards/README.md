# Standards metadata fixtures

`ber-replacement/` retains the fields consumed from the IETF responses observed
on 8 November 2026. It covers the two-hop replacement chain from
`draft-gandhi-ippm-stamp-ber-07`, through `draft-ietf-ippm-stamp-ber-01`, to
`draft-ietf-bpm-stamp-ber-01`.

Document fields come from `/doc/<name>/doc.json`; relationships come from
`/api/v1/doc/relateddocument/?relationship=replaces&target__name=<name>` on
`https://datatracker.ietf.org`. Unused metadata is omitted. Tests modify copies
or construct separate responses for malformed metadata, cycles, branches,
traversal bounds, publication and watch-only behavior.
