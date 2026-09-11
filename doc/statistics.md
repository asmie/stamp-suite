# Statistics precision and retention

The original sender RTT/OWD summaries cover first replies to pending probes.
[Reply and directional summaries](measurements.md) additionally account for
burst copies, duplicates and late replies. Delay summaries retain their
accepted measurements across the run. Reporting
never resets the collectors. RTT and OWD each use a 64-bit observation count;
collection stops at `u64::MAX` observations rather than wrapping. Existing sender
wire sequence numbers, send/loss counters and reflector session counters retain
their existing widths and semantics.

## Quantiles

Each of RTT, forward OWD and reverse OWD keeps exact samples through 4096
observations. For a percentile `p`, the selected zero-based rank is
`round(p / 100 * (n - 1))`. This preserves the existing upper median for an even
sample count. Out-of-range percentiles are clamped; NaN selects the minimum.
RTT median/p95/p99 share one sorted copy per snapshot. Each OWD median sorts its
own bounded series once.

The 4097th observation converts that series, including every prior observation,
into a fixed logarithmic histogram. No sampling, sliding window or old-delay
eviction occurs. A snapshot visits the histogram once for all requested RTT
quantiles; it does not allocate or sort a sample array.

Magnitude buckets retain the eight most significant bits. Values 0–255 ns are
exact; larger bucket widths double at powers of two. For example, 1,000,000 ns
falls in the 999,424–1,003,519 ns bucket. Its representative is 999,424 ns.
Signed OWD uses mirrored buckets in signed numerical order, rounding toward
zero. The same magnitude example for a negative delay yields −999,424 ns.

For an exact selected order statistic `x != 0`, histogram value error is strictly
less than `abs(x) / 128`, or **0.78125% of its magnitude**. The rank is unchanged;
only the value is quantized. Zero and the minimum/maximum ranks remain exact,
and representatives are clamped to the observed extrema, so constant series
remain exact too. This is a deterministic value-error bound, not a confidence
interval or a bound on timestamp accuracy. JSON floating-point and decimal text/
CSV formatting can introduce additional rounding at the displayed precision.

`QuantilePrecision` discloses `exact_sample_limit = 4096` and
`relative_error_bound = 0.0078125` in JSON, including standalone OWD summaries.
Text prints the same policy. CSV adds `quantile_exact_sample_limit` and
`quantile_relative_error_bound` before the BER, measurements and OWD clock-quality JSON columns. This policy applies
independently to each series, even if RTT and usable OWD counts differ. It is a
conservative bound: it does not imply short series have been approximated.

Rust API changes: `StatsSnapshot::packets_received` and `OwdSummary::samples`
are now `u64`; both summary structs carry `quantile_precision`. `BerSummary`
uses `VecDeque` for interval/alarm history and adds the two omission counters.
Consumers constructing these public structs directly must supply the new fields.
`OwdSummary` additionally carries `clock_quality`. Use `OwdCollector::record_with_quality`
to attach endpoint estimates; the plain `record` API counts metadata as unknown.
[Clock-quality semantics](measurements.md#clock-quality-accompanying-delay) apply
independently of the quantile approximation policy.

## Cumulative moments

Counts, extrema, sums and the sum of successive absolute RTT differences use
integer accumulators over the complete series. Means are converted to floating
point at snapshot time. Population standard deviation uses an online Welford
update, centered on the first integer RTT before conversion to floating point.
This avoids overflowing the old sum of squared nanoseconds and preserves small
spreads on a large common baseline. Floating-point variance remains subject to
rounding for very large spreads or observation counts.

The existing `jitter_ms` field is the mean absolute difference between successive
RTTs in receive order. It requires at least two RTT samples. Earlier source
comments attributed this arithmetic mean to RFC 3550; that attribution was
incorrect. [RFC 3550 §6.4.1](https://www.rfc-editor.org/rfc/rfc3550.html#section-6.4.1)
defines an exponentially smoothed RTP transit-time estimator. This change
preserves the sender summary metric and corrects its description. The separate
SNMP smoothed RTT-variation metric retains its existing behavior.

## Memory and BER history

At most 4096 eight-byte values are retained per exact delay series. The RTT
histogram has 7424 eight-byte counters; each signed OWD histogram has 14593.
Combined histogram storage is **292,880 bytes** (about 286 KiB), independent of
run length. Conversion briefly retains the old 32 KiB series while allocating
its histogram; exact snapshots use at most a 32 KiB scratch array at a time.
Scalar collector state and allocator bookkeeping are additional. These bounds
cover delay collectors, not the entire process or pending packet/session tables.

BER keeps lifetime directional totals separately from history. Its deques retain
up to **1024 completed nonempty intervals** and **1024 alarms**, evicting the
oldest records. `intervals_omitted` and `alarms_omitted` count evictions. A snapshot
can additionally contain the current nonempty partial interval, for at most
1025 interval records; it does not consume or evict collector history. Empty
intervals remain omitted by policy and do not increment the eviction counter.

Threshold state continues across evictions, and every new threshold crossing
still produces a log event. Text reports nonzero omission counts; JSON and the
quoted CSV BER object always contain them. Save periodic reports and alarm logs
externally when longer retention is needed; deduplicate interval/alarm identities
when combining snapshots. Existing `-R` packet output can stream RTT details.

## Local optimization evidence

The O05 comparison runs the committed `9e16824` collectors and the new collectors
in the same release binary, using deterministic RTT and signed OWD data. Three
trials alternate implementation order, warm one snapshot, then time repeated
snapshots. Tracking the system allocator measures requested heap bytes, excluding
allocator bookkeeping and stack. Timings are medians on a shared WSL2 workstation.

| Samples per series | Retained heap before / after | Snapshot before / after |
| --- | --- | --- |
| 1,000 | 32,768 / 24,576 bytes | 22.6 / 11.0 µs |
| 4,096 | 131,072 / 98,304 bytes | 103.0 / 67.1 µs |
| 100,000 | 4,194,304 / 292,880 bytes | 5.17 ms / 12.3 µs |
| 1,000,000 | 33,554,432 / 292,880 bytes | 66.45 ms / 8.4 µs |

Recording one million samples per series took 18.60 ms before and 19.80 ms after
(about 6% slower). Quantile accuracy changes after 4096 observations as disclosed
above. These are collector measurements, without serialization, BER, socket
traffic or concurrent reporting; they establish no network throughput or
cross-platform speedup. [Raw data, harness and metadata](reviews/2026-09-08/logs/optimization-o05/profile-results.json)
are retained with the review evidence.

To reproduce, copy the archived `baseline-stats.rs` to
`/tmp/stamp-o05-baseline-stats.rs`, copy `stats-profile.rs` from the same evidence
directory to `examples/o05_stats_profile.rs`, and run
`cargo run --locked --release --example o05_stats_profile`. Remove the temporary
example afterward. The harness checks that collector allocations are released.
