# Statistics precision and retention

RTT and OWD summaries count first replies to pending probes. The
[reply collector](measurements.md) also tracks burst copies, duplicates, and late
replies. Reporting never resets the delay collectors. Each uses a 64-bit count
and stops accepting observations at `u64::MAX`.

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

[Clock-quality metadata](measurements.md#clock-quality-accompanying-delay)
is independent of quantile precision.

## Cumulative moments

Counts, extrema, sums and the sum of successive absolute RTT differences use
integer accumulators over the complete series. Means are converted to floating
point at snapshot time. Population standard deviation uses an online Welford
update, centered on the first integer RTT before conversion to floating point.
This preserves small spreads on a large common baseline. Floating-point variance remains subject to
rounding for very large spreads or observation counts.

`jitter_ms` is the mean absolute difference between successive RTTs in receive
order and requires at least two samples. The SNMP smoothed RTT-variation metric
uses a separate calculation.

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
