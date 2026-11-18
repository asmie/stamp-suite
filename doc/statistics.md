# Statistics precision and retention

How precise the delay figures are, and how much history the sender keeps
during long or high-rate runs.

RTT and OWD summaries count the first reply to each pending probe. The
[reply collector](measurements.md) also tracks burst copies, duplicates and
late replies. Reports never reset the delay collectors. Each collector keeps a
64-bit count and stops taking new observations once the count reaches
`u64::MAX`.

## Quantiles

RTT, forward OWD and reverse OWD each keep exact samples for the first 4096
observations. For percentile `p`, the sender picks the zero-based rank
`round(p / 100 * (n - 1))`. With an even number of samples the median is
therefore the upper of the two middle values. Percentiles outside 0 to 100 are
clamped, and NaN selects the minimum. A snapshot sorts a single copy of the
RTT samples and uses it for the median, p95 and p99. Each OWD median sorts its
own series once.

On the 4097th observation the series is converted into a fixed logarithmic
histogram that includes every earlier observation. Nothing is sampled, there
is no sliding window, and old delays are never evicted. A snapshot walks the
histogram once for all the RTT quantiles it needs. It does not allocate or
sort a sample array.

Each bucket keeps the eight most significant bits of the value. Values from 0
to 255 ns are exact, and above that the bucket width doubles at each power of
two. For example, 1,000,000 ns falls in the 999,424–1,003,519 ns bucket, which
reports 999,424 ns. Signed OWD uses mirrored buckets in signed numerical order
and rounds toward zero, so the same delay with a negative sign reports
−999,424 ns.

For an exact order statistic `x != 0`, the histogram value is off by less than
`abs(x) / 128` (0.78125%). The rank itself does not change. Zero and the
extreme ranks stay exact. Reported values are clamped to the observed minimum
and maximum, so a constant series is reported exactly. This limit covers
bucket quantization only. It says nothing about timestamp accuracy or
statistical uncertainty, and output formatting can round further.

JSON reports the policy as `exact_sample_limit = 4096` and
`relative_error_bound = 0.0078125` in `QuantilePrecision`, OWD summaries
included. Text reports print the policy. CSV has
`quantile_exact_sample_limit` and `quantile_relative_error_bound` columns
before the BER, measurements and OWD columns. Each series switches to the
histogram on its own, so a short series is always exact.

[Clock-quality metadata](measurements.md#clock-quality-accompanying-delay)
is separate from quantile precision.

## Cumulative moments

Counts, minimum and maximum, sums, and the sum of absolute differences between
successive RTTs are kept in integer accumulators over the whole series. Means
are converted to floating point when a snapshot is taken. The population
standard deviation uses Welford's online update. Each RTT is offset by the
first RTT while still an integer and only then converted to floating point,
so a small spread on top of a large common baseline does not lose precision.
The floating-point variance can still round when the spread or the number of
observations is very large.

`jitter_ms` is the mean absolute difference between successive RTTs in the
order they were received. It needs at least two samples. The SNMP smoothed
RTT-variation metric is calculated separately.

## Memory and BER history

Each exact delay series holds at most 4096 eight-byte values. The RTT
histogram has 7424 eight-byte counters, and each signed OWD histogram has
14593. Together the histograms take 292,880 bytes (about 286 KiB) however
long the run lasts. During conversion the old 32 KiB series is still held
while its histogram is allocated. Exact snapshots use one scratch array of at
most 32 KiB at a time. Scalar collector state and allocator bookkeeping come
on top. These figures cover the delay collectors only, not the whole process
or the tables of pending packets and sessions.

BER keeps lifetime totals for each direction apart from its history. The
history holds up to 1024 completed nonempty intervals and 1024 alarms,
and drops the oldest record when full. `intervals_omitted` and
`alarms_omitted` count those drops. A snapshot can also include the current
partial interval if it is not empty, so it holds at most 1025 interval
records. Taking a snapshot does not consume or evict anything from the
collector. Empty intervals are never recorded and do not count as drops.

Threshold state carries on across drops, and every new threshold crossing is
still logged. Text reports show the omission counts when they are nonzero.
JSON and the quoted BER object in CSV always include them. If you need a
longer history, save the periodic reports and alarm logs somewhere else. When
you combine snapshots, remove intervals and alarms that appear in more than
one.

## Report output and pending probes

`StatsOutput` formats and writes reports on a shared thread through a 64 KiB
buffer, which it flushes after each report. The sender reserves a queue slot
before it calculates a snapshot and copies its history, so an interim report
that gets skipped costs nothing.

The queue holds up to eight pending reports or text packet-detail lines, plus
the one being written. All targets share it. When it is full, new interim
reports and detail lines are skipped and a throttled diagnostic is logged.
Final reports wait for space instead of being dropped. If queueing and
flushing a final report take longer than five seconds, the run returns an
output error. A closed pipe also returns an error rather than a panic. The
writer has its own stdout descriptor, so a blocked write cannot keep the
process from exiting. The writer thread itself can stay blocked until the
reader resumes or the process exits.

`-R` prints per-packet RTT details as replies arrive. In text mode these lines
go through the same queue. In JSON and CSV mode they go to stderr. The final
summary still contains the cumulative measurements when interim reports were
skipped, within the BER history limits above.

Pending probes have their own retention. `--timeout 0` turns off
timed expiry, and with the default `--max-pending-probes 0` every lost reply
then stays in the pending table, which can grow without limit. Set
`--max-pending-probes N` to keep at most N unanswered records per target.
The ordered index of live records and its generation lookup then hold at most
N entries each. Records are aged by the order of successful sends, so tied
timestamps and 32-bit sequence wrap do not confuse which record is oldest.
With a limit set, a generation is removed as soon as it is answered or
retired, and no expiry queue keeps it around. Without a limit, neither index
exists and the sender uses the time-based expiry queue. Each record stores the
send time, the wire T1 as sent, and the measurement T1, which kernel TX
timestamping can correct. Hash map overhead, tree nodes and allocator
bookkeeping come on top of that.

The limit does not pause sending or make up timed expirations. When a
successful send needs room, the oldest record is retired and counted as lost.
Reusing the sequence number of an outstanding probe retires its old
generation the same way. `measurements.pending_evictions` counts these
retirements apart from timed loss and history eviction. The other `pending_*`
fields report the limit, the current number of records and the peak. Text
reports and the JSON in the CSV `measurements` column show the same fields.
Records still pending at the end of the run count as lost, once. Late replies
are handled as described in
[measurement semantics](measurements.md#probes-reply-copies-and-duplicates).

With `--timeout 0` the failure monitor keeps no per-probe timeout window, so
the limit removes the last way for the pending table to grow forever. With a
nonzero timeout, the monitor keeps its own window of at most send rate ×
timeout entries, which it needs to detect failure and recovery. The limit does
not cap the memory or RSS of the whole process. Collectors, reporting, the
kernel and per-target resources are separate.
