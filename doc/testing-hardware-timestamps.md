# Hardware timestamp verification on a two-host testbed

This procedure checks that a NIC delivers hardware timestamps to stamp-suite.
It needs two Linux hosts with timestamp-capable NICs and synchronized clocks.
Judge the timestamps that arrive, not what the NIC reports it can do. Loopback
and virtual NICs cannot show delivery from a physical NIC. See the
Linux [timestamping interfaces](https://docs.kernel.org/networking/timestamping.html)
for the kernel side and
[Hardware-assisted timestamping](architecture.md#hardware-assisted-timestamping)
for how stamp-suite uses them.

1. On both hosts, record the commit, `rustc -Vv`, the build features, the
   kernel, the NIC model and firmware, the driver, the interface addresses and
   MTU, and the route. Save the output of `ethtool -i <interface>` and
   `ethtool -T <interface>`. For every direction you want to claim as
   hardware-timestamped, the NIC must report hardware transmit or receive
   support and a PHC. Before you start, save the current hardware timestamp
   filter settings with the NIC or driver tooling. `--hwtstamp on` may change
   filters that are shared with other users of the NIC.
2. On both hosts, record how the PHC and the system clock are synchronized,
   the time scale, the UTC offset and the measured error. Use the clock
   discipline the testbed already has. This procedure does not configure or
   step clocks. Raw NIC T2 can be in a different clock domain from software T3.
   Declaring synchronized clocks on the command line does not show that the
   clocks are aligned.
3. Build with `cargo build --locked --release --features hwtstamp` and record
   the SHA-256 of the executable on both hosts. Pick concrete local addresses,
   a temporary test key file shared by both hosts (mode 0600), SSID 42 and
   unused test ports. Start a separate packet capture on the physical link.
   Keep both endpoint logs and the pcap. A capture taken on the host before
   checksum offload can show UDP checksums that are not filled in yet, so check
   checksums at a capture point after the offload.
4. On the reflector, with the testbed's real address and key path in place of
   the examples:

   ```sh
   sudo ./target/release/stamp-suite --is-reflector \
     --local-addr 192.0.2.2 --local-port 20862 --stateful-reflector \
     --auth-mode A --hmac-key-file /tmp/stamp-test.key \
     --clock-source NTP --hwtstamp on \
     > reflector.stdout 2> reflector.stderr
   ```

   On the sender, once the reflector is ready:

   ```sh
   sudo ./target/release/stamp-suite \
     --local-addr 192.0.2.1 --local-port 20863 \
     --remote-addr 192.0.2.2 --remote-port 20862 --ssid 42 \
     --auth-mode A --hmac-key-file /tmp/stamp-test.key \
     --clock-source NTP --hwtstamp on --timestamp-info --follow-up-telemetry \
     --count 100 --send-delay 20 --timeout 3 --output-format json -R \
     > sender.jsonl 2> sender.stderr
   ```

   The commands keep the defaults, which do not claim synchronized clocks. Add
   `--clock-synchronized` only if you have established synchronization by
   other means.
   Repeat with `--clock-source PTP`, and repeat in open mode if you want to
   claim it too. Use IPv6 addresses to collect separate IPv6 evidence.
5. Verify the base and TLV HMAC of every accepted reply with your own tool, not
   with stamp-suite. Decode the Type 3 Timestamp Information and Type 7
   Follow-Up values from the wire bytes. A hardware-RX claim needs actual RX
   `HwAssist` reports (method 1). The reflector's T3 is currently generated in
   software. A hardware-TX claim needs later Follow-Up reports with method 1
   that match the earlier reflector sequence numbers correctly. Methods 2 and
   3, or a socket that merely has timestamping enabled, do not prove NIC
   delivery. At startup the reflector can fall back to software timestamps.
   Report every direction that fell back or was unavailable. If delivery is
   mixed, give a count per method instead of a single pass label.
6. Run a software control with `--hwtstamp off`, then a kernel software control
   with `--hwtstamp auto`. Compare counts, wire flags, timing domains and packet
   sequences. Exact timestamp values do not have to match between runs. A
   hardware claim needs hardware-marked observations that the software controls
   do not produce. Plausible delay numbers are not enough. Correlate
   reverse-delay calculations only where you have shown that the clock domains
   are aligned and how good that alignment is.
7. Stop only the test processes and the capture, then restore the saved NIC
   timestamp settings with the testbed's driver tooling. Save the exit statuses
   and a result record. It should list the requested and observed RX/TX
   methods, sample counts, failures and fallbacks, the synchronization
   evidence, and the raw artifacts with their hashes.

