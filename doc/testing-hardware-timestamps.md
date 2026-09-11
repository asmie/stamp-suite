# Hardware timestamp verification on a two-host testbed

This procedure verifies actual NIC timestamp delivery, not just advertised
capability or a successful `--hwtstamp on` startup. It requires Linux, two
timestamp-capable NICs, an approved clock-synchronization setup and privileges
to configure the test NIC. Ordinary loopback and virtual NICs cannot substitute.
See Linux's [timestamping interfaces](https://docs.kernel.org/networking/timestamping.html)
for the distinction between software, transformed and raw hardware timestamps.

1. Record the commit, `rustc -Vv`, build features, kernel, NIC model/firmware,
   driver, interface addresses/MTU and route on both hosts. Save `ethtool -i
   <interface>` and `ethtool -T <interface>`. Require hardware transmit/receive
   support and a PHC for any claimed hardware direction. Save current hardware
   timestamp filter settings using the installed NIC/driver tooling before
   starting the test; `--hwtstamp on` may change shared NIC filters.
2. Record the PHC/system-clock synchronization method, time scale, UTC offset
   and measured error on both hosts. Use the testbed's established clock
   discipline; this procedure does not configure or step clocks. Raw NIC T2
   can be in a different domain from software T3. The CLI's synchronization
   declaration is not evidence that these clocks are aligned.
3. Build `cargo build --locked --release --features ttl-nix,hwtstamp` and retain
   the executable SHA-256 on both hosts. Choose concrete local addresses, a
   shared temporary test key file (mode 0600), SSID 42 and unused test ports.
   Start an independent packet capture on the physical link. Preserve both
   endpoint logs and the pcap; local offload capture can show unfinished UDP
   checksums, so verify checksum claims at a capture point after offload.
4. On the reflector, substituting the testbed's actual address and key path:

   ```sh
   sudo ./target/release/stamp-suite --is-reflector \
     --local-addr 192.0.2.2 --local-port 20862 --stateful-reflector \
     --auth-mode A --hmac-key-file /tmp/stamp-test.key \
     --clock-source NTP --hwtstamp on \
     > reflector.stdout 2> reflector.stderr
   ```

   On the sender, after the reflector is ready:

   ```sh
   sudo ./target/release/stamp-suite \
     --local-addr 192.0.2.1 --local-port 20863 \
     --remote-addr 192.0.2.2 --remote-port 20862 --ssid 42 \
     --auth-mode A --hmac-key-file /tmp/stamp-test.key \
     --clock-source NTP --hwtstamp on --timestamp-info --follow-up-telemetry \
     --count 100 --send-delay 20 --timeout 3 --output-format json -R \
     > sender.jsonl 2> sender.stderr
   ```

   These documentation addresses must be replaced. Declare synchronized clocks
   only if independently established; the command's defaults intentionally do
   not assert synchronization. Repeat with `--clock-source PTP`, and repeat
   open mode if claiming it. Use IPv6 addresses for separate IPv6 evidence.
5. Check every accepted reply's base/TLV HMAC independently. Decode the Type 3
   Timestamp Information and Type 7 Follow-Up values from wire bytes. Require
   actual RX `HwAssist` reports (method 1) for a hardware-RX claim; the current
   reflector T3 remains software-generated. Require later Follow-Up reports of
   method 1, correctly correlated with previous reflector sequences, for a
   hardware-TX claim. Methods 2/3 or an enabled socket alone do not prove NIC
   delivery. Startup can fall back to software; report fallback or unavailable
   directions explicitly. Retain per-method counts rather than a single success
   label if delivery is mixed.
6. Run a software control with `--hwtstamp off`, then a kernel-software control
   with `--hwtstamp auto`. Compare counts, wire flags, timing domains and packet
   sequences. Exact timestamp values need not match across runs. A hardware
   claim requires hardware-marked observations beyond the software controls;
   plausible delay numbers alone are insufficient. Correlate reverse-delay
   calculations only where clock-domain alignment and quality are established.
7. Stop only the test processes/capture and restore the saved NIC timestamp
   settings using the testbed's driver tooling. Save exit statuses and a result
   record containing requested versus observed RX/TX methods, sample counts,
   failures/fallbacks, synchronization evidence, raw artifacts and their hashes.

O11 local availability result (2026-09-11): WSL2 `eth0` advertised only
software-transmit, software-receive and software-system-clock; PHC and hardware
filter/transmit modes were absent. This is **hardware unavailable**, not a pass
or an internally skipped hardware test. The ordinary kernel timestamp and
Follow-Up regressions remain separate software evidence.
