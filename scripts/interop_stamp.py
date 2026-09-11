#!/usr/bin/env python3
"""Independent Linux UDP fixture runner; uses only Python's standard library.

Wire layouts and the deliberately narrow test profile are documented in
doc/testing-interop.md. No stamp-suite encoders, parsers or crypto are imported.
"""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import hmac
import itertools
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests/fixtures/interop/requests.json"
KEYS = {42: bytes.fromhex("ab" * 16), 43: bytes.fromhex("cd" * 16),
        99: bytes.fromhex("ef" * 16)}


class WireError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise WireError(message)


def digest(key, data):
    return hmac.digest(key, data, "sha256")[:16]


def tlv(kind, value):
    return struct.pack("!BBH", 0x80, kind, len(value)) + value


def request(ip, auth, sender_clock, ssid, burst):
    """Fixed timestamps intentionally test echo/format, not measured latency."""
    base = bytearray(112 if auth else 44)
    struct.pack_into("!I", base, 0, 7 if burst else 8)
    timestamp = 16 if auth else 4
    struct.pack_into("!IIHH", base, timestamp, 0x12345678, 123456789,
                     0x4001 if sender_clock == "PTP" else 1, ssid)
    extensions = b""
    if burst:
        extensions += tlv(12, struct.pack("!HHII", 0, 3, 120_000_000, 0))
        extensions += tlv(4, bytes([184, 0, 0, 0]))
        extensions += tlv(5, struct.pack("!III", 1, 0, 0))
        extensions += tlv(7, bytes(16))
        extensions += tlv(9, socket.inet_pton(socket.AF_INET6 if ":" in ip
                                            else socket.AF_INET, ip))
        # Forwarding is disabled in this profile: the reply must carry U=1.
        extensions += tlv(10, tlv(4, socket.inet_pton(socket.AF_INET6, "::1")))
    if auth:
        base[96:112] = digest(KEYS[ssid], base[:96])
    # Exercise keyed TLVs in BOTH authentication modes, using per-SSID/default keys.
    extensions += tlv(8, digest(KEYS[ssid], base[:4] + extensions))
    return bytes(base) + extensions


def make_vectors():
    return {"schema_version": 1, "profile": "loopback-burst-fallback-v1",
            "vectors": [
                {"id": f"ipv{6 if ':' in ip else 4}-{'auth' if auth else 'open'}-"
                       f"{clock.lower()}-ssid{ssid}",
                 "ip": ip, "auth": auth, "sender_clock": clock, "ssid": ssid,
                 "burst_hex": request(ip, auth, clock, ssid, True).hex(),
                 "ordinary_hex": request(ip, auth, clock, ssid, False).hex()}
                for ip, auth, clock, ssid in itertools.product(
                    ("127.0.0.1", "::1"), (False, True), ("NTP", "PTP"), KEYS)]}


def parse_tlvs(data, start):
    """Strict for this fixture profile: no padding, duplicate or trailing TLVs."""
    result = {}
    while start < len(data):
        require(start + 4 <= len(data), "truncated TLV header")
        flags, kind, size = struct.unpack_from("!BBH", data, start)
        end = start + 4 + size
        require(end <= len(data), "truncated TLV value")
        require(kind not in result, "duplicate TLV")
        result[kind] = (flags, data[start + 4:end], start)
        start = end
    return result


def verify_reply(data, sent, vector, clock, stateful, ordinal, tos, peer,
                 target, burst, received_count=0, previous=None, first=None):
    auth, ssid = vector["auth"], vector["ssid"]
    base, t3, t2, echo, error = ((112, 16, 32, 48, 24) if auth
                                else (44, 4, 16, 24, 12))
    require(len(data) == len(sent), "reply size differs from fixture")
    require(peer[:2] == target[:2], "reply source address/port differs")
    require(tos == (184 if burst else 0), "wrong IP traffic class")
    require(data[:4] == (struct.pack("!I", ordinal) if stateful else sent[:4]),
            "wrong reflector sequence")
    require(data[error + 2:error + 4] == struct.pack("!H", ssid), "wrong SSID")
    require(bool(data[error] & 0x40) == (clock == "PTP"), "wrong reflector clock")
    require(data[echo:echo + 4] == sent[:4], "wrong echoed sequence")
    echo_ts = 64 if auth else 28
    require(data[echo_ts:echo_ts + 10] == sent[t3:t3 + 10],
            "wrong echoed sender timestamp/error estimate")
    require(any(data[t2:t2 + 8]) and any(data[t3:t3 + 8]), "zero T2/T3")
    if clock == "PTP":
        for offset in (t2, t3):
            require(struct.unpack_from("!I", data, offset + 4)[0] < 1_000_000_000,
                    "invalid PTP nanoseconds")
    if auth:
        require(hmac.compare_digest(data[96:112], digest(KEYS[ssid], data[:96])),
                "invalid base HMAC")
    fields = parse_tlvs(data, base)
    expected = [12, 4, 5, 7, 9, 10, 8] if burst else [8]
    require(list(fields) == expected, "missing/reordered/unexpected TLV")
    for kind, (flags, _, _) in fields.items():
        require(flags == (0x80 if kind == 10 else 0), f"wrong Type {kind} flags")
    _, mac, offset = fields[8]
    require(len(mac) == 16 and hmac.compare_digest(
        mac, digest(KEYS[ssid], data[:4] + data[base:offset])), "invalid TLV HMAC")
    if burst:
        original = parse_tlvs(sent, base)
        for kind in (9, 10, 12):
            require(fields[kind][1] == original[kind][1], f"changed Type {kind} value")
        require(fields[4][1] == bytes([184, 0, 0x30, 0]), "wrong CoS report")
        require(fields[5][1] == struct.pack("!III", 1, received_count, ordinal),
                "wrong Direct Measurement counters")
        follow = fields[7][1]
        require(len(follow) == 16, "wrong Follow-Up size")
        if stateful and previous is not None:
            require(follow[:12] == previous[:4] + previous[t3:t3 + 8],
                    "wrong Follow-Up sequence/timestamp")
            require(follow[12:] == bytes([2, 0, 0, 0]), "wrong Follow-Up method")
        else:
            require(follow[:12] == bytes(12), "nonzero initial/stateless Follow-Up")
        if first is not None:
            require(data[t2:t2 + 8] == first[t2:t2 + 8], "burst T2 changed")
            require(data[t3:t3 + 8] > previous[t3:t3 + 8], "burst T3 did not advance")


def udp(ip, timeout=2):
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                         socket.SOCK_DGRAM)
    try:
        sock.bind((ip, 0))
        sock.settimeout(timeout)
        if ":" in ip:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)
        else:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
        return sock
    except BaseException:
        sock.close()
        raise


def receive(sock, records):
    data, ancillary, flags, peer = sock.recvmsg(4096, 128)
    classes = []
    for level, kind, value in ancillary:
        if level == socket.IPPROTO_IP and kind == socket.IP_TOS:
            classes.append(value[0])
        elif level == socket.IPPROTO_IPV6 and kind == socket.IPV6_TCLASS:
            classes.append(struct.unpack("=i", value)[0])
    record = {"direction": "rx", "hex": data.hex(), "peer": list(peer),
              "traffic_class": classes, "recvmsg_flags": flags}
    records.append(record)
    require(flags == 0, "truncated datagram/ancillary data")
    require(len(classes) == 1, "missing/ambiguous traffic class metadata")
    return data, classes[0], peer


def send(sock, data, target, records):
    sock.sendto(data, target)
    records.append({"direction": "tx", "hex": data.hex(), "peer": list(target)})


@contextlib.contextmanager
def reflector(binary, ip, auth, clock, stateful, directory, result):
    with udp(ip) as reserve:
        target = reserve.getsockname()
    keys = directory / "keys"
    keys.mkdir(mode=0o700)
    for name, ssid in (("002a.key", 42), ("002b.key", 43), ("default.key", 99)):
        path = keys / name
        path.write_text(KEYS[ssid].hex(), encoding="ascii")
        path.chmod(0o600)
    command = [str(binary), "--is-reflector", "--local-addr", "::" if ":" in ip else "0.0.0.0",
               "--local-port", str(target[1]), "--auth-mode", "A" if auth else "O",
               "--clock-source", clock, "--hmac-key-dir", str(keys),
               "--reflected-control-max-count", "3", "--hwtstamp", "off"]
    if stateful:
        command.append("--stateful-reflector")
    result["command"] = command
    with (directory / "stderr.log").open("w+") as log:
        environment = {**os.environ, "TOKIO_WORKER_THREADS": "2"}
        environment.pop("STAMP_HMAC_KEY", None)
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log,
                                   env=environment)
        try:
            # Keep this endpoint reserved throughout the case: its state must
            # never be reused by a measured exchange.
            with udp(ip, 0.05) as warmup:
                deadline = time.monotonic() + 5
                while True:
                    require(process.poll() is None, "reflector exited during startup")
                    warmup.sendto(request(ip, auth, "NTP", 42, False), target)
                    try:
                        warmup.recvfrom(4096)
                        break
                    except TimeoutError:
                        require(time.monotonic() < deadline, "reflector startup timeout")
                yield target
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log.seek(0)
            result["reflector_stderr"] = log.read()


def exercise(binary, vectors, ip, auth, clock, stateful, result):
    sender_clock = "PTP" if clock == "NTP" else "NTP"
    with tempfile.TemporaryDirectory(prefix="stamp-interop-") as temporary:
        with reflector(binary, ip, auth, clock, stateful, Path(temporary), result) as target:
            for vector in vectors:
                if (vector["ip"], vector["auth"], vector["sender_clock"]) != (ip, auth, sender_clock):
                    continue
                records = []
                result["exchanges"].append({"vector": vector["id"], "datagrams": records})
                burst, ordinary = (bytes.fromhex(vector[name]) for name in
                                   ("burst_hex", "ordinary_hex"))
                with udp(ip) as sock:
                    expected_source = (ip, target[1])
                    # A different directory entry's key must not authenticate
                    # the base, even though the claimed SSID is configured.
                    if auth:
                        forged = bytearray(burst)
                        wrong_key = KEYS[43 if vector["ssid"] == 42 else 42]
                        forged[96:112] = digest(wrong_key, forged[:96])
                        send(sock, forged, target, records)
                        sock.settimeout(0.15)
                        try:
                            receive(sock, records)
                        except TimeoutError:
                            records.append({"direction": "timeout", "expected": "bad base HMAC drop"})
                        else:
                            raise WireError("bad base HMAC received a reply")
                        sock.settimeout(2)
                    send(sock, burst, target, records)
                    first = receive(sock, records)
                    verify_reply(first[0], burst, vector, clock, stateful, 0,
                                 *first[1:], expected_source, True, received_count=1)
                    send(sock, ordinary, target, records)
                    middle = receive(sock, records)
                    verify_reply(middle[0], ordinary, vector, clock, stateful, 1,
                                 *middle[1:], target, False)
                    previous = middle[0]
                    for ordinal in (2, 3):
                        reply = receive(sock, records)
                        verify_reply(reply[0], burst, vector, clock, stateful, ordinal,
                                     *reply[1:], expected_source, True, received_count=2,
                                     previous=previous, first=first[0])
                        previous = reply[0]
                    sock.settimeout(0.15)
                    try:
                        receive(sock, records)
                    except TimeoutError:
                        records.append({"direction": "timeout", "expected": "burst complete"})
                    else:
                        raise WireError("unexpected extra burst reply")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="Linux nix-backend stamp-suite executable")
    parser.add_argument("--report", type=Path, help="write JSON results, including failed cases and wire bytes")
    parser.add_argument("--write-vectors", action="store_true", help="explicitly regenerate checked-in requests")
    args = parser.parse_args()
    if args.write_vectors:
        require(args.binary is None and args.report is None, "vector generation is a separate operation")
        VECTORS.parent.mkdir(parents=True, exist_ok=True)
        VECTORS.write_text(json.dumps(make_vectors(), indent=2) + "\n", encoding="utf-8")
        return 0
    if args.binary is None or args.report is None:
        parser.error("--binary and --report are required for live tests")
    require(sys.platform == "linux", "this traffic-class fixture profile requires Linux")
    binary = args.binary.resolve(strict=True)
    fixture_bytes = VECTORS.read_bytes()
    fixtures = json.loads(fixture_bytes)
    require(fixtures == make_vectors(), "checked-in fixtures differ from encoder; review before regenerating")
    report = {"schema_version": 1, "profile": fixtures["profile"],
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "python": platform.python_version(),
              "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "fixtures_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
              "expected_cases": 16, "completed": False, "cases": []}
    for ip, auth, clock, stateful in itertools.product(
            ("127.0.0.1", "::1"), (False, True), ("NTP", "PTP"), (False, True)):
        result = {"ip": ip, "auth": auth, "reflector_clock": clock,
                  "stateful": stateful, "exchanges": [], "passed": False}
        report["cases"].append(result)
        try:
            exercise(binary, fixtures["vectors"], ip, auth, clock, stateful, result)
            result["passed"] = True
        except (WireError, OSError, subprocess.SubprocessError) as error:
            result["error"] = str(error)
        print(f"{'PASS' if result['passed'] else 'FAIL'} {ip} auth={auth} "
              f"clock={clock} stateful={stateful} {result.get('error', '')}", flush=True)
        report["completed"] = len(report["cases"]) == report["expected_cases"]
        report["passed"] = sum(case["passed"] for case in report["cases"])
        report["failed"] = len(report["cases"]) - report["passed"]
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if all(case["passed"] for case in report["cases"]) else 1


if __name__ == "__main__":
    sys.exit(main())
