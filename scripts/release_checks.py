#!/usr/bin/env python3
"""Live control/key-rotation and Net-SNMP reference-master release fixtures.

Only owned temporary processes, files and loopback endpoints are used. See
doc/release-evidence.md for prerequisites, commands and coverage limits.
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import http.client as http_client
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from interop_stamp import WireError, digest, parse_tlvs, require, tlv

TOKEN = "stamp-release-fixture-token"
OLD, NEW, FALLBACK = (bytes([v]) * 16 for v in (0xAB, 0xCD, 0xEF))
ROOT_OID = ".1.3.6.1.4.1.65134"


def udp(ip):
    sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((ip, 0))
        sock.settimeout(2)
        return sock
    except BaseException:
        sock.close()
        raise


def packet(seq, ssid, key, burst=False):
    data = bytearray(112)
    struct.pack_into("!I", data, 0, seq)
    struct.pack_into("!QHH", data, 16, 1, 1, ssid)
    data[96:112] = digest(key, data[:96])
    if burst:
        data += tlv(12, struct.pack("!HHII", 0, 3, 500_000_000, 0))
        data += tlv(10, tlv(4, socket.inet_pton(socket.AF_INET6, "::1")))
    data += tlv(8, digest(key, data[:4] + data[112:]))
    return bytes(data)


def receive(sock, target, request, key, sequence, events, burst=False):
    data, peer = sock.recvfrom(4096)
    events.append({"udp_rx": data.hex(), "peer": list(peer)})
    require(peer[:2] == target[:2], "wrong reply endpoint")
    require(len(data) == len(request), "wrong reply size")
    require(data[:4] == struct.pack("!I", sequence), "wrong session sequence")
    require(data[48:52] == request[:4] and data[26:28] == request[26:28], "wrong echo/SSID")
    require(data[96:112] == digest(key, data[:96]), "wrong base signing key")
    fields = parse_tlvs(data, 112)
    require(list(fields) == ([12, 10, 8] if burst else [8]), "wrong reply TLVs")
    for kind, (flags, _, _) in fields.items():
        require(flags == (0x80 if kind == 10 else 0), "wrong fallback/integrity flags")
    _, mac, offset = fields[8]
    require(mac == digest(key, data[:4] + data[112:offset]), "wrong final TLV signing key")
    return data


def send(sock, target, data, events):
    sock.sendto(data, target)
    events.append({"udp_tx": data.hex(), "peer": list(target)})


def dropped(sock, target, data, events):
    send(sock, target, data, events)
    sock.settimeout(0.2)
    try:
        reply, peer = sock.recvfrom(4096)
        events.append({"unexpected_udp_rx": reply.hex(), "peer": list(peer)})
        raise WireError("revoked/wrong key was accepted")
    except TimeoutError:
        events.append({"expected_drop": True})
    finally:
        sock.settimeout(2)


@contextlib.contextmanager
def child(command, directory, name, events, extra_env=None):
    environment = {**os.environ, "TOKIO_WORKER_THREADS": "2"}
    environment.pop("STAMP_HMAC_KEY", None)
    environment.update(extra_env or {})
    record = {"process": name, "command": [str(arg) for arg in command]}
    events.append(record)
    with (directory / (name + ".log")).open("w+") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
        try:
            yield process
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log.seek(0)
            record.update(returncode=process.returncode, output=log.read())


def control_case(binary, ip, tls, directory, events):
    with udp(ip) as reserve:
        target = reserve.getsockname()
    with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET) as reserve:
        reserve.bind((ip, 0))
        control = reserve.getsockname()
    keys = directory / "keys"
    keys.mkdir(mode=0o700)
    keyfile = keys / "002a.key"
    keyfile.write_text(OLD.hex())
    keyfile.chmod(0o600)
    tokenfile = directory / "token"
    tokenfile.write_text(TOKEN)
    tokenfile.chmod(0o600)
    command = [str(binary), "--is-reflector", "--local-addr", ip, "--local-port", str(target[1]),
               "--auth-mode", "A", "--hmac-key-dir", str(keys), "--stateful-reflector",
               "--hwtstamp", "off", "--clock-source", "NTP",
               "--reflected-control-max-count", "3", "--control",
               "--control-addr", f"[{ip}]:{control[1]}" if ":" in ip else f"{ip}:{control[1]}",
               "--control-token-file", str(tokenfile)]
    context = None
    if tls:
        cert, private = directory / "cert.pem", directory / "private.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(private), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", f"subjectAltName=IP:{ip}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        private.chmod(0o600)
        command += ["--control-tls-cert", str(cert), "--control-tls-key", str(private)]
        context = ssl.create_default_context(cafile=str(cert))

    def http(method, path, expected, body=None, token=TOKEN, record=True):
        connection = (http_client.HTTPSConnection(ip, control[1], timeout=3, context=context)
                      if tls else http_client.HTTPConnection(ip, control[1], timeout=3))
        try:
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            connection.request(method, path, body=json.dumps(body) if body is not None else None,
                               headers=headers)
            response = connection.getresponse()
            text = response.read().decode()
            if record:
                events.append({"http": method + " " + path, "status": response.status,
                               "authorized": token == TOKEN, "body": text})
            require(response.status == expected, f"{method} {path}: {response.status}, expected {expected}")
            return json.loads(text) if text else None
        finally:
            connection.close()

    with child(command, directory, "reflector", events) as process, udp(ip) as sock:
        deadline = time.monotonic() + 8
        while True:
            require(process.poll() is None, "reflector exited during control startup")
            try:
                http("GET", "/v1/status", 200, record=False)
                break
            except OSError:
                require(time.monotonic() < deadline, "control startup timeout")
                time.sleep(0.03)
        http("GET", "/v1/status", 401, token=None)
        http("PUT", "/v1/keys/42", 401, {"key_hex": NEW.hex()}, token="wrong-token")
        burst = packet(7, 42, OLD, burst=True)
        send(sock, target, burst, events)
        first = receive(sock, target, burst, OLD, 0, events, burst=True)
        http("PUT", "/v1/keys/42", 204, {"key_hex": NEW.hex()})
        seconds, nanos = divmod(time.time_ns(), 1_000_000_000)
        rotated_ntp = (((seconds + 2_208_988_800) << 32) | ((nanos << 32) // 1_000_000_000)) % (1 << 64)
        events.append({"rotation_ack_ntp": rotated_ntp})
        for sequence in (1, 2):
            copy = receive(sock, target, burst, OLD, sequence, events, burst=True)
            require(copy[32:40] == first[32:40], "queued burst T2 changed after rotation")
            # Both processes use the same host's software NTP clock. Serial
            # comparison handles the NTP era wrap without accepting old copies.
            t3 = int.from_bytes(copy[16:24], "big")
            require((t3 - rotated_ntp) % (1 << 64) < (1 << 63),
                    "copy predates rotation acknowledgement; timing fixture inconclusive")
        dropped(sock, target, packet(8, 42, OLD), events)
        for sequence, sender in ((3, 9), (4, 10)):
            if sequence == 4:
                http("DELETE", "/v1/keys/42", 401, token="wrong-token")
            request = packet(sender, 42, NEW)
            send(sock, target, request, events)
            receive(sock, target, request, NEW, sequence, events)
        inventory = http("GET", "/v1/keys", 200)
        require(all(key.hex() not in json.dumps(inventory).lower() for key in (OLD, NEW, FALLBACK)),
                "key inventory disclosed key material")
        http("DELETE", "/v1/keys/42", 204)
        dropped(sock, target, packet(11, 42, NEW), events)
        http("PUT", "/v1/keys/default", 204, {"key_hex": FALLBACK.hex()})
        for ssid, sequence in ((42, 5), (99, 0)):
            request = packet(12, ssid, FALLBACK)
            send(sock, target, request, events)
            receive(sock, target, request, FALLBACK, sequence, events)
        http("DELETE", "/v1/keys/default", 204)
        for ssid in (42, 99):
            dropped(sock, target, packet(13, ssid, FALLBACK), events)
        http("GET", "/v1/status", 200)
        http("POST", "/v1/shutdown", 202)
        require(process.wait(timeout=5) == 0, "control shutdown failed")


def snmp_case(binary, tools, directory, events):
    with udp("127.0.0.1") as reserve:
        port = reserve.getsockname()[1]
    with udp("127.0.0.1") as reserve:
        target = reserve.getsockname()
    master_socket = directory / "agentx"
    config = directory / "snmpd.conf"
    config.write_text(f"agentaddress udp:127.0.0.1:{port}\nmaster agentx\n"
                      f"agentXSocket {master_socket}\nagentXPerms 0600 0700\n"
                      f"rocommunity stamp-fixture 127.0.0.1 {ROOT_OID}\n")
    persistent = directory / "persistent"
    persistent.mkdir()
    environment = {"MIBS": "", "SNMPCONFPATH": str(directory),
                   "SNMP_PERSISTENT_DIR": str(persistent)}
    master_command = [tools["snmpd"], "-f", "-Lo", "-C", "-c", str(config),
                      "-p", str(directory / "snmpd.pid")]

    def query(tool, oids, options=(), values=False, record=True):
        command = [tools[tool], "-v2c", "-c", "stamp-fixture", "-t", "1", "-r", "0",
                   "-Oqv" if values else "-On", *options, f"127.0.0.1:{port}", *oids]
        output = subprocess.run(command, capture_output=True, text=True, timeout=5,
                                env={**os.environ, **environment})
        if record:
            events.append({"query": command, "status": output.returncode,
                           "stdout": output.stdout, "stderr": output.stderr})
        require(output.returncode == 0, "Net-SNMP query failed: " + output.stderr)
        return output.stdout.strip()

    auth_oid = ROOT_OID + ".1.1.1.4.0"
    stats = [ROOT_OID + ".1.1.2." + str(i) + ".0" for i in (1, 2, 4)]

    def registered(master, reflector):
        deadline = time.monotonic() + 12
        while True:
            require(master.poll() is None and reflector.poll() is None, "reference process exited")
            try:
                if query("snmpget", [auth_oid], values=True, record=False) == "2":
                    return
            except WireError:
                pass
            require(time.monotonic() < deadline, "STAMP subtree did not register/reconnect")
            time.sleep(0.05)

    with contextlib.ExitStack() as stack:
        master = stack.enter_context(child(master_command, directory, "master", events, environment))
        deadline = time.monotonic() + 5
        while not master_socket.exists():
            require(master.poll() is None and time.monotonic() < deadline, "AgentX startup failed")
            time.sleep(0.03)
        reflector = stack.enter_context(child(
            [str(binary), "--is-reflector", "--local-addr", "127.0.0.1", "--local-port", str(target[1]),
             "--stateful-reflector", "--auth-mode", "A", "--hmac-key", OLD.hex(), "--hwtstamp", "off",
             "--snmp", "--snmp-socket", str(master_socket)], directory, "reflector", events))
        registered(master, reflector)
        require(query("snmpget", stats, values=True).splitlines() == ["0", "0", "0"], "nonzero initial counters")
        clients = [stack.enter_context(udp("127.0.0.1")) for _ in range(2)]
        for sock in clients:
            request = packet(1, 42, OLD)
            send(sock, target, request, events)
            receive(sock, target, request, OLD, 0, events)
        require(query("snmpget", stats, values=True).splitlines() == ["2", "2", "2"], "wrong live SNMP counters")
        table = ROOT_OID + ".1.1.3.1"
        walk = query("snmpwalk", [table])
        oids = re.findall(r"^(\.[0-9.]+) =", walk, re.MULTILINE)
        require(len(oids) == 14, "expected two sessions in seven columns")
        require(oids == sorted(set(oids), key=lambda s: tuple(map(int, s[1:].split('.')))), "unordered/duplicate table walk")
        bulk = query("snmpbulkget", [stats[0], table + ".1", table + ".2"], ["-Cn1", "-Cr3"])
        bulk_oids = re.findall(r"^(\.[0-9.]+) =", bulk, re.MULTILINE)
        require(bulk_oids == [stats[1], oids[0], oids[2], oids[1], oids[3], oids[2], oids[4]],
                "unexpected non-repeater/repeater order")
        end = query("snmpgetnext", [ROOT_OID + ".999"])
        require("No more variables" in end, "missing end-of-MIB boundary")
        master.terminate()
        master.wait(timeout=5)
        request = packet(2, 42, OLD)
        send(clients[0], target, request, events)
        receive(clients[0], target, request, OLD, 1, events)
        restarted = stack.enter_context(child(master_command, directory, "master-restarted", events, environment))
        registered(restarted, reflector)
        require(query("snmpget", stats, values=True).splitlines() == ["3", "3", "2"], "state lost across master restart")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--only", choices=("control", "snmp", "all"), default="all")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    tools = {}
    if args.only != "control":
        for name in ("snmpd", "snmpget", "snmpgetnext", "snmpwalk", "snmpbulkget"):
            tools[name] = shutil.which(name)
            require(tools[name] is not None, f"required reference tool missing: {name}")
    cases = []
    if args.only != "snmp":
        for ip in ("127.0.0.1", "::1"):
            for tls in (False, True):
                cases.append((f"control-{ip}-{'tls' if tls else 'http'}",
                              lambda directory, events, ip=ip, tls=tls: control_case(binary, ip, tls, directory, events)))
    if args.only != "control":
        cases.append(("net-snmp-master", lambda directory, events: snmp_case(binary, tools, directory, events)))
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "platform": platform.platform(),
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "expected_cases": len(cases), "completed": False, "cases": []}
    if tools:
        version = subprocess.run([tools["snmpd"], "--version"], capture_output=True, text=True, timeout=5)
        report["net_snmp_version"] = version.stdout + version.stderr
    for name, exercise in cases:
        result = {"name": name, "passed": False, "events": []}
        report["cases"].append(result)
        try:
            with tempfile.TemporaryDirectory(prefix="stamp-release-") as temporary:
                exercise(Path(temporary), result["events"])
            result["passed"] = True
        except (WireError, OSError, subprocess.SubprocessError, http_client.HTTPException) as error:
            result["error"] = str(error)
        print(f"{'PASS' if result['passed'] else 'FAIL'} {name} {result.get('error', '')}", flush=True)
        report["completed"] = len(report["cases"]) == len(cases)
        report["passed"] = sum(c["passed"] for c in report["cases"])
        report["failed"] = len(report["cases"]) - report["passed"]
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    return int(report["failed"] != 0)


if __name__ == "__main__":
    sys.exit(main())
