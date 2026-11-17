#!/usr/bin/env python3
"""Install, exercise and remove one Linux package in a disposable Docker container."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
KEY = bytes([0xab]) * 32  # Public fixture key, never an operator credential.
UNIT = Path("/usr/lib/systemd/system/stamp-suite.service")
# capability(7) numbers for the capabilities a STAMP reflector unit may grant.
CAPABILITY_BITS = {"CAP_NET_BIND_SERVICE": 10, "CAP_NET_ADMIN": 12, "CAP_NET_RAW": 13}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(events, args, *, timeout=60, check=True):
    event = {"command": [str(arg) for arg in args]}
    events.append(event)
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        event["timeout_seconds"] = timeout
        raise
    event.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
    if check:
        require(result.returncode == 0, f"command failed: {args[0]} ({result.returncode})")
    return result


def request(auth):
    data = bytearray(112 if auth else 44)
    data[:4] = (17).to_bytes(4, "big")
    offset = 16 if auth else 4
    data[offset:offset + 8] = (0xedde123456780000).to_bytes(8, "big")
    data[offset + 8:offset + 10] = (1).to_bytes(2, "big")
    data[offset + 10:offset + 12] = (11).to_bytes(2, "big")
    if auth:
        data[96:] = hmac.digest(KEY, data[:96], "sha256")[:16]
    return bytes(data)


def verify_reply(sent, reply, auth):
    require(len(reply) == len(sent), "unexpected reply length")
    seq, timestamp, ssid, sent_timestamp = (48, 64, 26, 16) if auth else (24, 28, 14, 4)
    require(reply[seq:seq + 4] == sent[:4], "wrong echoed sequence")
    require(reply[timestamp:timestamp + 8] == sent[sent_timestamp:sent_timestamp + 8],
            "wrong echoed timestamp")
    require(reply[ssid:ssid + 2] == (11).to_bytes(2, "big"), "wrong SSID")
    if auth:
        require(hmac.compare_digest(reply[96:], hmac.digest(KEY, reply[:96], "sha256")[:16]),
                "invalid reply HMAC")


def service_settings(text):
    """The sandbox the shipped unit asks systemd for: account, capabilities
    and NoNewPrivileges from its [Service] section."""
    section, values = None, {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
        elif section == "[Service]" and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()

    def capabilities(key):
        names = values.get(key, "").split()
        for name in names:
            require(name in CAPABILITY_BITS, f"unit grants unsupported capability {name}")
        return names

    require("User" in values and "Group" in values, "unit does not name a service account")
    return {
        "user": values["User"],
        "group": values["Group"],
        "ambient": capabilities("AmbientCapabilities"),
        "bounding": capabilities("CapabilityBoundingSet"),
        "no_new_privs": values.get("NoNewPrivileges", "no").lower() in {"yes", "true", "1", "on"},
    }


def setpriv_capabilities(names):
    return ",".join("+" + name.removeprefix("CAP_").lower() for name in names)


def service_command(settings, ip, auth, capability=True):
    """Run the reflector as the unit would, or with no capabilities at all."""
    bounding = settings["bounding"] if capability else []
    ambient = settings["ambient"] if capability else []
    args = ["setpriv", f"--reuid={settings['user']}", f"--regid={settings['group']}",
            "--init-groups", ",".join(["--bounding-set=-all"] + ([setpriv_capabilities(bounding)]
                                                                   if bounding else []))]
    if ambient:
        caps = setpriv_capabilities(ambient)
        args += [f"--inh-caps={caps}", f"--ambient-caps={caps}"]
    if settings["no_new_privs"]:
        args.append("--no-new-privs")
    args += ["/usr/bin/stamp-suite", "--is-reflector",
             "--local-addr", ip, "--local-port", "862", "--hwtstamp", "off"]
    if auth:
        args += ["--auth-mode", "A", "--hmac-key", KEY.hex()]
    return args


def reflect(events, settings, uid, gid, ip, auth):
    environment = {**os.environ, "TOKIO_WORKER_THREADS": "2", "RUST_LOG": "off"}
    environment.pop("STAMP_HMAC_KEY", None)
    child = subprocess.Popen(service_command(settings, ip, auth), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=environment)
    try:
        with socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                           socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.2)
            sent = request(auth)
            deadline = time.monotonic() + 8
            while True:
                require(child.poll() is None, "packaged reflector exited during startup")
                sock.sendto(sent, (ip, 862))
                try:
                    reply, peer = sock.recvfrom(2048)
                    break
                except TimeoutError:
                    require(time.monotonic() < deadline, "packaged reflector did not answer")
            require(peer[:2] == (ip, 862), "wrong reply endpoint")
            verify_reply(sent, reply, auth)
        status = Path(f"/proc/{child.pid}/status").read_text()
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        require(all(int(value) == uid for value in fields["Uid"].split()), "wrong service UID")
        require(all(int(value) == gid for value in fields["Gid"].split()), "wrong service GID")
        expected_caps = sum(1 << CAPABILITY_BITS[name] for name in settings["ambient"])
        require(int(fields["CapEff"].strip(), 16) == expected_caps,
                "effective capabilities differ from the unit's")
        require(fields["NoNewPrivs"].strip() == ("1" if settings["no_new_privs"] else "0"),
                "NoNewPrivileges differs from the unit's")
        events.append({"reflection": ip, "authenticated": auth, "uid": uid,
                       "effective_capabilities": fields["CapEff"].strip(),
                       "request": sent.hex(), "reply": reply.hex()})
    finally:
        child.terminate()
        try:
            stdout, stderr = child.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate(timeout=5)
            events.append({"service_timeout": True, "stdout": stdout, "stderr": stderr})
            raise
        events.append({"service_exit": child.returncode, "stdout": stdout, "stderr": stderr})
    require(child.returncode == 0, "packaged reflector did not shut down cleanly")


def inside(kind, events):
    # This entry point installs packages and removes accounts. Refuse ordinary
    # host invocation; the outer command supplies an isolated network/filesystem.
    require(os.environ.get("STAMP_PACKAGE_CHECK_CONTAINER") == "1"
            and Path("/.dockerenv").is_file() and os.geteuid() == 0,
            "package lifecycle checks require the disposable Docker container")
    require(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip() == "1024",
            "low-port capability check requires ip_unprivileged_port_start=1024")
    import pwd

    events.append({"os_release": Path("/etc/os-release").read_text()})
    package = f"/inputs/package.{kind}"
    # The local RPM is unsigned. Skip signature trust only; dependency and
    # payload digest checks remain enforced by the native package manager.
    install = ["dpkg", "--install", package] if kind == "deb" else ["rpm", "--install", "--nosignature", package]
    command(events, install)
    settings = service_settings(UNIT.read_text())
    events.append({"service_settings": settings})
    account = pwd.getpwnam(settings["user"])
    require(account.pw_uid != 0 and account.pw_gid != 0, "service identity must not be root")
    uid, gid = account.pw_uid, account.pw_gid
    require(Path("/usr/bin/stamp-suite").is_file(), "packaged binary is missing")
    events.append({"binary_sha256": hashlib.sha256(Path("/usr/bin/stamp-suite").read_bytes()).hexdigest()})
    command(events, ["/usr/bin/stamp-suite", "--version"])
    command(events, ["systemd-analyze", "verify", str(UNIT)])
    reinstall = install if kind == "deb" else ["rpm", "--upgrade", "--replacepkgs", "--nosignature", package]
    command(events, reinstall)
    account = pwd.getpwnam(settings["user"])
    require((account.pw_uid, account.pw_gid) == (uid, gid), "reinstall changed the service identity")
    for ip in ["127.0.0.1", "::1"]:
        for auth in [False, True]:
            reflect(events, settings, uid, gid, ip, auth)
    denied = command(events, service_command(settings, "127.0.0.1", False, capability=False),
                     check=False)
    require(denied.returncode != 0 and "Permission denied" in denied.stderr,
            "binding port 862 without the capability was not rejected")
    if kind == "deb":
        command(events, ["dpkg", "--remove", "stamp-suite"])
        require(pwd.getpwnam("stamp").pw_uid == uid, "remove deleted the reusable service account")
        command(events, ["dpkg", "--purge", "stamp-suite"])
        try:
            pwd.getpwnam("stamp")
        except KeyError:
            pass
        else:
            raise ValueError("service account remains after purge")
    else:
        command(events, ["rpm", "--erase", "stamp-suite"])
    require(not Path("/usr/bin/stamp-suite").exists(), "uninstall left the binary installed")


def outside(package, image, report):
    package = package.resolve(strict=True)
    kind = package.suffix.removeprefix(".")
    require(kind in ("deb", "rpm"), "expected one .deb or .rpm file")
    require(package.is_file(), "package must be a regular file")
    script = Path(__file__).resolve()
    require("," not in str(package) and "," not in str(script), "Docker bind paths cannot contain commas")
    report.update(kind=kind, package=str(package), package_sha256=hashlib.sha256(package.read_bytes()).hexdigest())
    events = report["events"]
    if image is None:
        image = f"stamp-suite-install-check-{kind}:local"
        command(events, ["docker", "build", "--tag", image, "--file",
                         ROOT / "dist/package-check" / f"{kind}.Dockerfile",
                         ROOT / "dist/package-check"], timeout=600)
    inspected = command(events, ["docker", "image", "inspect", image])
    metadata = json.loads(inspected.stdout)[0]
    report.update(image_id=metadata["Id"], architecture=metadata["Architecture"])
    name = "stamp-suite-install-check-" + uuid.uuid4().hex
    try:
        result = command(events, ["docker", "run", "--rm", "--name", name,
                                  "--network", "none", "--sysctl", "net.ipv4.ip_unprivileged_port_start=1024",
                                  "--env", "STAMP_PACKAGE_CHECK_CONTAINER=1", "--env", "LC_ALL=C",
                                  "--mount", f"type=bind,src={package},dst=/inputs/package.{kind},readonly",
                                  "--mount", f"type=bind,src={script},dst=/inputs/check.py,readonly",
                                  metadata["Id"], "python3", "/inputs/check.py", "--inside", kind],
                         timeout=180, check=False)
        report["container"] = json.loads(result.stdout)
        require(result.returncode == 0 and report["container"].get("complete") is True,
                "package installation check failed")
    finally:
        # Also remove a still-running container after a client timeout. A
        # successful --rm run has already removed it; that error is harmless.
        command(events, ["docker", "rm", "--force", name], timeout=30, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--image", help="Use an existing test image instead of building one")
    parser.add_argument("--inside", choices=["deb", "rpm"], help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside is None and args.package is None:
        parser.error("--package is required")
    if args.report and args.package and args.report.resolve() == args.package.resolve():
        parser.error("report must not overwrite the package")
    report = {"complete": False, "events": []}
    try:
        if args.inside:
            inside(args.inside, report["events"])
        else:
            outside(args.package, args.image, report)
        report["complete"] = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    text = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text)
    print(text, end="")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
