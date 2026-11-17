"""Package gates reject bad wire replies, failures and unsafe host invocation."""
import hmac
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("package_install", ROOT / "scripts/check_package_install.py")
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class PackageInstallTests(unittest.TestCase):
    def test_inside_refuses_host_before_running_commands(self):
        with patch.dict(install.os.environ, {}, clear=True), patch.object(install, "command") as command:
            with self.assertRaisesRegex(ValueError, "disposable Docker"):
                install.inside("deb", [])
            command.assert_not_called()

    def test_sandbox_expectations_come_from_the_shipped_unit(self):
        settings = install.service_settings((ROOT / "dist/systemd/stamp-suite.service").read_text())
        self.assertEqual(settings, {
            "user": "stamp",
            "group": "stamp",
            "ambient": ["CAP_NET_BIND_SERVICE"],
            "bounding": ["CAP_NET_BIND_SERVICE"],
            "no_new_privs": True,
        })
        granted = install.service_command(settings, "::1", False)
        self.assertEqual(granted[:7], [
            "setpriv", "--reuid=stamp", "--regid=stamp", "--init-groups",
            "--bounding-set=-all,+net_bind_service",
            "--inh-caps=+net_bind_service", "--ambient-caps=+net_bind_service",
        ])
        self.assertIn("--no-new-privs", granted)
        denied = install.service_command(settings, "::1", False, capability=False)
        self.assertIn("--bounding-set=-all", denied)
        self.assertFalse(any(arg.startswith(("--inh-caps", "--ambient-caps")) for arg in denied))

    def test_unit_changes_change_the_expectations(self):
        unit = "[Service]\nUser=probe\nGroup=probe\nAmbientCapabilities=CAP_NET_RAW\n"
        settings = install.service_settings(unit)
        self.assertEqual((settings["user"], settings["no_new_privs"]), ("probe", False))
        self.assertNotIn("--no-new-privs", install.service_command(settings, "127.0.0.1", False))
        for unit in ["[Service]\nUser=a\n", "[Service]\nUser=a\nGroup=a\nAmbientCapabilities=CAP_SYS_ADMIN\n"]:
            with self.subTest(unit=unit), self.assertRaises(ValueError):
                install.service_settings(unit)

    def test_reply_identity_and_signature_are_required(self):
        for auth in [False, True]:
            sent = install.request(auth)
            reply = bytearray(len(sent))
            seq, timestamp, ssid, source = (48, 64, 26, 16) if auth else (24, 28, 14, 4)
            reply[seq:seq + 4] = sent[:4]
            reply[timestamp:timestamp + 8] = sent[source:source + 8]
            reply[ssid:ssid + 2] = (11).to_bytes(2, "big")
            if auth:
                reply[96:] = hmac.digest(install.KEY, reply[:96], "sha256")[:16]
            install.verify_reply(sent, reply, auth)
            for offset in [seq, timestamp, ssid] + ([96] if auth else []):
                corrupt = reply.copy()
                corrupt[offset] ^= 1
                with self.subTest(auth=auth, offset=offset), self.assertRaises(ValueError):
                    install.verify_reply(sent, corrupt, auth)
            with self.assertRaisesRegex(ValueError, "length"):
                install.verify_reply(sent, reply[:-1], auth)

    def test_failed_container_report_cannot_pass_even_with_zero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "candidate.deb"
            package.write_bytes(b"fixture")
            responses = [
                subprocess.CompletedProcess([], 0, json.dumps([{"Id": "sha256:test", "Architecture": "amd64"}])),
                subprocess.CompletedProcess([], 0, '{"complete": false}'),
                subprocess.CompletedProcess([], 1, ""),
            ]
            with patch.object(install, "command", side_effect=responses) as command:
                with self.assertRaisesRegex(ValueError, "installation check failed"):
                    install.outside(package, "test-image", {"events": []})
                self.assertEqual(command.call_args.args[1][:3], ["docker", "rm", "--force"])

    def test_client_timeout_still_removes_container(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "candidate.rpm"
            package.write_bytes(b"fixture")
            responses = [
                subprocess.CompletedProcess([], 0, json.dumps([{"Id": "sha256:test", "Architecture": "amd64"}])),
                subprocess.TimeoutExpired("docker run", 180),
                subprocess.CompletedProcess([], 0, ""),
            ]
            with patch.object(install, "command", side_effect=responses) as command:
                with self.assertRaises(subprocess.TimeoutExpired):
                    install.outside(package, "test-image", {"events": []})
                self.assertEqual(command.call_args.args[1][:3], ["docker", "rm", "--force"])

    def test_missing_package_writes_failure_report(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with patch("sys.argv", ["check", "--package", str(Path(directory) / "missing.deb"),
                                    "--report", str(report)]), patch("builtins.print"):
                self.assertEqual(install.main(), 1)
            result = json.loads(report.read_text())
            self.assertFalse(result["complete"])
            self.assertIn("error", result)
