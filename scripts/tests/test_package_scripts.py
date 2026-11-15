"""Exercise package service-account setup without touching host accounts."""
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
RPM = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["metadata"]["generate-rpm"]


@unittest.skipUnless(os.name == "posix", "package scripts require a POSIX shell")
class PackageScriptTests(unittest.TestCase):
    def pre_install(self, existing=False, group_status=0, user_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "commands.log"
            for command, status in [("getent", 0 if existing else 2),
                                    ("groupadd", group_status), ("useradd", user_status)]:
                stub = root / command
                stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "{command} $*" >> "$PACKAGE_TEST_LOG"\nexit {status}\n')
                stub.chmod(0o755)
            result = subprocess.run(
                ["/bin/sh", "-c", RPM["pre_install_script"]],
                env={"PATH": directory, "PACKAGE_TEST_LOG": str(log)},
                capture_output=True, text=True, check=False,
            )
            return result.returncode, log.read_text().splitlines()

    def test_creates_missing_service_accounts(self):
        status, commands = self.pre_install()
        self.assertEqual(status, 0)
        self.assertEqual([command.split()[0] for command in commands],
                         ["getent", "groupadd", "getent", "useradd"])

    def test_preserves_existing_service_accounts(self):
        status, commands = self.pre_install(existing=True)
        self.assertEqual(status, 0)
        self.assertEqual(commands, ["getent group stamp", "getent passwd stamp"])

    def test_group_creation_failure_aborts_installation(self):
        status, commands = self.pre_install(group_status=10)
        self.assertNotEqual(status, 0)
        self.assertFalse(any(command.startswith("useradd ") for command in commands))

    def test_user_creation_failure_aborts_installation(self):
        status, _ = self.pre_install(user_status=9)
        self.assertNotEqual(status, 0)

    def test_maintainer_scripts_parse(self):
        scripts = [RPM[name] for name in ["pre_install_script", "post_install_script",
                                          "pre_uninstall_script", "post_uninstall_script"]]
        scripts += [(ROOT / "dist/debian" / name).read_text()
                    for name in ["postinst", "prerm", "postrm"]]
        for script in scripts:
            with self.subTest(script=script):
                subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)
