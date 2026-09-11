"""Check fixture stability and ensure the independent oracle rejects divergences."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("interop_stamp", SCRIPTS / "interop_stamp.py")
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class InteropChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(wire.VECTORS.read_text())
        cls.replies = json.loads((wire.VECTORS.parent / "replies.json").read_text())

    def test_frozen_request_vectors(self):
        self.assertEqual(self.vectors, wire.make_vectors())
        self.assertEqual(len(self.vectors["vectors"]), 24)
        self.assertEqual(len({v["id"] for v in self.vectors["vectors"]}), 24)

    def test_rfc4231_hmac_sha256_test_case_1_truncated_to_128_bits(self):
        self.assertEqual(wire.digest(bytes([0x0b]) * 20, b"Hi There").hex(),
                         "b0344c61d8db38535ca8afceaf0bf12b")

    def test_parser_rejects_truncation_duplicates_and_trailing_data(self):
        for data in (b"\x80", b"\x80\x08\x00\x10\x00",
                     wire.tlv(4, bytes(4)) * 2, wire.tlv(8, bytes(16)) + b"\x00"):
            with self.subTest(data=data.hex()), self.assertRaises(wire.WireError):
                wire.parse_tlvs(data, 0)

    def arguments(self, case, ordinal):
        vector = next(v for v in self.vectors["vectors"] if v["id"] == case["vector"])
        packet = case["replies"][ordinal]
        burst = ordinal != 1
        return dict(
            data=bytes.fromhex(packet["hex"]),
            sent=bytes.fromhex(vector["burst_hex" if burst else "ordinary_hex"]),
            vector=vector, clock=case["reflector_clock"], stateful=case["stateful"],
            ordinal=ordinal, tos=packet["traffic_class"][0], peer=packet["peer"],
            target=packet["peer"], burst=burst, received_count=1 if ordinal == 0 else 2,
            previous=bytes.fromhex(case["replies"][ordinal - 1]["hex"]) if ordinal > 1 else None,
            first=bytes.fromhex(case["replies"][0]["hex"]) if ordinal > 1 else None)

    def test_recorded_open_auth_stateful_stateless_replies(self):
        self.assertEqual(len(self.replies["cases"]), 4)
        for case in self.replies["cases"]:
            self.assertEqual(len(case["replies"]), 4)
            for ordinal in range(4):
                with self.subTest(vector=case["vector"], stateful=case["stateful"], ordinal=ordinal):
                    wire.verify_reply(**self.arguments(case, ordinal))

    def authenticated_follow_up(self):
        return self.arguments(self.replies["cases"][-1], 2)

    def test_wrong_endpoint_or_traffic_class_is_rejected(self):
        for key, value, message in (("tos", 0, "traffic class"),
                                    ("peer", ["::2", 1], "source address/port")):
            args = self.authenticated_follow_up()
            args[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(wire.WireError, message):
                wire.verify_reply(**args)

    def test_corrupt_base_and_extension_digests_are_rejected(self):
        for offset, message in ((96, "base HMAC"), (-1, "TLV HMAC")):
            args = self.authenticated_follow_up()
            data = bytearray(args["data"])
            data[offset] ^= 1
            args["data"] = bytes(data)
            with self.subTest(offset=offset), self.assertRaisesRegex(wire.WireError, message):
                wire.verify_reply(**args)

    def test_signed_but_wrong_fields_are_rejected(self):
        for target, message in (("sequence", "reflector sequence"), ("echo", "echoed sender"),
                                ("clock", "reflector clock"), ("t2", "T2 changed"),
                                (4, "CoS report"), (5, "Measurement counters"),
                                (7, "Follow-Up sequence"), (10, "Type 10 flags")):
            args = self.authenticated_follow_up()
            data = bytearray(args["data"])
            fields = wire.parse_tlvs(data, 112)
            offsets = {"sequence": 3, "echo": 64, "clock": 24, "t2": 32}
            offset = offsets[target] if isinstance(target, str) else fields[target][2] + (0 if target == 10 else 4)
            data[offset] ^= 0x40 if target == "clock" else 1
            key = wire.KEYS[args["vector"]["ssid"]]
            data[96:112] = wire.digest(key, data[:96])
            mac_offset = fields[8][2]
            data[mac_offset + 4:] = wire.digest(key, data[:4] + data[112:mac_offset])
            args["data"] = bytes(data)
            with self.subTest(target=target), self.assertRaisesRegex(wire.WireError, message):
                wire.verify_reply(**args)

    def test_live_report_retains_failure_and_runs_remaining_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "binary"
            binary.write_bytes(b"mock binary for report bookkeeping")
            report = Path(temporary) / "report.json"
            # Only the socket/process exercise is mocked; use the real frozen
            # input validation, case matrix, report writer and exit decision.
            outcomes = [wire.WireError("injected bad reply")] + [None] * 15
            with mock.patch.object(wire, "exercise", side_effect=outcomes) as exercise, \
                    mock.patch.object(sys, "platform", "linux"), \
                    mock.patch.object(sys, "argv", ["interop_stamp", "--binary", str(binary),
                                                   "--report", str(report)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(wire.main(), 1)
            self.assertEqual(exercise.call_count, 16)
            result = json.loads(report.read_text())
            self.assertTrue(result["completed"])
            self.assertEqual((result["passed"], result["failed"]), (15, 1))
            self.assertEqual(result["cases"][0]["error"], "injected bad reply")


if __name__ == "__main__":
    unittest.main()
