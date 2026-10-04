"""Mutation checks for the external application evidence checkers."""
import copy
import hmac
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import interop_apps as apps
import summarize_interop_apps as summary

FIXTURE = Path(__file__).resolve().parents[2] / 'tests/fixtures/interop/app-evidence.json'


class AppEvidenceChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads(FIXTURE.read_text())['cases']

    def test_recorded_exchanges_pass_wire_checks(self):
        for name, recorded in self.cases.items():
            with self.subTest(case=name):
                case = copy.deepcopy(recorded)
                self.assertEqual(summary.audit(case), [])
                apps.examine(case, case)
                self.assertEqual((case['requests'], case['replies']), (2, 2))
                self.assertEqual(case['wire_issues'], [])
                self.assertEqual(summary.audit(case), [])

    def test_corrupt_authenticated_base_is_detected(self):
        case = copy.deepcopy(self.cases['authenticated'])
        reply = next(r for r in case['wire'] if r['direction'] == 'reply')
        data = bytearray.fromhex(reply['hex'])
        data[32] ^= 1
        reply['hex'] = data.hex()
        apps.examine(case, case)
        self.assertIn('invalid reflected base HMAC', case['wire_issues'])

    def test_wrong_echo_is_detected_even_after_resigning(self):
        case = copy.deepcopy(self.cases['authenticated'])
        reply = next(r for r in case['wire'] if r['direction'] == 'reply')
        data = bytearray.fromhex(reply['hex'])
        data[64] ^= 1
        data[96:112] = hmac.digest(apps.KEY.encode(), data[:96], 'sha256')[:16]
        reply['hex'] = data.hex()
        apps.examine(case, case)
        self.assertIn('sender timestamp/error echo mismatch', case['wire_issues'])
        self.assertNotIn('invalid reflected base HMAC', case['wire_issues'])

    def test_cos_report_must_match_captured_ip_metadata(self):
        case = copy.deepcopy(self.cases['cos'])
        reply = next(r for r in case['wire'] if r['direction'] == 'reply')
        cos = next(f for f in reply['tlvs'] if f['type'] == 4)
        data = bytearray.fromhex(reply['hex'])
        data[cos['offset'] + 5] ^= 4  # Received ECN, not requested ECN.
        reply['hex'] = data.hex()
        reply['tlvs'] = apps.tlvs(data, False)
        self.assertIn('CoS received DSCP/ECN report differs from request IP metadata', summary.audit(case))

    def test_same_host_epoch_discrepancy_is_detected(self):
        case = copy.deepcopy(self.cases['open'])
        reply = next(r for r in case['wire'] if r['direction'] == 'reply')
        data = bytearray.fromhex(reply['hex'])
        data[16] ^= 1  # T2 seconds; preserve echoed T1.
        reply['hex'] = data.hex()
        self.assertIn('same-host timestamp epoch/format discrepancy exceeds 10 seconds', summary.audit(case))


if __name__ == '__main__':
    unittest.main()
