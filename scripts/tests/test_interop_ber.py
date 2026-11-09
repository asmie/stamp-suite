"""Exercise the BER oracle using frozen observations and signed divergences."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location(
    'interop_ber', Path(__file__).resolve().parents[1] / 'interop_ber.py')
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class BerOracleChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(wire.VECTORS.read_text())['vectors']
        cls.observed = json.loads((wire.VECTORS.parent / 'replies.json').read_text())

    def test_frozen_vectors_and_distinct_case_matrix(self):
        self.assertEqual(json.loads(wire.VECTORS.read_text()), wire.make_vectors())
        self.assertEqual(len(self.vectors), 17)
        self.assertEqual(len({v['id'] for v in self.vectors}), 17)
        cases = list(wire.configurations())
        self.assertEqual(len(cases), 60)
        self.assertEqual(len({json.dumps(c, sort_keys=True) for c in cases}), 60)

    def test_hmac_rfc4231_and_bit_reference(self):
        self.assertEqual(wire.digest(b'Hi There', bytes([11]) * 20).hex(),
                         'b0344c61d8db38535ca8afceaf0bf12b')
        self.assertEqual(wire.bits(bytes.fromhex('03c0'), bytes(4)), (4, 4))
        self.assertEqual(wire.bits(wire.DEFAULT * 4, wire.DEFAULT), (0, 0))
        self.assertEqual(wire.bits(bytes.fromhex('8181'), bytes(4)), (4, 2))

    def test_framing_rejects_truncation_but_preserves_duplicates(self):
        for data in (b'\x80', b'\x80\xf3\x00\x08\x00', wire.tlv(1, b'') + b'\x00'):
            with self.subTest(data=data.hex()), self.assertRaises(wire.WireError):
                wire.fields(data)
        self.assertEqual(len(wire.fields(wire.tlv(1, b'') * 2)), 2)

    def arguments(self, case, index):
        vector = self.vectors[index]
        return dict(reply=bytes.fromhex(case['replies'][index]),
                    sent=wire.encode_packet(case['mode'], wire.unpack_items(vector['request']), index + 10),
                    mode=case['mode'], expected=wire.unpack_items(vector['expected']),
                    reflector_sequence=index if case['stateful'] else None)

    def test_all_recorded_reflector_vectors_and_failure_echoes(self):
        self.assertEqual(len(self.observed['reflectors']), 12)
        for case in self.observed['reflectors']:
            self.assertEqual(len(case['replies']), 17)
            for index in range(17):
                with self.subTest(case=case['mode'], ip=case['ip'], stateful=case['stateful'], index=index):
                    wire.verify_reflector_reply(**self.arguments(case, index))
            if case['mode'] != 'open':
                echo = case['failure_echo']
                sent = bytes.fromhex(echo['request'])
                expected = [(32, t, v) for _, t, v, _ in wire.fields(sent, 112 if case['mode'] == 'auth' else 44)
                            if t != 8]
                wire.verify_reflector_reply(bytes.fromhex(echo['reply']), sent, case['mode'], expected,
                                            17 if case['stateful'] else None, failure_echo=True)

    def authenticated(self):
        case = next(c for c in self.observed['reflectors'] if c['mode'] == 'auth' and c['stateful'])
        return case, self.arguments(case, 3)  # five-byte explicit pattern

    def resign(self, data):
        mac = next(f for f in wire.fields(data, 112) if f[1] == 8)
        data[mac[3] + 4:mac[3] + 20] = wire.digest(data[:4] + data[112:mac[3]])
        data[96:112] = wire.digest(data[:96])

    def test_signed_semantic_mutations_are_rejected(self):
        _, original = self.authenticated()
        parsed = wire.fields(original['reply'], 112)
        parent, pad = next(f for f in parsed if f[1] == wire.BER), next(f for f in parsed if f[1] == 1)
        offsets = [3, 48, 64, 26, parent[3], parent[3] + 7, parent[3] + 11,
                   parent[3] + 12, parent[3] + 16, pad[3] + 4]
        for offset in offsets:
            args = dict(original)
            data = bytearray(args['reply'])
            data[offset] ^= 1
            self.resign(data)
            args['reply'] = bytes(data)
            with self.subTest(offset=offset), self.assertRaises(wire.WireError):
                wire.verify_reflector_reply(**args)

    def test_corrupt_digests_and_asymmetric_packets_are_rejected(self):
        _, original = self.authenticated()
        mac = next(f for f in wire.fields(original['reply'], 112) if f[1] == 8)
        for offset in (96, mac[3] + 4):
            args = dict(original)
            data = bytearray(args['reply'])
            data[offset] ^= 1
            args['reply'] = bytes(data)
            with self.subTest(offset=offset), self.assertRaises(wire.WireError):
                wire.verify_reflector_reply(**args)
        with self.assertRaisesRegex(wire.WireError, 'asymmetric'):
            wire.verify_reflector_reply(**{**original, 'reply': original['reply'] + b'\x00'})

    def test_failure_echo_must_preserve_failed_digest_and_values(self):
        case, _ = self.authenticated()
        echo = case['failure_echo']
        sent, reply = bytes.fromhex(echo['request']), bytes.fromhex(echo['reply'])
        expected = [(32, t, v) for _, t, v, _ in wire.fields(sent, 112) if t != 8]
        for offset in (112, 116, next(f for f in wire.fields(reply, 112) if f[1] == 8)[3] + 4, len(reply) - 1):
            changed = bytearray(reply)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(wire.WireError):
                wire.verify_reflector_reply(bytes(changed), sent, 'auth', expected, 17, failure_echo=True)

    def test_sender_request_contract_rejects_wrong_counters_pattern_and_legacy(self):
        for explicit in (False, True):
            pattern = bytes.fromhex('aa55cc330f') if explicit else wire.DEFAULT
            items = [(128, wire.BER, wire.metadata(pattern=pattern, flags=128) if explicit else wire.metadata()),
                     (128, 1, pattern * (60 // len(pattern)))]
            good = wire.encode_packet('auth', items)
            wire.verify_sender_request(good, 'auth', pattern, 60, explicit=explicit)
            for invalid in ([(128, wire.BER, wire.metadata(1))] + items[1:],
                            [(128, 241, bytes(4))] + items[1:], items + items[:1],
                            items[:1] + [(128, 1, bytes(60))]):
                packet = wire.encode_packet('auth', invalid)
                with self.subTest(explicit=explicit, invalid=invalid), self.assertRaises(wire.WireError):
                    wire.verify_sender_request(packet, 'auth', pattern, 60, explicit=explicit)

    def test_all_sender_summaries_and_requests(self):
        self.assertEqual(len(self.observed['senders']), 48)
        for case in self.observed['senders']:
            wire.verify_summary(case['summary'], case['behavior'], 60)
            pattern = bytes.fromhex('aa55cc330f') if case['explicit'] else wire.DEFAULT
            for ordinal, request in enumerate(case['requests']):
                present = not (ordinal > 0 and case['behavior'] in ('parent-u', 'child-u'))
                wire.verify_sender_request(bytes.fromhex(request), case['mode'], pattern, 60, present, case['explicit'])

    def test_summary_mutations_are_rejected(self):
        for case in self.observed['senders']:
            if case['mode'] != 'auth' or case['ip'] != '::1' or not case['explicit']:
                continue
            for path in (('packets_received',), ('ber', 'disabled_by_peer'),
                         ('ber', 'forward', 'packets_received'), ('ber', 'reverse', 'padding_bits'),
                         ('ber', 'forward', 'bit_errors'), ('ber', 'reverse', 'bit_errors'),
                         ('ber', 'forward', 'burst_samples'), ('ber', 'reverse', 'packets_with_errors')):
                value = copy.deepcopy(case['summary'])
                target = value
                for key in path[:-1]:
                    target = target[key]
                old = target[path[-1]]
                target[path[-1]] = not old if isinstance(old, bool) else old + 1
                with self.subTest(behavior=case['behavior'], path=path), self.assertRaises(wire.WireError):
                    wire.verify_summary(value, case['behavior'], 60)

    def test_complete_failure_report_and_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary, report = Path(temporary) / 'binary', Path(temporary) / 'report.json'
            binary.write_bytes(b'fixture binary')
            argv = ['interop_ber', '--binary', str(binary), '--report', str(report)]
            with mock.patch.object(wire, 'exercise', side_effect=[wire.WireError('injected')] + [None] * 59) as exercise, \
                    mock.patch.object(sys, 'platform', 'linux'), mock.patch.object(sys, 'argv', argv), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(wire.main(), 1)
            self.assertEqual(exercise.call_count, 60)
            value = json.loads(report.read_text())
            self.assertTrue(value['completed'])
            self.assertEqual((value['passed'], value['failed']), (59, 1))
            self.assertEqual(value['cases'][0]['error'], 'injected')
            bad_fixture = Path(temporary) / 'requests.json'
            bad_fixture.write_text('{}')
            with mock.patch.object(wire, 'VECTORS', bad_fixture), mock.patch.object(sys, 'argv', argv), \
                    mock.patch.object(wire, 'exercise') as exercise, self.assertRaises(wire.WireError):
                wire.main()
            exercise.assert_not_called()


if __name__ == '__main__':
    unittest.main()
