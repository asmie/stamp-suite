#!/usr/bin/env python3
"""Independent successor BER wire peer (Python standard library, Linux loopback)."""
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
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / 'tests/fixtures/residual-ber/requests.json'
KEY = bytes.fromhex('ab' * 16)  # public fixture key
DEFAULT = bytes.fromhex('ff00ff00')
BER, PATTERN = 243, 241  # local experimental allocations, not IANA assignments
MODES = ('open', 'keyed', 'auth')


class WireError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise WireError(message)


def digest(data, key=KEY):
    return hmac.digest(key, data, 'sha256')[:16]


def tlv(kind, value, flags=0x80):
    return struct.pack('!BBH', flags, kind, len(value)) + value


def fields(data, offset=0):
    """Complete framing, preserving duplicates and offsets for integrity checks."""
    result = []
    while offset < len(data):
        require(offset + 4 <= len(data), 'truncated header')
        flags, kind, size = struct.unpack_from('!BBH', data, offset)
        end = offset + 4 + size
        require(end <= len(data), 'truncated value')
        result.append((flags, kind, data[offset + 4:end], offset))
        offset = end
    return result


def bits(padding, pattern):
    mismatches = ''.join(f'{byte ^ pattern[i % len(pattern)]:08b}'
                         for i, byte in enumerate(padding))
    return mismatches.count('1'), max(map(len, mismatches.split('0')), default=0)


def metadata(count=0, burst=0, pattern=None, flags=0):
    value = struct.pack('!II', count, burst)
    return value + (tlv(PATTERN, pattern, flags) if pattern is not None else b'')


def make_vectors():
    """Expected byte values are independent of the Rust implementation."""
    result = []

    def add(name, request, expected):
        encode = lambda items: [dict(flags=f, type=t, value_hex=v.hex()) for f, t, v in items]
        result.append(dict(id=name, request=encode(request), expected=encode(expected)))

    pad = DEFAULT * 16
    damaged = bytearray(pad)
    damaged[0] ^= 3
    damaged[1] ^= 0xc0
    add('clean-default', [(128, BER, metadata()), (128, 1, pad)],
        [(0, BER, metadata()), (0, 1, pad)])
    add('default-errors', [(128, BER, metadata()), (128, 1, bytes(damaged))],
        [(0, BER, metadata(4, 4)), (0, 1, pad)])
    for pattern in (bytes.fromhex('aa55aa55'), bytes.fromhex('aa55cc330f')):
        clean = pattern * (60 // len(pattern))
        damaged = bytearray(clean)
        damaged[len(pattern) - 1] ^= 3
        damaged[len(pattern)] ^= 0xc0
        add(f'explicit-{len(pattern)}', [(128, BER, metadata(pattern=pattern, flags=128)),
                                       (128, 1, bytes(damaged))],
            [(0, BER, metadata(4, 4, pattern)), (0, 1, clean)])
    unknown = tlv(245, b'\x01\x02\x03', 0xb7)
    add('unknown-child', [(128, BER, metadata() + unknown), (128, 1, pad)],
        [(0, BER, metadata() + tlv(245, b'\x01\x02\x03', 128)), (0, 1, pad)])
    add('missing-padding', [(128, BER, metadata())], [(16, BER, metadata())])
    add('duplicate-padding', [(128, BER, metadata()), (128, 1, b'\x07' * 4), (128, 1, pad)],
        [(16, BER, metadata()), (0, 1, b'\x07' * 4), (0, 1, pad)])
    add('duplicate-ber', [(128, BER, metadata()), (128, BER, metadata()), (128, 1, pad)],
        [(16, BER, metadata()), (16, BER, metadata()), (0, 1, pad)])
    duplicate = metadata(pattern=DEFAULT, flags=128) + tlv(PATTERN, DEFAULT)
    duplicate_reply = metadata(pattern=DEFAULT) + tlv(PATTERN, DEFAULT, 0)
    add('duplicate-pattern', [(128, BER, duplicate), (128, 1, pad)],
        [(16, BER, duplicate_reply), (0, 1, pad)])
    add('unaligned-default', [(128, BER, metadata()), (128, 1, b'\x07' * 3)],
        [(16, BER, metadata()), (0, 1, b'\x07' * 3)])
    add('short-outer', [(128, BER, bytes(7)), (128, 1, pad)],
        [(0x50, BER, bytes(7)), (128, 1, pad)])
    short = tlv(PATTERN, b'\x01\x02\x03')
    add('short-pattern', [(128, BER, metadata() + short), (128, 1, b'\x07' * 4)],
        [(0, BER, metadata() + tlv(PATTERN, b'\x01\x02\x03', 64)), (0, 1, b'\x07' * 4)])
    fragment = bytes([128, PATTERN, 0, 4, 1, 2])
    add('nested-truncation', [(128, BER, metadata() + fragment), (128, 1, pad)],
        [(64, BER, metadata() + bytes([64]) + fragment[1:]), (128, 1, pad)])
    add('short-nested-header', [(128, BER, metadata() + bytes([128, PATTERN])), (128, 1, pad)],
        [(64, BER, metadata() + bytes([128, PATTERN])), (128, 1, pad)])
    fragment = bytes([128, 245, 0, 5, 1])
    add('processed-prefix', [(128, BER, metadata(pattern=DEFAULT, flags=128) + fragment), (128, 1, pad)],
        [(64, BER, metadata(pattern=DEFAULT) + bytes([192]) + fragment[1:]), (128, 1, pad)])
    opaque = bytes([0xb7, 245, 0, 5, 1])
    add('opaque-after-m', [(128, BER, metadata() + short + opaque), (128, 1, pad)],
        [(0, BER, metadata() + tlv(PATTERN, b'\x01\x02\x03', 64) + opaque), (0, 1, pad)])
    legacy = [(128, 240, DEFAULT[:2]), (128, 241, bytes(4)), (128, 242, bytes(4))]
    add('retired-legacy', legacy + [(128, 1, b'\x07' * 4)], legacy + [(0, 1, b'\x07' * 4)])
    return dict(schema_version=1, profile='successor-ber-v1', source='draft-ietf-bpm-stamp-ber-01',
                outer_type=BER, pattern_subtlv_type=PATTERN, vectors=result)


def unpack_items(items):
    return [(i['flags'], i['type'], bytes.fromhex(i['value_hex'])) for i in items]


def encode_packet(mode, items, sequence=7, request=None):
    auth, keyed = mode == 'auth', mode != 'open'
    base = bytearray(112 if auth else 44)
    timestamp, error, receive, echo, echo_timestamp, ttl = ((16, 24, 32, 48, 64, 80)
                                                          if auth else (4, 12, 16, 24, 28, 40))
    struct.pack_into('!I', base, 0, sequence)
    struct.pack_into('!IIHH', base, timestamp, 0x12345678, 123456789, 1, 42)
    if request is not None:
        base[:4] = request[:4]
        base[echo:echo + 4] = request[:4]
        base[echo_timestamp:echo_timestamp + 10] = request[timestamp:timestamp + 10]
        base[error + 2:error + 4] = request[error + 2:error + 4]
        struct.pack_into('!II', base, receive, 0x12345678, 1)
        base[ttl] = 64
    if auth:
        base[96:112] = digest(base[:96])
    covered = b''.join(tlv(t, v, f) for f, t, v in items if t != 1)
    padding = b''.join(tlv(t, v, f) for f, t, v in items if t == 1)
    mac = tlv(8, digest(base[:4] + covered), 0 if request is not None else 128) if keyed else b''
    return bytes(base) + covered + mac + padding


def verify_integrity(packet, mode):
    auth = mode == 'auth'
    base = 112 if auth else 44
    require(len(packet) >= base, 'short packet base')
    if auth:
        require(hmac.compare_digest(packet[96:112], digest(packet[:96])), 'invalid base HMAC')
    parsed = fields(packet, base)
    macs = [f for f in parsed if f[1] == 8]
    if mode == 'open':
        require(not macs, 'unexpected HMAC in unkeyed profile')
    else:
        require(len(macs) == 1, 'missing/duplicate HMAC TLV')
        flags, _, value, offset = macs[0]
        require(len(value) == 16 and hmac.compare_digest(value, digest(packet[:4] + packet[base:offset])),
                'invalid TLV HMAC')
        require(all(t == 1 for _, t, _, at in parsed if at > offset), 'metadata after HMAC')
    return parsed


def verify_reflector_reply(reply, sent, mode, expected, reflector_sequence=None, failure_echo=False):
    require(len(reply) == len(sent), 'asymmetric reply size')
    if failure_echo:
        # RFC 8972 §4.8 requires copying the failed HMAC, not generating a
        # fresh valid TLV HMAC over an I-marked failure echo.
        base = 112 if mode == 'auth' else 44
        require(len(reply) >= base, 'short failure echo')
        if mode == 'auth':
            require(hmac.compare_digest(reply[96:112], digest(reply[:96])), 'invalid base HMAC')
        parsed, original = fields(reply, base), fields(sent, base)
        require([(t, v) for _, t, v, _ in parsed] == [(t, v) for _, t, v, _ in original],
                'failure echo changed copied values')
        require(all(f == 32 for f, _, _, _ in parsed), 'failure echo missing I flags')
    else:
        parsed = verify_integrity(reply, mode)
    auth = mode == 'auth'
    echo, echo_timestamp, timestamp, error, receive = ((48, 64, 16, 24, 32) if auth else (24, 28, 4, 12, 16))
    expected_sequence = sent[:4] if reflector_sequence is None else struct.pack('!I', reflector_sequence)
    require(reply[:4] == expected_sequence and reply[echo:echo + 4] == sent[:4], 'wrong sequence/echo')
    require(reply[echo_timestamp:echo_timestamp + 10] == sent[timestamp:timestamp + 10], 'wrong echoed timestamp')
    require(reply[error + 2:error + 4] == sent[error + 2:error + 4], 'wrong SSID')
    require(any(reply[timestamp:timestamp + 8]) and any(reply[receive:receive + 8]), 'missing timestamps')
    actual = [(f, t, v) for f, t, v, _ in parsed if t != 8]
    require(actual == expected, 'wrong BER/padding fields or flags')


def socket_for(ip, timeout=2):
    sock = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, 0))
    sock.settimeout(timeout)
    return sock


def send(sock, packet, target, result):
    require(sock.sendto(packet, target) == len(packet), 'short datagram send')
    result['wire'].append(dict(direction='tx', hex=packet.hex(), peer=list(target)))


def receive(sock, result):
    data, ancillary, flags, peer = sock.recvmsg(65535, 128)
    require(flags == 0, 'truncated datagram or ancillary data')
    result['wire'].append(dict(direction='rx', hex=data.hex(), peer=list(peer)))
    return data, peer


def environment():
    result = {**os.environ, 'TOKIO_WORKER_THREADS': '2', 'RUST_LOG': 'info'}
    result.pop('STAMP_HMAC_KEY', None)
    return result


def key_args(directory, mode):
    if mode == 'open':
        return []
    path = directory / 'key.hex'
    path.write_text(KEY.hex())
    path.chmod(0o600)
    return ['--hmac-key-file', str(path)]


@contextlib.contextmanager
def launched(command, directory, result):
    result['command'] = command
    with (directory / 'stdout').open('w+') as out, (directory / 'stderr').open('w+') as err:
        process = subprocess.Popen(command, stdout=out, stderr=err, env=environment())
        try:
            yield process, out, err
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            result['returncode'] = process.returncode
            out.seek(0)
            err.seek(0)
            result['stdout'], result['stderr'] = out.read(), err.read()


def reflector_case(binary, ip, mode, stateful, vectors, result):
    with tempfile.TemporaryDirectory(prefix='stamp-ber-wire-') as temporary:
        directory = Path(temporary)
        command = [str(binary), '--is-reflector', '--local-addr', ip, '--local-port', '0',
                   '--hwtstamp', 'off', '--log-format', 'json', '--auth-mode', 'A' if mode == 'auth' else 'O']
        command += key_args(directory, mode)
        if stateful:
            command += ['--stateful-reflector']
        if mode != 'open':
            command += ['--verify-tlv-hmac']
        with launched(command, directory, result) as (process, _, err):
            deadline = time.monotonic() + 5
            while True:
                require(process.poll() is None, 'reflector exited during startup')
                err.seek(0)
                match = re.search(r'STAMP Reflector listening on ([^ ]+)', err.read())
                if match:
                    target = (ip, int(match[1].rsplit(':', 1)[1]))
                    break
                require(time.monotonic() < deadline, 'reflector startup timeout')
                time.sleep(.01)
            # Kernel-selected reflector port; no reserve/drop race. Readiness
            # uses a retained endpoint distinct from the measured session.
            with socket_for(ip) as warmup:
                packet = encode_packet(mode, [], 1)
                warmup.sendto(packet, target)
                warmup.recvfrom(65535)
                with socket_for(ip) as sock:
                    for ordinal, vector in enumerate(vectors):
                        sequence = ordinal + 10
                        packet = encode_packet(mode, unpack_items(vector['request']), sequence)
                        send(sock, packet, target, result)
                        reply, peer = receive(sock, result)
                        require(peer[:2] == target[:2], 'wrong reply source endpoint')
                        verify_reflector_reply(reply, packet, mode, unpack_items(vector['expected']), ordinal if stateful else None)
                    if mode != 'open':
                        # Invalid TLV HMAC: nested flags and padding stay opaque.
                        value = metadata(pattern=DEFAULT, flags=0xf0)
                        items = [(128, BER, value), (128, 1, b'\x07' * 4)]
                        packet = bytearray(encode_packet(mode, items, 100))
                        mac = next(f for f in fields(packet, 112 if mode == 'auth' else 44) if f[1] == 8)
                        packet[mac[3] + 4] ^= 1
                        send(sock, bytes(packet), target, result)
                        reply, _ = receive(sock, result)
                        verify_reflector_reply(reply, packet, mode, [(32, BER, value), (32, 1, b'\x07' * 4)],
                                               len(vectors) if stateful else None, failure_echo=True)
                    if mode == 'auth':
                        packet = bytearray(encode_packet(mode, [(128, BER, metadata()), (128, 1, DEFAULT)], 101))
                        packet[96] ^= 1
                        send(sock, packet, target, result)
                        sock.settimeout(.15)
                        try:
                            receive(sock, result)
                        except TimeoutError:
                            result['wire'].append(dict(direction='timeout', expected='invalid base HMAC'))
                        else:
                            raise WireError('invalid base HMAC was accepted')


def verify_sender_request(packet, mode, pattern, padding_size, expect_ber=True, explicit=False):
    parsed = verify_integrity(packet, mode)
    require(all(f == 128 for f, _, _, _ in parsed), 'wrong sender TLV flags')
    pads = [v for _, t, v, _ in parsed if t == 1]
    metadata_fields = [v for _, t, v, _ in parsed if t == BER]
    require(len(pads) == 1 and len(pads[0]) == padding_size, 'wrong sender padding size/count')
    require(pads[0] == pattern * (padding_size // len(pattern)), 'wrong sender padding pattern')
    require(len(metadata_fields) == int(expect_ber), 'wrong sender BER count/disable behavior')
    if expect_ber:
        expected = metadata(pattern=pattern, flags=128) if explicit else metadata()
        require(metadata_fields[0] == expected, 'wrong sender counters or pattern sub-TLV')
    require(all(t in (1, 8, BER) for _, t, _, _ in parsed), 'unexpected sender TLV')
    return pads[0]


def peer_reply(request, mode, pattern, fault='valid', expect_ber=True, explicit=False):
    value = metadata(4, 4, pattern if explicit else None)
    padding = bytearray(pattern * (60 // len(pattern)))
    # Controlled reverse-path payload transform, outside TLV HMAC coverage.
    padding[0] ^= 1
    items = [(0, BER, value)] if expect_ber else []
    if fault == 'parent-c':
        items[0] = (16, BER, value)
    elif fault == 'parent-m':
        items[0] = (64, BER, value)
    elif fault in ('child-m', 'child-i', 'child-u'):
        flag = {'child-m': 64, 'child-i': 32, 'child-u': 128}[fault]
        items[0] = (0, BER, metadata(4, 4, pattern, flag))
    elif fault == 'parent-u':
        items[0] = (128, BER, value)
    elif fault == 'duplicate':
        items.append(items[0])
    elif fault == 'wrong-pattern':
        items[0] = (0, BER, metadata(4, 4, b'\x07' * 4))
    elif fault == 'large-count':
        items[0] = (0, BER, metadata(len(padding) * 8 + 1, 1, pattern if explicit else None))
    elif fault == 'resized':
        padding = padding[:-len(pattern)]
    elif fault == 'unknown-clear':
        items[0] = (0, BER, value + tlv(245, b'', 0))
    elif fault == 'duplicate-pattern':
        items[0] = (0, BER, metadata(4, 4, pattern) + tlv(PATTERN, pattern, 0))
    elif fault == 'unavailable':
        items[0] = (0, BER, metadata(2, 0, pattern if explicit else None))
        padding = bytearray(pattern * (60 // len(pattern)))
    items.append((0, 1, bytes(padding)))
    result = bytearray(encode_packet(mode, items, request=request))
    if fault == 'bad-mac':
        mac = next(f for f in fields(result, 112 if mode == 'auth' else 44) if f[1] == 8)
        result[mac[3] + 4] ^= 1
    return bytes(result)


def verify_summary(summary, behavior, padding_size):
    ber = summary['ber']
    count = 12 if behavior == 'gates' else 3
    require(summary['packets_received'] == count, 'delay/loss measurements did not continue')
    disabled = behavior in ('parent-u', 'child-u')
    require(ber['disabled_by_peer'] == disabled, 'wrong BER support state')
    samples = 0 if disabled else 2 if behavior == 'gates' else 3
    errors = 0 if disabled else 6 if behavior == 'gates' else 12
    for direction in ('forward', 'reverse'):
        stats = ber[direction]
        require(stats['packets_received'] == samples, f'wrong {direction} sample admission')
        require(stats['padding_bits'] == samples * padding_size * 8, f'wrong {direction} denominator')
        require(sum(window[direction]['packets_received'] for window in ber['intervals']) == samples,
                f'wrong {direction} interval totals')
        for metric in ('padding_bits', 'bit_errors', 'packets_with_errors', 'burst_samples'):
            require(sum(window[direction][metric] for window in ber['intervals']) == stats[metric],
                    f'wrong {direction} interval {metric}')
    require(ber['forward']['bit_errors'] == errors, 'wrong forward error total')
    require(ber['reverse']['bit_errors'] == (0 if disabled else 1 if behavior == 'gates' else 3),
            'wrong reverse error total')
    if not disabled:
        require(ber['forward']['packets_with_errors'] == samples, 'wrong errored packet total')
        require(ber['forward']['burst_samples'] == (1 if behavior == 'gates' else 3), 'unavailable burst counted')
        require(ber['forward']['max_burst_bits'] == 4, 'wrong forward burst maximum')
        require(ber['forward']['average_max_burst_bits'] == 4, 'wrong forward burst average')
        require(ber['reverse']['max_burst_bits'] == 1, 'wrong reverse burst maximum')
        reverse_errors = 1 if behavior == 'gates' else 3
        require(ber['reverse']['packets_with_errors'] == reverse_errors, 'wrong reverse errored packet total')
        require(ber['reverse']['burst_samples'] == samples, 'wrong reverse burst samples')
        require(ber['reverse']['average_max_burst_bits'] == reverse_errors / samples,
                'wrong reverse burst average')
        for direction in ('forward', 'reverse'):
            stats = ber[direction]
            ratio = stats['bit_errors'] / (samples * padding_size * 8)
            require(stats['bit_error_ratio'] == ratio, f'wrong {direction} BER ratio')
            require(stats['bit_errors_per_million'] == ratio * 1_000_000,
                    f'wrong {direction} bit error rate')
            require(stats['packets_with_errors_per_million'] == stats['packets_with_errors'] / samples * 1_000_000,
                    f'wrong {direction} errored packet rate')


def sender_case(binary, ip, mode, explicit, behavior, result):
    pattern = bytes.fromhex('aa55cc330f') if explicit else DEFAULT
    with tempfile.TemporaryDirectory(prefix='stamp-ber-peer-') as temporary, socket_for(ip) as peer:
        directory = Path(temporary)
        count = 12 if behavior == 'gates' else 3
        command = [str(binary), '--local-addr', ip, '--local-port', '0', '--remote-addr', ip,
                   '--remote-port', str(peer.getsockname()[1]), '--count', str(count),
                   '--send-delay', '100', '--timeout', '1', '--hwtstamp', 'off', '--ssid', '42',
                   '--ber', '--ber-padding-size', '60', '--ber-interval', '1', '--output-format', 'json',
                   '--auth-mode', 'A' if mode == 'auth' else 'O']
        command += key_args(directory, mode)
        if explicit:
            command += ['--ber-pattern', pattern.hex()]
        with launched(command, directory, result) as (process, out, _):
            faults = ['valid'] * count
            if behavior == 'gates':
                faults = ['valid', 'parent-c', 'child-m', 'child-i',
                          'bad-mac' if mode != 'open' else 'unknown-clear', 'duplicate',
                          'wrong-pattern', 'large-count', 'resized', 'unavailable', 'parent-m', 'duplicate-pattern']
            elif behavior in ('parent-u', 'child-u'):
                faults[0] = behavior
            for ordinal, fault in enumerate(faults):
                packet, source = receive(peer, result)
                present = not (behavior in ('parent-u', 'child-u') and ordinal > 0)
                verify_sender_request(packet, mode, pattern, 60, present, explicit)
                reply = peer_reply(packet, mode, pattern, fault, present, explicit)
                send(peer, reply, source, result)
                if behavior == 'baseline':
                    send(peer, reply, source, result)  # same-sequence duplicates add no BER sample
            require(process.wait(timeout=4) == 0, 'sender failed')
            out.seek(0)
            summaries = [value for line in out.read().splitlines()
                         if (value := json.loads(line)).get('type') == 'summary']
            require(len(summaries) == 1, 'missing/duplicate sender summary')
            result['summary'] = summaries[0]
            verify_summary(summaries[0], behavior, 60)


def configurations():
    for ip, mode in itertools.product(('127.0.0.1', '::1'), MODES):
        for stateful in (False, True):
            yield dict(role='reflector', ip=ip, mode=mode, stateful=stateful)
        for explicit, behavior in itertools.product((False, True), ('baseline', 'gates', 'parent-u', 'child-u')):
            yield dict(role='sender', ip=ip, mode=mode, explicit=explicit, behavior=behavior)


def exercise(binary, vectors, case, result):
    if case['role'] == 'reflector':
        reflector_case(binary, case['ip'], case['mode'], case['stateful'], vectors, result)
    else:
        sender_case(binary, case['ip'], case['mode'], case['explicit'], case['behavior'], result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--write-vectors', action='store_true')
    args = parser.parse_args()
    if args.write_vectors:
        require(args.binary is None and args.report is None, 'vector generation is separate')
        VECTORS.write_text(json.dumps(make_vectors(), indent=2) + '\n')
        return 0
    if args.binary is None or args.report is None:
        parser.error('--binary and --report are required')
    require(sys.platform == 'linux', 'Linux loopback profile required')
    binary = args.binary.resolve(strict=True)
    fixture_bytes = VECTORS.read_bytes()
    fixture = json.loads(fixture_bytes)
    require(fixture == make_vectors(), 'frozen BER vectors differ; review before regenerating')
    cases = list(configurations())
    report = dict(schema_version=1, profile=fixture['profile'], started_utc=datetime.now(timezone.utc).isoformat(),
                  platform=platform.platform(), python=platform.python_version(), binary=str(binary),
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  fixtures_sha256=hashlib.sha256(fixture_bytes).hexdigest(), expected_cases=len(cases),
                  completed=False, passed=0, failed=0, cases=[])
    for case in cases:
        result = {**case, 'wire': [], 'passed': False}
        report['cases'].append(result)
        try:
            exercise(binary, fixture['vectors'], case, result)
            result['passed'] = True
        except (WireError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
            result['error'] = str(error)
        report['completed'] = len(report['cases']) == len(cases)
        report['passed'] = sum(c['passed'] for c in report['cases'])
        report['failed'] = len(report['cases']) - report['passed']
        args.report.write_text(json.dumps(report, indent=2) + '\n')
        print(('PASS' if result['passed'] else 'FAIL'), case, result.get('error', ''), flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    sys.exit(main())
