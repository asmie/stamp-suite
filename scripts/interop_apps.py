#!/usr/bin/env python3
"""Run live application pairs and record outcomes without importing protocol code.

A loopback relay records payloads and traffic class; direct cases bypass it.
Exit status reports completion, not interoperability success.
"""
import argparse
import contextlib
import hashlib
import hmac
import itertools
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
KEY = 'interop-test-key-2026'
ENV = {**os.environ, 'TOKIO_WORKER_THREADS': '2', 'ROCKET_WORKERS': '2',
       'PYTHONPATH': '/tmp/stamp-interop-twampy/src'}
ENV.pop('STAMP_HMAC_KEY', None)


def udp(ip):
    s = socket.socket(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 0))
    s.setblocking(False)
    if ':' in ip:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)
    else:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    return s


def port(ip):
    with udp(ip) as s:
        return s.getsockname()[1]


def endpoint(ip, p):
    return f'[{ip}]:{p}' if ':' in ip else f'{ip}:{p}'


def tlvs(data, auth):
    pos = 112 if auth else 44
    fields = []
    while pos + 4 <= len(data):
        if not any(data[pos:]):
            break
        flags, kind, length = struct.unpack_from('!BBH', data, pos)
        fields.append({'type': kind, 'flags': flags, 'length': length,
                       'value': data[pos + 4:pos + 4 + length].hex(), 'offset': pos,
                       'truncated': pos + 4 + length > len(data)})
        if pos + 4 + length > len(data):
            break
        pos += 4 + length
    return fields


def extensions(app, names, ip, p):
    stamp = {
        'padding': ['--extra-padding', '64'], 'time': ['--timestamp-info'],
        'cos': ['--cos', '--dscp', '46', '--ecn', '2'], 'location': ['--location'],
        'access': ['--access-report', '1'], 'followup': ['--follow-up-telemetry'],
        'destination': ['--dest-node-addr', ip], 'return': ['--return-address', ip],
        'dm': ['--direct-measurement'], 'micro': ['--micro-session-id', '7'],
        'control': ['--reflected-control-count', '3', '--reflected-control-interval-ns', '20000000'],
        'ber': ['--ber', '--ber-pattern', 'aa55', '--ber-padding-size', '64'],
        'fixed': ['--reflected-fixed-hdr'], 'hmac': ['--tlv-hmac', 'on'],
        'badflags': ['--malformed', 'bad-flags'], 'badlength': ['--malformed', 'bad-length'],
        'alternate': ['--return-address', '127.0.0.2'],
        'srv6': ['--return-srv6-sids', '::1'], 'mpls': ['--return-sr-mpls-labels', '16,32'],
        'returncc': ['--return-path-cc', '1'],
        'attached': ['--attach-ext-hdr', 'dest'],
        'attachedboth': ['--attach-ext-hdr', 'hbh', '--attach-ext-hdr', 'dest'],
    }
    tea = {
        'padding': ['padding', '-s', '64'], 'time': ['time'],
        'cos': ['class-of-service', '--dscp', 'ef', '--ecn', 'ect0'],
        'cosv2': ['class-of-service-v2', '--dscp', 'ef', '--ecn', 'ect0'],
        'location': ['location'], 'access': ['access-report', 'non-three-gpp'],
        'followup': ['followup'], 'destination': ['destination-address', '--address', ip],
        'return': ['return-path', '--address', ip], 'history': ['history'],
        'unknown': ['unrecognized'], 'destport': ['destination-port', '--port', str(p)],
        'control': ['reflected-control', '--reflected-length', '0', '--count', '3', '--interval', '1'],
        'ber': ['bit-error-rate', '--pattern', 'aa55', '-s', '64'],
        'fixed': ['reflected-fixed-header-data', '-t', 'ipv6' if ':' in ip else 'ipv4'],
        'ext': ['reflected-v6-extension-header-data'], 'hmac': ['hmac'],
        'alternate': ['return-path', '--address', '127.0.0.2'],
    }
    if app == 'stamp':
        return sum((stamp[n] for n in names), [])
    args = []
    for n in names:
        if n in ('badflags', 'badlength'):
            continue
        if args:
            args += ['--']
        args += tea[n]
    return ['tlvs'] + args if args else []


def sender_cmd(args, case, ip, target, source):
    app = case['sender']
    names = case.get('extensions', [])
    auth = case.get('sender_auth', False)
    key = KEY if case.get('key_relation', 'same') != 'wrong' else 'incorrect-key-2026'
    if case.get('key_relation') == 'zero':
        key = '\x00' * 16  # stamp only; HMAC equivalent to Teaparty's fallback 00
    if app == 'stamp':
        cmd = [str(args.stamp), '--remote-addr', ip, '--remote-port', str(target),
               '--local-addr', ip, '--local-port', str(source), '--count', str(case.get('count', 2)),
               '--send-delay', '20', '--timeout', '1', '--hwtstamp', 'off',
               '--output-format', 'json', '--auth-mode', 'A' if auth else 'O',
               '--clock-source', case.get('sender_clock', 'NTP'), '--ssid', str(case.get('ssid', 42))]
        if not auth and 'hmac' not in names:
            cmd += ['--tlv-hmac', 'off']
        if auth or case.get('sender_key', False) or 'hmac' in names:
            cmd += ['--hmac-key', key.encode().hex()]
        cmd += tune_cos(extensions(app, names, ip, target), app, case)
        return cmd + case.get('sender_options', [])
    if app == 'tea':
        cmd = [str(args.tea), '-dd', 'sender', ip, str(target), '--src-port', str(source)]
        if case.get('ssid', 42):
            cmd += ['--ssid', str(case.get('ssid', 42))]
        if auth:
            cmd += ['--authenticated', key]
        for n in names:
            if n in ('badflags', 'badlength'):
                cmd += ['--malformed', 'bad-flags' if n == 'badflags' else 'bad-length']
        return cmd + case.get('sender_options', []) + tune_cos(extensions(app, names, ip, target), app, case)
    if app == 'twampy':
        return ['python3', '-m', 'twampy', 'sender', endpoint(ip, target), endpoint(ip, source),
                '--count', '2', '--interval', '100', '--padding', str(case.get('padding', 128)), '-d']
    if app == 'stamplite':
        return ['/tmp/stamp-interop-stamplite/build/stamp_sender', ip, str(target), '2',
                str(int(auth)), '0', '500000', '0', '20000', str(case.get('ssid', 42)),
                '0', case['key_file']]
    if app == 'xilong':
        return ['/tmp/stamp-interop-xilong/build/stamp-client', '-c', '2', '-P', str(target)] + (
            ['-p'] if auth else []) + [ip]
    return [str(args.cujo / 'twamp-light-client'), f'{ip}:{target}', '-a', ip,
            '-P', str(source), '-n', '2', '-l', str(case.get('padding', 128)), '-t', '1',
            '--ip', '6' if ':' in ip else '4', '-i', '20', '--constant-inter-packet-delay',
            '--print-lost-packets', '--print-digest']


def tune_cos(cmd, app, case):
    if 'cos_dscp' in case and '--dscp' in cmd:
        value = case['cos_dscp']
        cmd[cmd.index('--dscp') + 1] = str(value) if app == 'stamp' else {0: 'cs0', 8: 'cs1', 46: 'ef', 56: 'cs7'}[value]
    if 'cos_ecn' in case and '--ecn' in cmd:
        value = case['cos_ecn']
        cmd[cmd.index('--ecn') + 1] = str(value) if app == 'stamp' else ['not-ect', 'ect1', 'ect0', 'ce'][value]
    return cmd


@contextlib.contextmanager
def reflector(args, case, ip, p, directory, result):
    app = case['reflector']
    stateful = case.get('stateful', True)
    if app == 'stamp':
        cmd = [str(args.stamp), '-i', '--local-addr', ip, '--local-port', str(p),
               '--hwtstamp', 'off', '--auth-mode', 'A' if case.get('reflector_auth') else 'O',
               '--clock-source', case.get('reflector_clock', 'NTP')]
        if case.get('reflector_key', True):
            cmd += ['--hmac-key', KEY.encode().hex()]
        if stateful:
            cmd += ['--stateful-reflector']
        cmd += case.get('reflector_options', [])
    elif app == 'tea':
        meta = port('127.0.0.1')
        config = directory / 'teaparty.yaml'
        config.write_text(f'-\n  - general:\n      stateless: {str(not stateful).lower()}\n'
                          f'      listen:\n        ip: "{ip}"\n        port: {p}\n'
                          f'      meta_addr:\n        ip: 127.0.0.1\n        port: {meta}\n')
        cmd = [str(args.tea), '-dd', 'reflector', '--config', str(config)]
        result['reflector_config'] = config.read_text()
        result['meta_port'] = meta
    elif app == 'twampy':
        cmd = ['python3', '-m', 'twampy', 'responder', endpoint(ip, p), '-d']
    elif app == 'stamplite':
        cmd = ['/tmp/stamp-interop-stamplite/build/stamp_receiver', '-b', ip, '-p', str(p),
               '-s', str(int(stateful)), '-a', str(int(case.get('reflector_auth', False))),
               '-k', case['key_file'], '-r', '0']
    elif app == 'xilong':
        cmd = ['/tmp/stamp-interop-xilong/build/stamp-server', str(p)]
    else:
        cmd = [str(args.cujo / 'twamp-light-server'), '-a', ip, '-P', str(p),
               '--ip', '6' if ':' in ip else '4']
    result['reflector_command'] = cmd
    with (directory / 'reflector.log').open('w+') as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=log, env=ENV,
                                stdin=subprocess.PIPE if app == 'xilong' else subprocess.DEVNULL)
        if app == 'xilong':
            proc.stdin.write((KEY + '\n').encode()); proc.stdin.flush()
        try:
            deadline = time.monotonic() + 4
            # Check socket readiness without sending measured-session probes.
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f'reflector startup exited: {proc.returncode}')
                table = Path('/proc/net/udp6' if ':' in ip else '/proc/net/udp').read_text()
                if any(int(row.split()[1].split(':')[1], 16) == p for row in table.splitlines()[1:]):
                    break
                time.sleep(.01)
            else:
                raise RuntimeError('reflector startup timeout')
            yield
        finally:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=.5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            result['reflector_exit'] = proc.returncode
            log.seek(0)
            result['reflector_log'] = log.read()


def provision(case, result, source, dest, ip):
    if case['reflector'] != 'tea' or not case.get('provision', case.get('sender_auth', False)):
        return
    if ':' in ip:
        result['provision_gap'] = 'Teaparty SessionRequest src_ip/dst_ip require IPv4'
        return
    body = {'src_ip': ip, 'dst_ip': ip, 'src_port': source, 'dst_port': dest,
            'ssid': case.get('ssid', 42), 'key': KEY}
    result['provision_request'] = body
    deadline = time.monotonic() + 4
    while True:
        try:
            request = urllib.request.Request(f'http://127.0.0.1:{result["meta_port"]}/session',
                                             json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=.5) as response:
                result['provision_response'] = response.read().decode()
            return
        except Exception as exc:
            if not case.get('stateful', True) and getattr(exc, 'code', None) == 500:
                result['provision_gap'] = 'Teaparty stateless reflector has no session/key store (HTTP 500)'
                return
            if time.monotonic() > deadline:
                raise RuntimeError(f'provision failed: {exc}') from exc
            time.sleep(.02)


def examine(result, case):
    tx = [r for r in result['wire'] if r['direction'] == 'request']
    rx = [r for r in result['wire'] if r['direction'] == 'reply']
    result['requests'] = len(tx)
    result['replies'] = len(rx)
    auth = case.get('sender_auth', False)
    issues = []
    for rec in rx:
        data = bytes.fromhex(rec['hex'])
        rec['tlvs'] = tlvs(data, auth)
        echo_seq = 48 if auth else 24
        sent = next((bytes.fromhex(t['hex']) for t in tx
                     if bytes.fromhex(t['hex'])[:4] == data[echo_seq:echo_seq + 4]), None)
        if sent is None:
            issues.append('echoed sequence does not match any request')
            continue
        ts, echo_ts, ssid = (16, 64, 26) if auth else (4, 28, 14)
        if data[echo_ts:echo_ts + 10] != sent[ts:ts + 10]:
            issues.append('sender timestamp/error echo mismatch')
        if data[ssid:ssid + 2] != sent[ssid:ssid + 2]:
            issues.append('SSID not echoed')
        if auth:
            key = (b'\0' * 16 if case.get('key_relation') == 'zero' else KEY.encode())
            if data[96:112] != hmac.digest(key, data[:96], 'sha256')[:16]:
                issues.append('invalid reflected base HMAC')
        for f in rec['tlvs']:
            if f['type'] == 8 and not f['truncated']:
                key = KEY.encode() if case.get('key_relation') != 'zero' else b'\0' * 16
                expected = hmac.digest(key, data[:4] + data[(112 if auth else 44):f['offset']], 'sha256')[:16]
                if bytes.fromhex(f['value']) != expected:
                    issues.append('invalid reflected TLV HMAC')
    output = result.get('sender_stdout', '') + result.get('sender_stderr', '')
    if case['sender'] == 'stamp':
        try:
            stats = json.loads(result.get('sender_stdout', ''))
            result['sender_stats'] = stats
            result['accepted'] = stats.get('packets_received', 0)
        except (ValueError, TypeError):
            result['accepted'] = 0
    elif case['sender'] == 'tea':
        result['accepted'] = int('Deserialized response:' in output and
                                 not any(x in output for x in ('InvalidSignature', 'Reflected contents are wrong', 'Could not deserialize')))
    else:
        result['accepted'] = None
        if case['sender'] == 'stamplite':
            result['accepted'] = result.get('sender_artifacts', {}).get('json', '').count('"event":"received_')
    result['wire_issues'] = sorted(set(issues))
    result['tlv_outcomes'] = sorted(set((f['type'], f['flags'], f['length']) for r in rx for f in r['tlvs']))
    if case.get('direct'):
        result['outcome'] = 'accepted' if result['accepted'] else 'not-accepted'
    elif not tx:
        result['outcome'] = 'no-request'
    elif not rx:
        result['outcome'] = 'no-reply'
    elif issues:
        result['outcome'] = 'wire-misalignment'
    elif result['accepted'] == 0:
        result['outcome'] = 'sender-rejected'
    else:
        result['outcome'] = 'exchange'


def run_case(args, case, index):
    ip = case.get('ip', '127.0.0.1')
    result = {'id': index, **case, 'wire': []}
    with tempfile.TemporaryDirectory(prefix='stamp-app-interop-') as tmp, udp(ip) as relay:
        target = port(ip)
        src = port(ip)
        relay_port = relay.getsockname()[1]
        result['ports'] = {'reflector': target, 'relay': relay_port, 'sender': src}
        try:
            with reflector(args, case, ip, target, Path(tmp), result):
                provision(case, result, src if case.get('direct') else relay_port, target, ip)
                cmd = sender_cmd(args, case, ip, target if case.get('direct') else relay_port, src)
                result['sender_command'] = cmd
                if case.get('preamble_wrong_key'):
                    if not case.get('direct'):
                        raise ValueError('wrong-key preamble requires direct mode')
                    bad = sender_cmd(args, {**case, 'key_relation': 'wrong'}, ip, target, src)
                    result['preamble_command'] = bad
                    try:
                        preamble = subprocess.run(bad, capture_output=True, text=True, env=ENV, timeout=2)
                        result['preamble_stdout'] = preamble.stdout
                        result['preamble_stderr'] = preamble.stderr
                    except subprocess.TimeoutExpired:
                        result['preamble_timeout'] = True
                with (Path(tmp) / 'sender.out').open('w+') as out, (Path(tmp) / 'sender.err').open('w+') as err:
                    work = Path(tmp) / 'work'
                    work.mkdir()
                    for folder in ('logs', 'json'):
                        (Path(tmp) / 'data' / folder).mkdir(parents=True)
                    proc = subprocess.Popen(cmd, stdout=out, stderr=err, env=ENV, cwd=work,
                                            stdin=subprocess.PIPE if case['sender'] == 'xilong' else subprocess.DEVNULL)
                    if case['sender'] == 'xilong' and case.get('sender_auth'):
                        proc.stdin.write((KEY + '\n').encode()); proc.stdin.flush()
                    deadline = time.monotonic() + (4 if case['sender'] in ('twampy', 'cujo') else 1.7)
                    sender_peer = None
                    exited = None
                    while time.monotonic() < deadline:
                        if proc.poll() is not None:
                            if exited is None:
                                exited = time.monotonic()
                            if time.monotonic() - exited > .09:
                                break
                        readable, _, _ = select.select([relay], [], [], .01)
                        if not readable:
                            continue
                        data, ancillary, _, peer = relay.recvmsg(65535, 256)
                        reply = peer[1] == target
                        tos = 0
                        for level, kind, value in ancillary:
                            if level == socket.IPPROTO_IP and kind == socket.IP_TOS:
                                tos = value[0]
                            elif level == socket.IPPROTO_IPV6 and kind == socket.IPV6_TCLASS:
                                tos = struct.unpack('=i', value)[0]
                        result['wire'].append({'direction': 'reply' if reply else 'request',
                                               'hex': data.hex(), 'peer': list(peer), 'tos': tos,
                                               'time_ns': time.monotonic_ns()})
                        if not reply:
                            sender_peer = peer
                        destination = sender_peer if reply else (ip, target)
                        if destination:
                            forwarded = data
                            direction = 'reply' if reply else 'request'
                            if case.get('tamper') == direction + '-tlv-hmac':
                                forwarded = data[:-1] + bytes([data[-1] ^ 1])
                                result['wire'][-1]['forwarded_hex'] = forwarded.hex()
                            relay.setsockopt(socket.IPPROTO_IPV6 if ':' in ip else socket.IPPROTO_IP,
                                             socket.IPV6_TCLASS if ':' in ip else socket.IP_TOS, tos)
                            relay.sendto(forwarded, destination)
                    if proc.poll() is None:
                        result['sender_timeout'] = True
                        proc.kill()
                    proc.wait()
                    result['sender_exit'] = proc.returncode
                    out.seek(0); err.seek(0)
                    result['sender_stdout'] = out.read()
                    result['sender_stderr'] = err.read()
                    if case['sender'] == 'stamplite':
                        result['sender_artifacts'] = {
                            'log': '\n'.join(p.read_text() for p in (Path(tmp) / 'data/logs').glob('*')),
                            'json': '\n'.join(p.read_text() for p in (Path(tmp) / 'data/json').glob('*'))}
        except Exception as exc:
            result['harness_error'] = repr(exc)
    examine(result, case)
    return result


COMMON = ['padding', 'time', 'cos', 'location', 'access', 'followup', 'destination', 'return']
STAMP_EXTRA = ['dm', 'micro', 'control', 'ber', 'fixed', 'hmac', 'badflags', 'badlength', 'srv6', 'mpls', 'returncc']
TEA_EXTRA = ['cosv2', 'history', 'unknown', 'destport', 'control', 'ber', 'fixed', 'ext', 'hmac', 'badflags', 'badlength']


def matrix(suite):
    roles = [('stamp', 'tea'), ('tea', 'stamp')]
    if suite == 'smoke':
        for sender, ref in roles:
            for auth in (False, True):
                for names in ([], ['time', 'cos'], ['hmac']):
                    yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=auth, extensions=names, group='smoke')
        return
    if suite in ('full', 'core'):
        for sender, ref in roles:
            for ip, auth, stateful, names in itertools.product(('127.0.0.1', '::1'), (False, True), (False, True), [[]] + [[n] for n in COMMON + (STAMP_EXTRA if sender == 'stamp' else TEA_EXTRA)]):
                yield dict(sender=sender, reflector=ref, ip=ip, sender_auth=auth, reflector_auth=auth, stateful=stateful, extensions=names, group='singles')
        for sender, ref in roles:
            for auth, stateful, clock in itertools.product((False, True), (False, True), ('NTP', 'PTP')):
                for direct in (False, True):
                    yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=auth,
                               stateful=stateful, extensions=[], direct=direct,
                               **({'sender_clock': clock} if sender == 'stamp' else {'reflector_clock': clock}), group='clocks-direct')
        for sender, ref in roles:
            for auth, relation in itertools.product((False, True), ('wrong', 'same')):
                yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=not auth,
                           key_relation=relation, extensions=[], group='mixed-modes')
        for sender, ref in roles:
            for names in ([n] for n in COMMON + ['hmac']):
                for auth, policy in itertools.product((False, True), ('default', 'ignore', 'deny', 'reflector-only')):
                    if ref == 'tea' and policy != 'default':
                        continue
                    opts = {'default': [], 'ignore': ['--tlv-mode', 'ignore'],
                            'deny': ['--allowed-dscp', 'none', '--allowed-ecn', 'none', '--location-disclose', 'none'],
                            'reflector-only': ['--timestamp-info', '--cos', '--location', '--direct-measurement', '--extra-padding', '64']}[policy]
                    yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=auth,
                               extensions=[] if policy == 'reflector-only' else names,
                               reflector_options=opts, policy=policy, group='policies')
        for sender, ref in roles:
            for auth in (False, True):
                yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=auth,
                           extensions=[], direct=True, group='direct-auth')
        for sender, ref in roles:
            for auth in (False, True):
                for names in (['attached'], ['attachedboth']) if sender == 'stamp' else [['ext']]:
                    yield dict(sender=sender, reflector=ref, ip='::1', sender_auth=auth, reflector_auth=auth,
                               direct=True, extensions=names, sender_options=[] if sender == 'stamp' else ['--destination-ext', '1,4'], group='ipv6-attached')
    if suite in ('full', 'subsets'):
        for sender, ref in roles:
            for auth in (False, True):
                for bits in range(1 << len(COMMON)):
                    yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=auth,
                               extensions=[n for i, n in enumerate(COMMON) if bits & (1 << i)], group='exhaustive-common-subsets')
    if suite in ('full', 'pairs'):
        for sender, ref in roles:
            menu = COMMON + (STAMP_EXTRA if sender == 'stamp' else TEA_EXTRA)
            for names in itertools.combinations(menu, 2):
                yield dict(sender=sender, reflector=ref, sender_auth=False, reflector_auth=False,
                           extensions=list(names), group='all-pairs')
            for n in menu:
                if n != 'hmac':
                    for auth in (False, True):
                        yield dict(sender=sender, reflector=ref, sender_auth=auth, reflector_auth=auth,
                                   extensions=[n, 'hmac'], group='hmac-composition')
    if suite in ('full', 'other'):
        for peer in ('twampy', 'cujo'):
            for ip in ('127.0.0.1', '::1'):
                for auth, clock, names in itertools.product((False, True), ('NTP', 'PTP'), [[]] + [[n] for n in COMMON + ['dm', 'micro', 'hmac', 'control', 'ber']]):
                    yield dict(sender='stamp', reflector=peer, ip=ip, sender_auth=auth,
                               sender_clock=clock, extensions=names, group='other-reflector')
                for stateful, strict, clock in itertools.product((False, True), (False, True), ('NTP', 'PTP')):
                    yield dict(sender=peer, reflector='stamp', ip=ip, stateful=stateful,
                               reflector_clock=clock, reflector_options=['--strict-packets'] if strict else [], group='other-sender')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stamp', type=Path, default=ROOT / 'target/debug/stamp-suite')
    parser.add_argument('--tea', type=Path, default=Path('/tmp/stamp-interop-teaparty-target/debug/teaparty'))
    parser.add_argument('--cujo', type=Path, default=Path('/tmp/stamp-interop-cujo/build'))
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--cases', type=Path, help='Run explicit JSON case configurations')
    parser.add_argument('--suite', choices=['smoke', 'core', 'subsets', 'pairs', 'other', 'full'], default='full')
    args = parser.parse_args()
    cases = json.loads(args.cases.read_text()) if args.cases else list(matrix(args.suite))
    report = {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'platform': platform.platform(), 'expected': len(cases), 'cases': [],
              'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'binary_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (args.stamp, args.tea) if p.exists()}}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    for index, case in enumerate(cases):
        result = run_case(args, case, index)
        report['cases'].append(result)
        if (index + 1) % 20 == 0 or index == len(cases) - 1:
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            counts = {}
            for r in report['cases']:
                counts[r['outcome']] = counts.get(r['outcome'], 0) + 1
            print(f'{index + 1}/{len(cases)} {counts}', flush=True)
    report['completed_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
