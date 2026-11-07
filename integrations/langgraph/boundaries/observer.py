"""Separate observer owns its file-backed test key; private bytes are never exported."""
import argparse
import os
from pathlib import Path
import sys
import time
import uuid
from cryptography.hazmat.primitives import serialization
from integrations.langgraph.run import disable_network, encoded
from integrations.langgraph.temporal.core import identity, tick
from tools.airep_v02.json_input import loads
from tools.airep_v02.producer import digest_bytes
from .binding import Writer, exact


def sample(path, origin):
    start = time.monotonic_ns() - origin
    raw = path.read_bytes() if path.exists() else b''
    return {'start': start, 'end': time.monotonic_ns() - origin, 'bytes_hex': raw.hex()}


def project(source):
    exact(source, 'schema identity nonce clock_id before after')
    if source['schema'] != 'boundary-observation-v1':
        raise ValueError('unsupported observer source')
    identity(source['identity'])
    for key in ('nonce', 'clock_id'):
        if type(source[key]) is not str or not source[key] or len(source[key]) > 256:
            raise ValueError('explicit observer nonce and clock required')
    samples = []
    for name in ('before', 'after'):
        s = source[name]; exact(s, 'start end bytes_hex')
        if not tick(s['start']) or not tick(s['end']) or s['start'] > s['end']:
            raise ValueError('invalid observation interval')
        raw = bytes.fromhex(s['bytes_hex'])
        if len(raw) > 131072 or (raw and not raw.endswith(b'\n')):
            raise ValueError('invalid effect file')
        rows = [loads(line) for line in raw.splitlines()]
        for i, row in enumerate(rows, 1):
            exact(row, 'identity step')
            if row['identity'] != source['identity'] or type(row['step']) is not int or row['step'] != i:
                raise ValueError('effect identity or append sequence mismatch')
        samples.append((raw, len(rows)))
    if source['before']['end'] > source['after']['start'] or not samples[1][0].startswith(samples[0][0]):
        raise ValueError('observation order or append-only history not established')
    return {'identity': source['identity'], 'nonce': source['nonce'], 'clock_id': source['clock_id'],
            'window': [source['before']['start'], source['after']['end']], 'cutoff': source['after']['end'],
            'status': 'QUIESCENT_REPORTED' if samples[0][0] == samples[1][0] else 'CONTINUED_REPORTED',
            'before_count': samples[0][1], 'after_count': samples[1][1],
            'boundary': 'local-worker-business-file', 'qualification': 'two samples; same-host author trust'}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--root', type=Path, required=True); args = ap.parse_args()
    disable_network(); root = args.root
    private, public = root / 'private', root / 'public'
    private.mkdir(mode=0o700); public.mkdir()
    writer = Writer('observer'); key_path = private / 'signing.key'
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(writer.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        stream.flush(); os.fsync(stream.fileno())
    ready = {'schema': 'observer-ready-v1', 'pid': os.getpid(), 'trust': writer.trust}
    (public / 'record.json').write_bytes(encoded(writer.sign(ready, {'kind': 'observer-ready'})))
    origin, clock, windows = time.monotonic_ns(), 'observer-' + str(uuid.uuid4()), {}
    def emit(value):
        sys.stdout.buffer.write(encoded(value)); sys.stdout.buffer.flush()
    emit({'kind': 'ready', 'pid': os.getpid(), 'trust': writer.trust, 'clock_id': clock,
          'key_hash': digest_bytes(key_path.read_bytes()), 'record_hash': digest_bytes((public / 'record.json').read_bytes()),
          'key_mode': key_path.stat().st_mode & 0o777, 'record_mode': (public / 'record.json').stat().st_mode & 0o777,
          'namespaces': {kind: os.readlink('/proc/self/ns/' + kind) for kind in ('user', 'pid', 'mnt', 'net')}})
    try:
        for line in sys.stdin.buffer:
            request = loads(line)
            if request['op'] == 'start':
                nonce = request['nonce']
                if nonce in windows:
                    raise ValueError('duplicate observation nonce')
                path = Path(request['path']); identity(request['identity'])
                windows[nonce] = (request['identity'], path, sample(path, origin))
                emit({'kind': 'window_started', 'nonce': nonce})
            elif request['op'] == 'end':
                scope, path, before = windows.pop(request['nonce'])
                source = {'schema': 'boundary-observation-v1', 'identity': scope, 'nonce': request['nonce'],
                          'clock_id': clock, 'before': before, 'after': sample(path, origin)}
                delivery = writer.sign(source, project(source))
                (public / ('effect-' + scope['target_id'] + '.json')).write_bytes(encoded(delivery))
                emit({'kind': 'observation', 'nonce': request['nonce'], 'delivery': delivery})
            elif request['op'] == 'close':
                emit({'kind': 'owner_check', 'key_hash': digest_bytes(key_path.read_bytes()),
                      'record_hash': digest_bytes((public / 'record.json').read_bytes()),
                      'key_mode': key_path.stat().st_mode & 0o777, 'record_mode': (public / 'record.json').stat().st_mode & 0o777,
                      'owner_can_write': (public / 'owner-write-check.json').write_bytes(b'{}\n') == 3})
                break
            else:
                raise ValueError('unsupported observer operation')
    finally:
        key_path.unlink(missing_ok=True)
        private.rmdir()


if __name__ == '__main__':
    main()
