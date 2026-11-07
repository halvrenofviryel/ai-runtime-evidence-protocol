"""Controlled barriers, real targets, separate observer and bounded mount authority."""
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time
import uuid
from integrations.langgraph.run import ROOT, encoded
from tools.airep_v02.json_input import loads
from .binding import Writer


class Peer:
    def __init__(self, name, argv, log, record):
        self.name, self.record, self.buffer = name, record, b''
        self.log = log.open('wb')
        self.process = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.log, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True)
    def send(self, message, *, audit=None):
        raw = encoded(message)
        self.process.stdin.write(raw); self.process.stdin.flush()
        self.record(self.name, 'sent', encoded(audit) if audit is not None else raw)
    def read(self, timeout=20):
        deadline = time.monotonic() + timeout
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.process.stdout], [], [], remaining)[0]:
                raise TimeoutError('waiting for ' + self.name)
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk: raise RuntimeError(self.name + ' closed its output; inspect its log')
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        self.record(self.name, 'received', line + b'\n')
        return loads(line)
    def until(self, kind, timeout=20):
        deadline = time.monotonic() + timeout
        while True:
            event = self.read(max(0, deadline - time.monotonic()))
            if event.get('kind') == kind: return event
    def finish(self, timeout=5, *, force=False):
        forced = False
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if not force: raise
            forced = True; self.process.kill(); code = self.process.wait(timeout=5)
        self.record(self.name, 'cleanup', encoded({'forced': forced, 'exitcode': code, 'pid': self.process.pid}))
        self.process.stdin.close(); self.process.stdout.close(); self.log.close()
        return forced
    def abort(self):
        if self.process.poll() is None: self.process.kill()
        self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.log):
            if not stream.closed: stream.close()


def sandbox(work, observer_public):
    envroot = Path(sys.prefix).resolve()
    argv = ['/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--disable-userns', '--assert-userns-disabled',
            '--cap-drop', 'ALL', '--die-with-parent', '--new-session', '--clearenv']
    for directory in ('/usr', '/lib', '/lib64'):
        if Path(directory).exists(): argv += ['--ro-bind', directory, directory]
    argv += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/observer-private', '--remount-ro', '/observer-private',
             '--ro-bind', str(ROOT), '/repo', '--ro-bind', str(envroot), '/env',
             '--ro-bind', str(observer_public.resolve()), '/observer', '--bind', str(work.resolve()), '/work',
             '--chdir', '/repo', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
             '/env/bin/python', '-B', '-m', 'integrations.langgraph.boundaries.worker', '--request', '/work/request.json']
    return argv


def capture(root, scenario):
    if scenario not in ('both_paused', 'one_unknown', 'inflight', 'timeout'):
        raise ValueError('unsupported scenario')
    if not shutil.which('bwrap'): raise RuntimeError('bubblewrap required; no unconfined fallback')
    root.mkdir(parents=True, exist_ok=False)
    origin, schedule, peers = time.monotonic_ns(), [], []
    def record(peer, direction, raw):
        item = {'seq': len(schedule) + 1, 'tick': time.monotonic_ns() - origin,
                'peer': peer, 'direction': direction, 'message_hex': raw.hex()}
        schedule.append(item)
        with (root / 'schedule.jsonl').open('ab') as stream: stream.write(encoded(item))
    targets = ['A', 'B'] if scenario in ('both_paused', 'one_unknown') else ['A']
    intent = {'workflow_id': 'boundary-local-workflow', 'run_id': str(uuid.uuid4()),
              'control_id': 'pause-1', 'attempt_id': 'attempt-1', 'targets': targets}
    observer_root = root / 'observer'; observer_root.mkdir()
    observer = Peer('observer', [sys.executable, '-B', '-m', 'integrations.langgraph.boundaries.observer',
                    '--root', str(observer_root.resolve())], root / 'observer.log', record); peers.append(observer)
    try:
        ready = observer.until('ready')
        workers, scopes = {}, {}
        for target in targets:
            work = root / target; work.mkdir()
            mode = 'inflight' if scenario == 'inflight' else 'ignore' if scenario == 'timeout' else 'pause'
            scope = {k: intent[k] for k in ('workflow_id', 'run_id', 'control_id', 'attempt_id')}
            scope['target_id'] = target
            (work / 'request.json').write_bytes(encoded({'identity': scope, 'mode': mode}))
            peer = Peer(target, sandbox(work, observer_root / 'public'), root / (target + '.log'), record)
            peers.append(peer); workers[target] = peer
            scopes[target] = peer.until('ready')['identity']
            peer.until('authority_probe')
            if mode in ('inflight', 'ignore'): peer.until('inflight_ready')
        for target in targets:
            peer, scope = workers[target], scopes[target]
            if scenario == 'one_unknown' and target == 'B':
                # Target really runs, but delivery and observation are intentionally unavailable.
                continue
            peer.send({'op': 'pause', 'identity': scope})
            peer.until('graph_completed' if scenario == 'timeout' else 'native_paused')
            nonce = str(uuid.uuid4())
            observer.send({'op': 'start', 'nonce': nonce, 'identity': scope,
                           'path': str((root / target / 'effects.jsonl').resolve())},
                          audit={'op': 'start', 'nonce': nonce, 'identity': scope, 'source_slot': target + '/effects.jsonl'})
            observer.until('window_started')
            if scenario in ('inflight', 'timeout'):
                peer.send({'op': 'release_effect'}); peer.until('release_ack')
            observer.send({'op': 'end', 'nonce': nonce}); observer.until('observation')
        for target, peer in workers.items():
            forced = scenario == 'timeout' or (scenario == 'one_unknown' and target == 'B')
            if not forced:
                peer.send({'op': 'exit'}); peer.until('finished')
            peer.finish(timeout=0.15 if forced else 5, force=forced)
        observer.send({'op': 'close'}); observer.until('owner_check'); observer.finish()
        if (observer_root / 'private').exists(): raise RuntimeError('private key cleanup failed')
        source = {'schema': 'boundary-capture-v1', 'intent': intent, 'scenario': scenario,
                  'controller_clock_id': 'controller-' + str(uuid.uuid4()), 'schedule': schedule,
                  'authority_config': 'bwrap-minimal-ro-observer-hidden-key-v1'}
        (root / 'source.json').write_bytes(encoded(source))
        return source, ready['trust']
    finally:
        for peer in peers: peer.abort()
        # These are exclusively generated test keys, never user credentials.
        key = observer_root / 'private/signing.key'
        key.unlink(missing_ok=True)
        if key.parent.exists(): key.parent.rmdir()


def baseline(root):
    proc = subprocess.run([sys.executable, '-B', '-m', 'integrations.langgraph.boundaries.worker',
                           '--baseline', str(root.resolve())], cwd=ROOT, capture_output=True, timeout=20)
    if proc.returncode: raise RuntimeError(proc.stderr.decode())
    return loads(proc.stdout)
