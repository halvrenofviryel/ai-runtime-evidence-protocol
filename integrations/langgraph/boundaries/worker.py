"""Real LangGraph target and deliberately hostile probes inside the executor view."""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import sys
import threading
import time
from typing import TypedDict
import uuid

from integrations.langgraph.run import disable_network, encoded
from tools.airep_v02.json_input import loads


def probes(work, public, key):
    results = []
    def attempt(name, operation):
        try:
            operation(); results.append({'operation': name, 'allowed': True, 'errno': None})
        except OSError as exc:
            results.append({'operation': name, 'allowed': False, 'errno': exc.errno})
    def append(path):
        with path.open('ab') as stream:
            stream.write(b'ATTACK\n')
    record = public / 'record.json'
    attempt('record_append', lambda: append(record))
    attempt('record_truncate', lambda: os.truncate(record, 0))
    attempt('record_chmod', lambda: os.chmod(record, 0o000))
    attempt('record_unlink', record.unlink)
    replacement = work / 'replacement'; replacement.write_bytes(b'ATTACK\n')
    attempt('record_replace', lambda: os.replace(replacement, record))
    alias = work / 'record-link'; alias.symlink_to(record)
    attempt('record_symlink_write', lambda: append(alias))
    attempt('key_read', key.read_bytes)
    attempt('key_write', lambda: append(key))
    attempt('key_unlink', key.unlink)
    attempt('own_business_write', lambda: (work / 'own-write-check').write_bytes(b'ok\n'))
    libc = ctypes.CDLL(None, use_errno=True)
    def syscall(call, *args):
        if call(*args) != 0:
            number = ctypes.get_errno(); raise OSError(number, os.strerror(number))
    attempt('nested_user_namespace', lambda: syscall(libc.unshare, 0x10000000))
    attempt('observer_remount_rw', lambda: syscall(libc.mount, None, str(public).encode(), None, 32 | 4096, None))
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    mount = [line.split()[5] for line in Path('/proc/self/mountinfo').read_text().splitlines()
             if line.split()[4] == str(public)]
    return {'attempts': results, 'cap_eff': status['CapEff'].strip(), 'no_new_privs': status['NoNewPrivs'].strip(),
            'observer_mount_options': mount, 'namespace_pid': os.getpid(),
            'namespaces': {kind: os.readlink('/proc/self/ns/' + kind) for kind in ('user', 'pid', 'mnt', 'net')}}


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--request', type=Path)
    parser.add_argument('--baseline', type=Path)
    args = parser.parse_args()
    disable_network(); sys.dont_write_bytecode = True
    if args.baseline:
        # Disposable canaries only; never use the live observer key in this control.
        root = args.baseline; root.mkdir()
        record = root / 'record'; key = root / 'key'
        record.write_bytes(b'original'); key.write_bytes(os.urandom(32))
        read = len(key.read_bytes()) == 32; record.write_bytes(b'changed'); os.chmod(record, 0o600)
        print(encoded({'key_read': read, 'record_write': record.read_bytes() == b'changed',
                       'record_chmod': record.stat().st_mode & 0o777 == 0o600}).decode(), end='')
        key.unlink(); return
    from langgraph.graph import StateGraph, START, END
    from langgraph.checkpoint.memory import InMemorySaver
    from langgraph.types import interrupt
    request = loads(args.request.read_bytes())
    class State(TypedDict):
        done: bool
    scope = dict(request['identity'], runtime_epoch=str(uuid.uuid4()))
    origin, clock, counter = time.monotonic_ns(), 'worker-' + scope['runtime_epoch'], 0
    lock, release = threading.Lock(), threading.Event()
    thread = None
    def emit(kind, data):
        nonlocal counter
        with lock:
            counter += 1
            value = {'event_id': 'worker-' + str(counter), 'identity': dict(scope), 'clock_id': clock,
                     'tick': time.monotonic_ns() - origin, 'kind': kind, 'data': data}
            sys.stdout.buffer.write(encoded(value)); sys.stdout.buffer.flush()
    def receive():
        raw = sys.stdin.buffer.readline()
        if not raw: raise RuntimeError('controller pipe closed')
        return raw, loads(raw)
    def effect():
        emit('inflight_ready', {})
        if not release.wait(30): raise TimeoutError('inflight barrier expired')
        with Path('/work/effects.jsonl').open('ab') as stream:
            stream.write(encoded({'identity': scope, 'step': 1})); stream.flush(); os.fsync(stream.fileno())
        emit('effect_committed', {'step': 1})
    def action(state):
        nonlocal thread
        if request['mode'] in ('inflight', 'ignore'):
            thread = threading.Thread(target=effect, daemon=False); thread.start()
        raw, command = receive()
        if command != {'op': 'pause', 'identity': scope}:
            raise ValueError('control identity mismatch')
        emit('receipt', {'command_hex': raw.hex()})
        if request['mode'] != 'ignore':
            interrupt(command)
        emit('ignored', {'operation': 'continue-without-pause'})
        return {'done': True}
    builder = StateGraph(State); builder.add_node('action', action)
    builder.add_edge(START, 'action'); builder.add_edge('action', END)
    graph = builder.compile(checkpointer=InMemorySaver(), interrupt_before=['action'])
    config = {'configurable': {'thread_id': scope['run_id'] + ':' + scope['target_id']}}
    graph.invoke({'done': False}, config, version='v2')
    initial = graph.get_state(config); scope['checkpoint_id'] = initial.config['configurable']['checkpoint_id']
    emit('ready', {'pid': os.getpid(), 'checkpoint_next': list(initial.next)})
    emit('authority_probe', probes(Path('/work'), Path('/observer'), Path('/observer-private/signing.key')))
    result = graph.invoke(None, initial.config, version='v2')
    terminal = graph.get_state(config)
    if result.interrupts:
        emit('native_paused', {'terminal_checkpoint_id': terminal.config['configurable']['checkpoint_id'],
              'next': list(terminal.next), 'interrupts': [i.value for i in result.interrupts],
              'checkpoint_interrupts': [i.value for task in terminal.tasks for i in task.interrupts]})
    else:
        emit('graph_completed', {'next': list(terminal.next)})
    while True:
        _, request = receive()
        if request == {'op': 'release_effect'} and thread:
            release.set(); thread.join(5)
            if thread.is_alive(): raise RuntimeError('effect did not complete')
            emit('release_ack', {})
        elif request == {'op': 'exit'}:
            if thread and thread.is_alive(): raise RuntimeError('inflight effect still pending')
            emit('finished', {}); return
        else:
            raise ValueError('unsupported harness operation')


if __name__ == '__main__':
    main()
