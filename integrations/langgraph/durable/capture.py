"""Two real processes, one durable thread. Local experimental harness only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
from typing import TypedDict
import uuid

from integrations.langgraph.run import disable_network, encoded, utc, ROOT


def sha(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def snapshot_state(state):
    return {'checkpoint_id': state.config['configurable']['checkpoint_id'],
            'next': list(state.next), 'values': state.values,
            'interrupts': [i.value for task in state.tasks for i in task.interrupts]}


def worker(directory, phase):
    disable_network()
    os.environ['LANGGRAPH_STRICT_MSGPACK'] = 'true'
    from langgraph.checkpoint.sqlite import SqliteSaver
    from langgraph.graph import StateGraph, START, END
    from langgraph.types import Command, interrupt

    class State(TypedDict):
        run_id: str
        control_id: str
        completed: bool

    root = Path(directory)
    request = json.loads((root / 'request.json').read_bytes())
    epoch, pid = str(uuid.uuid4()), os.getpid()
    clock, origin = 'worker-' + epoch, time.monotonic_ns()
    events = []
    def emit(kind, data):
        events.append({'event_id': 'worker-event-' + str(len(events) + 1),
                       'runtime_epoch': epoch, 'clock_id': clock,
                       'tick': time.monotonic_ns() - origin, 'kind': kind, 'data': data})
    business = sqlite3.connect(root / 'business.sqlite')
    business.execute('PRAGMA synchronous=FULL')
    business.execute('CREATE TABLE IF NOT EXISTS effects (seq INTEGER PRIMARY KEY, '
                     'effect_key TEXT UNIQUE, stage TEXT, run_id TEXT, runtime_epoch TEXT, invocation_id TEXT)')
    invocation = str(uuid.uuid4())
    def effect(stage):
        obligation = request['run_id'] + ':' + stage
        key = obligation if request['mode'] == 'idempotent' else obligation + ':' + invocation
        with business:
            cursor = business.execute('INSERT OR IGNORE INTO effects '
                '(effect_key, stage, run_id, runtime_epoch, invocation_id) VALUES (?, ?, ?, ?, ?)',
                (key, stage, request['run_id'], epoch, invocation))
        emit('effect_attempt', {'obligation': obligation, 'stage': stage,
                               'invocation_id': invocation, 'inserted': cursor.rowcount == 1})
    def action(state):
        if state['run_id'] != request['run_id'] or state['control_id'] != request['control_id']:
            raise ValueError('loaded state does not belong to this run/control')
        emit('node_entered', {'invocation_id': invocation})
        effect('before_interrupt')
        answer = interrupt({'run_id': state['run_id'], 'control_id': state['control_id'], 'operation': 'pause'})
        if answer != {'operation': 'resume', 'run_id': state['run_id'], 'control_id': state['control_id']}:
            raise ValueError('resume command mismatch')
        emit('resume_returned', {'answer': answer})
        effect('after_resume')
        return {'completed': True}

    checkpoint = root / 'checkpoints.sqlite'
    before_hash = sha(checkpoint.read_bytes()) if checkpoint.exists() else None
    try:
        with SqliteSaver.from_conn_string(str(checkpoint)) as saver:
            builder = StateGraph(State)
            builder.add_node('action', action)
            builder.add_edge(START, 'action'); builder.add_edge('action', END)
            graph = builder.compile(checkpointer=saver)
            config = {'configurable': {'thread_id': request['thread_id']}}
            if phase == 'pause':
                loaded = None
                result = graph.invoke({'run_id': request['run_id'], 'control_id': request['control_id'],
                                       'completed': False}, config, version='v2', durability='sync')
            else:
                loaded = snapshot_state(graph.get_state(config))
                result = graph.invoke(Command(resume={'operation': 'resume', 'run_id': request['run_id'],
                    'control_id': request['control_id']}), config, version='v2', durability='sync')
            terminal = snapshot_state(graph.get_state(config))
        record = {'schema': 'durable-worker-v1', 'phase': phase, 'pid': pid, 'runtime_epoch': epoch,
                  'thread_id': request['thread_id'], 'run_id': request['run_id'],
                  'control_id': request['control_id'], 'mode': request['mode'],
                  'checkpoint_before_hash': before_hash, 'loaded': loaded, 'terminal': terminal,
                  'result_interrupts': [i.value for i in result.interrupts], 'events': events}
        (root / (phase + '-worker.json')).write_bytes(encoded(record))
    finally:
        business.close()


def sample(root, origin):
    start = time.monotonic_ns() - origin
    with sqlite3.connect(root / 'business.sqlite') as conn:
        rows = conn.execute('SELECT seq, effect_key, stage, run_id, runtime_epoch, invocation_id '
                            'FROM effects ORDER BY seq').fetchall()
    return {'start': start, 'end': time.monotonic_ns() - origin, 'rows_hex': encoded(rows).hex()}


def capture(root, mode, *, timeout=30):
    if mode not in ('repeat', 'idempotent'):
        raise ValueError('unsupported mode')
    root.mkdir(parents=True, exist_ok=False)
    request = {'workflow_id': 'durable-local-workflow', 'thread_id': str(uuid.uuid4()),
               'run_id': str(uuid.uuid4()), 'control_id': 'pause-1', 'attempt_id': 'attempt-1',
               'target_id': 'worker-1', 'mode': mode}
    (root / 'request.json').write_bytes(encoded(request))
    origin, clock = time.monotonic_ns(), 'harness-session-' + str(uuid.uuid4())
    records, sources, lifecycle = {}, [], []
    def run(phase):
        start = time.monotonic_ns() - origin
        with (root / (phase + '.log')).open('wb') as log:
            process = subprocess.Popen([sys.executable, '-m', 'integrations.langgraph.durable.capture',
                '--worker', phase, '--directory', str(root.resolve())], cwd=ROOT, stdout=log, stderr=log,
                env={'PATH': os.environ.get('PATH', ''), 'LANG': 'C.UTF-8'})
            forced = False
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                forced = True
                process.kill(); code = process.wait(timeout=5)
            lifecycle.append({'phase': phase, 'pid': process.pid, 'start': start,
                              'end': time.monotonic_ns() - origin, 'exitcode': code, 'forced_cleanup': forced})
        (root / 'lifecycle.json').write_bytes(encoded(lifecycle))
        if forced or code != 0:
            raise RuntimeError('worker failed; see lifecycle and phase log, cleanup is not a successful pause')
        raw = (root / (phase + '-worker.json')).read_bytes()
        record = json.loads(raw)
        if record['pid'] != process.pid:
            raise ValueError('worker PID mismatch')
        records[phase] = record
        shutil.copyfile(root / 'checkpoints.sqlite', root / (phase + '-checkpoint.sqlite'))
        return raw
    def source(scope, event_id, kind, data):
        item = {'schema': 'durable-source-v1', 'identity': scope, 'thread_id': request['thread_id'],
                'clock_id': clock, 'event_id': event_id, 'tick': time.monotonic_ns() - origin,
                'timestamp_utc': utc(), 'kind': kind, 'data': data}
        sources.append(item)
    pause_raw = run('pause')
    pause = records['pause']
    scope = {k: request[k] for k in ('workflow_id', 'run_id', 'control_id', 'attempt_id', 'target_id')}
    scope.update(runtime_epoch=pause['runtime_epoch'], checkpoint_id=pause['terminal']['checkpoint_id'])
    source(dict(scope), 'execution-1', 'checkpoint_paused', {'worker_hex': pause_raw.hex()})
    before = sample(root, origin); time.sleep(0.01); after = sample(root, origin)
    source(dict(scope), 'effect-1', 'effect_sampled', {'before': before, 'after': after})
    before_resume = sample(root, origin)
    resume_raw = run('resume')
    resumed = records['resume']
    if (resumed['loaded'] != pause['terminal']
        or resumed['checkpoint_before_hash'] != sha((root / 'pause-checkpoint.sqlite').read_bytes())
        or resumed['pid'] == pause['pid'] or resumed['runtime_epoch'] == pause['runtime_epoch']):
        raise ValueError('durable process/checkpoint continuity not established')
    scope['runtime_epoch'] = resumed['runtime_epoch']
    source(dict(scope), 'execution-1', 'resume_completed', {'worker_hex': resume_raw.hex(),
        'pause_worker_hex': pause_raw.hex(), 'paused_checkpoint_hash': sha((root / 'pause-checkpoint.sqlite').read_bytes())})
    source(dict(scope), 'effect-1', 'effect_sampled', {'before': before_resume, 'after': sample(root, origin)})
    quiet_before = sample(root, origin); time.sleep(0.01)
    source(dict(scope), 'effect-2', 'effect_sampled', {'before': quiet_before, 'after': sample(root, origin)})
    (root / 'sources.jsonl').write_bytes(b''.join(encoded(item) for item in sources))
    return {'request': request, 'workers': records, 'lifecycle': lifecycle,
            'sources': sources, 'paused_checkpoint_hash': sha((root / 'pause-checkpoint.sqlite').read_bytes())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', choices=('pause', 'resume'), required=True)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    worker(args.directory, args.worker)


if __name__ == '__main__':
    main()
