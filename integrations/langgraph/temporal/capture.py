"""Capture bounded real LangGraph runs and file effects for transport replay."""
import json
import multiprocessing as mp
import os
from pathlib import Path
import time
import uuid

from integrations.langgraph.run import disable_network, encoded, utc, TIMEOUT


def worker(directory, mode, base, clock_id, origin, commands, telemetry):
    disable_network()
    try:
        from langgraph.graph import StateGraph, START, END
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.types import interrupt
        from typing import TypedDict

        class State(TypedDict):
            steps: int

        scope = dict(base, runtime_epoch=str(uuid.uuid4()))

        def emit(kind, data):
            telemetry.send({'schema': 'captured-v1', 'identity': dict(scope),
                            'clock_id': clock_id, 'event_id': str(uuid.uuid4()),
                            'tick': time.monotonic_ns() - origin, 'timestamp_utc': utc(),
                            'kind': kind, 'data': data})

        def receive_control():
            if not commands.poll(TIMEOUT):
                raise TimeoutError('control barrier expired')
            raw = commands.recv_bytes()
            command = json.loads(raw)
            candidate = command['identity']
            if any(candidate[k] != scope[k] for k in scope if k != 'control_id'):
                raise ValueError('command scope mismatch')
            if command['operation'] != 'pause' or not candidate['control_id']:
                raise ValueError('invalid command')
            scope['control_id'] = candidate['control_id']
            emit('receiver_observed', {'command_hex': raw.hex()})
            return command

        def advance():
            if not commands.poll(TIMEOUT) or commands.recv_bytes() != b'advance':
                raise TimeoutError('action barrier expired')

        def action(state):
            command = receive_control()
            if mode in ('pause', 'unobserved'):
                interrupt(command)
            emit('handler_ignored', {'operation': 'continue-without-pause'})
            emit('quiet_barrier', {})
            advance()
            with (Path(directory) / 'effects.jsonl').open('ab') as stream:
                stream.write(encoded({'step': 1}))
                stream.flush()
                os.fsync(stream.fileno())
            emit('step_barrier', {'step': 1})
            receive_control()
            emit('handler_ignored', {'operation': 'continue-without-pause'})
            emit('second_control_barrier', {})
            advance()
            with (Path(directory) / 'effects.jsonl').open('ab') as stream:
                stream.write(encoded({'step': 2}))
                stream.flush()
                os.fsync(stream.fileno())
            return {'steps': 2}

        builder = StateGraph(State)
        builder.add_node('controlled_action', action)
        builder.add_edge(START, 'controlled_action')
        builder.add_edge('controlled_action', END)
        graph = builder.compile(checkpointer=InMemorySaver(), interrupt_before=['controlled_action'])
        config = {'configurable': {'thread_id': base['run_id']}}
        graph.invoke({'steps': 0}, config, version='v2')
        initial = graph.get_state(config)
        scope['checkpoint_id'] = initial.config['configurable']['checkpoint_id']
        emit('ready', {'pid': os.getpid(), 'checkpoint_next': list(initial.next)})
        result = graph.invoke(None, initial.config, version='v2')
        terminal = graph.get_state(config)
        data = {'terminal_checkpoint_id': terminal.config['configurable']['checkpoint_id'],
                'checkpoint_next': list(terminal.next)}
        if result.interrupts:
            data['interrupts'] = [i.value for i in result.interrupts]
            data['checkpoint_interrupts'] = [i.value for task in terminal.tasks for i in task.interrupts]
            emit('native_interrupt_observed', data)
        else:
            emit('graph_completed', data)
        emit('finished', {})
    except BaseException as exc:
        telemetry.send({'kind': 'error', 'message': str(exc), 'error_type': type(exc).__name__})
        raise
    finally:
        commands.close()
        telemetry.close()


def capture(directory, mode, *, clock_id, origin, timeout=TIMEOUT):
    if mode not in ('pause', 'ignore', 'unobserved'):
        raise ValueError('unsupported capture mode')
    directory.mkdir(parents=True, exist_ok=False)
    base = {'workflow_id': 'temporal-local-workflow', 'run_id': str(uuid.uuid4()),
            'control_id': 'pending', 'attempt_id': 'attempt-1', 'target_id': 'worker-1'}
    ctx = mp.get_context('spawn')
    receiver, sender = ctx.Pipe(duplex=False)
    reader, writer = ctx.Pipe(duplex=False)
    child = ctx.Process(target=worker, args=(str(directory), mode, base, clock_id, origin, receiver, writer))
    events, scope = [], None
    deadline = time.monotonic() + timeout
    def append(item):
        events.append(item)
        with (directory / 'events.jsonl').open('ab') as stream:
            stream.write(encoded(item))
    def until(kind):
        nonlocal scope
        while True:
            left = deadline - time.monotonic()
            if left <= 0 or not reader.poll(left):
                raise TimeoutError('waiting for ' + kind)
            item = reader.recv()
            append(item)
            if item['kind'] == 'error':
                raise RuntimeError(item['message'])
            scope = item['identity']
            if item['kind'] == kind:
                return item
    def command(control_id):
        nonlocal scope
        scope = dict(scope, control_id=control_id)
        sender.send_bytes(encoded({'identity': scope, 'operation': 'pause'}))
    def sample():
        start = time.monotonic_ns() - origin
        path = directory / 'effects.jsonl'
        data = path.read_bytes() if path.exists() else b''
        return {'start': start, 'end': time.monotonic_ns() - origin, 'bytes_hex': data.hex()}
    def observation(before, after):
        append({'schema': 'captured-v1', 'identity': dict(scope), 'clock_id': clock_id,
                'event_id': str(uuid.uuid4()), 'kind': 'effect_sampled',
                'tick': time.monotonic_ns() - origin, 'timestamp_utc': utc(),
                'data': {'before': before, 'after': after}})
    started = False
    try:
        child.start(); started = True
        receiver.close(); writer.close()
        until('ready')
        command('pause-1')
        if mode == 'ignore':
            until('quiet_barrier')
            before = sample()
            time.sleep(0.01)
            observation(before, sample())
            before = sample()
            sender.send_bytes(b'advance')
            until('step_barrier')
            observation(before, sample())
            command('pause-2')
            until('second_control_barrier')
            before = sample()
            sender.send_bytes(b'advance')
            until('finished')
            observation(before, sample())
        else:
            until('finished')
            if mode == 'pause':
                before = sample(); time.sleep(0.01)
                observation(before, sample())
        child.join(max(0, deadline - time.monotonic()))
        if child.is_alive() or child.exitcode != 0:
            raise RuntimeError('runtime did not finish successfully')
    finally:
        forced = started and child.is_alive()
        if forced:
            child.terminate(); child.join(2)
            if child.is_alive():
                child.kill(); child.join(2)
        alive = started and child.is_alive()
        cleanup = {'kind': 'cleanup', 'forced': forced, 'alive': alive,
                   'exitcode': child.exitcode if started else None}
        append(cleanup)
        for pipe in (receiver, sender, reader, writer):
            pipe.close()
        if started and not alive:
            child.close()
        if alive:
            raise RuntimeError('child cleanup failed')
    return events
