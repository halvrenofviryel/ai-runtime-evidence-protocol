"""One real LangGraph target; delegates over Unix sockets from this process."""
import argparse
import fcntl
import os
from pathlib import Path
import socket
import sys
import threading
import time
import uuid
from typing import TypedDict
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import interrupt
from integrations.langgraph.run import encoded
from tools.airep_v02.json_input import loads
from .binding import Writer
from .transport import read_line, send_attempt


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args(); request = loads(args.request.read_bytes())
    target, work = request['identity']['target_id'], args.request.parent
    scope = dict(request['identity'], runtime_epoch=str(uuid.uuid4()))
    writer = Writer(target); events = []; start = time.monotonic_ns(); lock = threading.Lock()
    cancel, stopped, first_effect = threading.Event(), threading.Event(), threading.Event()
    control = {}; result = {}; paused = None; configured = None; dropped = False

    def emit(kind, data):
        with lock:
            events.append({'seq': len(events)+1, 'tick': time.monotonic_ns()-start, 'kind': kind, 'data': data})
            with (work/'events.jsonl').open('ab') as stream: stream.write(encoded(events[-1]))

    class State(TypedDict):
        done: bool

    def action(state):
        step = 0
        while not cancel.wait(0.01):
            step += 1
            with (work/'effects.jsonl').open('ab') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX)
                stream.write(encoded({'identity': scope, 'step': step})); stream.flush(); os.fsync(stream.fileno())
            first_effect.set()
        interrupt(control['command'])
        return {'done': True}

    builder = StateGraph(State); builder.add_node('action', action)
    builder.add_edge(START, 'action'); builder.add_edge('action', END)
    graph = builder.compile(checkpointer=InMemorySaver(), interrupt_before=['action'])
    config = {'configurable': {'thread_id': scope['run_id']+':'+target}}
    graph.invoke({'done': False}, config, version='v2'); checkpoint = graph.get_state(config)
    scope['checkpoint_id'] = checkpoint.config['configurable']['checkpoint_id']

    def run():
        try:
            native = graph.invoke(None, checkpoint.config, version='v2'); state = graph.get_state(config)
            result.update({'terminal_checkpoint_id': state.config['configurable']['checkpoint_id'],
                'next': list(state.next), 'interrupts': [i.value for i in native.interrupts],
                'checkpoint_interrupts': [i.value for t in state.tasks for i in t.interrupts]})
        finally:
            stopped.set()

    thread = threading.Thread(target=run, daemon=True); thread.start()
    if not first_effect.wait(5): raise RuntimeError('business node did not start')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(request['socket']); server.listen(5)
        emit('ready', {'identity': scope, 'pid': os.getpid(), 'checkpoint_next': list(checkpoint.next)})
        print(encoded({'identity': scope, 'trust': writer.trust, 'pid': os.getpid()}).decode(), end='', flush=True)
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(10); raw = read_line(connection); command = loads(raw)
                if command.get('op') == 'configure':
                    if configured is not None: raise ValueError('cannot replace frozen configuration')
                    configured = command['intent']
                    if configured['identities'][target] != scope: raise ValueError('wrong configured identity')
                    emit('configured', {'intent': configured}); connection.sendall(encoded({'configured': True})); continue
                if command == {'op': 'snapshot'}:
                    source = {'schema': 'multitarget-node-v1', 'identity': scope,
                              'clock_id': 'worker-'+scope['runtime_epoch'], 'events': list(events)}
                    from .consumer import project_node
                    delivery = writer.sign(source, project_node(source, configured, target))
                    (work/'delivery.json').write_bytes(encoded(delivery))
                    connection.sendall(encoded(delivery)); continue
                if command == {'op': 'exit'}:
                    if paused is None: raise ValueError('unpaused worker requires explicit forced cleanup')
                    connection.sendall(encoded({'exiting': True})); return
                if configured is None or command.get('op') != 'pause' or command['identity'] != scope:
                    raise ValueError('wrong control request')
                emit('receipt', {'command_hex': raw.hex()})
                duplicate = paused is not None
                if request['mode'] == 'refuse':
                    status = 'REFUSED'; emit('refused', {'delivery_attempt_id': command['delivery_attempt_id']})
                else:
                    if not duplicate:
                        control['command'] = command; cancel.set()
                        if not stopped.wait(5): raise TimeoutError('native pause timed out')
                        emit('native_paused', result); paused = result
                    status = 'PAUSED_REPORTED'
                children = []
                next_target = configured['children'][target]
                if status == 'PAUSED_REPORTED' and next_target and not duplicate:
                    child = next_target[0]
                    for _ in range(2 if request['retry'] else 1):
                        forwarded = {'op': 'pause', 'identity': configured['identities'][child], 'sender': target,
                            'path': command['path']+[child], 'delivery_attempt_id': str(uuid.uuid4()),
                            'parent_delivery_attempt_id': command['delivery_attempt_id']}
                        attempt = send_attempt(request['sockets'][child], forwarded, emit); children.append(attempt)
                        if attempt['status'] == 'RESPONSE': break
                reply = {'target_id': target, 'delivery_attempt_id': command['delivery_attempt_id'],
                         'local_status': status, 'duplicate': duplicate, 'children': children}
                drop = request['drop_first_response'] and not dropped
                emit('reply', {'response_hex': encoded(reply).hex(), 'dropped': drop})
                if drop: dropped = True
                else: connection.sendall(encoded(reply))


if __name__ == '__main__': main()
