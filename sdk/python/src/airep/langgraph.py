"""One-run cooperative hook for a caller-owned synchronous StateGraph.

The caller supplies the graph, key, producer identity and optional bounded file
observer. No model, provider, network transport or default trust is created.
This in-process hook is not a sandbox or a hard timeout for application code.
"""
from datetime import datetime, timezone
import importlib.metadata
import os
from pathlib import Path
import time
from uuid import uuid4
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._native import Chain, digest_bytes
from .io import encoded, read_bytes, bounded_loads
from .mapping import identity, project, native_checkpoint, BASIS

_EPOCH = (os.getpid(), 'process-' + str(uuid4()))


def process_epoch():
    global _EPOCH
    if _EPOCH[0] != os.getpid():
        _EPOCH = (os.getpid(), 'process-' + str(uuid4()))
    return _EPOCH[1]


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


class FileObserver:
    """Read only the explicitly selected local regular file; export hashes, not contents."""
    def __init__(self, path):
        self.path = Path(path).absolute()

    def sample(self, clock):
        start = clock()
        raw = read_bytes(self.path, 65536, absent_ok=True)
        return {'start': start, 'end': clock(), 'exists': raw is not None,
                'size': len(raw or b''), 'digest': digest_bytes(raw or b'')}


class ControlSession:
    def __init__(self, *, key, producer, workflow_id, node_name, target_id, control_id):
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError('caller-supplied Ed25519 private key required')
        for value in (producer, workflow_id, node_name, target_id, control_id):
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError('nonempty bounded identifiers required')
        if importlib.metadata.version('langgraph') != '1.2.19':
            raise ValueError('this experimental hook requires LangGraph 1.2.19')
        self._key, self.producer = key, producer
        self._base = dict(workflow_id=workflow_id, node_name=node_name, target_id=target_id, control_id=control_id)
        self._used, self._active, self._entered, self._wrapped = False, False, False, False
        self._events = []

    def _clock(self):
        return time.monotonic_ns() - self._origin

    def _emit(self, kind, data):
        self._events.append(encoded({'kind': kind, 'identity': self.identity, 'tick': self._clock(), 'utc': utc(), 'data': data}))

    def wrap_node(self, function):
        """Wrap one synchronous state-only callable before the caller compiles its graph."""
        if self._wrapped or self._used:
            raise ValueError('one wrapped node per fresh session required')
        import inspect
        if not callable(function) or inspect.iscoroutinefunction(function):
            raise TypeError('synchronous state-only node callable required')
        self._wrapped = True

        # Do not preserve the original signature: LangGraph must inject config.
        def controlled(state, config):
            from langgraph.types import interrupt
            if (not self._active or self._entered or
                    config.get('configurable', {}).get('thread_id') != self._thread):
                raise RuntimeError('node invocation outside this single run or repeated attempt')
            self._entered = True
            self._emit('received', {'command_hex': self._command.hex()})
            if self._honor:
                self._emit('pause_requested', {'instruction_digest': digest_bytes(self._command)})
                interrupt({'airep': self.identity, 'instruction_digest': digest_bytes(self._command)})
                raise RuntimeError('resume is outside this one-run SDK contract')
            self._emit('ignored', {'operation': 'continue-without-pause'})
            return function(state)
        controlled.__name__ = function.__name__
        return controlled

    def invoke(self, graph, initial_state, *, thread_id, observer=None, honor_pause=True):
        from langgraph.graph.state import CompiledStateGraph
        if self._used or not self._wrapped:
            raise ValueError('wrap a node and use a fresh session for each run')
        if not isinstance(graph, CompiledStateGraph):
            raise TypeError('caller-owned compiled StateGraph required')
        if type(thread_id) is not str or not thread_id or len(thread_id) > 256:
            raise ValueError('bounded fresh thread_id required')
        if type(honor_pause) is not bool or (observer is not None and not isinstance(observer, FileObserver)):
            raise TypeError('explicit handler mode and FileObserver required')
        self._used = True
        self._thread, self._honor = thread_id, honor_pause
        config = {'configurable': {'thread_id': thread_id}}
        before = graph.get_state(config)
        if (before.config or {}).get('configurable', {}).get('checkpoint_id') or before.created_at is not None:
            raise ValueError('existing checkpoint/resume is outside this one-run contract')
        self._origin = time.monotonic_ns()
        graph.invoke(initial_state, config, interrupt_before=[self._base['node_name']], version='v2')
        anchor = graph.get_state(config)
        checkpoint = (anchor.config or {}).get('configurable', {}).get('checkpoint_id')
        if list(anchor.next) != [self._base['node_name']] or not checkpoint:
            raise ValueError('runtime did not reach exactly the instrumented node boundary')
        self.identity = identity(dict(self._base, run_id='run-' + str(uuid4()),
            runtime_epoch=process_epoch(), checkpoint_id=checkpoint, attempt_id='attempt-1'))
        self._command = encoded({'instruction_id': self.identity['control_id'],
            'action': {'operation': 'cooperative-pause', 'identity': self.identity}})
        self._emit('decision', {'command_hex': self._command.hex()})
        self._emit('dispatched', {'command_digest': digest_bytes(self._command)})
        initial_sample = observer.sample(self._clock) if observer else None
        self._active = True
        try:
            result = graph.invoke(None, config, interrupt_before=[], version='v2')
        finally:
            self._active = False
        snapshot = graph.get_state(config)
        native = native_checkpoint({
            'checkpoint_id': (snapshot.config or {}).get('configurable', {}).get('checkpoint_id'),
            'next': list(snapshot.next), 'interrupts': [i.value for i in result.interrupts],
            'checkpoint_interrupts': [i.value for task in snapshot.tasks for i in task.interrupts]},
            self.identity, digest_bytes(self._command))
        self._emit('native_result', native)
        if observer:
            self._emit('effect_sampled', {'before': initial_sample, 'after': observer.sample(self._clock)})
        expected, observation = project(self._events, self.identity, self.producer)
        chain = Chain(self._key, self.producer, chain_id=self.identity['run_id'] + '.chain')
        artifacts = [chain.emit(row['family'], row['payload'],
            record_id=self.identity['run_id'] + '.' + row['name'], timestamp=row['timestamp'],
            scope=row['scope'])
            for row in expected]
        bundle = {'format': 'airep-sdk-hook-v1', 'basis': BASIS, 'identity': self.identity,
            'producer': self.producer, 'sources': [raw.decode() for raw in self._events], 'artifacts': artifacts}
        # Apply the same size/depth admission boundary before returning evidence.
        bounded_loads(encoded(bundle))
        return bundle
