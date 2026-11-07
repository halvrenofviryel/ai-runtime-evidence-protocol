"""Caller-owned graph example. Fresh ephemeral keys are explicitly TEST ONLY.

Copy this file outside the checkout and run it with the installed wheel.
No provider, API key or external service is used.
"""
import argparse
from pathlib import Path
from typing import TypedDict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from airep.langgraph import ControlSession, FileObserver
from airep.consumer import consume
from airep.io import encoded, write_bytes
from airep.trust import from_bytes


class State(TypedDict):
    completed: int


def run(directory, mode):
    directory.mkdir(parents=True, exist_ok=False)
    effect = directory / 'business.txt'
    key = Ed25519PrivateKey.generate()  # Explicit fresh local TEST key, never written to disk.
    producer = 'example.local-user'
    session = ControlSession(key=key, producer=producer, workflow_id='example.file-work',
                             node_name='user_write', target_id='business-file', control_id='pause-1')

    def my_node(state):
        effect.write_text('one actual application write\n')
        return {'completed': state['completed'] + 1}

    graph = StateGraph(State)
    graph.add_node('user_write', session.wrap_node(my_node))
    graph.add_edge(START, 'user_write')
    graph.add_edge('user_write', END)
    compiled = graph.compile(checkpointer=InMemorySaver())
    bundle = session.invoke(compiled, {'completed': 0}, thread_id='example-' + mode,
                            observer=None if mode == 'unobserved' else FileObserver(effect),
                            honor_pause=mode != 'ignored')
    trust = {'bindings': {'bindings': {producer: {'subject_identity': producer, 'role': 'producer',
        'suite': 'ed25519', 'trusted': True, 'public_key_hex': key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}},
        'producer_bindings': {producer: producer}, 'witness_bindings': {}},
        'revocation': {'snapshot_id': 'example.local-test', 'bindings': {producer: {'state': 'active'}}}}
    # This self-selected test trust is separate from the evidence input. A real
    # consumer must select its own trusted bindings and revocation policy.
    result = consume(encoded(bundle), ops=from_bytes(encoded(trust)), expected_identity=bundle['identity'])
    for name, value in [('bundle', bundle), ('trust', trust), ('query', bundle['identity']), ('result', result)]:
        write_bytes(directory / (name + '.json'), encoded(value))
    expected = {'paused': ('PAUSED_REPORTED', 'QUIESCENT_REPORTED', 'MATCH'),
                'ignored': ('CONTINUED_REPORTED', 'CHANGED_REPORTED', 'NO_MATCH'),
                'unobserved': ('PAUSED_REPORTED', 'MISSING', 'NO_MATCH')}[mode]
    actual = result['consumer']
    assert (actual['observation']['execution'], actual['observation']['effect'], actual['policy_result']) == expected, result
    assert effect.exists() == (mode == 'ignored')
    assert result['native']['summary']['status'] != 'SATISFIED'
    print(encoded({'mode': mode, 'native': result['native']['summary']['status'], 'consumer': actual['observation'],
                   'policy_result': actual['policy_result'], 'key_origin': 'fresh ephemeral self-trusted TEST key; not exported'}).decode(), end='')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mode', choices=['paused', 'ignored', 'unobserved'], default='paused')
    args = parser.parse_args()
    run(args.out, args.mode)
