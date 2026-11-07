"""Authored fixture reports, not measured runtime event traces."""
import copy
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.airep_v02.basis import verifier
from tools.airep_v02.producer import Chain, digest_bytes
from .core import BASIS


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def query(**identity_changes):
    return {'identity': dict(workflow_id='workflow-1', run_id='run-B', runtime_epoch='epoch-1',
                             checkpoint_id='checkpoint-1', control_id='pause-2', attempt_id='attempt-1',
                             target_id='worker-1', **{}) | identity_changes,
            'clock_id': 'fixture-clock-1', 'boundary': 'fixture-state',
            'predicate_id': 'local-work-progress', 'window': [6, 10], 'cutoff': 20}


class FixtureFactory:
    def __init__(self):
        self.key = Ed25519PrivateKey.generate()
        self.actor = 'local.fixture'
        self.sources = {}
        self.ops = verifier.OperatorInputs()
        self.ops.bindings_doc = {'bindings': {self.actor: {'subject_identity': self.actor,
            'role': 'producer', 'suite': 'ed25519', 'trusted': True,
            'public_key_hex': self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw).hex()}},
            'producer_bindings': {self.actor: self.actor}, 'witness_bindings': {}}
        self.ops.revocation_doc = {'snapshot_id': 'local.fixture-snapshot',
                                   'bindings': {self.actor: {'state': 'active'}}}

    def delivery(self, event_id, *, status='CONTINUED', kind='effect', arrival=20, **changes):
        event = {'identity': query()['identity'], 'event_id': event_id, 'kind': kind,
                 'status': status, 'source_actor': self.actor, 'boundary': 'fixture-state',
                 'predicate_id': 'local-work-progress',
                 'clock_id': 'fixture-clock-1', 'event_time': 10, 'observed_time': 10,
                 'window': [6, 10], 'observer_relationship': 'same_executor'}
        event.update(copy.deepcopy(changes))
        source = encoded(event)
        source_ref = 'source:' + digest_bytes(source)
        self.sources[source_ref] = source
        event.update(basis_digest=BASIS, source_ref=source_ref, source_hash=digest_bytes(source))
        return self.bind(event, arrival)

    def bind(self, event, arrival=20):
        raw = encoded(event)
        event_ref = 'event:' + digest_bytes(raw)
        artifact = Chain(self.key, self.actor).emit_decision({
            'input': {'input_ref': event['source_ref'], 'input_digest': event['source_hash']},
            'claim': {'assertion': 'Record an authored temporal regression fixture; no runtime truth claim.',
                      'basis': [BASIS]},
            'directive': {'verb': 'release', 'policy_basis': ['local-fixture-only']},
            'output': {'result_ref': event_ref, 'result_digest': digest_bytes(raw)},
            'evidence': [{'type': 'other', 'ref': event_ref, 'content_hash': digest_bytes(raw), 'resolvable': True}]
        }, timestamp='2026-11-06T00:00:00Z')
        return {'event_bytes': raw, 'event_ref': event_ref, 'artifact': artifact, 'arrival_time': arrival}
