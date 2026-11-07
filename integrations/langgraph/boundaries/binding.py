"""Exact source/interpretation and bounded-scope binding. Native results are retained."""
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.airep_v02.basis import verifier
from tools.airep_v02.producer import Chain, digest_bytes
from tools.airep_v02.json_input import loads
from tools.airep_v02.verify import evaluate_request
from integrations.langgraph.run import encoded, utc

CONTRACT_BYTES = Path(__file__).with_name('CONTRACT.json').read_bytes()
CONTRACT = loads(CONTRACT_BYTES)
BASIS = digest_bytes(CONTRACT_BYTES)
ACTORS = {'controller': 'boundary-local.controller', 'observer': 'boundary-local.observer'}
MAX_BYTES = 2 * 1024 * 1024


def exact(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        raise ValueError('closed boundary contract violated')


def assertion(role):
    return 'First-party ' + role + ' mapping report; signature does not establish event truth.'


def public_inputs(key, role):
    actor = ACTORS[role]
    return {'bindings': {'bindings': {actor: {'subject_identity': actor, 'role': 'producer',
        'suite': 'ed25519', 'trusted': True, 'public_key_hex': key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}},
        'producer_bindings': {actor: actor}, 'witness_bindings': {}},
        'revocation': {'snapshot_id': 'local.boundary-' + role, 'bindings': {actor: {'state': 'active'}}}}


class Writer:
    def __init__(self, role, key=None):
        self.role = role; self.key = key or Ed25519PrivateKey.generate()
        self.chain = Chain(self.key, ACTORS[role]); self.trust = public_inputs(self.key, role)

    def sign(self, source, projection, *, scope=None):
        raw, mapped = encoded(source), encoded(projection)
        ref, outref = 'source:' + digest_bytes(raw), 'mapping:' + digest_bytes(mapped)
        artifact = self.chain.emit_decision({
            'input': {'input_ref': ref, 'input_digest': digest_bytes(raw)},
            'claim': {'assertion': assertion(self.role), 'basis': [BASIS]},
            'directive': {'verb': 'release', 'policy_basis': ['local-boundary-report-only']},
            'output': {'result_ref': outref, 'result_digest': digest_bytes(mapped)},
            'evidence': [{'type': 'other', 'ref': outref, 'content_hash': digest_bytes(mapped), 'resolvable': True}]
        }, timestamp=utc(), scope=CONTRACT['scope'] if scope is None else scope)
        return {'source_bytes': raw.decode(), 'projection_bytes': mapped.decode(), 'artifact': artifact}


class ReportFailure(ValueError):
    def __init__(self, message, native):
        super().__init__(message)
        self.native = native


class AuthenticationFailure(ReportFailure):
    def __init__(self, native):
        super().__init__('native authentication not established', native)


def authenticate(delivery, trust, role):
    exact(delivery, 'source_bytes projection_bytes artifact')
    for field in ('source_bytes', 'projection_bytes'):
        if type(delivery[field]) is not str or len(delivery[field].encode()) > MAX_BYTES:
            raise ValueError('bounded exact report bytes required')
    raw, mapped, artifact = delivery['source_bytes'].encode(), delivery['projection_bytes'].encode(), delivery['artifact']
    ops = verifier.OperatorInputs(); ops.bindings_doc = trust['bindings']; ops.revocation_doc = trust['revocation']
    native = evaluate_request({'artifact': artifact, 'related_artifacts': []}, ops=ops)
    if native['authenticated_failures'] or native['authenticated_withheld']:
        raise AuthenticationFailure(native)
    ref, outref = 'source:' + digest_bytes(raw), 'mapping:' + digest_bytes(mapped)
    if (artifact['artifact_type'] != 'decision' or artifact['subject']['producer'] != ACTORS[role]
        or artifact['scope'] != CONTRACT['scope']
        or artifact['claim'] != {'assertion': assertion(role), 'basis': [BASIS]}
        or artifact['directive'] != {'verb': 'release', 'policy_basis': ['local-boundary-report-only']}
        or artifact['input'] != {'input_ref': ref, 'input_digest': digest_bytes(raw)}
        or artifact['output'] != {'result_ref': outref, 'result_digest': digest_bytes(mapped)}
        or artifact['evidence'] != [{'type': 'other', 'ref': outref, 'content_hash': digest_bytes(mapped), 'resolvable': True}]):
        raise ReportFailure('signed actor/source/mapping/basis/scope binding mismatch', native)
    return loads(raw), loads(mapped), native
