"""Explicit projection of captured bytes into the bounded temporal consumer."""
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.airep_v02.basis import verifier
from tools.airep_v02.json_input import loads
from tools.airep_v02.producer import Chain, digest_bytes
from integrations.langgraph.run import encoded
from .core import identity, tick, MAX_BYTES

CONTRACT_BYTES = Path(__file__).with_name('RUNTIME_CONTRACT.json').read_bytes()
MAPPED_KINDS = {'receiver_observed', 'handler_ignored', 'native_interrupt_observed', 'effect_sampled'}
ACTOR = 'langgraph-local.capture-report'


def step_bytes(sample):
    if (type(sample) is not dict or set(sample) != {'start', 'end', 'bytes_hex'} or not tick(sample['start'])
        or not tick(sample['end']) or sample['start'] > sample['end']):
        raise ValueError('invalid sample interval')
    raw = bytes.fromhex(sample['bytes_hex'])
    if raw and not raw.endswith(b'\n'):
        raise ValueError('incomplete business-step row')
    rows = [loads(line) for line in raw.splitlines()]
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or set(row) != {'step'} or type(row['step']) is not int or row['step'] != index:
            raise ValueError('business-step history malformed')
    return raw


class RuntimeSourcePolicy:
    name = 'local-captured-temporal-v1'
    basis = digest_bytes(CONTRACT_BYTES)
    limits = loads(CONTRACT_BYTES)['limits']

    @staticmethod
    def project(raw):
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise ValueError('bounded captured source required')
        source = loads(raw)
        if (type(source) is not dict or set(source) != {'schema', 'identity', 'clock_id', 'event_id',
            'kind', 'tick', 'timestamp_utc', 'data'} or source['schema'] != 'captured-v1'):
            raise ValueError('closed captured source contract violated')
        identity(source['identity'])
        if not tick(source['tick']):
            raise ValueError('invalid capture tick')
        for field in ('clock_id', 'event_id', 'timestamp_utc'):
            if type(source[field]) is not str or not source[field] or len(source[field]) > 256:
                raise ValueError('missing capture metadata')
        data, kind, end = source['data'], source['kind'], source['tick']
        if type(data) is not dict:
            raise ValueError('capture data must be an object')
        if kind == 'receiver_observed':
            if set(data) != {'command_hex'}:
                raise ValueError('exact received command required')
            command = loads(bytes.fromhex(data['command_hex']))
            if command != {'identity': source['identity'], 'operation': 'pause'}:
                raise ValueError('received command identity/operation mismatch')
            stage, status, period = 'receipt', 'RECEIVED', [end, end]
        elif kind == 'handler_ignored':
            if data != {'operation': 'continue-without-pause'}:
                raise ValueError('explicit ignored handler report required')
            stage, status, period = 'execution', 'CONTINUED', [end, end]
        elif kind == 'native_interrupt_observed':
            expected = {'identity': source['identity'], 'operation': 'pause'}
            if (set(data) != {'terminal_checkpoint_id', 'checkpoint_next', 'interrupts', 'checkpoint_interrupts'}
                or data['interrupts'] != [expected] or data['checkpoint_interrupts'] != [expected]
                or data['checkpoint_next'] != ['controlled_action']
                or type(data['terminal_checkpoint_id']) is not str or not data['terminal_checkpoint_id']):
                raise ValueError('native interrupt/checkpoint binding mismatch')
            stage, status, period = 'execution', 'PAUSED', [end, end]
        elif kind == 'effect_sampled':
            if set(data) != {'before', 'after'}:
                raise ValueError('both effect samples required')
            before, after = data['before'], data['after']
            initial, final = step_bytes(before), step_bytes(after)
            if before['end'] > after['start'] or after['end'] > end:
                raise ValueError('effect sample order not established')
            if not final.startswith(initial):
                raise ValueError('effect history removed or replaced')
            stage = 'effect'
            status = 'QUIESCENT' if final == initial else 'CONTINUED'
            period = [before['start'], after['end']]
        else:
            raise ValueError('unsupported captured event kind')
        return {'identity': source['identity'], 'event_id': source['event_id'], 'kind': stage,
                'status': status, 'source_actor': ACTOR, 'boundary': 'local-business-file',
                'predicate_id': 'sampled-business-step-progress', 'clock_id': source['clock_id'],
                'event_time': period[1], 'observed_time': end, 'window': period,
                'observer_relationship': 'same_executor'}


class RuntimeReports:
    """Local test trust; only public inputs are exported. No production keys."""
    def __init__(self):
        self.policy = RuntimeSourcePolicy()
        self.key = Ed25519PrivateKey.generate()
        self.chain = Chain(self.key, ACTOR)
        self.sources = {}
        self.ops = verifier.OperatorInputs()
        self.ops.bindings_doc = {'bindings': {ACTOR: {'subject_identity': ACTOR,
            'role': 'producer', 'suite': 'ed25519', 'trusted': True,
            'public_key_hex': self.key.public_key().public_bytes(serialization.Encoding.Raw,
                serialization.PublicFormat.Raw).hex()}}, 'producer_bindings': {ACTOR: ACTOR}, 'witness_bindings': {}}
        self.ops.revocation_doc = {'snapshot_id': 'local.capture-report', 'bindings': {ACTOR: {'state': 'active'}}}

    def bind_event(self, event, arrival, timestamp):
        """Signing is deliberately separate; admission must re-project the source."""
        raw = encoded(event)
        ref = 'event:' + digest_bytes(raw)
        artifact = self.chain.emit_decision({
            'input': {'input_ref': event['source_ref'], 'input_digest': event['source_hash']},
            'claim': {'assertion': 'Record a first-party captured-runtime mapping report; signature is not event truth.',
                      'basis': [self.policy.basis]},
            'directive': {'verb': 'release', 'policy_basis': ['local-captured-report-only']},
            'output': {'result_ref': ref, 'result_digest': digest_bytes(raw)},
            'evidence': [{'type': 'other', 'ref': ref, 'content_hash': digest_bytes(raw), 'resolvable': True}]
        }, timestamp=timestamp)
        return {'event_bytes': raw, 'event_ref': ref, 'artifact': artifact, 'arrival_time': arrival}

    def delivery(self, raw, *, arrival):
        projection = self.policy.project(raw)
        source_hash = digest_bytes(raw)
        source_ref = 'capture:' + source_hash
        self.sources[source_ref] = raw
        return self.bind_event(dict(projection, basis_digest=self.policy.basis,
                                   source_ref=source_ref, source_hash=source_hash),
                               arrival, loads(raw)['timestamp_utc'])


def query_for(delivery):
    e = loads(delivery['event_bytes'])
    return {k: e[k] for k in ('identity', 'clock_id', 'boundary', 'predicate_id', 'window')} | {'cutoff': e['observed_time']}
