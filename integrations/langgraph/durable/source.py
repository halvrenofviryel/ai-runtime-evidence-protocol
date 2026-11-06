"""Closed projection and bounded signed scope for the durable experiment."""
from pathlib import Path

from tools.airep_v02.json_input import loads
from tools.airep_v02.producer import Chain, digest_bytes
from integrations.langgraph.run import encoded
from integrations.langgraph.temporal.core import identity, tick, MAX_BYTES
from integrations.langgraph.temporal.runtime_source import RuntimeReports

CONTRACT_BYTES = Path(__file__).with_name('CONTRACT.json').read_bytes()
CONTRACT = loads(CONTRACT_BYTES)
ACTOR = 'durable-local.capture-report'
ASSERTION = 'Record a first-party durable-checkpoint mapping report; signature is not event truth.'
DIRECTIVE = {'verb': 'release', 'policy_basis': ['local-durable-report-only']}


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ValueError('closed durable source contract violated')


def nonempty(value):
    if type(value) is not str or not value or len(value) > 256:
        raise ValueError('nonempty bounded metadata required')


def rows(sample, run_id):
    exact(sample, 'start end rows_hex')
    if not tick(sample['start']) or not tick(sample['end']) or sample['start'] > sample['end']:
        raise ValueError('invalid sample interval')
    result = loads(bytes.fromhex(sample['rows_hex']))
    if type(result) is not list or len(result) > 100:
        raise ValueError('bounded effect rows required')
    keys = set()
    for i, row in enumerate(result, 1):
        if (type(row) is not list or len(row) != 6 or type(row[0]) is not int or row[0] != i
            or row[2] not in ('before_interrupt', 'after_resume') or row[3] != run_id):
            raise ValueError('effect history malformed or wrong run')
        for item in row[1:]:
            nonempty(item)
        if row[1] in keys:
            raise ValueError('duplicate effect key')
        keys.add(row[1])
    return result


def worker(raw, scope, thread_id, phase):
    value = loads(bytes.fromhex(raw))
    exact(value, 'schema phase pid runtime_epoch thread_id run_id control_id mode '
          'checkpoint_before_hash loaded terminal result_interrupts events')
    if (value['schema'] != 'durable-worker-v1' or value['phase'] != phase
        or type(value['pid']) is not int or value['pid'] <= 0 or value['thread_id'] != thread_id
        or any(value[k] != scope[k] for k in ('run_id', 'control_id'))
        or value['mode'] not in ('repeat', 'idempotent')):
        raise ValueError('worker scope mismatch')
    nonempty(value['runtime_epoch'])
    if type(value['events']) is not list or len(value['events']) > 20:
        raise ValueError('bounded worker event list required')
    last = -1
    for i, event in enumerate(value['events'], 1):
        exact(event, 'event_id runtime_epoch clock_id tick kind data')
        if (event['event_id'] != 'worker-event-' + str(i) or event['runtime_epoch'] != value['runtime_epoch']
            or event['clock_id'] != 'worker-' + value['runtime_epoch']
            or not tick(event['tick']) or event['tick'] < last):
            raise ValueError('invalid worker-local ordering metadata')
        last = event['tick']
        data = event['data']
        if event['kind'] == 'node_entered':
            exact(data, 'invocation_id'); nonempty(data['invocation_id'])
        elif event['kind'] == 'effect_attempt':
            exact(data, 'obligation stage invocation_id inserted')
            if (data['stage'] not in ('before_interrupt', 'after_resume')
                or type(data['inserted']) is not bool
                or data['obligation'] != scope['run_id'] + ':' + data['stage']):
                raise ValueError('invalid effect attempt')
            nonempty(data['invocation_id'])
        elif event['kind'] == 'resume_returned':
            exact(data, 'answer')
        else:
            raise ValueError('unsupported worker event')
    expected = ['node_entered', 'effect_attempt']
    if phase == 'resume':
        expected += ['resume_returned', 'effect_attempt']
    if [e['kind'] for e in value['events']] != expected:
        raise ValueError('worker event lifecycle mismatch')
    return value


def state(value, scope, *, completed):
    exact(value, 'checkpoint_id next values interrupts')
    nonempty(value['checkpoint_id'])
    exact(value['values'], 'run_id control_id completed')
    expected = {'run_id': scope['run_id'], 'control_id': scope['control_id'], 'completed': completed}
    if type(value['values'].get('completed')) is not bool or value['values'] != expected:
        raise ValueError('checkpoint state/run/control mismatch')
    payload = {'run_id': scope['run_id'], 'control_id': scope['control_id'], 'operation': 'pause'}
    if value['next'] != ([] if completed else ['action']) or value['interrupts'] != ([] if completed else [payload]):
        raise ValueError('checkpoint interrupt/completion mismatch')


class DurablePolicy:
    name = CONTRACT['profile']
    basis = digest_bytes(CONTRACT_BYTES)
    limits = CONTRACT['limits']

    @staticmethod
    def validate_artifact(artifact):
        if artifact['scope'] != CONTRACT['artifact_scope']:
            raise ValueError('signed durable scope differs from contract')
        if artifact['claim'] != {'assertion': ASSERTION, 'basis': [DurablePolicy.basis]}:
            raise ValueError('signed durable claim differs from contract')
        if artifact['directive'] != DIRECTIVE:
            raise ValueError('signed durable directive differs from contract')

    @staticmethod
    def project(raw):
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise ValueError('bounded exact durable source required')
        source = loads(raw)
        exact(source, 'schema identity thread_id clock_id event_id tick timestamp_utc kind data')
        if source['schema'] != 'durable-source-v1' or not tick(source['tick']):
            raise ValueError('invalid durable source metadata')
        scope = source['identity']; identity(scope)
        for k in ('thread_id', 'clock_id', 'event_id', 'timestamp_utc'):
            nonempty(source[k])
        data, end, kind = source['data'], source['tick'], source['kind']
        if kind == 'effect_sampled':
            exact(data, 'before after')
            before, after = data['before'], data['after']
            initial, final = rows(before, scope['run_id']), rows(after, scope['run_id'])
            if before['end'] > after['start'] or after['end'] > end:
                raise ValueError('effect sample order not established')
            if final[:len(initial)] != initial:
                raise ValueError('effect history removed or replaced')
            stage, status = 'effect', 'QUIESCENT' if initial == final else 'CONTINUED'
            period = [before['start'], after['end']]
        elif kind in ('checkpoint_paused', 'resume_completed'):
            phase = 'pause' if kind == 'checkpoint_paused' else 'resume'
            exact(data, 'worker_hex' if phase == 'pause' else 'worker_hex pause_worker_hex paused_checkpoint_hash')
            record = worker(data['worker_hex'], scope, source['thread_id'], phase)
            if record['runtime_epoch'] != scope['runtime_epoch']:
                raise ValueError('worker epoch mismatch')
            if phase == 'pause':
                state(record['terminal'], scope, completed=False)
                if (record['loaded'] is not None or record['checkpoint_before_hash'] is not None
                    or record['terminal']['checkpoint_id'] != scope['checkpoint_id']
                    or record['result_interrupts'] != record['terminal']['interrupts']):
                    raise ValueError('paused checkpoint binding mismatch')
            else:
                prior = worker(data['pause_worker_hex'], scope, source['thread_id'], 'pause')
                state(prior['terminal'], scope, completed=False)
                state(record['terminal'], scope, completed=True)
                if (record['loaded'] != prior['terminal']
                    or record['loaded']['checkpoint_id'] != scope['checkpoint_id']
                    or record['terminal']['checkpoint_id'] == scope['checkpoint_id']
                    or record['checkpoint_before_hash'] != data['paused_checkpoint_hash']
                    or type(data['paused_checkpoint_hash']) is not str
                    or len(data['paused_checkpoint_hash']) != 71
                    or not data['paused_checkpoint_hash'].startswith('sha256:')
                    or any(c not in '0123456789abcdef' for c in data['paused_checkpoint_hash'][7:])
                    or record['pid'] == prior['pid'] or record['runtime_epoch'] == prior['runtime_epoch']
                    or record['mode'] != prior['mode'] or record['result_interrupts'] != []):
                    raise ValueError('durable checkpoint/process continuity mismatch')
                expected = {'operation': 'resume', 'run_id': scope['run_id'], 'control_id': scope['control_id']}
                returns = [e['data'] for e in record['events'] if e['kind'] == 'resume_returned']
                if returns != [{'answer': expected}]:
                    raise ValueError('resume return evidence missing')
            stage, status, period = 'execution', 'PAUSED' if phase == 'pause' else 'CONTINUED', [end, end]
        else:
            raise ValueError('unsupported durable event kind')
        return {'identity': scope, 'event_id': source['event_id'], 'kind': stage, 'status': status,
                'source_actor': ACTOR, 'boundary': 'local-sqlite-business-ledger',
                'predicate_id': 'sampled-committed-row-progress', 'clock_id': source['clock_id'],
                'event_time': period[1], 'observed_time': end, 'window': period,
                'observer_relationship': 'same_executor'}


class DurableReports(RuntimeReports):
    def __init__(self):
        super().__init__()
        self.policy = DurablePolicy()
        old = next(iter(self.ops.bindings_doc['bindings']))
        binding = self.ops.bindings_doc['bindings'][old]
        binding['subject_identity'] = ACTOR
        self.ops.bindings_doc = {'bindings': {ACTOR: binding}, 'producer_bindings': {ACTOR: ACTOR}, 'witness_bindings': {}}
        self.ops.revocation_doc = {'snapshot_id': 'local.durable-report', 'bindings': {ACTOR: {'state': 'active'}}}
        self.chain = Chain(self.key, ACTOR)

    def bind_event(self, event, arrival, timestamp, *, scope=None, assertion=None):
        raw = encoded(event); ref = 'event:' + digest_bytes(raw)
        artifact = self.chain.emit_decision({
            'input': {'input_ref': event['source_ref'], 'input_digest': event['source_hash']},
            'claim': {'assertion': ASSERTION if assertion is None else assertion, 'basis': [self.policy.basis]},
            'directive': DIRECTIVE,
            'output': {'result_ref': ref, 'result_digest': digest_bytes(raw)},
            'evidence': [{'type': 'other', 'ref': ref, 'content_hash': digest_bytes(raw), 'resolvable': True}]
        }, timestamp=timestamp, scope=CONTRACT['artifact_scope'] if scope is None else scope)
        return {'event_bytes': raw, 'event_ref': ref, 'artifact': artifact, 'arrival_time': arrival}
