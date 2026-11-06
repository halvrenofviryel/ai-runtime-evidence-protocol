"""Closed SDK hook source projection; no inference from scenario labels."""
import json
from importlib.resources import files

from ._native import digest_bytes, digest_json
from .io import bounded_loads

CONTRACT = files('airep').joinpath('CONSUMER_CONTRACT.json').read_bytes()
BASIS = digest_bytes(CONTRACT)
IDENTITY = tuple(json.loads(CONTRACT)['identity'])
KINDS = ('decision', 'dispatched', 'received', 'pause_requested', 'ignored', 'native_result', 'effect_sampled')


def identity(value):
    if (type(value) is not dict or set(value) != set(IDENTITY) or
            any(type(x) is not str or not x or len(x) > 256 for x in value.values())):
        raise ValueError('complete bounded identity required')
    return value


def tick(value):
    return type(value) is int and 0 <= value <= 9007199254740991


def sample(value):
    if (type(value) is not dict or set(value) != {'start', 'end', 'exists', 'size', 'digest'} or
            not tick(value['start']) or not tick(value['end']) or value['end'] < value['start'] or
            type(value['exists']) is not bool or type(value['size']) is not int or not 0 <= value['size'] <= 65536):
        raise ValueError('invalid bounded file sample')
    digest = value['digest']
    if not isinstance(digest, str) or len(digest) != 71 or not digest.startswith('sha256:'):
        raise ValueError('sample digest required')
    try:
        bytes.fromhex(digest[7:])
    except ValueError as exc:
        raise ValueError('sample digest malformed') from exc
    if not value['exists'] and (value['size'] != 0 or digest != digest_bytes(b'')):
        raise ValueError('absent file must have empty content')
    return value


def project(sources, expected, producer):
    """Return exact native family payloads and a separate bounded observation view."""
    identity(expected)
    if type(sources) is not list or not 2 <= len(sources) <= len(KINDS):
        raise ValueError('bounded source inventory required')
    events, raw_by_kind = {}, {}
    previous = -1
    for raw in sources:
        if type(raw) is not bytes or len(raw) > 131072:
            raise ValueError('bounded source bytes required')
        e = bounded_loads(raw)
        if (type(e) is not dict or set(e) != {'kind', 'identity', 'tick', 'utc', 'data'} or
                e['kind'] not in KINDS or e['kind'] in events or e['identity'] != expected or
                not tick(e['tick']) or e['tick'] < previous or type(e['utc']) is not str or
                type(e['data']) is not dict):
            raise ValueError('source identity, order or shape mismatch')
        previous = e['tick']
        events[e['kind']], raw_by_kind[e['kind']] = e, raw
    if list(events) != [kind for kind in KINDS if kind in events]:
        raise ValueError('source stage order mismatch')
    if not {'decision', 'dispatched'} <= set(events):
        raise ValueError('issuer source events missing')
    command_raw = bytes.fromhex(events['decision']['data']['command_hex'])
    command = bounded_loads(command_raw)
    action = {'operation': 'cooperative-pause', 'identity': expected}
    if (events['decision']['data'] != {'command_hex': command_raw.hex()} or
            command != {'instruction_id': expected['control_id'], 'action': action} or
            events['dispatched']['data'] != {'command_digest': digest_bytes(command_raw)}):
        raise ValueError('exact issued instruction binding mismatch')
    ref = lambda name: {'chain_id': expected['run_id'] + '.chain', 'record_id': expected['run_id'] + '.' + name}
    output = []

    def add(name, family, payload, kinds):
        payload = dict(payload, evidence=[{'type': 'other', 'ref': 'source:' + digest_bytes(raw_by_kind[k]),
            'content_hash': digest_bytes(raw_by_kind[k]), 'resolvable': True} for k in kinds])
        output.append({'name': name, 'family': family, 'payload': payload, 'timestamp': events[kinds[-1]]['utc']})

    add('decision', 'decision', {'input': {'input_ref': 'command:' + digest_bytes(command_raw), 'input_digest': digest_bytes(command_raw)},
        'claim': {'assertion': 'Operator requested cooperative pause at one instrumented node.', 'basis': [BASIS]},
        'directive': {'verb': 'release', 'policy_basis': [BASIS]},
        'output': {'result_ref': 'source:' + digest_bytes(raw_by_kind['decision']), 'result_digest': digest_bytes(raw_by_kind['decision'])}}, ['decision'])
    common = {'decision_ref': ref('decision'), 'instruction_id': command['instruction_id'], 'instruction_digest': digest_bytes(command_raw)}
    control = dict(common, authorized_action_digest=digest_json(action),
                   authority={'issuer_id': producer, 'writable_by_controlled_system': True})
    add('dispatch', 'control', dict(control, control_event='dispatched', boundary_side='issuer'), ['dispatched'])
    receipt = 'received' in events
    execution = 'MISSING'
    if receipt:
        if events['received']['data'] != {'command_hex': command_raw.hex()}:
            raise ValueError('receiver bytes differ from issued command')
        add('receipt', 'control', dict(control, control_event='received', boundary_side='receiver'), ['received'])
    if 'pause_requested' in events and events['pause_requested']['data'] != {'instruction_digest': digest_bytes(command_raw)}:
        raise ValueError('pause request does not match command')
    if 'ignored' in events and events['ignored']['data'] != {'operation': 'continue-without-pause'}:
        raise ValueError('ignored control source malformed')
    if 'pause_requested' in events and 'ignored' in events:
        raise ValueError('conflicting handler outcomes')
    if 'native_result' in events:
        native = events['native_result']['data']
        if (set(native) != {'checkpoint_id', 'next', 'interrupts', 'checkpoint_interrupts'} or
                type(native['checkpoint_id']) is not str or not native['checkpoint_id'] or
                type(native['next']) is not list or type(native['interrupts']) is not list or
                type(native['checkpoint_interrupts']) is not list):
            raise ValueError('native checkpoint shape invalid')
        interrupt = {'airep': expected, 'instruction_digest': digest_bytes(command_raw)}
        paused = (native['next'] == [expected['node_name']] and native['interrupts'] == [interrupt]
                  and native['checkpoint_interrupts'] == [interrupt])
        if receipt and 'pause_requested' in events and paused:
            execution = 'PAUSED_REPORTED'
            add('execution', 'execution', dict(common, execution_event='executed', executed_action_digest=digest_json(action)),
                ['received', 'pause_requested', 'native_result'])
        elif receipt and 'ignored' in events and not native['interrupts'] and not native['checkpoint_interrupts']:
            execution = 'CONTINUED_REPORTED'
            add('execution', 'execution', dict(common, execution_event='failed',
                executed_action_digest=digest_json({'operation': 'continue-without-pause', 'identity': expected})),
                ['received', 'ignored', 'native_result'])
    effect, period = 'MISSING', None
    if 'effect_sampled' in events:
        data = events['effect_sampled']['data']
        if set(data) != {'before', 'after'}:
            raise ValueError('sample pair required')
        before, after = sample(data['before']), sample(data['after'])
        if not before['end'] <= after['start'] <= after['end'] <= events['effect_sampled']['tick']:
            raise ValueError('sample time order invalid')
        if before['start'] < events['dispatched']['tick']:
            raise ValueError('sample window predates dispatched control')
        period = [before['start'], after['end']]
        effect = 'QUIESCENT_REPORTED' if all(before[k] == after[k] for k in ('exists', 'size', 'digest')) else 'CHANGED_REPORTED'
        if execution != 'MISSING':
            add('effect', 'effect', {'decision_ref': ref('decision'), 'execution_ref': ref('execution'),
                'observer_relationship': 'same_executor',
                'observed_state': {'description': 'Bounded same-host file sample comparison: ' + effect + '; not continuous stopping or causation.',
                                   'state_digest': digest_json(data)}}, ['effect_sampled'])
        else:
            effect = 'MISSING'
    return output, {'receipt': 'RECEIVED' if receipt else 'MISSING', 'execution': execution,
                    'effect': effect, 'window': period}
