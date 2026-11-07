"""Versioned partial-evidence projection; the original v1 consumer stays closed."""
from tools.airep_v02.basis import verifier
from tools.airep_v02.reconcile import reconcile
from tools.airep_v02.json_input import loads
from integrations.langgraph.temporal.core import tick
from .binding import authenticate as authenticate_node, exact, ACTORS, ReportFailure
from .binding_partial import authenticate, CONTRACT
from .consumer import (TARGETS, require, intent_check, project_node, event_check,
                       command_check, transport_check)


def inventory(value, label):
    require(type(value) is dict and set(value) <= set(TARGETS),
            'invalid ' + label + ' inventory')


def observation_check(obs, intent, target, source):
    exact(obs, 'identity clock_id before after')
    require(obs['identity'] == intent['identities'][target]
            and obs['clock_id'] == source['controller_clock_id'],
            'observation identity/clock mismatch')
    counts, previous = [], None
    for sample in (obs['before'], obs['after']):
        exact(sample, 'start end bytes_hex')
        require(tick(sample['start']) and tick(sample['end'])
                and sample['start'] <= sample['end'], 'sample window order mismatch')
        raw = bytes.fromhex(sample['bytes_hex'])
        require(len(raw) <= 524288 and raw.endswith(b'\n'), 'bounded whole effect lines required')
        rows = [loads(line) for line in raw.splitlines()]
        for index, row in enumerate(rows, 1):
            require(row == {'identity': intent['identities'][target], 'step': index},
                    'effect identity/append sequence mismatch')
        if previous is not None:
            require(raw.startswith(previous), 'effect history replacement')
        previous = raw
        counts.append(len(rows))
    require(source['control_end_tick'] <= obs['before']['start'] <= obs['before']['end']
            < obs['after']['start'], 'observation must follow control round')
    return counts


def project(source, expected_intent, node_trust):
    intent_check(expected_intent)
    exact(source, 'schema intent controller_clock_id events control_end_tick nodes observations cleanup')
    require(source['schema'] == 'multitarget-partial-capture-v2'
            and source['intent'] == expected_intent, 'expected intent/schema mismatch')
    require(type(source['controller_clock_id']) is str and bool(source['controller_clock_id']),
            'controller clock required')
    require(type(node_trust) is dict and set(node_trust) == set(TARGETS),
            'all intended trust inputs required, including missing reports')
    for field in ('nodes', 'observations', 'cleanup'):
        inventory(source[field], field)
    nodes, native = {}, {}
    for target in TARGETS:
        if target not in source['nodes']:
            continue
        raw, mapped, verdict = authenticate_node(source['nodes'][target], node_trust[target], target)
        projected = project_node(raw, expected_intent, target)
        require(mapped == projected, 'node projection mismatch')
        nodes[target], native[target] = projected, verdict
    require(len({n['pid'] for n in nodes.values()}) == len(nodes), 'distinct target processes required')
    events = source['events']
    event_check(events)
    outgoing, pending = [], None
    for event in events:
        data = event['data']
        if event['kind'] == 'send':
            exact(data, 'command_hex')
            command = loads(bytes.fromhex(data['command_hex']))
            command_check(command, expected_intent, command['identity']['target_id'])
            require(command['sender'] == 'controller' and pending is None, 'invalid controller dispatch')
            pending = {'command': command, 'command_hex': data['command_hex'], 'transport': None}
            outgoing.append(pending)
        elif event['kind'] == 'transport':
            require(pending is not None, 'controller response without send')
            transport_check(data, pending['command']['delivery_attempt_id'])
            pending['transport'], pending = data, None
        else:
            raise ValueError('unrecognized controller event')
    require(pending is None and [a['command']['identity']['target_id'] for a in outgoing]
            == expected_intent['children']['controller'], 'controller must dispatch each root target exactly once')
    require(tick(source['control_end_tick']) and events[-1]['tick'] <= source['control_end_tick'],
            'control cutoff order mismatch')
    all_sends = outgoing + [a for t in TARGETS if t in nodes for a in nodes[t]['outgoing']]
    sends = {a['command']['delivery_attempt_id']: a for a in all_sends}
    require(len(sends) == len(all_sends), 'reused transport attempt identity')
    receipts = {r['command']['delivery_attempt_id']: (t, r)
                for t in TARGETS if t in nodes for r in nodes[t]['receipts']}
    require(len(receipts) == sum(len(n['receipts']) for n in nodes.values()), 'cross-target attempt collision')
    unresolved = []
    for aid, (target, receipt) in receipts.items():
        if aid not in sends:
            sender = receipt['command']['sender']
            require(sender != 'controller' and sender not in nodes, 'receiver has no exact sender request')
            unresolved.append({'target_id': target, 'delivery_attempt_id': aid,
                               'reason': 'SENDER_REPORT_MISSING'})
        else:
            require(sends[aid]['command_hex'] == receipt['command_hex'], 'sender/receiver request mismatch')
    for aid, sent in sends.items():
        command, transport = sent['command'], sent['transport']
        parent = command['parent_delivery_attempt_id']
        if parent is not None:
            require(parent in receipts and receipts[parent][0] == command['sender'], 'borrowed parent hop')
        target, received = command['identity']['target_id'], receipts.get(aid)
        if target not in nodes:
            unresolved.append({'target_id': target, 'delivery_attempt_id': aid,
                               'reason': 'RECEIVER_REPORT_MISSING'})
            if transport['status'] == 'RESPONSE':
                reply = loads(bytes.fromhex(transport['response_hex']))
                exact(reply, 'target_id delivery_attempt_id local_status duplicate children')
                require(reply['target_id'] == target and reply['delivery_attempt_id'] == aid
                        and reply['local_status'] in ('PAUSED_REPORTED', 'REFUSED')
                        and type(reply['duplicate']) is bool and type(reply['children']) is list,
                        'unconfirmed response identity/type mismatch')
            continue
        if transport['status'] == 'RESPONSE':
            require(received is not None and received[1]['reply']['dropped'] is False
                    and received[1]['reply']['response_hex'] == transport['response_hex'],
                    'gateway changed receiver response or fabricated success')
        elif received is not None:
            require(received[1]['reply']['dropped'] is True and transport['error'] == 'EOFError',
                    'lost response/receipt history mismatch')
    output = []
    for target in TARGETS:
        node = nodes.get(target)
        obs, cleanup = source['observations'].get(target), source['cleanup'].get(target)
        missing = [name for name in ('nodes', 'observations', 'cleanup') if target not in source[name]]
        counts = observation_check(obs, expected_intent, target, source) if target in source['observations'] else None
        if target in source['cleanup']:
            exact(cleanup, 'forced exitcode pid tick')
            require(type(cleanup['forced']) is bool and type(cleanup['exitcode']) is int
                    and type(cleanup['pid']) is int and cleanup['pid'] > 0
                    and (node is None or cleanup['pid'] == node['pid'])
                    and tick(cleanup['tick'])
                    and (obs['after']['end'] if counts is not None else source['control_end_tick']) < cleanup['tick']
                    and (cleanup['exitcode'] != 0 if cleanup['forced'] else cleanup['exitcode'] == 0),
                    'cleanup result/order mismatch')
        attempts = [a for a in all_sends if a['command']['identity']['target_id'] == target]
        gaps = [u for u in unresolved if u['target_id'] == target]
        parent_role = next(role for role, children in expected_intent['children'].items() if target in children)
        if not attempts and parent_role != 'controller' and parent_role not in nodes:
            gaps.append({'target_id': target, 'delivery_attempt_id': None,
                         'reason': 'SENDER_ATTEMPT_INVENTORY_MISSING'})
        effect = ('UNKNOWN' if counts is None else
                  'QUIESCENT_REPORTED' if counts[0] == counts[1] else 'CONTINUED_REPORTED')
        execution = node['execution'] if node else 'UNKNOWN'
        transport = ('RESPONSE_UNCONFIRMED' if gaps else 'RESPONSE') if any(
            a['transport']['status'] == 'RESPONSE' for a in attempts) else (
            'TRANSPORT_UNKNOWN' if attempts else 'UNKNOWN' if gaps else 'NOT_ATTEMPTED')
        bounded = (not missing and not gaps and execution == 'PAUSED_REPORTED'
                   and effect == 'QUIESCENT_REPORTED' and transport == 'RESPONSE' and not cleanup['forced'])
        output.append({'target_id': target, 'identity': expected_intent['identities'][target],
                       'receipt': 'UNKNOWN' if node is None else 'RECEIVED_REPORTED' if node['receipts'] else 'MISSING',
                       'execution': execution, 'effect': effect, 'transport': transport,
                       'node': node, 'observation': obs, 'sample_counts': counts, 'cleanup': cleanup,
                       'attempts': attempts, 'reported_delivery_attempt_count': len(attempts),
                       'native_pause_count': None if node is None else int(node['native_pause'] is not None),
                       'missing_evidence': missing, 'corroboration_gaps': gaps,
                       'assessment': 'INDETERMINATE' if missing or gaps else 'BOUNDED_EVIDENCE',
                       'bounded_pause': bool(bounded)})
    count = sum(t['bounded_pause'] for t in output)
    return {'intent': expected_intent, 'profile': CONTRACT['profile'],
            'aggregate': 'ALL_ENUMERATED_TARGETS_BOUNDED_PAUSE' if count == 3 else 'PARTIAL',
            'intended_target_count': 3, 'bounded_pause_count': count,
            'reported_target_count': len(nodes), 'reported_delivery_attempt_count': len(all_sends),
            'delivery_attempt_inventory': 'COMPLETE_WITHIN_LOCAL_CONTRACT' if len(nodes) == 3 else 'PARTIAL',
            'targets': output, 'node_native': native, 'unresolved_links': unresolved,
            'limits': CONTRACT['limits']}


def evaluate(delivery, expected_intent, controller_trust, node_trust):
    native = native_reconciliation = None
    try:
        require(type(node_trust) is dict and set(node_trust) == set(TARGETS), 'all intended trust inputs required')
        trusts = {'controller': controller_trust, **node_trust}
        keys = [trusts[role]['bindings']['bindings'][actor]['public_key_hex'] for role, actor in ACTORS.items()]
        require(len(set(keys)) == 4, 'distinct role keys required')
        source, mapped, native = authenticate(delivery, controller_trust, 'controller')
        projected = project(source, expected_intent, node_trust)
        require(mapped == projected, 'controller source projection mismatch')
        ops = verifier.OperatorInputs()
        ops.bindings_doc = {key: {k: v for trust in trusts.values() for k, v in trust['bindings'][key].items()}
                            for key in ('bindings', 'producer_bindings', 'witness_bindings')}
        ops.revocation_doc = {'snapshot_id': 'local.multitarget-partial-all',
                              'bindings': {k: v for trust in trusts.values() for k, v in trust['revocation']['bindings'].items()}}
        native_reconciliation = reconcile([delivery['artifact']] + [source['nodes'][t]['artifact']
                                           for t in TARGETS if t in source['nodes']], ops=ops)
        return {'admission': 'MATCH', 'native': native, 'native_reconciliation': native_reconciliation,
                'result': projected, 'errors': []}
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError) as exc:
        return {'admission': 'NO_MATCH', 'native': native if native is not None else getattr(exc, 'native', None),
                'native_reconciliation': native_reconciliation,
                'failed_report_native': exc.native if isinstance(exc, ReportFailure) else None,
                'result': None, 'errors': [str(exc)]}
