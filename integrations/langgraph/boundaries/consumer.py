"""Closed capture projection: intended denominator, barrier order and tested authority."""
from integrations.langgraph.run import encoded
from integrations.langgraph.temporal.core import identity, tick
from tools.airep_v02.json_input import loads
from .binding import authenticate, exact, CONTRACT, ACTORS, AuthenticationFailure, ReportFailure
from .observer import project as observer_project

OPS = {'record_append','record_truncate','record_chmod','record_unlink','record_replace','record_symlink_write',
       'key_read','key_write','key_unlink','own_business_write','nested_user_namespace','observer_remount_rw'}
KINDS = {'ready','authority_probe','receipt','ignored','native_paused','graph_completed','inflight_ready',
         'effect_committed','release_ack','finished'}


def one(rows, description, *, optional=False):
    if optional and not rows: return None
    if len(rows) != 1: raise ValueError('exactly one ' + description + ' required')
    return rows[0]


def project(source, expected_intent, observer_trust):
    exact(source, 'schema intent scenario controller_clock_id schedule authority_config')
    exact(expected_intent, 'workflow_id run_id control_id attempt_id targets')
    targets = expected_intent['targets']
    if (type(targets) is not list or not targets or len(targets) > 8
        or any(type(t) is not str or not t or len(t) > 64 for t in targets) or len(targets) != len(set(targets))):
        raise ValueError('explicit unique intended targets required')
    if (source['schema'] != 'boundary-capture-v1' or source['intent'] != expected_intent
        or source['authority_config'] != 'bwrap-minimal-ro-observer-hidden-key-v1'
        or type(source['controller_clock_id']) is not str or not source['controller_clock_id']):
        raise ValueError('capture intent or accepted basis mismatch')
    if type(source['schedule']) is not list or len(source['schedule']) > 200:
        raise ValueError('bounded controller schedule required')
    records, last = [], -1
    for index, row in enumerate(source['schedule'], 1):
        exact(row, 'seq tick peer direction message_hex')
        if (type(row['seq']) is not int or row['seq'] != index or not tick(row['tick']) or row['tick'] < last
            or row['peer'] not in targets + ['observer'] or row['direction'] not in ('sent','received','cleanup')):
            raise ValueError('controller ordering/peer mismatch')
        last = row['tick']; raw = bytes.fromhex(row['message_hex'])
        if len(raw) > 131072: raise ValueError('bounded message required')
        records.append(dict(row, message=loads(raw)))
    def select(peer, direction, kind=None, op=None):
        return [r for r in records if r['peer'] == peer and r['direction'] == direction
                and (kind is None or r['message'].get('kind') == kind) and (op is None or r['message'].get('op') == op)]
    observer_ready = one(select('observer','received','ready'), 'observer ready')['message']
    owner = one(select('observer','received','owner_check'), 'observer owner check')['message']
    if observer_ready['trust'] != observer_trust: raise ValueError('accepted observer trust mismatch')
    owner_ok = (all(owner[k] == observer_ready[k] for k in ('key_hash','record_hash','key_mode','record_mode'))
                and owner['owner_can_write'] is True)
    starts = select('observer','sent',op='start')
    if len({r['message']['nonce'] for r in starts}) != len(starts): raise ValueError('duplicate observer nonce')
    observations, observer_native = {}, []
    for response in select('observer','received','observation'):
        message = response['message']; nonce = message['nonce']
        start = one([r for r in starts if r['message']['nonce'] == nonce], 'matching observation start')
        ack = one([r for r in select('observer','received','window_started') if r['message']['nonce'] == nonce], 'window acknowledgement')
        end = one([r for r in select('observer','sent',op='end') if r['message']['nonce'] == nonce], 'matching observation end')
        if not start['seq'] < ack['seq'] < end['seq'] < response['seq']:
            raise ValueError('observer barrier order mismatch')
        raw, mapped, native = authenticate(message['delivery'], observer_trust, 'observer')
        if mapped != observer_project(raw): raise ValueError('observer source projection mismatch')
        if (raw['identity'] != start['message']['identity'] or raw['nonce'] != nonce
            or raw['clock_id'] != observer_ready['clock_id']):
            raise ValueError('observer identity/nonce/clock mismatch')
        target = raw['identity']['target_id']
        if target not in targets or target in observations or start['message']['source_slot'] != target + '/effects.jsonl':
            raise ValueError('observer target/slot/duplicate mismatch')
        observations[target] = {'projection': mapped, 'source': raw, 'native': native,
                                'start_seq': start['seq'], 'end_request_seq': end['seq'], 'end_seq': response['seq']}
        observer_native.append(native)
    output = []
    for target in targets:
        received = select(target,'received'); ready = one([r for r in received if r['message']['kind']=='ready'], 'target ready')
        scope = ready['message']['identity']; identity(scope)
        if (any(scope[k] != expected_intent[k] for k in ('workflow_id','run_id','control_id','attempt_id'))
            or scope['target_id'] != target or ready != received[0]
            or ready['message']['data']['checkpoint_next'] != ['action']):
            raise ValueError('target readiness identity mismatch')
        previous = -1
        for index, row in enumerate(received, 1):
            m = row['message']; exact(m, 'event_id identity clock_id tick kind data')
            if (m['identity'] != scope or m['event_id'] != 'worker-' + str(index)
                or m['clock_id'] != 'worker-' + scope['runtime_epoch'] or not tick(m['tick'])
                or m['tick'] < previous or m['kind'] not in KINDS or type(m['data']) is not dict):
                raise ValueError('worker identity/event/order mismatch')
            previous = m['tick']
        receipt = one(select(target,'received','receipt'), 'receipt', optional=True)
        command = one(select(target,'sent',op='pause'), 'pause command', optional=True)
        if receipt and (not command or command['seq'] >= receipt['seq']
                        or receipt['message']['data'] != {'command_hex': command['message_hex']}):
            raise ValueError('receipt does not bind exact prior command')
        if command and command['message'] != {'op':'pause','identity':scope}:
            raise ValueError('command identity mismatch')
        paused = one(select(target,'received','native_paused'), 'native pause', optional=True)
        ignored = one(select(target,'received','ignored'), 'ignored handler', optional=True)
        if paused:
            d = paused['message']['data']; exact(d, 'terminal_checkpoint_id next interrupts checkpoint_interrupts')
            if (not receipt or paused['seq'] <= receipt['seq'] or ignored
                or not isinstance(d['terminal_checkpoint_id'], str) or not d['terminal_checkpoint_id']
                or d['next'] != ['action'] or d['interrupts'] != [command['message']]
                or d['checkpoint_interrupts'] != [command['message']]):
                raise ValueError('native interrupt/checkpoint mismatch')
        if ignored and (not receipt or ignored['seq'] <= receipt['seq']
                        or ignored['message']['data'] != {'operation':'continue-without-pause'}):
            raise ValueError('ignored-handler evidence mismatch')
        cleanup = one(select(target,'cleanup'), 'cleanup')
        clean = cleanup['message']; exact(clean, 'forced exitcode pid')
        if (type(clean['forced']) is not bool or type(clean['exitcode']) is not int or cleanup['seq'] <= received[-1]['seq']
            or (clean['forced'] and clean['exitcode'] == 0) or (not clean['forced'] and clean['exitcode'] != 0)):
            raise ValueError('cleanup outcome mismatch')
        obs = observations.get(target)
        if obs and (obs['projection']['identity'] != scope or obs['end_seq'] >= cleanup['seq']):
            raise ValueError('observation identity mismatch or after cleanup')
        if obs and (paused or ignored) and obs['start_seq'] <= (paused or ignored)['seq']:
            raise ValueError('observation does not follow reported handler boundary')
        probe = one(select(target,'received','authority_probe'), 'authority probe')['message']['data']
        exact(probe, 'attempts cap_eff no_new_privs observer_mount_options namespace_pid namespaces')
        attempts = probe['attempts']
        if type(attempts) is not list or {a['operation'] for a in attempts} != OPS or len(attempts) != len(OPS):
            raise ValueError('complete authority probe inventory required')
        for a in attempts:
            exact(a, 'operation allowed errno')
            if type(a['allowed']) is not bool or (a['allowed'] and a['errno'] is not None):
                raise ValueError('authority probe result mismatch')
        allowed_errno = {'record_replace': {18,30,13,1}, 'key_read': {2,13}, 'key_write': {2,30,13},
                         'key_unlink': {2,30,13}, 'nested_user_namespace': {1,13,28}, 'observer_remount_rw': {1,13}}
        probe_ok = all(a['allowed'] if a['operation']=='own_business_write' else
                       (not a['allowed'] and type(a['errno']) is int and a['errno'] in allowed_errno.get(a['operation'],{30,13,1}))
                       for a in attempts)
        authority = (probe_ok and owner_ok and probe['cap_eff']=='0000000000000000' and probe['no_new_privs']=='1'
                     and len(probe['observer_mount_options'])==1 and 'ro' in probe['observer_mount_options'][0].split(',')
                     and set(probe['namespaces']) == {'mnt','pid','user','net'}
                     and all(probe['namespaces'][k] != observer_ready['namespaces'][k] for k in probe['namespaces']))
        inflight = one(select(target,'received','inflight_ready'),'inflight barrier',optional=True)
        committed = one(select(target,'received','effect_committed'),'effect commit',optional=True)
        release = one(select(target,'sent',op='release_effect'),'release barrier',optional=True)
        if committed and (not inflight or not release or not inflight['seq'] < release['seq'] < committed['seq']):
            raise ValueError('effect barrier order not established')
        if committed and obs and not obs['start_seq'] < release['seq'] < committed['seq'] < obs['end_request_seq']:
            raise ValueError('commit is outside the acknowledged observation barriers')
        after_pause = bool(committed and paused and inflight and receipt
                           and inflight['seq'] < receipt['seq'] < paused['seq'] < release['seq'] < committed['seq'])
        stages = {'receipt':'RECEIVED_REPORTED' if receipt else 'MISSING',
                  'execution':'PAUSED_REPORTED' if paused else 'CONTINUED_REPORTED' if ignored else 'MISSING',
                  'effect':obs['projection']['status'] if obs else 'MISSING'}
        bounded = stages == {'receipt':'RECEIVED_REPORTED','execution':'PAUSED_REPORTED','effect':'QUIESCENT_REPORTED'} and not clean['forced']
        output.append({'target_id':target,'identity':scope,'stages':stages,'bounded_pause':bounded,
            'cleanup':clean,'authority':'TESTED_PATHS_RESTRICTED' if authority else 'BOUNDARY_NOT_ESTABLISHED',
            'authority_probe':probe,'observer':obs,'effect_commit_after_native_pause':after_pause,
            'barriers':{k:(v['seq'] if v else None) for k,v in [('inflight',inflight),('receipt',receipt),('pause',paused),('release',release),('commit',committed),('cleanup',cleanup)]},
            'history':[{'controller_seq':r['seq'],'controller_tick':r['tick'],'event':r['message']} for r in received]})
    count = sum(r['bounded_pause'] for r in output)
    if any(r['authority'] != 'TESTED_PATHS_RESTRICTED' for r in output): aggregate='BOUNDARY_NOT_ESTABLISHED'
    elif count == len(targets): aggregate='ALL_TARGETS_BOUNDED_PAUSE'
    elif count: aggregate='PARTIAL'
    elif any(r['cleanup']['forced'] for r in output): aggregate='CLEANUP_TERMINATED'
    elif any(r['stages']['effect']=='CONTINUED_REPORTED' for r in output): aggregate='EFFECT_CONTINUED'
    else: aggregate='UNESTABLISHED'
    return {'expected_intent':expected_intent,'controller_clock_id':source['controller_clock_id'],
            'aggregate':aggregate,'intended_target_count':len(targets),'bounded_pause_count':count,
            'targets':output,'observer_owner_check':owner,'observer_native':observer_native,'limits':CONTRACT['limits']}


def evaluate(delivery, expected_intent, controller_trust, observer_trust):
    native = None
    try:
        if (controller_trust['bindings']['bindings'][ACTORS['controller']]['public_key_hex']
            == observer_trust['bindings']['bindings'][ACTORS['observer']]['public_key_hex']):
            raise ValueError('distinct controller and observer keys required')
        source, mapped, native = authenticate(delivery, controller_trust, 'controller')
        projected = project(source, expected_intent, observer_trust)
        if mapped != projected: raise ValueError('controller source projection mismatch')
        return {'admission':'MATCH','native':native,'result':projected,'errors':[]}
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,RecursionError) as exc:
        return {'admission':'NO_MATCH','native':native if native is not None else getattr(exc,'native',None),
                'failed_report_native':exc.native if isinstance(exc,ReportFailure) else None,'failed_authentication':exc.native if isinstance(exc,AuthenticationFailure) else None,'result':None,'errors':[str(exc)]}
