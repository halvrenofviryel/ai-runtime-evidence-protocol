"""Closed three-target contract; cross-check sender and receiver reports, not gateway labels."""
from integrations.langgraph.temporal.core import identity, tick
from integrations.langgraph.run import encoded
from tools.airep_v02.json_input import loads
from tools.airep_v02.basis import verifier
from tools.airep_v02.reconcile import reconcile
from .binding import authenticate, exact, CONTRACT, ACTORS, ReportFailure

TARGETS = ['A', 'B', 'C']
TOPOLOGIES = {'fanout': {'controller': TARGETS, 'A': [], 'B': [], 'C': []},
              'chain': {'controller': ['A'], 'A': ['B'], 'B': ['C'], 'C': []}}


def require(condition, message):
    if not condition: raise ValueError(message)


def intent_check(intent):
    exact(intent, 'targets topology children identities')
    require(intent['targets'] == TARGETS and intent['topology'] in TOPOLOGIES, 'fixed unique three-target intent required')
    require(intent['children'] == TOPOLOGIES[intent['topology']], 'accepted acyclic topology required')
    require(type(intent['identities']) is dict and set(intent['identities']) == set(TARGETS), 'all intended identities required')
    common = None
    for target in TARGETS:
        scope = intent['identities'][target]; identity(scope)
        require(scope['target_id'] == target, 'target identity replacement')
        value = tuple(scope[k] for k in ('workflow_id', 'run_id', 'control_id', 'attempt_id'))
        if common is None: common = value
        require(common == value, 'workflow/run/control/execution attempt mismatch')
    for key in ('runtime_epoch', 'checkpoint_id'):
        require(len({intent['identities'][t][key] for t in TARGETS}) == 3, 'borrowed target epoch/checkpoint')


def command_check(command, intent, target):
    exact(command, 'op identity sender path delivery_attempt_id parent_delivery_attempt_id')
    require(command['op'] == 'pause' and command['identity'] == intent['identities'][target], 'command identity mismatch')
    sender = command['sender']
    require(sender in intent['children'] and target in intent['children'][sender], 'wrong delegation edge')
    path = ['controller', target] if intent['topology']=='fanout' else ['controller']+TARGETS[:TARGETS.index(target)+1]
    require(command['path'] == path, 'wrong delegation route')
    aid = command['delivery_attempt_id']; parent = command['parent_delivery_attempt_id']
    require(type(aid) is str and 0 < len(aid) <= 128, 'delivery attempt identity required')
    require(parent is None if sender=='controller' else type(parent) is str and bool(parent), 'parent delivery identity required')


def event_check(events):
    require(type(events) is list and len(events) <= 64, 'bounded event log required')
    last = -1
    for index, event in enumerate(events, 1):
        exact(event, 'seq tick kind data')
        require(type(event['seq']) is int and event['seq'] == index and tick(event['tick'])
                and event['tick'] >= last and type(event['data']) is dict, 'event sequence/clock mismatch')
        last = event['tick']


def transport_check(result, aid):
    exact(result, 'delivery_attempt_id status response_hex error')
    require(result['delivery_attempt_id'] == aid, 'transport attempt mismatch')
    if result['status'] == 'RESPONSE':
        require(result['error'] is None and type(result['response_hex']) is str, 'response bytes required')
        loads(bytes.fromhex(result['response_hex']))
    else:
        require(result['status']=='TRANSPORT_UNKNOWN' and result['response_hex'] is None
                and result['error'] in ('EOFError','FileNotFoundError','ConnectionRefusedError','TimeoutError','ConnectionResetError','BrokenPipeError'),
                'unknown transport must retain error')


def project_node(source, intent, target):
    intent_check(intent); exact(source, 'schema identity clock_id events')
    require(source['schema']=='multitarget-node-v1' and source['identity']==intent['identities'][target]
            and source['clock_id']=='worker-'+source['identity']['runtime_epoch'], 'node identity/clock mismatch')
    events = source['events']; event_check(events)
    require(len(events)>=2 and events[0]['kind']=='ready' and events[1]['kind']=='configured', 'ready/configuration order required')
    ready = events[0]['data']; exact(ready, 'identity pid checkpoint_next')
    require(ready['identity']==source['identity'] and type(ready['pid']) is int and ready['pid']>0
            and ready['checkpoint_next']==['action'], 'native initial checkpoint mismatch')
    require(events[1]['data']=={'intent':intent}, 'frozen worker intent mismatch')
    receipts, outgoing, active, pending = [], [], None, None
    native = None
    for event in events[2:]:
        kind, data = event['kind'], event['data']
        if kind=='receipt':
            exact(data, 'command_hex'); command=loads(bytes.fromhex(data['command_hex'])); command_check(command,intent,target)
            require(active is None and len(receipts)<2, 'overlapping or excessive receipts')
            require(command['delivery_attempt_id'] not in [r['command']['delivery_attempt_id'] for r in receipts], 'duplicate delivery attempt id')
            active={'command':command,'command_hex':data['command_hex'],'duplicate':native is not None,
                    'native_pause':None,'refused':False,'outgoing':[],'reply':None}; receipts.append(active)
        elif kind=='native_paused':
            exact(data, 'terminal_checkpoint_id next interrupts checkpoint_interrupts')
            require(active is not None and native is None and not active['refused'], 'unexpected repeated native execution')
            require(type(data['terminal_checkpoint_id']) is str and bool(data['terminal_checkpoint_id'])
                    and data['terminal_checkpoint_id']!=source['identity']['checkpoint_id']
                    and data['next']==['action'] and data['interrupts']==[active['command']]
                    and data['checkpoint_interrupts']==[active['command']], 'native interrupt binding mismatch')
            active['native_pause']=data; native=data
        elif kind=='refused':
            require(active is not None and native is None and not active['refused']
                    and data=={'delivery_attempt_id':active['command']['delivery_attempt_id']}, 'refusal binding mismatch')
            active['refused']=True
        elif kind=='send':
            exact(data, 'command_hex'); command=loads(bytes.fromhex(data['command_hex']))
            child=command['identity']['target_id']; command_check(command,intent,child)
            require(active is not None and native is not None and not active['duplicate'] and pending is None
                    and command['sender']==target and command['parent_delivery_attempt_id']==active['command']['delivery_attempt_id'],
                    'forwarded request must descend from received control')
            require(len(active['outgoing'])<2 and (not active['outgoing'] or active['outgoing'][-1]['transport']['status']=='TRANSPORT_UNKNOWN'),
                    'retry requires prior failed transport')
            pending={'command':command,'command_hex':data['command_hex'],'transport':None}
            outgoing.append(pending); active['outgoing'].append(pending)
        elif kind=='transport':
            require(pending is not None, 'transport without send'); transport_check(data,pending['command']['delivery_attempt_id'])
            pending['transport']=data; pending=None
        elif kind=='reply':
            exact(data, 'response_hex dropped'); require(active is not None and pending is None and type(data['dropped']) is bool, 'reply state mismatch')
            reply=loads(bytes.fromhex(data['response_hex'])); exact(reply, 'target_id delivery_attempt_id local_status duplicate children')
            require(type(reply['duplicate']) is bool and type(reply['children']) is list, 'typed reply fields required')
            status='REFUSED' if active['refused'] else 'PAUSED_REPORTED'
            require(active['refused'] or native is not None, 'cannot claim pause without native interrupt')
            require(reply=={'target_id':target,'delivery_attempt_id':active['command']['delivery_attempt_id'],
                'local_status':status,'duplicate':active['duplicate'],'children':[a['transport'] for a in active['outgoing']]},
                'gateway local status, duplicate flag or downstream history mismatch')
            if status=='PAUSED_REPORTED' and not active['duplicate']:
                require(bool(active['outgoing'])==bool(intent['children'][target]), 'delegation missing from accepted handler')
            require(not active['refused'] or not active['outgoing'], 'refusal cannot silently forward')
            active['reply']=data; active=None
        else: raise ValueError('unrecognized node event')
    require(active is None and pending is None, 'incomplete node event sequence')
    return {'target_id':target,'identity':source['identity'],'clock_id':source['clock_id'],'pid':ready['pid'],
            'receipts':receipts,'outgoing':outgoing,'native_pause':native,
            'execution':'PAUSED_REPORTED' if native else 'REFUSED' if receipts else 'UNKNOWN'}


def project(source, expected_intent, node_trust):
    intent_check(expected_intent)
    exact(source, 'schema intent controller_clock_id events control_end_tick nodes observations cleanup')
    require(source['schema']=='multitarget-capture-v1' and source['intent']==expected_intent, 'expected intent mismatch')
    require(type(source['controller_clock_id']) is str and bool(source['controller_clock_id']), 'controller clock required')
    require(set(source['nodes'])==set(TARGETS) and set(node_trust)==set(TARGETS), 'all intended node reports and trust required')
    nodes, native = {}, {}
    for target in TARGETS:
        raw,mapped,verdict=authenticate(source['nodes'][target],node_trust[target],target)
        projected=project_node(raw,expected_intent,target)
        require(mapped==projected, 'node projection mismatch')
        nodes[target]=projected; native[target]=verdict
    require(len({n['pid'] for n in nodes.values()})==3, 'distinct target processes required')
    events=source['events']; event_check(events); outgoing=[]; pending=None
    for event in events:
        data=event['data']
        if event['kind']=='send':
            exact(data,'command_hex'); command=loads(bytes.fromhex(data['command_hex']))
            command_check(command,expected_intent,command['identity']['target_id'])
            require(command['sender']=='controller' and pending is None, 'invalid controller dispatch')
            pending={'command':command,'command_hex':data['command_hex'],'transport':None}; outgoing.append(pending)
        elif event['kind']=='transport':
            require(pending is not None,'controller response without send'); transport_check(data,pending['command']['delivery_attempt_id'])
            pending['transport']=data; pending=None
        else: raise ValueError('unrecognized controller event')
    require(pending is None and [a['command']['identity']['target_id'] for a in outgoing]==expected_intent['children']['controller'],
            'controller must dispatch each root target exactly once')
    require(tick(source['control_end_tick']) and events[-1]['tick']<=source['control_end_tick'], 'control cutoff order mismatch')
    all_sends=outgoing+[a for t in TARGETS for a in nodes[t]['outgoing']]
    sends={a['command']['delivery_attempt_id']:a for a in all_sends}
    require(len(sends)==len(all_sends),'reused transport attempt identity')
    receipts={r['command']['delivery_attempt_id']:(t,r) for t in TARGETS for r in nodes[t]['receipts']}
    require(len(receipts)==sum(len(n['receipts']) for n in nodes.values()), 'cross-target attempt collision')
    for aid,(target,r) in receipts.items():
        require(aid in sends and sends[aid]['command_hex']==r['command_hex'], 'receiver has no exact sender request')
    for aid,sent in sends.items():
        command=sent['command']; parent=command['parent_delivery_attempt_id']
        if parent is not None:
            require(parent in receipts and receipts[parent][0]==command['sender'], 'borrowed parent hop')
        transport=sent['transport']; received=receipts.get(aid)
        if transport['status']=='RESPONSE':
            require(received is not None and received[1]['reply']['dropped'] is False
                    and received[1]['reply']['response_hex']==transport['response_hex'], 'gateway changed receiver response or fabricated success')
        elif received is not None:
            require(received[1]['reply']['dropped'] is True and transport['error']=='EOFError', 'lost response/receipt history mismatch')
    require(set(source['observations'])==set(TARGETS) and set(source['cleanup'])==set(TARGETS), 'target observation/cleanup inventory mismatch')
    output=[]
    for target in TARGETS:
        node=nodes[target]; obs=source['observations'][target]
        exact(obs, 'identity clock_id before after'); require(obs['identity']==node['identity'] and obs['clock_id']==source['controller_clock_id'], 'observation identity/clock mismatch')
        counts=[]; previous=None
        for sample in (obs['before'],obs['after']):
            exact(sample,'start end bytes_hex'); require(tick(sample['start']) and tick(sample['end']) and sample['start']<=sample['end'], 'sample window order mismatch')
            raw=bytes.fromhex(sample['bytes_hex']); rows=[loads(line) for line in raw.splitlines()]
            require(len(raw)<=524288 and raw.endswith(b'\n'), 'bounded whole effect lines required')
            for index,row in enumerate(rows,1):
                require(row=={'identity':node['identity'],'step':index}, 'effect identity/append sequence mismatch')
            if previous is not None: require(raw.startswith(previous),'effect history replacement')
            previous=raw; counts.append(len(rows))
        require(source['control_end_tick']<=obs['before']['start']<=obs['before']['end']<obs['after']['start'], 'observation must follow control round')
        cleanup=source['cleanup'][target]; exact(cleanup, 'forced exitcode pid tick')
        require(type(cleanup['forced']) is bool and type(cleanup['exitcode']) is int and cleanup['pid']==node['pid']
                and tick(cleanup['tick']) and obs['after']['end']<cleanup['tick']
                and (cleanup['exitcode']!=0 if cleanup['forced'] else cleanup['exitcode']==0), 'cleanup result/order mismatch')
        attempts=[a for a in all_sends if a['command']['identity']['target_id']==target]
        effect='QUIESCENT_REPORTED' if counts[0]==counts[1] else 'CONTINUED_REPORTED'
        transport='RESPONSE' if any(a['transport']['status']=='RESPONSE' for a in attempts) else 'TRANSPORT_UNKNOWN' if attempts else 'NOT_ATTEMPTED'
        bounded=(node['execution']=='PAUSED_REPORTED' and effect=='QUIESCENT_REPORTED' and transport=='RESPONSE' and not cleanup['forced'])
        output.append({'target_id':target,'identity':node['identity'],'receipt':'RECEIVED_REPORTED' if node['receipts'] else 'MISSING',
            'execution':node['execution'],'effect':effect,'transport':transport,'delivery_attempt_count':len(attempts),
            'native_pause_count':int(node['native_pause'] is not None),'attempts':attempts,'node':node,
            'observation':obs,'sample_counts':counts,'cleanup':cleanup,'bounded_pause':bounded})
    count=sum(t['bounded_pause'] for t in output)
    return {'intent':expected_intent,'aggregate':'ALL_ENUMERATED_TARGETS_BOUNDED_PAUSE' if count==3 else 'PARTIAL',
            'intended_target_count':3,'bounded_pause_count':count,'delivery_attempt_count':len(all_sends),
            'targets':output,'node_native':native,'limits':CONTRACT['limits']}


def evaluate(delivery, expected_intent, controller_trust, node_trust):
    native=None; native_reconciliation=None
    try:
        trusts={'controller':controller_trust,**node_trust}
        keys=[trusts[role]['bindings']['bindings'][actor]['public_key_hex'] for role,actor in ACTORS.items()]
        require(len(set(keys))==4,'distinct role keys required')
        source,mapped,native=authenticate(delivery,controller_trust,'controller')
        projected=project(source,expected_intent,node_trust)
        ops=verifier.OperatorInputs()
        ops.bindings_doc={key:{k:v for trust in trusts.values() for k,v in trust['bindings'][key].items()}
                          for key in ('bindings','producer_bindings','witness_bindings')}
        ops.revocation_doc={'snapshot_id':'local.multitarget-all','bindings':{k:v for trust in trusts.values() for k,v in trust['revocation']['bindings'].items()}}
        native_reconciliation=reconcile([delivery['artifact']]+[source['nodes'][t]['artifact'] for t in TARGETS],ops=ops)
        require(mapped==projected,'controller source projection mismatch')
        return {'admission':'MATCH','native':native,'native_reconciliation':native_reconciliation,'result':projected,'errors':[]}
    except (ValueError,TypeError,KeyError,IndexError,AttributeError,RecursionError) as exc:
        return {'admission':'NO_MATCH','native':native if native is not None else getattr(exc,'native',None),
                'native_reconciliation':native_reconciliation,'failed_report_native':exc.native if isinstance(exc,ReportFailure) else None,
                'result':None,'errors':[str(exc)]}
