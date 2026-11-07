"""Measured K7 captures, separately labeled signed negatives, and exact-byte offline replay."""
import argparse
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
from integrations.langgraph.run import ROOT, encoded, utc
from tools.airep_v02.json_input import loads
from .binding import Writer, CONTRACT, BASIS
from .capture import capture, SCENARIOS
from .consumer import project, project_node, evaluate


def make_inputs(root):
    writer=Writer('controller'); cases=[]
    for name in SCENARIOS:
        source,trusts=capture(root/name,name); mapped=project(source,source['intent'],trusts)
        count={'fanout_all':3,'fanout_unknown':2,'chain_all':3,'chain_refused':1,'chain_unknown':2,'chain_retry':3}[name]
        if mapped['bounded_pause_count']!=count: raise AssertionError((name,mapped['bounded_pause_count']))
        cases.append({'label':name,'origin':'measured same-host LangGraph processes and Unix socket transport',
            'expected_count':count,'expected_admission':'MATCH','intent':copy.deepcopy(source['intent']),
            'node_trust':trusts,'delivery':writer.sign(source,mapped)})
    # A gateway is itself signed by an accepted local producer. Rewriting a child result
    # still fails against the separately authenticated child source / attempt history.
    for name,gateway,mode in [('chain_refused','A','refusal'),('chain_unknown','B','unknown')]:
        base=next(c for c in cases if c['label']==name); source=loads(base['delivery']['source_bytes'].encode())
        node=loads(source['nodes'][gateway]['source_bytes'].encode()); liar=Writer(gateway)
        trusts=copy.deepcopy(base['node_trust']); trusts[gateway]=liar.trust
        for event in node['events']:
            if event['kind']=='transport':
                transport=event['data']
                if mode=='refusal':
                    reply=loads(bytes.fromhex(transport['response_hex'])); reply['local_status']='PAUSED_REPORTED'
                else:
                    reply={'target_id':'C','delivery_attempt_id':transport['delivery_attempt_id'],
                           'local_status':'PAUSED_REPORTED','duplicate':False,'children':[]}
                transport.update(status='RESPONSE',error=None,response_hex=encoded(reply).hex())
            elif event['kind']=='reply':
                reply=loads(bytes.fromhex(event['data']['response_hex']))
                reply['children']=[e['data'] for e in node['events'] if e['kind']=='transport']
                event['data']['response_hex']=encoded(reply).hex()
        source['nodes'][gateway]=liar.sign(node,project_node(node,base['intent'],gateway))
        # Preserve the upstream wire view: this edited fixture is not a live capture.
        reply=next(e['data']['response_hex'] for e in node['events'] if e['kind']=='reply')
        if gateway=='A':
            source['events'][-1]['data']['response_hex']=reply
        else:
            ancestor=loads(source['nodes']['A']['source_bytes'].encode()); ancestor_writer=Writer('A'); trusts['A']=ancestor_writer.trust
            for event in ancestor['events']:
                if event['kind']=='transport': event['data']['response_hex']=reply
                elif event['kind']=='reply':
                    upper=loads(bytes.fromhex(event['data']['response_hex']))
                    upper['children']=[e['data'] for e in ancestor['events'] if e['kind']=='transport']
                    event['data']['response_hex']=encoded(upper).hex()
            source['nodes']['A']=ancestor_writer.sign(ancestor,project_node(ancestor,base['intent'],'A'))
            source['events'][-1]['data']['response_hex']=next(e['data']['response_hex'] for e in ancestor['events'] if e['kind']=='reply')
        cases.append({'label':'gateway_'+mode+'_laundering','origin':'authored signed negative fixture; not a measured incident',
            'expected_count':None,'expected_admission':'NO_MATCH','intent':base['intent'],'node_trust':trusts,
            'delivery':writer.sign(source,loads(base['delivery']['projection_bytes'].encode()))})
    base=cases[0]; source=loads(base['delivery']['source_bytes'].encode()); scope=copy.deepcopy(CONTRACT['scope'])
    scope['covers'].append('All execution paths independently and permanently stopped')
    cases.append({'label':'scope_inflation','origin':'authored signed negative fixture', 'expected_count':None,
        'expected_admission':'NO_MATCH','intent':base['intent'],'node_trust':base['node_trust'],
        'delivery':writer.sign(source,loads(base['delivery']['projection_bytes'].encode()),scope=scope)})
    return {'format':'multitarget-inputs-v1','basis_digest':BASIS,'controller_trust':writer.trust,'cases':cases}


def replay(inputs):
    if inputs['format']!='multitarget-inputs-v1' or inputs['basis_digest']!=BASIS: raise ValueError('unaccepted package basis')
    views=[]
    for case in inputs['cases']:
        evaluation=evaluate(case['delivery'],case['intent'],inputs['controller_trust'],case['node_trust'])
        count=evaluation['result']['bounded_pause_count'] if evaluation['result'] else None
        if evaluation['admission']!=case['expected_admission'] or count!=case['expected_count']:
            raise AssertionError((case['label'],evaluation['errors'],evaluation['admission'],count))
        views.append({'label':case['label'],'origin':case['origin'],'evaluation':evaluation})
    return views


def write_report(out,replay_path=None):
    out.mkdir(parents=True,exist_ok=False)
    if replay_path:
        raw=replay_path.read_bytes()
        if len(raw)>24*1024*1024: raise ValueError('bounded replay package required')
        inputs=loads(raw)
    else: inputs=make_inputs(out/'capture')
    views=replay(inputs); (out/'inputs.json').write_bytes(encoded(inputs))
    record={'created_utc':utc(),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'worktree_status':subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True),'basis_digest':BASIS,
        'fresh_capture':not bool(replay_path),'python':platform.python_version(),'langgraph':importlib.metadata.version('langgraph'),
        'kernel':platform.release(),'views':views}
    (out/'report.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    payload=json.dumps(views).replace('<','\\u003c').replace('&','\\u0026')
    (out/'index.html').write_text(Path(__file__).with_name('view.html').read_text().replace('__REPORT_DATA__',payload))
    manifest={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file()}
    (out/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'views':len(views),'fresh_capture':not bool(replay_path),
        'results':[(v['label'],v['evaluation']['admission'],v['evaluation']['result']['bounded_pause_count'] if v['evaluation']['result'] else None) for v in views]}))
    return record


def main():
    p=argparse.ArgumentParser(); p.add_argument('--out',type=Path,required=True); p.add_argument('--replay',type=Path)
    a=p.parse_args(); write_report(a.out,a.replay)

if __name__=='__main__': main()
