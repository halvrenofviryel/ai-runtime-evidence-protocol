"""Measured boundary experiments and explicitly labeled signed negative fixtures."""
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
from .capture import capture, baseline
from .consumer import project, evaluate


def make_inputs(root):
    writer = Writer('controller'); cases=[]
    for name, expected in [('both_paused','ALL_TARGETS_BOUNDED_PAUSE'),('one_unknown','PARTIAL'),
                           ('inflight','EFFECT_CONTINUED'),('timeout','CLEANUP_TERMINATED')]:
        source, observer_trust = capture(root/name,name)
        mapped = project(source, source['intent'], observer_trust)
        cases.append({'label':name,'origin':'measured local LangGraph / separate observer / OS probes',
            'expected':expected,'expected_admission':'MATCH','intent':source['intent'],
            'observer_trust':observer_trust,'delivery':writer.sign(source,mapped)})
    base = cases[0]
    source = loads(base['delivery']['source_bytes'].encode())
    # An actual failed probe must remain disqualifying even if a trusted author signs it.
    for row in source['schedule']:
        message = loads(bytes.fromhex(row['message_hex']))
        if row['peer']=='A' and message.get('kind')=='authority_probe':
            message['data']['attempts'][0].update(allowed=True,errno=None)
            row['message_hex'] = encoded(message).hex(); break
    cases.append({'label':'authority_failure_fixture','origin':'authored signed negative fixture',
        'expected':'BOUNDARY_NOT_ESTABLISHED','expected_admission':'MATCH','intent':base['intent'],
        'observer_trust':base['observer_trust'],'delivery':writer.sign(source,project(source,base['intent'],base['observer_trust']))})
    source = loads(base['delivery']['source_bytes'].encode()); scope = copy.deepcopy(CONTRACT['scope'])
    scope['covers'].append('Independently enforced permanent stop')
    cases.append({'label':'scope_inflation_fixture','origin':'authored signed negative fixture',
        'expected':None,'expected_admission':'NO_MATCH','intent':base['intent'],
        'observer_trust':base['observer_trust'],'delivery':writer.sign(source,project(source,base['intent'],base['observer_trust']),scope=scope)})
    canaries = baseline(root/'unconfined-canary-control')
    if canaries != {'key_read':True,'record_write':True,'record_chmod':True}:
        raise AssertionError('positive permission control failed')
    return {'format':'boundary-inputs-v1','controller_trust':writer.trust,'cases':cases,
            'unconfined_canary_control':canaries,'basis_digest':BASIS}


def replay(inputs):
    if inputs['format']!='boundary-inputs-v1' or inputs['basis_digest']!=BASIS:
        raise ValueError('unsupported input format or basis')
    views=[]
    for case in inputs['cases']:
        result=evaluate(case['delivery'],case['intent'],inputs['controller_trust'],case['observer_trust'])
        aggregate = result['result']['aggregate'] if result['result'] else None
        if result['admission']!=case['expected_admission'] or aggregate!=case['expected']:
            raise AssertionError((case['label'],result['errors'],result['admission'],aggregate,case['expected']))
        views.append({'label':case['label'],'origin':case['origin'],'evaluation':result})
    return views


def write_report(out,replay_path=None):
    out.mkdir(parents=True,exist_ok=False)
    if replay_path:
        raw=replay_path.read_bytes()
        if len(raw)>16*1024*1024: raise ValueError('bounded replay package required')
        inputs=loads(raw)
    else: inputs=make_inputs(out/'capture')
    views=replay(inputs); (out/'inputs.json').write_bytes(encoded(inputs))
    record={'created_utc':utc(),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'worktree_status':subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True),
        'basis_digest':BASIS,'fresh_capture':not bool(replay_path),'python':platform.python_version(),
        'langgraph':importlib.metadata.version('langgraph'),'kernel':platform.release(),
        'bubblewrap':subprocess.check_output(['bwrap','--version'],text=True).strip(),
        'bubblewrap_sha256':hashlib.sha256(Path('/usr/bin/bwrap').read_bytes()).hexdigest(),
        'unconfined_canary_control':inputs['unconfined_canary_control'],'views':views}
    (out/'report.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
    payload=json.dumps(views).replace('<','\\u003c').replace('&','\\u0026')
    (out/'index.html').write_text(Path(__file__).with_name('view.html').read_text().replace('__REPORT_DATA__',payload))
    manifest={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file()}
    (out/'SHA256SUMS.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'views':len(views),'fresh_capture':not bool(replay_path),
                     'results':[(v['label'],v['evaluation']['admission'],v['evaluation']['result']['aggregate'] if v['evaluation']['result'] else None) for v in views]}))
    return record


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--replay',type=Path)
    a=p.parse_args();write_report(a.out,a.replay)

if __name__=='__main__': main()
