#!/usr/bin/env python3
"""Execute the documented developer workflow with the current Python environment."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    def run(argv):
        print('COMMAND',json.dumps(argv),flush=True)
        p=subprocess.run(argv,cwd=ROOT,capture_output=True,text=True)
        print(p.stdout,end=''); print(p.stderr,end='',file=sys.stderr)
        if p.returncode: raise RuntimeError(f'command exited {p.returncode}')
        return p.stdout

    with tempfile.TemporaryDirectory(prefix='airep-quickstart-') as tmp:
        temp=Path(tmp); demo=temp/'demo-output'
        run([sys.executable,'examples/v02/run_lifecycle.py','--out',str(demo)])
        run([sys.executable,'-m','tools.airep_v02','keygen','--out',str(temp/'my-test-key.json')])
        docs=[]
        for name,family,role,chain,previous in [
            ('decision','decision','governor','demo.governance-chain',None),
            ('dispatch','control','governor',None,'decision'),
            ('receipt','control','executor','demo.execution-chain',None),
            ('execution','execution','executor',None,'receipt'),
            ('effect','effect','observer','demo.observation-chain',None)]:
            out=temp/(name+'.json')
            cmd=[sys.executable,'-m','tools.airep_v02','emit-'+family,'--key',str(demo/'keys'/(role+'.json')),
                 '--producer','demo.'+role,'--record-id','demo.'+name,'--payload',str(demo/'payloads'/(name+'.json')),'--out',str(out)]
            cmd+=['--previous',str(temp/(previous+'.json'))] if previous else ['--chain-id',chain]
            run(cmd); docs.append(json.loads(out.read_text()))
        batch=temp/'lifecycle.json'; batch.write_text(json.dumps(docs))
        inputs=['--bindings',str(demo/'bindings.json'),'--revocation',str(demo/'revocation.json'),
                '--independence-policy',str(demo/'independence.json')]
        verify=json.loads(run([sys.executable,'-m','tools.airep_v02','verify','--input',str(batch),*inputs]))
        assert len(verify['verdicts'])==5 and all(v['class']=='AIREP-Authenticated' for v in verify['verdicts'])
        reconciled=json.loads(run([sys.executable,'-m','tools.airep_v02','reconcile','--input',str(batch),*inputs]))
        assert reconciled['summary']['counts']['FAILURE']==0 and reconciled['summary']['counts']['MISSING']==0
        assert reconciled['summary']['status']=='INCOMPLETE'
        for name in ('issuer_dispatch','receiver_receipt','toctou','effect_binding'):
            values=[c['state'] for c in reconciled['checks'] if c['check']==name]
            assert values and set(values)=={'SATISFIED'},name
        node=json.loads(run(['node','tools/airep_v02/verify_node.mjs','--request',str(demo/'requests/demo.effect.json'),*inputs]))
        assert node['class']=='AIREP-Authenticated' and node['observer_assessment']=='independent'
        negative=json.loads(run([sys.executable,'-m','tools.airep_v02','reconcile','--input',str(demo/'variants/no-receipt.json'),*inputs]))
        assert any(c['check']=='receiver_receipt' and c['state']=='MISSING' for c in negative['checks'])
        print('QUICKSTART PASS: keygen, five emit commands, Python/Node verification, reconciliation and missing-receipt negative.')


if __name__=='__main__':
    main()
