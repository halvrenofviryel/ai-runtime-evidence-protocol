"""Generate native expected outputs before entering a clean installed environment."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from examples.v02.run_lifecycle import lifecycle, policy, VARIANTS
from tools.airep_v02.reconcile import reconcile
from tools.airep_v02.verify import evaluate_request, operator_inputs
import json


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def main(out):
    out.mkdir(parents=True, exist_ok=False)
    bindings, revocation, independence = policy()
    for name, data in [('bindings', bindings), ('revocation', revocation), ('independence', independence)]:
        (out/(name+'.json')).write_bytes(encoded(data))
    cases=[]
    for variant in VARIANTS:
        trust = {'bindings': bindings, 'revocation': revocation}
        if variant != 'unproven-independent':
            trust['independence'] = independence
        ops = operator_inputs(bindings=str(out/'bindings.json'), revocation=str(out/'revocation.json'),
            independence_policy=None if variant=='unproven-independent' else str(out/'independence.json'))
        docs,_ = lifecycle(variant)
        cases.append({'name': variant, 'artifacts': docs, 'trust': trust, 'expected': reconcile(docs, ops=ops)})
    (out/'native-cases.json').write_bytes(encoded(cases))
    # A positive signed request plus a valid-Core/invalid-signature request.
    docs,_ = lifecycle('complete')
    requests=[]
    ops = operator_inputs(bindings=str(out/'bindings.json'), revocation=str(out/'revocation.json'), independence_policy=str(out/'independence.json'))
    for name in ['valid', 'invalid-signature']:
        artifact=json.loads(json.dumps(docs[-1]))
        if name=='invalid-signature':
            artifact['integrity']['signature']['value']='0'*128
        request={'artifact':artifact,'related_artifacts':docs[:-1]}
        requests.append({'name':name,'request':request,'trust':{'bindings':bindings,'revocation':revocation,'independence':independence},
                         'expected':evaluate_request(encoded(request),ops=ops)})
    (out/'verify-cases.json').write_bytes(encoded(requests))
    print('11 native reconciliation cases and 2 raw verifier cases prepared')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    main(parser.parse_args().out)
