#!/usr/bin/env python3
"""A real local file lifecycle with explicit role reports and test-only keys.

Run: python3 examples/v02/run_lifecycle.py --out /tmp/airep-demo
No service, monorepo, network, or unpublished dependency is needed.
"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.airep_v02 import Chain, digest_bytes, digest_json, reference
from tools.airep_v02.json_input import dumps
from tools.airep_v02.reconcile import reconcile
from tools.airep_v02.verify import evaluate_request, operator_inputs

TIME = '2026-09-08T12:00:00Z'
VARIANTS = ('complete', 'no-receipt', 'no-execution', 'toctou-mismatch', 'no-effect',
            'same-executor', 'unproven-independent', 'broken-decision', 'broken-control',
            'broken-execution', 'broken-effect')


def key_for(role):
    # PUBLIC, INSECURE test seeds. Never reuse these keys for real evidence.
    return Ed25519PrivateKey.from_private_bytes(bytes([{'governor':1, 'executor':2, 'observer':3}[role]]) * 32)


def policy():
    bindings = {'bindings':{}, 'producer_bindings':{}, 'witness_bindings':{}}
    revocation = {'snapshot_id':'demo.snapshot', 'bindings':{}}
    for role in ('governor', 'executor', 'observer'):
        bid = 'demo.' + role
        bindings['bindings'][bid] = {'subject_identity':bid, 'role':'producer', 'suite':'ed25519', 'trusted':True,
            'public_key_hex':key_for(role).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        bindings['producer_bindings'][bid] = bid
        revocation['bindings'][bid] = {'state':'active'}
    independence = {'independent_pairs':[{'a':'demo.executor','b':'demo.observer'}], 'non_independent_pairs':[]}
    return bindings, revocation, independence


def lifecycle(variant='complete', runtime=None):
    """Build signed examples; with runtime, dispatch/read/execute/read real files."""
    if variant not in VARIANTS:
        raise ValueError('unknown scenario')
    action = {'operation':'set-state', 'resource':'local-worker', 'state':'paused'}
    action_raw = (json.dumps(action, sort_keys=True, separators=(',', ':'))+'\n').encode()
    instruction_raw = (json.dumps({'instruction_id':'demo.pause-1', 'action':action}, sort_keys=True, separators=(',', ':'))+'\n').encode()
    decision_result = b'{"directive":"release","policy":"demo.local-owner"}\n'
    if runtime is not None:
        runtime.mkdir()
        (runtime/'governed-input.json').write_bytes(action_raw)
        (runtime/'decision-result.json').write_bytes(decision_result)
    governor = Chain(key_for('governor'), 'demo.governor', chain_id='demo.governance-chain')
    executor = Chain(key_for('executor'), 'demo.executor', chain_id='demo.execution-chain')
    observer = Chain(key_for('observer'), 'demo.observer', chain_id='demo.observation-chain')
    payloads = {}
    payloads['decision'] = {'input':{'input_ref':'runtime/governed-input.json', 'input_digest':digest_bytes(action_raw)},
        'claim':{'assertion':'Local owner permits pausing the worker', 'basis':['demo.local-owner']},
        'directive':{'verb':'release', 'policy_basis':['demo.local-owner']},
        'output':{'result_ref':'runtime/decision-result.json','result_digest':digest_bytes(decision_result)}, 'evidence':[]}
    decision = governor.emit_decision(payloads['decision'], record_id='demo.decision', timestamp=TIME)
    if runtime is not None:
        # Dispatch follows the governance decision across a local file boundary.
        (runtime/'instruction.json').write_bytes(instruction_raw)
    payloads['dispatch'] = {'decision_ref':reference(decision), 'instruction_id':'demo.pause-1',
        'instruction_digest':digest_bytes(instruction_raw), 'authorized_action_digest':digest_json(action),
        'control_event':'dispatched', 'boundary_side':'issuer',
        'authority':{'issuer_id':'demo.governor', 'writable_by_controlled_system':False}}
    dispatch = governor.emit_control(payloads['dispatch'], record_id='demo.dispatch', timestamp=TIME)
    received_raw = instruction_raw if runtime is None else (runtime/'instruction.json').read_bytes()
    received = json.loads(received_raw)
    if received['instruction_id'] != 'demo.pause-1':
        raise ValueError('instruction changed at receiver')
    payloads['receipt'] = dict(deepcopy(payloads['dispatch']), instruction_digest=digest_bytes(received_raw), control_event='received', boundary_side='receiver')
    receipt = executor.emit_control(payloads['receipt'], record_id='demo.receipt', timestamp=TIME)
    executed_action = dict(received['action'], state='running') if variant=='toctou-mismatch' else received['action']
    payloads['execution'] = {'decision_ref':reference(decision), 'instruction_id':'demo.pause-1',
        'instruction_digest':digest_bytes(received_raw), 'executed_action_digest':digest_json(executed_action), 'execution_event':'executed'}
    if runtime is not None:
        (runtime/'state.json').write_text(json.dumps({'state':executed_action['state']})+'\n')
    execution = executor.emit_execution(payloads['execution'], record_id='demo.execution', timestamp=TIME)
    state = {'state':executed_action['state']}
    if runtime is not None:
        state = json.loads((runtime/'state.json').read_bytes())  # observer-side read after execution
    payloads['effect'] = {'decision_ref':reference(decision), 'execution_ref':reference(execution),
        'observer_relationship':'same_executor' if variant=='same-executor' else 'independent',
        'observed_state':{'description':'Observer read worker state: ' + state['state'], 'state_digest':digest_json(state)}}
    effect = (executor if variant=='same-executor' else observer).emit_effect(payloads['effect'], record_id='demo.effect', timestamp=TIME)
    artifacts = [decision, dispatch, receipt, execution, effect]
    if variant=='no-receipt':
        artifacts = [decision, dispatch]
    elif variant=='no-execution':
        artifacts = [decision, dispatch, receipt]
    elif variant=='no-effect':
        artifacts = artifacts[:-1]
    elif variant.startswith('broken-'):
        broken = next(a for a in artifacts if a['artifact_type']==variant[7:])
        broken['scope']['covers'].append('tampered after signing')
    return artifacts, payloads


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    bindings, revocation, independence = policy()
    for name, value in [('bindings',bindings), ('revocation',revocation), ('independence',independence)]:
        (args.out/(name+'.json')).write_text(dumps(value))
    ops = operator_inputs(bindings=str(args.out/'bindings.json'), revocation=str(args.out/'revocation.json'),
                          independence_policy=str(args.out/'independence.json'))
    keys = args.out/'keys'; keys.mkdir()
    for role in ('governor','executor','observer'):
        from tools.airep_v02.__main__ import write
        write(str(keys/(role+'.json')), {'seed_hex':bytes([{'governor':1,'executor':2,'observer':3}[role]] * 32).hex()}, private=True)
    artifacts, payloads = lifecycle(runtime=args.out/'runtime')
    (args.out/'lifecycle.json').write_text(dumps(artifacts))
    (args.out/'reconciliation.json').write_text(dumps(reconcile(artifacts, ops=ops)))
    verdicts = []
    payload_dir = args.out/'payloads'; payload_dir.mkdir()
    requests = args.out/'requests'; requests.mkdir()
    for name, payload in payloads.items():
        (payload_dir/(name+'.json')).write_text(dumps(payload))
    for i, artifact in enumerate(artifacts):
        request = {'artifact':artifact, 'related_artifacts':artifacts[:i]+artifacts[i+1:]}
        (requests/(artifact['record_id']+'.json')).write_text(dumps(request))
        verdicts.append(evaluate_request(request, ops=ops))
    (args.out/'verification.json').write_text(dumps({'verdicts':verdicts}))
    failures = args.out/'variants'; failures.mkdir()
    for variant in VARIANTS[1:]:
        docs, _ = lifecycle(variant)
        variant_ops = ops
        if variant=='unproven-independent':
            variant_ops = operator_inputs(bindings=str(args.out/'bindings.json'), revocation=str(args.out/'revocation.json'))
        (failures/(variant+'.json')).write_text(dumps(docs))
        (failures/(variant+'.result.json')).write_text(dumps(reconcile(docs, ops=variant_ops)))
    print('Wrote a real local Decision → dispatch → receipt → Execution → Effect run to', args.out)
    print('Five Authenticated records; observer independence accepted only under the supplied TEST policy.')
    print('Summary remains INCOMPLETE: intended-target coverage is NOT_EVALUATED. No truth or external independence claim.')


if __name__=='__main__':
    main()
