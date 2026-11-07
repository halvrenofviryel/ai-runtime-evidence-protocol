"""Author-fixture experiment, not a general trust-discovery CLI or fresh capture."""
import argparse
import copy
import json
from pathlib import Path
from integrations.langgraph.run import encoded
from tools.airep_v02.json_input import loads
from tools.airep_v02.producer import digest_bytes
from .binding_partial import Writer, BASIS
from .partial import project, evaluate


def replay(inputs):
    if inputs['basis_digest'] != BASIS:
        raise ValueError('partial consumer basis mismatch')
    return [{'label': c['label'], 'origin': c['origin'],
             'evaluation': evaluate(c['delivery'], c['intent'], inputs['controller_trust'], c['node_trust'])}
            for c in inputs['cases']]


def build():
    path = Path(__file__).with_name('evidence') / '2026-11-07/inputs.json'
    old = loads(path.read_bytes())
    writer = Writer('controller')
    cases = []
    specs = [('chain_complete', 'chain_all', None, ()),
             ('fanout_complete', 'fanout_all', None, ()),
             ('chain_c_absent', 'chain_all', 'C', ('nodes', 'observations', 'cleanup')),
             ('fanout_c_absent', 'fanout_all', 'C', ('nodes', 'observations', 'cleanup')),
             ('c_report_absent_effect_observed', 'chain_unknown', 'C', ('nodes',)),
             ('c_observation_absent', 'chain_all', 'C', ('observations',)),
             ('c_cleanup_absent', 'chain_all', 'C', ('cleanup',)),
             ('b_absent', 'chain_all', 'B', ('nodes', 'observations', 'cleanup')),
             ('all_absent', 'chain_all', 'ALL', ('nodes', 'observations', 'cleanup')),
             ('invalid_present_node', 'chain_all', None, ()),
             ('narrowed_inventory', 'chain_all', None, ()),
             ('invented_c_success', 'chain_all', 'C', ('nodes', 'observations', 'cleanup'))]
    for label, base, target, fields in specs:
        original = next(c for c in old['cases'] if c['label'] == base)
        source = loads(original['delivery']['source_bytes'].encode())
        source['schema'] = 'multitarget-partial-capture-v2'
        for field in fields:
            for t in ('A', 'B', 'C') if target == 'ALL' else (target,):
                del source[field][t]
        mapped = project(source, original['intent'], original['node_trust'])
        if label == 'invalid_present_node': source['nodes']['C']['source_bytes'] += ' '
        elif label == 'narrowed_inventory': source['intent']['targets'] = ['A', 'B']
        elif label == 'invented_c_success': mapped['bounded_pause_count'] = 3
        cases.append({'label': label, 'origin': 'AUTHOR_TRANSFORMATION_OF_HISTORICAL_CAPTURE',
                      'historical_case': base, 'intent': copy.deepcopy(original['intent']),
                      'node_trust': copy.deepcopy(original['node_trust']),
                      'delivery': writer.sign(source, mapped)})
    return {'schema': 'multitarget-partial-fixtures-v2', 'basis_digest': BASIS,
            'historical_input_sha256': digest_bytes(path.read_bytes()),
            'trust_note': 'Explicit author fixture trust, not independently established operator trust.',
            'new_runtime_captures': 0, 'new_model_calls': 0,
            'controller_trust': writer.trust, 'cases': cases}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--replay', type=Path, help='Read saved fixture inputs without generating a new signing key')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    inputs = loads(args.replay.read_bytes()) if args.replay else build()
    result = replay(inputs)
    assert [r['evaluation']['admission'] for r in result] == ['MATCH'] * 9 + ['NO_MATCH'] * 3
    for r in result[2:4]:
        assert r['evaluation']['result']['bounded_pause_count'] == 2
        assert r['evaluation']['result']['intended_target_count'] == 3
    (args.out / 'inputs.json').write_bytes(encoded(inputs))
    (args.out / 'report.json').write_bytes(encoded(result))
    assert replay(loads((args.out / 'inputs.json').read_bytes())) == loads((args.out / 'report.json').read_bytes())
    manifest = {name: digest_bytes((args.out / name).read_bytes()) for name in ('inputs.json', 'report.json')}
    (args.out / 'MANIFEST.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'cases': len(result), 'exact_replay': True, 'new_captures': 0, 'manifest': manifest}))


if __name__ == '__main__':
    main()
