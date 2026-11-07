"""Versioned, non-normative LightEval claim preservation experiment.

The receiver supplies its own query and accepted local basis. No network fetches,
key discovery, native assurance artifacts or inference are performed.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import math
from pathlib import Path
import re

from integrations.lighteval import export_embedded_evaluation as exporter

HERE = Path(__file__).resolve().parent
MAX_BYTES = 2_000_000
SOURCE_SHA = '1b3464e5237d77d648b1960b7a879f4674d59a3c04d97279135a1b0fa59e103b'
DETAILS_SHA = 'c4f6ea15515ff7f0d1cfc9a6c23e1079dfc5b07fa508dab717d12777f315b298'
ALLOWED_INPUTS = {'results.json', 'context.json', 'conditions.json', 'details.parquet', 'previous.json'}


class Refused(ValueError):
    pass


class Unavailable(Refused):
    pass


def need(test, message):
    if not test:
        raise Refused(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pairs(items):
    obj = {}
    for key, value in items:
        need(key not in obj, 'duplicate JSON member')
        obj[key] = value
    return obj


def load(raw):
    need(isinstance(raw, bytes) and len(raw) <= MAX_BYTES, 'input byte limit')
    obj = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(Refused('non-finite number')))
    def check(value, depth=0):
        need(depth <= 40, 'JSON depth limit')
        if isinstance(value, float):
            need(math.isfinite(value), 'non-finite number')
        if isinstance(value, dict):
            for item in value.values():
                check(item, depth + 1)
        if isinstance(value, list):
            for item in value:
                check(item, depth + 1)
    check(obj)
    return obj


def keys(obj, names, label):
    need(isinstance(obj, dict) and set(obj) == set(names.split()), label + ' fields')


def count(value):
    return type(value) is int and 0 <= value <= 1_000_000_000


def local_basis():
    return exporter.Basis.from_dir(exporter.DEFAULT_PROFILE_DIR)


def basis_ids(basis):
    return {'contract': digest((HERE / 'CONTRACT.json').read_bytes()),
            'mapping': digest(Path(__file__).read_bytes()),
            'exporter': digest(Path(exporter.__file__).read_bytes()),
            'schema': basis.schema_digest, 'registry': basis.registry_digest}


def source_facts(inputs, context, conditions):
    """Selected source configuration, not proof of what weights were executed."""
    task, metric = context['measurement']['criterion']['task'], context['measurement']['criterion']['metric']
    base = {'task': task, 'metric': metric, 'run_id': context['evaluation']['run_id'],
            'record_id': conditions['record_id']}
    if 'results.json' not in inputs:
        need(context['measurement']['execution_status'] == 'NOT_RUN', 'results missing for executed run')
        tasks = context['evaluation']['tasks']
        need(len(tasks) == 1 and tasks[0]['task_id'] == task, 'NOT_RUN requires one declared task')
        cfg = tasks[0]
        base.update(model_id=context['target']['model_id'], model_revision=context['target']['model_revision'],
                    dataset_id=cfg['dataset_ref'].removeprefix('hf://datasets/'),
                    dataset_revision=cfg['dataset_revision'], splits=cfg['split'].split(','))
        return base, None, 'DECLARED_NOT_RUN'
    source = load(inputs['results.json'])
    keys(source, 'config_general results versions config_tasks summary_tasks summary_general', 'supported source root')
    general, cfg = source['config_general'], source['config_tasks'][task]
    need(general['lighteval_sha'] == load((HERE / 'CONTRACT.json').read_bytes())['source_revision'],
         'unsupported LightEval source revision')
    model = general['model_config']
    need(general['model_name'] == model['model_name'], 'conflicting source model names')
    need(context['target']['model_id'] == model['model_name'] and
         context['target']['model_revision'] == model['revision'], 'context overrides source model')
    need(context['evaluation']['framework']['revision'] == general['lighteval_sha'], 'context overrides framework')
    need(context['evaluation']['framework']['name'] == 'lighteval' and
         context['evaluation']['framework']['version'] == '0.13.1.dev0', 'unsupported declared framework')
    effective = cfg.get('effective_num_docs')
    if type(effective) is int and effective >= 0:
        need(effective == conditions['coverage']['observed'], 'native effective count mismatch')
    base.update(model_id=model['model_name'], model_revision=model['revision'], dataset_id=cfg['hf_repo'],
                dataset_revision=cfg['hf_revision'], splits=cfg['evaluation_splits'])
    need(type(source['results'][task][metric]) in (int, float), 'selected metric must be numeric')
    # Re-read the exact JSON number token. Binary64 profile projection is a separate representation.
    exact = json.loads(inputs['results.json'], parse_float=str, parse_int=str)
    token = exact['results'][task][metric]
    need(len(token) <= 128 and abs(Decimal(token).adjusted()) <= 100, 'numeric token limit')
    for declared_task in context['evaluation'].get('tasks', []):
        need(declared_task['task_id'] == task and declared_task['dataset_revision'] == cfg['hf_revision'] and
             declared_task['dataset_ref'] == 'hf://datasets/' + cfg['hf_repo'] and
             declared_task['split'] == ','.join(cfg['evaluation_splits']), 'context overrides source dataset')
    return base, token, 'SOURCE_REPORTED_CONFIGURATION_AND_METRIC'


def project(inputs, basis):
    need(set(inputs) <= ALLOWED_INPUTS, 'unsupported input')
    if not {'context.json', 'conditions.json'} <= set(inputs):
        raise Unavailable('context or conditions unavailable')
    for raw in inputs.values():
        need(isinstance(raw, bytes) and len(raw) <= MAX_BYTES, 'input byte limit')
    context, cond = load(inputs['context.json']), load(inputs['conditions.json'])
    keys(cond, 'version origin record_id results_name coverage attempts supersedes', 'conditions')
    need(cond['version'] == '0.1' and cond['origin'] in ('HISTORICAL_SOURCE_REUSE', 'AUTHORED_FIXTURE'), 'conditions version/origin')
    need(isinstance(cond['record_id'], str) and 0 < len(cond['record_id']) <= 200, 'record id')
    need(isinstance(cond['results_name'], str) and exporter.RESULTS_NAME.fullmatch(cond['results_name']), 'results basename')
    need('threshold' not in context['measurement']['criterion'],
         'v1 has no accepted predeclared-criterion evidence; use receiver post-hoc policy')
    selection, token, attribution = source_facts(inputs, context, cond)
    coverage = cond['coverage']
    keys(coverage, 'observed expected excluded', 'coverage')
    need(count(coverage['observed']) and (coverage['expected'] is None or
         count(coverage['expected']) and coverage['expected'] >= coverage['observed']), 'coverage denominator')
    need(context['measurement']['sample_count'] == coverage['observed'], 'context sample count mismatch')
    need(isinstance(coverage['excluded'], list), 'exclusions list')
    ids = []
    for item in coverage['excluded']:
        keys(item, 'id reason', 'exclusion')
        need(isinstance(item['id'], str) and item['id'] and isinstance(item['reason'], str) and item['reason'], 'exclusion reason')
        ids.append(item['id'])
    need(len(ids) == len(set(ids)), 'duplicate exclusion')
    if coverage['expected'] is not None:
        need(len(ids) <= coverage['expected'] - coverage['observed'], 'exclusions exceed unobserved population')
    if context['measurement']['execution_status'] == 'NOT_RUN':
        need(token is None and coverage['observed'] == 0, 'NOT_RUN with observations')
    details_count = None
    if 'details.parquet' in inputs:
        import pyarrow.parquet as pq
        # Metadata only; no deserialization of application objects or remote lookups.
        details_count = pq.read_metadata(io.BytesIO(inputs['details.parquet'])).num_rows
        need(details_count == coverage['observed'], 'Parquet row count mismatch')
    if cond['origin'] == 'HISTORICAL_SOURCE_REUSE':
        need(digest(inputs.get('results.json', b'')) == SOURCE_SHA and
             digest(inputs.get('details.parquet', b'')) == DETAILS_SHA, 'historical source bytes mismatch')
        need(coverage['expected'] is None and coverage['observed'] == 2, 'historical coverage not established')
    attempts = cond['attempts']
    if attempts is None:
        need('attempts' not in context['measurement'] and not context['disclosure']['retries'], 'attempt inventory missing')
    else:
        need(isinstance(attempts, list) and attempts, 'attempt inventory empty')
        seen, selected = set(), []
        for attempt in attempts:
            keys(attempt, 'id state selected reason results_digest', 'attempt')
            need(isinstance(attempt['id'], str) and attempt['id'] and attempt['id'] not in seen, 'attempt id')
            seen.add(attempt['id'])
            need(attempt['state'] in ('RAN', 'ERROR', 'NOT_RUN') and type(attempt['selected']) is bool, 'attempt state')
            need(isinstance(attempt['reason'], str) and attempt['reason'], 'attempt reason')
            if attempt['selected']:
                selected.append(attempt)
            else:
                need(attempt['results_digest'] is None, 'v1 supports one supplied attempt result')
        need(len(selected) == 1 and context['measurement']['attempts'] == len(attempts), 'attempt coverage mismatch')
        need(selected[0]['results_digest'] == (digest(inputs['results.json']) if token is not None else None), 'selected attempt source mismatch')
        need(selected[0]['state'] == ('NOT_RUN' if token is None else 'RAN'), 'selected attempt state mismatch')
        need(len(context['disclosure']['retries']) == len(attempts) - 1, 'retry disclosure count mismatch')
    previous = None
    if cond['supersedes'] is not None:
        keys(cond['supersedes'], 'record_id sha256', 'supersedes')
        if 'previous.json' not in inputs:
            raise Unavailable('prior record unavailable')
        previous = load(inputs['previous.json'])
        need(previous['record_id'] == cond['supersedes']['record_id'] and
             digest(inputs['previous.json']) == cond['supersedes']['sha256'] and
             previous['record_id'] != cond['record_id'], 'prior record binding mismatch')
    else:
        need('previous.json' not in inputs, 'unlinked prior record')
    results = exporter.NativeFile(cond['results_name'], 'aggregate-result', inputs['results.json']) if 'results.json' in inputs else None
    extra = [exporter.NativeFile(name, 'sample-details' if name == 'details.parquet' else 'other', inputs[name])
             for name in sorted(inputs) if name != 'results.json']
    profile, _, validation = exporter.export(inputs['context.json'], results, extra, basis)
    need(profile is not None and validation['schema_valid'], 'profile validation failed')
    sidecar = {'version': '0.1', 'selection': selection,
               'source': {'attribution': attribution, 'numeric_token': token,
                          'criterion': 'NOT_REPORTED', 'verdict': 'NOT_REPORTED',
                          'run_id_origin': 'AUTHOR_DECLARED', 'details_rows': details_count},
               'author_context': context, 'author_conditions': cond, 'prior_record': previous}
    return profile, sidecar


def produce(inputs, basis, *, profile_only=False):
    profile, sidecar = project(inputs, basis)
    package = {'basis': basis_ids(basis), 'inputs': {k: digest(v) for k, v in sorted(inputs.items())},
               'profile': profile, 'sidecar': None if profile_only else sidecar,
               'disclosed_losses': load((HERE / 'CONTRACT.json').read_bytes())['profile_only_losses'] if profile_only else []}
    package['output_digest'] = digest(canonical({'profile': package['profile'], 'sidecar': package['sidecar']}))
    return package


def query_for(inputs, basis, *, threshold=None):
    """Author/demo convenience only. Real receiver must select and pin these independently."""
    _, sidecar = project(inputs, basis)
    return {'selection': sidecar['selection'], 'input_digests': {k: digest(v) for k, v in sorted(inputs.items())},
            'policy': {'threshold': threshold, 'chronology': 'POST_HOC', 'display_decimals': 2}}


def consume(package_raw, inputs, query_raw, basis):
    report = {'contract': 'airep.lighteval.claim-consumer/0.1.0', 'status': 'REJECTED',
              'checks': {'basis': 'NOT_EVALUATED', 'digest_binding': 'NOT_EVALUATED',
                         'schema_validation': 'NOT_EVALUATED', 'mapping_compare': 'NOT_EVALUATED'},
              'source': None, 'preserved': None, 'derived_assessment': None,
              'non_claims': load((HERE / 'CONTRACT.json').read_bytes())['non_claims']}
    try:
        package, query = load(package_raw), load(query_raw)
        keys(package, 'basis inputs profile sidecar disclosed_losses output_digest', 'package')
        keys(query, 'selection input_digests policy', 'query')
        if basis is None:
            raise Unavailable('receiver accepted profile basis unavailable')
        need(package['basis'] == basis_ids(basis), 'basis not accepted')
        report['checks']['basis'] = 'MATCH'
        need(isinstance(query['input_digests'], dict) and set(query['input_digests']) <= ALLOWED_INPUTS, 'query input inventory')
        if set(query['input_digests']) - set(inputs):
            raise Unavailable('receiver-required source inputs unavailable')
        actual = {k: digest(v) for k, v in sorted(inputs.items())}
        need(actual == package['inputs'] == query['input_digests'], 'input digest/inventory mismatch')
        need(digest(canonical({'profile': package['profile'], 'sidecar': package['sidecar']})) == package['output_digest'], 'output digest mismatch')
        report['checks']['digest_binding'] = 'MATCH_SUPPLIED_BYTES'
        need(not basis.errors(package['profile']), 'profile schema mismatch')
        report['checks']['schema_validation'] = 'VALID'
        profile, expected = project(inputs, basis)
        need(package['profile'] == profile, 'profile mapping mismatch')
        need(package['sidecar'] is None or package['sidecar'] == expected, 'sidecar mapping mismatch')
        losses = load((HERE / 'CONTRACT.json').read_bytes())['profile_only_losses'] if package['sidecar'] is None else []
        need(package['disclosed_losses'] == losses, 'loss disclosure mismatch')
        report['checks']['mapping_compare'] = 'MATCH'
        keys(query['selection'], ' '.join(expected['selection']), 'receiver selection')
        need({k: v for k, v in query['selection'].items() if k != 'record_id'} ==
             {k: v for k, v in expected['selection'].items() if k != 'record_id'}, 'receiver selection mismatch')
        report['source'] = expected['source']
        report['preserved'] = expected if package['sidecar'] is not None else None
        if query['selection']['record_id'] != expected['selection']['record_id']:
            report.update(status='STALE', reason='record does not satisfy receiver current-record selection')
            return report
        policy = query['policy']
        keys(policy, 'threshold chronology display_decimals', 'receiver policy')
        need(policy['chronology'] == 'POST_HOC' and type(policy['display_decimals']) is int and
             0 <= policy['display_decimals'] <= 6, 'unsupported policy')
        threshold_match = None
        if policy['threshold'] is not None:
            need(isinstance(policy['threshold'], str) and len(policy['threshold']) <= 128, 'policy threshold')
            threshold_match = re.fullmatch(r'(<=|>=|==|!=|<|>) (-?\d+(?:\.\d+)?)', policy['threshold'])
            need(threshold_match is not None, 'policy threshold grammar')
        assessment = {'attribution': 'RECEIVER_POST_HOC', 'criterion': policy['threshold'],
                      'status': 'NOT_EVALUATED', 'display_value': None,
                      'meaning': 'selected scalar comparison only; not source verdict, coverage or model acceptance'}
        if losses:
            report.update(status='QUALIFIED_LOSS', reason='loss disclosed; full preservation not established', losses=losses)
        else:
            report.update(status='PRESERVED', reason='selected bytes and declared qualifications preserved under this contract', losses=[])
            token = expected['source']['numeric_token']
            if token is not None:
                value = Decimal(token)
                # Presentation is never the input to a decision.
                assessment['display_value'] = format(value, f'.{policy["display_decimals"]}f')
                if threshold_match is not None:
                    op, bound = threshold_match[1], Decimal(threshold_match[2])
                    passed = {'<=': value <= bound, '>=': value >= bound, '<': value < bound,
                              '>': value > bound, '==': value == bound, '!=': value != bound}[op]
                    assessment['status'] = 'SATISFIED' if passed else 'NOT_SATISFIED'
        report['derived_assessment'] = assessment
    except Unavailable as exc:
        report.update(status='UNESTABLISHED', reason=str(exc))
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError, InvalidOperation) as exc:
        report.update(status='REJECTED', reason=str(exc))
        report['source'] = report['preserved'] = report['derived_assessment'] = None
    return report


def read_inputs(directory):
    result = {}
    for path in Path(directory).iterdir():
        need(path.name in ALLOWED_INPUTS and path.is_file() and not path.is_symlink(), 'unsupported input file')
        need(path.stat().st_size <= MAX_BYTES, 'input byte limit')
        result[path.name] = path.read_bytes()
    return result


def read_bounded(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= MAX_BYTES, 'bounded regular input required')
    with path.open('rb') as handle:
        raw = handle.read(MAX_BYTES + 1)
    need(len(raw) <= MAX_BYTES, 'input byte limit')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--query', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    report = consume(read_bounded(args.package), read_inputs(args.inputs), read_bounded(args.query), local_basis())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(canonical(report) + b'\n')
    return 0 if report['status'] in ('PRESERVED', 'QUALIFIED_LOSS') else 2


if __name__ == '__main__':
    raise SystemExit(main())
