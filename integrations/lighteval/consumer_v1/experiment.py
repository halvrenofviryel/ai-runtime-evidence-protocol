"""Reuse one committed historical run; other cases are authored transformations."""
from __future__ import annotations
import argparse
from copy import deepcopy
import html
import json
from pathlib import Path

from .consumer import canonical, consume, digest, load, local_basis, produce, project, query_for

ROOT = Path(__file__).resolve().parents[3]
HISTORICAL = ROOT / 'integrations/evaleval/experiment'
NAME = 'results_2026-09-24T00-59-40.590371.json'


def historical():
    return {'results.json': (HISTORICAL / 'native/results/sshleifer/tiny-gpt2' / NAME).read_bytes(),
            'details.parquet': (HISTORICAL / 'native/details/sshleifer/tiny-gpt2/2026-09-24T00-59-40.590371/details_hellaswag_0_2026-09-24T00-59-40.590371.parquet').read_bytes(),
            'context.json': (HISTORICAL / 'context/airep-context.json').read_bytes(),
            'conditions.json': canonical({'version': '0.1', 'origin': 'HISTORICAL_SOURCE_REUSE',
                'record_id': 'historical-september-2026', 'results_name': NAME,
                'coverage': {'observed': 2, 'expected': None, 'excluded': []},
                'attempts': None, 'supersedes': None})}


def fixture(name, *, value=0.0, observed=2, expected=None):
    inputs = historical()
    del inputs['details.parquet']
    context, source, cond = (load(inputs[k]) for k in ('context.json', 'results.json', 'conditions.json'))
    source['results']['hellaswag|0']['em'] = source['results']['all']['em'] = value
    source['config_general']['max_samples'] = observed
    source['config_tasks']['hellaswag|0']['effective_num_docs'] = observed
    source['config_tasks']['hellaswag|0']['original_num_docs'] = expected if expected is not None else -1
    source['summary_tasks'] = source['summary_general'] = {}
    context['evaluation']['run_id'] = 'authored-' + name
    context['evaluation']['objective'] = 'Authored transformation; no new LightEval/model execution.'
    context['measurement']['sample_count'] = observed
    context['measurement']['execution_status'] = 'PARTIAL' if expected is not None and observed < expected else 'RAN'
    context['measurement']['observed'] = {'status': 'INCONCLUSIVE', 'summary': 'Authored scalar; no source evaluator verdict.'}
    context['measurement']['limitations'] = ['Authored fixture, not an observed runtime experiment.', 'No evaluator independence established.']
    context['disclosure']['deviations'] = [{'type': 'authored transformation', 'description': 'Controlled data mutation; not a new model run.', 'impact': 'material'}]
    context['scope'] = {'covers': ['controlled mapping fixture'], 'does_not_cover': ['real model execution', 'capability or safety']}
    cond.update(origin='AUTHORED_FIXTURE', record_id=name,
                coverage={'observed': observed, 'expected': expected, 'excluded': []})
    inputs.update({'context.json': canonical(context), 'results.json': canonical(source), 'conditions.json': canonical(cond)})
    return inputs


def replace(inputs, name, fn):
    value = load(inputs[name]); fn(value); inputs[name] = canonical(value)


def not_run():
    inputs = fixture('not-run', observed=0, expected=100)
    del inputs['results.json']
    def context(ctx):
        ctx['measurement']['execution_status'] = 'NOT_RUN'
        ctx['measurement']['observed'] = {'status': 'NOT_MEASURED', 'summary': 'Authored NOT_RUN declaration.'}
        ctx['evaluation']['tasks'] = [{'task_id': 'hellaswag|0', 'dataset_ref': 'hf://datasets/Rowan/hellaswag',
            'dataset_revision': '218ec52e09a7e7462a5400043bb9a69a41d06b76', 'split': 'validation'}]
    replace(inputs, 'context.json', context)
    return inputs


def retry():
    inputs = fixture('retry', value=0.81, observed=80, expected=100)
    def context(ctx):
        ctx['measurement']['attempts'] = 2
        ctx['disclosure']['retries'] = [{'attempt': 2, 'reason': 'first attempt errored; controlled declaration', 'changed_configuration': False}]
    replace(inputs, 'context.json', context)
    def conditions(cond):
        cond['attempts'] = [
            {'id': 'attempt-1', 'state': 'ERROR', 'selected': False, 'reason': 'authored timeout', 'results_digest': None},
            {'id': 'attempt-2', 'state': 'RAN', 'selected': True, 'reason': 'selected authored result', 'results_digest': digest(inputs['results.json'])}]
    replace(inputs, 'conditions.json', conditions)
    return inputs


def amended():
    inputs = fixture('amended-v2', value=0.7)
    prior = {'record_id': 'amended-v1', 'qualification': 'preliminary authored result', 'numeric_token': '0.9'}
    inputs['previous.json'] = canonical(prior)
    replace(inputs, 'conditions.json', lambda c: c.update(supersedes={'record_id': prior['record_id'], 'sha256': digest(inputs['previous.json'])}))
    return inputs


def cases(basis):
    definitions = [
        ('historical', historical(), False, None), ('profile-only', historical(), True, None),
        ('not-run', not_run(), False, '>= 0.8'),
        ('partial-80-of-100', fixture('partial', value=0.9, observed=80, expected=100), False, '>= 0.8'),
        ('retry-first-error', retry(), False, '>= 0.8'),
        ('rounding', fixture('rounding', value=0.79996), False, '>= 0.8'),
        ('amended', amended(), False, '>= 0.8')]
    output = {}
    for name, inputs, profile_only, threshold in definitions:
        package = produce(inputs, basis, profile_only=profile_only)
        query = query_for(inputs, basis, threshold=threshold)
        output[name] = (inputs, package, query, basis)
    old = fixture('amended-v1', value=0.9)
    old_package, old_query = produce(old, basis), query_for(old, basis, threshold='>= 0.8')
    old_query['selection']['record_id'] = 'amended-v2'
    output['stale'] = (old, old_package, old_query, basis)
    for field in ('model_id', 'dataset_revision', 'run_id', 'metric'):
        inputs, package, query, _ = deepcopy(output['historical'])
        query['selection'][field] = 'wrong-selection'
        output['wrong-' + field] = (inputs, package, query, basis)
    inputs, package, query, _ = deepcopy(output['historical'])
    del inputs['results.json']
    output['missing-source'] = (inputs, package, query, basis)
    inputs, package, query, _ = output['historical']
    output['missing-basis'] = (inputs, package, query, None)
    return output


def write_experiment(out):
    out.mkdir(parents=True, exist_ok=False)
    basis = local_basis()
    summary, rows = {}, []
    for name, (inputs, package, query, accepted_basis) in cases(basis).items():
        directory = out / name
        (directory / 'inputs').mkdir(parents=True, exist_ok=True)
        for filename, raw in inputs.items():
            (directory / 'inputs' / filename).write_bytes(raw)
        report = consume(canonical(package), inputs, canonical(query), accepted_basis)
        for filename, obj in [('package', package), ('query', query), ('report', report)]:
            (directory / (filename + '.json')).write_bytes(canonical(obj) + b'\n')
        (directory / 'receiver-basis.json').write_bytes(canonical({'available': accepted_basis is not None}) + b'\n')
        summary[name] = {'status': report['status'], 'report_sha256': digest(canonical(report) + b'\n')}
        escaped = html.escape(json.dumps(report, indent=2))
        source = report['source'] or {}
        preserved = report['preserved'] or {}
        conditions = preserved.get('author_conditions', {})
        measurement = preserved.get('author_context', {}).get('measurement', {})
        assessment = report['derived_assessment'] or {}
        fields = {
            'Preservation decision': report['status'], 'Reason': report['reason'],
            'Source scalar (exact token)': source.get('numeric_token'),
            'Source criterion / verdict': [source.get('criterion'), source.get('verdict')],
            'Origin of additional conditions': conditions.get('origin'),
            'Declared execution / observation': [measurement.get('execution_status'), measurement.get('observed', {}).get('status')],
            'Declared observed / expected population': conditions.get('coverage'),
            'Declared attempt history': conditions.get('attempts'),
            'Superseded record': conditions.get('supersedes'),
            'Receiver post-hoc criterion / scalar decision': [assessment.get('criterion'), assessment.get('status')],
            'Rounded display (not decision input)': assessment.get('display_value'),
            'Typed checks': report['checks'], 'Disclosed losses': report.get('losses', [])}
        fields_html = ''.join('<dt>' + html.escape(label) + '</dt><dd>' + html.escape(json.dumps(value, ensure_ascii=False)) + '</dd>' for label, value in fields.items())
        rows.append(f'<article id="{name}"><h2>{name}: {report["status"]}</h2><dl>{fields_html}</dl><details><summary>Full bound report: {name}</summary><pre>{escaped}</pre></details></article>')
    (out / 'SUMMARY.json').write_bytes(canonical(summary) + b'\n')
    (out / 'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>LightEval claim preservation review</title>'
        '<style>body{max-width:1050px;margin:40px auto;font:17px/1.55 system-ui;padding:0 24px;color:#172437}article{border-top:1px solid #ccd3dc;padding:16px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px}summary{cursor:pointer}dl{display:grid;grid-template-columns:40% 60%;font-size:14px}dt,dd{margin:0;padding:7px;border-bottom:1px solid #eee;overflow-wrap:anywhere}dt{font-weight:600}@media(max-width:700px){dl{display:block}dd{padding-left:16px}}</style>'
        '<h1>LightEval claim preservation review</h1><p>One historical two-sample run reused; other cases are authored transformations and receiver-side negative checks. No new model inference.</p>'
        '<p>PRESERVED concerns the bounded mapping. It does not mean the model passed, the benchmark is complete, or the evidence is authenticated. QUALIFIED_LOSS remains loss.</p>' + ''.join(rows) + '</html>')
    return summary


def replay(directory):
    from .consumer import read_inputs
    summary = load((directory / 'SUMMARY.json').read_bytes())
    for name, entry in summary.items():
        path = directory / name
        basis = local_basis() if load((path / 'receiver-basis.json').read_bytes())['available'] else None
        report = consume((path / 'package.json').read_bytes(), read_inputs(path / 'inputs'), (path / 'query.json').read_bytes(), basis)
        assert canonical(report) + b'\n' == (path / 'report.json').read_bytes(), name + ' replay differs'
        assert digest((path / 'report.json').read_bytes()) == entry['report_sha256'], name + ' digest differs'
    return {'replayed': len(summary), 'exact_report_matches': len(summary), 'fresh_model_runs': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['generate', 'replay'])
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(write_experiment(args.out) if args.action == 'generate' else replay(args.out), indent=2))


if __name__ == '__main__':
    main()
