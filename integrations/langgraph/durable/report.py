"""Capture durable runs or reproduce their signed, offline delivery views."""
import argparse
import copy
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess

from integrations.langgraph.run import ROOT, encoded, utc
from integrations.langgraph.temporal.runtime_source import query_for
from tools.airep_v02.basis import verifier
from tools.airep_v02.json_input import loads
from .capture import capture
from .consumer import evaluate
from .source import DurableReports, DurablePolicy


def make_inputs(root):
    factory = DurableReports()
    captures = {mode: capture(root / mode, mode) for mode in ('repeat', 'idempotent')}
    rows = {mode: [factory.delivery(encoded(s), arrival=i + 1) for i, s in enumerate(c['sources'])]
            for mode, c in captures.items()}
    cases = []
    def case(label, deliveries, query, effect, execution='MISSING', *, origin='measured capture / offline replay'):
        cases.append({'label': label, 'deliveries': deliveries, 'query': query,
                      'expected': {'receipt': 'MISSING', 'execution': execution, 'effect': effect}, 'origin': origin})
    a, quiet, b, progress, quiet2 = rows['repeat']
    query = query_for(progress)
    case('T05 paused checkpoint / bounded quiet window', [a, quiet], query_for(quiet), 'QUIESCENT_REPORTED', 'PAUSED_REPORTED')
    case('T07 fresh process / continued execution', [b, progress], query, 'CONTINUED_REPORTED', 'CONTINUED_REPORTED')
    late = copy.deepcopy([b, progress, a, quiet]); late[2]['arrival_time'] = 100; late[3]['arrival_time'] = 101
    case('T07 delayed old pause / current result preserved', late, query, 'CONTINUED_REPORTED', 'CONTINUED_REPORTED')
    case('T07 reverse delivery list / same result', list(reversed(late)), query, 'CONTINUED_REPORTED', 'CONTINUED_REPORTED')
    probe = query_for(quiet); probe['identity']['runtime_epoch'] = query['identity']['runtime_epoch']
    case('T04 epoch-only identity negative / same window', [a, quiet], probe, 'MISSING', origin='authored query probe against measured source')
    probe = query_for(quiet); probe['identity']['run_id'] = 'another-run'
    case('T04 reused thread does not establish a new run', [a, quiet], probe, 'MISSING', origin='authored query probe against measured source')
    case('T04 reused event IDs / both epochs retained', rows['repeat'], query, 'CONTINUED_REPORTED', 'CONTINUED_REPORTED')
    case('T07 later quiet window / no permanent stop claim', rows['repeat'], query_for(quiet2), 'QUIESCENT_REPORTED', 'CONTINUED_REPORTED')
    c, d, e, f, g = rows['idempotent']
    case('T06 idempotent effect / resume still observed', [c, d, e, f, g], query_for(f), 'CONTINUED_REPORTED', 'CONTINUED_REPORTED')
    conflicting = copy.deepcopy(captures['repeat']['sources'][3])
    conflicting['event_id'] = 'fixture-conflict'
    conflicting['data']['after']['rows_hex'] = conflicting['data']['before']['rows_hex']
    other = factory.delivery(encoded(conflicting), arrival=200)
    case('T08 incompatible same-window signed reports', [b, progress, other], query, 'INDETERMINATE', 'CONTINUED_REPORTED', origin='authored signed negative fixture')
    unordered = copy.deepcopy(conflicting); unordered['clock_id'] = 'unaccepted-worker-clock'; unordered['event_id'] = 'fixture-unordered'
    other = factory.delivery(encoded(unordered), arrival=201)
    case('T08 unestablished cross-clock order', [b, progress, other], query, 'INDETERMINATE', 'INDETERMINATE', origin='authored signed negative fixture')
    cases[-1]['expected']['receipt'] = 'INDETERMINATE'
    overlap = copy.deepcopy(conflicting); overlap['event_id'] = 'fixture-overlap'
    overlap['data']['before']['start'] -= 1
    other = factory.delivery(encoded(overlap), arrival=202)
    case('T08 partly overlapping windows / reconciliation required', [b, progress, other], query,
         'INDETERMINATE', 'CONTINUED_REPORTED', origin='authored signed negative fixture; overlap is not automatically a contradiction')
    for item in cases:
        item['deliveries'] = [dict(row, event_bytes=row['event_bytes'].decode()) for row in item['deliveries']]
    summaries = {}
    for mode, cap in captures.items():
        workers = cap['workers']
        final = loads(bytes.fromhex(cap['sources'][3]['data']['after']['rows_hex']))
        attempts = [e for w in workers.values() for e in w['events'] if e['kind'] == 'effect_attempt']
        summaries[mode] = {'thread_id': cap['request']['thread_id'], 'run_id': cap['request']['run_id'],
            'processes': cap['lifecycle'], 'paused_checkpoint_hash': cap['paused_checkpoint_hash'],
            'paused_checkpoint_id': workers['pause']['terminal']['checkpoint_id'],
            'loaded_checkpoint_id': workers['resume']['loaded']['checkpoint_id'],
            'runtime_epochs': [workers[p]['runtime_epoch'] for p in ('pause', 'resume')],
            'node_invocations': sum(e['kind'] == 'node_entered' for w in workers.values() for e in w['events']),
            'effect_attempts': len(attempts), 'inserted_effects': len(final),
            'before_interrupt_effects': sum(row[2] == 'before_interrupt' for row in final),
            'after_resume_effects': sum(row[2] == 'after_resume' for row in final)}
    return {'format': 'durable-temporal-inputs-v1', 'bindings': factory.ops.bindings_doc,
            'revocation': factory.ops.revocation_doc, 'sources': {k: v.decode() for k, v in factory.sources.items()},
            'cases': cases, 'capture_summary': summaries}


def replay(inputs):
    if inputs['format'] != 'durable-temporal-inputs-v1':
        raise ValueError('unsupported replay format')
    ops = verifier.OperatorInputs(); ops.bindings_doc = inputs['bindings']; ops.revocation_doc = inputs['revocation']
    sources = {k: v.encode() for k, v in inputs['sources'].items()}
    views = []
    for case in inputs['cases']:
        deliveries = [dict(row, event_bytes=row['event_bytes'].encode()) for row in case['deliveries']]
        result = evaluate(deliveries, case['query'], sources, ops)
        observed = {k: v['status'] for k, v in result['stages'].items()}
        if observed != case['expected']:
            raise AssertionError((case['label'], case['expected'], observed))
        views.append({'label': case['label'], 'origin': case['origin'], 'expected': case['expected'], 'result': result,
            'scope_note': 'Local experimental durable checkpoint capture. ' + case['origin'] + '. Signed reports do not establish independent enforcement or production SDK support.',
            'clock_note': 'Observation ticks belong to one continuously running harness. Worker-local clocks are retained but never compared across epochs. Arrival ticks are an offline replay schedule.'})
    return views


def write_report(out, replay_path=None):
    out.mkdir(parents=True, exist_ok=False)
    if replay_path is None:
        inputs = make_inputs(out / 'capture')
    else:
        raw = replay_path.read_bytes()
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('replay package exceeds 8 MiB')
        inputs = loads(raw)
    (out / 'inputs.json').write_bytes(encoded(inputs))
    views = replay(inputs)
    record = {'created_utc': utc(), 'fresh_capture': replay_path is None, 'basis_digest': DurablePolicy.basis,
              'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'worktree_status': subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True),
              'python': platform.python_version(), 'dependencies': {name: importlib.metadata.version(name)
                  for name in ('langgraph', 'langgraph-checkpoint', 'langgraph-checkpoint-sqlite')},
              'capture_summary': inputs['capture_summary'], 'views': views}
    (out / 'report.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    payload = json.dumps(views).replace('<', '\\u003c').replace('&', '\\u0026')
    (out / 'index.html').write_text(Path(__file__).with_name('view.html').read_text().replace('__REPORT_DATA__', payload))
    manifest = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file()}
    (out / 'SHA256SUMS.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'views': len(views), 'all_expected_stages_match': True, 'fresh_capture': replay_path is None,
                      'capture_summary': inputs['capture_summary']}))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--replay', type=Path)
    args = parser.parse_args(); write_report(args.out, args.replay)


if __name__ == '__main__':
    main()
