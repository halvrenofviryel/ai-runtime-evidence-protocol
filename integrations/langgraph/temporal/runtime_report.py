"""Capture real local runs, then replay explicit offline delivery schedules."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import time
import uuid

from tools.airep_v02.basis import verifier
from tools.airep_v02.json_input import loads
from integrations.langgraph.run import encoded, runtime_basis, utc, ROOT
from .capture import capture
from .core import evaluate
from .runtime_source import MAPPED_KINDS, RuntimeReports, RuntimeSourcePolicy, query_for


def make_inputs(directory):
    factory = RuntimeReports()
    clock_id, origin = 'local-session-' + str(uuid.uuid4()), time.monotonic_ns()
    traces, rows = {}, {}
    for name, mode in (('run-A', 'pause'), ('run-B', 'ignore'), ('run-C', 'unobserved')):
        events = capture(directory / name, mode, clock_id=clock_id, origin=origin)
        traces[name] = events
        rows[name] = [factory.delivery(encoded(e), arrival=i + 1)
                      for i, e in enumerate(events) if e['kind'] in MAPPED_KINDS]
    def event(row):
        return loads(row['event_bytes'])
    a, b, c = (rows[k] for k in ('run-A', 'run-B', 'run-C'))
    a_effect = next(row for row in a if event(row)['kind'] == 'effect')
    old, current, c2 = [row for row in b if event(row)['kind'] == 'effect']
    old['arrival_time'] = 100
    a_effect['arrival_time'] = 110
    q = query_for(current)
    c2_q = query_for(c2)
    c2_stages = [row for row in b if event(row)['identity']['control_id'] == 'pause-2' and event(row)['kind'] != 'effect']
    # Hold the old observation window/clock constant in identity-only negatives.
    # Otherwise a broken ID matcher could pass simply because windows differ.
    stale_control_q = copy.deepcopy(q)
    stale_control_q['identity'] = copy.deepcopy(c2_q['identity'])
    stale_control_q['cutoff'] = c2_q['cutoff']
    stale_run_q = query_for(a_effect)
    stale_run_q['identity'] = copy.deepcopy(q['identity'])
    stale_run_q['cutoff'] = q['cutoff']
    c_query = query_for(c[-1])
    # No source observation exists for run C. This is an explicit consumer
    # request after the captured native interrupt, not an invented source event.
    c_query['window'] = [c_query['cutoff'], c_query['cutoff'] + 1]
    c_query['cutoff'] += 1
    wrong_window = copy.deepcopy(q)
    wrong_window['window'][0] += 1
    duplicate = copy.deepcopy(current); duplicate['arrival_time'] = 120
    damaged = copy.deepcopy(current)
    damaged['artifact']['integrity']['signature']['value'] = '0' * 128
    cases = [
        ('T01 before delayed observation', [current], q, 'CONTINUED_REPORTED'),
        ('T01 after delayed observation', [current, old], q, 'CONTINUED_REPORTED'),
        ('T01 reversed arrival list', [old, current], q, 'CONTINUED_REPORTED'),
        ('T01 inspect earlier sampled window', [current, old], query_for(old), 'QUIESCENT_REPORTED'),
        ('T02 new control / old observation', c2_stages + [current], stale_control_q, 'MISSING'),
        ('T02 new control / matching observation', c2_stages + [current, c2], c2_q, 'CONTINUED_REPORTED'),
        ('T03 selected run B / only late run A', [a_effect], stale_run_q, 'MISSING'),
        ('T03 selected run B / late run A', [current, a_effect], q, 'CONTINUED_REPORTED'),
        ('T03 inspect historical run A', [current, a_effect], query_for(a_effect), 'QUIESCENT_REPORTED'),
        ('T09 repeated delivery', [current, duplicate], q, 'CONTINUED_REPORTED'),
        ('T10 corrupted signature', [damaged], q, 'INDETERMINATE'),
        ('T11 receiver and pause / no observer', c, c_query, 'MISSING'),
        ('T11 wrong sampled window', [current], wrong_window, 'MISSING'),
        ('Positive native pause / matching samples', a, query_for(a_effect), 'QUIESCENT_REPORTED'),
    ]
    return {'format': 'captured-temporal-inputs-v1',
            'transport': 'Offline deterministic delivery scheduling; arrival ticks are not measured network latency.',
            'cases': [{'label': label, 'query': query, 'expected_effect': expected,
                       'deliveries': [dict(row, event_bytes=row['event_bytes'].decode()) for row in deliveries]}
                      for label, deliveries, query, expected in cases],
            'sources': {k: v.decode() for k, v in factory.sources.items()},
            'bindings': factory.ops.bindings_doc, 'revocation': factory.ops.revocation_doc,
            'capture_summary': {name: {'run_id': events[0]['identity']['run_id'],
                'event_count': len(events), 'cleanup': events[-1]} for name, events in traces.items()}}


def replay(inputs):
    if inputs['format'] != 'captured-temporal-inputs-v1':
        raise ValueError('unsupported replay format')
    ops = verifier.OperatorInputs()
    ops.bindings_doc, ops.revocation_doc = inputs['bindings'], inputs['revocation']
    sources = {k: v.encode() for k, v in inputs['sources'].items()}
    views = []
    for case in inputs['cases']:
        deliveries = [dict(row, event_bytes=row['event_bytes'].encode()) for row in case['deliveries']]
        result = evaluate(deliveries, case['query'], sources, ops, source_policy=RuntimeSourcePolicy())
        observed = result['stages']['effect']['status']
        if observed != case['expected_effect']:
            raise AssertionError((case['label'], case['expected_effect'], observed))
        views.append({'label': case['label'], 'expected_effect': case['expected_effect'], 'result': result,
            'scope_note': 'Real local LangGraph capture + offline delivery replay. Signed Decision reports bind the mapping; they do not establish independent enforcement. No durable restart tested.',
            'clock_note': 'Event and observation ticks are relative same-host monotonic nanoseconds. Arrival ticks belong to the separate replay schedule; they are not measured delivery latency.'})
    return views


def write_report(out, *, replay_path=None):
    out.mkdir(parents=True, exist_ok=False)
    if replay_path is None:
        runtime = runtime_basis()
        inputs = make_inputs(out / 'capture')
    else:
        # An explicit local input is read once. Embedded source refs are opaque;
        # nothing is fetched from a URL or an embedded filesystem path.
        raw = replay_path.read_bytes()
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('replay package exceeds 8 MiB')
        inputs, runtime = loads(raw), None
    (out / 'inputs.json').write_bytes(encoded(inputs))
    views = replay(inputs)
    paths = sorted(Path(__file__).parent.rglob('*.py')) + sorted(Path(__file__).parent.glob('*.json'))
    paths += [Path(__file__).with_name('view.html')] + sorted((ROOT / 'tools/airep_v02').glob('*.py'))
    paths += [ROOT / 'integrations/langgraph/run.py', ROOT / 'integrations/langgraph/requirements.lock']
    record = {'scope': 'Controlled runtime capture and offline replay; no durable restart or independent observer.',
              'created_utc': utc(), 'source_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'worktree_status': subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True),
              'runtime': runtime, 'replay_input_sha256': hashlib.sha256(raw).hexdigest() if replay_path else None,
              'source_hashes': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
              'views': views}
    (out / 'report.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    payload = json.dumps(views).replace('<', '\\u003c').replace('&', '\\u0026')
    (out / 'index.html').write_text(Path(__file__).with_name('view.html').read_text().replace('__REPORT_DATA__', payload))
    manifest = {str(p.relative_to(out)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob('*')) if p.is_file()}
    (out / 'SHA256SUMS.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'views': len(views), 'expected_observed_matches': len(views),
                      'fresh_runtime_capture': replay_path is None, 'basis_digest': RuntimeSourcePolicy.basis}))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--replay', type=Path, help='Replay saved public inputs, without running LangGraph again')
    args = parser.parse_args()
    write_report(args.out, replay_path=args.replay)


if __name__ == '__main__':
    main()
