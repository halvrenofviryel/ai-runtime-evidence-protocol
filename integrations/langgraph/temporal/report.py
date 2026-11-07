"""Write a reproducible input/report bundle and a small local DOM fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from .core import evaluate, BASIS
from .fixtures import FixtureFactory, query

ROOT = Path(__file__).resolve().parents[3]


def build():
    f = FixtureFactory()
    newer = f.delivery('newer', status='CONTINUED')
    older = f.delivery('older', status='QUIESCENT', window=[0, 5], event_time=5, observed_time=5, arrival=30)
    old_control = f.delivery('old-control', status='QUIESCENT', identity=query(control_id='pause-1')['identity'])
    old_run = f.delivery('old-run', status='QUIESCENT', identity=query(run_id='run-A')['identity'], arrival=30)
    receipt = f.delivery('receipt', status='RECEIVED', kind='receipt')
    pause = f.delivery('pause', status='PAUSED', kind='execution')
    effect = f.delivery('quiescent', status='QUIESCENT')
    cases = [
        ('T01 before delayed observation', [newer], query(), 'CONTINUED_REPORTED'),
        ('T01 after delayed observation', [newer, older], query(), 'CONTINUED_REPORTED'),
        ('T01 reversed arrival list', [older, newer], query(), 'CONTINUED_REPORTED'),
        ('T02 new control / old observation', [old_control], query(), 'MISSING'),
        ('T03 active run B / late run A', [newer, old_run], query(), 'CONTINUED_REPORTED'),
        ('T03 inspect historical run A', [newer, old_run], query(run_id='run-A'), 'QUIESCENT_REPORTED'),
        ('T11 receiver and pause / no observer', [receipt, pause], query(), 'MISSING'),
        ('Positive exact-scope observation', [receipt, pause, effect], query(), 'QUIESCENT_REPORTED'),
    ]
    views, inputs = [], []
    for label, deliveries, q, expected in cases:
        result = evaluate(deliveries, q, f.sources, f.ops)
        observed = result['stages']['effect']['status']
        if observed != expected:
            raise AssertionError((label, expected, observed))
        views.append({'label': label, 'expected_effect': expected, 'result': result})
        inputs.append({'label': label, 'query': q,
                       'deliveries': [dict(d, event_bytes=d['event_bytes'].decode()) for d in deliveries]})
    return views, {'cases': inputs, 'sources': {k: v.decode() for k, v in f.sources.items()},
                   'bindings': f.ops.bindings_doc, 'revocation': f.ops.revocation_doc}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    out = parser.parse_args().out
    out.mkdir(parents=True, exist_ok=False)
    views, inputs = build()
    paths = sorted(Path(__file__).parent.rglob('*.py')) + [Path(__file__).with_name('CONTRACT.json'), Path(__file__).with_name('view.html')]
    record = {'scope': 'Author-generated signed fixtures; no new runtime-delay/restart experiment',
              'basis_digest': BASIS, 'views': views,
              'source_commit': subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
              'source_hashes': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},
              'worktree_status': subprocess.check_output(['git', '-c', 'safe.directory=' + str(ROOT), '-c', 'core.filemode=false', 'status', '--porcelain'], cwd=ROOT, text=True)}
    (out / 'report.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    (out / 'inputs.json').write_text(json.dumps(inputs, indent=2, sort_keys=True) + '\n')
    payload = json.dumps(views).replace('<', '\\u003c').replace('&', '\\u0026')
    html = Path(__file__).with_name('view.html').read_text().replace('__REPORT_DATA__', payload)
    (out / 'index.html').write_text(html)
    print(json.dumps({'views': len(views), 'expected_observed_matches': len(views), 'basis_digest': BASIS}))


if __name__ == '__main__':
    main()
