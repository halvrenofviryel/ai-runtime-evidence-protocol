#!/usr/bin/env python3
"""CI-equivalent checks in a disposable copy; never overwrite pinned evidence.

Each command, cwd, exit and complete output is retained, including failures.
Usage: python3 scripts/check_beta.py --out /tmp/airep-checks [--historical-only]
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--historical-only', action='store_true')
    ap.add_argument('--with-v01-typescript', action='store_true', help='also reproduce the legacy npm/build/producer-interop CI job (registry access)')
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    scratch = Path(tempfile.mkdtemp(prefix='airep-beta-check-')) / 'repo'
    common_ignore=shutil.ignore_patterns('.git', '.venv', 'node_modules', '__pycache__', '.pytest_cache', 'dist')
    def ignore(directory, names):
        ignored=common_ignore(directory, names)
        if Path(directory).is_relative_to(ROOT/'reports'):
            ignored=set(ignored)|{'parity'}
        return ignored
    shutil.copytree(ROOT, scratch, ignore=ignore)
    basis=[]
    for pattern in ('tools/airep_v02', 'tests/v02', 'examples/v02', 'scripts', '.github/workflows'):
        for p in sorted((ROOT/pattern).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                basis.append({'path':str(p.relative_to(ROOT)), 'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
    for name in ('README.md','CITATION.cff','spec/airep/v0.2/SPEC.md','spec/airep/v0.2/RECONCILIATION.md',
                 'spec/airep/v0.2/JSON_INPUT_ADMISSIBILITY.md','spec/airep/v0.2/CONFORMANCE_CLASSES.md',
                 'spec/airep/v0.2/INTEGRITY.md','spec/airep/v0.2/class-verification/contract-r3/CLASS_VERIFIER_CONTRACT_R3.md'):
        basis.append({'path':name,'sha256':hashlib.sha256((ROOT/name).read_bytes()).hexdigest()})
    (args.out/'source-basis.json').write_text(json.dumps(sorted(basis,key=lambda x:x['path']),indent=2)+'\n')
    cv = 'spec/airep/v0.2/class-verification'
    sv = 'spec/airep/v0.2/schema-validation'
    venv = scratch / cv / 'offline-python-deps/.venv/bin/python'
    commands = []

    def add(cwd, *argv):
        commands.append((cwd, list(argv)))

    add('.', 'python3', '-VV')
    add('.', 'node', '--version')
    add(cv, 'python3', 'offline-node-deps/materialize_node_modules.py')
    add(cv, 'python3', 'offline-python-deps/prepare_offline_venv.py')
    add(cv, 'python3', 'preflight_offline_basis.py')
    vec = 'spec/airep/v0.2/vectors'
    add(vec, str(venv), 'generator_py/generate_vectors.py')
    add(vec, 'node', 'generator_node/generate_vectors.mjs')
    add(vec, str(venv), 'compare_vectors.py')
    add(vec, str(venv), 'prove_extra_field_gate.py')
    add('spec/airep/v0.2/stage4', 'bash', 'reproduce.sh')
    add('spec/airep/v0.2/stage4', str(venv), 'prove_envelope_gate.py')
    add('spec/airep/v0.2', str(venv), 'prove_signature_input_pinning.py')
    add('spec/airep/v0.2', str(venv), 'prove_jcs_exponent_artifact_path.py')
    add(sv, str(venv), 'run_python.py')
    add(sv, 'ln', '-s', '../class-verification/verifier_node_r2/node_modules', 'node_modules')
    add(sv, 'node', 'run_node.mjs')
    add(sv, str(venv), 'compare_schema_results.py')
    add(sv, str(venv), 'prove_schema_gates.py')
    nd = cv + '/verifier_node_r2'
    add(nd, 'node', 'class_verifier.mjs', '--corpus', '../corpus', '--out', 'out_run1.json')
    add(nd, 'cp', 'out_run1.json', 'out_run2.json')
    for script in ('selfcheck', 'corpus_compare', 'rulings_check', 'errata_check',
                   'exitcode_check', 'exitcode_check_selftest', 'preimage_check'):
        add(nd, 'node', script + '.mjs')
    for script in ('selfcheck_errata', 'selfcheck_s9_round2', 'selfcheck_s9_round3', 'selfcheck_s9_round4'):
        add(cv + '/verifier_py', str(venv), script + '.py')
    add(cv, 'python3', 'comparator/compare.py', '--root', '.', '--out-dir', str(scratch.parent / 'comparison-work'),
        '--result', str(args.out.resolve() / 'parity.json'), '--summary', str(args.out.resolve() / 'parity.txt'))
    add(cv + '/comparator', 'python3', 'negative_proofs/run_all.py')
    v01 = 'spec/airep/v0.1'
    for script in ('validate', 'enas_profiles', 'enas_obligation_reconciler', 'test_jcs',
                   'test_verifier_parity', 'test_trusted_gates', 'test_strict_trusted'):
        add(v01, str(venv), 'conformance/' + script + '.py')
    add(v01, 'python3', '-m', 'pytest', 'conformance', '-q')
    add(v01, 'node', 'conformance/verify.mjs', 'examples/chain.jsonl', '--pubkey', 'examples/test_public_key.txt')
    add(v01, str(venv), 'examples/regenerate.py')
    add('.', str(venv), 'scripts/check_beta_docs.py')
    if args.with_v01_typescript:
        add('producers/typescript', 'npm', 'install', '--ignore-scripts', '--no-audit', '--no-fund')
        add('producers/typescript', 'npm', 'run', 'build')
        add('.', str(venv), 'scripts/check_v01_typescript.py')
    add('.', 'python3', 'tools/interop_pkg/test_crypto_projection.py')
    add('.', str(venv), 'spec/airep/v0.2/interop/interop_eval_py/test_interop_eval.py')
    add('spec/airep/v0.2/interop/interop_eval_node', 'node', 'selftest.mjs')
    if not args.historical_only:
        add('.', str(venv), '-m', 'unittest', 'discover', '-s', 'tests/v02', '-v')
        add('.', str(venv), 'examples/v02/run_lifecycle.py', '--out', str(args.out.resolve() / 'lifecycle'))
        add('.', str(venv), 'scripts/check_quickstart.py')
        add('.', str(venv), 'scripts/check_beta_docs.py')
    results = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    for i, (cwd, command) in enumerate(commands, 1):
        start = time.monotonic()
        try:
            p = subprocess.run(command, cwd=scratch / cwd, env=env, capture_output=True, timeout=600)
            output, code = p.stdout + p.stderr, p.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            output, code = str(exc).encode(), -1
        log = f'{i:02d}.log'
        (args.out / log).write_bytes(output)
        results.append({'cwd':cwd, 'command':command, 'exit':code, 'seconds':round(time.monotonic()-start, 3),
                        'log':log, 'log_sha256':hashlib.sha256(output).hexdigest()})
        (args.out / 'results.json').write_text(json.dumps({'scratch':str(scratch), 'checks':results}, indent=2)+'\n')
        print(f'{i}/{len(commands)} exit={code} {cwd}: {" ".join(command)}', flush=True)
    failed = sum(r['exit'] != 0 for r in results)
    print(f'{len(results)-failed}/{len(results)} commands passed; {failed} failed. Evidence: {args.out}')
    return bool(failed)


if __name__ == '__main__':
    sys.exit(main())
