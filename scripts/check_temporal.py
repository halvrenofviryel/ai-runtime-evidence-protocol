#!/usr/bin/env python3
"""Run captured-runtime regressions from the existing beta CI entry point.

Default provisioning downloads only hash-pinned wheels into a dedicated venv.
--python reuses an explicitly supplied environment; capture checks its versions.
Node dependencies are materialized from the existing offline archive. Only test
scratch output and ignored dependency directories are written.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--python', type=Path, help='Explicit already-provisioned CPython 3.12 environment')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands, results = [], []
    # Preserve a venv's symlink path; resolving it selects the base interpreter.
    python = str(args.python.absolute()) if args.python else str(out / '.venv/bin/python')
    if not args.python:
        commands.extend([
            [sys.executable, '-m', 'venv', str(out / '.venv')],
            [python, '-m', 'pip', 'install', '--require-hashes', '--only-binary=:all:',
             '-r', str(ROOT / 'integrations/langgraph/requirements.lock')]])
    commands.append([sys.executable, str(ROOT / 'spec/airep/v0.2/class-verification/offline-node-deps/materialize_node_modules.py')])
    for directory, pattern in [('tests/v02', 'test_beta.py'), ('tests/v02', 'test_explain.py'),
                               ('integrations/langgraph/tests', 'test*.py'),
                               ('integrations/langgraph/temporal/tests', 'test*.py')]:
        commands.append([python, '-B', '-m', 'unittest', 'discover', '-s', directory, '-p', pattern, '-v'])
    module = 'integrations.langgraph.temporal.runtime_report'
    commands.extend([
        [python, '-B', '-m', module, '--out', str(out / 'capture')],
        [python, '-B', '-m', module, '--replay', str(out / 'capture/inputs.json'), '--out', str(out / 'replay')]])
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    for index, command in enumerate(commands, 1):
        log = out / f'{index:02d}.log'
        with log.open('wb') as stream:
            try:
                code = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                      stderr=subprocess.STDOUT, timeout=600).returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                stream.write(str(exc).encode()); code = -1
        results.append({'command': command, 'exit': code, 'log': log.name,
                        'sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        (out / 'checks.json').write_text(json.dumps(results, indent=2) + '\n')
        print(f'{index}/{len(commands)} exit={code} {command}', flush=True)
        if code:
            return 1
    captured = json.loads((out / 'capture/report.json').read_text())
    replayed = json.loads((out / 'replay/report.json').read_text())
    if len(captured['views']) != 14 or captured['views'] != replayed['views']:
        raise AssertionError('saved-input native and consumer results differ')
    (out / 'replay-equality.json').write_text(json.dumps({'views': 14, 'equal': True,
        'source_commit': captured['source_commit']}, indent=2) + '\n')
    print('All 14 native and consumer views reproduce exactly.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
