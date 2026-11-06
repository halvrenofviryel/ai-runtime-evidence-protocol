#!/usr/bin/env python3
"""Build and verify the installed SDK through the existing beta CI entry.

Uses the original committed checkout. Only the requested new output directory
is written. Retains command logs even on failure; never publishes a package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main(out):
    out.mkdir(parents=True, exist_ok=False)
    results = []
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
    def run(command):
        command = [str(a) for a in command]
        log = out / f'{len(results)+1:02d}.log'
        with log.open('wb') as stream:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=600)
        results.append({'command': command, 'exit': result.returncode, 'log': log.name,
                        'sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        (out/'checks.json').write_text(json.dumps(results, indent=2)+'\n')
        print(f'SDK CI step {len(results)}: exit={result.returncode}', flush=True)
        if result.returncode:
            raise RuntimeError('SDK CI failed; inspect retained command log')
    run([sys.executable, '-m', 'venv', out/'.build-env'])
    python = out/'.build-env/bin/python'
    run([python, '-m', 'pip', '--isolated', 'install', '--index-url', 'https://pypi.org/simple',
         '--no-input', '--disable-pip-version-check', '--no-cache-dir',
         'build==1.4.2', 'setuptools==68.1.2', 'wheel==0.42.0'])
    run([python, '-B', ROOT/'scripts/build_sdk.py', '--out', out/'build'])
    version = tomllib.loads((ROOT/'sdk/python/pyproject.toml').read_text())['project']['version']
    wheel = out/'build/dist'/f'airep_sdk-{version}-py3-none-any.whl'
    for label in ('a', 'b'):
        run([sys.executable, '-B', ROOT/'scripts/check_sdk.py',
             '--wheel', wheel, '--out', out/('clean-'+label)])
    records = [json.loads((out/('clean-'+label)/'ACCEPTANCE.json').read_text()) for label in ('a','b')]
    build = json.loads((out/'build/BUILD_RECORD.json').read_text())
    assert all(r['installed']['source_commit'] == build['source_commit'] and
               r['wheel_sha256'] == build['artifacts'][wheel.name]['sha256'] for r in records)
    (out/'CI_ACCEPTANCE.json').write_text(json.dumps({
        'source_commit':build['source_commit'], 'sdk_version':version,
        'clean_installs':records, 'github_run_id':os.environ.get('GITHUB_RUN_ID'),
        'scope':'Automated project checks; no independent adoption'}, indent=2)+'\n')
    # These are disposable environments created above; retain all logs, inputs,
    # examples and wheel bytes, without uploading three installed dependency trees.
    for directory in (out/'.build-env',out/'clean-a/environment',out/'clean-b/environment'):
        shutil.rmtree(directory)
    print('SDK build and both clean installed-wheel checks PASS', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    main(parser.parse_args().out.resolve())
