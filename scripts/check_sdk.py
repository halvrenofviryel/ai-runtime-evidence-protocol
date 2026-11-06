#!/usr/bin/env python3
"""Measure one fresh installed SDK environment outside the checkout.

Run twice with different --out directories for two author-side clean installs.
Dependency downloads use the committed hash lock, no pip cache and no editable
install. This is installation evidence, not an external developer trial.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main(wheel, out):
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    venv, user = out/'environment', out/'user-application'
    user.mkdir()
    results=[]
    env={k:v for k,v in os.environ.items() if k in {'PATH','LANG','LC_ALL','SYSTEMROOT'}}
    env.update(PYTHONDONTWRITEBYTECODE='1', LANGSMITH_TRACING='false', LANGCHAIN_TRACING_V2='false')

    def run(command, cwd=user, timeout=180, expected=0):
        log=out/f'{len(results)+1:02d}.log'
        begin=time.monotonic()
        with log.open('wb') as output:
            p=subprocess.run([str(a) for a in command],cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=timeout)
        results.append({'command':[str(a) for a in command],'exit':p.returncode,'expected_exit':expected,
            'seconds':round(time.monotonic()-begin,3),'log':log.name,'sha256':hashlib.sha256(log.read_bytes()).hexdigest()})
        (out/'checks.json').write_text(json.dumps(results,indent=2)+'\n')
        if p.returncode!=expected:
            raise RuntimeError('SDK acceptance command failed; inspect '+str(log))
        print(f'{len(results)}: exit={p.returncode} elapsed={results[-1]["seconds"]}',flush=True)
        return log

    run([sys.executable,'-m','venv',venv])
    python=venv/'bin/python'
    run([python,'-m','pip','--isolated','install','--index-url','https://pypi.org/simple',
        '--no-input','--disable-pip-version-check','--no-cache-dir','--require-hashes','--only-binary=:all:',
        '-r',ROOT/'integrations/langgraph/requirements.lock'],timeout=600)
    run([python,'-m','pip','--isolated','install','--no-input','--no-index','--no-deps',wheel])
    for source,dest in [('examples/user_graph.py','user_graph.py'),('tests/test_installed_sdk.py','test_installed_sdk.py'),
                        ('tests/check_native_parity.py','check_native_parity.py')]:
        shutil.copy2(ROOT/'sdk/python'/source,user/dest)
    run([python,'-I','user_graph.py','--mode','paused','--out','paused'])
    first_seconds=round(time.monotonic()-started,3)
    for mode in ['ignored','unobserved']:
        run([python,'-I','user_graph.py','--mode',mode,'--out',mode])
    testlog=run([python,'-I','test_installed_sdk.py','-v'])
    assert 'Ran 29 tests' in testlog.read_text() and '\nOK\n' in testlog.read_text()
    native=out/'native-inputs'
    run([python,'-B',ROOT/'sdk/python/tests/prepare_native_parity.py','--out',native],cwd=ROOT)
    paritylog=run([python,'-I','check_native_parity.py','--inputs',native])
    parity=json.loads(paritylog.read_text()); assert parity['all_equal'] and parity['count']==13
    for mode,exitcode in [('paused',0),('ignored',3),('unobserved',3)]:
        run([venv/'bin/airep','consume','--input',f'{mode}/bundle.json','--trust',f'{mode}/trust.json',
             '--query',f'{mode}/query.json','--require-policy-match','--out',f'{mode}/cli-result.json'],expected=exitcode)
    versions=run([python,'-I','-c',
        'import importlib.metadata as m,json,airep; from airep._native.basis import PACKAGE,MANIFEST; '
        'print(json.dumps({"versions":{n:m.version(n) for n in ["airep-sdk","langgraph","langgraph-checkpoint","cryptography","jsonschema","referencing"]},'
        '"installed_package":str(PACKAGE),"source_commit":MANIFEST["source_commit"],"dirty":MANIFEST["dirty_development_build"]}))'])
    installed=json.loads(versions.read_text())
    assert Path(installed['installed_package']).is_relative_to(venv)
    assert not installed['dirty']
    observed={mode:json.loads((user/mode/'result.json').read_text())['consumer'] for mode in ['paused','ignored','unobserved']}
    record={'scope':'author-side clean install on same host; no outside adoption',
        'wheel':wheel.name,'wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest(),
        'pip_cache_disabled':True,'first_verified_output_seconds':first_seconds,'under_15_minutes':first_seconds<900,
        'unit_tests':29,'native_parity_cases':13,'installed':installed,'observed':observed,
        'command_count':len(results),'all_expected_exits':True}
    (out/'ACCEPTANCE.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'first_verified_output_seconds':first_seconds,'unit_tests':29,'native_parity_cases':13,'commands':len(results)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheel',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    main(args.wheel.resolve(),args.out.resolve())
