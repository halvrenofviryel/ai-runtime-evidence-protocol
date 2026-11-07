"""Real three-process fan-out and chain; deterministic missing endpoint / dropped reply injections."""
import copy
import fcntl
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import uuid
from integrations.langgraph.run import ROOT, encoded
from tools.airep_v02.json_input import loads
from .consumer import TARGETS, TOPOLOGIES
from .transport import call, send_attempt

SCENARIOS = ('fanout_all','fanout_unknown','chain_all','chain_refused','chain_unknown','chain_retry')


def capture(root, scenario):
    if scenario not in SCENARIOS: raise ValueError('unknown experiment')
    root.mkdir(parents=True, exist_ok=False); workers={}; logs={}
    topology='fanout' if scenario.startswith('fanout') else 'chain'
    intent={'targets':list(TARGETS),'topology':topology,'children':copy.deepcopy(TOPOLOGIES[topology]),'identities':{}}
    common={'workflow_id':'k7-local-workflow','run_id':str(uuid.uuid4()),'control_id':'pause-1','attempt_id':'execution-1'}
    events=[]; start=time.monotonic_ns(); clock='controller-'+str(uuid.uuid4())
    def now(): return time.monotonic_ns()-start
    def emit(kind,data):
        events.append({'seq':len(events)+1,'tick':now(),'kind':kind,'data':data})
        with (root/'controller.jsonl').open('ab') as stream: stream.write(encoded(events[-1]))
    with tempfile.TemporaryDirectory(prefix='airep-k7-sockets-') as tmp:
        sockets={t:str(Path(tmp)/t) for t in TARGETS}; missing=str(Path(tmp)/'missing-C'); trusts={}
        try:
            for target in TARGETS:
                work=root/target; work.mkdir(); endpoints=dict(sockets)
                if scenario=='chain_unknown' and target=='B': endpoints['C']=missing
                request={'identity':dict(common,target_id=target),'socket':sockets[target],'sockets':endpoints,
                    'mode':'refuse' if scenario=='chain_refused' and target=='B' else 'pause',
                    'retry':scenario=='chain_retry' and target=='B',
                    'drop_first_response':scenario=='chain_retry' and target=='C'}
                (work/'request.json').write_bytes(encoded(request)); logs[target]=(work/'worker.log').open('wb')
                process=subprocess.Popen([sys.executable,'-B','-m','integrations.langgraph.multitarget.worker',
                    '--request',str((work/'request.json').resolve())],cwd=ROOT,stdout=subprocess.PIPE,stderr=logs[target],
                    env={'PATH':os.environ['PATH'],'LANG':'C.UTF-8'},close_fds=True)
                workers[target]=process
                if not select.select([process.stdout],[],[],20)[0]: raise TimeoutError('worker readiness: '+target)
                line=process.stdout.readline()
                if not line: raise RuntimeError('worker startup failed: '+target+'; inspect '+str(work/'worker.log'))
                ready=loads(line); intent['identities'][target]=ready['identity']; trusts[target]=ready['trust']
                if ready['pid']!=process.pid: raise ValueError('wrong process identity')
            # Frozen before any control result is available.
            (root/'intent-before-dispatch.json').write_bytes(encoded(intent))
            for target in TARGETS:
                if loads(call(sockets[target],{'op':'configure','intent':intent}))!={'configured':True}:
                    raise ValueError('configuration not acknowledged')
            for target in intent['children']['controller']:
                command={'op':'pause','identity':intent['identities'][target],'sender':'controller','path':['controller',target],
                         'delivery_attempt_id':str(uuid.uuid4()),'parent_delivery_attempt_id':None}
                endpoint=missing if scenario=='fanout_unknown' and target=='C' else sockets[target]
                send_attempt(endpoint,command,emit)
            control_end=now(); observations={}
            def sample(target):
                begin=now()
                with (root/target/'effects.jsonl').open('rb') as stream:
                    fcntl.flock(stream,fcntl.LOCK_SH); raw=stream.read()
                return {'start':begin,'end':now(),'bytes_hex':raw.hex()}
            for target in TARGETS:
                observations[target]={'identity':intent['identities'][target],'clock_id':clock,'before':sample(target)}
            time.sleep(0.12)
            for target in TARGETS: observations[target]['after']=sample(target)
            nodes={t:loads(call(sockets[t],{'op':'snapshot'})) for t in TARGETS}; cleanup={}
            for target in TARGETS:
                paused=loads(nodes[target]['projection_bytes'].encode())['execution']=='PAUSED_REPORTED'
                if paused:
                    if loads(call(sockets[target],{'op':'exit'}))!={'exiting':True}: raise ValueError('exit not acknowledged')
                else: workers[target].kill()
                code=workers[target].wait(timeout=5)
                cleanup[target]={'forced':not paused,'exitcode':code,'pid':workers[target].pid,'tick':now()}
            source={'schema':'multitarget-capture-v1','intent':intent,'controller_clock_id':clock,'events':events,
                'control_end_tick':control_end,'nodes':nodes,'observations':observations,'cleanup':cleanup}
            (root/'source.json').write_bytes(encoded(source)); (root/'node-trust.json').write_bytes(encoded(trusts))
            return source,trusts
        finally:
            for process in workers.values():
                if process.poll() is None: process.kill()
                process.wait(timeout=5); process.stdout.close()
            for stream in logs.values(): stream.close()
