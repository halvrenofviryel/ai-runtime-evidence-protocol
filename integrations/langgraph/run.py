#!/usr/bin/env python3
"""Real, local LangGraph execution; no model, provider, or remote service."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import multiprocessing as mp
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import time
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tools.airep_v02 import Chain, digest_bytes, digest_json, reference
from tools.airep_v02.explain import explain, render_text
from tools.airep_v02.reconcile import reconcile
from tools.airep_v02.verify import operator_inputs

SCENARIOS = ('normal', 'stop-before-start', 'stop-during-action',
             'receiver-unreachable', 'receiver-ignores-stop', 'effect-unobserved')
STEPS = 4
TIMEOUT = 15.0
BASE = '0130fcf8e7d70a0f9c4f977957e5de76ca8ef689'


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def event(kind, actor, **data):
    return dict(kind=kind, actor=actor, timestamp_utc=utc(), monotonic_ns=time.monotonic_ns(), **data)


def disable_network():
    """Fail if a dependency tries outbound traffic; no credential is read."""
    # Delete by name without fetching values; dependencies cannot inherit keys.
    for name in tuple(os.environ):
        if name not in {'PATH', 'LANG', 'LC_ALL', 'TZ', 'PYTHONHASHSEED', 'SYSTEMROOT'}:
            del os.environ[name]
    os.environ['LANGSMITH_TRACING'] = 'false'
    os.environ['LANGCHAIN_TRACING_V2'] = 'false'
    def denied(*args, **kwargs):
        raise RuntimeError('Network disabled in local runtime experiment')
    socket.socket.connect = denied
    socket.socket.connect_ex = denied
    socket.create_connection = denied


class State(TypedDict):
    completed_steps: int


def worker(directory, scenario, control, telemetry, begin, continue_action):
    """One spawned process runs the actual installed LangGraph interpreter."""
    disable_network()
    try:
        from langgraph.checkpoint.memory import InMemorySaver
        from langgraph.graph import END, START, StateGraph
        from langgraph.types import interrupt

        def emit(kind, **data):
            telemetry.send(event(kind, 'runtime', **data))

        unavailable = scenario == 'receiver-unreachable'
        if unavailable:
            control.close()  # Fault injection: actual pipe endpoint is closed.
            emit('receiver_endpoint_closed')
        emit('worker_ready', pid=os.getpid(), langgraph=importlib.metadata.version('langgraph'))
        if not begin.wait(TIMEOUT):
            raise TimeoutError('start barrier expired')

        def checkpoint():
            if unavailable or not control.poll():
                return
            raw = control.recv_bytes()
            command = json.loads(raw)
            emit('receiver_observed', instruction=command, instruction_digest=digest_bytes(raw))
            if scenario == 'receiver-ignores-stop':
                emit('enforcement_unavailable', instruction_id=command['instruction_id'],
                     attempted_action=command['action'], actual_action={'operation': 'continue-without-pause'},
                     reason='Deliberately disabled cooperative handler; command was received.')
                return
            emit('enforcement_requested', instruction_id=command['instruction_id'], action=command['action'])
            # Do not catch GraphInterrupt. LangGraph must handle and persist it.
            interrupt({'instruction_id': command['instruction_id'], 'operation': 'cooperative-pause'})

        def controlled_action(state):
            emit('node_entered', node='controlled_action')
            checkpoint()  # Stop before the first business side effect.
            for step in range(1, STEPS + 1):
                with (Path(directory) / 'effects.jsonl').open('ab') as stream:
                    stream.write(encoded({'step': step}))
                    stream.flush()
                    os.fsync(stream.fileno())
                emit('business_step_written', step=step)
                if step == 1:
                    emit('action_barrier_reached', completed_steps=step)
                    if not continue_action.wait(TIMEOUT):
                        raise TimeoutError('in-action barrier expired')
                checkpoint()  # Cooperative boundary; cannot preempt a file write.
            return {'completed_steps': STEPS}

        builder = StateGraph(State)
        builder.add_node('controlled_action', controlled_action)
        builder.add_edge(START, 'controlled_action')
        builder.add_edge('controlled_action', END)
        graph = builder.compile(checkpointer=InMemorySaver())
        config = {'configurable': {'thread_id': scenario}}
        emit('graph_invocation_started')
        result = graph.invoke({'completed_steps': 0}, config, version='v2')
        snapshot = graph.get_state(config)
        if result.interrupts:
            emit('native_interrupt_observed', interrupts=[{'id': i.id, 'value': i.value} for i in result.interrupts],
                 checkpoint_next=list(snapshot.next),
                 checkpoint_interrupts=[i.value for task in snapshot.tasks for i in task.interrupts],
                 state_value=result.value)
        else:
            emit('graph_completed', state_value=result.value, checkpoint_next=list(snapshot.next))
        emit('worker_finished')
    except BaseException as exc:
        telemetry.send(event('worker_error', 'runtime', error=type(exc).__name__, message=str(exc)))
        raise
    finally:
        control.close()
        telemetry.close()


def observe(directory):
    path = directory / 'effects.jsonl'
    raw = path.read_bytes() if path.exists() else b''
    rows = [json.loads(line) for line in raw.splitlines()]
    return {'file_exists': path.exists(), 'completed_steps': len(rows),
            'steps': [row['step'] for row in rows], 'file_digest': digest_bytes(raw)}


def collect_run(directory, scenario, *, timeout=TIMEOUT):
    """Barriers order experiments; statuses are derived only from captured events."""
    if scenario not in SCENARIOS:
        raise ValueError('unknown scenario')
    directory.mkdir(parents=True, exist_ok=False)
    events = []
    def append(item):
        item = dict(item, event_id=f'e{len(events)+1:04d}')
        events.append(item)
        with (directory / 'events.jsonl').open('ab') as stream:
            stream.write(encoded(item))
    ctx = mp.get_context('spawn')
    receiver, sender = ctx.Pipe(duplex=False)
    read_events, write_events = ctx.Pipe(duplex=False)
    begin, continue_action = ctx.Event(), ctx.Event()
    child = ctx.Process(target=worker, args=(str(directory), scenario, receiver, write_events, begin, continue_action))
    deadline = time.monotonic() + timeout
    def until(kind):
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not read_events.poll(remaining):
                raise TimeoutError('waiting for ' + kind)
            try:
                item = read_events.recv()
            except EOFError as exc:
                raise RuntimeError('runtime telemetry ended before ' + kind) from exc
            append(item)
            if item['kind'] == 'worker_error':
                raise RuntimeError(item['message'])
            if item['kind'] == kind:
                return
    def send_stop():
        command = {'instruction_id': scenario + '.stop', 'action': {'operation': 'cooperative-pause', 'node': 'controlled_action'}}
        raw = encoded(command)
        (directory / 'instruction.json').write_bytes(raw)
        append(event('decision_recorded', 'issuer', instruction=command, instruction_digest=digest_bytes(raw),
                     policy='Experiment operator requests cooperative pause at next checkpoint'))
        append(event('control_command_produced', 'issuer', instruction_digest=digest_bytes(raw)))
        try:
            sender.send_bytes(raw)
        except (BrokenPipeError, OSError) as exc:
            append(event('delivery_failed', 'issuer', instruction_digest=digest_bytes(raw), error=type(exc).__name__))
        else:
            append(event('issuer_dispatched', 'issuer', instruction_digest=digest_bytes(raw)))
    failure = None
    started = False
    try:
        child.start()
        started = True
        receiver.close()
        write_events.close()
        until('worker_ready')
        if scenario in ('stop-before-start', 'effect-unobserved'):
            send_stop()
        begin.set()
        if scenario not in ('stop-before-start', 'effect-unobserved'):
            until('action_barrier_reached')
            if scenario != 'normal':
                send_stop()
            continue_action.set()
        until('worker_finished')
        child.join(max(0, deadline - time.monotonic()))
        if child.is_alive():
            raise TimeoutError('runtime process did not exit')
        if child.exitcode != 0:
            raise RuntimeError('runtime exit code ' + str(child.exitcode))
        if scenario == 'effect-unobserved':
            append(event('observation_disabled', 'harness', reason='Negative control: no post-run effect observer executed'))
        else:
            start = observe(directory)
            window_start = time.monotonic_ns()
            time.sleep(0.03)
            end = observe(directory)
            append(event('effect_observed', 'harness', initial=start, final=end,
                         window_start_ns=window_start, window_end_ns=time.monotonic_ns(),
                         stable_between_reads=start == end))
    except BaseException as exc:
        failure = exc
        append(event('harness_error', 'harness', error=type(exc).__name__, message=str(exc)))
    finally:
        forced = False
        if started:
            if child.is_alive():
                forced = True
                child.terminate()  # Safety cleanup, never classified as successful stop.
                child.join(2)
                if child.is_alive():
                    child.kill()
                    child.join(2)
            alive, exitcode = child.is_alive(), child.exitcode
        else:
            alive, exitcode = False, None
        for connection in (receiver, sender, read_events, write_events):
            connection.close()
        append(event('cleanup_completed', 'harness', worker_alive=alive, worker_exitcode=exitcode,
                     forced_termination=forced))
        if started and not alive:
            child.close()
        if alive:
            raise RuntimeError('cleanup failed: child remains alive')
    event_dir = directory / 'events'
    event_dir.mkdir()
    for item in events:
        (event_dir / (item['event_id'] + '.json')).write_bytes(encoded(item))
    if failure is not None:
        raise failure
    return events


def project(events, run_id):
    """A first-party report adapter, not a claim adjudicator or event authenticator.

    In particular the scenario name NEVER selects an execution outcome.
    Missing receiver/native-pause/observation events cannot produce that evidence.
    """
    keys = {role: Ed25519PrivateKey.generate() for role in ('issuer', 'runtime')}
    chains = {role: Chain(key, 'langgraph-local.' + role, chain_id=run_id + '.' + role)
              for role, key in keys.items()}
    bindings = {'bindings': {}, 'producer_bindings': {}, 'witness_bindings': {}}
    revocation = {'snapshot_id': run_id + '.local-test', 'bindings': {}}
    for role, key in keys.items():
        identity = 'langgraph-local.' + role
        bindings['bindings'][identity] = {'subject_identity': identity, 'role': 'producer', 'suite': 'ed25519', 'trusted': True,
            'public_key_hex': key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        bindings['producer_bindings'][identity] = identity
        revocation['bindings'][identity] = {'state': 'active'}
    artifacts = []
    mapping = []
    def evidence(items):
        return [{'type': 'other', 'ref': 'events/' + item['event_id'] + '.json', 'resolvable': True,
                 'content_hash': digest_bytes(encoded(item))} for item in items]
    def emit(role, family, payload, items):
        result = chains[role].emit(family, dict(payload, evidence=evidence(items)),
            record_id=run_id + '.' + str(len(artifacts)), timestamp=items[-1]['timestamp_utc'],
            scope={'covers': ['First-party local experiment report derived from referenced event bytes'],
                   'does_not_cover': ['Independent corroboration', 'Event truth established by signature',
                                      'Preemptive cancellation', 'LLM behavior', 'Complete history or production deployment']})
        artifacts.append(result)
        mapping.append({'artifact_ref': reference(result), 'source_event_ids': [i['event_id'] for i in items]})
        return result
    def find(kind):
        return next((item for item in events if item['kind'] == kind), None)
    decision_event = find('decision_recorded')
    if decision_event is None:
        return artifacts, mapping, bindings, revocation
    command = decision_event['instruction']
    action = command['action']
    decision = emit('issuer', 'decision', {
        'input': {'input_ref': 'instruction.json', 'input_digest': decision_event['instruction_digest']},
        'claim': {'assertion': decision_event['policy'], 'basis': ['local-experiment-operator']},
        'directive': {'verb': 'release', 'policy_basis': ['local-experiment-operator']},
        'output': {'result_ref': 'events/' + decision_event['event_id'] + '.json',
                   'result_digest': digest_bytes(encoded(decision_event))}}, [decision_event])
    common = {'decision_ref': reference(decision), 'instruction_id': command['instruction_id'],
              'instruction_digest': decision_event['instruction_digest']}
    control = dict(common, authorized_action_digest=digest_json(action),
                   authority={'issuer_id': 'langgraph-local.issuer', 'writable_by_controlled_system': True})
    for kind, native in [('issuer_dispatched', 'dispatched'), ('delivery_failed', 'delivery_failed')]:
        item = find(kind)
        if item:
            emit('issuer', 'control', dict(control, instruction_digest=item['instruction_digest'],
                 control_event=native, boundary_side='issuer'), [item])
    receipt = find('receiver_observed')
    if receipt:
        emit('runtime', 'control', dict(control, instruction_digest=receipt['instruction_digest'],
             control_event='received', boundary_side='receiver'), [receipt])
    execution = None
    request, paused, refused = find('enforcement_requested'), find('native_interrupt_observed'), find('enforcement_unavailable')
    # Receipt must match bytes/identity; a request alone is never execution proof.
    matched = receipt and receipt['instruction_digest'] == common['instruction_digest'] and receipt['instruction'] == command
    if matched and request and paused and request['action'] == action and request['instruction_id'] == command['instruction_id']:
        ids = [i['value'].get('instruction_id') for i in paused['interrupts']]
        checkpoint_ids = [i.get('instruction_id') for i in paused['checkpoint_interrupts']]
        if command['instruction_id'] in ids and command['instruction_id'] in checkpoint_ids and paused['checkpoint_next']:
            execution = emit('runtime', 'execution', dict(common, executed_action_digest=digest_json(action), execution_event='executed'),
                             [receipt, request, paused])
    elif matched and refused and refused['instruction_id'] == command['instruction_id']:
        execution = emit('runtime', 'execution', dict(common, executed_action_digest=digest_json(refused['actual_action']), execution_event='failed'),
                         [receipt, refused])
    observation = find('effect_observed')
    if execution and observation:
        emit('runtime', 'effect', {'decision_ref': reference(decision), 'execution_ref': reference(execution),
            'observer_relationship': 'same_executor',
            'observed_state': {'description': 'Local post-run file observation: ' + json.dumps(observation['final'], sort_keys=True)
                              + '; stability is bounded to the recorded two-read window; not causation.',
                               'state_digest': digest_json(observation['final'])}}, [observation])
    return artifacts, mapping, bindings, revocation


def source_basis():
    paths = sorted((ROOT / 'integrations/langgraph').rglob('*.py'))
    paths += sorted((ROOT / 'tools/airep_v02').glob('*.py'))
    paths += [ROOT / 'integrations/langgraph/requirements.lock']
    return [{'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()} for path in paths]


def runtime_basis():
    locked = []
    for line in (ROOT / 'integrations/langgraph/requirements.lock').read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        name, rest = line.split('==', 1)
        version = rest.split()[0]
        installed = importlib.metadata.version(name)
        if installed != version:
            raise RuntimeError(f'Pinned dependency mismatch: {name} expected {version}, found {installed}')
        locked.append({'name': name, 'version': installed})
    distribution = importlib.metadata.distribution('langgraph')
    sources = [{'path': str(p), 'sha256': hashlib.sha256(distribution.locate_file(p).read_bytes()).hexdigest()}
               for p in distribution.files if str(p).startswith('langgraph/') and str(p).endswith('.py')]
    return {'dependencies': locked, 'installed_langgraph_source_files': sorted(sources, key=lambda i: i['path'])}


def run_suite(out, scenarios=SCENARIOS):
    out.mkdir(parents=True, exist_ok=False)
    record = {'base_commit': BASE, 'source_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'source_worktree_status': subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True),
        'started_utc': utc(), 'python': sys.version, 'platform': platform.platform(), 'argv': sys.argv,
        'runtime': {'name': 'langgraph', 'version': importlib.metadata.version('langgraph'), **runtime_basis()},
        'source_basis': source_basis(), 'scenarios': [],
        'constraints': ['No LLM or provider calls', 'Native LangGraph cooperative interrupt only',
                        'One local author/trust domain; no independent interop evidence',
                        'Authority writable by controlled system; no security-isolation claim']}
    for scenario in scenarios:
        directory = out / scenario
        events = collect_run(directory, scenario)
        artifacts, mapping, bindings, revocation = project(events, scenario)
        for name, value in [('lifecycle', artifacts), ('event-mapping', mapping), ('bindings', bindings), ('revocation', revocation)]:
            save(directory / (name + '.json'), value)
        ops = operator_inputs(bindings=str(directory / 'bindings.json'), revocation=str(directory / 'revocation.json'))
        report, view = reconcile(artifacts, ops=ops), explain(artifacts, ops=ops)
        save(directory / 'reconciliation.json', report)
        save(directory / 'explain.json', view)
        (directory / 'explain.txt').write_text(render_text(view))
        observed = next((i['final']['completed_steps'] for i in events if i['kind'] == 'effect_observed'), None)
        row = {'scenario': scenario, 'observed_steps': observed,
               'event_kinds': [i['kind'] for i in events], 'reconciliation_summary': report['summary'],
               'artifact_count': len(artifacts), 'cleanup': events[-1]}
        record['scenarios'].append(row)
        print(json.dumps({'scenario': scenario, 'observed_steps': observed, 'artifacts': len(artifacts), 'summary': report['summary']['status']}), flush=True)
    record['finished_utc'] = utc()
    record['artifacts'] = [{'path': str(p.relative_to(out)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in sorted(out.rglob('*')) if p.is_file()]
    save(out / 'run_record.json', record)
    (out / 'run_record.sha256').write_text(hashlib.sha256((out / 'run_record.json').read_bytes()).hexdigest() + '  run_record.json\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--scenario', choices=SCENARIOS, action='append')
    args = parser.parse_args()
    run_suite(args.out, args.scenario or SCENARIOS)


if __name__ == '__main__':
    main()
