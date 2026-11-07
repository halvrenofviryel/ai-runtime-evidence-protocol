"""Acceptance tests intended to run against an installed wheel outside the checkout."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver

from airep import digest_bytes, ProfileBases
from airep._native.basis import verifier, MANIFEST, PACKAGE
from airep.consumer import consume
from airep.io import bounded_loads, read_bytes, write_bytes, encoded, artifacts
from airep.langgraph import ControlSession, FileObserver
from airep.trust import from_bytes


def trust_for(key):
    producer = 'tests.user'
    return {'bindings': {'bindings': {producer: {'subject_identity': producer, 'role': 'producer',
        'suite': 'ed25519', 'trusted': True, 'public_key_hex': key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}},
        'producer_bindings': {producer: producer}, 'witness_bindings': {}},
        'revocation': {'snapshot_id': 'tests.local', 'bindings': {producer: {'state': 'active'}}}}


class InstalledSDK(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.network = patch.object(socket.socket, 'connect', side_effect=AssertionError('network forbidden'))
        self.network.start(); self.addCleanup(self.network.stop)

    def run_graph(self, *, honor=True, observed=True, wrapped=True):
        key = Ed25519PrivateKey.generate()
        session = ControlSession(key=key, producer='tests.user', workflow_id='test.workflow',
                                 node_name='my_node', target_id='local-file', control_id='pause-1')
        effect = self.root / ('effect-' + str(len(list(self.root.iterdir()))))
        def user_node(state):
            effect.write_bytes(b'PRIVATE_APPLICATION_PAYLOAD')
            return {'done': True}
        hook = session.wrap_node(user_node)
        builder = StateGraph(dict)
        builder.add_node('my_node', hook if wrapped else user_node)
        builder.add_edge(START, 'my_node'); builder.add_edge('my_node', END)
        graph = builder.compile(checkpointer=InMemorySaver())
        bundle = session.invoke(graph, {'done': False}, thread_id='new-thread',
                                observer=FileObserver(effect) if observed else None, honor_pause=honor)
        return bundle, key, trust_for(key), effect, session, graph

    def result(self, bundle, trust, query=None):
        return consume(encoded(bundle), ops=from_bytes(encoded(trust)), expected_identity=query or bundle['identity'])

    def test_real_caller_graph_pauses_before_user_effect(self):
        b, key, trust, effect, session, graph = self.run_graph()
        r = self.result(b, trust)
        self.assertFalse(effect.exists())
        self.assertEqual(r['consumer']['policy_result'], 'MATCH')
        self.assertEqual(r['consumer']['observation']['execution'], 'PAUSED_REPORTED')
        self.assertEqual(r['native']['summary']['status'], 'INCOMPLETE')
        self.assertTrue(b['identity']['checkpoint_id'])

    def test_ignored_pause_runs_real_user_code_and_does_not_match(self):
        b, _, trust, effect, *_ = self.run_graph(honor=False)
        r = self.result(b, trust)
        self.assertEqual(effect.read_bytes(), b'PRIVATE_APPLICATION_PAYLOAD')
        self.assertEqual(r['consumer']['observation']['execution'], 'CONTINUED_REPORTED')
        self.assertEqual(r['consumer']['observation']['effect'], 'CHANGED_REPORTED')
        self.assertEqual(r['consumer']['policy_result'], 'NO_MATCH')
        self.assertEqual(r['native']['summary']['status'], 'FAILURE')

    def test_missing_observer_is_not_quiescence(self):
        b, _, trust, *_ = self.run_graph(observed=False)
        r = self.result(b, trust)
        self.assertEqual(r['consumer']['observation']['effect'], 'MISSING')
        self.assertEqual(r['consumer']['policy_result'], 'NO_MATCH')

    def test_uninstrumented_graph_cannot_invent_receipt_or_pause(self):
        b, _, trust, effect, *_ = self.run_graph(wrapped=False)
        r = self.result(b, trust)
        self.assertTrue(effect.exists())
        self.assertEqual(r['consumer']['observation']['receipt'], 'MISSING')
        self.assertEqual(r['consumer']['observation']['execution'], 'MISSING')
        self.assertEqual(r['consumer']['policy_result'], 'NO_MATCH')

    def test_foreign_run_query_does_not_reuse_old_pause(self):
        b, _, trust, *_ = self.run_graph()
        query = dict(b['identity'], run_id='another-run')
        r = self.result(b, trust, query)
        self.assertFalse(r['consumer']['identity_matches_query'])
        self.assertEqual(r['consumer']['observation']['execution'], 'MISSING')

    def test_changed_source_rejected_even_with_unchanged_valid_signature(self):
        b, _, trust, *_ = self.run_graph()
        event = json.loads(b['sources'][-1]); event['identity']['control_id'] = 'another-control'
        b['sources'][-1] = encoded(event).decode()
        r = self.result(b, trust)
        self.assertTrue(r['consumer']['errors'])
        self.assertEqual(r['consumer']['policy_result'], 'NO_MATCH')

    def test_validly_resigned_wrong_projection_does_not_match(self):
        b, key, trust, *_ = self.run_graph()
        effect = b['artifacts'][-1]
        effect['observed_state']['state_digest'] = digest_bytes(b'fabricated')
        effect['integrity']['current'] = verifier.compute_current(effect)
        effect['integrity']['signature']['value'] = key.sign(verifier.record_sig_preimage(
            '0.2', 'effect', 'ed25519', effect['integrity']['current'])).hex()
        r = self.result(b, trust)
        self.assertFalse(r['native']['records'][-1]['class_result']['authenticated_failures'])
        self.assertEqual(r['consumer']['observation']['effect'], 'INDETERMINATE')

    def test_broken_signature_is_not_a_successful_mapping(self):
        b, _, trust, *_ = self.run_graph()
        b['artifacts'][-1]['integrity']['signature']['value'] = '0' * 128
        self.assertEqual(self.result(b, trust)['consumer']['policy_result'], 'NO_MATCH')

    def resign_scopes(self, bundle, key, changes):
        # Rebuild the entire chain: negatives must retain valid signatures,
        # hashes and predecessor links, including when only one scope changes.
        from airep import Chain
        from airep.mapping import project
        b = copy.deepcopy(bundle)
        rows, _ = project([s.encode() for s in b['sources']], b['identity'], b['producer'])
        chain = Chain(key, b['producer'], chain_id=b['identity']['run_id'] + '.chain')
        b['artifacts'] = [chain.emit(row['family'], row['payload'],
            record_id=b['identity']['run_id'] + '.' + row['name'], timestamp=row['timestamp'],
            scope=changes.get(i, bundle['artifacts'][i]['scope'])) for i, row in enumerate(rows)]
        return b

    def assert_scope_rejected(self, bundle, key, trust, changes):
        original = self.result(bundle, trust)
        changed = self.resign_scopes(bundle, key, changes)
        r = self.result(changed, trust)
        self.assertEqual(r['native']['summary'], original['native']['summary'])
        for row in r['native']['records']:
            self.assertEqual(row['admission'], 'SATISFIED')
            self.assertFalse(row['class_result']['authenticated_failures'])
            self.assertFalse(row['class_result']['authenticated_withheld'])
        self.assertEqual(r['consumer']['policy_result'], 'NO_MATCH')
        self.assertEqual(r['consumer']['observation']['effect'], 'INDETERMINATE')
        self.assertEqual(r['consumer']['errors'], ['signed artifact scope differs from SDK contract'])

    def test_each_validly_resigned_artifact_rejects_expanded_scope(self):
        b, key, trust, *_ = self.run_graph()
        for i, artifact in enumerate(b['artifacts']):
            for claim in ('Continuous, independently verified full workflow stop',
                          'Production enforcement certified', 'SYNTHETIC_PRIVATE_SCOPE_MARKER'):
                with self.subTest(artifact=i, claim=claim):
                    scope = copy.deepcopy(artifact['scope'])
                    scope['covers'].append(claim)
                    self.assert_scope_rejected(b, key, trust, {i: scope})

    def test_each_artifact_requires_every_scope_exclusion(self):
        b, key, trust, *_ = self.run_graph()
        for i, artifact in enumerate(b['artifacts']):
            for j in range(len(artifact['scope']['does_not_cover'])):
                with self.subTest(artifact=i, missing_exclusion=j):
                    scope = copy.deepcopy(artifact['scope'])
                    del scope['does_not_cover'][j]
                    self.assert_scope_rejected(b, key, trust, {i: scope})

    def test_consistently_expanded_scope_across_entire_chain_is_rejected(self):
        b, key, trust, *_ = self.run_graph()
        changes = {}
        for i, artifact in enumerate(b['artifacts']):
            scope = copy.deepcopy(artifact['scope'])
            scope['covers'] = ['Production enforcement certified']
            scope['does_not_cover'] = []
            changes[i] = scope
        self.assert_scope_rejected(b, key, trust, changes)

    def test_scope_contract_is_exact_not_free_text_inference(self):
        b, key, trust, *_ = self.run_graph()
        scope = copy.deepcopy(b['artifacts'][-1]['scope'])
        scope['does_not_cover'].reverse()
        self.assert_scope_rejected(b, key, trust, {len(b['artifacts']) - 1: scope})

    def test_previous_scope_basis_is_not_silently_reinterpreted(self):
        b, _, trust, *_ = self.run_graph()
        # Exact contract digest from the retained 0.1.0a2 wheel.
        b['basis'] = 'sha256:d75d8ec2cb52e05802b3e678327ae34452ddc1a7f786902587e905258a87b398'
        with self.assertRaisesRegex(ValueError, 'unknown or malformed SDK mapping basis'):
            self.result(b, trust)

    def test_no_implicit_trust_from_producer_bundle(self):
        b, *_ = self.run_graph()
        self.assertEqual(self.result(b, {})['consumer']['observation']['execution'], 'INDETERMINATE')

    def test_one_session_cannot_be_reused_as_restart_evidence(self):
        b, key, trust, effect, session, graph = self.run_graph()
        with self.assertRaises(ValueError):
            session.invoke(graph, {}, thread_id='new-thread')
        other = ControlSession(key=key, producer='tests.user', workflow_id='test.workflow', node_name='my_node', target_id='local-file', control_id='pause-2')
        other.wrap_node(lambda state: state)
        with self.assertRaises(ValueError):
            other.invoke(graph, {}, thread_id='new-thread')

    def test_graph_must_be_actual_compiled_stategraph(self):
        s = ControlSession(key=Ed25519PrivateKey.generate(), producer='tests.user', workflow_id='w', node_name='n', target_id='t', control_id='c')
        s.wrap_node(lambda state: state)
        with self.assertRaises(TypeError):
            s.invoke(object(), {}, thread_id='fresh')

    def test_async_node_is_explicitly_outside_scope(self):
        s = ControlSession(key=Ed25519PrivateKey.generate(), producer='tests.user', workflow_id='w', node_name='n', target_id='t', control_id='c')
        async def node(state):
            return state
        with self.assertRaises(TypeError):
            s.wrap_node(node)

    def test_key_must_be_explicit_before_application_execution(self):
        with self.assertRaises(TypeError):
            ControlSession(key=None, producer='tests.user', workflow_id='w', node_name='n', target_id='t', control_id='c')

    def test_process_epoch_stable_across_distinct_runs(self):
        first, *_ = self.run_graph()
        second, *_ = self.run_graph()
        self.assertEqual(first['identity']['runtime_epoch'], second['identity']['runtime_epoch'])
        self.assertNotEqual(first['identity']['run_id'], second['identity']['run_id'])

    def test_profile_digest_and_path_boundaries_remain_native(self):
        schema = {'$schema': 'https://json-schema.org/draft/2020-12/schema', 'type': 'integer', 'minimum': 0}
        raw = encoded(schema)
        (self.root/'schema.json').write_bytes(raw)
        registry = {'profiles': {'tests.numeric': {'schema_path': 'schema.json', 'basis_digest': digest_bytes(raw)}}}
        (self.root/'registry.json').write_bytes(encoded(registry))
        bases = ProfileBases(str(self.root/'registry.json'))
        result = bases.evaluate({'profiles': {'tests.numeric': 1, 'tests.unknown': {'x': 1}}})
        self.assertEqual(result['tests.numeric']['result'], 'PASS')
        self.assertEqual(result['tests.unknown']['result'], 'NOT_EVALUATED')
        self.assertEqual(bases.evaluate({'profiles': {'tests.numeric': -1}})['tests.numeric']['result'], 'FAIL')
        registry['profiles']['tests.numeric']['basis_digest'] = digest_bytes(b'wrong')
        (self.root/'registry.json').write_bytes(encoded(registry))
        with self.assertRaises(ValueError):
            ProfileBases(str(self.root/'registry.json'))
        nested = self.root/'nested'; nested.mkdir()
        registry['profiles']['tests.numeric'] = {'schema_path': '../schema.json', 'basis_digest': digest_bytes(raw)}
        (nested/'registry.json').write_bytes(encoded(registry))
        with self.assertRaises(ValueError):
            ProfileBases(str(nested/'registry.json'))

    def test_output_contains_neither_effect_content_nor_private_key(self):
        b, key, _, *_ = self.run_graph(honor=False)
        raw = encoded(b)
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex().encode()
        self.assertNotIn(b'PRIVATE_APPLICATION_PAYLOAD', raw)
        self.assertNotIn(seed, raw)
        self.assertNotIn(str(self.root).encode(), raw)

    def test_application_interrupt_payload_rejected_before_evidence_serialization(self):
        from langgraph.types import interrupt
        session = ControlSession(key=Ed25519PrivateKey.generate(), producer='tests.user',
            workflow_id='w', node_name='n', target_id='t', control_id='c')
        def application(state):
            interrupt({'private_application_value': state['secret']})
        graph = StateGraph(dict)
        graph.add_node('n', session.wrap_node(application))
        graph.add_edge(START, 'n'); graph.add_edge('n', END)
        marker = 'SYNTHETIC_PRIVATE_INTERRUPT_MARKER'
        with self.assertRaisesRegex(ValueError, 'application interrupt payload') as error:
            session.invoke(graph.compile(checkpointer=InMemorySaver()), {'secret': marker},
                           thread_id='fresh', honor_pause=False)
        self.assertNotIn(marker, str(error.exception))
        self.assertNotIn(marker.encode(), b''.join(session._events))
        self.assertFalse(any(json.loads(raw)['kind'] == 'native_result' for raw in session._events))

    def test_consumer_rejects_foreign_interrupt_without_echoing_its_payload(self):
        b, _, trust, *_ = self.run_graph()
        events = [json.loads(raw) for raw in b['sources']]
        native = next(e for e in events if e['kind'] == 'native_result')['data']
        native['interrupts'] = native['checkpoint_interrupts'] = [{'secret': 'SYNTHETIC_PRIVATE_MARKER'}]
        b['sources'] = [encoded(e).decode() for e in events]
        result = self.result(b, trust)
        self.assertEqual(result['consumer']['policy_result'], 'NO_MATCH')
        self.assertIn('application interrupt payload', result['consumer']['errors'][0])
        self.assertNotIn(b'SYNTHETIC_PRIVATE_MARKER', encoded(result))

    def test_observation_samples_bracket_receipt_and_native_result(self):
        original, _, trust, *_ = self.run_graph()
        for case in ('both-before-receipt', 'initial-after-receipt', 'final-before-native-result'):
            with self.subTest(case=case):
                b = copy.deepcopy(original)
                events = [json.loads(raw) for raw in b['sources']]
                by_kind = {e['kind']: e for e in events}
                data = by_kind['effect_sampled']['data']
                if case == 'both-before-receipt':
                    for sample in data.values():
                        sample['start'] = sample['end'] = by_kind['dispatched']['tick']
                elif case == 'initial-after-receipt':
                    data['before']['start'] = data['before']['end'] = by_kind['native_result']['tick']
                else:
                    data['after']['start'] = data['after']['end'] = by_kind['received']['tick']
                b['sources'] = [encoded(e).decode() for e in events]
                result = self.result(b, trust)
                self.assertEqual(result['consumer']['policy_result'], 'NO_MATCH')
                self.assertEqual(result['consumer']['observation']['effect'], 'INDETERMINATE')
                self.assertTrue(any('sample' in message for message in result['consumer']['errors']))

    def test_duplicate_members_depth_and_size_are_rejected(self):
        for raw in (b'{"x":1,"x":2}', b'[' * 33 + b'0' + b']' * 33, b' ' * (1024*1024+1)):
            with self.assertRaises(ValueError):
                bounded_loads(raw)
        self.assertEqual(bounded_loads(b'{"brackets":"[[[{{{\\\""}'), {'brackets': '[[[{{{"'})

    def test_raw_core_sequence_boundary_before_rounding(self):
        with self.assertRaises(ValueError):
            artifacts(b'[{"sequence":9007199254740991.1}]')
        b, _, trust, *_ = self.run_graph()
        raw = encoded(b).replace(b'"sequence":0', b'"sequence":9007199254740991.1', 1)
        with self.assertRaises(ValueError):
            consume(raw, ops=from_bytes(encoded(trust)), expected_identity=b['identity'])

    def test_input_and_parent_symlinks_are_rejected(self):
        target = self.root / 'input'; target.write_bytes(b'{}')
        link = self.root / 'link'; link.symlink_to(target)
        parent = self.root / 'parent'; parent.symlink_to(self.root, target_is_directory=True)
        for path in (link, parent / 'input'):
            with self.assertRaises(OSError):
                read_bytes(path)
        with self.assertRaises(OSError):
            write_bytes(parent / 'new', b'no')

    def test_fifo_and_growing_or_large_file_are_not_read(self):
        fifo = self.root / 'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            read_bytes(fifo)
        large = self.root / 'large'; large.write_bytes(b'x' * 65537)
        with self.assertRaises(ValueError):
            FileObserver(large).sample(lambda: 0)

    def test_no_overwrite_and_private_output_mode(self):
        path = self.root / 'result'
        write_bytes(path, b'first')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            write_bytes(path, b'second')
        self.assertEqual(path.read_bytes(), b'first')

    def cli_files(self):
        b, _, trust, *_ = self.run_graph(observed=False)
        for name, val in [('input', b), ('trust', trust), ('query', b['identity'])]:
            (self.root / name).write_bytes(encoded(val))
        return [sys.executable, '-I', '-m', 'airep', 'consume', '--input', str(self.root/'input'),
                '--trust', str(self.root/'trust'), '--query', str(self.root/'query')]

    def test_cli_completion_zero_is_not_policy_match(self):
        command = self.cli_files()
        done = subprocess.run(command, capture_output=True, timeout=20)
        gate = subprocess.run(command + ['--require-policy-match'], capture_output=True, timeout=20)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(gate.returncode, 3, gate.stderr)
        self.assertEqual(json.loads(done.stdout)['consumer']['policy_result'], 'NO_MATCH')

    def test_cli_timeout_emits_no_partial_result(self):
        output = self.root / 'result'
        result = subprocess.run(self.cli_files() + ['--timeout', '0.000001', '--out', str(output)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertEqual(result.stdout, b'')
        self.assertFalse(output.exists())

    def test_cli_rejects_nonfinite_timeout(self):
        result = subprocess.run(self.cli_files() + ['--timeout', 'nan'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')

    def test_installed_resource_hashes_and_native_version(self):
        self.assertEqual(MANIFEST['native_version'], '0.2.0-beta.1')
        for row in MANIFEST['files']:
            self.assertEqual(hashlib.sha256((PACKAGE / row['package_path']).read_bytes()).hexdigest(), row['sha256'])
        self.assertTrue(any(r['repository_path'].endswith('/jcs.py') for r in MANIFEST['files']))
        self.assertEqual(len([r for r in MANIFEST['files'] if '/schemas/' in r['package_path'] and r['package_path'].endswith('.schema.json')]), 5)
        packaged = PACKAGE/'_basis/spec/airep/v0.2/profiles/embedded-evaluation/registry.json'
        self.assertTrue(ProfileBases(str(packaged)).validators)

    def test_tampered_packaged_schema_fails_before_loading_verifier(self):
        copy_root=self.root/'tampered'; copy_root.mkdir()
        shutil.copytree(PACKAGE,copy_root/'airep',ignore=shutil.ignore_patterns('__pycache__'))
        path=copy_root/'airep/_basis/spec/airep/v0.2/schemas/common.schema.json'
        path.write_bytes(path.read_bytes()+b' ')
        code='import sys; sys.path.insert(0, '+repr(str(copy_root))+'); import airep'
        result=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'SDK resource integrity mismatch',result.stderr)


if __name__ == '__main__':
    unittest.main()
