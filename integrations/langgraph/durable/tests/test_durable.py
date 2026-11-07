import copy
import itertools
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from integrations.langgraph.run import encoded, ROOT
from integrations.langgraph.temporal.runtime_source import query_for
from tools.airep_v02.json_input import loads
from tools.airep_v02.verify import evaluate_request
from integrations.langgraph.durable.capture import capture, sha
from integrations.langgraph.durable.consumer import evaluate
from integrations.langgraph.durable.report import make_inputs, replay
from integrations.langgraph.durable.source import DurableReports, DurablePolicy, CONTRACT


class DurableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='airep-durable-tests-')
        cls.root = Path(cls.scratch.name)
        cls.inputs = make_inputs(cls.root)
        cls.captured = {mode: [loads(line) for line in (cls.root / mode / 'sources.jsonl').read_bytes().splitlines()]
                        for mode in ('repeat', 'idempotent')}

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def setUp(self):
        self.factory = DurableReports()
        self.source = copy.deepcopy(self.captured['repeat'][3])
        self.row = self.factory.delivery(encoded(self.source), arrival=1)

    def result(self, rows=None, query=None):
        return evaluate(rows or [self.row], query or query_for(self.row), self.factory.sources, self.factory.ops)

    def test_T05_actual_disk_checkpoint_new_process_and_same_state(self):
        for mode in ('repeat', 'idempotent'):
            root = self.root / mode
            pause = loads((root / 'pause-worker.json').read_bytes())
            resume = loads((root / 'resume-worker.json').read_bytes())
            self.assertNotEqual(pause['pid'], resume['pid'])
            self.assertNotEqual(pause['runtime_epoch'], resume['runtime_epoch'])
            self.assertEqual(pause['thread_id'], resume['thread_id'])
            self.assertEqual(pause['run_id'], resume['run_id'])
            self.assertEqual(pause['terminal'], resume['loaded'])
            self.assertNotEqual(resume['loaded']['checkpoint_id'], resume['terminal']['checkpoint_id'])
            self.assertEqual(resume['checkpoint_before_hash'], sha((root / 'pause-checkpoint.sqlite').read_bytes()))
            with sqlite3.connect(root / 'pause-checkpoint.sqlite') as db:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone(), ('ok',))
                ids = {r[0] for r in db.execute('SELECT checkpoint_id FROM checkpoints')}
                self.assertIn(resume['loaded']['checkpoint_id'], ids)
            lifecycle = loads((root / 'lifecycle.json').read_bytes())
            self.assertLess(lifecycle[0]['end'], lifecycle[1]['start'])
            self.assertTrue(all(r['exitcode'] == 0 and not r['forced_cleanup'] for r in lifecycle))

    def test_T06_node_replay_and_idempotent_counterexample_are_measured(self):
        for mode, before_count, total in (('repeat', 2, 3), ('idempotent', 1, 2)):
            root = self.root / mode
            events = [e for phase in ('pause', 'resume')
                      for e in loads((root / (phase + '-worker.json')).read_bytes())['events']]
            invocations = [e['data']['invocation_id'] for e in events if e['kind'] == 'node_entered']
            self.assertEqual(len(set(invocations)), 2)
            attempts = [e for e in events if e['kind'] == 'effect_attempt']
            self.assertEqual(len(attempts), 3)
            self.assertEqual(sum(e['data']['inserted'] for e in attempts), total)
            with sqlite3.connect(root / 'business.sqlite') as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM effects').fetchone()[0], total)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM effects WHERE stage='before_interrupt'").fetchone()[0], before_count)
            a, b = self.captured[mode][0]['identity'], self.captured[mode][2]['identity']
            self.assertEqual(a['attempt_id'], b['attempt_id'])
            self.assertEqual(a['control_id'], b['control_id'])

    def test_T04_reused_event_id_retains_both_epochs(self):
        old = self.factory.delivery(encoded(self.captured['repeat'][1]), arrival=2)
        result = self.result([self.row, old])
        self.assertEqual(len(result['history']), 2)
        self.assertEqual({r['event']['event_id'] for r in result['history']}, {'effect-1'})
        self.assertFalse(result['identity_conflict'])
        self.assertEqual(result['duplicate_deliveries'], 0)
        self.assertEqual(result['stages']['effect']['status'], 'CONTINUED_REPORTED')

    def test_T04_each_identity_field_is_required_for_correlation(self):
        for key in self.source['identity']:
            query = query_for(self.row); query['identity'][key] = 'other'
            with self.subTest(key=key):
                result = self.result(query=query)
                self.assertEqual(result['stages']['effect']['status'], 'MISSING')
                self.assertEqual(len(result['history']), 1)

    def test_missing_epoch_is_not_guessed(self):
        source = copy.deepcopy(self.source); del source['identity']['runtime_epoch']
        with self.assertRaises(ValueError):
            DurablePolicy.project(encoded(source))
        query = query_for(self.row); del query['identity']['runtime_epoch']
        with self.assertRaises(ValueError):
            self.result(query=query)

    def test_T07_old_pause_never_overwrites_current_resume_in_any_arrival_order(self):
        rows = [self.factory.delivery(encoded(s), arrival=i + 1) for i, s in enumerate(self.captured['repeat'][:4])]
        baseline = self.result(rows)
        self.assertEqual(baseline['stages']['execution']['status'], 'CONTINUED_REPORTED')
        for permutation in itertools.permutations(rows):
            self.assertEqual(self.result(list(permutation)), baseline)
        self.assertIn('PAUSED', {r['event']['status'] for r in baseline['history']})

    def test_T07_quiet_window_is_not_permanent_or_execution_state(self):
        views = replay(self.inputs)
        historical = views[0]['result']; later = views[7]['result']
        self.assertEqual(historical['stages']['execution']['status'], 'PAUSED_REPORTED')
        self.assertEqual(later['stages']['execution']['status'], 'CONTINUED_REPORTED')
        self.assertEqual(later['stages']['effect']['status'], 'QUIESCENT_REPORTED')
        self.assertEqual(later['stages']['receipt']['status'], 'MISSING')
        self.assertIn('CONTINUED', {r['event']['status'] for r in later['history']})

    def test_T08_conflict_and_unordered_clocks_keep_both_sources(self):
        views = replay(self.inputs)
        for index in (9, 10, 11):
            result = views[index]['result']
            self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
            self.assertEqual(len(result['history']), 3)
            self.assertTrue(all(r['native_verification']['class'] == 'AIREP-Authenticated' for r in result['history']))
        self.assertTrue(views[10]['result']['ordering_unestablished'])
        self.assertTrue(views[11]['result']['overlap_requires_reconciliation'])
        self.assertFalse(views[9]['result']['overlap_requires_reconciliation'])

    def test_T08_non_equivalent_window_cannot_substitute_for_requested_window(self):
        query = query_for(self.row); query['window'][0] -= 1
        self.assertEqual(self.result(query=query)['stages']['effect']['status'], 'MISSING')

    def test_replay_serialization_is_exact_and_all_12_views_match(self):
        a, b = replay(self.inputs), replay(loads(encoded(self.inputs)))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 12)
        self.assertEqual(a[2]['result'], a[3]['result'])

    def test_measured_sources_exist_byte_exact_and_fixtures_are_labeled(self):
        captured = {line for mode in ('repeat', 'idempotent')
                    for line in (self.root / mode / 'sources.jsonl').read_bytes().splitlines(keepends=True)}
        self.assertEqual(len(captured), 10)
        for case in self.inputs['cases']:
            if 'negative fixture' in case['origin']:
                continue
            for row in case['deliveries']:
                event = loads(row['event_bytes'].encode())
                self.assertIn(self.inputs['sources'][event['source_ref']].encode(), captured)

    def test_source_byte_tamper_is_rejected(self):
        event = loads(self.row['event_bytes'])
        self.factory.sources[event['source_ref']] += b' '
        result = self.result()
        self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
        self.assertIn('hash mismatch', result['binding_errors'][0]['reason'])

    def test_valid_signature_cannot_relabel_projection_or_basis(self):
        for field in ('runtime_epoch', 'checkpoint_id', 'control_id', 'window', 'status', 'basis_digest'):
            event = loads(self.row['event_bytes'])
            if field in event['identity']:
                event['identity'][field] = 'forged'
            elif field == 'window':
                event['window'][0] += 1
            elif field == 'status':
                event[field] = 'QUIESCENT'
            else:
                event[field] = 'sha256:' + '0' * 64
            forged = self.factory.bind_event(event, 1, self.source['timestamp_utc'])
            with self.subTest(field=field):
                self.assertTrue(self.result([forged])['binding_errors'])

    def test_R3_signed_stronger_scope_and_missing_limits_are_rejected(self):
        scopes = []
        for i in range(len(CONTRACT['artifact_scope']['does_not_cover'])):
            scope = copy.deepcopy(CONTRACT['artifact_scope']); del scope['does_not_cover'][i]; scopes.append(scope)
        scope = copy.deepcopy(CONTRACT['artifact_scope']); scope['covers'].append('Independent enforced stop'); scopes.append(scope)
        event = loads(self.row['event_bytes'])
        baseline = evaluate_request({'artifact': self.row['artifact'], 'related_artifacts': []}, ops=self.factory.ops)
        for scope in scopes:
            row = self.factory.bind_event(event, 1, self.source['timestamp_utc'], scope=scope)
            native = evaluate_request({'artifact': row['artifact'], 'related_artifacts': []}, ops=self.factory.ops)
            self.assertEqual(native['class'], baseline['class'])
            self.assertEqual(native['authenticated_failures'], baseline['authenticated_failures'])
            self.assertEqual(native['authenticated_withheld'], baseline['authenticated_withheld'])
            result = self.result([row])
            self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
            self.assertIn('scope differs', result['binding_errors'][0]['reason'])

    def test_R3_signed_stronger_assertion_is_rejected(self):
        event = loads(self.row['event_bytes'])
        row = self.factory.bind_event(event, 1, self.source['timestamp_utc'], assertion='Proves independently enforced permanent stop')
        self.assertIn('claim differs', self.result([row])['binding_errors'][0]['reason'])

    def test_native_authentication_is_not_bypassed(self):
        self.factory.ops.bindings_doc = None
        result = self.result()
        self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
        self.assertTrue(result['binding_errors'][0]['native_verification']['authenticated_withheld'])

    def test_source_rejects_replaced_truncated_foreign_or_malformed_rows(self):
        for rows in ([['bad']], [[True, 'x', 'before_interrupt', self.source['identity']['run_id'], 'epoch', 'call']],
                     [[1, 'x', 'before_interrupt', 'another-run', 'epoch', 'call']], []):
            source = copy.deepcopy(self.source); source['data']['after']['rows_hex'] = encoded(rows).hex()
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                DurablePolicy.project(encoded(source))

    def test_source_rejects_unordered_samples(self):
        source = copy.deepcopy(self.source)
        source['data']['before']['end'] = source['tick'] + 1
        with self.assertRaises(ValueError):
            DurablePolicy.project(encoded(source))

    def test_resume_requires_checkpoint_thread_run_epoch_pid_and_payload_continuity(self):
        original = self.captured['repeat'][2]
        mutations = ('checkpoint_id', 'loaded', 'pid', 'runtime_epoch', 'thread_id', 'run_id', 'control_id',
                     'checkpoint_before_hash', 'mode', 'result_interrupts', 'events')
        for field in mutations:
            source = copy.deepcopy(original)
            worker = loads(bytes.fromhex(source['data']['worker_hex']))
            prior = loads(bytes.fromhex(source['data']['pause_worker_hex']))
            if field == 'checkpoint_id': worker['loaded']['checkpoint_id'] = 'other'
            elif field == 'loaded': worker['loaded'] = None
            elif field in ('pid', 'runtime_epoch'): worker[field] = prior[field]
            elif field == 'result_interrupts': worker[field] = [{'operation': 'pause'}]
            elif field == 'events': worker[field] = []
            else: worker[field] = 'other'
            source['data']['worker_hex'] = encoded(worker).hex()
            with self.subTest(field=field), self.assertRaises(ValueError):
                DurablePolicy.project(encoded(source))

    def test_pause_requires_actual_pending_interrupt_payload(self):
        source = copy.deepcopy(self.captured['repeat'][0])
        worker = loads(bytes.fromhex(source['data']['worker_hex']))
        worker['terminal']['interrupts'] = []
        source['data']['worker_hex'] = encoded(worker).hex()
        with self.assertRaises(ValueError):
            DurablePolicy.project(encoded(source))

    def test_fresh_process_cannot_resume_a_missing_checkpoint(self):
        root = self.root / 'no-checkpoint'; root.mkdir()
        request = loads((self.root / 'repeat/request.json').read_bytes())
        (root / 'request.json').write_bytes(encoded(request))
        proc = subprocess.run([sys.executable, '-m', 'integrations.langgraph.durable.capture',
            '--worker', 'resume', '--directory', str(root)], cwd=ROOT, capture_output=True, timeout=30)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse((root / 'resume-worker.json').exists())

    def test_timeout_cleanup_cannot_produce_success_evidence(self):
        root = self.root / 'timeout'
        with self.assertRaisesRegex(RuntimeError, 'cleanup is not a successful pause'):
            capture(root, 'repeat', timeout=0)
        life = loads((root / 'lifecycle.json').read_bytes())
        self.assertTrue(life[0]['forced_cleanup'])
        self.assertNotEqual(life[0]['exitcode'], 0)
        self.assertFalse((root / 'sources.jsonl').exists())


if __name__ == '__main__':
    unittest.main()
