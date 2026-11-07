import copy
from pathlib import Path
import tempfile
import unittest

from tools.airep_v02.json_input import loads
from integrations.langgraph.run import encoded
from integrations.langgraph.temporal.core import evaluate
from integrations.langgraph.temporal.runtime_report import make_inputs, replay
from integrations.langgraph.temporal.runtime_source import RuntimeReports, RuntimeSourcePolicy, query_for


class CapturedRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='airep-captured-tests-')
        cls.root = Path(cls.scratch.name)
        cls.inputs = make_inputs(cls.root)
        cls.traces = {name: [loads(line) for line in (cls.root / name / 'events.jsonl').read_bytes().splitlines()]
                      for name in ('run-A', 'run-B', 'run-C')}

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def setUp(self):
        self.f = RuntimeReports()
        self.source = next(e for e in self.traces['run-B'] if e['kind'] == 'effect_sampled'
                           and e['data']['before']['bytes_hex'] != e['data']['after']['bytes_hex'])

    def result(self, rows, query=None):
        return evaluate(rows, query or query_for(rows[0]), self.f.sources, self.f.ops, source_policy=self.f.policy)

    def test_actual_runtime_files_checkpoints_and_cleanup(self):
        self.assertEqual((self.root / 'run-B' / 'effects.jsonl').read_bytes(), b'{"step":1}\n{"step":2}\n')
        for name in ('run-A', 'run-C'):
            self.assertFalse((self.root / name / 'effects.jsonl').exists())
        for events in self.traces.values():
            ready = events[0]
            self.assertEqual(ready['kind'], 'ready')
            self.assertTrue(ready['identity']['checkpoint_id'])
            self.assertEqual(ready['data']['checkpoint_next'], ['controlled_action'])
            self.assertGreater(ready['data']['pid'], 0)
            self.assertEqual(events[-1], {'kind': 'cleanup', 'forced': False, 'alive': False, 'exitcode': 0})

    def test_T01_T02_T03_T09_T10_T11_and_positive_replay(self):
        views = replay(self.inputs)
        self.assertEqual(len(views), 14)
        self.assertTrue(all(v['expected_effect'] == v['result']['stages']['effect']['status'] for v in views))
        self.assertEqual(views[1]['result'], views[2]['result'])
        self.assertEqual(len(views[7]['result']['history']), 2)
        self.assertEqual(views[9]['result']['duplicate_deliveries'], 1)

    def test_serialized_replay_reproduces_all_native_and_consumer_results(self):
        self.assertEqual(replay(self.inputs), replay(loads(encoded(self.inputs))))

    def test_every_report_source_is_byte_exact_in_the_captured_trace(self):
        captured = {line for name in self.traces
                    for line in (self.root / name / 'events.jsonl').read_bytes().splitlines(keepends=True)}
        self.assertTrue(self.inputs['sources'])
        for source in self.inputs['sources'].values():
            self.assertIn(source.encode(), captured)

    def test_native_pause_and_missing_effect_remain_distinct(self):
        views = {v['label']: v['result'] for v in replay(self.inputs)}
        missing = views['T11 receiver and pause / no observer']
        self.assertEqual([missing['stages'][k]['status'] for k in ('receipt', 'execution', 'effect')],
                         ['RECEIVED_REPORTED', 'PAUSED_REPORTED', 'MISSING'])
        positive = views['Positive native pause / matching samples']
        self.assertEqual(positive['stages']['effect']['status'], 'QUIESCENT_REPORTED')
        self.assertTrue(all(r['native_verification']['class'] == 'AIREP-Authenticated' for r in positive['history']))

    def test_same_run_two_actual_received_control_ids(self):
        received = [e for e in self.traces['run-B'] if e['kind'] == 'receiver_observed']
        self.assertEqual([e['identity']['control_id'] for e in received], ['pause-1', 'pause-2'])
        self.assertEqual(received[0]['identity']['run_id'], received[1]['identity']['run_id'])
        for source in received:
            command = loads(bytes.fromhex(source['data']['command_hex']))
            self.assertEqual(command['identity'], source['identity'])

    def test_identity_negatives_do_not_pass_only_because_windows_differ(self):
        for index in (4, 6):
            case = self.inputs['cases'][index]
            effects = [loads(row['event_bytes']) for row in case['deliveries']
                       if loads(row['event_bytes'])['kind'] == 'effect']
            self.assertEqual(len(effects), 1)
            self.assertEqual(effects[0]['window'], case['query']['window'])
            self.assertEqual(effects[0]['clock_id'], case['query']['clock_id'])
            self.assertNotEqual(effects[0]['identity'], case['query']['identity'])

    def test_signature_cannot_relabel_measured_run_control_window_or_state(self):
        row = self.f.delivery(encoded(self.source), arrival=1)
        for field in ('run_id', 'control_id', 'checkpoint_id', 'window', 'status'):
            with self.subTest(field=field):
                event = loads(row['event_bytes'])
                if field in event['identity']:
                    event['identity'][field] = 'forged'
                elif field == 'window':
                    event[field][0] += 1
                else:
                    event[field] = 'QUIESCENT'
                forged = self.f.bind_event(event, 1, self.source['timestamp_utc'])
                result = self.result([forged])
                self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
                self.assertIn('projection mismatch', result['binding_errors'][0]['reason'])

    def test_changed_source_bytes_fail_even_with_unchanged_event_signature(self):
        row = self.f.delivery(encoded(self.source), arrival=1)
        source_ref = loads(row['event_bytes'])['source_ref']
        self.f.sources[source_ref] += b' '
        self.assertIn('hash mismatch', self.result([row])['binding_errors'][0]['reason'])

    def test_signed_changed_basis_is_not_accepted(self):
        row = self.f.delivery(encoded(self.source), arrival=1)
        event = loads(row['event_bytes']); event['basis_digest'] = 'sha256:' + '0' * 64
        row = self.f.bind_event(event, 1, self.source['timestamp_utc'])
        self.assertIn('basis', self.result([row])['binding_errors'][0]['reason'])

    def test_two_signed_reports_with_same_id_different_content_have_no_winner(self):
        current = self.f.delivery(encoded(self.source), arrival=1)
        conflicting = copy.deepcopy(self.source)
        conflicting['data']['after']['bytes_hex'] = conflicting['data']['before']['bytes_hex']
        other = self.f.delivery(encoded(conflicting), arrival=2)
        for order in ([current, other], [other, current]):
            result = self.result(order, query_for(current))
            self.assertTrue(result['identity_conflict'])
            self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
            self.assertEqual(len(result['history']), 2)

    def test_effect_mapper_rejects_changed_truncated_or_malformed_history(self):
        for raw in (b'{"step":9}\n', b'{"step":true}\n', b'{"step":1}', b'{"step":1,"step":2}\n'):
            source = copy.deepcopy(self.source)
            source['data']['after']['bytes_hex'] = raw.hex()
            with self.assertRaises(ValueError):
                self.f.policy.project(encoded(source))

    def test_effect_mapper_rejects_reversed_or_incomparable_measurement_times(self):
        for field in ('start', 'end'):
            source = copy.deepcopy(self.source)
            source['data']['before'][field] = source['tick'] + 1
            with self.assertRaises(ValueError):
                self.f.policy.project(encoded(source))
        row = self.f.delivery(encoded(self.source), arrival=1)
        q = query_for(row); q['clock_id'] = 'unaccepted-clock'
        self.assertTrue(self.result([row], q)['ordering_unestablished'])

    def test_native_interrupt_requires_actual_matching_checkpoint_payload(self):
        original = next(e for e in self.traces['run-A'] if e['kind'] == 'native_interrupt_observed')
        for field in ('interrupts', 'checkpoint_interrupts', 'checkpoint_next', 'terminal_checkpoint_id'):
            source = copy.deepcopy(original)
            source['data'][field] = '' if field == 'terminal_checkpoint_id' else []
            with self.assertRaises(ValueError):
                self.f.policy.project(encoded(source))

    def test_receipt_does_not_accept_another_control_or_guess_missing_identity(self):
        source = copy.deepcopy(next(e for e in self.traces['run-B'] if e['kind'] == 'receiver_observed'))
        source['identity']['control_id'] = 'other'
        with self.assertRaises(ValueError):
            self.f.policy.project(encoded(source))
        source = copy.deepcopy(self.source); del source['identity']['runtime_epoch']
        with self.assertRaises(ValueError):
            self.f.policy.project(encoded(source))

    def test_fixture_policy_does_not_implicitly_accept_runtime_policy(self):
        row = self.f.delivery(encoded(self.source), arrival=1)
        result = evaluate([row], query_for(row), self.f.sources, self.f.ops)
        self.assertIn('unaccepted interpretation basis', result['binding_errors'][0]['reason'])

    def test_no_operator_binding_withholds_native_authentication(self):
        row = self.f.delivery(encoded(self.source), arrival=1)
        self.f.ops.bindings_doc = None
        result = self.result([row])
        self.assertEqual(result['stages']['effect']['status'], 'INDETERMINATE')
        self.assertTrue(result['binding_errors'][0]['native_verification']['authenticated_withheld'])


if __name__ == '__main__':
    unittest.main()
