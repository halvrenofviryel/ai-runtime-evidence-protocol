import copy
import itertools
import json
import unittest
from integrations.langgraph.temporal.core import evaluate
from integrations.langgraph.temporal.fixtures import FixtureFactory, encoded, query


class TemporalCore(unittest.TestCase):
    def setUp(self):
        self.f = FixtureFactory()

    def result(self, deliveries, q=None, **kw):
        return evaluate(deliveries, q or query(), self.f.sources, self.f.ops, **kw)

    def effect(self, deliveries, q=None):
        return self.result(deliveries, q)['stages']['effect']['status']

    def test_T01_late_old_window_does_not_overwrite_continued_execution(self):
        old = self.f.delivery('old', status='QUIESCENT', window=[0, 5], event_time=5, observed_time=5, arrival=30)
        new = self.f.delivery('new', arrival=20)
        for order in itertools.permutations([old, new]):
            r = self.result(order)
            self.assertEqual(r['stages']['effect']['status'], 'CONTINUED_REPORTED')
            self.assertEqual(len(r['history']), 2)
            self.assertEqual(next(x for x in r['history'] if x['event']['event_id'] == 'old')['arrival_time'], 30)
        earlier = query(); earlier['window'] = [0, 5]; earlier['cutoff'] = 5
        self.assertEqual(self.effect([old, new], earlier), 'QUIESCENT_REPORTED')

    def test_T02_old_control_cannot_settle_new_control(self):
        old = self.f.delivery('old-control', status='QUIESCENT', identity=query(control_id='pause-1')['identity'])
        self.assertEqual(self.effect([old]), 'MISSING')
        self.assertEqual(self.effect([old], query(control_id='pause-1')), 'QUIESCENT_REPORTED')

    def test_T03_old_run_cannot_settle_active_run(self):
        old = self.f.delivery('old-run', status='QUIESCENT', identity=query(run_id='run-A')['identity'], arrival=30)
        new = self.f.delivery('active-run')
        self.assertEqual(self.effect([old]), 'MISSING')
        self.assertEqual(self.effect([new, old]), 'CONTINUED_REPORTED')
        self.assertEqual(self.effect([new, old], query(run_id='run-A')), 'QUIESCENT_REPORTED')

    def test_positive_control_stages_are_separate(self):
        rows = [self.f.delivery('receipt', kind='receipt', status='RECEIVED'),
                self.f.delivery('pause', kind='execution', status='PAUSED'),
                self.f.delivery('effect', status='QUIESCENT')]
        r = self.result(rows)
        self.assertEqual([r['stages'][k]['status'] for k in ('receipt', 'execution', 'effect')],
                         ['RECEIVED_REPORTED', 'PAUSED_REPORTED', 'QUIESCENT_REPORTED'])
        self.assertEqual(self.effect(rows[:2]), 'MISSING')

    def test_T09_duplicate_idempotence_and_reorder(self):
        event = self.f.delivery('duplicate')
        duplicate = copy.deepcopy(event); duplicate['arrival_time'] = 25
        a, b = self.result([event, duplicate]), self.result([duplicate, event])
        self.assertEqual(a, b)
        self.assertEqual(a['duplicate_deliveries'], 1)
        self.assertEqual(len(a['history']), 1)

    def test_T09_same_identity_different_content_has_no_winner(self):
        a, b = self.f.delivery('collision'), self.f.delivery('collision', status='QUIESCENT')
        for order in ([a, b], [b, a]):
            r = self.result(order)
            self.assertTrue(r['identity_conflict'])
            self.assertEqual(r['stages']['effect']['status'], 'INDETERMINATE')
            self.assertEqual(len(r['history']), 2)

    def test_same_event_in_multiple_signed_reports_retains_all_references(self):
        a = self.f.delivery('repeated')
        b = self.f.bind(json.loads(a['event_bytes']), arrival=25)
        r = self.result([a, b])
        self.assertEqual(r, self.result([b, a]))
        self.assertEqual(len(r['history']), 1)
        self.assertEqual(len(r['history'][0]['bound_reports']), 2)

    def test_T10_tampered_event_bytes_and_wrong_pointer(self):
        for mutation in ('event', 'pointer', 'signature'):
            with self.subTest(mutation=mutation):
                row = self.f.delivery('test')
                if mutation == 'event':
                    e = json.loads(row['event_bytes']); e['identity']['run_id'] = 'another-run'
                    row['event_bytes'] = encoded(e)
                elif mutation == 'pointer':
                    row['event_ref'] = 'not-the-signed-reference'
                else:
                    row['artifact']['integrity']['signature']['value'] = '0' * 128
                r = self.result([row])
                self.assertTrue(r['binding_errors'])
                self.assertEqual(r['stages']['effect']['status'], 'INDETERMINATE')
                if mutation == 'signature':
                    self.assertTrue(r['binding_errors'][0]['native_verification']['authenticated_failures'])

    def test_malformed_native_artifact_is_visible_failure_not_crash(self):
        row = self.f.delivery('malformed')
        del row['artifact']['scope']
        r = self.result([row])
        self.assertTrue(r['binding_errors'])
        self.assertEqual(r['stages']['effect']['status'], 'INDETERMINATE')

    def test_T10_source_bytes_and_interpretation_basis_are_checked(self):
        row = self.f.delivery('test')
        e = json.loads(row['event_bytes'])
        self.f.sources[e['source_ref']] += b' '
        self.assertTrue(self.result([row])['binding_errors'])
        row = self.f.delivery('basis')
        e = json.loads(row['event_bytes']); e['basis_digest'] = 'sha256:' + '0' * 64
        self.assertTrue(self.result([self.f.bind(e)])['binding_errors'])

    def test_T10_valid_signature_cannot_relabel_source_identity(self):
        row = self.f.delivery('identity')
        e = json.loads(row['event_bytes']); e['identity']['run_id'] = 'run-A'
        self.assertTrue(self.result([self.f.bind(e)])['binding_errors'])

    def test_T11_missing_observer_and_wrong_window_are_not_continued(self):
        self.assertEqual(self.effect([]), 'MISSING')
        row = self.f.delivery('wrong-window', window=[0, 5], status='QUIESCENT')
        self.assertEqual(self.effect([row]), 'MISSING')
        self.assertEqual(self.effect([self.f.delivery('continued')]), 'CONTINUED_REPORTED')

    def test_unaccepted_clock_does_not_order_events(self):
        self.assertEqual(self.effect([self.f.delivery('clock', clock_id='other-clock')]), 'INDETERMINATE')

    def test_wrong_boundary_or_predicate_cannot_supply_effect(self):
        for field in ('boundary', 'predicate_id'):
            row = self.f.delivery(field, status='QUIESCENT', **{field: 'other'})
            self.assertEqual(self.effect([row]), 'MISSING')

    def test_epoch_target_attempt_and_checkpoint_boundaries(self):
        for key in ('runtime_epoch', 'target_id', 'attempt_id', 'checkpoint_id', 'workflow_id'):
            with self.subTest(key=key):
                row = self.f.delivery(key, status='QUIESCENT', identity=query(**{key: 'other'})['identity'])
                self.assertEqual(self.effect([row]), 'MISSING')

    def test_same_window_conflict_requires_explicit_authorized_revision(self):
        old = self.f.delivery('old', status='QUIESCENT')
        later = self.f.delivery('revision', event_time=12, observed_time=12,
                               supersedes='old', revision_reason='corrected fixture observation')
        self.assertEqual(self.effect([old, later]), 'INDETERMINATE')
        r = self.result([later, old], revision_authorities={'local.fixture'})
        self.assertEqual(r['stages']['effect']['status'], 'CONTINUED_REPORTED')
        self.assertTrue(next(row for row in r['history'] if row['event']['event_id'] == 'old')['superseded'])
        self.assertEqual(len(r['history']), 2)

    def test_revision_cannot_cross_scope_or_point_to_future(self):
        old = self.f.delivery('old', status='QUIESCENT')
        for changes in ({'identity': query(run_id='run-A')['identity']}, {'event_time': 9, 'observed_time': 10}):
            later = self.f.delivery('revision', supersedes='old', revision_reason='attempt', **changes)
            q = query(run_id='run-A') if 'identity' in changes else query()
            r = self.result([old, later], q, revision_authorities={'local.fixture'})
            self.assertTrue(r['revision_errors'])
            self.assertEqual(r['stages']['effect']['status'], 'INDETERMINATE')

    def test_duplicate_json_member_and_missing_epoch_rejected(self):
        row = self.f.delivery('test')
        row['event_bytes'] = b'{"identity":{},"identity":{}}'
        self.assertTrue(self.result([row])['binding_errors'])
        row = self.f.delivery('other')
        e = json.loads(row['event_bytes']); del e['identity']['runtime_epoch']
        self.assertTrue(self.result([self.f.bind(e)])['binding_errors'])


if __name__ == '__main__':
    unittest.main()
