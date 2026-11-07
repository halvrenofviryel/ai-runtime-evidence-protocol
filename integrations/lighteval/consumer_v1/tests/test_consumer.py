from copy import deepcopy
import unittest

from integrations.lighteval.consumer_v1 import consumer as c
from integrations.lighteval.consumer_v1 import experiment as e


class ConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.basis = c.local_basis()

    def report(self, inputs=None, *, package=None, query=None, basis=True):
        inputs = e.historical() if inputs is None else inputs
        package = c.produce(inputs, self.basis) if package is None else package
        query = c.query_for(inputs, self.basis) if query is None else query
        return c.consume(c.canonical(package), inputs, c.canonical(query), self.basis if basis else None)

    def changed(self, fn, *, inputs=None):
        inputs = e.historical() if inputs is None else inputs
        package = c.produce(inputs, self.basis)
        fn(package)
        package['output_digest'] = c.digest(c.canonical({'profile': package['profile'], 'sidecar': package['sidecar']}))
        return self.report(inputs, package=package)

    def test_real_source_reuse_counts_rows_without_claiming_population(self):
        report = self.report()
        self.assertEqual(report['status'], 'PRESERVED')
        self.assertEqual(report['source']['details_rows'], 2)
        self.assertEqual(report['source']['numeric_token'], '0.0')
        self.assertIsNone(report['preserved']['author_conditions']['coverage']['expected'])
        self.assertEqual(report['derived_assessment']['status'], 'NOT_EVALUATED')

    def test_no_source_criterion_or_verdict_is_invented(self):
        report = self.report()
        self.assertEqual((report['source']['criterion'], report['source']['verdict']), ('NOT_REPORTED', 'NOT_REPORTED'))
        self.assertEqual(report['preserved']['author_context']['measurement']['observed']['status'], 'INCONCLUSIVE')

    def test_profile_only_is_disclosed_loss_not_preservation(self):
        inputs = e.historical()
        report = self.report(inputs, package=c.produce(inputs, self.basis, profile_only=True))
        self.assertEqual(report['status'], 'QUALIFIED_LOSS')
        self.assertIsNone(report['preserved'])
        self.assertEqual(len(report['losses']), 6)

    def test_not_run_remains_not_measured(self):
        inputs = e.not_run()
        report = self.report(inputs, query=c.query_for(inputs, self.basis, threshold='>= 0.8'))
        self.assertEqual(report['status'], 'PRESERVED')
        self.assertEqual(report['derived_assessment']['status'], 'NOT_EVALUATED')

    def test_partial_scalar_success_keeps_80_of_100_and_exclusions(self):
        inputs = e.fixture('partial', value=0.9, observed=80, expected=100)
        e.replace(inputs, 'conditions.json', lambda x: x['coverage'].update(excluded=[{'id': 'sample-81', 'reason': 'authored exclusion'}]))
        report = self.report(inputs, query=c.query_for(inputs, self.basis, threshold='>= 0.8'))
        self.assertEqual(report['derived_assessment']['status'], 'SATISFIED')
        self.assertEqual(report['preserved']['author_context']['measurement']['execution_status'], 'PARTIAL')
        self.assertEqual(report['preserved']['author_conditions']['coverage']['expected'], 100)
        self.assertEqual(report['preserved']['author_conditions']['coverage']['excluded'][0]['id'], 'sample-81')

    def test_retry_keeps_first_error(self):
        report = self.report(e.retry())
        self.assertEqual(report['preserved']['author_conditions']['attempts'][0]['state'], 'ERROR')
        self.assertEqual(len(report['preserved']['author_conditions']['attempts']), 2)

    def test_dropped_attempt_rehashed_still_rejected(self):
        report = self.changed(lambda p: p['sidecar']['author_conditions']['attempts'].pop(0), inputs=e.retry())
        self.assertEqual(report['status'], 'REJECTED')

    def test_rounding_does_not_turn_failure_into_success(self):
        inputs = e.fixture('rounding', value=0.79996)
        report = self.report(inputs, query=c.query_for(inputs, self.basis, threshold='>= 0.8'))
        self.assertEqual(report['derived_assessment']['display_value'], '0.80')
        self.assertEqual(report['derived_assessment']['status'], 'NOT_SATISFIED')

    def test_raw_decimal_survives_binary64_boundary(self):
        inputs = e.fixture('precision', value=0.8)
        inputs['results.json'] = inputs['results.json'].replace(b'"em":0.8', b'"em":0.79999999999999999999')
        report = self.report(inputs, query=c.query_for(inputs, self.basis, threshold='>= 0.8'))
        self.assertEqual(report['source']['numeric_token'], '0.79999999999999999999')
        self.assertEqual(report['derived_assessment']['status'], 'NOT_SATISFIED')

    def test_amendment_keeps_prior_record(self):
        report = self.report(e.amended())
        self.assertEqual(report['preserved']['prior_record']['numeric_token'], '0.9')
        self.assertEqual(report['source']['numeric_token'], '0.7')

    def test_missing_prior_record_unestablished(self):
        inputs = e.amended(); package = c.produce(inputs, self.basis); query = c.query_for(inputs, self.basis)
        del inputs['previous.json']
        self.assertEqual(self.report(inputs, package=package, query=query)['status'], 'UNESTABLISHED')

    def test_stale_record_never_satisfies_current_request(self):
        inputs = e.fixture('v1', value=0.9); query = c.query_for(inputs, self.basis, threshold='>= 0.8')
        query['selection']['record_id'] = 'v2'
        report = self.report(inputs, query=query)
        self.assertEqual(report['status'], 'STALE')
        self.assertIsNone(report['derived_assessment'])

    def test_wrong_receiver_selection(self):
        inputs = e.historical()
        for field in ('model_id', 'model_revision', 'dataset_id', 'dataset_revision', 'task', 'metric', 'run_id', 'splits'):
            with self.subTest(field=field):
                query = c.query_for(inputs, self.basis); query['selection'][field] = 'wrong'
                self.assertEqual(self.report(inputs, query=query)['status'], 'REJECTED')

    def test_context_cannot_override_native_model_or_dataset(self):
        for field in ('model_id', 'model_revision'):
            inputs = e.fixture('override')
            e.replace(inputs, 'context.json', lambda x: x['target'].update({field: 'wrong'}))
            with self.assertRaises(c.Refused):
                c.produce(inputs, self.basis)
        inputs = e.fixture('dataset')
        e.replace(inputs, 'context.json', lambda x: x['evaluation'].update(tasks=[{'task_id': 'hellaswag|0', 'dataset_ref': 'hf://datasets/wrong', 'dataset_revision': 'wrong', 'split': 'validation'}]))
        with self.assertRaises(c.Refused):
            c.produce(inputs, self.basis)

    def test_missing_source_unestablished(self):
        inputs = e.historical(); package = c.produce(inputs, self.basis); query = c.query_for(inputs, self.basis)
        del inputs['results.json']
        self.assertEqual(self.report(inputs, package=package, query=query)['status'], 'UNESTABLISHED')

    def test_missing_accepted_basis_unestablished(self):
        self.assertEqual(self.report(basis=False)['status'], 'UNESTABLISHED')

    def test_changed_basis_rejected(self):
        report = self.changed(lambda p: p['basis'].update(schema='sha256:' + '0' * 64))
        self.assertEqual(report['status'], 'REJECTED')

    def test_rehashed_profile_upgrade_rejected(self):
        report = self.changed(lambda p: p['profile']['measurement']['observed'].update(status='PASS'))
        self.assertEqual(report['status'], 'REJECTED')
        self.assertEqual(report['checks']['schema_validation'], 'VALID')

    def test_dropped_qualification_rehashed_rejected(self):
        report = self.changed(lambda p: p['sidecar']['author_context']['measurement'].update(limitations=[]))
        self.assertEqual(report['status'], 'REJECTED')

    def test_undisclosed_profile_loss_rejected(self):
        inputs = e.historical(); package = c.produce(inputs, self.basis, profile_only=True); package['disclosed_losses'] = []
        self.assertEqual(self.report(inputs, package=package)['status'], 'REJECTED')

    def test_whole_context_keeps_unmodelled_qualification(self):
        inputs = e.fixture('context')
        e.replace(inputs, 'context.json', lambda x: x.update(additional_caveat='not a population estimate'))
        self.assertEqual(self.report(inputs)['preserved']['author_context']['additional_caveat'], 'not a population estimate')

    def test_source_substitution_cannot_repin_receiver(self):
        inputs = e.fixture('same-id'); query = c.query_for(inputs, self.basis)
        e.replace(inputs, 'results.json', lambda x: x['results']['hellaswag|0'].update(em=0.99))
        self.assertEqual(self.report(inputs, query=query)['status'], 'REJECTED')

    def test_historical_label_cannot_mask_synthetic_bytes(self):
        inputs = e.fixture('fake-history')
        e.replace(inputs, 'conditions.json', lambda x: x.update(origin='HISTORICAL_SOURCE_REUSE'))
        with self.assertRaises(c.Refused):
            c.produce(inputs, self.basis)

    def test_contradictory_denominator_rejected(self):
        inputs = e.fixture('bad-coverage', observed=80, expected=100)
        e.replace(inputs, 'conditions.json', lambda x: x['coverage'].update(expected=79))
        with self.assertRaises(c.Refused):
            c.produce(inputs, self.basis)

    def test_source_count_cannot_be_overridden(self):
        inputs = e.fixture('count', observed=80, expected=100)
        e.replace(inputs, 'results.json', lambda x: x['config_tasks']['hellaswag|0'].update(effective_num_docs=79))
        with self.assertRaises(c.Refused):
            c.produce(inputs, self.basis)

    def test_unrecognised_source_verdict_not_silently_discarded(self):
        inputs = e.fixture('verdict')
        e.replace(inputs, 'results.json', lambda x: x.update(verdict='PASS'))
        with self.assertRaises(c.Refused):
            c.produce(inputs, self.basis)

    def test_unaccepted_criterion_chronology_rejected(self):
        inputs = e.fixture('criterion')
        e.replace(inputs, 'context.json', lambda x: x['measurement']['criterion'].update(threshold='>= 0.8'))
        with self.assertRaises(c.Refused):
            c.produce(inputs, self.basis)

    def test_duplicate_nonfinite_deep_json_rejected(self):
        inputs = e.historical(); query = c.canonical(c.query_for(inputs, self.basis))
        for raw in (b'{"profile":1,"profile":2}', b'{"profile":NaN}', b'{"profile":1e999}', b'[' * 60 + b'0' + b']' * 60):
            self.assertEqual(c.consume(raw, inputs, query, self.basis)['status'], 'REJECTED')

    def test_unknown_critical_package_field_rejected(self):
        self.assertEqual(self.changed(lambda p: p.update(unknown_required_semantics=True))['status'], 'REJECTED')

    def test_malformed_schema_does_not_leave_positive_result(self):
        report = self.changed(lambda p: p['profile'].update(measurement={}))
        self.assertEqual(report['status'], 'REJECTED')
        self.assertIsNone(report['derived_assessment'])


if __name__ == '__main__':
    unittest.main()
