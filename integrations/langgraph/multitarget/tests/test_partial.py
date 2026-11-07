import copy
import itertools
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tools.airep_v02.json_input import loads
from integrations.langgraph.run import encoded
from integrations.langgraph.multitarget import consumer, partial
from integrations.langgraph.multitarget.binding import Writer as NodeWriter
from integrations.langgraph.multitarget.binding_partial import Writer, BASIS, CONTRACT


class PartialEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inputs = loads((Path(__file__).parents[1] / 'evidence/2026-11-07/inputs.json').read_bytes())

    def setUp(self):
        self.select('chain_all')

    def select(self, label):
        self.case = copy.deepcopy(next(c for c in self.inputs['cases'] if c['label'] == label))
        self.source = loads(self.case['delivery']['source_bytes'].encode())
        self.source['schema'] = 'multitarget-partial-capture-v2'
        self.intent = copy.deepcopy(self.case['intent'])
        self.trust = copy.deepcopy(self.case['node_trust'])
        self.writer = Writer('controller')

    def drop(self, target, fields=('nodes', 'observations', 'cleanup')):
        for field in fields:
            del self.source[field][target]

    def evaluate(self, mapped=None, scope=None):
        if mapped is None:
            mapped = partial.project(self.source, self.intent, self.trust)
        return partial.evaluate(self.writer.sign(self.source, mapped, scope=scope), self.intent,
                                self.writer.trust, self.trust)

    def reject(self):
        result = self.evaluate(mapped={})
        self.assertEqual(result['admission'], 'NO_MATCH')
        self.assertIsNone(result['result'])
        return result

    def test_missing_c_preserves_a_b_and_original_denominator_both_topologies(self):
        for label in ('chain_all', 'fanout_all'):
            self.select(label); self.drop('C')
            e = self.evaluate(); r = e['result']
            self.assertEqual(e['admission'], 'MATCH')
            self.assertEqual((r['bounded_pause_count'], r['intended_target_count']), (2, 3))
            self.assertTrue(all(t['bounded_pause'] for t in r['targets'][:2]))
            c = r['targets'][2]
            self.assertEqual((c['receipt'], c['execution'], c['effect'], c['assessment']),
                             ('UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'INDETERMINATE'))
            self.assertEqual(c['transport'], 'RESPONSE_UNCONFIRMED')
            self.assertIsNone(c['node']); self.assertIsNone(c['native_pause_count'])
            self.assertNotIn('C', r['node_native'])

    def test_all_six_complete_cases_preserve_v1_decisions(self):
        for case in self.inputs['cases'][:6]:
            self.select(case['label'])
            old = consumer.evaluate(case['delivery'], case['intent'], self.inputs['controller_trust'], case['node_trust'])
            new = self.evaluate()
            self.assertEqual(new['admission'], old['admission'])
            self.assertEqual(new['result']['bounded_pause_count'], old['result']['bounded_pause_count'])
            for a, b in zip(new['result']['targets'], old['result']['targets']):
                for field in ('target_id', 'receipt', 'execution', 'effect', 'transport', 'bounded_pause', 'attempts'):
                    self.assertEqual(a[field], b[field], (case['label'], field))

    def test_native_incomplete_and_coverage_not_evaluated_preserved(self):
        self.drop('C'); e = self.evaluate()
        self.assertEqual(e['native']['class'], 'AIREP-Authenticated')
        self.assertEqual(e['native_reconciliation']['summary']['status'], 'INCOMPLETE')
        self.assertEqual([c['state'] for c in e['native_reconciliation']['checks']
                          if c['check'] == 'intended_target_coverage'], ['NOT_EVALUATED'])

    def test_missing_observer_keeps_receipt_execution_but_not_effect(self):
        self.drop('C', ('observations',)); c = self.evaluate()['result']['targets'][2]
        self.assertEqual((c['receipt'], c['execution'], c['effect']),
                         ('RECEIVED_REPORTED', 'PAUSED_REPORTED', 'UNKNOWN'))
        self.assertFalse(c['bounded_pause'])

    def test_missing_node_keeps_actual_observation_not_inferred_execution(self):
        self.select('chain_unknown'); self.drop('C', ('nodes',))
        c = self.evaluate()['result']['targets'][2]
        self.assertEqual((c['execution'], c['effect']), ('UNKNOWN', 'CONTINUED_REPORTED'))
        self.assertFalse(c['bounded_pause'])

    def test_missing_cleanup_cannot_confirm_bounded_pause(self):
        self.drop('C', ('cleanup',)); c = self.evaluate()['result']['targets'][2]
        self.assertEqual(c['effect'], 'QUIESCENT_REPORTED'); self.assertFalse(c['bounded_pause'])

    def test_missing_intermediate_report_marks_uncorroborated_child(self):
        self.drop('B'); r = self.evaluate()['result']
        self.assertTrue(r['targets'][0]['bounded_pause'])
        self.assertEqual(r['targets'][1]['execution'], 'UNKNOWN')
        self.assertEqual(r['targets'][2]['execution'], 'PAUSED_REPORTED')
        self.assertEqual(r['targets'][2]['corroboration_gaps'][0]['reason'], 'SENDER_REPORT_MISSING')
        self.assertFalse(r['targets'][2]['bounded_pause'])

    def test_all_reports_absent_remain_three_unknowns(self):
        for target in ('A', 'B', 'C'): self.drop(target)
        r = self.evaluate()['result']
        self.assertEqual((r['bounded_pause_count'], r['reported_target_count'], r['intended_target_count']), (0, 0, 3))
        self.assertTrue(all(t['execution'] == 'UNKNOWN' for t in r['targets']))
        self.assertEqual(r['delivery_attempt_inventory'], 'PARTIAL')
        self.assertEqual([t['transport'] for t in r['targets'][1:]], ['UNKNOWN', 'UNKNOWN'])

    def test_missing_parent_cannot_be_called_no_attempt(self):
        self.select('chain_refused'); self.drop('B')
        c = self.evaluate()['result']['targets'][2]
        self.assertEqual(c['transport'], 'UNKNOWN')
        self.assertEqual(c['assessment'], 'INDETERMINATE')

    def test_controller_cannot_shrink_the_consumer_inventory(self):
        self.drop('C'); self.source['intent']['targets'] = ['A', 'B']; self.reject()
        self.intent['targets'] = ['A', 'B']; self.reject()

    def test_wrong_target_epoch_or_control_is_rejected(self):
        for field in ('runtime_epoch', 'control_id', 'checkpoint_id'):
            self.select('chain_all'); self.source['observations']['A']['identity'][field] = 'borrowed'; self.reject()

    def test_present_invalid_signature_is_not_missing(self):
        self.source['nodes']['C']['source_bytes'] += ' '; e = self.reject()
        self.assertIsNotNone(e['failed_report_native'])

    def test_present_null_report_observation_cleanup_are_rejected(self):
        for field in ('nodes', 'observations', 'cleanup'):
            self.select('chain_all'); self.source[field]['C'] = None; self.reject()

    def test_extra_unknown_target_is_rejected(self):
        for field in ('nodes', 'observations', 'cleanup'):
            self.select('chain_all'); self.source[field]['D'] = self.source[field]['C']; self.reject()

    def test_missing_trust_even_for_absent_node_is_rejected(self):
        self.drop('C'); del self.trust['C']; self.reject()

    def test_shared_role_keys_rejected(self):
        self.trust['C'] = copy.deepcopy(self.trust['B']); self.reject()

    def test_signed_claim_cannot_upgrade_missing_target(self):
        self.drop('C'); p = partial.project(self.source, self.intent, self.trust)
        p['targets'][2]['bounded_pause'] = True; p['bounded_pause_count'] = 3
        self.assertEqual(self.evaluate(mapped=p)['admission'], 'NO_MATCH')

    def test_old_and_new_contracts_do_not_silently_accept_each_other(self):
        self.assertEqual(partial.evaluate(self.case['delivery'], self.intent,
                                         self.inputs['controller_trust'], self.trust)['admission'], 'NO_MATCH')
        p = partial.project(self.source, self.intent, self.trust)
        self.assertEqual(consumer.evaluate(self.writer.sign(self.source, p), self.intent,
                                         self.writer.trust, self.trust)['admission'], 'NO_MATCH')

    def test_removed_scope_exclusion_rejected(self):
        scope = copy.deepcopy(CONTRACT['scope']); scope['does_not_cover'].pop()
        self.assertEqual(self.evaluate(scope=scope)['admission'], 'NO_MATCH')

    def test_present_gateway_laundering_still_rejected(self):
        for label in ('gateway_refusal_laundering', 'gateway_unknown_laundering'):
            self.select(label); self.reject()

    def test_wrong_response_identity_when_receiver_absent_rejected(self):
        self.select('fanout_all'); self.drop('C')
        e = self.source['events'][-1]['data']
        reply = loads(bytes.fromhex(e['response_hex'])); reply['target_id'] = 'B'
        e['response_hex'] = encoded(reply).hex(); self.reject()

    def test_replaced_observation_history_rejected(self):
        obs = self.source['observations']['A']; obs['after']['bytes_hex'] = '00'; self.reject()

    def test_forced_cleanup_is_not_control_success(self):
        self.select('chain_unknown'); self.drop('C', ('nodes',))
        self.assertFalse(self.evaluate()['result']['targets'][2]['bounded_pause'])
        self.source['cleanup']['C']['forced'] = False; self.reject()

    def test_fresh_basis_is_hash_bound(self):
        self.assertTrue(BASIS.startswith('sha256:'))
        from integrations.langgraph.multitarget.binding import BASIS as old
        self.assertNotEqual(BASIS, old)

    def test_each_missing_target_subset_preserves_denominator_without_upgrading(self):
        for topology in ('chain_all', 'fanout_all'):
            for mask in itertools.product((False, True), repeat=3):
                self.select(topology)
                absent = [t for t, drop in zip(('A', 'B', 'C'), mask) if drop]
                for target in absent:
                    self.drop(target)
                result = self.evaluate()
                self.assertEqual(result['admission'], 'MATCH', (topology, absent))
                projected = result['result']
                self.assertEqual(projected['intended_target_count'], 3)
                self.assertEqual(projected['reported_target_count'], 3 - len(absent))
                self.assertLessEqual(projected['bounded_pause_count'], 3 - len(absent))
                for target in projected['targets']:
                    if target['target_id'] in absent:
                        self.assertEqual((target['receipt'], target['execution'], target['effect']),
                                         ('UNKNOWN', 'UNKNOWN', 'UNKNOWN'))
                        self.assertEqual(target['assessment'], 'INDETERMINATE')
                        self.assertFalse(target['bounded_pause'])

    def test_invalid_present_report_is_rejected_even_when_another_target_is_absent(self):
        self.drop('C')
        self.source['nodes']['A']['source_bytes'] += ' '
        self.assertEqual(self.reject()['admission'], 'NO_MATCH')

    def test_saved_replay_cli_preserves_bytes_and_does_not_generate_keys(self):
        from integrations.langgraph.multitarget import partial_report
        inputs = partial_report.build()
        expected = encoded(partial_report.replay(inputs))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'saved.json'
            source.write_bytes(encoded(inputs))
            out = root / 'replayed'
            with patch('sys.argv', ['partial_report', '--replay', str(source), '--out', str(out)]), \
                    patch.object(partial_report, 'build', side_effect=AssertionError('must not regenerate')):
                partial_report.main()
            self.assertEqual((out / 'inputs.json').read_bytes(), source.read_bytes())
            self.assertEqual((out / 'report.json').read_bytes(), expected)

    def test_saved_replay_rejects_another_basis_before_evaluating(self):
        from integrations.langgraph.multitarget import partial_report
        with patch.object(partial_report, 'evaluate', side_effect=AssertionError('must not evaluate')):
            with self.assertRaisesRegex(ValueError, 'basis mismatch'):
                partial_report.replay({'basis_digest': 'sha256:' + '0' * 64, 'cases': []})


if __name__ == '__main__':
    unittest.main()
