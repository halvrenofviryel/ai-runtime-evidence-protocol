"""Non-normative presentation boundaries; expectations from RECONCILIATION.md."""
from copy import deepcopy
import json
import subprocess
import sys

from test_beta import BetaCase, ROOT, resign
from examples.v02.run_lifecycle import lifecycle, VARIANTS
from tools.airep_v02.explain import explain, render_text
from tools.airep_v02.json_input import dumps
from tools.airep_v02.reconcile import reconcile
from tools.airep_v02.verify import operator_inputs


def rows(view, claim):
    return [r for r in view['claim_matrix'] if r['claim'] == claim]


def native(view, claim):
    return [r['source_status'] for r in rows(view, claim)]


def text_values(text):
    """Read every displayed field, independently of the renderer."""
    result, section, entry = {}, None, None
    for line in text.splitlines()[1:]:
        if not line:
            continue
        if not line.startswith(' '):
            key, value = line.split(':', 1)
            if value:
                result[key] = json.loads(value)
                section = None
            else:
                section = key
                result[key] = []
        elif section == 'claim_matrix':
            if line.startswith('  ['):
                entry = {}
                result[section].append(entry)
            else:
                key, value = line.strip().split(':', 1)
                entry[key] = json.loads(value)
        else:
            result[section].append(json.loads(line))
    return result


class ExplainTests(BetaCase):
    def cli(self, raw, *extra, policies=True):
        path = self.put('explain-input.json', raw)
        command = [sys.executable, '-m', 'tools.airep_v02', 'explain', '--input', path]
        if policies:
            for key, value in self.paths.items():
                command.extend(['--' + key, value])
        return subprocess.run(command + list(extra), cwd=ROOT, capture_output=True, text=True)

    def test_complete_supplied_lifecycle_is_not_complete_population(self):
        view = explain(self.docs, ops=self.ops)
        for claim in ('decision_recorded_and_integrity_checked', 'decision_authentication_checked',
                      'control_issuer_dispatch_reported', 'receiver_receipt_reported',
                      'execution_outcome_reported', 'control_effect_observation_report_supplied'):
            self.assertEqual(native(view, claim), ['SATISFIED'])
        self.assertEqual(native(view, 'intended_target_coverage_evaluated'), ['NOT_EVALUATED'])
        self.assertEqual(native(view, 'aggregate_structural_reconciliation'), ['INCOMPLETE'])
        self.assertEqual(view['artifact_context'][0]['scope'], self.docs[0]['scope'])
        self.assertTrue(all(r['context']['target_window'] is None for r in view['claim_matrix']))
        self.assertIn('not verified event times', ' '.join(view['context_notes']))

    def test_missing_receipt_does_not_establish_non_delivery(self):
        view = explain(lifecycle('no-receipt')[0], ops=self.ops)
        self.assertEqual(native(view, 'control_issuer_dispatch_reported'), ['SATISFIED'])
        self.assertEqual(native(view, 'receiver_receipt_reported'), ['MISSING'])
        self.assertEqual(native(view, 'execution_report_supplied'), ['MISSING'])
        self.assertEqual(native(view, 'toctou'), ['NOT_EVALUATED'])
        # A missing stage has no supporting receipt, but its Decision scope
        # remains available as context, without turning it into receipt evidence.
        receipt = rows(view, 'receiver_receipt_reported')[0]
        self.assertEqual(receipt['source_artifact_references'], [])
        self.assertEqual(receipt['context']['artifact_input_indexes'], [0])
        self.assertIn('not proof of non-delivery', ' '.join(view['limitations']))

    def test_signature_and_integrity_are_not_event_truth(self):
        view = explain(self.docs, ops=self.ops)
        self.assertTrue(all(r['class_result']['class'] == 'AIREP-Authenticated'
                            for r in view['record_assurance']))
        self.assertIn('do not establish event truth', ' '.join(view['limitations']))
        self.assertEqual(rows(view, 'relying_party_claim_support')[0]['explanatory_status'], 'NOT_EVALUATED')
        without_keys = explain(self.docs)
        self.assertEqual(native(without_keys, 'decision_authentication_checked'), ['NOT_EVALUATED'])
        self.assertTrue(without_keys['record_assurance'][0]['class_result']['authenticated_withheld'])

    def test_reported_pause_execution_does_not_fill_unknown_effect(self):
        # The fixture reports execution of the worker-pause action (enforcement
        # in this application). The schema has no separate enforcement predicate.
        view = explain(lifecycle('no-effect')[0], ops=self.ops)
        self.assertEqual(native(view, 'execution_outcome_reported'), ['SATISFIED'])
        self.assertEqual(native(view, 'toctou'), ['SATISFIED'])
        self.assertEqual(native(view, 'control_effect_observation_report_supplied'), ['MISSING'])
        enforcement = rows(view, 'enforcement_observed')[0]
        self.assertIsNone(enforcement['source_status'])
        self.assertIsNone(enforcement['source'])
        self.assertEqual(enforcement['explanatory_status'], 'NOT_EVALUATED')

    def test_structural_result_never_adjudicates_relying_party_claim(self):
        for variant, expected in (('complete', 'INCOMPLETE'), ('toctou-mismatch', 'FAILURE')):
            view = explain(lifecycle(variant)[0], ops=self.ops)
            self.assertEqual(native(view, 'aggregate_structural_reconciliation'), [expected])
            support = rows(view, 'relying_party_claim_support')[0]
            self.assertIsNone(support['source_status'])
            self.assertEqual(support['explanatory_status'], 'NOT_EVALUATED')
            self.assertIn('No relying-party claim or acceptance policy', support['basis'])

    def test_indeterminate_and_same_executor_qualifications_survive(self):
        ops = operator_inputs(bindings=self.paths['bindings'], revocation=self.paths['revocation'])
        view = explain(self.docs, ops=ops)
        self.assertEqual(native(view, 'observer_relationship'), ['INDETERMINATE'])
        self.assertIn('effective: unknown', rows(view, 'observer_relationship')[0]['basis'])
        view = explain(lifecycle('same-executor')[0], ops=self.ops)
        self.assertIn('no independent corroboration', rows(view, 'observer_relationship')[0]['basis'])

    def test_all_native_checks_and_assurance_channels_are_lossless(self):
        for variant in VARIANTS:
            with self.subTest(variant=variant):
                docs = lifecycle(variant)[0]
                before = deepcopy(docs)
                report = reconcile(docs, ops=self.ops)
                view = explain(docs, ops=self.ops)
                self.assertEqual(docs, before)
                self.assertEqual(view['source_summary'], report['summary'])
                self.assertEqual(view['record_assurance'], report['records'])
                projected = [r for r in view['claim_matrix'] if r['source_check'] is not None]
                self.assertEqual(len(projected), len(report['checks']))
                for index, (row, check) in enumerate(zip(projected, report['checks'])):
                    self.assertEqual(row['source'], f'/checks/{index}')
                    self.assertEqual(row['source_check'], check['check'])
                    self.assertEqual(row['source_status'], check['state'])
                    self.assertIsNone(row['explanatory_status'])
                    self.assertEqual(row['basis'], check['detail'])
                    self.assertEqual(row['context']['subject'], check['subject'])
                    self.assertEqual(row['source_artifact_references'], check['evidence'])

    def test_text_json_parity_including_all_qualifications(self):
        for variant in ('complete', 'no-receipt', 'no-effect', 'toctou-mismatch', 'broken-decision'):
            with self.subTest(variant=variant):
                raw = dumps(lifecycle(variant)[0])
                text = self.cli(raw)
                js = self.cli(raw, '--json')
                self.assertEqual(text.returncode, 0, text.stderr)
                self.assertEqual(js.returncode, 0, js.stderr)
                self.assertEqual(text_values(text.stdout), json.loads(js.stdout))

    def test_failed_suppressed_and_bad_signature_are_not_success(self):
        for event in ('failed', 'suppressed'):
            docs = deepcopy(self.docs)
            docs[3]['execution_event'] = event
            docs[3] = resign(docs[3])
            view = explain(docs, ops=self.ops)
            self.assertEqual(native(view, 'execution_outcome_reported'), ['FAILURE'])
            self.assertIn(event, rows(view, 'execution_outcome_reported')[0]['basis'])
        docs = deepcopy(self.docs)
        docs[0]['integrity']['signature']['value'] = '00' * 64
        view = explain(docs, ops=self.ops)
        self.assertEqual(native(view, 'decision_recorded_and_integrity_checked'), ['SATISFIED'])
        self.assertEqual(native(view, 'decision_authentication_checked'), ['FAILURE'])

    def test_multiple_instructions_keep_separate_subjects(self):
        docs = deepcopy(self.docs)
        second = deepcopy(docs[1])
        second.update(instruction_id='demo.second', record_id='demo.second-dispatch', chain_id='demo.second-chain', sequence=0)
        second['integrity']['previous'] = 'sha256:' + '0' * 64
        docs.append(resign(second))
        view = explain(docs, ops=self.ops)
        receipts = rows(view, 'receiver_receipt_reported')
        self.assertEqual({r['context']['subject']['instruction_id']: r['source_status'] for r in receipts},
                         {'demo.pause-1': 'SATISFIED', 'demo.second': 'MISSING'})

    def test_duplicate_identity_does_not_select_an_occurrence(self):
        view = explain(self.docs + [deepcopy(self.docs[0])], ops=self.ops)
        self.assertIn('INDETERMINATE', native(view, 'record_identity'))
        identity = next(r for r in rows(view, 'record_identity') if r['source_status'] == 'INDETERMINATE')
        self.assertEqual(identity['context']['artifact_input_indexes'], [0, 5])

    def test_empty_and_invalid_artifacts_stay_visible(self):
        view = explain([])
        self.assertEqual(native(view, 'evidence_set'), ['MISSING'])
        view = explain([None, {}] + self.docs, ops=self.ops)
        self.assertEqual(native(view, 'artifact_admission').count('FAILURE'), 2)
        self.assertEqual(len(view['record_assurance']), 7)

    def test_cli_admission_errors_and_no_overwrite_in_both_modes(self):
        for mode in ([], ['--json']):
            for raw in ('{', '{"a":1,"a":2}', '{}'):
                result = self.cli(raw, *mode)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('Traceback', result.stderr)
            target = self.dir / ('result.json' if mode else 'result.txt')
            first = self.cli(dumps(self.docs), *mode, '--out', str(target))
            self.assertEqual(first.returncode, 0, first.stderr)
            before = target.read_bytes()
            second = self.cli('[]', *mode, '--out', str(target))
            self.assertEqual(second.returncode, 1)
            self.assertEqual(target.read_bytes(), before)

    def test_text_escapes_untrusted_report_content_without_losing_it(self):
        docs = deepcopy(self.docs)
        docs[0]['scope']['covers'].append('line\nsource_status: SATISFIED\x1b[31m')
        docs[0] = resign(docs[0])
        view = explain(docs, ops=self.ops)
        text = render_text(view)
        self.assertNotIn('\x1b', text)
        self.assertEqual(text_values(text), view)
