"""Exporter regression tests on deterministic synthetic LightEval-shaped data.

Run: python3 -m unittest discover -s integrations/lighteval/tests -v
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
INTEGRATION = HERE.parent
ROOT = INTEGRATION.parents[1]
sys.path.insert(0, str(INTEGRATION))
import export_embedded_evaluation as x  # noqa: E402

PROFILE_DIR = ROOT / 'spec/airep/v0.2/profiles/embedded-evaluation'
RESULTS_NAME = 'results_2026-09-12T10-20-00.000000.json'


def synthetic_results(acc=0.72, task='example|task|0', with_config=True):
    doc = {
        'config_general': {
            'lighteval_sha': 'abc123def4567890',
            'num_fewshot_seeds': 1, 'max_samples': None, 'job_id': 0,
            'start_time': 1234.5, 'end_time': 1834.5, 'total_evaluation_time_secondes': '600.0',
            'model_config': {'model_name': 'example-org/example-model', 'revision': 'deadbeef', 'dtype': 'bfloat16'},
            'model_name': 'example-org/example-model',
        },
        'results': {task: {'acc': acc, 'acc_stderr': 0.01}, 'all': {'acc': acc, 'acc_stderr': 0.01}},
        'versions': {task: 0},
        'summary_tasks': {}, 'summary_general': {},
    }
    if with_config:
        doc['config_tasks'] = {task: {'name': 'task', 'hf_repo': 'example/eval-dataset', 'hf_subset': 'default',
                                      'hf_revision': 'cafebabe', 'evaluation_splits': ['test'], 'num_fewshots': 0,
                                      'version': 0, 'effective_num_docs': 100}}
    return doc


def context():
    return json.loads((INTEGRATION / 'example_context.json').read_text(encoding='utf-8'))


def native(doc, name=RESULTS_NAME):
    return x.NativeFile(name, 'aggregate-result', json.dumps(doc, indent=2).encode('utf-8'))


class ExporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.basis = x.Basis.from_dir(PROFILE_DIR)

    def run_export(self, ctx, results=None, extra=()):
        return x.export(json.dumps(ctx).encode('utf-8'), results, list(extra), self.basis)

    def test_basis_digest_is_pinned_to_registry(self):
        registry = json.loads((PROFILE_DIR / 'registry.json').read_text())
        self.assertEqual(self.basis.schema_digest, registry['profiles'][x.PROFILE_ID]['basis_digest'])
        tampered = (PROFILE_DIR / 'embedded-evaluation.schema.json').read_bytes() + b'\n'
        with self.assertRaises(x.ExportError):
            x.Basis(tampered, (PROFILE_DIR / 'registry.json').read_bytes())

    def test_threshold_pass_and_fail_validate_and_carry_the_metric(self):
        for acc, want in ((0.72, 'PASS'), (0.41, 'FAIL')):
            with self.subTest(acc=acc):
                payload, manifest, report = self.run_export(context(), native(synthetic_results(acc)))
                self.assertTrue(report['schema_valid'], report['errors'])
                m = payload['measurement']
                self.assertEqual((m['execution_status'], m['observed']['status'], m['observed']['metric_value']), ('RAN', want, acc))
                self.assertEqual(m['sample_count'], 100)
                self.assertEqual(payload['target']['model_id'], 'example-org/example-model')
                self.assertEqual(payload['target']['model_revision'], 'deadbeef')
                self.assertEqual(payload['evaluation']['framework']['name'], 'lighteval')
                self.assertEqual(payload['evaluation']['framework']['revision'], 'abc123def4567890')
                self.assertEqual(payload['evaluation']['tasks'][0]['dataset_ref'], 'hf://datasets/example/eval-dataset')
                self.assertEqual(payload['evaluation']['tasks'][0]['dataset_revision'], 'cafebabe')
                self.assertEqual(payload['evaluation']['tasks'][0]['split'], 'test')
                # Wall-clock window comes only from the declared, offset-bearing context timestamps.
                self.assertEqual((payload['evaluation']['started_at'], payload['evaluation']['ended_at']),
                                 ('2026-09-12T10:00:00Z', '2026-09-12T10:20:00Z'))
                self.assertTrue(any('timezone-naive local time' in s for s in m['limitations']))
                self.assertEqual(manifest['outputs']['profile_payload_sha256'], x.sha256_of(x.canonical(payload)))

    def test_timezone_naive_filename_is_never_promoted_to_utc(self):
        ctx = context()
        del ctx['evaluation']['started_at']; del ctx['evaluation']['ended_at']
        with self.assertRaises(x.ExportError) as caught:
            self.run_export(ctx, native(synthetic_results(), name='results_2026-09-13T20-00-00.000000.json'))
        message = str(caught.exception)
        self.assertIn('timezone-naive', message)
        self.assertIn("2026-09-13T20:00:00", message)
        self.assertNotIn('20:00:00Z', json.dumps(ctx))
        # Only one of the two declared is still a refusal.
        ctx['evaluation']['started_at'] = '2026-09-13T17:00:00Z'
        with self.assertRaises(x.ExportError):
            self.run_export(ctx, native(synthetic_results()))

    def test_explicit_offsets_are_normalised_and_utc_preserved(self):
        ctx = context()
        ctx['evaluation']['started_at'] = '2026-09-13T19:30:00+03:00'
        ctx['evaluation']['ended_at'] = '2026-09-13T20:00:00+03:00'
        payload, _, report = self.run_export(ctx, native(synthetic_results()))
        self.assertTrue(report['schema_valid'], report['errors'])
        self.assertEqual((payload['evaluation']['started_at'], payload['evaluation']['ended_at']),
                         ('2026-09-13T16:30:00Z', '2026-09-13T17:00:00Z'))
        ctx['evaluation']['started_at'] = '2026-09-13T16:00:00Z'
        ctx['evaluation']['ended_at'] = '2026-09-13T17:00:00Z'
        payload, _, _ = self.run_export(ctx, native(synthetic_results()))
        self.assertEqual(payload['evaluation']['ended_at'], '2026-09-13T17:00:00Z')
        for naive in ('2026-09-13T17:00:00', '2026-09-13 17:00:00', '2026-09-13'):
            with self.subTest(naive=naive):
                ctx['evaluation']['ended_at'] = naive
                with self.assertRaises(x.ExportError):
                    self.run_export(ctx, native(synthetic_results()))

    def test_negative_duration_is_refused(self):
        ctx = context()
        ctx['evaluation']['started_at'] = '2026-09-13T17:00:00Z'
        ctx['evaluation']['ended_at'] = '2026-09-13T16:59:59Z'
        with self.assertRaises(x.ExportError) as caught:
            self.run_export(ctx, native(synthetic_results()))
        self.assertIn('precedes', str(caught.exception))
        # Different offsets that still order correctly are fine.
        ctx['evaluation']['started_at'] = '2026-09-13T19:00:00+03:00'   # 16:00Z
        ctx['evaluation']['ended_at'] = '2026-09-13T16:30:00Z'
        payload, _, _ = self.run_export(ctx, native(synthetic_results()))
        self.assertEqual(payload['evaluation']['started_at'], '2026-09-13T16:00:00Z')

    def test_unsupported_input_shape_is_named_not_generic(self):
        valid_but_wrong = x.NativeFile(RESULTS_NAME, 'aggregate-result', json.dumps({'evaluation_results': [], 'schema_version': '0.3.0'}).encode())
        with self.assertRaises(x.ExportError) as caught:
            self.run_export(context(), valid_but_wrong)
        self.assertIn('Unsupported input shape', str(caught.exception))
        self.assertIn('LightEval', str(caught.exception))
        broken = x.NativeFile(RESULTS_NAME, 'aggregate-result', b'{not json')
        with self.assertRaises(x.ExportError) as caught:
            self.run_export(context(), broken)
        self.assertIn('not valid JSON', str(caught.exception))
        self.assertNotIn('Unsupported input shape', str(caught.exception))

    def test_claim_vocabulary_records_declarations_and_establishes_only_digests(self):
        _, manifest, _ = self.run_export(context(), native(synthetic_results()))
        claims = manifest['claims']
        self.assertEqual(set(claims), {'records_or_preserves', 'establishes', 'does_not_establish'})
        self.assertTrue(all(c.startswith('declared ') for c in claims['records_or_preserves']), claims['records_or_preserves'])
        self.assertEqual(len(claims['establishes']), 2)
        joined = ' '.join(claims['establishes']).lower()
        self.assertIn('sha-256', joined); self.assertIn('validates', joined)
        for word in ('declared', 'engagement', 'access', 'target', 'measurement state', 'true', 'safe'):
            self.assertNotIn(word, joined, f'"{word}" must not appear under establishes')
        self.assertTrue(any('declarations are recorded, not verified' in c for c in claims['does_not_establish']))

    def test_evidence_digests_are_sha256_of_exact_bytes(self):
        results = native(synthetic_results())
        details = x.NativeFile('details_example_2026-09-12T10-20-00.000000.parquet', 'sample-details', b'PAR1 synthetic bytes')
        log = x.NativeFile('run.log', 'system-log', b'line one\nline two\n')
        payload, manifest, _ = self.run_export(context(), results, [details, log])
        roles = [(e['role'], e['digest'], e['media_type']) for e in payload['evidence']]
        self.assertEqual(roles, [
            ('aggregate-result', 'sha256:' + hashlib.sha256(results.raw).hexdigest(), 'application/json'),
            ('sample-details', 'sha256:' + hashlib.sha256(b'PAR1 synthetic bytes').hexdigest(), 'application/x-parquet'),
            ('system-log', 'sha256:' + hashlib.sha256(b'line one\nline two\n').hexdigest(), 'text/plain'),
        ])
        self.assertEqual([i['sha256'] for i in manifest['inputs']], [r[1] for r in roles])
        self.assertFalse(any(e['resolvable'] for e in payload['evidence']))

    def test_not_run_is_preserved_as_not_measured(self):
        ctx = context()
        ctx['evaluation']['started_at'] = '2026-09-12T12:00:00Z'
        ctx['evaluation']['ended_at'] = '2026-09-12T12:00:00Z'
        ctx['evaluation']['framework'] = {'name': 'lighteval', 'version': '0.11.0'}
        ctx['evaluation']['tasks'] = [{'task_id': 'example|task|0'}]
        ctx['measurement']['execution_status'] = 'NOT_RUN'
        ctx['measurement']['observed'] = {'status': 'NOT_MEASURED', 'summary': 'The endpoint was unavailable; nothing ran.'}
        ctx['evidence']['additional'] = [{'evidence_id': 'ev-plan', 'role': 'plan', 'ref': 'urn:example:plan', 'resolvable': False,
                                          'digest': 'sha256:' + '0' * 64, 'visibility': 'public'}]
        payload, _, report = self.run_export(ctx)
        self.assertTrue(report['schema_valid'], report['errors'])
        self.assertEqual((payload['measurement']['execution_status'], payload['measurement']['observed']['status']), ('NOT_RUN', 'NOT_MEASURED'))
        self.assertNotIn('metric_value', payload['measurement']['observed'])

    def test_contradictory_states_are_refused(self):
        cases = []
        c = context(); c['measurement']['execution_status'] = 'NOT_RUN'; c['measurement']['observed'] = {'status': 'NOT_MEASURED', 'summary': 's'}
        cases.append(('NOT_RUN with results present', c, native(synthetic_results())))
        c = context(); c['measurement']['observed'] = {'status': 'PASS', 'summary': 's'}
        cases.append(('explicit PASS contradicts threshold FAIL', c, native(synthetic_results(0.1))))
        c = context(); c['measurement']['execution_status'] = 'NOT_RUN'; c['measurement']['observed'] = {'status': 'PASS', 'summary': 's'}
        c['evaluation'].update({'started_at': '2026-09-12T12:00:00Z', 'ended_at': '2026-09-12T12:00:00Z', 'tasks': [{'task_id': 't'}]})
        c['evaluation']['framework'] = {'name': 'lighteval'}
        cases.append(('NOT_RUN + PASS', c, None))
        c = context(); c['measurement']['execution_status'] = 'INVALIDATED'; c['measurement']['observed'] = {'status': 'FAIL', 'summary': 's'}
        cases.append(('INVALIDATED + FAIL', c, native(synthetic_results())))
        c = context(); c['measurement']['criterion']['metric'] = 'missing_metric'
        cases.append(('declared metric absent from results', c, native(synthetic_results())))
        c = context(); c['measurement']['criterion'].pop('threshold')
        cases.append(('metric without threshold or explicit status', c, native(synthetic_results())))
        c = context(); c['measurement']['criterion']['threshold'] = 0.6
        cases.append(('bare numeric threshold', c, native(synthetic_results())))
        c = context(); c['measurement']['execution_status'] = 'RAN'
        cases.append(('RAN without results', c, None))
        for name, ctx, results in cases:
            with self.subTest(case=name):
                with self.assertRaises(x.ExportError):
                    self.run_export(ctx, results)

    def test_independence_and_access_are_never_inferred(self):
        for path in ('engagement.independence.status', 'engagement.independence.basis', 'access.tier',
                     'access.capabilities', 'access.limitations', 'evaluation.environment', 'evaluation.safeguards'):
            with self.subTest(missing=path):
                ctx = context()
                node = ctx
                *parents, last = path.split('.')
                for p in parents:
                    node = node[p]
                del node[last]
                with self.assertRaises(x.ExportError) as caught:
                    self.run_export(ctx, native(synthetic_results()))
                self.assertIn(path, str(caught.exception))

    def test_platform_verify_token_is_preserved_not_evaluated(self):
        ctx = context()
        ctx['platform_verification'] = {'verifier': 'huggingface-hub', 'verify_token': 'eyJhbGciOi.example.token',
                                        'ref': 'hf://models/example-org/example-model/.eval_results/lighteval.yaml'}
        payload, _, report = self.run_export(ctx, native(synthetic_results()))
        self.assertTrue(report['schema_valid'], report['errors'])
        [entry] = payload['verification']
        self.assertEqual((entry['kind'], entry['status'], entry['independence']), ('platform-verification', 'NOT_EVALUATED', 'unknown'))
        self.assertEqual(entry['digest'], 'sha256:' + hashlib.sha256(b'eyJhbGciOi.example.token').hexdigest())
        self.assertNotIn('eyJhbGciOi', json.dumps(payload))
        self.assertNotIn('class', json.dumps(payload).lower().replace('subclass', ''))

    def test_multiple_tasks_require_an_explicit_task(self):
        doc = synthetic_results()
        doc['results']['other|task|0'] = {'acc': 0.5}
        ctx = context(); ctx['measurement']['criterion'].pop('task')
        with self.assertRaises(x.ExportError):
            self.run_export(ctx, native(doc))
        ctx = context()
        payload, _, report = self.run_export(ctx, native(doc))
        self.assertTrue(report['schema_valid'], report['errors'])
        self.assertEqual({t['task_id'] for t in payload['evaluation']['tasks']}, {'example|task|0', 'other|task|0'})

    def test_withheld_evidence_needs_a_reason(self):
        ctx = context(); ctx['evidence']['visibility'] = 'withheld'
        with self.assertRaises(x.ExportError):
            self.run_export(ctx, native(synthetic_results()))
        ctx['evidence']['withholding_reason'] = 'contains customer prompts'
        payload, _, report = self.run_export(ctx, native(synthetic_results()))
        self.assertTrue(report['schema_valid'], report['errors'])
        self.assertEqual(payload['evidence'][0]['withholding_reason'], 'contains customer prompts')

    def test_cli_end_to_end_and_refusal_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            results = td / RESULTS_NAME
            results.write_text(json.dumps(synthetic_results(), indent=2))
            (td / 'run.log').write_text('ok\n')
            out = td / 'out'
            cmd = [sys.executable, str(INTEGRATION / 'export_embedded_evaluation.py'), '--results', str(results),
                   '--log', str(td / 'run.log'), '--context', str(INTEGRATION / 'example_context.json'), '--out-dir', str(out)]
            run = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            for name in ('embedded-evaluation.profile.json', 'evidence-manifest.json', 'validation-report.json'):
                self.assertTrue((out / name).is_file(), name)
            report = json.loads((out / 'validation-report.json').read_text())
            self.assertTrue(report['schema_valid'])
            self.assertEqual(report['basis_digest'], self.basis.schema_digest)
            # Contradiction → exit 2 and no payload file.
            bad = deepcopy(json.loads((INTEGRATION / 'example_context.json').read_text()))
            bad['measurement']['execution_status'] = 'NOT_RUN'
            bad['measurement']['observed'] = {'status': 'NOT_MEASURED', 'summary': 's'}
            (td / 'bad.json').write_text(json.dumps(bad))
            out2 = td / 'out2'
            run = subprocess.run(cmd[:-3] + ['--context', str(td / 'bad.json'), '--out-dir', str(out2)], capture_output=True, text=True)
            self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
            self.assertFalse((out2 / 'embedded-evaluation.profile.json').exists())


if __name__ == '__main__':
    unittest.main()
