import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'run.py'
# multiprocessing.spawn needs the module to be importable by its actual name.
import sys
sys.path.insert(0, str(MODULE.parent))
import run


class RuntimeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='airep-langgraph-tests-')
        cls.root = Path(cls.scratch.name)
        cls.events = {name: run.collect_run(cls.root / name, name) for name in run.SCENARIOS}

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def kinds(self, scenario):
        return [e['kind'] for e in self.events[scenario]]

    def artifacts(self, scenario, events=None):
        return run.project(events if events is not None else self.events[scenario], scenario)[0]

    def test_normal_executes_all_real_file_steps(self):
        self.assertEqual(run.observe(self.root / 'normal')['steps'], [1, 2, 3, 4])
        self.assertIn('graph_completed', self.kinds('normal'))
        self.assertNotIn('native_interrupt_observed', self.kinds('normal'))
        self.assertEqual(self.artifacts('normal'), [])

    def test_prestart_stop_has_actual_checkpoint_and_zero_side_effects(self):
        kinds = self.kinds('stop-before-start')
        self.assertLess(kinds.index('issuer_dispatched'), kinds.index('graph_invocation_started'))
        self.assertLess(kinds.index('receiver_observed'), kinds.index('native_interrupt_observed'))
        self.assertNotIn('business_step_written', kinds)
        paused = next(e for e in self.events['stop-before-start'] if e['kind'] == 'native_interrupt_observed')
        self.assertEqual(paused['checkpoint_next'], ['controlled_action'])
        self.assertEqual(run.observe(self.root / 'stop-before-start')['completed_steps'], 0)

    def test_inflight_stop_preserves_completed_side_effect(self):
        kinds = self.kinds('stop-during-action')
        self.assertLess(kinds.index('business_step_written'), kinds.index('issuer_dispatched'))
        self.assertEqual(run.observe(self.root / 'stop-during-action')['steps'], [1])
        self.assertIn('native_interrupt_observed', kinds)
        self.assertNotIn('graph_completed', kinds)

    def test_unreachable_receiver_has_real_failure_and_no_fabricated_receipt(self):
        events = self.events['receiver-unreachable']
        failed = next(e for e in events if e['kind'] == 'delivery_failed')
        self.assertEqual(failed['error'], 'BrokenPipeError')
        artifacts = self.artifacts('receiver-unreachable')
        self.assertEqual([a['artifact_type'] for a in artifacts], ['decision', 'control'])
        self.assertEqual(artifacts[1]['control_event'], 'delivery_failed')
        report = run.reconcile(artifacts)
        states = {c['check']: c['state'] for c in report['checks']}
        self.assertEqual(states['receiver_receipt'], 'MISSING')
        self.assertEqual(states['execution_evidence'], 'MISSING')
        self.assertEqual(states['issuer_dispatch'], 'MISSING')
        self.assertEqual(run.observe(self.root / 'receiver-unreachable')['steps'], [1, 2, 3, 4])

    def test_receipt_is_not_enforcement(self):
        artifacts = self.artifacts('receiver-ignores-stop')
        execution = next(a for a in artifacts if a['artifact_type'] == 'execution')
        self.assertEqual(execution['execution_event'], 'failed')
        checks = {c['check']: c['state'] for c in run.reconcile(artifacts)['checks']}
        self.assertEqual(checks['receiver_receipt'], 'SATISFIED')
        self.assertEqual(checks['execution_outcome'], 'FAILURE')
        self.assertEqual(checks['toctou'], 'FAILURE')
        self.assertEqual(run.observe(self.root / 'receiver-ignores-stop')['steps'], [1, 2, 3, 4])

    def test_effect_is_not_inferred_from_native_interrupt(self):
        artifacts = self.artifacts('effect-unobserved')
        self.assertTrue(any(a['artifact_type'] == 'execution' for a in artifacts))
        self.assertFalse(any(a['artifact_type'] == 'effect' for a in artifacts))
        checks = {c['check']: c['state'] for c in run.reconcile(artifacts)['checks']}
        self.assertEqual(checks['effect_evidence'], 'MISSING')

    def test_omission_controls_cannot_upgrade_missing_stages(self):
        for missing in ('receiver_observed', 'enforcement_requested', 'native_interrupt_observed'):
            with self.subTest(missing=missing):
                events = [e for e in self.events['stop-before-start'] if e['kind'] != missing]
                artifacts = self.artifacts('stop-before-start', events)
                self.assertFalse(any(a['artifact_type'] in ('execution', 'effect') for a in artifacts))

    def test_mismatched_runtime_pause_identity_is_not_stop_execution(self):
        events = json.loads(json.dumps(self.events['stop-before-start']))
        paused = next(e for e in events if e['kind'] == 'native_interrupt_observed')
        paused['interrupts'][0]['value']['instruction_id'] = 'another-command'
        self.assertFalse(any(a['artifact_type'] == 'execution' for a in self.artifacts('stop-before-start', events)))

    def test_event_pointer_hashes_and_frozen_core_admission(self):
        for scenario, events in self.events.items():
            for artifact in self.artifacts(scenario):
                run.reconcile([artifact])  # Exercises the preserved core verifier.
                from tools.airep_v02.producer import check_core
                check_core(artifact)
                for pointer in artifact['evidence']:
                    self.assertEqual(run.digest_bytes((self.root / scenario / pointer['ref']).read_bytes()), pointer['content_hash'])

    def test_explain_keeps_non_evaluated_and_same_executor_limits(self):
        view = run.explain(self.artifacts('stop-during-action'))
        for name in ('enforcement_observed', 'relying_party_claim_support'):
            row = next(r for r in view['claim_matrix'] if r['claim'] == name)
            self.assertIsNone(row['source_status'])
            self.assertEqual(row['explanatory_status'], 'NOT_EVALUATED')
        effects = [a for a in self.artifacts('stop-during-action') if a['artifact_type'] == 'effect']
        self.assertEqual(effects[0]['observer_relationship'], 'same_executor')

    def test_all_runs_join_processes_without_forced_stop(self):
        for events in self.events.values():
            cleanup = events[-1]
            self.assertEqual(cleanup['kind'], 'cleanup_completed')
            self.assertFalse(cleanup['worker_alive'])
            self.assertFalse(cleanup['forced_termination'])
            self.assertEqual(cleanup['worker_exitcode'], 0)

    def test_timeout_cleans_up_and_never_becomes_successful_enforcement(self):
        out = self.root / 'timeout-negative'
        with self.assertRaises(TimeoutError):
            run.collect_run(out, 'normal', timeout=0.001)
        events = [json.loads(line) for line in (out / 'events.jsonl').read_text().splitlines()]
        self.assertFalse(events[-1]['worker_alive'])
        self.assertTrue(events[-1]['forced_termination'])
        self.assertFalse(any(a['artifact_type'] == 'execution' for a in run.project(events, 'timeout')[0]))

    def test_guard_removes_inherited_values_and_refuses_connections(self):
        script = ('import os, socket, run; run.disable_network(); '
                  'assert "K3_TEST_SECRET" not in os.environ; '
                  'assert os.environ["LANGSMITH_TRACING"] == "false"; '
                  '\ntry: socket.create_connection(("127.0.0.1", 9))'
                  '\nexcept RuntimeError as exc: assert "Network disabled" in str(exc)'
                  '\nelse: raise AssertionError("network guard did not reject connection")')
        # This is an invented test value, not an existing credential.
        result = subprocess.run([sys.executable, '-c', script], cwd=MODULE.parent,
                                env={'PATH': os.defpath, 'K3_TEST_SECRET': 'fixture-only'},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
