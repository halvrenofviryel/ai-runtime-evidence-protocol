"""Regression tests for the deterministic Hermes -> AIREP mapping corpus.

Run: python3 -m unittest discover -s integrations/hermes/tests -v
"""
from collections import Counter
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
sys.path.insert(0, str(ROOT))

import generate_fixtures as generator  # noqa: E402
import verify_fixtures as verifier  # noqa: E402
from tools.airep_v02.json_input import loads  # noqa: E402


class HermesMappingTests(unittest.TestCase):
    def test_complete_validation_entry_point(self):
        result = verifier.validate()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(result["fixtures"]), 11)
        self.assertEqual(result["record_count"], 31)
        self.assertRegex(result["corpus_manifest_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_fresh_generation_is_byte_identical(self):
        with tempfile.TemporaryDirectory(prefix="hermes mapping test ") as tmp:
            fresh = Path(tmp) / "generated"
            generator.build_tree(fresh)
            self.assertEqual(
                generator.generated_files(fresh),
                generator.generated_files(INTEGRATION),
            )

    def test_expected_family_and_negative_state_coverage(self):
        summary = loads((INTEGRATION / "summary.json").read_bytes())
        by_id = {row["id"]: row for row in summary["fixtures"]}
        self.assertEqual(set(by_id), {scenario_id for scenario_id, _, _ in generator.SCENARIOS})
        all_families = Counter()
        for row in by_id.values():
            all_families.update(row["artifact_family_counts"])
        self.assertTrue({"decision", "control", "execution", "effect"}.issubset(all_families))
        self.assertEqual(by_id["HERMES-AIREP-06"]["expected_negative_states"],
                         {"execution_outcome": ["FAILURE"]})
        self.assertEqual(by_id["HERMES-AIREP-07"]["expected_negative_states"],
                         {"toctou": ["FAILURE"]})
        self.assertEqual(
            by_id["HERMES-AIREP-11"]["important_reconciliation_states"]["observer_relationship"],
            ["SATISFIED"],
        )

    def test_unknown_stages_remain_absent_and_ids_are_distinct(self):
        for _, directory, _ in generator.SCENARIOS:
            fixture = INTEGRATION / "fixtures" / directory
            facts = loads((fixture / "native_facts.json").read_bytes())
            artifacts = loads((fixture / "artifacts.json").read_bytes())
            request_id = facts["observed_source_facts"]["approval_request_id"]
            instruction_ids = {
                artifact["instruction_id"] for artifact in artifacts
                if artifact["artifact_type"] in ("control", "execution")
            }
            self.assertNotIn(request_id, instruction_ids)
            if directory in ("03-release-no-dispatch", "04-dispatch-no-execution",
                             "09-consumed-crash-unknown"):
                self.assertNotIn("execution", [a["artifact_type"] for a in artifacts])
        scenario_03 = loads((INTEGRATION / "fixtures/03-release-no-dispatch/artifacts.json").read_bytes())
        self.assertEqual([a["artifact_type"] for a in scenario_03], ["decision"])

    def test_generator_requires_an_explicit_mode(self):
        run = subprocess.run(
            [sys.executable, str(INTEGRATION / "generate_fixtures.py")],
            cwd=ROOT, capture_output=True, text=True,
        )
        self.assertEqual(run.returncode, 2)
        self.assertIn("required", run.stderr)

    def test_docs_preserve_claim_boundaries_and_source_basis(self):
        mapping = (INTEGRATION / "MAPPING.md").read_text(encoding="utf-8")
        readme = (INTEGRATION / "README.md").read_text(encoding="utf-8")
        gaps = (INTEGRATION / "UPSTREAM_GAPS.md").read_text(encoding="utf-8")
        basis = json.loads((INTEGRATION / "SOURCE_BASIS.json").read_text(encoding="utf-8"))
        self.assertIn("request_id` ≠ Control `instruction_id", mapping)
        self.assertIn("not a Hermes-native authorization contract", mapping)
        self.assertIn("not independent Hermes", readme)
        self.assertIn("open and unmerged", gaps)
        self.assertEqual(basis["airep_commit"], generator.AIREP_COMMIT)
        self.assertEqual(basis["hermes_commit"], generator.HERMES_COMMIT)
        self.assertIn("open/unmerged", basis["hermes_pr_104960"]["status"])


if __name__ == "__main__":
    unittest.main()
