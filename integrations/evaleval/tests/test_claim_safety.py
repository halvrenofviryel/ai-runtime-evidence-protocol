"""Adversarial tests for the narrow LightEval -> EEE research mapper."""

from __future__ import annotations

import copy
import importlib.util
import json
import math
from pathlib import Path
import unittest


HERE = Path(__file__).resolve()
MAPPER_PATH = HERE.parents[1] / "experimental_lighteval_to_eee.py"
SPEC = importlib.util.spec_from_file_location("experimental_lighteval_to_eee", MAPPER_PATH)
assert SPEC and SPEC.loader
MAPPER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAPPER)

LIGHTEVAL_COMMIT = "6b9d193b48de24d1ee87f3089303643b993cf4f9"
MODEL_REVISION = "5f91d94bd9cd7190a9f3216ff93cd1dd95f2c7be"
DATASET_REVISION = "218ec52e09a7e7462a5400043bb9a69a41d06b76"


def source_document() -> dict:
    return {
        "config_general": {
            "lighteval_sha": LIGHTEVAL_COMMIT,
            "max_samples": 2,
            "model_name": "sshleifer/tiny-gpt2",
            "model_config": {
                "model_name": "sshleifer/tiny-gpt2",
                "revision": MODEL_REVISION,
                "generation_parameters": {"temperature": 0},
            },
        },
        "results": {
            "hellaswag|0": {"em": 0.0, "em_stderr": 0.0},
            "all": {"em": 0.0, "em_stderr": 0.0},
        },
        "config_tasks": {
            "hellaswag|0": {
                "name": "hellaswag",
                "hf_repo": "Rowan/hellaswag",
                "hf_revision": DATASET_REVISION,
                "evaluation_splits": ["validation"],
                "generation_size": 1,
                "num_fewshots": 0,
                "prompt_function": "hellaswag_prompt",
                "stop_sequence": ["\n"],
                "metrics": [
                    {
                        "metric_name": "em",
                        "higher_is_better": True,
                        "sample_level_fn": "ExactMatches(strip_strings=True)",
                        "corpus_level_fn": "mean",
                    }
                ],
            }
        },
    }


def context_document() -> dict:
    return {
        "record_created_at": "2026-09-23T22:03:06.509768Z",
        "selector": {"task": "hellaswag|0", "metric": "em", "stderr_metric": "em_stderr"},
        "expected": {
            "lighteval_commit": LIGHTEVAL_COMMIT,
            "model_id": "sshleifer/tiny-gpt2",
            "model_revision": MODEL_REVISION,
            "dataset_repo": "Rowan/hellaswag",
            "dataset_revision": DATASET_REVISION,
        },
        "source": {
            "source_name": "LightEval native results",
            "source_type": "evaluation_run",
            "source_organization_name": "AIREP EEE crosswalk experiment",
            "evaluator_relationship": "third_party",
            "relationship_basis": "Declared operator relationship; independence was not evaluated.",
        },
        "lighteval": {"package_version": "0.13.1.dev0"},
        "model": {
            "inference_platform": "local CPU",
            "inference_engine": {"name": "transformers", "version": "4.57.3"},
            "deployment_type": "self_deployed",
            "model_availability": "open_weights",
        },
        "dataset": {"dataset_name": "HellaSwag"},
        "metric": {
            "metric_id": "exact-match",
            "metric_kind": "accuracy",
            "metric_unit": "proportion",
            "lower_is_better": False,
            "score_type": "continuous",
            "min_score": 0.0,
            "max_score": 1.0,
            "description": "Source-reported exact-match score for the selected LightEval task.",
            "registry_revision": "8b83e9c",
        },
    }


def encode(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), allow_nan=True).encode()


def build(source: dict | None = None, context: dict | None = None):
    return MAPPER.build_record(encode(source or source_document()), encode(context or context_document()))


class ClaimSafetyTests(unittest.TestCase):
    def assert_refused(self, source=None, context=None, contains=None):
        with self.assertRaises(MAPPER.MappingError) as raised:
            build(source, context)
        if contains:
            self.assertIn(contains, str(raised.exception))

    def test_valid_narrow_mapping_preserves_score_without_verdict(self):
        record, report, _ = build()
        result = record["evaluation_results"][0]
        self.assertEqual(result["score_details"]["score"], 0.0)
        self.assertEqual(result["score_details"]["details"]["verdict"],
                         "not attributed to source evaluator")
        self.assertIn("no source criterion or PASS/FAIL verdict exists", report["material_limits"])

    def test_direction_lost_is_refused(self):
        source = source_document()
        del source["config_tasks"]["hellaswag|0"]["metrics"][0]["higher_is_better"]
        self.assert_refused(source=source, contains="direction is absent")

    def test_direction_reversed_is_refused(self):
        context = context_document()
        context["metric"]["lower_is_better"] = True
        self.assert_refused(context=context, contains="direction contradicts")

    def test_no_criterion_cannot_become_pass(self):
        context = context_document()
        context["criterion"] = {"threshold": ">= 0"}
        self.assert_refused(context=context, contains="criterion")

    def test_completion_cannot_become_source_verdict(self):
        context = context_document()
        context["source_verdict"] = "PASS"
        self.assert_refused(context=context, contains="source_verdict")

    def test_sample_cap_cannot_become_population_complete(self):
        context = context_document()
        context["population_complete"] = True
        self.assert_refused(context=context, contains="population_complete")

    def test_missing_framework_revision_fails(self):
        source = source_document()
        del source["config_general"]["lighteval_sha"]
        self.assert_refused(source=source, contains="lighteval_sha")

    def test_missing_model_revision_fails(self):
        source = source_document()
        del source["config_general"]["model_config"]["revision"]
        self.assert_refused(source=source, contains="model revision")

    def test_missing_dataset_revision_fails(self):
        source = source_document()
        del source["config_tasks"]["hellaswag|0"]["hf_revision"]
        self.assert_refused(source=source, contains="task hf_revision")

    def test_evaluator_relationship_does_not_establish_independence(self):
        record, report, _ = build()
        self.assertEqual(record["source_metadata"]["evaluator_relationship"], "third_party")
        self.assertIn("no evaluator independence is established", report["material_limits"])

    def test_independence_claim_is_refused_even_if_declared(self):
        context = context_document()
        context["independence"] = "independent-declared"
        self.assert_refused(context=context, contains="independence")

    def test_evidence_reference_cannot_claim_recomputed_digest(self):
        context = context_document()
        context["evidence_available"] = True
        self.assert_refused(context=context, contains="evidence_available")

    def test_restricted_or_unavailable_evidence_is_not_promoted_to_public(self):
        _, report, _ = build()
        serialized = json.dumps(report).lower()
        self.assertNotIn('"visibility": "public"', serialized)
        self.assertNotIn('"resolvable": true', serialized)

    def test_rounding_cannot_create_a_criterion(self):
        source = source_document()
        source["results"]["hellaswag|0"]["em"] = 0.9999999
        record, report, _ = build(source=source)
        self.assertEqual(record["evaluation_results"][0]["score_details"]["score"], 0.9999999)
        self.assertIn("no source criterion or PASS/FAIL verdict exists", report["material_limits"])

    def test_sample_trace_is_not_promoted_to_airep_lifecycle_evidence(self):
        _, report, _ = build()
        self.assertIn(
            "native details parquet is retained separately and is not converted to an EEE instance sidecar",
            report["material_limits"],
        )
        self.assertNotIn("decision", json.dumps(report["preserved_or_explicitly_derived"]).lower())

    def test_schema_pass_is_not_semantic_truth_or_interoperability(self):
        _, report, _ = build()
        self.assertIn(
            "schema validation does not establish semantic equivalence, truth or interoperability",
            report["material_limits"],
        )
        self.assertIn("EEE-AIREP interoperability", report["not_established"])

    def test_multi_task_source_is_refused(self):
        source = source_document()
        source["results"]["other|0"] = {"em": 1.0, "em_stderr": 0.0}
        source["config_tasks"]["other|0"] = copy.deepcopy(source["config_tasks"]["hellaswag|0"])
        self.assert_refused(source=source, contains="multi-task")

    def test_synthetic_all_selector_is_refused(self):
        context = context_document()
        context["selector"]["task"] = "all"
        self.assert_refused(context=context, contains="synthetic 'all'")

    def test_nonfinite_score_is_refused(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                source = source_document()
                source["results"]["hellaswag|0"]["em"] = value
                self.assert_refused(source=source, contains="finite JSON number")

    def test_malformed_generation_parameters_is_refused(self):
        source = source_document()
        source["config_general"]["model_config"]["generation_parameters"] = []
        self.assert_refused(source=source, contains="generation_parameters")

    def test_metric_range_is_explicit_and_enforced(self):
        context = context_document()
        context["metric"]["max_score"] = -0.1
        self.assert_refused(context=context, contains="min_score < max_score")
        context = context_document()
        context["metric"]["max_score"] = 0.5
        source = source_document()
        source["results"]["hellaswag|0"]["em"] = 0.75
        self.assert_refused(source=source, context=context, contains="outside")

    def test_deployment_and_availability_require_explicit_context(self):
        for field in ("deployment_type", "model_availability"):
            with self.subTest(field=field):
                context = context_document()
                del context["model"][field]
                self.assert_refused(context=context, contains=f"model.{field}")

    def test_duplicate_json_member_is_refused(self):
        source = encode(source_document())
        duplicate = source[:-1] + b',"results":{}}'
        with self.assertRaisesRegex(MAPPER.MappingError, "duplicate JSON member"):
            MAPPER.build_record(duplicate, encode(context_document()))


if __name__ == "__main__":
    unittest.main()
