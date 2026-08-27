#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Python reference interop evaluator.

Every input here is SYNTHETIC and constructed in this file. No corpus bytes and
no scenario fixtures are created: corpus construction is on HOLD until the
evaluator contract's section 12 step 3, and these tests deliberately do not
anticipate it. The synthetic artifacts are unsigned skeletons that are never
submitted to the frozen verifier -- the frozen-verifier subprocess is stubbed
through ``evaluate_bundle``'s ``invoke`` seam, so what is measured here is this
evaluator's own composition logic, not the frozen verifier's semantics.

Two tests DO touch the real frozen lane, because they measure this evaluator's
contract-3 obligations rather than any scenario outcome:
``test_frozen_digests_assert_against_the_repository`` and
``test_frozen_verifier_really_is_invocable``.

Usage:  python3 test_interop_eval.py     (or: python3 -m pytest test_interop_eval.py)
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import interop_eval as ie  # noqa: E402


# --------------------------------------------------------------------------
# Synthetic builders
# --------------------------------------------------------------------------

def artifact(artifact_type: str, record_id: str, chain_id: str = "chain-a", **extra):
    value = {
        "airep_version": "0.2",
        "artifact_type": artifact_type,
        "chain_id": chain_id,
        "record_id": record_id,
        "sequence": 1,
        "subject": {"producer": "wire-producer",
                    "timestamp_utc": "2026-01-01T00:00:00Z"},
        "scope": {"covers": [], "does_not_cover": []},
        "integrity": {"previous": "sha256:" + "0" * 64,
                      "current": "sha256:" + "1" * 64,
                      "signature": {"alg": "ed25519", "value": "a" * 128}},
    }
    value.update(extra)
    return value


DIGEST_ONE = "sha256:" + "1" * 64
DIGEST_TWO = "sha256:" + "2" * 64


def four_artifact_bundle(executed=DIGEST_ONE, effect_decision_ref="rec-decision"):
    """A synthetic Decision -> Control -> Execution -> Effect graph."""
    return [
        artifact("decision", "rec-decision",
                 input={}, claim={}, directive={}, output={}, evidence=[]),
        artifact("control", "rec-control",
                 decision_ref={"record_id": "rec-decision"},
                 instruction_id="i-1", instruction_digest=DIGEST_TWO,
                 authorized_action_digest=DIGEST_ONE,
                 control_event="authorize", boundary_side="inbound",
                 authority={}),
        artifact("execution", "rec-execution",
                 decision_ref={"record_id": "rec-decision"},
                 instruction_id="i-1", instruction_digest=DIGEST_TWO,
                 executed_action_digest=executed,
                 execution_event="execute"),
        artifact("effect", "rec-effect",
                 decision_ref={"record_id": effect_decision_ref},
                 execution_ref={"record_id": "rec-execution"},
                 observer_relationship="independent",
                 observed_state={}),
    ]


def verdict(record_id, chain_id="chain-a", cls="AIREP-Authenticated",
            authenticated_failures=(), authenticated_withheld=(),
            witnessed_withheld=("no-witness-supplied",),
            observer_assessment="not_applicable"):
    return {
        "artifact_ref": {"chain_id": chain_id, "record_id": record_id},
        "class": cls,
        "authenticated_failures": list(authenticated_failures),
        "authenticated_withheld": list(authenticated_withheld),
        "authenticated_caveats": [],
        "witnessed_failures": [],
        "witnessed_withheld": list(witnessed_withheld),
        "observer_assessment": observer_assessment,
        "evidence": {"now": None, "freshness_window_seconds": None,
                     "bindings_digest": None,
                     "independence_policy_digest": None,
                     "revocation_digest": None},
    }


def write_bundle(directory, scenario_id, artifacts, extra_files=None,
                 corrupt=None, omit=None, manifest_doc=None):
    """Write a synthetic bundle and a manifest whose digests are correct."""
    files = {}
    for index, value in enumerate(artifacts):
        name = "artifact-%d.json" % index
        files[name] = json.dumps(value, sort_keys=True).encode("utf-8")
    for name, payload in (extra_files or {}).items():
        files[name] = payload
    manifest_files = {name: hashlib.sha256(data).hexdigest()
                      for name, data in files.items()}
    for name, data in files.items():
        if name == omit:
            continue
        if name == corrupt:
            data = data + b" "
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(data)
    doc = manifest_doc if manifest_doc is not None else {
        "scenario_id": scenario_id, "files": manifest_files}
    with open(os.path.join(directory, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(doc, handle, sort_keys=True)
    return manifest_files


def make_args(bundle, **overrides):
    args = argparse.Namespace(
        bundle=bundle, bindings=None, independence_policy=None, revocation=None,
        now=None, freshness_window=None, head_witness=None)
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


def stub_invoke(per_record, exit_codes=None, stderr=b""):
    """Frozen-verifier stub keyed by the primary artifact's ``record_id``."""
    exit_codes = exit_codes or {}

    def invoke(request, flags):
        envelope = json.loads(request.decode("utf-8"))
        record_id = envelope["artifact"]["record_id"]
        code = exit_codes.get(record_id, 0)
        if code != 0:
            return code, b"", stderr
        return 0, json.dumps(per_record[record_id]).encode("utf-8"), stderr

    return invoke


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ie.main(argv)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------


class TestNumericPreflight(unittest.TestCase):
    def test_clean_document_passes(self):
        self.assertIsNone(ie.numeric_preflight(
            {"a": 1, "b": [0, 2.5], "c": {"d": ie.MAX_SAFE_INTEGER}}))

    def test_integer_above_2_53_is_rejected_with_its_pointer(self):
        offending = ie.numeric_preflight({"profiles": {"x.y": {"n": 2 ** 53}}})
        self.assertIsNotNone(offending)
        self.assertEqual("/profiles/x.y/n", offending[0])

    def test_max_safe_integer_is_admissible_but_one_more_is_not(self):
        self.assertIsNone(ie.numeric_preflight({"n": ie.MAX_SAFE_INTEGER}))
        self.assertIsNone(ie.numeric_preflight({"n": -ie.MAX_SAFE_INTEGER}))
        self.assertEqual("/n", ie.numeric_preflight({"n": ie.MAX_SAFE_INTEGER + 1})[0])
        self.assertEqual("/n", ie.numeric_preflight({"n": -ie.MAX_SAFE_INTEGER - 1})[0])

    def test_nan_and_infinity_are_rejected(self):
        for literal in ("NaN", "Infinity", "-Infinity", "1e400"):
            document = json.loads('{"v": %s}' % literal)
            offending = ie.numeric_preflight(document)
            self.assertIsNotNone(offending, literal)
            self.assertEqual("/v", offending[0])

    def test_array_index_and_rfc6901_escaping_in_pointers(self):
        self.assertEqual("/a/1", ie.numeric_preflight({"a": [1, 2 ** 53]})[0])
        self.assertEqual("/a~1b", ie.numeric_preflight({"a/b": 2 ** 53})[0])
        self.assertEqual("/a~0b", ie.numeric_preflight({"a~b": 2 ** 53})[0])

    def test_booleans_are_not_numbers(self):
        self.assertIsNone(ie.numeric_preflight({"t": True, "f": False}))


class TestEnvelope(unittest.TestCase):
    def test_related_artifacts_are_the_other_three_in_record_id_byte_order(self):
        artifacts = [ie.Artifact("f", v) for v in four_artifact_bundle()]
        artifacts.sort(key=lambda a: ie.record_sort_key(a.record_id))
        primary = [a for a in artifacts if a.artifact_type == "effect"][0]
        envelope = ie.build_envelope(primary, artifacts, None)
        self.assertEqual(primary.value, envelope["artifact"])
        self.assertEqual(["rec-control", "rec-decision", "rec-execution"],
                         [a["record_id"] for a in envelope["related_artifacts"]])

    def test_single_artifact_scenario_gets_an_empty_array_not_an_absent_member(self):
        artifacts = [ie.Artifact("f", artifact("decision", "rec-only"))]
        envelope = ie.build_envelope(artifacts[0], artifacts, None)
        self.assertIn("related_artifacts", envelope)
        self.assertEqual([], envelope["related_artifacts"])
        self.assertNotIn("head_witness", envelope)

    def test_head_witness_is_present_only_when_supplied(self):
        artifacts = [ie.Artifact("f", artifact("decision", "rec-only"))]
        witness = {"witness_id": "w"}
        self.assertEqual(witness,
                         ie.build_envelope(artifacts[0], artifacts, witness)["head_witness"])

    def test_envelope_digest_is_a_function_of_the_value_not_the_source_bytes(self):
        one = json.loads('{"b":2,"a":1}')
        two = json.loads('{"a":1,  "b":2}')
        self.assertEqual(ie.envelope_bytes(one), ie.envelope_bytes(two))
        self.assertTrue(ie.digest_str(ie.envelope_bytes(one)).startswith("sha256:"))
        self.assertEqual(71, len(ie.digest_str(ie.envelope_bytes(one))))


class TestPredicates(unittest.TestCase):
    def artifacts(self, **kwargs):
        values = four_artifact_bundle(**kwargs)
        return sorted((ie.Artifact("f", v) for v in values),
                      key=lambda a: ie.record_sort_key(a.record_id))

    def test_r_a_passes_when_every_reference_resolves_uniquely(self):
        self.assertEqual(ie.PASS, ie.predicate_r_a(self.artifacts())[0])

    def test_r_a_fails_on_an_unresolved_reference(self):
        outcome, why = ie.predicate_r_a(
            self.artifacts(effect_decision_ref="rec-absent-0000"))
        self.assertEqual(ie.FAIL, outcome)
        self.assertTrue(any("unresolved" in reason for reason in why))

    def test_r_a_fails_closed_on_an_ambiguous_reference(self):
        artifacts = self.artifacts()
        artifacts.append(ie.Artifact("dup", artifact("decision", "rec-decision",
                                                     input={}, claim={}, directive={},
                                                     output={}, evidence=[])))
        outcome, why = ie.predicate_r_a(artifacts)
        self.assertEqual(ie.FAIL, outcome)
        self.assertTrue(any("ambiguous" in reason for reason in why))

    def test_chain_id_narrows_resolution_when_the_reference_carries_one(self):
        artifacts = self.artifacts()
        self.assertEqual("resolved", ie.resolve_reference(
            {"record_id": "rec-decision", "chain_id": "chain-a"}, artifacts))
        self.assertEqual("unresolved", ie.resolve_reference(
            {"record_id": "rec-decision", "chain_id": "chain-other"}, artifacts))

    def test_r_b_compares_exact_strings(self):
        self.assertEqual(ie.PASS, ie.predicate_r_b(self.artifacts())[0])
        self.assertEqual(ie.FAIL,
                         ie.predicate_r_b(self.artifacts(executed=DIGEST_TWO))[0])

    def test_r_b_does_not_case_fold(self):
        artifacts = self.artifacts()
        control = [a for a in artifacts if a.artifact_type == "control"][0]
        control.value["authorized_action_digest"] = DIGEST_ONE.upper()
        self.assertEqual(ie.FAIL, ie.predicate_r_b(artifacts)[0])

    def test_r_c_is_taken_from_the_frozen_observer_assessment(self):
        artifacts = self.artifacts()
        clean = {"rec-effect": verdict("rec-effect", observer_assessment="independent")}
        self.assertEqual(ie.PASS, ie.predicate_r_c(artifacts, clean)[0])
        broken = {"rec-effect": verdict("rec-effect", observer_assessment="unknown")}
        self.assertEqual(ie.FAIL, ie.predicate_r_c(artifacts, broken)[0])

    def test_r_c_does_not_fail_when_the_wire_never_claimed_independence(self):
        artifacts = self.artifacts()
        effect = [a for a in artifacts if a.artifact_type == "effect"][0]
        effect.value["observer_relationship"] = "same_executor"
        verdicts = {"rec-effect": verdict("rec-effect", observer_assessment="unknown")}
        self.assertEqual(ie.PASS, ie.predicate_r_c(artifacts, verdicts)[0])


class TestLevel1Mapping(unittest.TestCase):
    def test_pinned_order(self):
        every_fail = {"R_A": ie.FAIL, "R_B": ie.FAIL, "R_C": ie.FAIL}
        self.assertEqual(ie.REJECT, ie.map_level1(True, every_fail))
        self.assertEqual(ie.INDEPENDENCE_NOT_ESTABLISHED,
                         ie.map_level1(False, every_fail))
        self.assertEqual(ie.RECONCILIATION_MISMATCH, ie.map_level1(
            False, {"R_A": ie.FAIL, "R_B": ie.PASS, "R_C": ie.PASS}))
        self.assertEqual(ie.RECONCILIATION_MISMATCH, ie.map_level1(
            False, {"R_A": ie.PASS, "R_B": ie.FAIL, "R_C": ie.PASS}))
        self.assertEqual(ie.ACCEPT, ie.map_level1(
            False, {"R_A": ie.PASS, "R_B": ie.PASS, "R_C": ie.PASS}))

    def test_not_applicable_is_never_a_fail_and_never_a_pass_shortcut(self):
        self.assertEqual(ie.ACCEPT, ie.map_level1(False, ie.na_predicates()))


class TestBundleEvaluation(unittest.TestCase):
    def evaluate(self, scenario_id, artifacts, verdicts, exit_codes=None):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, scenario_id, artifacts)
            return ie.evaluate_bundle(
                make_args(directory),
                invoke=stub_invoke(verdicts, exit_codes))

    def clean_verdicts(self, observer="independent"):
        return {
            "rec-decision": verdict("rec-decision"),
            "rec-control": verdict("rec-control"),
            "rec-execution": verdict("rec-execution"),
            "rec-effect": verdict("rec-effect", observer_assessment=observer),
        }

    def test_clean_reconciliation_bundle_accepts_with_all_three_predicates_pass(self):
        code, result = self.evaluate("IOP-R-CLEAN", four_artifact_bundle(),
                                     self.clean_verdicts())
        self.assertEqual(0, code)
        self.assertEqual(ie.MEASURED, result["measurement_status"])
        self.assertEqual(ie.ACCEPT, result["level1"])
        self.assertEqual({"R_A": ie.PASS, "R_B": ie.PASS, "R_C": ie.PASS},
                         result["predicates"])
        self.assertEqual(4, len(result["artifacts"]))

    def test_digest_mismatch_scenario_maps_to_reconciliation_mismatch(self):
        code, result = self.evaluate("IOP-R-TOCTOU",
                                     four_artifact_bundle(executed=DIGEST_TWO),
                                     self.clean_verdicts())
        self.assertEqual(0, code)
        self.assertEqual(ie.RECONCILIATION_MISMATCH, result["level1"])
        self.assertEqual({"R_A": ie.PASS, "R_B": ie.FAIL, "R_C": ie.PASS},
                         result["predicates"])

    def test_unresolved_reference_scenario_maps_to_reconciliation_mismatch(self):
        code, result = self.evaluate(
            "IOP-R-XREF", four_artifact_bundle(effect_decision_ref="rec-absent-0000"),
            self.clean_verdicts())
        self.assertEqual(0, code)
        self.assertEqual(ie.RECONCILIATION_MISMATCH, result["level1"])
        self.assertEqual({"R_A": ie.FAIL, "R_B": ie.PASS, "R_C": ie.PASS},
                         result["predicates"])

    def test_independence_scenario_maps_to_independence_not_established(self):
        code, result = self.evaluate("IOP-R-INDEP", four_artifact_bundle(),
                                     self.clean_verdicts(observer="unknown"))
        self.assertEqual(0, code)
        self.assertEqual(ie.INDEPENDENCE_NOT_ESTABLISHED, result["level1"])
        self.assertEqual({"R_A": ie.PASS, "R_B": ie.PASS, "R_C": ie.FAIL},
                         result["predicates"])

    def test_all_three_predicates_run_even_after_one_has_failed(self):
        _, result = self.evaluate("IOP-R-TOCTOU",
                                  four_artifact_bundle(executed=DIGEST_TWO,
                                                       effect_decision_ref="rec-absent"),
                                  self.clean_verdicts())
        self.assertEqual({"R_A": ie.FAIL, "R_B": ie.FAIL, "R_C": ie.PASS},
                         result["predicates"])

    def test_single_artifact_scenario_is_not_run_through_the_predicates(self):
        code, result = self.evaluate(
            "IOP-P-DEC",
            [artifact("decision", "rec-only", input={}, claim={}, directive={},
                      output={}, evidence=[])],
            {"rec-only": verdict("rec-only")})
        self.assertEqual(0, code)
        self.assertEqual(ie.ACCEPT, result["level1"])
        self.assertEqual(ie.na_predicates(), result["predicates"])

    def test_authenticated_failure_is_a_reject_at_step_1(self):
        verdicts = self.clean_verdicts()
        verdicts["rec-execution"] = verdict(
            "rec-execution", cls="AIREP-Core",
            authenticated_failures=["producer-signature-invalid"])
        code, result = self.evaluate("IOP-B-EXE", four_artifact_bundle(), verdicts)
        self.assertEqual(0, code)
        self.assertEqual(ie.REJECT, result["level1"])

    def test_reject_precedes_the_reconciliation_predicates(self):
        verdicts = self.clean_verdicts(observer="unknown")
        verdicts["rec-control"] = verdict(
            "rec-control", cls="AIREP-Core",
            authenticated_failures=["producer-binding-revoked"])
        _, result = self.evaluate("IOP-R-INDEP",
                                  four_artifact_bundle(executed=DIGEST_TWO), verdicts)
        self.assertEqual(ie.REJECT, result["level1"])
        self.assertEqual(ie.FAIL, result["predicates"]["R_C"])

    # ---- contract 7.1 ----------------------------------------------------

    def test_authenticated_withheld_is_measurement_invalid_never_accept(self):
        verdicts = self.clean_verdicts()
        verdicts["rec-effect"] = verdict(
            "rec-effect", cls="AIREP-Core",
            authenticated_withheld=["producer-binding-missing"],
            observer_assessment="unknown")
        with self.assertRaises(ie.Unmeasurable) as caught:
            self.evaluate("IOP-R-CLEAN", four_artifact_bundle(), verdicts)
        self.assertEqual(ie.MEASUREMENT_INVALID, caught.exception.status)
        self.assertEqual("IOP-R-CLEAN", caught.exception.scenario_id)
        reasons = caught.exception.withheld_reasons
        self.assertTrue(any(r["authenticated_withheld"] == ["producer-binding-missing"]
                            for r in reasons))

    def test_witnessed_withheld_alone_is_reported_but_still_measured(self):
        _, result = self.evaluate("IOP-R-CLEAN", four_artifact_bundle(),
                                  self.clean_verdicts())
        self.assertEqual(ie.MEASURED, result["measurement_status"])
        self.assertEqual(4, len(result["withheld_reasons"]))
        self.assertEqual(["no-witness-supplied"],
                         result["withheld_reasons"][0]["witnessed_withheld"])

    # ---- contract 7.2 ----------------------------------------------------

    def test_exit_1_is_reject_only_for_the_three_pinned_scenarios(self):
        for scenario in ("IOP-B-DEC", "IOP-B-CTL", "IOP-B-EFF"):
            code, result = self.evaluate(
                scenario,
                [artifact("decision", "rec-only", input={}, claim={}, directive={},
                          output={}, evidence=[])],
                {}, exit_codes={"rec-only": 1})
            self.assertEqual(0, code, scenario)
            self.assertEqual(ie.REJECT, result["level1"], scenario)
            self.assertIsNone(result["artifacts"][0]["verifier_result"], scenario)
            self.assertEqual(1, result["artifacts"][0]["verifier_exit_code"], scenario)

    def test_exit_1_anywhere_else_is_the_evaluators_own_error(self):
        for scenario in ("IOP-B-EXE", "IOP-P-DEC", "IOP-R-CLEAN"):
            with self.assertRaises(ie.Unmeasurable) as caught:
                self.evaluate(
                    scenario,
                    [artifact("decision", "rec-only", input={}, claim={},
                              directive={}, output={}, evidence=[])],
                    {}, exit_codes={"rec-only": 1})
            self.assertEqual(ie.ERROR, caught.exception.status, scenario)

    def test_a_frozen_exit_2_is_never_a_level1_result(self):
        with self.assertRaises(ie.Unmeasurable) as caught:
            self.evaluate(
                "IOP-B-DEC",
                [artifact("decision", "rec-only", input={}, claim={}, directive={},
                          output={}, evidence=[])],
                {}, exit_codes={"rec-only": 2})
        self.assertEqual(ie.ERROR, caught.exception.status)

    # ---- contract 8.3 / 8.4 ---------------------------------------------

    def test_artifact_entry_shape_and_ordering(self):
        _, result = self.evaluate("IOP-R-CLEAN", four_artifact_bundle(),
                                  self.clean_verdicts())
        self.assertEqual(["rec-control", "rec-decision", "rec-effect", "rec-execution"],
                         [e["artifact_ref"]["record_id"] for e in result["artifacts"]])
        for entry in result["artifacts"]:
            self.assertEqual({"artifact_ref", "request_envelope_digest",
                              "verifier_exit_code", "verifier_result",
                              "verifier_stderr_digest"}, set(entry))
            self.assertTrue(entry["request_envelope_digest"].startswith("sha256:"))
            self.assertTrue(entry["verifier_stderr_digest"].startswith("sha256:"))
            self.assertEqual({"record_id", "chain_id"}, set(entry["artifact_ref"]))

    def test_result_object_carries_exactly_the_pinned_members(self):
        _, result = self.evaluate("IOP-R-CLEAN", four_artifact_bundle(),
                                  self.clean_verdicts())
        self.assertEqual({"scenario_id", "measurement_status", "level1", "predicates",
                          "artifacts", "withheld_reasons", "verifier_digests",
                          "evaluator_version"}, set(result))
        self.assertEqual(ie.FROZEN_DIGESTS, result["verifier_digests"])

    def test_output_is_byte_identical_across_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-R-CLEAN", four_artifact_bundle())
            invoke = stub_invoke(self.clean_verdicts())
            first = ie.dump_json(ie.evaluate_bundle(make_args(directory), invoke)[1])
            second = ie.dump_json(ie.evaluate_bundle(make_args(directory), invoke)[1])
        self.assertEqual(first, second)

    def test_numeric_preflight_rejects_a_profile_number_before_any_invocation(self):
        artifacts = four_artifact_bundle()
        artifacts[0]["profiles"] = {"iop.test": {"n": 2 ** 53}}
        calls = []

        def invoke(request, flags):
            calls.append(request)
            return 0, b"{}", b""

        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-R-CLEAN", artifacts)
            with self.assertRaises(ie.Unmeasurable) as caught:
                ie.evaluate_bundle(make_args(directory), invoke)
        self.assertEqual(ie.ERROR, caught.exception.status)
        self.assertIn("/profiles/iop.test/n", caught.exception.detail)
        self.assertEqual([], calls)

    def test_a_bundle_that_is_neither_shape_is_not_measured(self):
        with self.assertRaises(ie.Unmeasurable) as caught:
            self.evaluate("IOP-R-CLEAN", four_artifact_bundle()[:2], {})
        self.assertEqual(ie.ERROR, caught.exception.status)


class TestManifestAndCli(unittest.TestCase):
    def test_missing_manifest_is_exit_1_with_no_result_object(self):
        with tempfile.TemporaryDirectory() as directory:
            code, out, err = run_cli(["--bundle", directory])
        self.assertEqual(1, code)
        self.assertEqual("", out)
        self.assertNotEqual("", err)

    def test_unparseable_manifest_is_exit_1(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "manifest.json"), "w") as handle:
                handle.write("{not json")
            code, out, _ = run_cli(["--bundle", directory])
        self.assertEqual(1, code)
        self.assertEqual("", out)

    def test_manifest_without_scenario_id_is_exit_1(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-P-DEC", [artifact("decision", "rec-only")],
                         manifest_doc={"files": {}})
            code, out, _ = run_cli(["--bundle", directory])
        self.assertEqual(1, code)
        self.assertEqual("", out)

    def test_a_listed_file_that_is_absent_is_exit_1(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-P-DEC", [artifact("decision", "rec-only")],
                         omit="artifact-0.json")
            code, out, _ = run_cli(["--bundle", directory])
        self.assertEqual(1, code)
        self.assertEqual("", out)

    def test_a_file_failing_its_manifest_digest_is_exit_3_with_a_result_object(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-P-DEC", [artifact("decision", "rec-only")],
                         corrupt="artifact-0.json")
            code, out, _ = run_cli(["--bundle", directory])
        self.assertEqual(3, code)
        result = json.loads(out)
        self.assertEqual("IOP-P-DEC", result["scenario_id"])
        self.assertEqual(ie.ERROR, result["measurement_status"])
        self.assertIsNone(result["level1"])
        self.assertEqual(ie.na_predicates(), result["predicates"])

    def test_missing_bundle_flag_is_a_cli_usage_error(self):
        code, out, _ = run_cli([])
        self.assertEqual(2, code)
        self.assertEqual("", out)

    def test_unknown_flag_is_a_cli_usage_error(self):
        with self.assertRaises(SystemExit) as caught:
            run_cli(["--bundle", ".", "--not-a-flag"])
        self.assertEqual(2, caught.exception.code)

    def test_manifest_files_array_form_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            values = [artifact("decision", "rec-only")]
            digests = write_bundle(directory, "IOP-P-DEC", values)
            manifest = ie.load_manifest(directory)
            with open(os.path.join(directory, "manifest.json"), "w") as handle:
                json.dump({"scenario_id": "IOP-P-DEC",
                           "files": [{"path": p, "sha256": d}
                                     for p, d in digests.items()]}, handle)
            self.assertEqual(manifest.files, ie.load_manifest(directory).files)

    def test_operator_input_outside_the_manifest_is_not_measured(self):
        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-P-DEC", [artifact("decision", "rec-only")])
            with open(os.path.join(directory, "bindings.json"), "w") as handle:
                handle.write("{}")
            with self.assertRaises(ie.Unmeasurable) as caught:
                ie.evaluate_bundle(make_args(directory, bindings="bindings.json"),
                                   stub_invoke({}))
        self.assertEqual(ie.ERROR, caught.exception.status)
        self.assertIn("not covered by the manifest", caught.exception.detail)

    def test_operator_inputs_are_forwarded_by_path_unchanged(self):
        payload = b'{"bindings":{},"producer_bindings":{},"witness_bindings":{}}'
        seen = {}

        def invoke(request, flags):
            seen["flags"] = flags
            return 0, json.dumps(verdict("rec-only")).encode("utf-8"), b""

        with tempfile.TemporaryDirectory() as directory:
            write_bundle(directory, "IOP-P-DEC",
                         [artifact("decision", "rec-only", input={}, claim={},
                                   directive={}, output={}, evidence=[])],
                         extra_files={"bindings.json": payload})
            ie.evaluate_bundle(
                make_args(directory, bindings="bindings.json",
                          now="2026-01-01T00:00:00Z", freshness_window="60"),
                invoke)
            forwarded = seen["flags"][seen["flags"].index("--bindings") + 1]
            with open(forwarded, "rb") as handle:
                self.assertEqual(payload, handle.read())
        self.assertIn("--now", seen["flags"])
        self.assertIn("2026-01-01T00:00:00Z", seen["flags"])
        self.assertIn("--freshness-window", seen["flags"])
        self.assertIn("60", seen["flags"])


class TestFrozenLane(unittest.TestCase):
    def test_frozen_digests_assert_against_the_repository(self):
        ie.assert_frozen_digests()          # raises Unmeasurable on drift

    def test_the_node_row_is_carried_but_not_asserted_by_this_lane(self):
        self.assertIn("verifier_node_r2/class_verifier.mjs", ie.FROZEN_DIGESTS)
        self.assertNotIn("verifier_node_r2/class_verifier.mjs", ie.ASSERTED_BY_THIS_LANE)

    def test_frozen_verifier_really_is_invocable(self):
        # A structurally impossible request: proves the subprocess seam reaches
        # the real frozen Python verifier and that its exit code is taken
        # verbatim. Not a scenario, and no corpus bytes are involved.
        code, stdout, stderr = ie.invoke_frozen_verifier(b"{not json", [])
        self.assertEqual(1, code)
        self.assertEqual(b"", stdout)
        self.assertNotEqual(b"", stderr)

    def test_this_lane_only_ever_names_the_python_verifier(self):
        self.assertTrue(ie.frozen_verifier_path().endswith(
            os.path.join("verifier_py", "class_verifier.py")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
