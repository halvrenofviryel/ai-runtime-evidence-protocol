"""Positive + negative coverage for the ENAS bundle reconciliation validators.

Exercises the three bundle functions in ``enas_profiles``:
``validate_issuer_bundle``, ``validate_lifecycle_bundle``,
``validate_issuer_lifecycle_pair``. A golden valid issuer/lifecycle PAIR is loaded from
the fixture corpus and mutated for each negative case, so a positive baseline and its
rejection are asserted from the same source. Totality: every malformed / untrusted input
must return a validation-error LIST, never raise (no ``KeyError`` on a missing required
field, no ``AttributeError`` on a non-dict record/link/endpoint).
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from enas_profiles import (
    validate_issuer_bundle,
    validate_issuer_lifecycle_pair,
    validate_lifecycle_bundle,
)

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "enas_profiles"


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def issuer() -> dict:
    return _load("valid_issuer_bundle.json")


@pytest.fixture
def lifecycle() -> dict:
    return _load("valid_lifecycle_bundle.json")


def _record(bundle: dict, profile_type: str) -> dict:
    return next(r for r in bundle["records"] if r.get("profile_type") == profile_type)


def _link(bundle: dict, relation: str) -> dict:
    return next(link for link in bundle["links"] if link.get("relation") == relation)


# ── positive baselines ─────────────────────────────────────────────

def test_valid_issuer_bundle_passes(issuer):
    assert validate_issuer_bundle(issuer) == []


def test_valid_lifecycle_bundle_passes(lifecycle):
    assert validate_lifecycle_bundle(lifecycle) == []


def test_valid_pair_passes(issuer, lifecycle):
    assert validate_issuer_lifecycle_pair(issuer, lifecycle) == []


# ── totality: malformed input returns errors, never raises ──────────

@pytest.mark.parametrize("bad", [None, 42, "str", [], {}, {"records": "notlist"},
                                 {"records": ["notdict", 3]},
                                 {"records": [{"profile_type": "execution_link"}]}])
def test_issuer_validator_is_total(bad):
    result = validate_issuer_bundle(bad)
    assert isinstance(result, list) and result  # errors, not an exception


@pytest.mark.parametrize("bad", [None, 7, "str", [], {},
                                 {"records": [1], "links": [2], "instruction": "x"},
                                 {"records": "x", "links": "y", "instruction": {}}])
def test_lifecycle_validator_is_total(bad):
    result = validate_lifecycle_bundle(bad)
    assert isinstance(result, list) and result


@pytest.mark.parametrize("a,b", [(None, None), ({}, {}), ("x", "y"),
                                 ({"records": [None]}, {"records": [None]})])
def test_pair_validator_is_total(a, b):
    assert isinstance(validate_issuer_lifecycle_pair(a, b), list)


# ── issuer negatives ────────────────────────────────────────────────

def test_issuer_unsupported_boundary(issuer):
    issuer["boundary"] = "SOMETHING_ELSE"
    assert any("boundary" in e for e in validate_issuer_bundle(issuer))


def test_issuer_unsupported_disposition(issuer):
    issuer["disposition"] = "MAYBE"
    assert any("disposition" in e for e in validate_issuer_bundle(issuer))


def test_issuer_records_not_object_array(issuer):
    issuer["records"] = [issuer["records"][0], "not-a-dict"]
    errs = validate_issuer_bundle(issuer)
    assert any("object array" in e for e in errs)


def test_issuer_unknown_profile_type(issuer):
    _record(issuer, "evidence_use")["profile_type"] = "mystery_profile"
    assert any("unsupported record type" in e for e in validate_issuer_bundle(issuer))


def test_issuer_missing_manifest(issuer):
    issuer["records"] = [r for r in issuer["records"]
                         if r.get("profile_type") != "decision_input_manifest"]
    assert any("exactly one decision-input manifest" in e for e in validate_issuer_bundle(issuer))


def test_issuer_duplicate_manifest(issuer):
    issuer["records"].append(copy.deepcopy(_record(issuer, "decision_input_manifest")))
    assert any("exactly one decision-input manifest" in e for e in validate_issuer_bundle(issuer))


def test_issuer_missing_a_typed_link(issuer):
    issuer["records"] = [r for r in issuer["records"]
                         if r.get("relation") != "DECISION_TO_INSTRUCTION"]
    errs = validate_issuer_bundle(issuer)
    assert any("two typed links" in e or "DECISION_TO_INSTRUCTION" in e for e in errs)


def test_issuer_duplicate_link(issuer):
    issuer["records"].append(copy.deepcopy(_record(issuer, "execution_link")))
    assert any("two typed links" in e or "exactly one" in e for e in validate_issuer_bundle(issuer))


def test_issuer_link_crosses_attempt(issuer):
    link = next(r for r in issuer["records"] if r.get("profile_type") == "execution_link")
    link["action_attempt_id"] = "attempt-from-another-run"
    assert any("crosses manifest identity" in e for e in validate_issuer_bundle(issuer))


def test_issuer_decision_digest_mismatch_across_links(issuer):
    _link_rec = next(r for r in issuer["records"]
                     if r.get("relation") == "DECISION_TO_INSTRUCTION")
    _link_rec["source"]["digest"] = "sha256:" + "0" * 64
    assert any("decision digest differs" in e for e in validate_issuer_bundle(issuer))


def test_issuer_non_dict_endpoint_does_not_raise(issuer):
    link = next(r for r in issuer["records"] if r.get("relation") == "ACTION_TO_DECISION")
    link["target"] = "not-an-object"  # endpoint present but not a dict
    errs = validate_issuer_bundle(issuer)  # must not raise
    assert isinstance(errs, list) and errs


def test_issuer_missing_evidence_use(issuer):
    # drop one evidence_use → count no longer matches inputs
    uses = [r for r in issuer["records"] if r.get("profile_type") == "evidence_use"]
    issuer["records"].remove(uses[0])
    assert any("one evidence-use event per input" in e for e in validate_issuer_bundle(issuer))


def test_issuer_duplicate_evidence_use(issuer):
    use = next(r for r in issuer["records"] if r.get("profile_type") == "evidence_use")
    issuer["records"].append(copy.deepcopy(use))
    assert any("duplicate" in e or "one evidence-use event per input" in e
               for e in validate_issuer_bundle(issuer))


def test_issuer_evidence_use_digest_mismatch(issuer):
    use = next(r for r in issuer["records"] if r.get("profile_type") == "evidence_use")
    use["evidence_digest"] = "sha256:" + "1" * 64
    assert any("does not reconcile" in e for e in validate_issuer_bundle(issuer))


# ── lifecycle negatives ─────────────────────────────────────────────

def test_lifecycle_missing_instruction(lifecycle):
    del lifecycle["instruction"]
    assert any("instruction, records, and links" in e for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_non_dict_record_does_not_raise(lifecycle):
    lifecycle["records"].append("not-a-dict")
    errs = validate_lifecycle_bundle(lifecycle)  # must not raise
    assert isinstance(errs, list) and errs


def test_lifecycle_non_dict_link_does_not_raise(lifecycle):
    lifecycle["links"].append(12345)
    errs = validate_lifecycle_bundle(lifecycle)  # must not raise
    assert isinstance(errs, list) and any("not an object" in e or "four typed links" in e
                                          for e in errs)


def test_lifecycle_record_missing_id_does_not_raise(lifecycle):
    ack = _record(lifecycle, "enforcement_acknowledgement")
    del ack["enforcement_ack_id"]  # the record[id_field] access the founder flagged
    errs = validate_lifecycle_bundle(lifecycle)  # must not raise (was a KeyError)
    assert isinstance(errs, list) and errs


def test_lifecycle_unknown_profile_type(lifecycle):
    _record(lifecycle, "effect_observation")["profile_type"] = "unknown_kind"
    assert any("unsupported" in e or "exactly one" in e for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_duplicate_relation(lifecycle):
    lifecycle["links"].append(copy.deepcopy(_link(lifecycle, "EXECUTION_TO_EFFECT")))
    assert any("four typed links" in e or "exactly one" in e
               for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_missing_relation(lifecycle):
    lifecycle["links"] = [link for link in lifecycle["links"]
                          if link.get("relation") != "APPLICATION_TO_EXECUTION"]
    errs = validate_lifecycle_bundle(lifecycle)
    assert any("four typed links" in e or "missing required relations" in e
               or "APPLICATION_TO_EXECUTION" in e for e in errs)


def test_lifecycle_record_crosses_attempt(lifecycle):
    _record(lifecycle, "execution_observation")["action_attempt_id"] = "other-attempt"
    assert any("crosses action attempts" in e for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_record_crosses_trace(lifecycle):
    _record(lifecycle, "effect_observation")["trace_id"] = "other-trace"
    assert any("crosses trace or decision" in e for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_record_crosses_decision(lifecycle):
    _record(lifecycle, "enforcement_result")["decision_id"] = "other-decision"
    assert any("crosses trace or decision" in e for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_link_digest_mismatch(lifecycle):
    _link(lifecycle, "EXECUTION_TO_EFFECT")["source"]["digest"] = "sha256:" + "2" * 64
    assert any("digest mismatch" in e for e in validate_lifecycle_bundle(lifecycle))


def test_lifecycle_broken_endpoint_does_not_raise(lifecycle):
    _link(lifecycle, "INSTRUCTION_TO_ACKNOWLEDGEMENT")["source"] = "not-a-node"
    errs = validate_lifecycle_bundle(lifecycle)  # must not raise
    assert isinstance(errs, list) and errs


def test_lifecycle_acknowledgement_unbinds_instruction(lifecycle):
    _record(lifecycle, "enforcement_acknowledgement")["instruction_digest"] = "sha256:" + "3" * 64
    assert any("does not bind the lifecycle instruction" in e
               for e in validate_lifecycle_bundle(lifecycle))


@pytest.mark.parametrize("bad_ts", [
    "not-a-timestamp",  # str → ValueError (already caught)
    12345,              # int → AttributeError on .replace
    None,               # NoneType → AttributeError on .replace
    ["x"],              # list → AttributeError on .replace
    {"k": 1},           # dict → AttributeError on .replace
])
def test_lifecycle_broken_timestamp_does_not_raise(lifecycle, bad_ts):
    _record(lifecycle, "enforcement_result")["observed_at"] = bad_ts
    errs = validate_lifecycle_bundle(lifecycle)  # must not raise
    assert isinstance(errs, list) and errs


# ── pair (cross-bundle) negatives ───────────────────────────────────

def test_pair_cross_trace(issuer, lifecycle):
    lifecycle["trace_id"] = "a-different-trace"
    assert any("trace_id does not match issuer" in e
               for e in validate_issuer_lifecycle_pair(issuer, lifecycle))


def test_pair_cross_attempt(issuer, lifecycle):
    lifecycle["action_attempt_id"] = "a-different-attempt"
    assert any("action_attempt_id does not match issuer" in e
               for e in validate_issuer_lifecycle_pair(issuer, lifecycle))


def test_pair_cross_decision(issuer, lifecycle):
    lifecycle["decision_id"] = "a-different-decision"
    assert any("decision_id does not match issuer" in e
               for e in validate_issuer_lifecycle_pair(issuer, lifecycle))


def test_pair_instruction_mismatch(issuer, lifecycle):
    lifecycle["instruction"]["digest"] = "sha256:" + "4" * 64
    assert any("instruction does not match issuer" in e
               for e in validate_issuer_lifecycle_pair(issuer, lifecycle))


def test_pair_disposition_mismatch(issuer, lifecycle):
    issuer["disposition"] = "DENY" if issuer["disposition"] == "ALLOW" else "ALLOW"
    errs = validate_issuer_lifecycle_pair(issuer, lifecycle)
    assert any("requested disposition does not match issuer" in e for e in errs)
